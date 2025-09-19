"""Validator worker that performs deterministic retests before promotion."""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    import redis
except ImportError:  # pragma: no cover - runtime dependency
    redis = None  # type: ignore

try:
    import requests
    from requests import Response, Session
    from requests.exceptions import RequestException
except ImportError:  # pragma: no cover - runtime dependency
    requests = None  # type: ignore

    class Session:  # type: ignore
        def request(self, *args, **kwargs):  # pragma: no cover - runtime guard
            raise RuntimeError("requests is required for validator HTTP checks")

    class RequestException(Exception):
        pass


LOG = logging.getLogger("medusa.workers.validator")


class RetryableJobError(Exception):
    """Raised when a job should be retried after a delay."""


class FatalJobError(Exception):
    """Raised when a job should be moved to the dead-letter queue."""


@dataclass
class WorkerConfig:
    """Runtime configuration loaded from environment variables."""

    redis_url: str = field(default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    queue_key: str = field(
        default_factory=lambda: os.getenv("VALIDATOR_QUEUE_KEY", "queues:validator:jobs")
    )
    dead_letter_key: str = field(
        default_factory=lambda: os.getenv("VALIDATOR_DEAD_LETTER_KEY", "queues:validator:dead")
    )
    max_retries: int = field(default_factory=lambda: int(os.getenv("VALIDATOR_MAX_RETRIES", "3")))
    poll_timeout: int = field(default_factory=lambda: int(os.getenv("VALIDATOR_POLL_TIMEOUT", "5")))
    callback_token: Optional[str] = field(
        default_factory=lambda: os.getenv("VALIDATOR_CALLBACK_TOKEN")
        or os.getenv("MEDUSA_VALIDATOR_CALLBACK_TOKEN")
    )
    http_timeout: int = field(default_factory=lambda: int(os.getenv("VALIDATOR_HTTP_TIMEOUT", "10")))

    @classmethod
    def load(cls) -> "WorkerConfig":
        config = cls()
        LOG.debug("Loaded validator worker config: %s", config)
        return config


@dataclass
class HttpVerificationStep:
    method: str
    url: str
    expected_status: int


@dataclass
class ValidatorJob:
    """Incoming validator job payload."""

    job_id: str
    finding_id: str
    scan_id: str
    target_id: str
    target_scope: Optional[str]
    callback_url: str
    severity: str
    evidence_hash: str
    submitted_at: datetime
    metadata: Dict[str, Any]
    http_steps: List[HttpVerificationStep] = field(default_factory=list)

    @classmethod
    def from_json(cls, payload: str) -> "ValidatorJob":
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:  # pragma: no cover - invalid data guard
            raise FatalJobError(f"Invalid job payload: {exc}") from exc

        if not isinstance(data, dict):
            raise FatalJobError("Job payload must be a JSON object")

        try:
            job_id = str(data["job_id"]).strip()
            finding_id = str(data["finding_id"]).strip()
            scan_id = str(data["scan_id"]).strip()
            target_id = str(data["target_id"]).strip()
            callback_url = str(data["callback_url"]).strip()
            severity = str(data.get("severity", "info")).strip()
            evidence_hash = str(data["evidence_hash"]).strip()
        except KeyError as exc:
            raise FatalJobError(f"Missing required field: {exc.args[0]}") from exc

        if not job_id or not finding_id or not scan_id or not target_id or not callback_url:
            raise FatalJobError("Job payload missing required identifiers")

        submitted_raw = data.get("submitted_at")
        submitted_at = (
            datetime.fromisoformat(submitted_raw)
            if isinstance(submitted_raw, str)
            else datetime.now(tz=timezone.utc)
        )
        if submitted_at.tzinfo is None:
            submitted_at = submitted_at.replace(tzinfo=timezone.utc)

        metadata = data.get("metadata") or {}
        if not isinstance(metadata, dict):
            raise FatalJobError("Job metadata must be an object")

        http_steps: List[HttpVerificationStep] = []
        verification = data.get("verification") or {}
        if isinstance(verification, dict):
            raw_steps = verification.get("http") or []
            if isinstance(raw_steps, list):
                for step in raw_steps:
                    if not isinstance(step, dict):
                        continue
                    url = str(step.get("url") or "").strip()
                    if not url.lower().startswith(("http://", "https://")):
                        continue
                    method = str(step.get("method") or "GET").upper()
                    try:
                        expected_status = int(step.get("expected_status", 200))
                    except (TypeError, ValueError):
                        expected_status = 200
                    http_steps.append(HttpVerificationStep(method=method, url=url, expected_status=expected_status))

        return cls(
            job_id=job_id,
            finding_id=finding_id,
            scan_id=scan_id,
            target_id=target_id,
            target_scope=str(data.get("target_scope") or "") or None,
            callback_url=callback_url,
            severity=severity,
            evidence_hash=evidence_hash,
            submitted_at=submitted_at,
            metadata=metadata,
            http_steps=http_steps,
        )


@dataclass
class ValidatorResult:
    status: str
    observed_at: datetime
    details: Dict[str, Any]


class ValidatorWorker:
    """Redis-backed worker that performs deterministic validation checks."""

    def __init__(self, config: WorkerConfig) -> None:
        if redis is None:  # pragma: no cover - handled at runtime
            raise RuntimeError("redis is required to run the validator worker")
        if requests is None:  # pragma: no cover - handled at runtime
            raise RuntimeError("requests is required to run the validator worker")

        self._config = config
        self._redis = redis.Redis.from_url(
            config.redis_url, encoding="utf-8", decode_responses=True
        )
        self._http: Session = requests.Session()

    def run_forever(self) -> None:
        LOG.info("Starting validator worker", extra={"queue": self._config.queue_key})
        while True:
            try:
                self._process_next_job()
            except Exception:  # pragma: no cover - defensive logging
                LOG.exception("Unexpected validator worker error")
                time.sleep(1)

    def _process_next_job(self) -> None:
        item = self._redis.blpop(self._config.queue_key, timeout=self._config.poll_timeout)
        if item is None:
            return
        queue, payload = item
        LOG.debug("Dequeued validator job", extra={"queue": queue})

        try:
            job = ValidatorJob.from_json(payload)
            result = self._execute_job(job)
            self._post_callback(job, result)
        except RetryableJobError as exc:
            LOG.warning("Validator job retry", extra={"job_id": job.job_id, "error": str(exc)})
            self._redis.rpush(self._config.queue_key, payload)
            time.sleep(1)
        except FatalJobError as exc:
            LOG.error("Validator job failed fatally", extra={"error": str(exc)})
            self._redis.rpush(self._config.dead_letter_key, payload)
        except Exception as exc:  # pragma: no cover - defensive catch
            LOG.exception("Validator job crashed", extra={"error": str(exc)})
            self._redis.rpush(self._config.dead_letter_key, payload)

    def _execute_job(self, job: ValidatorJob) -> ValidatorResult:
        details: Dict[str, Any] = {"http": []}
        status = "passed"

        for step in job.http_steps:
            LOG.debug(
                "Executing HTTP validation step", extra={"job_id": job.job_id, "url": step.url}
            )
            try:
                response: Response = self._http.request(
                    step.method,
                    step.url,
                    timeout=self._config.http_timeout,
                    allow_redirects=False,
                )
            except RequestException as exc:
                details.setdefault("http", []).append(
                    {"url": step.url, "error": str(exc), "status": "failed"}
                )
                status = "failed"
                continue

            record = {
                "url": step.url,
                "observed_status": response.status_code,
                "expected_status": step.expected_status,
            }
            if response.status_code != step.expected_status:
                status = "failed"
                record["status"] = "mismatch"
            else:
                record["status"] = "matched"
            details.setdefault("http", []).append(record)

        observed_at = datetime.now(tz=timezone.utc)
        if not details["http"]:
            details.pop("http")
        return ValidatorResult(status=status, observed_at=observed_at, details=details)

    def _post_callback(self, job: ValidatorJob, result: ValidatorResult) -> None:
        headers: Dict[str, str] = {}
        if self._config.callback_token:
            headers["X-Callback-Token"] = self._config.callback_token

        payload = {
            "job_id": job.job_id,
            "status": "completed" if result.status == "passed" else "failed",
            "processed_at": result.observed_at.isoformat(),
            "findings": [
                {
                    "finding_id": job.finding_id,
                    "status": result.status,
                    "observed_at": result.observed_at.isoformat(),
                    "evidence_hash": job.evidence_hash,
                    "severity": job.severity,
                    "details": result.details,
                }
            ],
        }

        LOG.debug(
            "Posting validator callback",
            extra={"job_id": job.job_id, "status": result.status},
        )
        response = self._http.post(job.callback_url, json=payload, headers=headers, timeout=15)
        if response.status_code >= 300:
            raise RetryableJobError(
                f"Controller callback rejected validator result: {response.status_code}"
            )


if __name__ == "__main__":  # pragma: no cover - manual execution entrypoint
    logging.basicConfig(level=logging.INFO)
    worker = ValidatorWorker(WorkerConfig.load())
    worker.run_forever()
