"""Validator worker responsible for retesting findings before promotion."""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

try:  # Optional dependency during unit tests.
    import redis
except ImportError:  # pragma: no cover - handled at runtime.
    redis = None  # type: ignore

try:  # Optional dependency during unit tests.
    import requests
    from requests import Session
    from requests.exceptions import RequestException
except ImportError:  # pragma: no cover - handled at runtime.
    requests = None  # type: ignore

    class Session:  # type: ignore
        def request(self, *args, **kwargs):  # pragma: no cover - placeholder
            raise RuntimeError("requests must be installed to execute validation probes")

    class RequestException(Exception):
        pass


LOG = logging.getLogger("medusa.workers.validator")
CALLBACK_TOKEN_HEADER = "X-Callback-Token"


class RetryableJobError(Exception):
    """Raised when a job should be retried at a later time."""


class FatalJobError(Exception):
    """Raised when a job should be moved directly to the dead-letter queue."""


@dataclass
class WorkerConfig:
    """Runtime configuration for the validator worker."""

    redis_url: str = field(
        default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0")
    )
    queue_key: str = field(
        default_factory=lambda: os.getenv("VALIDATOR_QUEUE_KEY", "queues:validator:jobs")
    )
    dead_letter_key: str = field(
        default_factory=lambda: os.getenv("VALIDATOR_DEAD_LETTER_KEY", "queues:validator:dead")
    )
    max_retries: int = field(default_factory=lambda: int(os.getenv("VALIDATOR_MAX_RETRIES", "3")))
    poll_timeout: int = field(default_factory=lambda: int(os.getenv("VALIDATOR_POLL_TIMEOUT", "5")))
    http_timeout: int = field(default_factory=lambda: int(os.getenv("VALIDATOR_HTTP_TIMEOUT", "10")))
    verify_tls: bool = field(
        default_factory=lambda: os.getenv("VALIDATOR_VERIFY_TLS", "true").lower() != "false"
    )
    callback_token: str = field(
        default_factory=lambda: os.getenv("VALIDATOR_CALLBACK_TOKEN", "")
    )

    @classmethod
    def load(cls) -> "WorkerConfig":
        config = cls()
        LOG.debug("Loaded validator worker config: %s", config)
        return config


@dataclass
class ValidationJob:
    """Normalized job payload produced by the controller."""

    job_id: str
    validation_id: str
    finding_id: str
    scan_id: str
    target_id: Optional[str]
    target: Optional[str]
    severity: str
    validator: str
    probe: Dict[str, Any]
    callback_url: str
    attempts: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_json(cls, payload: str) -> "ValidationJob":
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:  # pragma: no cover - defensive
            raise FatalJobError(f"invalid job payload: {exc}") from exc

        if not isinstance(data, dict):
            raise FatalJobError("job payload must be a JSON object")

        required_fields = [
            "job_id",
            "validation_id",
            "finding_id",
            "scan_id",
            "severity",
            "validator",
            "probe",
            "callback_url",
        ]
        for field_name in required_fields:
            if field_name not in data:
                raise FatalJobError(f"job payload missing '{field_name}'")

        probe_payload = data.get("probe")
        if not isinstance(probe_payload, dict):
            raise FatalJobError("job probe must be an object")

        metadata_payload = data.get("metadata")
        if metadata_payload is None:
            metadata_payload = {}
        if not isinstance(metadata_payload, dict):
            raise FatalJobError("job metadata must be an object")

        return cls(
            job_id=str(data["job_id"]),
            validation_id=str(data["validation_id"]),
            finding_id=str(data["finding_id"]),
            scan_id=str(data["scan_id"]),
            target_id=(str(data.get("target_id")) if data.get("target_id") else None),
            target=(str(data.get("target")) if data.get("target") else None),
            severity=str(data["severity"]),
            validator=str(data["validator"]),
            probe=probe_payload,
            callback_url=str(data["callback_url"]),
            attempts=int(data.get("attempts", 0)),
            metadata=metadata_payload,
        )


@dataclass
class ValidationResult:
    """Result returned by the validation worker."""

    status: str
    outcome: Optional[str]
    processed_at: datetime
    attempts: int
    observations: Dict[str, Any] = field(default_factory=dict)
    evidence: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def to_payload(self, job: ValidationJob) -> Dict[str, Any]:
        payload = {
            "validation_id": job.validation_id,
            "finding_id": job.finding_id,
            "job_id": job.job_id,
            "status": self.status,
            "processed_at": self.processed_at.isoformat(),
            "outcome": self.outcome,
            "attempts": self.attempts,
            "observations": self.observations,
            "evidence": self.evidence,
        }
        if self.error:
            payload["error"] = self.error
        return payload


@dataclass
class QueuedJob:
    """Container combining serialized payload and parsed job."""

    raw: str
    job: ValidationJob


class RedisJobQueue:
    """Minimal Redis-backed queue wrapper for validator jobs."""

    def __init__(self, config: WorkerConfig) -> None:
        if redis is None:  # pragma: no cover - runtime dependency check
            raise RuntimeError("redis dependency is required to process validator jobs")
        self._config = config
        self._client: Optional[redis.Redis] = None  # type: ignore[attr-defined]

    @property
    def client(self):
        if self._client is None:
            self._client = redis.Redis.from_url(self._config.redis_url, decode_responses=True)
        return self._client

    def fetch(self) -> Optional[QueuedJob]:
        result = self.client.blpop(self._config.queue_key, timeout=self._config.poll_timeout)
        if result is None:
            return None
        _, raw_payload = result
        job = ValidationJob.from_json(raw_payload)
        return QueuedJob(raw=raw_payload, job=job)

    def acknowledge(self, _job: QueuedJob) -> None:
        """Acknowledgement is implicit when the job is removed from the queue."""

    def requeue(self, item: QueuedJob, error: Exception) -> None:
        job_dict = json.loads(item.raw)
        job_dict["attempts"] = int(job_dict.get("attempts", 0)) + 1
        if job_dict["attempts"] > self._config.max_retries:
            self.move_to_dead_letter(item, error)
            return
        LOG.warning(
            "Retrying validation job", extra={"validation_id": job_dict.get("validation_id"), "attempts": job_dict["attempts"]}
        )
        self.client.rpush(self._config.queue_key, json.dumps(job_dict))

    def move_to_dead_letter(self, item: QueuedJob, error: Exception) -> None:
        job_dict = json.loads(item.raw)
        job_dict["attempts"] = int(job_dict.get("attempts", 0))
        job_dict["error"] = str(error)
        job_dict["failed_at"] = datetime.now(tz=timezone.utc).isoformat()
        self.client.rpush(self._config.dead_letter_key, json.dumps(job_dict))
        LOG.error(
            "Validation job moved to dead-letter queue",
            extra={"validation_id": job_dict.get("validation_id"), "error": str(error)},
        )


def _create_http_session() -> Session:
    if requests is None:  # pragma: no cover - handled when requests missing
        raise RuntimeError("requests is required for HTTP validation probes")
    return requests.Session()  # type: ignore[call-arg]


def _execute_http_probe(job: ValidationJob, config: WorkerConfig, session: Optional[Session]) -> ValidationResult:
    if session is None:
        session = _create_http_session()

    method = str(job.probe.get("method", "GET")).upper()
    url = job.probe.get("url")
    if not isinstance(url, str) or not url.strip():
        raise FatalJobError("HTTP probe missing url")
    url = url.strip()
    expected_status = job.probe.get("expected_status")
    match_string = job.probe.get("match")
    timeout_seconds = int(job.probe.get("timeout_seconds", config.http_timeout))

    observations: Dict[str, Any] = {"probe": "http", "method": method}
    evidence: Dict[str, Any] = {}

    try:
        response = session.request(
            method,
            url,
            timeout=timeout_seconds,
            verify=config.verify_tls,
        )
    except RequestException as exc:
        observations["error"] = str(exc)
        return ValidationResult(
            status="failed",
            outcome=None,
            processed_at=datetime.now(tz=timezone.utc),
            attempts=job.attempts,
            observations=observations,
            error=str(exc),
        )

    observations["status_code"] = response.status_code
    observations["content_length"] = len(response.content)
    if expected_status is not None:
        observations["expected_status"] = expected_status
    if match_string:
        observations["match"] = match_string

    matched = True
    if isinstance(expected_status, int) and response.status_code != expected_status:
        matched = False
    response_text: Optional[str] = None
    if match_string:
        response_text = response.text
        observations["match_found"] = match_string in response_text
        if match_string not in response_text:
            matched = False

    outcome = "confirmed" if matched else "not_reproduced"
    if response_text is None:
        try:
            response_text = response.text
        except Exception:  # pragma: no cover - best effort for binary responses
            response_text = None

    if response_text:
        evidence["response_snippet"] = response_text[:512]
    evidence["status_code"] = response.status_code

    return ValidationResult(
        status="completed",
        outcome=outcome,
        processed_at=datetime.now(tz=timezone.utc),
        attempts=job.attempts,
        observations=observations,
        evidence=evidence,
    )


def execute_validation(job: ValidationJob, config: WorkerConfig) -> ValidationResult:
    """Execute the configured probe and return a structured result."""

    validator = job.validator.lower().strip()
    if validator == "noop" or job.probe.get("type") == "noop":
        return ValidationResult(
            status="completed",
            outcome="inconclusive",
            processed_at=datetime.now(tz=timezone.utc),
            attempts=job.attempts,
            observations={"probe": "noop"},
        )

    if validator == "http":
        return _execute_http_probe(job, config, None)

    raise FatalJobError(f"unsupported validator type: {validator}")


def post_callback(job: ValidationJob, result: ValidationResult, config: WorkerConfig) -> None:
    if requests is None:  # pragma: no cover - dependency enforced at runtime
        raise RuntimeError("requests must be installed to deliver callbacks")

    headers = {CALLBACK_TOKEN_HEADER: config.callback_token}
    payload = result.to_payload(job)
    LOG.debug(
        "Posting validation callback",
        extra={"validation_id": job.validation_id, "status": result.status},
    )
    response = requests.post(job.callback_url, json=payload, headers=headers, timeout=config.http_timeout)  # type: ignore[arg-type]
    response.raise_for_status()


def process_queue_once(queue: RedisJobQueue, config: WorkerConfig) -> bool:
    """Process at most one job from the queue and return True when work occurred."""

    item = queue.fetch()
    if item is None:
        return False
    try:
        result = execute_validation(item.job, config)
        post_callback(item.job, result, config)
        queue.acknowledge(item)
    except RetryableJobError as exc:  # pragma: no cover - placeholder for future logic
        LOG.warning(
            "Retryable error while processing validation job",
            extra={"validation_id": item.job.validation_id, "error": str(exc)},
        )
        queue.requeue(item, exc)
    except FatalJobError as exc:
        LOG.error(
            "Fatal error processing validation job",
            extra={"validation_id": item.job.validation_id, "error": str(exc)},
        )
        queue.move_to_dead_letter(item, exc)
    except Exception as exc:  # pragma: no cover - defensive logging
        LOG.exception(
            "Unexpected error processing validation job",
            extra={"validation_id": item.job.validation_id},
        )
        queue.move_to_dead_letter(item, exc)
    return True


__all__ = [
    "WorkerConfig",
    "ValidationJob",
    "ValidationResult",
    "RedisJobQueue",
    "execute_validation",
    "process_queue_once",
]


def main() -> None:  # pragma: no cover - integration entrypoint
    """Entry point used by the container image."""

    config = WorkerConfig.load()
    queue = RedisJobQueue(config)
    while True:
        processed = process_queue_once(queue, config)
        if not processed:
            time.sleep(max(config.poll_timeout, 1))


if __name__ == "__main__":  # pragma: no cover - script execution
    main()
