"""Nuclei worker for the Medusa scanning pipeline.

This module provides a long-running process that:
- Pulls scan jobs from Redis (enqueued by the controller).
- Executes nuclei with deterministic JSON output.
- Streams logs and artifacts to S3/MinIO for auditing.
- Posts normalized findings back to the controller callback endpoint.

The implementation deliberately avoids cleverness.  The goal is an
observable and easily auditable worker that can run inside Kubernetes or a
local Docker Compose stack.  Secrets are read exclusively from environment
variables.  The worker assumes that the controller has already validated
scope and provided a job payload similar to:

```
{
    "job_id": "uuid",
    "scan_id": 42,
    "target": "https://example.com",
    "templates": ["cves/2022/CVE-2022-1234.yaml"],
    "tags": ["web"],
    "callback_url": "http://controller:8000/internal/callback",
    "attempts": 0,
    "metadata": {"scan_id": "..."}
}
```
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from io import StringIO
from typing import Any, Dict, Iterable, List, Optional

try:  # Redis is optional during unit tests.
    import redis
except ImportError:  # pragma: no cover - handled at runtime when missing.
    redis = None  # type: ignore

try:  # Boto3 is optional during unit tests.
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:  # pragma: no cover - handled at runtime when missing.
    boto3 = None  # type: ignore
    BotoCoreError = ClientError = Exception  # type: ignore

try:
    import requests
    from requests import Session
    from requests.exceptions import RequestException
except ImportError:  # pragma: no cover - fall back for test environments.
    requests = None  # type: ignore

    class Session:  # type: ignore
        """Minimal stand-in used when requests is unavailable during tests."""

        def post(self, *args, **kwargs):  # pragma: no cover - placeholder only.
            raise RuntimeError("requests is required to issue HTTP callbacks")

    class RequestException(Exception):
        pass


LOG = logging.getLogger("medusa.workers.web.nuclei")


class RetryableJobError(Exception):
    """Raised when a job should be retried."""


class FatalJobError(Exception):
    """Raised when a job should move directly to the dead-letter queue."""


@dataclass
class WorkerConfig:
    """Runtime configuration pulled from environment variables."""

    redis_url: str = field(default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    queue_key: str = field(default_factory=lambda: os.getenv("NUCLEI_QUEUE_KEY", "queue:web:nuclei"))
    dead_letter_key: str = field(default_factory=lambda: os.getenv("NUCLEI_DEAD_LETTER_KEY", "queue:web:nuclei:dead"))
    max_retries: int = field(default_factory=lambda: int(os.getenv("NUCLEI_MAX_RETRIES", "3")))
    poll_timeout: int = field(default_factory=lambda: int(os.getenv("NUCLEI_POLL_TIMEOUT", "5")))
    nuclei_binary: str = field(default_factory=lambda: os.getenv("NUCLEI_BINARY", "nuclei"))
    nuclei_rate_limit: Optional[str] = field(default_factory=lambda: os.getenv("NUCLEI_RATE_LIMIT"))
    artifact_bucket: Optional[str] = field(default_factory=lambda: os.getenv("NUCLEI_ARTIFACT_BUCKET"))
    artifact_prefix: str = field(default_factory=lambda: os.getenv("NUCLEI_ARTIFACT_PREFIX", "nuclei/"))
    s3_endpoint_url: Optional[str] = field(default_factory=lambda: os.getenv("S3_ENDPOINT_URL"))
    callback_timeout: int = field(default_factory=lambda: int(os.getenv("NUCLEI_CALLBACK_TIMEOUT", "30")))
    verify_tls: bool = field(default_factory=lambda: os.getenv("NUCLEI_CALLBACK_VERIFY_TLS", "true").lower() != "false")
    callback_token: str = field(
        default_factory=lambda: os.getenv("NUCLEI_CALLBACK_TOKEN")
        or os.getenv("MEDUSA_NUCLEI_CALLBACK_TOKEN", "")
    )

    @classmethod
    def load(cls) -> "WorkerConfig":
        config = cls()
        LOG.debug("Loaded worker configuration: %s", config)
        return config


@dataclass
class NucleiJob:
    """Incoming job payload from the controller."""

    job_id: str
    target: str
    templates: List[str]
    scan_id: str
    callback_url: str
    attempts: int = 0
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_json(cls, payload: str) -> "NucleiJob":
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:  # pragma: no cover - defensive.
            raise FatalJobError(f"Invalid job payload: {exc}") from exc

        job_id = data.get("job_id")
        target = data.get("target")
        callback_url = data.get("callback_url")
        templates = data.get("templates")
        metadata = data.get("metadata") or {}
        scan_id_raw = data.get("scan_id", metadata.get("scan_id"))
        if not job_id or not isinstance(job_id, str):
            raise FatalJobError("Job payload missing 'job_id'")
        if not target or not isinstance(target, str):
            raise FatalJobError("Job payload missing 'target'")
        if not callback_url or not isinstance(callback_url, str):
            raise FatalJobError("Job payload missing 'callback_url'")
        if isinstance(templates, str):
            templates = [templates]
        if not templates or not isinstance(templates, list):
            raise FatalJobError("Job payload missing nuclei templates")
        if scan_id_raw is None:
            raise FatalJobError("Job payload missing 'scan_id'")
        try:
            scan_id = int(scan_id_raw)
        except (TypeError, ValueError) as exc:
            raise FatalJobError("Job payload contains invalid 'scan_id'") from exc

        attempts = int(data.get("attempts", 0))
        tags = data.get("tags") or []
        metadata_payload = data.get("metadata") or {}
        if not isinstance(metadata_payload, dict):
            raise FatalJobError("Job metadata must be a JSON object")
        scan_id_value = data.get("scan_id") or metadata_payload.get("scan_id")
        if scan_id_value is None:
            raise FatalJobError("Job payload missing 'scan_id'")
        try:
            int(scan_id_value)
        except (TypeError, ValueError) as exc:
            raise FatalJobError("Job payload contains invalid 'scan_id'") from exc
        scan_id_str = str(scan_id_value)

        return cls(
            job_id=job_id,
            target=target,
            templates=[str(t) for t in templates],
            scan_id=scan_id_str,
            callback_url=callback_url,
            attempts=attempts,
            tags=[str(tag) for tag in tags],
            metadata=metadata_payload,
            raw=data,
        )

    def with_attempt(self, attempts: int) -> "NucleiJob":
        clone = NucleiJob(
            job_id=self.job_id,
            target=self.target,
            templates=list(self.templates),
            scan_id=self.scan_id,
            callback_url=self.callback_url,
            attempts=attempts,
            tags=list(self.tags),
            metadata=dict(self.metadata),
            raw=dict(self.raw),
        )
        clone.raw["attempts"] = attempts
        return clone

    def to_json(self) -> str:
        payload = dict(self.raw)
        payload.update(
            {
                "job_id": self.job_id,
                "target": self.target,
                "templates": self.templates,
                "scan_id": self.scan_id,
                "callback_url": self.callback_url,
                "attempts": self.attempts,
                "tags": self.tags,
                "metadata": self.metadata,
            }
        )
        return json.dumps(payload)


@dataclass
class ScanResult:
    """Encapsulates nuclei execution output."""

    records: List[Dict[str, Any]]
    stdout: str
    stderr: str
    exit_code: int
    duration_seconds: float


class RedisQueue:
    """Simple BLPOP-based queue wrapper for Redis."""

    def __init__(self, config: WorkerConfig) -> None:
        if redis is None:  # pragma: no cover - runtime validation only.
            raise RuntimeError("redis-py must be installed to use RedisQueue")
        self._pool = redis.Redis.from_url(config.redis_url, decode_responses=True)
        self.queue_key = config.queue_key
        self.dead_letter_key = config.dead_letter_key
        self.max_retries = config.max_retries
        self.poll_timeout = config.poll_timeout

    def fetch(self) -> Optional[NucleiJob]:
        result = self._pool.blpop(self.queue_key, timeout=self.poll_timeout)
        if not result:
            return None
        _, payload = result
        job = NucleiJob.from_json(payload)
        LOG.info("Dequeued job %s (attempt %s)", job.job_id, job.attempts)
        return job

    def retry(self, job: NucleiJob, reason: str) -> None:
        next_attempt = job.attempts + 1
        if next_attempt > self.max_retries:
            LOG.error("Job %s exceeded max retries: %s", job.job_id, reason)
            self.dead_letter(job, reason)
            return
        LOG.warning(
            "Retrying job %s (%s/%s): %s",
            job.job_id,
            next_attempt,
            self.max_retries,
            reason,
        )
        requeued = job.with_attempt(next_attempt)
        self._pool.rpush(self.queue_key, requeued.to_json())

    def dead_letter(self, job: NucleiJob, reason: str) -> None:
        payload = job.raw.copy()
        payload.update({"error": reason, "dead_lettered_at": int(time.time())})
        self._pool.rpush(self.dead_letter_key, json.dumps(payload))
        LOG.error("Job %s moved to dead-letter queue: %s", job.job_id, reason)


def build_s3_client(config: WorkerConfig):
    if not config.artifact_bucket:
        return None
    if boto3 is None:  # pragma: no cover - runtime validation only.
        raise RuntimeError("boto3 must be installed for artifact uploads")
    session = boto3.session.Session()
    return session.client(
        "s3",
        endpoint_url=config.s3_endpoint_url,
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID") or os.getenv("S3_ACCESS_KEY"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY")
        or os.getenv("S3_SECRET_KEY"),
        aws_session_token=os.getenv("AWS_SESSION_TOKEN"),
        region_name=os.getenv("AWS_REGION", "us-east-1"),
    )


def run_nuclei_scan(job: NucleiJob, config: WorkerConfig) -> ScanResult:
    """Execute nuclei with deterministic JSON output."""

    from subprocess import PIPE, Popen  # Imported lazily for testability.

    args = [
        config.nuclei_binary,
        "-json",
        "-silent",
        "-target",
        job.target,
    ]
    for template in job.templates:
        args.extend(["-t", template])
    if config.nuclei_rate_limit:
        args.extend(["-rl", config.nuclei_rate_limit])

    env = os.environ.copy()
    env["NUCLEI_NO_TELEMETRY"] = "true"

    stdout_buffer = StringIO()
    stderr_buffer = StringIO()

    LOG.info("Running nuclei for job %s on target %s", job.job_id, job.target)
    start = time.time()
    process = Popen(args, stdout=PIPE, stderr=PIPE, text=True, env=env)

    records: List[Dict[str, Any]] = []
    assert process.stdout is not None  # For type checkers.
    for line in process.stdout:
        stdout_buffer.write(line)
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            LOG.warning("Skipping non-JSON nuclei line: %s", line)
            continue
        records.append(record)

    assert process.stderr is not None
    for line in process.stderr:
        stderr_buffer.write(line)

    exit_code = process.wait()
    duration = time.time() - start
    LOG.info(
        "Nuclei finished for job %s (exit=%s, duration=%.2fs)",
        job.job_id,
        exit_code,
        duration,
    )

    return ScanResult(
        records=records,
        stdout=stdout_buffer.getvalue(),
        stderr=stderr_buffer.getvalue(),
        exit_code=exit_code,
        duration_seconds=duration,
    )


def _coerce_tags(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item]
    if isinstance(value, str):
        return [value]
    return []


def _coerce_cve(info: Dict[str, Any]) -> Optional[str]:
    candidates: List[str] = []
    for key in ("cve", "cveID", "cveId", "cve-id"):
        value = info.get(key)
        if isinstance(value, str):
            return value
        if isinstance(value, list):
            candidates.extend(str(item) for item in value if item)
    list_value = info.get("cveIds")
    if isinstance(list_value, list):
        candidates.extend(str(item) for item in list_value if item)
    return candidates[0] if candidates else None


def normalize_findings(records: Iterable[Dict[str, Any]], job: NucleiJob) -> List[Dict[str, Any]]:
    """Convert nuclei JSON records into the controller callback schema."""

    allowed_severities = {"critical", "high", "medium", "low", "info"}
    findings: List[Dict[str, Any]] = []
    for record in records:
        info = record.get("info") or {}
        template_id = record.get("templateID") or record.get("template-id")

        severity = str(info.get("severity") or "info").lower()
        if severity not in allowed_severities:
            severity = "info"

        title_value = info.get("name") or template_id or f"nuclei finding for {job.target}"
        title = str(title_value)

        description_value = info.get("description")
        if isinstance(description_value, str):
            description = description_value.strip()
        else:
            description = ""
        if not description:
            description = (
                f"Nuclei template {template_id or 'unknown'} reported a {severity} finding "
                f"for job {job.job_id} targeting {job.target}."
            )

        evidence_source = {
            "matched_at": record.get("matched-at") or record.get("matchedAt"),
            "extracted_results": record.get("extracted-results")
            or record.get("extractedResults"),
            "curl_command": record.get("curl-command") or record.get("curlCommand"),
            "matcher_name": record.get("matcher-name") or record.get("matcherName"),
            "timestamp": record.get("timestamp"),
            "ip": record.get("ip"),
            "port": record.get("port"),
        }
        evidence = {k: v for k, v in evidence_source.items() if v}

        info_tags = _coerce_tags(info.get("tags"))
        combined_tags = sorted({*job.tags, *info_tags})
        metadata_source = {
            "job_id": job.job_id,
            "template_id": template_id,
            "template_path": record.get("template-path") or record.get("templatePath"),
            "matcher_name": evidence.get("matcher_name"),
            "matched_at": evidence.get("matched_at"),
            "host": record.get("host"),
            "tags": combined_tags,
        }
        metadata = {k: v for k, v in metadata_source.items() if v}

        classification = info.get("classification") or {}
        cve_id = (
            _coerce_cve(classification)
            or _coerce_cve(info)
            or record.get("cve")
        )
        if isinstance(cve_id, list):
            cve_id = next((str(item) for item in cve_id if item), None)
        elif cve_id is not None:
            cve_id = str(cve_id)

        findings.append(
            {
                "title": title,
                "severity": severity,
                "description": description,
                "cve_id": cve_id,
                "metadata": metadata,
                "evidence": evidence,
            }
        )
    return findings


def upload_artifacts(
    result: ScanResult, job: NucleiJob, config: WorkerConfig, s3_client
) -> Dict[str, str]:
    """Upload stdout/stderr artifacts to S3, returning object references."""

    if not config.artifact_bucket or not s3_client:
        return {}
    artifacts: Dict[str, str] = {}
    base_key = f"{config.artifact_prefix.rstrip('/')}/{job.job_id}/"
    try:
        if result.stdout:
            key = f"{base_key}stdout.log"
            s3_client.put_object(
                Bucket=config.artifact_bucket,
                Key=key,
                Body=result.stdout.encode("utf-8"),
            )
            artifacts["stdout"] = key
        if result.stderr:
            key = f"{base_key}stderr.log"
            s3_client.put_object(
                Bucket=config.artifact_bucket,
                Key=key,
                Body=result.stderr.encode("utf-8"),
            )
            artifacts["stderr"] = key
        if result.records:
            key = f"{base_key}findings.json"
            body = json.dumps(result.records, indent=2).encode("utf-8")
            s3_client.put_object(Bucket=config.artifact_bucket, Key=key, Body=body)
            artifacts["raw_findings"] = key
    except (BotoCoreError, ClientError) as exc:
        LOG.error("Failed to upload artifacts for job %s: %s", job.job_id, exc)
        raise RetryableJobError(f"artifact upload failed: {exc}") from exc
    return artifacts


def post_callback(
    job: NucleiJob,
    config: WorkerConfig,
    payload: Dict[str, Any],
    session: Optional[Session] = None,
) -> None:
    """Send job results back to the controller."""

    if session is None:
        if requests is None:
            raise RetryableJobError(
                "requests library unavailable for callback delivery"
            )
        session = requests.Session()
    headers: Dict[str, str] = {}
    if config.callback_token:
        headers["X-Callback-Token"] = config.callback_token
    try:
        headers = {}
        if config.callback_token:
            headers["X-Callback-Token"] = config.callback_token
        response = session.post(
            job.callback_url,
            json=payload,
            timeout=config.callback_timeout,
            verify=config.verify_tls,
            headers=headers,
        )
        response.raise_for_status()
    except RequestException as exc:
        LOG.error("Callback failed for job %s: %s", job.job_id, exc)
        raise RetryableJobError(f"callback failed: {exc}") from exc


def process_job(
    job: NucleiJob,
    config: WorkerConfig,
    queue: RedisQueue,
    *,
    run_scan=run_nuclei_scan,
    session: Optional[Session] = None,
    s3_client=None,
) -> None:
    """Execute a single job lifecycle."""

    scan_id = job.scan_id or job.metadata.get("scan_id") if isinstance(job.metadata, dict) else None
    if not scan_id:
        raise FatalJobError("Job payload missing 'scan_id' required for callback")

    scan = run_scan(job, config)
    if scan.exit_code != 0:
        raise RetryableJobError(f"nuclei exited with code {scan.exit_code}")

    findings = normalize_findings(scan.records, job)
    artifacts = upload_artifacts(scan, job, config, s3_client)
    worker_metadata: Dict[str, Any] = {
        "job_id": job.job_id,
        "target": job.target,
        "templates": job.templates,
        "tags": job.tags,
        "duration_seconds": scan.duration_seconds,
    }
    extra_metadata = {k: v for k, v in job.metadata.items() if k != "scan_id"} if job.metadata else {}
    if extra_metadata:
        worker_metadata["job_metadata"] = extra_metadata
    if artifacts:
        worker_metadata["artifact_locations"] = artifacts

    if job.metadata:
        worker_metadata.update({k: v for k, v in job.metadata.items() if k != "scan_id"})
    payload = {
        "scan_id": scan_id,
        "status": "completed",
        "findings": findings,
        "worker_metadata": worker_metadata,
        "error": None,
        "completed_at": datetime.now(tz=timezone.utc).isoformat(),
    }
    post_callback(job, config, payload, session=session)
    LOG.info("Job %s completed successfully", job.job_id)


def notify_failure(job: NucleiJob, config: WorkerConfig, reason: str, session: Optional[Session] = None) -> None:
    scan_id = job.scan_id or job.metadata.get("scan_id") if isinstance(job.metadata, dict) else None
    if not scan_id:
        LOG.error("Cannot notify controller for job %s without scan_id", job.job_id)
        return

    worker_metadata: Dict[str, Any] = {
        "job_id": job.job_id,
        "target": job.target,
        "templates": job.templates,
        "tags": job.tags,
    }
      
    extra_metadata = {k: v for k, v in job.metadata.items() if k != "scan_id"} if job.metadata else {}
    if extra_metadata:
        worker_metadata["job_metadata"] = extra_metadata

    payload = {
        "scan_id": scan_id,
        "status": "failed",
        "findings": [],
        "worker_metadata": worker_metadata,
        "error": reason,
        "completed_at": datetime.now(tz=timezone.utc).isoformat(),
    }
    try:
        post_callback(job, config, payload, session=session)
    except RetryableJobError:
        LOG.warning("Failed to notify controller about job %s failure", job.job_id)


def worker_loop() -> None:
    """Main worker loop."""

    logging.basicConfig(
        level=os.getenv("NUCLEI_WORKER_LOG_LEVEL", "INFO"),
        stream=sys.stdout,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    config = WorkerConfig.load()
    if not config.callback_token:
        LOG.warning("NUCLEI_CALLBACK_TOKEN is not configured; callbacks may be rejected")
    queue = RedisQueue(config)
    s3_client = build_s3_client(config)
    session = requests.Session() if requests else Session()

    while True:
        try:
            job = queue.fetch()
            if not job:
                continue
            try:
                process_job(job, config, queue, session=session, s3_client=s3_client)
            except RetryableJobError as exc:
                if job.attempts + 1 > config.max_retries:
                    queue.dead_letter(job, str(exc))
                    notify_failure(job, config, str(exc), session=session)
                else:
                    queue.retry(job, str(exc))
            except FatalJobError as exc:
                queue.dead_letter(job, str(exc))
                notify_failure(job, config, str(exc), session=session)
        except KeyboardInterrupt:
            LOG.info("Worker received shutdown signal")
            break
        except Exception as exc:  # pragma: no cover - defensive logging.
            LOG.exception("Unhandled exception in worker loop: %s", exc)
            time.sleep(2)


def main() -> None:  # pragma: no cover - thin wrapper for entrypoints.
    worker_loop()


if __name__ == "__main__":  # pragma: no cover - manual execution path.
    main()
