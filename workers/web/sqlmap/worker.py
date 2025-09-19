"""SQLMap worker implementation for Medusa."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

try:  # Redis is optional during unit tests.
    import redis
except ImportError:  # pragma: no cover - optional dependency for tests.
    redis = None  # type: ignore

try:
    import requests
    from requests import Session
    from requests.exceptions import RequestException
except ImportError:  # pragma: no cover - requests optional in tests.
    requests = None  # type: ignore

    class Session:  # type: ignore
        def post(self, *args, **kwargs):  # pragma: no cover - placeholder
            raise RuntimeError("requests library is required to deliver callbacks")

    class RequestException(Exception):
        pass


LOG = logging.getLogger("medusa.workers.web.sqlmap")

ALLOWED_SQLMAP_FLAGS: Sequence[str] = (
    "-u",
    "--batch",
    "--risk",
    "--level",
    "--technique",
    "--tamper",
    "--delay",
    "--time-sec",
    "--output-dir",
)

SQLMAP_TECHNIQUE_FLAGS: Dict[str, str] = {
    "boolean": "B",
    "error": "E",
    "stacked": "S",
    "time": "T",
    "union": "U",
}

RISK_TO_SEVERITY = {0: "info", 1: "low", 2: "medium", 3: "high"}


class RetryableJobError(Exception):
    """Raised when a job should be retried."""


class FatalJobError(Exception):
    """Raised when a job should be moved to the dead-letter queue."""


@dataclass
class WorkerConfig:
    """Runtime configuration for the SQLMap worker."""

    redis_url: str = field(default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    queue_key: str = field(default_factory=lambda: os.getenv("SQLMAP_QUEUE_KEY", "queues:sqlmap:jobs"))
    dead_letter_key: str = field(default_factory=lambda: os.getenv("SQLMAP_DEAD_LETTER_KEY", "queues:sqlmap:dead"))
    sqlmap_binary: str = field(default_factory=lambda: os.getenv("SQLMAP_BINARY", "sqlmap.py"))
    poll_timeout: int = field(default_factory=lambda: int(os.getenv("SQLMAP_POLL_TIMEOUT", "5")))
    max_retries: int = field(default_factory=lambda: int(os.getenv("SQLMAP_MAX_RETRIES", "3")))
    callback_timeout: int = field(default_factory=lambda: int(os.getenv("SQLMAP_CALLBACK_TIMEOUT", "30")))
    verify_tls: bool = field(default_factory=lambda: os.getenv("SQLMAP_CALLBACK_VERIFY_TLS", "true").lower() != "false")
    callback_token: str = field(
        default_factory=lambda: os.getenv("SQLMAP_CALLBACK_TOKEN")
        or os.getenv("MEDUSA_SQLMAP_CALLBACK_TOKEN", "")
    )
    work_dir: str = field(default_factory=lambda: os.getenv("SQLMAP_WORK_DIR", "/tmp/sqlmap"))

    @classmethod
    def load(cls) -> "WorkerConfig":
        config = cls()
        LOG.debug("Loaded SQLMap worker configuration: %s", config)
        return config


@dataclass
class SqlmapJob:
    """Normalized job payload."""

    job_id: str
    scan_id: str
    target: str
    callback_url: str
    scanner: str = "sqlmap"
    parameters: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    attempts: int = 0
    target_id: Optional[str] = None
    target_name: Optional[str] = None

    @classmethod
    def from_json(cls, payload: str) -> "SqlmapJob":
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:  # pragma: no cover - defensive
            raise FatalJobError(f"invalid job payload: {exc}") from exc

        if not isinstance(data, dict):
            raise FatalJobError("job payload must be a JSON object")

        job_id = str(data.get("job_id") or "").strip()
        if not job_id:
            raise FatalJobError("job payload missing job_id")

        scan_id = str(data.get("scan_id") or "").strip()
        if not scan_id:
            raise FatalJobError("job payload missing scan_id")

        target = str(data.get("target") or "").strip()
        if not target:
            raise FatalJobError("job payload missing target")

        callback_url = str(data.get("callback_url") or "").strip()
        if not callback_url:
            raise FatalJobError("job payload missing callback_url")

        parameters = data.get("parameters") or {}
        if not isinstance(parameters, dict):
            raise FatalJobError("job parameters must be an object")

        tags: List[str] = []
        raw_tags = data.get("tags")
        if isinstance(raw_tags, Sequence) and not isinstance(raw_tags, (str, bytes, bytearray)):
            for tag in raw_tags:
                if isinstance(tag, str) and tag.strip():
                    tags.append(tag.strip())

        metadata = data.get("metadata") or {}
        if not isinstance(metadata, dict):
            metadata = {}

        attempts_value = data.get("attempts", 0)
        try:
            attempts = int(attempts_value)
        except (TypeError, ValueError):
            attempts = 0

        scanner = str(data.get("scanner") or "sqlmap").strip() or "sqlmap"
        target_id = data.get("target_id")
        target_name = data.get("target_name")

        return cls(
            job_id=job_id,
            scan_id=scan_id,
            target=target,
            callback_url=callback_url,
            scanner=scanner,
            parameters=dict(parameters),
            tags=tags,
            metadata=dict(metadata),
            attempts=attempts,
            target_id=str(target_id) if target_id else None,
            target_name=str(target_name) if target_name else None,
        )


def _technique_flag(techniques: Sequence[str]) -> Optional[str]:
    parts = []
    for technique in techniques:
        flag = SQLMAP_TECHNIQUE_FLAGS.get(str(technique).lower())
        if flag and flag not in parts:
            parts.append(flag)
    if parts:
        return "".join(parts)
    return None


def build_sqlmap_command(job: SqlmapJob, config: WorkerConfig) -> List[str]:
    """Return a hardened SQLMap command for the provided job."""

    os.makedirs(config.work_dir, exist_ok=True)
    output_dir = os.path.join(config.work_dir, job.job_id)
    os.makedirs(output_dir, exist_ok=True)

    risk = int(job.parameters.get("risk", 1))
    level = int(job.parameters.get("level", 1))

    command: List[str] = [
        config.sqlmap_binary,
        "--batch",
        "-u",
        job.target,
        "--output-dir",
        output_dir,
        "--risk",
        str(max(0, min(3, risk))),
        "--level",
        str(max(1, min(5, level))),
    ]

    techniques = job.parameters.get("techniques")
    if isinstance(techniques, Sequence) and not isinstance(techniques, (str, bytes, bytearray)):
        flag = _technique_flag([str(item) for item in techniques])
        if flag:
            command.extend(["--technique", flag])

    tamper = job.parameters.get("tamper")
    tamper_list: List[str] = []
    if isinstance(tamper, str):
        tamper_list = [item.strip() for item in tamper.split(",") if item.strip()]
    elif isinstance(tamper, Sequence) and not isinstance(tamper, (bytes, bytearray, dict)):
        tamper_list = [str(item).strip() for item in tamper if str(item).strip()]
    if tamper_list:
        command.extend(["--tamper", ",".join(tamper_list)])

    delay = job.parameters.get("request_delay")
    try:
        delay_value = float(delay)
    except (TypeError, ValueError):
        delay_value = 0.0
    if delay_value > 0:
        command.extend(["--delay", f"{delay_value:.2f}".rstrip("0").rstrip(".")])

    for index, arg in enumerate(command):
        if index == 0:
            continue
        if isinstance(arg, str) and arg.startswith("-"):
            if arg not in ALLOWED_SQLMAP_FLAGS:
                raise FatalJobError(f"unsupported sqlmap flag requested: {arg}")

    return command


def normalize_vulnerabilities(records: Iterable[Dict[str, Any]], job: SqlmapJob) -> List[Dict[str, Any]]:
    """Normalize SQLMap vulnerability records into controller findings."""

    findings: List[Dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        title = str(record.get("title") or "SQL injection vulnerability")
        risk = record.get("risk")
        try:
            risk_value = int(risk)
        except (TypeError, ValueError):
            risk_value = 1
        severity = RISK_TO_SEVERITY.get(risk_value, "medium")

        description = record.get("description") or record.get("notes")
        if not isinstance(description, str) or not description.strip():
            parameter = record.get("parameter") or record.get("column") or "parameter"
            description = f"SQLMap identified a {severity} issue in {parameter} while targeting {job.target}"

        vector = record.get("vector") or record.get("place")
        payload = record.get("payload")
        payload_preview = None
        if isinstance(payload, str) and payload:
            payload_preview = payload[:120]

        evidence = {
            "vector": vector,
            "parameter": record.get("parameter"),
            "payload_preview": payload_preview,
        }
        evidence = {k: v for k, v in evidence.items() if v}

        technique = record.get("technique")
        dbms = record.get("dbms")
        rule_source = record.get("parameter") or vector or job.target
        metadata = {
            "scanner": job.scanner or "sqlmap",
            "rule_id": f"sqlmap:{rule_source}",
            "technique": technique,
            "dbms": dbms,
            "risk": risk_value,
            "level": record.get("level"),
            "tags": job.tags,
        }

        findings.append(
            {
                "title": title,
                "severity": severity,
                "description": str(description),
                "cve_id": record.get("cve"),
                "metadata": {k: v for k, v in metadata.items() if v},
                "evidence": evidence,
                "artifacts": [],
            }
        )

    return findings


def post_callback(
    job: SqlmapJob,
    config: WorkerConfig,
    payload: Dict[str, Any],
    session: Optional[Session] = None,
) -> None:
    if session is None:
        if requests is None:  # pragma: no cover - optional dependency
            raise RetryableJobError("requests library unavailable for callback delivery")
        session = requests.Session()

    headers: Dict[str, str] = {}
    if config.callback_token:
        headers["X-Callback-Token"] = config.callback_token

    try:
        response = session.post(
            job.callback_url,
            json=payload,
            timeout=config.callback_timeout,
            verify=config.verify_tls,
            headers=headers,
        )
        response.raise_for_status()
    except RequestException as exc:
        LOG.error("SQLMap callback failed for job %s: %s", job.job_id, exc)
        raise RetryableJobError(f"callback failed: {exc}") from exc


class RedisQueue:
    """Lightweight Redis-backed queue helper."""

    def __init__(self, redis_url: str) -> None:
        if redis is None:  # pragma: no cover - exercised in integration tests
            raise RuntimeError("redis package is required to run the worker")
        self._client = redis.Redis.from_url(redis_url, encoding="utf-8", decode_responses=True)

    def pop(self, queue: str, timeout: int) -> Optional[str]:
        result = self._client.blpop(queue, timeout=timeout)
        if result is None:
            return None
        _, payload = result
        return payload

    def push(self, queue: str, payload: str) -> None:
        self._client.rpush(queue, payload)


def process_job(
    job: SqlmapJob,
    config: WorkerConfig,
    queue: Optional[RedisQueue] = None,
    runner: Optional[Callable[..., subprocess.CompletedProcess[str]]] = None,
) -> None:
    runner = runner or (lambda cmd: subprocess.run(cmd, capture_output=True, text=True, check=False))
    command = build_sqlmap_command(job, config)

    try:
        result = runner(command)
    except OSError as exc:
        LOG.exception("Failed to execute SQLMap for job %s", job.job_id)
        raise RetryableJobError(f"failed to launch sqlmap: {exc}") from exc

    stdout = getattr(result, "stdout", "") or ""
    stderr = getattr(result, "stderr", "") or ""
    status_code = getattr(result, "returncode", 1)

    records: List[Dict[str, Any]] = []
    if stdout.strip():
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as exc:
            LOG.error("Invalid SQLMap output for job %s: %s", job.job_id, exc)
            raise RetryableJobError(f"invalid sqlmap output: {exc}") from exc
        data_records = payload.get("vulnerabilities")
        if isinstance(data_records, list):
            records = [item for item in data_records if isinstance(item, dict)]

    findings = normalize_vulnerabilities(records, job)
    callback_payload: Dict[str, Any] = {
        "scan_id": job.scan_id,
        "status": "completed" if status_code == 0 else "failed",
        "findings": findings,
    }
    if status_code != 0:
        callback_payload["error"] = (
            f"sqlmap exited with status {status_code}; stderr length={len(stderr)}"
        )

    post_callback(job, config, callback_payload)


def consume_forever(config: WorkerConfig) -> None:  # pragma: no cover - integration exercised elsewhere
    queue = RedisQueue(config.redis_url)
    LOG.info("Starting SQLMap worker; queue=%s", config.queue_key)
    while True:
        serialized = queue.pop(config.queue_key, config.poll_timeout)
        if serialized is None:
            continue

        try:
            job = SqlmapJob.from_json(serialized)
        except FatalJobError as exc:
            LOG.error("Discarding malformed job: %s", exc)
            queue.push(config.dead_letter_key, serialized)
            continue

        try:
            process_job(job, config, queue=queue)
        except RetryableJobError as exc:
            LOG.warning("Retryable error for job %s: %s", job.job_id, exc)
            job.attempts += 1
            if job.attempts > config.max_retries:
                LOG.error("Exceeded retries for job %s; moving to dead letter", job.job_id)
                queue.push(config.dead_letter_key, serialized)
            else:
                time.sleep(min(5, job.attempts))
                try:
                    payload = json.loads(serialized)
                except json.JSONDecodeError:
                    queue.push(config.queue_key, serialized)
                else:
                    if isinstance(payload, dict):
                        payload["attempts"] = job.attempts
                        serialized = json.dumps(payload, sort_keys=True)
                    queue.push(config.queue_key, serialized)
        except FatalJobError as exc:
            LOG.error("Fatal error for job %s: %s", job.job_id, exc)
            queue.push(config.dead_letter_key, serialized)


def main() -> None:  # pragma: no cover - manual execution only
    logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s %(name)s: %(message)s")
    config = WorkerConfig.load()
    consume_forever(config)


__all__ = [
    "ALLOWED_SQLMAP_FLAGS",
    "SqlmapJob",
    "WorkerConfig",
    "build_sqlmap_command",
    "normalize_vulnerabilities",
    "process_job",
    "post_callback",
    "consume_forever",
    "RedisQueue",
]
