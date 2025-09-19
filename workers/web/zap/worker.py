"""ZAP worker for the Medusa scanning pipeline.

This worker is intentionally small and auditable. It dequeues scan
instructions from Redis, executes the hardened OWASP ZAP baseline wrapper,
and reports normalized findings back to the controller. Only a constrained set
of command-line flags are used to reduce the risk of arbitrary execution when
running in multi-tenant environments.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

try:  # Redis is optional during unit tests.
    import redis
except ImportError:  # pragma: no cover - redis is optional in tests.
    redis = None  # type: ignore

try:
    import requests
    from requests import Session
    from requests.exceptions import RequestException
except ImportError:  # pragma: no cover - requests is optional in tests.
    requests = None  # type: ignore

    class Session:  # type: ignore
        def post(self, *args, **kwargs):  # pragma: no cover - placeholder
            raise RuntimeError("requests is required to post callbacks")

    class RequestException(Exception):
        pass


LOG = logging.getLogger("medusa.workers.web.zap")

ALLOWED_ZAP_POLICIES: Tuple[str, ...] = ("baseline", "full")
ALLOWED_ZAP_MODES: Tuple[str, ...] = ("baseline", "full")
ALLOWED_ZAP_FLAGS: Tuple[str, ...] = (
    "-cmd",
    "-addonupdate",
    "-quickprogress",
    "-quickurl",
    "-quickout",
    "-policy",
    "-include",
    "-exclude",
    "-ajaxspider",
)

ZAP_RISK_TO_SEVERITY: Dict[str, str] = {
    "0": "info",
    "1": "low",
    "2": "medium",
    "3": "high",
}


class RetryableJobError(Exception):
    """Raised when a job should be retried after a short delay."""


class FatalJobError(Exception):
    """Raised when a job should be sent to the dead-letter queue."""


@dataclass
class WorkerConfig:
    """Runtime configuration sourced from environment variables."""

    redis_url: str = field(default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    queue_key: str = field(default_factory=lambda: os.getenv("ZAP_QUEUE_KEY", "queues:zap:jobs"))
    dead_letter_key: str = field(default_factory=lambda: os.getenv("ZAP_DEAD_LETTER_KEY", "queues:zap:dead"))
    zap_binary: str = field(default_factory=lambda: os.getenv("ZAP_BINARY", "zap-baseline.py"))
    poll_timeout: int = field(default_factory=lambda: int(os.getenv("ZAP_POLL_TIMEOUT", "5")))
    max_retries: int = field(default_factory=lambda: int(os.getenv("ZAP_MAX_RETRIES", "3")))
    callback_timeout: int = field(default_factory=lambda: int(os.getenv("ZAP_CALLBACK_TIMEOUT", "30")))
    verify_tls: bool = field(default_factory=lambda: os.getenv("ZAP_CALLBACK_VERIFY_TLS", "true").lower() != "false")
    callback_token: str = field(
        default_factory=lambda: os.getenv("ZAP_CALLBACK_TOKEN")
        or os.getenv("MEDUSA_ZAP_CALLBACK_TOKEN", "")
    )
    work_dir: str = field(default_factory=lambda: os.getenv("ZAP_WORK_DIR", "/tmp/zap"))

    @classmethod
    def load(cls) -> "WorkerConfig":
        config = cls()
        LOG.debug("Loaded ZAP worker configuration: %s", config)
        return config


@dataclass
class ZapJob:
    """Normalized job payload produced by the controller."""

    job_id: str
    scan_id: str
    target: str
    callback_url: str
    scanner: str = "zap"
    parameters: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    attempts: int = 0
    target_id: Optional[str] = None
    target_name: Optional[str] = None

    @classmethod
    def from_json(cls, payload: str) -> "ZapJob":
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
            for item in raw_tags:
                if isinstance(item, str) and item.strip():
                    tags.append(item.strip())

        metadata = data.get("metadata") or {}
        if not isinstance(metadata, dict):
            metadata = {}

        attempts_value = data.get("attempts", 0)
        try:
            attempts = int(attempts_value)
        except (ValueError, TypeError):
            attempts = 0

        scanner = str(data.get("scanner") or "zap").strip() or "zap"
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


def build_zap_command(job: ZapJob, config: WorkerConfig) -> List[str]:
    """Return a hardened OWASP ZAP command for the given job."""

    os.makedirs(config.work_dir, exist_ok=True)
    report_path = os.path.join(config.work_dir, f"{job.job_id}.json")

    command: List[str] = [
        config.zap_binary,
        "-cmd",
        "-addonupdate",
        "-quickprogress",
        "-quickurl",
        job.target,
        "-quickout",
        report_path,
    ]

    policy = str(job.parameters.get("policy") or "").strip().lower()
    if policy in ALLOWED_ZAP_POLICIES:
        command.extend(["-policy", policy])

    mode = str(job.parameters.get("mode") or "").strip().lower()
    if mode in ALLOWED_ZAP_MODES and mode == "full":
        command.append("-ajaxspider")

    include_paths = job.parameters.get("include_paths")
    if isinstance(include_paths, Sequence) and not isinstance(include_paths, (str, bytes, bytearray)):
        for path in include_paths:
            if path:
                command.extend(["-include", str(path)])

    exclude_paths = job.parameters.get("exclude_paths")
    if isinstance(exclude_paths, Sequence) and not isinstance(exclude_paths, (str, bytes, bytearray)):
        for path in exclude_paths:
            if path:
                command.extend(["-exclude", str(path)])

    for index, arg in enumerate(command):
        if index == 0:
            continue
        if isinstance(arg, str) and arg.startswith("-") and arg not in ALLOWED_ZAP_FLAGS:
            raise FatalJobError(f"unsupported zap flag requested: {arg}")

    return command


def _extract_alerts(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    if not payload:
        return alerts

    if isinstance(payload.get("alerts"), list):
        alerts.extend(payload.get("alerts", []))
        return alerts

    sites = payload.get("site")
    if isinstance(sites, list):
        for site in sites:
            if isinstance(site, dict):
                site_alerts = site.get("alerts")
                if isinstance(site_alerts, list):
                    alerts.extend(site_alerts)
    return alerts


def normalize_alerts(records: Iterable[Dict[str, Any]], job: ZapJob) -> List[Dict[str, Any]]:
    """Normalize raw ZAP alerts into controller callback payloads."""

    findings: List[Dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        title = str(record.get("alert") or record.get("name") or "ZAP finding")
        risk_code = str(record.get("riskcode") or record.get("riskCode") or "").strip()
        severity = ZAP_RISK_TO_SEVERITY.get(risk_code)
        if severity is None:
            risk_desc = str(record.get("riskdesc") or record.get("riskDesc") or "").lower()
            if "high" in risk_desc:
                severity = "high"
            elif "medium" in risk_desc:
                severity = "medium"
            elif "low" in risk_desc:
                severity = "low"
            else:
                severity = "info"

        description = record.get("description") or record.get("desc")
        if not isinstance(description, str) or not description.strip():
            description = (
                f"OWASP ZAP reported a {severity} issue for {job.target} using policy "
                f"{job.parameters.get('policy', 'baseline')}"
            )

        instances = record.get("instances")
        instance = instances[0] if isinstance(instances, list) and instances else {}
        evidence_source = {
            "uri": instance.get("uri"),
            "method": instance.get("method"),
            "evidence": instance.get("evidence"),
            "param": instance.get("param"),
            "attack": instance.get("attack"),
        }
        evidence = {k: v for k, v in evidence_source.items() if v}

        plugin_id = record.get("pluginid") or record.get("pluginId")
        if plugin_id:
            rule_id = f"zap:{plugin_id}"
        else:
            rule_id = "zap:" + title.lower().replace(" ", "-")

        cve_id = record.get("cveid") or record.get("cveId")
        if isinstance(cve_id, list):
            cve_id = next((str(item) for item in cve_id if item), None)
        elif cve_id is not None:
            cve_id = str(cve_id)

        raw_tags = record.get("tags")
        alert_tags: List[str] = []
        if isinstance(raw_tags, Sequence) and not isinstance(raw_tags, (str, bytes, bytearray)):
            for tag in raw_tags:
                if isinstance(tag, str) and tag.strip():
                    alert_tags.append(tag.strip())

        metadata = {
            "scanner": job.scanner or "zap",
            "policy": job.parameters.get("policy"),
            "mode": job.parameters.get("mode"),
            "rule_id": rule_id,
            "plugin_id": plugin_id,
            "cwe_id": record.get("cweid") or record.get("cweId"),
            "wasc_id": record.get("wascid") or record.get("wascId"),
            "tags": sorted({*job.tags, *alert_tags}),
        }

        findings.append(
            {
                "title": title,
                "severity": severity,
                "description": str(description),
                "cve_id": cve_id,
                "metadata": {k: v for k, v in metadata.items() if v},
                "evidence": evidence,
                "artifacts": [],
            }
        )

    return findings


def post_callback(
    job: ZapJob,
    config: WorkerConfig,
    payload: Dict[str, Any],
    session: Optional[Session] = None,
) -> None:
    """Deliver scan results back to the controller callback endpoint."""

    if session is None:
        if requests is None:  # pragma: no cover - requests optional during tests
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
        LOG.error("ZAP callback failed for job %s: %s", job.job_id, exc)
        raise RetryableJobError(f"callback failed: {exc}") from exc


class RedisQueue:
    """Minimal Redis-backed queue implementation used by the worker."""

    def __init__(self, redis_url: str) -> None:
        if redis is None:  # pragma: no cover - exercised in integration tests
            raise RuntimeError("redis package is required to run the worker")
        self._client = redis.Redis.from_url(redis_url, encoding="utf-8", decode_responses=True)

    @property
    def client(self):  # pragma: no cover - trivial
        return self._client

    def pop(self, queue: str, timeout: int) -> Optional[str]:
        result = self._client.blpop(queue, timeout=timeout)
        if result is None:
            return None
        _, payload = result
        return payload

    def push(self, queue: str, payload: str) -> None:
        self._client.rpush(queue, payload)


def process_job(
    job: ZapJob,
    config: WorkerConfig,
    queue: Optional[RedisQueue] = None,
    runner: Optional[Callable[..., subprocess.CompletedProcess[str]]] = None,
) -> None:
    """Execute ZAP for the supplied job and post normalized findings."""

    runner = runner or (lambda cmd: subprocess.run(cmd, capture_output=True, text=True, check=False))
    command = build_zap_command(job, config)

    try:
        result = runner(command)
    except OSError as exc:
        LOG.exception("Failed to execute ZAP for job %s", job.job_id)
        raise RetryableJobError(f"failed to launch zap: {exc}") from exc

    stdout = getattr(result, "stdout", "") or ""
    stderr = getattr(result, "stderr", "") or ""
    status_code = getattr(result, "returncode", 1)

    alerts_payload: Dict[str, Any]
    try:
        alerts_payload = json.loads(stdout) if stdout.strip() else {}
    except json.JSONDecodeError as exc:
        LOG.error("Invalid ZAP output for job %s: %s", job.job_id, exc)
        raise RetryableJobError(f"invalid zap output: {exc}") from exc

    alerts = _extract_alerts(alerts_payload)
    findings = normalize_alerts(alerts, job)

    callback_payload: Dict[str, Any] = {
        "scan_id": job.scan_id,
        "status": "completed" if status_code == 0 else "failed",
        "findings": findings,
    }
    if status_code != 0:
        callback_payload["error"] = (
            f"zap exited with status {status_code}; stderr length={len(stderr)}"
        )

    post_callback(job, config, callback_payload)


def consume_forever(config: WorkerConfig) -> None:  # pragma: no cover - integration exercised elsewhere
    """Continuously consume jobs from Redis and execute ZAP."""

    queue = RedisQueue(config.redis_url)
    LOG.info("Starting ZAP worker; queue=%s", config.queue_key)
    while True:
        serialized = queue.pop(config.queue_key, config.poll_timeout)
        if serialized is None:
            continue

        try:
            job = ZapJob.from_json(serialized)
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
    "ALLOWED_ZAP_FLAGS",
    "ALLOWED_ZAP_POLICIES",
    "WorkerConfig",
    "ZapJob",
    "build_zap_command",
    "normalize_alerts",
    "post_callback",
    "process_job",
    "consume_forever",
    "RedisQueue",
]
