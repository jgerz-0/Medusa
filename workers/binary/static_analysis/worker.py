"""Entry point for the binary static analysis worker."""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import tempfile
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Tuple

try:  # pragma: no cover - redis optional during unit tests
    import redis
except Exception:  # pragma: no cover
    redis = None  # type: ignore[assignment]

try:  # pragma: no cover - requests optional during unit tests
    import requests
    from requests import Session
    from requests.exceptions import RequestException
except Exception:  # pragma: no cover
    requests = None  # type: ignore[assignment]

    class Session:  # type: ignore[no-redef]
        """Fallback session used when requests is unavailable under tests."""

        def post(self, *args, **kwargs):  # pragma: no cover - sanity guard
            raise RuntimeError("requests library is required for callback delivery")

    class RequestException(Exception):  # type: ignore[no-redef]
        pass


from workers.binary.preprocess.storage import (  # noqa: E402  - local import for optional boto3
    ObjectStorageClient,
    S3ObjectStorageClient,
)

from .runtime import ContainerRunner, RuntimeConfig
from .schemas import (
    AnalysisArtifact,
    AnalysisFinding,
    AnalysisToolReport,
    StaticAnalysisJob,
    StaticAnalysisResult,
)

LOG = logging.getLogger("medusa.workers.binary.static_analysis")

CHECKSEC_TOOL = "checksec"
BANDIT_TOOL = "bandit"

ALLOWED_CHECKSEC_STATES: Mapping[str, Tuple[str, str]] = {
    "no": ("high", "Feature disabled"),
    "none": ("high", "Feature disabled"),
    "disabled": ("high", "Feature disabled"),
    "partial": ("medium", "Feature partially enabled"),
    "warning": ("medium", "Potentially misconfigured"),
}


@dataclass
class WorkerConfig:
    """Runtime configuration sourced from environment variables."""

    redis_url: str = field(
        default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0")
    )
    queue_key: str = field(
        default_factory=lambda: os.getenv(
            "BINARY_STATIC_ANALYSIS_QUEUE_KEY", "queues:binary:static-analysis"
        )
    )
    dead_letter_key: str = field(
        default_factory=lambda: os.getenv(
            "BINARY_STATIC_ANALYSIS_DEAD_LETTER_KEY",
            "queues:binary:static-analysis:dead",
        )
    )
    poll_timeout: int = field(
        default_factory=lambda: int(
            os.getenv("BINARY_STATIC_ANALYSIS_POLL_TIMEOUT", "5")
        )
    )
    max_attempts: int = field(
        default_factory=lambda: int(
            os.getenv("BINARY_STATIC_ANALYSIS_MAX_ATTEMPTS", "3")
        )
    )
    container_runtime: str = field(
        default_factory=lambda: os.getenv("BINARY_STATIC_ANALYSIS_RUNTIME", "docker")
    )
    container_flags: Tuple[str, ...] = field(
        default_factory=lambda: _split_flags(
            os.getenv("BINARY_STATIC_ANALYSIS_RUNTIME_FLAGS", "")
        )
    )
    checksec_image: str = field(
        default_factory=lambda: os.getenv(
            "BINARY_STATIC_ANALYSIS_CHECKSEC_IMAGE",
            "docker.io/medusa/checksec:latest",
        )
    )
    bandit_image: str = field(
        default_factory=lambda: os.getenv(
            "BINARY_STATIC_ANALYSIS_BANDIT_IMAGE",
            "docker.io/medusa/bandit:latest",
        )
    )
    enable_checksec: bool = field(
        default_factory=lambda: os.getenv("BINARY_STATIC_ANALYSIS_ENABLE_CHECKSEC", "1")
        not in {"0", "false", "False"}
    )
    enable_bandit: bool = field(
        default_factory=lambda: os.getenv("BINARY_STATIC_ANALYSIS_ENABLE_BANDIT", "1")
        not in {"0", "false", "False"}
    )
    analysis_bucket: Optional[str] = field(
        default_factory=lambda: os.getenv("BINARY_ANALYSIS_BUCKET")
    )
    analysis_prefix: str = field(
        default_factory=lambda: os.getenv("BINARY_ANALYSIS_PREFIX", "analysis/reports/")
    )
    s3_endpoint_url: Optional[str] = field(
        default_factory=lambda: os.getenv("S3_ENDPOINT_URL")
    )
    s3_access_key: Optional[str] = field(
        default_factory=lambda: os.getenv("S3_ACCESS_KEY_ID")
        or os.getenv("AWS_ACCESS_KEY_ID")
    )
    s3_secret_key: Optional[str] = field(
        default_factory=lambda: os.getenv("S3_SECRET_ACCESS_KEY")
        or os.getenv("AWS_SECRET_ACCESS_KEY")
    )
    s3_region: Optional[str] = field(
        default_factory=lambda: os.getenv("AWS_DEFAULT_REGION")
    )
    callback_token: Optional[str] = field(
        default_factory=lambda: os.getenv("BINARY_STATIC_ANALYSIS_CALLBACK_TOKEN")
    )
    tool_timeout_seconds: int = field(
        default_factory=lambda: int(
            os.getenv("BINARY_STATIC_ANALYSIS_TOOL_TIMEOUT", "120")
        )
    )

    @classmethod
    def load(cls) -> "WorkerConfig":
        config = cls()
        LOG.debug("Loaded static analysis worker config", extra={"config": config})
        return config

    def runtime_config(self) -> RuntimeConfig:
        return RuntimeConfig(binary=self.container_runtime)


def _split_flags(raw: Optional[str]) -> Tuple[str, ...]:
    if not raw:
        return tuple()
    tokens = [token.strip() for token in raw.split() if token.strip()]
    return tuple(tokens)


@dataclass
class QueuedJob:
    job: StaticAnalysisJob
    attempts: int
    raw_payload: str


class RedisJobQueue:
    """Redis-backed queue for static analysis jobs."""

    def __init__(self, config: WorkerConfig, *, connection=None) -> None:
        if connection is None:
            if redis is None:  # pragma: no cover - runtime dependency validation
                raise RuntimeError(
                    "redis-py is required for the static analysis worker"
                )
            connection = redis.Redis.from_url(config.redis_url, decode_responses=True)
        self._client = connection
        self._config = config

    def fetch(self) -> Optional[QueuedJob]:
        response = self._client.blpop(
            self._config.queue_key, timeout=self._config.poll_timeout
        )
        if not response:
            return None
        _, payload = response
        try:
            return self._deserialize(payload)
        except Exception as exc:  # pragma: no cover - defensive logging
            LOG.exception("Failed to deserialize static analysis job: %s", exc)
            self.dead_letter_raw(payload, reason="deserialization_error")
            return None

    def dead_letter(
        self, queued_job: QueuedJob, reason: str, error: Optional[str] = None
    ) -> None:
        payload = {
            "status": "failed",
            "job": queued_job.job.model_dump(mode="json"),
            "attempts": queued_job.attempts,
            "reason": reason,
            "error": error,
            "dead_lettered_at": datetime.now(tz=timezone.utc).isoformat(),
        }
        self._client.rpush(self._config.dead_letter_key, json.dumps(payload))

    def dead_letter_raw(self, raw_payload: str, reason: str) -> None:
        payload = {
            "status": "failed",
            "raw": raw_payload,
            "reason": reason,
            "dead_lettered_at": datetime.now(tz=timezone.utc).isoformat(),
        }
        self._client.rpush(self._config.dead_letter_key, json.dumps(payload))

    def _deserialize(self, payload: str) -> QueuedJob:
        document = json.loads(payload)
        attempts = int(document.get("attempts", 0))
        job = StaticAnalysisJob.model_validate(document)
        return QueuedJob(job=job, attempts=attempts, raw_payload=payload)


class CallbackClient:
    """HTTP client responsible for delivering callback payloads."""

    def __init__(self, token: Optional[str], *, timeout: int = 30) -> None:
        self._token = token
        self._timeout = timeout

    def post(self, url: str, payload: Mapping[str, object]) -> None:
        if requests is None:  # pragma: no cover - optional dependency guard
            raise RuntimeError("requests library unavailable for callback delivery")
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["X-Callback-Token"] = self._token
        session: Session = requests.Session()
        try:
            response = session.post(
                url, json=payload, headers=headers, timeout=self._timeout
            )
        except RequestException as exc:  # pragma: no cover - network errors
            raise RuntimeError(f"Failed to POST callback: {exc}") from exc
        if response.status_code >= 400:
            raise RuntimeError(
                f"Callback rejected with status {response.status_code}: {response.text}"
            )


class ArtifactStorage:
    """Wrapper persisting tool outputs into MinIO/S3."""

    def __init__(
        self, client: ObjectStorageClient, *, default_bucket: Optional[str], prefix: str
    ) -> None:
        self._client = client
        self._default_bucket = default_bucket
        self._prefix = prefix.rstrip("/") + "/" if prefix else ""

    def persist(
        self, job: StaticAnalysisJob, tool: str, payload: Mapping[str, object]
    ) -> AnalysisArtifact:
        bucket = self._default_bucket or job.object_bucket
        suffix = uuid.uuid4().hex
        key = f"{self._prefix}{job.sample_id}/{tool}-{suffix}.json"
        self._client.put_json(bucket, key, dict(payload))
        return AnalysisArtifact(tool=tool, bucket=bucket, key=key)

    def fetch_original(self, bucket: str, key: str) -> bytes:
        """Download the original binary or source archive."""

        return self._client.fetch(bucket, key)


class StaticAnalysisProcessor:
    """Coordinate downloads, tool execution, and callback publishing."""

    def __init__(
        self,
        config: WorkerConfig,
        *,
        runner: ContainerRunner,
        storage: ArtifactStorage,
        callback: CallbackClient,
    ) -> None:
        self._config = config
        self._runner = runner
        self._storage = storage
        self._callback = callback

    def process(self, queued_job: QueuedJob) -> None:
        job = queued_job.job
        LOG.info(
            "Processing static analysis job",
            extra={"job_id": job.job_id, "sample_id": job.sample_id},
        )
        result = StaticAnalysisResult(
            status="completed",
            job_id=job.job_id,
            scan_id=job.scan_id,
            sample_id=job.sample_id,
            processed_at=datetime.now(tz=timezone.utc),
            metadata=dict(job.metadata or {}),
        )
        reports: List[AnalysisToolReport] = []

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                local_path = self._download_artifact(job, Path(temp_dir))
                if self._config.enable_checksec:
                    reports.append(self._run_checksec(job, local_path))
                if self._config.enable_bandit:
                    reports.append(self._run_bandit(job, Path(temp_dir)))
        except Exception as exc:
            LOG.exception("Static analysis execution failed: %s", exc)
            result.status = "failed"
            result.error = str(exc)
        else:
            for report in reports:
                result.reports.append(report)
                if report.artifact:
                    result.artifacts.append(report.artifact)
                result.findings.extend(report.findings)

        payload = result.model_dump(mode="json")
        try:
            self._callback.post(job.callback_url, payload)
            LOG.info("Published static analysis callback", extra={"job_id": job.job_id})
        except Exception as exc:
            LOG.exception("Failed to deliver callback for job %s", job.job_id)
            raise RuntimeError(str(exc))

    def _download_artifact(self, job: StaticAnalysisJob, destination: Path) -> Path:
        data = self._storage.fetch_original(job.object_bucket, job.object_key)
        filename = job.file_name or Path(job.object_key).name
        local_path = destination / filename
        local_path.write_bytes(data)
        return local_path

    def _run_checksec(
        self, job: StaticAnalysisJob, local_path: Path
    ) -> AnalysisToolReport:
        mount_dir = local_path.parent
        command = [
            "checksec",
            "--file",
            f"/workspace/{local_path.name}",
            "--format",
            "json",
        ]
        completed = self._runner.run(
            self._config.checksec_image,
            command,
            mounts={mount_dir: "/workspace:ro"},
            extra_flags=self._config.container_flags,
            timeout=self._config.tool_timeout_seconds,
        )
        raw_output = self._safe_json_loads(completed.stdout)
        findings = self._interpret_checksec(
            raw_output, executed_at=datetime.now(tz=timezone.utc)
        )
        artifact = self._storage.persist(
            job,
            CHECKSEC_TOOL,
            {
                "tool": CHECKSEC_TOOL,
                "exit_code": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "raw": raw_output,
            },
        )
        for finding in findings:
            finding.artifact_bucket = artifact.bucket
            finding.artifact_key = artifact.key
        status = "completed" if completed.returncode == 0 else "failed"
        report = AnalysisToolReport(
            tool=CHECKSEC_TOOL,
            status=status,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            raw_output=raw_output,
            findings=findings,
            artifact=artifact,
            executed_at=datetime.now(tz=timezone.utc),
        )
        if status == "failed":
            LOG.warning(
                "checksec exited with non-zero status",
                extra={"job_id": job.job_id, "exit_code": completed.returncode},
            )
        return report

    def _run_bandit(
        self, job: StaticAnalysisJob, mount_dir: Path
    ) -> AnalysisToolReport:
        command = ["bandit", "-r", "/workspace", "-f", "json", "-q"]
        completed = self._runner.run(
            self._config.bandit_image,
            command,
            mounts={mount_dir: "/workspace:ro"},
            extra_flags=self._config.container_flags,
            timeout=self._config.tool_timeout_seconds,
        )
        raw_output = self._safe_json_loads(completed.stdout)
        findings = self._interpret_bandit(
            raw_output, executed_at=datetime.now(tz=timezone.utc)
        )
        artifact = self._storage.persist(
            job,
            BANDIT_TOOL,
            {
                "tool": BANDIT_TOOL,
                "exit_code": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "raw": raw_output,
            },
        )
        for finding in findings:
            finding.artifact_bucket = artifact.bucket
            finding.artifact_key = artifact.key
        status = "completed" if completed.returncode == 0 else "failed"
        report = AnalysisToolReport(
            tool=BANDIT_TOOL,
            status=status,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            raw_output=raw_output,
            findings=findings,
            artifact=artifact,
            executed_at=datetime.now(tz=timezone.utc),
        )
        if status == "failed":
            LOG.warning(
                "bandit exited with non-zero status",
                extra={"job_id": job.job_id, "exit_code": completed.returncode},
            )
        return report

    @staticmethod
    def _safe_json_loads(content: str) -> Dict[str, object]:
        try:
            return json.loads(content) if content else {}
        except json.JSONDecodeError:
            return {"unparsed": content}

    def _interpret_checksec(
        self, payload: Mapping[str, object], *, executed_at: datetime
    ) -> List[AnalysisFinding]:
        checks = payload.get("checks") or payload.get("checksec")
        if not isinstance(checks, Mapping):
            return []
        findings: List[AnalysisFinding] = []
        for name, raw_value in checks.items():
            if not isinstance(raw_value, str):
                continue
            normalized = raw_value.strip().lower()
            if normalized in {"yes", "enabled", "full", "present"}:
                continue
            severity, description = ALLOWED_CHECKSEC_STATES.get(
                normalized, ("low", "Unexpected state")
            )
            findings.append(
                AnalysisFinding(
                    tool=CHECKSEC_TOOL,
                    severity=severity,  # type: ignore[arg-type]
                    title=f"{CHECKSEC_TOOL}: {name} not fully enabled",
                    description=description,
                    metadata={"feature": name, "state": raw_value},
                    evidence={"raw": payload},
                    artifact_bucket=None,
                    artifact_key=None,
                    executed_at=executed_at,
                )
            )
        return findings

    def _interpret_bandit(
        self, payload: Mapping[str, object], *, executed_at: datetime
    ) -> List[AnalysisFinding]:
        results = payload.get("results")
        if not isinstance(results, Iterable):
            return []
        findings: List[AnalysisFinding] = []
        for item in results:
            if not isinstance(item, Mapping):
                continue
            severity = str(item.get("issue_severity", "LOW")).lower()
            issue_text = str(item.get("issue_text", ""))
            test_id = str(item.get("test_id", "unknown"))
            path = str(item.get("filename", ""))
            title = f"bandit {test_id} finding"
            description = issue_text or "bandit flagged a potential security issue"
            metadata = {
                "filename": path,
                "line_number": item.get("line_number"),
                "confidence": item.get("issue_confidence"),
                "test_id": test_id,
            }
            evidence = {
                "code": item.get("code"),
                "more_info": item.get("more_info"),
            }
            findings.append(
                AnalysisFinding(
                    tool=BANDIT_TOOL,
                    severity=(
                        severity
                        if severity in {"info", "low", "medium", "high", "critical"}
                        else "low"
                    ),
                    title=title,
                    description=description,
                    metadata=metadata,
                    evidence=evidence,
                    artifact_bucket=None,
                    artifact_key=None,
                    executed_at=executed_at,
                )
            )
        return findings


class Worker:
    """Main worker loop orchestrating queue polling and job execution."""

    def __init__(self, config: WorkerConfig) -> None:
        self._config = config
        self._shutdown_event = threading.Event()
        runtime_config = config.runtime_config()
        runtime_config.base_flags = tuple(
            runtime_config.base_flags
        )  # ensure tuple for validation
        self._runner = ContainerRunner(runtime_config)
        self._queue = RedisJobQueue(config)
        self._storage = ArtifactStorage(
            self._build_storage_client(config),
            default_bucket=config.analysis_bucket,
            prefix=config.analysis_prefix,
        )
        self._callback = CallbackClient(config.callback_token)
        self._processor = StaticAnalysisProcessor(
            config,
            runner=self._runner,
            storage=self._storage,
            callback=self._callback,
        )

    def _build_storage_client(self, config: WorkerConfig) -> ObjectStorageClient:
        return S3ObjectStorageClient(
            endpoint_url=config.s3_endpoint_url,
            access_key=config.s3_access_key,
            secret_key=config.s3_secret_key,
            region_name=config.s3_region,
        )

    def run(self) -> None:
        LOG.info("Static analysis worker starting")
        while not self._shutdown_event.is_set():
            queued_job = self._queue.fetch()
            if not queued_job:
                continue
            try:
                self._processor.process(queued_job)
            except Exception as exc:
                LOG.exception("Job %s failed: %s", queued_job.job.job_id, exc)
                self._queue.dead_letter(
                    queued_job, reason="processing_error", error=str(exc)
                )

    def shutdown(self) -> None:
        self._shutdown_event.set()


def _install_signal_handlers(worker: Worker) -> None:
    def _handle_signal(
        signum, frame
    ):  # pragma: no cover - signal handling not exercised in unit tests
        LOG.info("Received signal %s, shutting down", signum)
        worker.shutdown()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Medusa binary static analysis worker")
    parser.add_argument(
        "--once",
        dest="job_file",
        help="Execute a single job from the provided JSON file and exit.",
    )
    return parser.parse_args(argv)


def run_single_job(config: WorkerConfig, job_file: Path) -> None:
    payload = json.loads(job_file.read_text())
    job = StaticAnalysisJob.model_validate(payload)
    queued = QueuedJob(
        job=job, attempts=payload.get("attempts", 0), raw_payload=job_file.read_text()
    )
    runtime_config = config.runtime_config()
    worker = StaticAnalysisProcessor(
        config,
        runner=ContainerRunner(runtime_config),
        storage=ArtifactStorage(
            S3ObjectStorageClient(
                endpoint_url=config.s3_endpoint_url,
                access_key=config.s3_access_key,
                secret_key=config.s3_secret_key,
                region_name=config.s3_region,
            ),
            default_bucket=config.analysis_bucket,
            prefix=config.analysis_prefix,
        ),
        callback=CallbackClient(config.callback_token),
    )
    worker.process(queued)


def main(argv: Optional[List[str]] = None) -> int:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    args = parse_args(argv)
    config = WorkerConfig.load()

    if args.job_file:
        run_single_job(config, Path(args.job_file))
        return 0

    worker = Worker(config)
    _install_signal_handlers(worker)
    try:
        worker.run()
    except KeyboardInterrupt:  # pragma: no cover - CLI convenience
        worker.shutdown()
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI invocation
    sys.exit(main())
