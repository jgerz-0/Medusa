"""Entry point for the angr symbolic execution worker."""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import tempfile
import threading
import time
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


from workers.binary.preprocess.storage import (  # noqa: E402 - local import for optional boto3
    ObjectStorageClient,
    S3ObjectStorageClient,
)
from workers.binary.static_analysis.runtime import ContainerRunner, RuntimeConfig

from .schemas import AngrArtifact, AngrExecutionReport, AngrFinding, AngrJob, AngrResult

LOG = logging.getLogger("medusa.workers.binary.angr")

ANGR_TOOL = "angr"


def _split_flags(raw: Optional[str]) -> Tuple[str, ...]:
    if not raw:
        return tuple()
    tokens = [token.strip() for token in raw.split() if token.strip()]
    return tuple(tokens)


def _split_command(raw: Optional[str]) -> Tuple[str, ...]:
    if not raw:
        return tuple()
    return tuple(token for token in raw.split() if token)


def _normalize_severity(value: Optional[str]) -> str:
    allowed = {"info", "low", "medium", "high", "critical"}
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in allowed:
            return lowered
    return "low"


def _coerce_datetime(value: Optional[str]) -> datetime:
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            LOG.debug("Failed to parse datetime", extra={"value": value})
    return datetime.now(tz=timezone.utc)


@dataclass
class WorkerConfig:
    """Runtime configuration sourced from environment variables."""

    redis_url: str = field(
        default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0")
    )
    queue_key: str = field(
        default_factory=lambda: os.getenv(
            "BINARY_SYMBOLIC_EXECUTION_QUEUE_KEY", "queues:binary:symbolic-execution"
        )
    )
    dead_letter_key: str = field(
        default_factory=lambda: os.getenv(
            "BINARY_SYMBOLIC_EXECUTION_DEAD_LETTER_KEY",
            "queues:binary:symbolic-execution:dead",
        )
    )
    poll_timeout: int = field(
        default_factory=lambda: int(os.getenv("BINARY_SYMBOLIC_EXECUTION_POLL_TIMEOUT", "5"))
    )
    max_attempts: int = field(
        default_factory=lambda: int(os.getenv("BINARY_SYMBOLIC_EXECUTION_MAX_ATTEMPTS", "3"))
    )
    container_runtime: str = field(
        default_factory=lambda: os.getenv("BINARY_SYMBOLIC_EXECUTION_RUNTIME", "docker")
    )
    container_flags: Tuple[str, ...] = field(
        default_factory=lambda: _split_flags(
            os.getenv("BINARY_SYMBOLIC_EXECUTION_RUNTIME_FLAGS", "")
        )
    )
    angr_image: str = field(
        default_factory=lambda: os.getenv(
            "BINARY_SYMBOLIC_EXECUTION_IMAGE", "docker.io/medusa/angr:latest"
        )
    )
    angr_command: Tuple[str, ...] = field(
        default_factory=lambda: _split_command(
            os.getenv("BINARY_SYMBOLIC_EXECUTION_COMMAND", "/opt/medusa/run_angr")
        )
    )
    analysis_bucket: Optional[str] = field(
        default_factory=lambda: os.getenv("BINARY_SYMBOLIC_EXECUTION_BUCKET")
    )
    analysis_prefix: str = field(
        default_factory=lambda: os.getenv(
            "BINARY_SYMBOLIC_EXECUTION_PREFIX", "analysis/symbolic/"
        )
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
        default_factory=lambda: os.getenv("BINARY_SYMBOLIC_EXECUTION_CALLBACK_TOKEN")
    )
    harness_timeout_seconds: int = field(
        default_factory=lambda: int(os.getenv("BINARY_SYMBOLIC_EXECUTION_TIMEOUT", "300"))
    )

    @classmethod
    def load(cls) -> "WorkerConfig":
        config = cls()
        LOG.debug("Loaded angr worker config", extra={"config": config})
        return config

    def runtime_config(self) -> RuntimeConfig:
        return RuntimeConfig(binary=self.container_runtime)


@dataclass
class QueuedJob:
    job: AngrJob
    attempts: int
    raw_payload: str


class RedisJobQueue:
    """Redis-backed queue for angr symbolic execution jobs."""

    def __init__(self, config: WorkerConfig, *, connection=None) -> None:
        if connection is None:
            if redis is None:  # pragma: no cover - runtime dependency validation
                raise RuntimeError(
                    "redis-py is required for the angr symbolic execution worker"
                )
            connection = redis.Redis.from_url(config.redis_url, decode_responses=True)
        self._client = connection
        self._config = config

    def fetch(self) -> Optional[QueuedJob]:
        response = self._client.blpop(self._config.queue_key, timeout=self._config.poll_timeout)
        if not response:
            return None
        _, payload = response
        try:
            return self._deserialize(payload)
        except Exception as exc:  # pragma: no cover - defensive logging
            LOG.exception("Failed to deserialize job payload", extra={"error": str(exc)})
            self.dead_letter_raw(payload, reason="deserialize_error", error=str(exc))
            return None

    def dead_letter(self, job: QueuedJob, *, reason: str, error: Optional[str] = None) -> None:
        document = json.loads(job.raw_payload)
        document["reason"] = reason
        document["error"] = error
        document["failed_at"] = datetime.now(tz=timezone.utc).isoformat()
        self._client.rpush(self._config.dead_letter_key, json.dumps(document))

    def dead_letter_raw(self, payload: str, *, reason: str, error: Optional[str] = None) -> None:
        document = json.loads(payload)
        document["reason"] = reason
        document["error"] = error
        document["failed_at"] = datetime.now(tz=timezone.utc).isoformat()
        self._client.rpush(self._config.dead_letter_key, json.dumps(document))

    def _deserialize(self, payload: str) -> QueuedJob:
        document = json.loads(payload)
        attempts = int(document.get("attempts", 0))
        job = AngrJob.model_validate(document)
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
            response = session.post(url, json=payload, headers=headers, timeout=self._timeout)
        except RequestException as exc:  # pragma: no cover - network errors
            raise RuntimeError(f"Failed to POST callback: {exc}") from exc
        if response.status_code >= 400:
            raise RuntimeError(
                f"Callback rejected with status {response.status_code}: {response.text}"
            )


class ArtifactStorage:
    """Wrapper persisting angr harness outputs into object storage."""

    def __init__(
        self, client: ObjectStorageClient, *, default_bucket: Optional[str], prefix: str
    ) -> None:
        self._client = client
        self._default_bucket = default_bucket
        self._prefix = prefix.rstrip("/") + "/" if prefix else ""

    def persist(self, job: AngrJob, name: str, payload: Mapping[str, object]) -> AngrArtifact:
        bucket = self._default_bucket or job.object_bucket
        suffix = uuid.uuid4().hex
        key = f"{self._prefix}{job.sample_id}/{name}-{suffix}.json"
        self._client.put_json(bucket, key, dict(payload))
        return AngrArtifact(tool=name, bucket=bucket, key=key)

    def fetch_original(self, bucket: str, key: str) -> bytes:
        return self._client.fetch(bucket, key)


class AngrAnalysisProcessor:
    """Coordinate artifact download, harness execution, and callback publishing."""

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
            "Processing angr job",
            extra={"job_id": job.job_id, "sample_id": job.sample_id},
        )
        result = AngrResult(
            status="completed",
            job_id=job.job_id,
            scan_id=job.scan_id,
            sample_id=job.sample_id,
            processed_at=datetime.now(tz=timezone.utc),
            metadata=dict(job.metadata or {}),
        )

        start_time = time.perf_counter()
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                local_path = self._download_artifact(job, Path(temp_dir))
                report = self._run_angr(job, local_path)
        except Exception as exc:
            LOG.exception("Symbolic execution failed", extra={"job_id": job.job_id})
            result.status = "failed"
            result.error = str(exc)
        else:
            report.duration_seconds = max(time.perf_counter() - start_time, 0.0)
            result.reports.append(report)
            result.metadata.update(report.raw_output.get("metadata", {}))
            findings, artifacts = self._interpret_output(job, report.raw_output)
            for artifact in artifacts:
                result.artifacts.append(artifact)
            for finding in findings:
                result.findings.append(finding)
            harness_status = report.raw_output.get("status")
            if harness_status in {"completed", "failed"}:
                result.status = harness_status  # type: ignore[assignment]
            if report.raw_output.get("error"):
                result.error = str(report.raw_output["error"])
            if report.status == "failed" and result.status != "failed":
                result.status = "failed"
                if not result.error:
                    result.error = (
                        f"angr exited with status {report.exit_code}"  # pragma: no cover
                    )

        payload = result.model_dump(mode="json")
        try:
            self._callback.post(job.callback_url, payload)
            LOG.info("Published symbolic execution callback", extra={"job_id": job.job_id})
        except Exception as exc:
            LOG.exception("Failed to deliver callback for job %s", job.job_id)
            raise RuntimeError(str(exc))

    def _download_artifact(self, job: AngrJob, destination: Path) -> Path:
        data = self._storage.fetch_original(job.object_bucket, job.object_key)
        filename = job.file_name or Path(job.object_key).name
        local_path = destination / filename
        local_path.write_bytes(data)
        return local_path

    def _build_environment(self, job: AngrJob, local_path: Path) -> Dict[str, str]:
        environment = {
            "ANGR_INPUT_PATH": f"/workspace/{local_path.name}",
            "ANGR_JOB_ID": job.job_id,
            "ANGR_SCAN_ID": job.scan_id,
            "ANGR_SAMPLE_ID": job.sample_id,
            "ANGR_TARGET_ID": job.target_id,
        }
        if job.metadata:
            environment["ANGR_JOB_METADATA"] = json.dumps(job.metadata, sort_keys=True)
        analysis_depth = job.metadata.get("analysis_depth") if isinstance(job.metadata, dict) else None
        if isinstance(analysis_depth, int):
            environment["ANGR_ANALYSIS_DEPTH"] = str(analysis_depth)
        timeout_override = job.metadata.get("timeout_seconds") if isinstance(job.metadata, dict) else None
        if isinstance(timeout_override, int):
            environment["ANGR_TIMEOUT_SECONDS"] = str(timeout_override)
        return environment

    def _run_angr(self, job: AngrJob, local_path: Path) -> "AngrExecutionReport":
        mount_dir = local_path.parent
        command = list(self._config.angr_command or ("/opt/medusa/run_angr",))
        completed = self._runner.run(
            self._config.angr_image,
            command,
            mounts={mount_dir: "/workspace"},
            extra_flags=self._config.container_flags,
            environment=self._build_environment(job, local_path),
            timeout=self._config.harness_timeout_seconds,
        )
        raw_output = self._safe_json_loads(completed.stdout)
        status = "completed" if completed.returncode == 0 else "failed"
        report = AngrExecutionReport(
            status=status,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            raw_output=raw_output,
            executed_at=datetime.now(tz=timezone.utc),
        )
        if status == "failed":
            LOG.warning(
                "angr harness exited with non-zero status",
                extra={"job_id": job.job_id, "exit_code": completed.returncode},
            )
        return report

    def _interpret_output(
        self, job: AngrJob, payload: Mapping[str, object]
    ) -> Tuple[List[AngrFinding], List[AngrArtifact]]:
        findings: List[AngrFinding] = []
        artifacts: List[AngrArtifact] = []
        artifact_map: Dict[str, AngrArtifact] = {}

        raw_artifacts = payload.get("artifacts")
        if isinstance(raw_artifacts, list):
            for item in raw_artifacts:
                if not isinstance(item, Mapping):
                    continue
                name = str(item.get("name") or ANGR_TOOL)
                content = item.get("payload")
                if not isinstance(content, Mapping):
                    continue
                stored = self._storage.persist(job, name, content)
                artifacts.append(stored)
                artifact_map[name] = stored

        raw_findings = payload.get("findings")
        if isinstance(raw_findings, list):
            for item in raw_findings:
                if not isinstance(item, Mapping):
                    continue
                severity = _normalize_severity(str(item.get("severity") or ""))
                title = str(item.get("title") or "angr finding")
                description = str(item.get("description") or "")
                metadata = (
                    dict(item.get("metadata", {}))
                    if isinstance(item.get("metadata"), Mapping)
                    else {}
                )
                evidence = (
                    dict(item.get("evidence", {}))
                    if isinstance(item.get("evidence"), Mapping)
                    else {}
                )
                executed_at_raw = item.get("executed_at")
                executed_at = (
                    _coerce_datetime(executed_at_raw)
                    if isinstance(executed_at_raw, str)
                    else datetime.now(tz=timezone.utc)
                )
                artifact_name = item.get("artifact")
                artifact_bucket: Optional[str] = None
                artifact_key: Optional[str] = None
                if isinstance(artifact_name, str) and artifact_name in artifact_map:
                    artifact_bucket = artifact_map[artifact_name].bucket
                    artifact_key = artifact_map[artifact_name].key
                finding = AngrFinding(
                    tool=str(item.get("tool") or ANGR_TOOL),
                    severity=severity,  # type: ignore[arg-type]
                    title=title,
                    description=description,
                    metadata=metadata,
                    evidence=evidence,
                    artifact_bucket=artifact_bucket,
                    artifact_key=artifact_key,
                    executed_at=executed_at,
                )
                findings.append(finding)
        return findings, artifacts

    @staticmethod
    def _safe_json_loads(content: str) -> Dict[str, object]:
        try:
            data = json.loads(content) if content else {}
            if isinstance(data, Mapping):
                return dict(data)
        except json.JSONDecodeError:
            LOG.debug("angr harness returned non-JSON payload", extra={"payload": content})
        return {"raw_stdout": content}


class Worker:
    """Main worker loop orchestrating queue polling and job execution."""

    def __init__(self, config: WorkerConfig) -> None:
        self._config = config
        self._shutdown_event = threading.Event()
        runtime_config = config.runtime_config()
        runtime_config.base_flags = tuple(runtime_config.base_flags)
        self._runner = ContainerRunner(runtime_config)
        self._queue = RedisJobQueue(config)
        self._storage = ArtifactStorage(
            self._build_storage_client(config),
            default_bucket=config.analysis_bucket,
            prefix=config.analysis_prefix,
        )
        self._callback = CallbackClient(config.callback_token)
        self._processor = AngrAnalysisProcessor(
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
        LOG.info("Angr symbolic execution worker starting")
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
    def _handle_signal(signum, frame):  # pragma: no cover - signal handling not exercised
        LOG.info("Received signal %s, shutting down", signum)
        worker.shutdown()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Medusa angr symbolic execution worker")
    parser.add_argument(
        "--once",
        dest="job_file",
        help="Execute a single job from the provided JSON file and exit.",
    )
    return parser.parse_args(argv)


def run_single_job(config: WorkerConfig, job_file: Path) -> None:
    payload = json.loads(job_file.read_text())
    job = AngrJob.model_validate(payload)
    queued = QueuedJob(job=job, attempts=payload.get("attempts", 0), raw_payload=job_file.read_text())
    runtime_config = config.runtime_config()
    worker = AngrAnalysisProcessor(
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
