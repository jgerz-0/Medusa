"""Entry point for the binary fuzzing worker."""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import subprocess
import sys
import tempfile
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

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


from workers.binary.preprocess.storage import (  # noqa: E402  - optional boto3
    ObjectStorageClient,
    S3ObjectStorageClient,
)
from workers.binary.static_analysis.runtime import ContainerRunner, RuntimeConfig
from workers.binary.static_analysis.schemas import AnalysisArtifact, AnalysisFinding

from .schemas import FuzzingJob, FuzzingResult, FuzzingRunSummary

LOG = logging.getLogger("medusa.workers.binary.fuzzing")

AFL_TOOL = "afl"
LIBFUZZER_TOOL = "libfuzzer"


def _split_flags(raw: Optional[str]) -> Tuple[str, ...]:
    if not raw:
        return tuple()
    tokens = [token.strip() for token in raw.split() if token.strip()]
    return tuple(tokens)


def _split_command(raw: Optional[str]) -> Tuple[str, ...]:
    if not raw:
        return tuple()
    return tuple(token for token in raw.split() if token)


@dataclass
class WorkerConfig:
    """Runtime configuration sourced from environment variables."""

    redis_url: str = field(
        default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0")
    )
    queue_key: str = field(
        default_factory=lambda: os.getenv(
            "BINARY_FUZZING_QUEUE_KEY", "queues:binary:fuzzing"
        )
    )
    dead_letter_key: str = field(
        default_factory=lambda: os.getenv(
            "BINARY_FUZZING_DEAD_LETTER_KEY", "queues:binary:fuzzing:dead"
        )
    )
    poll_timeout: int = field(
        default_factory=lambda: int(os.getenv("BINARY_FUZZING_POLL_TIMEOUT", "5"))
    )
    max_attempts: int = field(
        default_factory=lambda: int(os.getenv("BINARY_FUZZING_MAX_ATTEMPTS", "3"))
    )
    container_runtime: str = field(
        default_factory=lambda: os.getenv("BINARY_FUZZING_RUNTIME", "docker")
    )
    container_flags: Tuple[str, ...] = field(
        default_factory=lambda: _split_flags(
            os.getenv("BINARY_FUZZING_RUNTIME_FLAGS", "")
        )
    )
    afl_image: str = field(
        default_factory=lambda: os.getenv(
            "BINARY_FUZZING_AFL_IMAGE", "docker.io/medusa/afl:latest"
        )
    )
    libfuzzer_image: str = field(
        default_factory=lambda: os.getenv(
            "BINARY_FUZZING_LIBFUZZER_IMAGE", "docker.io/medusa/libfuzzer:latest"
        )
    )
    afl_command: Tuple[str, ...] = field(
        default_factory=lambda: _split_command(
            os.getenv("BINARY_FUZZING_AFL_COMMAND", "/opt/medusa/run_afl")
        )
    )
    libfuzzer_command: Tuple[str, ...] = field(
        default_factory=lambda: _split_command(
            os.getenv("BINARY_FUZZING_LIBFUZZER_COMMAND", "/opt/medusa/run_libfuzzer")
        )
    )
    enable_afl: bool = field(
        default_factory=lambda: os.getenv("BINARY_FUZZING_ENABLE_AFL", "1")
        not in {"0", "false", "False"}
    )
    enable_libfuzzer: bool = field(
        default_factory=lambda: os.getenv("BINARY_FUZZING_ENABLE_LIBFUZZER", "1")
        not in {"0", "false", "False"}
    )
    artifact_bucket: Optional[str] = field(
        default_factory=lambda: os.getenv("BINARY_FUZZING_BUCKET")
    )
    artifact_prefix: str = field(
        default_factory=lambda: os.getenv("BINARY_FUZZING_PREFIX", "analysis/fuzzing/")
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
        default_factory=lambda: os.getenv("BINARY_FUZZING_CALLBACK_TOKEN")
    )
    max_duration_seconds: int = field(
        default_factory=lambda: int(os.getenv("BINARY_FUZZING_MAX_DURATION", "900"))
    )

    def runtime_config(self) -> RuntimeConfig:
        return RuntimeConfig(binary=self.container_runtime)

    @classmethod
    def load(cls) -> "WorkerConfig":
        config = cls()
        LOG.debug("Loaded fuzzing worker config", extra={"config": config})
        return config


@dataclass
class QueuedJob:
    job: FuzzingJob
    attempts: int
    raw_payload: str


class RedisJobQueue:
    """Redis-backed queue for fuzzing jobs."""

    def __init__(self, config: WorkerConfig, *, connection=None) -> None:
        if connection is None:
            if redis is None:  # pragma: no cover - runtime dependency validation
                raise RuntimeError("redis-py is required for the fuzzing worker")
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
            LOG.exception("Failed to deserialize job payload", exc_info=exc)
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
        job = FuzzingJob.model_validate(document)
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


class FuzzingArtifactStorage:
    """Wrapper persisting fuzzing outputs into MinIO/S3."""

    def __init__(
        self, client: ObjectStorageClient, *, default_bucket: Optional[str], prefix: str
    ) -> None:
        self._client = client
        self._default_bucket = default_bucket
        self._prefix = prefix.rstrip("/") + "/" if prefix else ""

    def persist(
        self, job: FuzzingJob, tool: str, payload: Mapping[str, object]
    ) -> AnalysisArtifact:
        bucket = self._default_bucket or job.object_bucket
        suffix = uuid.uuid4().hex
        key = f"{self._prefix}{job.sample_id}/{tool}-{suffix}.json"
        self._client.put_json(bucket, key, dict(payload))
        return AnalysisArtifact(tool=tool, bucket=bucket, key=key)

    def fetch_original(self, bucket: str, key: str) -> bytes:
        return self._client.fetch(bucket, key)


class FuzzingProcessor:
    """Coordinate downloads, fuzzer execution, and callback publishing."""

    def __init__(
        self,
        config: WorkerConfig,
        *,
        runner: ContainerRunner,
        storage: FuzzingArtifactStorage,
        callback: CallbackClient,
    ) -> None:
        self._config = config
        self._runner = runner
        self._storage = storage
        self._callback = callback

    def process(self, queued_job: QueuedJob) -> None:
        job = queued_job.job
        LOG.info(
            "Processing fuzzing job",
            extra={"job_id": job.job_id, "sample_id": job.sample_id},
        )
        result = FuzzingResult(
            status="completed",
            job_id=job.job_id,
            scan_id=job.scan_id,
            sample_id=job.sample_id,
            processed_at=datetime.now(tz=timezone.utc),
            metadata=dict(job.metadata or {}),
        )

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                local_path = self._download_artifact(job, Path(temp_dir))
                if self._config.enable_afl and self._config.afl_command:
                    run = self._run_fuzzer(
                        job,
                        local_path,
                        tool=AFL_TOOL,
                        image=self._config.afl_image,
                        command=self._config.afl_command,
                    )
                    result.runs.append(run)
                    if run.artifact:
                        result.artifacts.append(run.artifact)
                    result.findings.extend(run.findings)
                if self._config.enable_libfuzzer and self._config.libfuzzer_command:
                    run = self._run_fuzzer(
                        job,
                        local_path,
                        tool=LIBFUZZER_TOOL,
                        image=self._config.libfuzzer_image,
                        command=self._config.libfuzzer_command,
                    )
                    result.runs.append(run)
                    if run.artifact:
                        result.artifacts.append(run.artifact)
                    result.findings.extend(run.findings)
        except Exception as exc:
            LOG.exception("Fuzzing execution failed: %s", exc)
            result.status = "failed"
            result.error = str(exc)

        payload = result.model_dump(mode="json")
        try:
            self._callback.post(job.callback_url, payload)
            LOG.info("Published fuzzing callback", extra={"job_id": job.job_id})
        except Exception as exc:
            LOG.exception("Failed to deliver callback for job %s", job.job_id)
            raise RuntimeError(str(exc))

    def _download_artifact(self, job: FuzzingJob, destination: Path) -> Path:
        data = self._storage.fetch_original(job.object_bucket, job.object_key)
        filename = job.file_name or Path(job.object_key).name
        local_path = destination / filename
        local_path.write_bytes(data)
        return local_path

    def _run_fuzzer(
        self,
        job: FuzzingJob,
        local_path: Path,
        *,
        tool: str,
        image: str,
        command: Sequence[str],
    ) -> FuzzingRunSummary:
        mount_dir = local_path.parent
        environment = {
            "MEDUSA_TARGET_PATH": f"/workspace/{local_path.name}",
            "MEDUSA_SAMPLE_ID": job.sample_id,
            "MEDUSA_SCAN_ID": job.scan_id,
            "MEDUSA_TOOL": tool,
        }
        timeout = job.max_duration_seconds or self._config.max_duration_seconds
        completed = self._runner.run(
            image,
            list(command),
            mounts={mount_dir: "/workspace:ro"},
            extra_flags=self._config.container_flags,
            environment=environment,
            timeout=timeout,
        )
        raw_output = self._safe_json_loads(completed.stdout)
        findings = self._interpret_crashes(
            tool,
            raw_output,
            executed_at=datetime.now(tz=timezone.utc),
        )
        artifact_payload = {
            "tool": tool,
            "exit_code": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "raw": raw_output,
        }
        artifact = self._storage.persist(job, tool, artifact_payload)
        for finding in findings:
            if not finding.artifact_bucket:
                finding.artifact_bucket = artifact.bucket
            if not finding.artifact_key:
                finding.artifact_key = artifact.key

        status = "completed" if completed.returncode == 0 else "failed"
        duration = None
        if isinstance(raw_output, Mapping):
            maybe_duration = raw_output.get("duration_seconds")
            if isinstance(maybe_duration, (int, float)):
                duration = int(maybe_duration)
        if status == "failed":
            LOG.warning(
                "%s exited with non-zero status", tool,
                extra={"job_id": job.job_id, "exit_code": completed.returncode},
            )
        return FuzzingRunSummary(
            tool=tool,
            status=status,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            raw_output=raw_output if isinstance(raw_output, dict) else {},
            findings=findings,
            artifact=artifact,
            executed_at=datetime.now(tz=timezone.utc),
            duration_seconds=duration,
        )

    @staticmethod
    def _safe_json_loads(content: str) -> Mapping[str, object]:
        try:
            loaded = json.loads(content) if content else {}
            return loaded if isinstance(loaded, Mapping) else {"unparsed": loaded}
        except json.JSONDecodeError:
            return {"unparsed": content}

    def _interpret_crashes(
        self, tool: str, payload: Mapping[str, object], *, executed_at: datetime
    ) -> List[AnalysisFinding]:
        crashes = payload.get("crashes")
        if not isinstance(crashes, Iterable):
            return []
        findings: List[AnalysisFinding] = []
        for item in crashes:
            if not isinstance(item, Mapping):
                continue
            severity = str(item.get("severity", "high")).lower()
            if severity not in {"critical", "high", "medium", "low", "info"}:
                severity = "high"
            crash_id = item.get("id") or item.get("crash_id")
            title = str(item.get("title") or f"{tool} crash {crash_id or 'unknown'}")
            description = str(
                item.get("description")
                or "Fuzzer discovered a crashing input for the target"
            )
            metadata = {
                key: value
                for key, value in item.items()
                if key
                not in {
                    "title",
                    "description",
                    "severity",
                    "evidence",
                    "artifact_bucket",
                    "artifact_key",
                    "evidence_bucket",
                    "evidence_key",
                }
            }
            if crash_id is not None:
                metadata.setdefault("crash_id", crash_id)
            evidence = item.get("evidence")
            if isinstance(evidence, Mapping):
                evidence_payload = dict(evidence)
            else:
                evidence_payload = {"raw": evidence} if evidence is not None else {}
            artifact_bucket = item.get("artifact_bucket")
            artifact_key = item.get("artifact_key")
            findings.append(
                AnalysisFinding(
                    tool=tool,
                    severity=severity,  # type: ignore[arg-type]
                    title=title,
                    description=description,
                    metadata=metadata,
                    evidence=evidence_payload,
                    artifact_bucket=artifact_bucket,
                    artifact_key=artifact_key,
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
        runtime_config.base_flags = tuple(runtime_config.base_flags)
        self._runner = ContainerRunner(runtime_config)
        self._queue = RedisJobQueue(config)
        self._storage = FuzzingArtifactStorage(
            self._build_storage_client(config),
            default_bucket=config.artifact_bucket,
            prefix=config.artifact_prefix,
        )
        self._callback = CallbackClient(config.callback_token)
        self._processor = FuzzingProcessor(
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
        LOG.info("Binary fuzzing worker starting")
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
    parser = argparse.ArgumentParser(description="Medusa binary fuzzing worker")
    parser.add_argument(
        "--once",
        dest="job_file",
        help="Execute a single job from the provided JSON file and exit.",
    )
    return parser.parse_args(argv)


def run_single_job(config: WorkerConfig, job_file: Path) -> None:
    payload = json.loads(job_file.read_text())
    job = FuzzingJob.model_validate(payload)
    queued = QueuedJob(
        job=job, attempts=payload.get("attempts", 0), raw_payload=job_file.read_text()
    )
    runtime_config = config.runtime_config()
    worker = FuzzingProcessor(
        config,
        runner=ContainerRunner(runtime_config),
        storage=FuzzingArtifactStorage(
            S3ObjectStorageClient(
                endpoint_url=config.s3_endpoint_url,
                access_key=config.s3_access_key,
                secret_key=config.s3_secret_key,
                region_name=config.s3_region,
            ),
            default_bucket=config.artifact_bucket,
            prefix=config.artifact_prefix,
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
    except KeyboardInterrupt:  # pragma: no cover - interactive shutdown
        LOG.info("Received keyboard interrupt, shutting down")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.argv[1:]))
