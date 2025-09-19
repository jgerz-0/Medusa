"""Entry point for the binary preprocessing worker."""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Iterable, List, Optional

try:  # pragma: no cover - redis optional in unit tests
    import redis
except Exception:  # pragma: no cover
    redis = None  # type: ignore[assignment]

from sqlalchemy.orm import Session

from controller.db.session import SessionLocal
from workers.binary.preprocess.inspection import MagicFileInspector
from workers.binary.preprocess.policies import (
    AllowMimeTypesPolicy,
    MaxFileSizePolicy,
    PolicySuite,
    TriagePolicy,
)
from workers.binary.preprocess.schemas import BinaryPreprocessJob, NormalizedBinaryMetadata
from workers.binary.preprocess.storage import MetadataRepository, ObjectStorageClient, S3ObjectStorageClient

LOG = logging.getLogger("medusa.workers.binary.preprocess")


def _default_allowed_mimes() -> tuple[str, ...]:
    raw = os.getenv(
        "BINARY_PREPROCESS_ALLOWED_MIMES",
        "application/x-dosexec,application/zip",
    )
    values: list[str] = []
    for part in raw.split(","):
        candidate = part.strip().lower()
        if candidate:
            values.append(candidate)
    return tuple(dict.fromkeys(values))


@dataclass
class WorkerConfig:
    """Runtime configuration derived from environment variables."""

    redis_url: str = field(default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    queue_key: str = field(
        default_factory=lambda: os.getenv("BINARY_PREPROCESS_QUEUE_KEY", "queues:binary:preprocess")
    )
    result_queue_key: Optional[str] = field(
        default_factory=lambda: os.getenv("BINARY_PREPROCESS_RESULT_KEY")
    )
    dead_letter_key: str = field(
        default_factory=lambda: os.getenv("BINARY_PREPROCESS_DEAD_LETTER_KEY", "queues:binary:preprocess:dead")
    )
    poll_timeout: int = field(default_factory=lambda: int(os.getenv("BINARY_PREPROCESS_POLL_TIMEOUT", "5")))
    max_attempts: int = field(default_factory=lambda: int(os.getenv("BINARY_PREPROCESS_MAX_ATTEMPTS", "3")))
    max_file_bytes: int = field(default_factory=lambda: int(os.getenv("BINARY_PREPROCESS_MAX_BYTES", "52428800")))
    allowed_mime_types: tuple[str, ...] = field(default_factory=_default_allowed_mimes)
    metadata_bucket: Optional[str] = field(
        default_factory=lambda: os.getenv("BINARY_METADATA_BUCKET")
    )
    metadata_prefix: str = field(
        default_factory=lambda: os.getenv("BINARY_METADATA_PREFIX", "preprocess/metadata/")
    )
    s3_endpoint_url: Optional[str] = field(
        default_factory=lambda: os.getenv("S3_ENDPOINT_URL")
    )
    s3_access_key: Optional[str] = field(
        default_factory=lambda: os.getenv("S3_ACCESS_KEY_ID") or os.getenv("AWS_ACCESS_KEY_ID")
    )
    s3_secret_key: Optional[str] = field(
        default_factory=lambda: os.getenv("S3_SECRET_ACCESS_KEY") or os.getenv("AWS_SECRET_ACCESS_KEY")
    )
    s3_region: Optional[str] = field(
        default_factory=lambda: os.getenv("AWS_DEFAULT_REGION")
    )
    database_url: Optional[str] = field(
        default_factory=lambda: os.getenv("DATABASE_URL")
    )

    @classmethod
    def load(cls) -> "WorkerConfig":
        config = cls()
        LOG.debug("Loaded worker config", extra={"config": config})
        return config


@dataclass
class QueuedJob:
    job: BinaryPreprocessJob
    attempts: int
    raw_payload: str


class RedisJobQueue:
    """Redis-backed queue client for preprocess jobs."""

    def __init__(self, config: WorkerConfig, *, connection=None) -> None:
        if connection is None:
            if redis is None:  # pragma: no cover - runtime dependency validation
                raise RuntimeError("redis-py is required for the preprocess worker")
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
            LOG.exception("Failed to deserialize preprocess job: %s", exc)
            self.dead_letter_raw(payload, reason="deserialization_error")
            return None

    def ack_success(self, queued_job: QueuedJob, result: NormalizedBinaryMetadata) -> None:
        if not self._config.result_queue_key:
            return
        payload = {
            "status": "completed",
            "job_id": queued_job.job.job_id,
            "scan_id": queued_job.job.scan_id,
            "attempts": queued_job.attempts,
            "processed_at": datetime.now(tz=timezone.utc).isoformat(),
            "metadata": result.model_dump(mode="json"),
        }
        self._client.rpush(self._config.result_queue_key, json.dumps(payload))

    def dead_letter(self, queued_job: QueuedJob, reason: str, error: Optional[str] = None) -> None:
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
        data = json.loads(payload)
        attempts = int(data.get("attempts", 0))
        job_payload = data.get("job") or data
        metadata = data.get("metadata") or {}
        job = BinaryPreprocessJob.model_validate(job_payload)
        if metadata and not job.metadata:
            job.metadata = metadata
        return QueuedJob(job=job, attempts=attempts, raw_payload=payload)


class BinaryPreprocessWorker:
    """Long-running worker responsible for binary preprocessing."""

    def __init__(
        self,
        config: WorkerConfig,
        *,
        queue: Optional[RedisJobQueue] = None,
        inspector: Optional[MagicFileInspector] = None,
        storage: Optional[ObjectStorageClient] = None,
        repository: Optional[MetadataRepository] = None,
        policies: Optional[Iterable[TriagePolicy]] = None,
        session_factory: Optional[Callable[[], Session]] = None,
    ) -> None:
        self._config = config
        self._queue = queue or RedisJobQueue(config)
        self._inspector = inspector or MagicFileInspector()
        if storage is None:
            storage = S3ObjectStorageClient(
                endpoint_url=config.s3_endpoint_url,
                access_key=config.s3_access_key,
                secret_key=config.s3_secret_key,
                region_name=config.s3_region,
            )
        self._storage = storage
        if repository is None:
            factory = session_factory or SessionLocal
            repository = MetadataRepository(factory)
        self._repository = repository
        self._policy_suite = PolicySuite(
            policies
            or (
                AllowMimeTypesPolicy(config.allowed_mime_types),
                MaxFileSizePolicy(config.max_file_bytes),
            )
        )
        self._shutdown = threading.Event()

    def run_forever(self) -> None:  # pragma: no cover - exercised in integration tests
        LOG.info("Binary preprocess worker starting")
        while not self._shutdown.is_set():
            queued_job = self._queue.fetch()
            if queued_job is None:
                continue
            try:
                result = self.process_job(queued_job.job)
                self._queue.ack_success(queued_job, result)
            except Exception as exc:  # pragma: no cover - defensive logging
                LOG.exception(
                    "Failed to process preprocess job", extra={"job_id": queued_job.job.job_id}
                )
                self._queue.dead_letter(
                    queued_job,
                    reason="processing_error",
                    error=str(exc),
                )

    def shutdown(self) -> None:  # pragma: no cover - used by signal handlers
        self._shutdown.set()

    def process_job(self, job: BinaryPreprocessJob) -> NormalizedBinaryMetadata:
        LOG.info(
            "Processing binary preprocess job",
            extra={"job_id": job.job_id, "scan_id": job.scan_id},
        )
        payload = self._storage.fetch(job.object_bucket, job.object_key)
        descriptor = self._inspector.identify(payload)
        decision = self._policy_suite.evaluate(job, descriptor)

        now = datetime.now(tz=timezone.utc)
        file_name = job.file_name or job.object_key.split("/")[-1] or job.object_key
        policy_status = "allowed" if decision.allowed else "blocked"

        extra_metadata = {
            "job_metadata": dict(job.metadata),
            "descriptor": {
                "sha256": descriptor.sha256,
                "size": descriptor.size,
                "mime_type": descriptor.mime_type,
                "magic_label": descriptor.magic_label,
            },
        }

        metadata = NormalizedBinaryMetadata(
            job_id=job.job_id,
            scan_id=job.scan_id,
            target_id=job.target_id,
            target_scope=job.target_scope,
            file_name=file_name,
            sha256=descriptor.sha256,
            file_size=descriptor.size,
            mime_type=descriptor.mime_type,
            magic_label=descriptor.magic_label,
            policy_status=policy_status,
            policy_reasons=list(decision.reasons),
            storage_bucket=job.object_bucket,
            storage_key=job.object_key,
            inspected_at=now,
            submitted_by=job.submitted_by,
            extra_metadata=extra_metadata,
        )

        record = self._repository.persist(metadata)
        metadata_object_bucket = self._config.metadata_bucket or job.object_bucket
        metadata_object_key = f"{self._config.metadata_prefix}{descriptor.sha256}.json"
        payload_json = metadata.model_dump(mode="json")
        payload_json["database_record_id"] = str(record.id)
        payload_json["policy_allowed"] = decision.allowed
        self._storage.put_json(metadata_object_bucket, metadata_object_key, payload_json)
        LOG.info(
            "Stored normalized metadata",
            extra={
                "job_id": job.job_id,
                "metadata_object": f"s3://{metadata_object_bucket}/{metadata_object_key}",
            },
        )

        return metadata


def _install_signal_handlers(worker: BinaryPreprocessWorker) -> None:  # pragma: no cover - runtime only
    def _handle_signal(signum, frame):
        LOG.info("Received signal %s; shutting down worker", signum)
        worker.shutdown()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)


def main(argv: Optional[List[str]] = None) -> int:  # pragma: no cover - CLI wrapper
    parser = argparse.ArgumentParser(description="Binary preprocess worker")
    parser.add_argument("--once", action="store_true", help="Process a single job and exit")
    args = parser.parse_args(argv)

    config = WorkerConfig.load()
    worker = BinaryPreprocessWorker(config)

    if args.once:
        job = worker._queue.fetch()  # type: ignore[attr-defined]
        if job is None:
            LOG.info("No job available; exiting")
            return 0
        try:
            worker.process_job(job.job)
        except Exception as exc:  # pragma: no cover - CLI diagnostics
            LOG.exception("Job failed: %s", exc)
            worker._queue.dead_letter(job, reason="processing_error", error=str(exc))
            return 1
        return 0

    _install_signal_handlers(worker)
    worker.run_forever()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
