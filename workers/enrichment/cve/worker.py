"""Entry point for the CVE enrichment worker.

The worker operates as a long-running process that dequeues enrichment jobs
from Redis, performs deterministic advisory lookups, and publishes normalized
results back to Redis channels for the controller. A single-shot mode is
retained for smoke testing (`--job-file`).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, Mapping, MutableMapping, Optional

try:  # pragma: no cover - requests optional in unit tests
    from requests import Session
except ImportError:  # pragma: no cover
    Session = object  # type: ignore[misc, assignment]

try:  # pragma: no cover - redis optional for unit tests
    import redis
except ImportError:  # pragma: no cover
    redis = None  # type: ignore[assignment]

from .qdrant import QdrantClient, QdrantConfig, build_advisory_points
from .schemas import CVEAdvisory, CVEEnrichmentJob, CVEEnrichmentResult, CVESource
from .sources import AdvisorySourceError, fetch_circl_advisory, fetch_nvd_advisory

LOG = logging.getLogger("medusa.workers.enrichment.cve")


@dataclass
class WorkerConfig:
    """Runtime configuration derived from environment variables."""

    redis_url: str = field(
        default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0")
    )
    queue_key: str = field(
        default_factory=lambda: os.getenv("CVE_ENRICHMENT_QUEUE_KEY", "queues:enrichment:cve")
    )
    result_queue_key: str = field(
        default_factory=lambda: os.getenv(
            "CVE_ENRICHMENT_RESULT_QUEUE_KEY", "queues:enrichment:cve:results"
        )
    )
    error_queue_key: str = field(
        default_factory=lambda: os.getenv(
            "CVE_ENRICHMENT_ERROR_QUEUE_KEY", "queues:enrichment:cve:errors"
        )
    )
    max_attempts: int = field(
        default_factory=lambda: int(os.getenv("CVE_ENRICHMENT_MAX_ATTEMPTS", "3"))
    )
    retry_backoff_seconds: float = field(
        default_factory=lambda: float(os.getenv("CVE_ENRICHMENT_RETRY_BACKOFF_SECONDS", "2.0"))
    )
    poll_timeout: int = field(
        default_factory=lambda: int(os.getenv("CVE_ENRICHMENT_QUEUE_POLL_TIMEOUT", "5"))
    )
    http_timeout: int = field(
        default_factory=lambda: int(os.getenv("CVE_ENRICHMENT_HTTP_TIMEOUT", "30"))
    )
    user_agent: Optional[str] = field(
        default_factory=lambda: os.getenv("CVE_ENRICHMENT_USER_AGENT")
    )
    qdrant_url: Optional[str] = field(
        default_factory=lambda: os.getenv("CVE_ENRICHMENT_QDRANT_URL")
    )
    qdrant_api_key: Optional[str] = field(
        default_factory=lambda: os.getenv("CVE_ENRICHMENT_QDRANT_API_KEY")
    )
    qdrant_collection: Optional[str] = field(
        default_factory=lambda: os.getenv("CVE_ENRICHMENT_QDRANT_COLLECTION")
    )
    qdrant_timeout: float = field(
        default_factory=lambda: float(os.getenv("CVE_ENRICHMENT_QDRANT_TIMEOUT", "5.0"))
    )
    qdrant_vector_size: int = field(
        default_factory=lambda: int(os.getenv("CVE_ENRICHMENT_QDRANT_VECTOR_SIZE", "64"))
    )

    @classmethod
    def load(cls) -> "WorkerConfig":
        config = cls()
        LOG.debug("Loaded worker configuration", extra={"config": config})
        return config

    @property
    def qdrant_enabled(self) -> bool:
        return bool(self.qdrant_url and self.qdrant_collection)

    def build_qdrant_config(self) -> Optional[QdrantConfig]:
        if not self.qdrant_enabled:
            return None
        return QdrantConfig(
            url=self.qdrant_url or "",
            collection=self.qdrant_collection or "",
            api_key=self.qdrant_api_key,
            timeout=self.qdrant_timeout,
        )


SOURCE_FETCHERS: Mapping[CVESource, Callable[..., Dict[str, object]]] = {
    CVESource.NVD: fetch_nvd_advisory,
    CVESource.CIRCL: fetch_circl_advisory,
}


@dataclass
class QueuedJob:
    """Wrapper describing a job fetched from Redis."""

    job: CVEEnrichmentJob
    attempts: int
    raw_payload: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class RedisJobQueue:
    """BLPOP-backed queue integration for CVE enrichment jobs."""

    def __init__(self, config: WorkerConfig, *, connection: Optional[Any] = None) -> None:
        if connection is None:
            if redis is None:  # pragma: no cover - runtime dependency validation
                raise RuntimeError("redis-py must be installed to use the CVE enrichment worker")
            connection = redis.Redis.from_url(config.redis_url, decode_responses=True)
        self._client = connection
        self._config = config
        self._queue_key = config.queue_key
        self._result_queue_key = config.result_queue_key
        self._error_queue_key = config.error_queue_key

    def fetch(self) -> Optional[QueuedJob]:
        response = self._client.blpop(self._queue_key, timeout=self._config.poll_timeout)
        if not response:
            return None
        _, payload = response
        try:
            return self._deserialize_payload(payload)
        except Exception as exc:  # pragma: no cover - defensive logging
            LOG.exception("Failed to deserialize job payload: %s", exc)
            self._publish_malformed(payload, exc)
            return None

    def publish_success(self, queued_job: QueuedJob, result: CVEEnrichmentResult) -> None:
        payload = {
            "status": "completed",
            "job": _serialize_job(queued_job.job),
            "result": _serialize_result(result),
            "attempts": queued_job.attempts,
            "processed_at": _utc_now_iso(),
        }
        if queued_job.metadata:
            payload["metadata"] = queued_job.metadata
        self._client.rpush(self._result_queue_key, json.dumps(payload))
        LOG.info("Published enrichment result", extra={"job_id": queued_job.job.job_id})

    def handle_failure(self, queued_job: QueuedJob, exc: Exception) -> None:
        error_info = {
            "type": exc.__class__.__name__,
            "message": str(exc),
        }
        next_attempt = queued_job.attempts + 1
        status = "retrying"
        payload = {
            "status": status,
            "job": _serialize_job(queued_job.job),
            "attempts": queued_job.attempts,
            "error": error_info,
            "processed_at": _utc_now_iso(),
        }
        if queued_job.metadata:
            payload["metadata"] = queued_job.metadata

        max_attempts = max(self._config.max_attempts, 1)
        if next_attempt >= max_attempts:
            payload["status"] = "failed"
            payload["dead_lettered_at"] = _utc_now_iso()
            self._client.rpush(self._result_queue_key, json.dumps(payload))
            self._client.rpush(self._error_queue_key, json.dumps(payload))
            LOG.error(
                "Job %s moved to dead-letter queue after %s attempts",
                queued_job.job.job_id,
                next_attempt,
            )
            return

        self._client.rpush(self._result_queue_key, json.dumps(payload))
        delay = max(self._config.retry_backoff_seconds, 0.0) * next_attempt
        if delay:
            LOG.debug(
                "Backing off %.2f seconds before retrying job %s",
                delay,
                queued_job.job.job_id,
            )
            time.sleep(delay)
        retry_payload = {
            "job": _serialize_job(queued_job.job),
            "attempts": next_attempt,
            "last_error": error_info,
            "requeued_at": _utc_now_iso(),
        }
        if queued_job.metadata:
            retry_payload["metadata"] = queued_job.metadata
        self._client.rpush(self._queue_key, json.dumps(retry_payload))
        LOG.warning(
            "Requeued job %s for attempt %s/%s",
            queued_job.job.job_id,
            next_attempt,
            max_attempts,
        )

    def _deserialize_payload(self, payload: str) -> QueuedJob:
        if not payload:
            raise ValueError("job payload is empty")
        data = json.loads(payload)
        if not isinstance(data, dict):
            raise ValueError("job payload must be a JSON object")
        attempts = _coerce_attempts(data.get("attempts", 0))
        metadata: Dict[str, Any] = {}
        if "job" in data and isinstance(data["job"], dict):
            metadata = {k: v for k, v in data.items() if k not in {"job", "attempts"}}
            job_payload = data["job"]
        else:
            job_payload = data
        job = CVEEnrichmentJob.parse_obj(job_payload)
        return QueuedJob(job=job, attempts=attempts, raw_payload=payload, metadata=metadata)

    def _publish_malformed(self, payload: str, exc: Exception) -> None:
        error_payload = {
            "status": "failed",
            "error": {
                "type": exc.__class__.__name__,
                "message": str(exc),
            },
            "raw_payload": payload,
            "processed_at": _utc_now_iso(),
        }
        self._client.rpush(self._error_queue_key, json.dumps(error_payload))


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CVE enrichment worker")
    parser.add_argument(
        "--job-file",
        dest="job_file",
        help="Path to a JSON file containing the enrichment job payload",
    )
    parser.add_argument(
        "--log-level",
        dest="log_level",
        default=os.getenv("LOG_LEVEL", "INFO"),
        help="Logging verbosity (default: INFO)",
    )
    return parser.parse_args(argv)


def load_job_from_stream(stream) -> CVEEnrichmentJob:
    try:
        payload = stream.read()
    except Exception as exc:  # pragma: no cover - defensive
        raise SystemExit(f"failed to read job payload: {exc}") from exc
    if not payload:
        raise SystemExit("job payload is empty")
    try:
        return CVEEnrichmentJob.parse_raw(payload)
    except ValueError as exc:
        raise SystemExit(f"invalid job payload: {exc}") from exc


def load_job(path: Optional[str]) -> CVEEnrichmentJob:
    if path:
        with open(path, "r", encoding="utf-8") as handle:
            return load_job_from_stream(handle)
    return load_job_from_stream(sys.stdin)


def collect_advisories(
    job: CVEEnrichmentJob,
    *,
    config: WorkerConfig,
    session: Optional[Session] = None,
) -> CVEEnrichmentResult:
    advisories: list[CVEAdvisory] = []
    errors: MutableMapping[CVESource, str] = {}
    if not job.cve_id:
        for source in job.sources:
            errors[source] = "job missing cve_id"
        return CVEEnrichmentResult(
            job_id=job.job_id,
            finding_id=job.finding_id,
            advisories=advisories,
            errors=dict(errors),
        )

    for source in job.sources:
        fetcher = SOURCE_FETCHERS.get(source)
        if fetcher is None:
            errors[source] = "source not implemented"
            continue
        try:
            payload = fetcher(
                job.cve_id,
                session=session,
                user_agent=config.user_agent,
                timeout=config.http_timeout,
            )
            advisories.append(CVEAdvisory.parse_obj(payload))
        except AdvisorySourceError as exc:
            errors[source] = str(exc)
        except Exception as exc:  # pragma: no cover - ensures deterministic errors
            errors[source] = f"unexpected error: {exc}"
    return CVEEnrichmentResult(
        job_id=job.job_id,
        finding_id=job.finding_id,
        advisories=advisories,
        errors=dict(errors),
    )


def build_job_from_finding(
    *,
    finding_id: str,
    scan_id: Optional[str],
    title: str,
    severity: str,
    metadata: Optional[Dict[str, object]] = None,
    cve_id: Optional[str] = None,
    sources: Optional[Iterable[str]] = None,
    requested_by: str,
) -> CVEEnrichmentJob:
    payload: Dict[str, Any] = {
        "job_id": str(uuid.uuid4()),
        "finding_id": finding_id,
        "scan_id": scan_id,
        "cve_id": cve_id,
        "title": title,
        "severity": severity,
        "metadata": metadata or {},
        "requested_by": requested_by,
        "requested_at": datetime.now(tz=timezone.utc),
    }
    if sources is not None:
        payload["sources"] = list(sources)
    return CVEEnrichmentJob(**payload)


def _serialize_job(job: CVEEnrichmentJob) -> Dict[str, Any]:
    return json.loads(job.json(by_alias=True, exclude_none=True))


def _serialize_result(result: CVEEnrichmentResult) -> Dict[str, Any]:
    return json.loads(result.json(by_alias=True, exclude_none=True))


def _coerce_attempts(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _create_http_session() -> Optional[Session]:
    if Session is object:  # pragma: no cover - ensures optional dependency support
        return None
    return Session()  # type: ignore[call-arg]


def process_queue_once(
    config: WorkerConfig,
    *,
    queue: RedisJobQueue,
    session: Optional[Session],
    qdrant_client: Optional[QdrantClient] = None,
) -> bool:
    queued_job = queue.fetch()
    if queued_job is None:
        return False
    try:
        result = collect_advisories(queued_job.job, config=config, session=session)
    except Exception as exc:
        LOG.exception("Failed to collect advisories", extra={"job_id": queued_job.job.job_id})
        try:
            queue.handle_failure(queued_job, exc)
        except Exception as handler_exc:  # pragma: no cover - defensive logging
            LOG.exception(
                "Failed to handle job failure",
                extra={"job_id": queued_job.job.job_id, "error": str(handler_exc)},
            )
        return True
    if qdrant_client:
        try:
            points = build_advisory_points(
                queued_job.job,
                result.advisories,
                dimensions=max(config.qdrant_vector_size, 1),
            )
            if points:
                qdrant_client.upsert(points)
        except Exception as exc:
            LOG.error(
                "Failed to upsert advisories into Qdrant",
                extra={
                    "job_id": queued_job.job.job_id,
                    "finding_id": queued_job.job.finding_id,
                    "error": str(exc),
                },
            )
    try:
        queue.publish_success(queued_job, result)
    except Exception as exc:
        LOG.exception(
            "Failed to publish enrichment result",
            extra={"job_id": queued_job.job.job_id},
        )
        try:
            queue.handle_failure(queued_job, exc)
        except Exception as handler_exc:  # pragma: no cover - defensive logging
            LOG.exception(
                "Failed to handle publish failure",
                extra={"job_id": queued_job.job.job_id, "error": str(handler_exc)},
            )
    return True


def run_worker_loop(
    config: WorkerConfig,
    *,
    queue: Optional[RedisJobQueue] = None,
    session: Optional[Session] = None,
    stop_event: Optional[threading.Event] = None,
    qdrant_client: Optional[QdrantClient] = None,
) -> None:
    created_session = False
    created_qdrant_client = False
    if queue is None:
        queue = RedisJobQueue(config)
    if session is None:
        session = _create_http_session()
        created_session = session is not None
    if qdrant_client is None:
        qdrant_config = config.build_qdrant_config()
        if qdrant_config is not None:
            try:
                qdrant_client = QdrantClient(qdrant_config)
                created_qdrant_client = True
            except Exception as exc:
                LOG.error(
                    "Failed to initialize Qdrant client",
                    extra={"collection": qdrant_config.collection, "error": str(exc)},
                )
                qdrant_client = None
    stop_event = stop_event or threading.Event()

    def _signal_handler(signum, _frame) -> None:  # pragma: no cover - signal handling
        LOG.info("Received signal %s, shutting down", signum)
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):  # pragma: no cover - system integration
        signal.signal(sig, _signal_handler)

    LOG.info(
        "Starting CVE enrichment worker loop",
        extra={"queue_key": config.queue_key, "result_queue": config.result_queue_key},
    )
    try:
        while not stop_event.is_set():
            try:
                processed = process_queue_once(
                    config,
                    queue=queue,
                    session=session,
                    qdrant_client=qdrant_client,
                )
            except Exception as exc:  # pragma: no cover - defensive logging
                LOG.exception("Unhandled worker error: %s", exc)
                backoff = max(config.retry_backoff_seconds, 1.0)
                time.sleep(backoff)
                continue
            if not processed:
                continue
    finally:
        if created_session and session and hasattr(session, "close"):
            session.close()
        if created_qdrant_client and qdrant_client is not None:
            qdrant_client.close()
        LOG.info("Worker shutdown complete")


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, str(args.log_level).upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    config = WorkerConfig.load()

    if args.job_file:
        job = load_job(args.job_file)
        LOG.info(
            "Processing enrichment job",
            extra={"job_id": job.job_id, "finding_id": job.finding_id},
        )
        session = _create_http_session()
        qdrant_client: Optional[QdrantClient] = None
        qdrant_config = config.build_qdrant_config()
        if qdrant_config is not None:
            try:
                qdrant_client = QdrantClient(qdrant_config)
            except Exception as exc:
                LOG.error(
                    "Failed to initialize Qdrant client",
                    extra={"collection": qdrant_config.collection, "error": str(exc)},
                )
        try:
            result = collect_advisories(job, config=config, session=session)
            if qdrant_client is not None:
                try:
                    points = build_advisory_points(
                        job,
                        result.advisories,
                        dimensions=max(config.qdrant_vector_size, 1),
                    )
                    if points:
                        qdrant_client.upsert(points)
                except Exception as exc:
                    LOG.error(
                        "Failed to upsert advisories into Qdrant",
                        extra={
                            "job_id": job.job_id,
                            "finding_id": job.finding_id,
                            "error": str(exc),
                        },
                    )
        finally:
            if session and hasattr(session, "close"):
                session.close()
            if qdrant_client is not None:
                qdrant_client.close()
        serialized = result.json(by_alias=True, exclude_none=True)
        print(serialized)
        return 0

    try:
        run_worker_loop(config)
    except RuntimeError as exc:
        LOG.error("Worker terminated due to runtime error: %s", exc)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
