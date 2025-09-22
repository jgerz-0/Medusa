"""Redis-backed worker that forwards anomaly detections to the controller."""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional

from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

try:
    import redis
except ImportError:  # pragma: no cover - optional runtime dependency
    redis = None  # type: ignore

try:
    import requests
except ImportError:  # pragma: no cover - optional runtime dependency
    requests = None  # type: ignore

from controller.db.models import AuditLog
from controller.db.session import create_db_engine

from .detector import AnomalyDetector, AnomalyEvent, AuditEvent

LOG = logging.getLogger("medusa.workers.anomaly")
CALLBACK_TOKEN_HEADER = "X-Callback-Token"


@dataclass
class WorkerConfig:
    """Runtime configuration controlling anomaly polling cadence."""

    database_url: str = field(
        default_factory=lambda: os.getenv("DATABASE_URL", "postgresql+psycopg://medusa:medusa@localhost:5432/medusa"),
    )
    redis_url: Optional[str] = field(default_factory=lambda: os.getenv("REDIS_URL"))
    state_key: str = field(
        default_factory=lambda: os.getenv("ANOMALY_STATE_KEY", "workers:anomaly:last_seen"),
    )
    callback_url: str = field(
        default_factory=lambda: os.getenv(
            "ANOMALY_CALLBACK_URL", "http://localhost:8000/internal/anomalies"
        )
    )
    callback_token: Optional[str] = field(
        default_factory=lambda: os.getenv("ANOMALY_CALLBACK_TOKEN")
        or os.getenv("MEDUSA_ANOMALY_CALLBACK_TOKEN"),
    )
    poll_interval: int = field(default_factory=lambda: int(os.getenv("ANOMALY_POLL_INTERVAL", "10")))
    batch_size: int = field(default_factory=lambda: int(os.getenv("ANOMALY_BATCH_SIZE", "200")))
    http_timeout: int = field(default_factory=lambda: int(os.getenv("ANOMALY_HTTP_TIMEOUT", "10")))
    source: str = field(default_factory=lambda: os.getenv("ANOMALY_SOURCE", "worker:anomaly"))
    access_denied_threshold: int = field(
        default_factory=lambda: max(1, int(os.getenv("ANOMALY_ACCESS_DENIED_THRESHOLD", "5")))
    )
    access_denied_window_seconds: int = field(
        default_factory=lambda: max(1, int(os.getenv("ANOMALY_ACCESS_DENIED_WINDOW_SECONDS", "600")))
    )
    rate_limit_threshold: int = field(
        default_factory=lambda: max(1, int(os.getenv("ANOMALY_RATE_LIMIT_THRESHOLD", "3")))
    )
    rate_limit_window_seconds: int = field(
        default_factory=lambda: max(1, int(os.getenv("ANOMALY_RATE_LIMIT_WINDOW_SECONDS", "300")))
    )
    scope_mismatch_threshold: int = field(
        default_factory=lambda: max(1, int(os.getenv("ANOMALY_SCOPE_MISMATCH_THRESHOLD", "2")))
    )
    scope_mismatch_window_seconds: int = field(
        default_factory=lambda: max(1, int(os.getenv("ANOMALY_SCOPE_MISMATCH_WINDOW_SECONDS", "900")))
    )
    cooldown_seconds: int = field(
        default_factory=lambda: max(1, int(os.getenv("ANOMALY_DETECTOR_COOLDOWN_SECONDS", "600")))
    )

    @classmethod
    def load(cls) -> "WorkerConfig":
        config = cls()
        LOG.debug("Loaded anomaly worker config", extra={"config": config})
        return config


class AnomalyWorker:
    """Poll the audit log table and forward suspicious activity to the controller."""

    def __init__(self, config: WorkerConfig, *, detector: Optional[AnomalyDetector] = None) -> None:
        if requests is None:  # pragma: no cover - runtime guard
            raise RuntimeError("requests package is required to run the anomaly worker")

        self._config = config
        self._detector = detector or AnomalyDetector(
            access_denied_threshold=config.access_denied_threshold,
            access_denied_window=timedelta(seconds=config.access_denied_window_seconds),
            rate_limit_threshold=config.rate_limit_threshold,
            rate_limit_window=timedelta(seconds=config.rate_limit_window_seconds),
            scope_mismatch_threshold=config.scope_mismatch_threshold,
            scope_mismatch_window=timedelta(seconds=config.scope_mismatch_window_seconds),
            cooldown=timedelta(seconds=config.cooldown_seconds),
        )
        self._engine: Engine = create_db_engine(config.database_url)
        self._session_factory = sessionmaker(bind=self._engine, expire_on_commit=False, class_=Session)
        self._http = requests.Session()
        self._redis = (
            redis.Redis.from_url(config.redis_url, decode_responses=True)
            if redis is not None and config.redis_url
            else None
        )
        self._last_seen: Optional[datetime] = None

    def run_forever(self) -> None:
        LOG.info("Starting anomaly worker loop", extra={"poll_interval": self._config.poll_interval})
        while True:
            try:
                anomalies = self.poll_once()
                if anomalies:
                    self._dispatch(anomalies)
            except Exception:  # pragma: no cover - defensive logging
                LOG.exception("Anomaly worker crash")
            time.sleep(max(1, self._config.poll_interval))

    def poll_once(self) -> List[AnomalyEvent]:
        """Fetch the next batch of audit events and evaluate heuristics."""

        last_seen = self._load_last_seen()
        events = self._fetch_audit_events(last_seen)
        if not events:
            return []

        anomalies: List[AnomalyEvent] = []
        for entry in events:
            anomalies.extend(self._detector.ingest(entry))

        newest_timestamp = events[-1].normalized_created_at()
        self._persist_last_seen(newest_timestamp)
        return anomalies

    def _fetch_audit_events(self, last_seen: Optional[datetime]) -> List[AuditEvent]:
        with self._session_factory() as session:
            query = select(AuditLog).order_by(AuditLog.created_at).limit(self._config.batch_size)
            if last_seen is not None:
                query = query.where(AuditLog.created_at > last_seen)
            result = session.execute(query)
            records = list(result.scalars())

        events: List[AuditEvent] = []
        for record in records:
            created_at = record.created_at
            if created_at is None:
                continue
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            metadata = record.evidence_snapshot if isinstance(record.evidence_snapshot, dict) else {}
            events.append(
                AuditEvent(
                    id=str(record.id),
                    actor=str(record.actor),
                    action=str(record.action),
                    created_at=created_at,
                    metadata=metadata,
                    message=record.message,
                )
            )
        return events

    def _load_last_seen(self) -> Optional[datetime]:
        if self._redis is not None:
            raw = self._redis.get(self._config.state_key)
            if raw:
                try:
                    loaded = datetime.fromisoformat(raw)
                    if loaded.tzinfo is None:
                        loaded = loaded.replace(tzinfo=timezone.utc)
                    return loaded
                except ValueError:
                    LOG.warning("Invalid timestamp in anomaly state", extra={"value": raw})
        if self._last_seen is not None:
            return self._last_seen
        return None

    def _persist_last_seen(self, value: datetime) -> None:
        timestamp = value.astimezone(timezone.utc).isoformat()
        self._last_seen = value
        if self._redis is not None:
            self._redis.set(self._config.state_key, timestamp)

    def _dispatch(self, anomalies: Iterable[AnomalyEvent]) -> None:
        payload = {
            "source": self._config.source,
            "detected_at": datetime.now(tz=timezone.utc).isoformat(),
            "anomalies": [anomaly.as_payload() for anomaly in anomalies],
        }
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if self._config.callback_token:
            headers[CALLBACK_TOKEN_HEADER] = self._config.callback_token

        response = self._http.post(
            self._config.callback_url,
            data=json.dumps(payload),
            headers=headers,
            timeout=self._config.http_timeout,
        )
        if response.status_code >= 300:
            LOG.warning(
                "Controller rejected anomaly payload",  # pragma: no cover - runtime diagnostics
                extra={"status": response.status_code, "body": response.text[:200]},
            )


def main() -> None:
    """Bootstrap the anomaly worker using environment configuration."""

    logging.basicConfig(level=logging.INFO)
    config = WorkerConfig.load()
    worker = AnomalyWorker(config)
    worker.run_forever()


__all__ = ["AnomalyWorker", "WorkerConfig", "main"]


if __name__ == "__main__":
    main()
