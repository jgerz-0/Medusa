"""Detection heuristics for audit log driven anomaly detection."""

from __future__ import annotations

import collections
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Deque, Dict, List, Optional


@dataclass
class AuditEvent:
    """Normalized audit log entry used by the anomaly detector."""

    id: str
    actor: str
    action: str
    created_at: datetime
    metadata: Dict[str, object] = field(default_factory=dict)
    message: Optional[str] = None

    def normalized_created_at(self) -> datetime:
        """Return a timezone-aware timestamp for comparisons."""

        if self.created_at.tzinfo is None:
            return self.created_at.replace(tzinfo=timezone.utc)
        return self.created_at.astimezone(timezone.utc)


@dataclass
class AnomalyEvent:
    """Structured anomaly signal emitted by the detector."""

    anomaly_type: str
    actor: str
    first_seen: datetime
    last_seen: datetime
    count: int
    window_seconds: int
    metadata: Dict[str, object] = field(default_factory=dict)

    def as_payload(self) -> Dict[str, object]:
        """Convert the anomaly to a JSON-serializable dict."""

        return {
            "anomaly_type": self.anomaly_type,
            "actor": self.actor,
            "first_seen": self.first_seen.astimezone(timezone.utc).isoformat(),
            "last_seen": self.last_seen.astimezone(timezone.utc).isoformat(),
            "count": self.count,
            "window_seconds": self.window_seconds,
            "metadata": self.metadata,
        }


class AnomalyDetector:
    """Windowed heuristic detector for suspicious audit log activity."""

    def __init__(
        self,
        *,
        access_denied_threshold: int = 5,
        access_denied_window: timedelta = timedelta(minutes=10),
        rate_limit_threshold: int = 3,
        rate_limit_window: timedelta = timedelta(minutes=5),
        scope_mismatch_threshold: int = 2,
        scope_mismatch_window: timedelta = timedelta(minutes=15),
        cooldown: timedelta = timedelta(minutes=10),
    ) -> None:
        self._access_denied_threshold = max(1, access_denied_threshold)
        self._access_denied_window = access_denied_window
        self._rate_limit_threshold = max(1, rate_limit_threshold)
        self._rate_limit_window = rate_limit_window
        self._scope_mismatch_threshold = max(1, scope_mismatch_threshold)
        self._scope_mismatch_window = scope_mismatch_window
        self._cooldown = cooldown

        self._access_denied: Dict[str, Deque[AuditEvent]] = collections.defaultdict(collections.deque)
        self._rate_limited: Dict[str, Deque[AuditEvent]] = collections.defaultdict(collections.deque)
        self._scope_mismatch: Dict[str, Deque[AuditEvent]] = collections.defaultdict(collections.deque)
        self._last_emitted: Dict[tuple[str, str], datetime] = {}

    def ingest(self, event: AuditEvent) -> List[AnomalyEvent]:
        """Process a new audit entry and emit anomalies when heuristics trigger."""

        timestamp = event.normalized_created_at()
        anomalies: List[AnomalyEvent] = []

        if event.action == "access_denied":
            anomalies.extend(self._handle_access_denied(event, timestamp))
        if event.action == "access_denied" and self._is_rate_limit(event):
            anomalies.extend(self._handle_rate_limited(event, timestamp))
        if event.action == "preprocess_scope_mismatch":
            anomalies.extend(self._handle_scope_mismatch(event, timestamp))

        return anomalies

    def _handle_access_denied(
        self, event: AuditEvent, timestamp: datetime
    ) -> List[AnomalyEvent]:
        bucket = self._access_denied[event.actor]
        bucket.append(event)
        self._prune(bucket, timestamp, self._access_denied_window)

        if len(bucket) < self._access_denied_threshold:
            return []

        reasons = collections.Counter(
            str(item.metadata.get("reason", "unknown")) for item in bucket
        )
        resources = sorted(
            {
                str(item.metadata.get("resource_id", ""))
                or str(item.metadata.get("resource_type", ""))
                for item in bucket
            }
        )
        anomaly = AnomalyEvent(
            anomaly_type="excessive_access_denied",
            actor=event.actor,
            first_seen=bucket[0].normalized_created_at(),
            last_seen=bucket[-1].normalized_created_at(),
            count=len(bucket),
            window_seconds=int(self._access_denied_window.total_seconds()),
            metadata={
                "reason_counts": dict(reasons),
                "resource_sample": resources[-5:],
                "event_ids": [item.id for item in list(bucket)[-10:]],
            },
        )
        if self._should_emit(anomaly):
            bucket.clear()
            return [anomaly]
        return []

    def _handle_rate_limited(
        self, event: AuditEvent, timestamp: datetime
    ) -> List[AnomalyEvent]:
        bucket = self._rate_limited[event.actor]
        bucket.append(event)
        self._prune(bucket, timestamp, self._rate_limit_window)

        if len(bucket) < self._rate_limit_threshold:
            return []

        hosts = collections.Counter(
            str(item.metadata.get("client_host", "unknown")) for item in bucket
        )
        anomaly = AnomalyEvent(
            anomaly_type="repeated_rate_limit",  # explicit naming for paging alerts
            actor=event.actor,
            first_seen=bucket[0].normalized_created_at(),
            last_seen=bucket[-1].normalized_created_at(),
            count=len(bucket),
            window_seconds=int(self._rate_limit_window.total_seconds()),
            metadata={
                "client_hosts": dict(hosts),
                "event_ids": [item.id for item in list(bucket)[-10:]],
            },
        )
        if self._should_emit(anomaly):
            bucket.clear()
            return [anomaly]
        return []

    def _handle_scope_mismatch(
        self, event: AuditEvent, timestamp: datetime
    ) -> List[AnomalyEvent]:
        bucket = self._scope_mismatch[event.actor]
        bucket.append(event)
        self._prune(bucket, timestamp, self._scope_mismatch_window)

        if len(bucket) < self._scope_mismatch_threshold:
            return []

        provided = [
            {
                "provided_scope": item.metadata.get("provided_scope"),
                "expected_scope": item.metadata.get("expected_scope"),
            }
            for item in bucket
        ]
        anomaly = AnomalyEvent(
            anomaly_type="scope_assertion_failures",
            actor=event.actor,
            first_seen=bucket[0].normalized_created_at(),
            last_seen=bucket[-1].normalized_created_at(),
            count=len(bucket),
            window_seconds=int(self._scope_mismatch_window.total_seconds()),
            metadata={
                "scope_examples": provided[-5:],
                "event_ids": [item.id for item in list(bucket)[-10:]],
            },
        )
        if self._should_emit(anomaly):
            bucket.clear()
            return [anomaly]
        return []

    def _prune(
        self, bucket: Deque[AuditEvent], now: datetime, window: timedelta
    ) -> None:
        cutoff = now - window
        while bucket and bucket[0].normalized_created_at() < cutoff:
            bucket.popleft()

    def _is_rate_limit(self, event: AuditEvent) -> bool:
        reason = str(event.metadata.get("reason", ""))
        return reason == "rate_limit_exceeded"

    def _should_emit(self, anomaly: AnomalyEvent) -> bool:
        key = (anomaly.anomaly_type, anomaly.actor)
        last_emitted = self._last_emitted.get(key)
        if last_emitted and anomaly.last_seen <= last_emitted + self._cooldown:
            return False
        self._last_emitted[key] = anomaly.last_seen
        return True


__all__ = ["AnomalyDetector", "AuditEvent", "AnomalyEvent"]
