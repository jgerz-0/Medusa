"""Monitor finding scope compliance and raise drift anomalies."""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional, Sequence, Set
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker, selectinload

try:
    import redis  # type: ignore
except ImportError:  # pragma: no cover - optional runtime dependency
    redis = None  # type: ignore

try:
    import requests
except ImportError:  # pragma: no cover - optional runtime dependency
    requests = None  # type: ignore

from controller.db.models import AuditLog, Finding, Scan, Target, _hash_evidence
from controller.db.session import create_db_engine
from controller.main import (
    FINDING_SCOPE_STATUS_IN_SCOPE,
    FINDING_SCOPE_STATUS_MIXED,
    FINDING_SCOPE_STATUS_OUT_OF_SCOPE,
    FINDING_SCOPE_STATUS_UNKNOWN,
    _filter_hosts_for_scope,
)

LOG = logging.getLogger("medusa.workers.scope")
CALLBACK_TOKEN_HEADER = "X-Callback-Token"

HOST_KEY_HINTS = {
    "host",
    "hostname",
    "ip",
    "ip_address",
    "domain",
    "target",
    "url",
    "remote_host",
    "address",
}
MAX_TRACKED_HOSTS = 256
HOST_PATTERN = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}", re.IGNORECASE
)


@dataclass
class WorkerConfig:
    """Configuration controlling polling cadence and anomaly dispatch."""

    database_url: str = field(
        default_factory=lambda: os.getenv(
            "DATABASE_URL",
            "postgresql+psycopg://medusa:medusa@localhost:5432/medusa",
        )
    )
    redis_url: Optional[str] = field(default_factory=lambda: os.getenv("REDIS_URL"))
    state_key: str = field(
        default_factory=lambda: os.getenv(
            "SCOPE_MONITOR_STATE_KEY", "workers:scope:last_seen"
        )
    )
    callback_url: str = field(
        default_factory=lambda: os.getenv(
            "ANOMALY_CALLBACK_URL", "http://localhost:8000/internal/anomalies"
        )
    )
    callback_token: Optional[str] = field(
        default_factory=lambda: os.getenv("ANOMALY_CALLBACK_TOKEN")
        or os.getenv("MEDUSA_ANOMALY_CALLBACK_TOKEN")
    )
    poll_interval: int = field(
        default_factory=lambda: int(os.getenv("SCOPE_MONITOR_POLL_INTERVAL", "30"))
    )
    batch_size: int = field(
        default_factory=lambda: int(os.getenv("SCOPE_MONITOR_BATCH_SIZE", "200"))
    )
    lookback_seconds: int = field(
        default_factory=lambda: int(
            os.getenv("SCOPE_MONITOR_LOOKBACK_SECONDS", "86400")
        )
    )
    http_timeout: int = field(
        default_factory=lambda: int(os.getenv("SCOPE_MONITOR_HTTP_TIMEOUT", "10"))
    )
    source: str = field(
        default_factory=lambda: os.getenv(
            "SCOPE_MONITOR_SOURCE", "worker:scope-monitor"
        )
    )
    audit_actor: str = field(
        default_factory=lambda: os.getenv("SCOPE_MONITOR_ACTOR", "worker:scope-monitor")
    )

    @classmethod
    def load(cls) -> "WorkerConfig":
        config = cls()
        LOG.debug("Loaded scope monitor config", extra={"config": config})
        return config


@dataclass
class ScopeDriftEvent:
    """Structured anomaly dispatched when scope violations are detected."""

    finding_id: str
    scan_id: str
    target_id: Optional[str]
    target_scope: Optional[str]
    rejected_hosts: List[str]
    allowed_hosts: List[str]
    scope_status: str
    severity: str
    observed_at: datetime

    def as_observation(self, source: str) -> Dict[str, object]:
        metadata = {
            "finding_id": self.finding_id,
            "scan_id": self.scan_id,
            "target_id": self.target_id,
            "target_scope": self.target_scope,
            "rejected_hosts": self.rejected_hosts,
            "allowed_hosts": self.allowed_hosts,
            "scope_status": self.scope_status,
            "severity": self.severity,
        }
        return {
            "anomaly_type": "scope_drift_detected",
            "actor": source,
            "first_seen": self.observed_at.isoformat(),
            "last_seen": self.observed_at.isoformat(),
            "count": max(1, len(self.rejected_hosts)),
            "window_seconds": 1,
            "metadata": metadata,
        }


class ScopeMonitorWorker:
    """Evaluate finding metadata for scope drift and raise anomalies."""

    def __init__(self, config: WorkerConfig) -> None:
        if requests is None:  # pragma: no cover - runtime guard
            raise RuntimeError(
                "requests package is required to run the scope monitor worker"
            )

        self._config = config
        self._engine: Engine = create_db_engine(config.database_url)
        self._session_factory = sessionmaker(
            bind=self._engine, expire_on_commit=False, class_=Session
        )
        self._http = requests.Session()
        self._redis = (
            redis.Redis.from_url(config.redis_url, decode_responses=True)
            if redis is not None and config.redis_url
            else None
        )
        self._last_seen: Optional[datetime] = None

    def run_forever(self) -> None:
        LOG.info(
            "Starting scope monitor worker",
            extra={"poll_interval": self._config.poll_interval},
        )
        while True:
            try:
                self.poll_once()
            except Exception:  # pragma: no cover - defensive logging
                LOG.exception("Scope monitor worker crash")
            time.sleep(max(1, self._config.poll_interval))

    def poll_once(self) -> List[ScopeDriftEvent]:
        """Process the next batch of findings and classify scope drift."""

        last_seen = self._load_last_seen()
        with self._session_factory() as session:
            findings = self._fetch_findings(session, last_seen)
            if not findings:
                return []

            drift_events: List[ScopeDriftEvent] = []
            newest_timestamp = last_seen
            for finding in findings:
                event = self._review_finding(session, finding)
                if event is not None:
                    drift_events.append(event)
                candidate_timestamp = finding.updated_at or finding.created_at
                if candidate_timestamp is not None:
                    if (
                        newest_timestamp is None
                        or candidate_timestamp > newest_timestamp
                    ):
                        newest_timestamp = candidate_timestamp
            session.commit()

        if newest_timestamp is not None:
            self._persist_last_seen(newest_timestamp)
        if drift_events:
            self._dispatch(drift_events)
        return drift_events

    def _fetch_findings(
        self, session: Session, last_seen: Optional[datetime]
    ) -> Sequence[Finding]:
        query = (
            select(Finding)
            .options(selectinload(Finding.scan).selectinload(Scan.target))
            .order_by(Finding.updated_at)
            .limit(self._config.batch_size)
        )
        if last_seen is not None:
            query = query.where(Finding.updated_at > last_seen)
        if self._config.lookback_seconds > 0:
            cutoff = datetime.now(tz=timezone.utc) - timedelta(
                seconds=self._config.lookback_seconds
            )
            query = query.where(Finding.updated_at >= cutoff)
        result = session.execute(query)
        return list(result.scalars())

    def _review_finding(
        self, session: Session, finding: Finding
    ) -> Optional[ScopeDriftEvent]:
        scan = finding.scan
        target = scan.target if scan is not None else None
        if target is None or not target.scope:
            return None

        hosts = _extract_candidate_hosts(finding.metadata_json, finding.evidence)
        if not hosts:
            desired_status = FINDING_SCOPE_STATUS_UNKNOWN
            return self._apply_scope_status(
                session, finding, desired_status, [], [], target
            )

        allowed_hosts, rejected_hosts = _filter_hosts_for_scope(target.scope, hosts)
        if rejected_hosts and allowed_hosts:
            desired_status = FINDING_SCOPE_STATUS_MIXED
        elif rejected_hosts:
            desired_status = FINDING_SCOPE_STATUS_OUT_OF_SCOPE
        elif allowed_hosts:
            desired_status = FINDING_SCOPE_STATUS_IN_SCOPE
        else:
            desired_status = FINDING_SCOPE_STATUS_UNKNOWN

        return self._apply_scope_status(
            session, finding, desired_status, allowed_hosts, rejected_hosts, target
        )

    def _apply_scope_status(
        self,
        session: Session,
        finding: Finding,
        desired_status: str,
        allowed_hosts: List[str],
        rejected_hosts: List[str],
        target: Optional[Target],
    ) -> Optional[ScopeDriftEvent]:
        normalized_current = (finding.scope_status or "").strip().lower()
        if normalized_current not in {
            FINDING_SCOPE_STATUS_UNKNOWN,
            FINDING_SCOPE_STATUS_IN_SCOPE,
            FINDING_SCOPE_STATUS_OUT_OF_SCOPE,
            FINDING_SCOPE_STATUS_MIXED,
        }:
            normalized_current = FINDING_SCOPE_STATUS_UNKNOWN

        if normalized_current == desired_status:
            return None

        timestamp = datetime.now(tz=timezone.utc)
        finding.scope_status = desired_status
        finding.updated_at = timestamp
        session.add(finding)

        drift_event: Optional[ScopeDriftEvent] = None
        if desired_status in {
            FINDING_SCOPE_STATUS_OUT_OF_SCOPE,
            FINDING_SCOPE_STATUS_MIXED,
        }:
            snapshot = {
                "finding_id": str(finding.id),
                "scan_id": str(finding.scan_id),
                "target_id": str(target.id) if target else None,
                "target_scope": target.scope if target else None,
                "scope_status": desired_status,
                "allowed_hosts": allowed_hosts,
                "rejected_hosts": rejected_hosts,
                "remediation": (
                    "Purge out-of-scope evidence and coordinate with the client "
                    "to adjust scope or discard the artifact."
                ),
            }
            audit_entry = AuditLog(
                scan_id=finding.scan_id,
                finding_id=finding.id,
                actor=self._config.audit_actor,
                action="scope_drift_detected",
                message="Finding evidence references assets outside authorized scope.",
                evidence_snapshot=snapshot,
                evidence_hash=_hash_evidence(snapshot),
            )
            session.add(audit_entry)
            drift_event = ScopeDriftEvent(
                finding_id=str(finding.id),
                scan_id=str(finding.scan_id),
                target_id=str(target.id) if target else None,
                target_scope=target.scope if target else None,
                rejected_hosts=list(rejected_hosts),
                allowed_hosts=list(allowed_hosts),
                scope_status=desired_status,
                severity=finding.severity,
                observed_at=timestamp,
            )

        return drift_event

    def _dispatch(self, events: Iterable[ScopeDriftEvent]) -> None:
        observations = [event.as_observation(self._config.source) for event in events]
        if not observations:
            return

        payload = {
            "source": self._config.source,
            "detected_at": datetime.now(tz=timezone.utc).isoformat(),
            "anomalies": observations,
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
        if response.status_code >= 300:  # pragma: no cover - runtime diagnostics
            LOG.warning(
                "Controller rejected scope anomaly payload",
                extra={"status": response.status_code, "body": response.text[:200]},
            )

    def _load_last_seen(self) -> Optional[datetime]:
        if self._redis is not None:
            raw = self._redis.get(self._config.state_key)
            if raw:
                try:
                    timestamp = datetime.fromisoformat(raw)
                    if timestamp.tzinfo is None:
                        timestamp = timestamp.replace(tzinfo=timezone.utc)
                    return timestamp
                except ValueError:
                    LOG.warning(
                        "Invalid timestamp in scope monitor state",
                        extra={"value": raw},
                    )
        return self._last_seen

    def _persist_last_seen(self, value: datetime) -> None:
        timestamp = value.astimezone(timezone.utc).isoformat()
        self._last_seen = value
        if self._redis is not None:
            self._redis.set(self._config.state_key, timestamp)


def _extract_candidate_hosts(*payloads: Dict[str, object]) -> List[str]:
    """Search metadata and evidence payloads for host/IP strings."""

    hosts: Set[str] = set()
    seen: Set[str] = set()

    def _consider_string(value: str, hint: Optional[str]) -> None:
        if len(value) > 512:
            return
        lowered_hint = hint.lower() if hint else ""
        inspect_value = bool(lowered_hint in HOST_KEY_HINTS)
        if "://" in value:
            inspect_value = True
        if not inspect_value and any(char in value for char in ".:"):
            inspect_value = True
        if not inspect_value:
            return

        candidates = _parse_string_for_hosts(value)
        for candidate in candidates:
            if candidate not in seen:
                seen.add(candidate)
                hosts.add(candidate)
                if len(hosts) >= MAX_TRACKED_HOSTS:
                    return

    def _walk(node: object, hint: Optional[str] = None) -> None:
        if node is None:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                next_hint = str(key).lower() if isinstance(key, str) else hint
                _walk(value, next_hint)
        elif isinstance(node, (list, tuple, set)):
            for item in node:
                _walk(item, hint)
        elif isinstance(node, str):
            _consider_string(node, hint)
        else:
            return

    for payload in payloads:
        _walk(payload)
        if len(hosts) >= MAX_TRACKED_HOSTS:
            break

    return sorted(hosts)


def _parse_string_for_hosts(value: str) -> List[str]:
    """Extract hostnames and IPs from an arbitrary string."""

    candidates: Set[str] = set()

    trimmed = value.strip().strip("[](){}<>")
    if not trimmed:
        return []

    try:
        parsed = urlparse(trimmed)
        if parsed.hostname:
            candidates.add(parsed.hostname.lower())
    except ValueError:
        pass

    for token in re.split(r"[^A-Za-z0-9:\-\.]+", trimmed):
        token = token.strip()
        if not token:
            continue
        if len(token) > 255:
            continue
        normalized = _normalize_candidate(token)
        if normalized:
            candidates.add(normalized)

    return sorted(candidates)


def _normalize_candidate(value: str) -> Optional[str]:
    """Normalize host/IP tokens discovered in payloads."""

    from ipaddress import ip_address

    try:
        return str(ip_address(value))
    except ValueError:
        pass

    lowered = value.lower().strip(".")
    if HOST_PATTERN.fullmatch(lowered):
        return lowered
    return None


__all__ = ["ScopeMonitorWorker", "WorkerConfig"]
