from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from controller.db.models import AuditLog, Base, Finding, Scan, Target
from controller.main import (
    FINDING_SCOPE_STATUS_IN_SCOPE,
    FINDING_SCOPE_STATUS_OUT_OF_SCOPE,
    FINDING_SCOPE_STATUS_UNKNOWN,
)
from workers.scope.worker import ScopeMonitorWorker, WorkerConfig


def _setup_database(tmp_path: Path) -> tuple[str, sessionmaker[Session]]:
    db_path = tmp_path / "scope.db"
    db_url = f"sqlite+pysqlite:///{db_path}"
    engine = create_engine(db_url, future=True)
    Base.metadata.create_all(bind=engine)
    return db_url, sessionmaker(bind=engine, expire_on_commit=False, class_=Session)


def _create_finding(
    session: Session,
    *,
    target_scope: str,
    metadata: Dict[str, object],
    evidence: Dict[str, object],
    finding_id: str,
) -> None:
    target = Target(
        id="target-1", name="Authorized", scope=target_scope, is_authorized=True
    )
    scan = Scan(id="scan-1", target=target, scanner="nuclei", status="completed")
    finding = Finding(
        id=finding_id,
        scan=scan,
        title="SQL injection",
        severity="medium",
        description="Union-based SQL injection",
        metadata_json=metadata,
        evidence=evidence,
        evidence_hash="0" * 64,
        status="open",
        validation_status="pending",
        validation_metadata={},
        tags=[],
    )
    session.add(finding)
    session.commit()


def test_scope_monitor_flags_out_of_scope(tmp_path: Path) -> None:
    db_url, SessionLocal = _setup_database(tmp_path)
    with SessionLocal() as session:
        _create_finding(
            session,
            target_scope="example.com",
            metadata={"url": "http://evil.example.net/login"},
            evidence={"host": "evil.example.net"},
            finding_id="finding-out",
        )

    config = WorkerConfig(
        database_url=db_url,
        redis_url=None,
        callback_url="http://controller/internal/anomalies",
        callback_token=None,
        poll_interval=0,
        batch_size=10,
        lookback_seconds=86400,
    )
    worker = ScopeMonitorWorker(config)

    dispatched: List = []

    def _capture(events):
        dispatched.extend(events)

    worker._dispatch = _capture  # type: ignore[assignment]

    events = worker.poll_once()
    assert len(events) == 1
    event = events[0]
    assert event.scope_status == FINDING_SCOPE_STATUS_OUT_OF_SCOPE
    assert event.rejected_hosts == ["evil.example.net"]

    with SessionLocal() as session:
        finding = session.get(Finding, "finding-out")
        assert finding is not None
        assert finding.scope_status == FINDING_SCOPE_STATUS_OUT_OF_SCOPE
        audits = session.query(AuditLog).all()
        assert len(audits) == 1
        entry = audits[0]
        assert entry.actor == config.audit_actor
        assert entry.evidence_snapshot["rejected_hosts"] == ["evil.example.net"]

    # Ensure repeated polling does not duplicate anomalies once the status is set
    second_events = worker.poll_once()
    assert second_events == []
    assert (
        dispatched and dispatched[0].scope_status == FINDING_SCOPE_STATUS_OUT_OF_SCOPE
    )

    with SessionLocal() as session:
        assert session.query(AuditLog).count() == 1


def test_scope_monitor_marks_in_scope_without_alert(tmp_path: Path) -> None:
    db_url, SessionLocal = _setup_database(tmp_path)
    with SessionLocal() as session:
        _create_finding(
            session,
            target_scope="example.com",
            metadata={"host": "api.example.com"},
            evidence={"details": {"url": "https://api.example.com/login"}},
            finding_id="finding-in",
        )

    config = WorkerConfig(
        database_url=db_url,
        redis_url=None,
        callback_url="http://controller/internal/anomalies",
        callback_token=None,
        poll_interval=0,
        batch_size=10,
        lookback_seconds=86400,
    )
    worker = ScopeMonitorWorker(config)

    worker._dispatch = lambda events: None  # type: ignore[assignment]

    events = worker.poll_once()
    assert events == []

    with SessionLocal() as session:
        finding = session.get(Finding, "finding-in")
        assert finding is not None
        assert finding.scope_status == FINDING_SCOPE_STATUS_IN_SCOPE
        assert session.query(AuditLog).count() == 0

    # Hosts remain unchanged so repeated polling should be a no-op
    assert worker.poll_once() == []


@pytest.mark.parametrize(
    "metadata, evidence",
    [
        ({"notes": "No network identifiers"}, {}),
        ({}, {"response": "plain text"}),
    ],
)
def test_scope_monitor_leaves_unknown_when_no_hosts(
    tmp_path: Path, metadata: Dict[str, object], evidence: Dict[str, object]
) -> None:
    db_url, SessionLocal = _setup_database(tmp_path)
    with SessionLocal() as session:
        _create_finding(
            session,
            target_scope="example.com",
            metadata=metadata,
            evidence=evidence,
            finding_id="finding-unknown",
        )

    config = WorkerConfig(
        database_url=db_url,
        redis_url=None,
        callback_url="http://controller/internal/anomalies",
        callback_token=None,
        poll_interval=0,
        batch_size=10,
        lookback_seconds=86400,
    )
    worker = ScopeMonitorWorker(config)
    worker._dispatch = lambda events: None  # type: ignore[assignment]

    events = worker.poll_once()
    assert events == []

    with SessionLocal() as session:
        finding = session.get(Finding, "finding-unknown")
        assert finding is not None
        assert finding.scope_status == FINDING_SCOPE_STATUS_UNKNOWN
        assert session.query(AuditLog).count() == 0
