"""Integration tests exercising ORM behavior using SQLite."""
from __future__ import annotations

import hashlib
import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from controller.db.models import AuditLog, Base, Finding, Scan, Target


@pytest.fixture()
def session() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(bind=engine, expire_on_commit=False)
    session = TestingSession()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


def _expected_hash(payload: dict) -> str:
    normalized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def test_target_scan_finding_crud(session: Session) -> None:
    target = Target(name="Authorized Demo", scope="demo.medusa", is_authorized=True)
    session.add(target)
    session.flush()

    scan = Scan(
        target_id=target.id,
        scanner="nuclei",
        parameters={"template": "example"},
    )
    session.add(scan)
    session.flush()

    finding = Finding(
        scan_id=scan.id,
        title="Cross-Site Scripting",
        severity="high",
        cve_id="CVE-2024-1234",
        description="Reflected XSS in search endpoint",
        evidence={"request": "GET /?q=<script>"},
        evidence_hash="",
    )
    session.add(finding)
    session.commit()

    reloaded_target = session.get(Target, target.id)
    assert reloaded_target is not None
    assert reloaded_target.scans[0].id == scan.id
    assert reloaded_target.scans[0].findings[0].id == finding.id
    assert reloaded_target.scans[0].findings[0].evidence_hash == _expected_hash(
        {"request": "GET /?q=<script>"}
    )


def test_finding_evidence_is_immutable(session: Session) -> None:
    target = Target(name="API", scope="api.medusa", is_authorized=True)
    session.add(target)
    session.flush()

    scan = Scan(target_id=target.id, scanner="zap", parameters={})
    session.add(scan)
    session.flush()

    evidence_payload = {"response_code": 500}
    finding = Finding(
        scan_id=scan.id,
        title="Server Error",
        severity="medium",
        cve_id=None,
        description="Unhandled exception surfaced",
        evidence=evidence_payload,
        evidence_hash="",
    )
    session.add(finding)
    session.commit()

    assert finding.evidence_hash == _expected_hash(evidence_payload)

    with pytest.raises(ValueError):
        finding.evidence = {"response_code": 200}
        session.flush()
    session.rollback()


def test_audit_log_evidence_is_immutable(session: Session) -> None:
    target = Target(name="Staging", scope="10.10.0.5", is_authorized=True)
    session.add(target)
    session.flush()

    scan = Scan(target_id=target.id, scanner="custom", parameters={})
    session.add(scan)
    session.flush()

    log = AuditLog(
        scan_id=scan.id,
        finding_id=None,
        actor="controller",
        action="scan.created",
        message="Scan queued",
        evidence_snapshot={"status": "queued"},
        evidence_hash="",
    )
    session.add(log)
    session.commit()

    assert log.evidence_hash == _expected_hash({"status": "queued"})

    with pytest.raises(ValueError):
        log.evidence_snapshot = {"status": "updated"}
        session.flush()
    session.rollback()
