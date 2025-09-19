"""Integration tests exercising ORM behavior using SQLite."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Optional

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from controller.db.models import (
    AuditLog,
    Base,
    Finding,
    FindingEnrichment,
    Scan,
    Target,
)


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


def _expected_finding_hash(evidence: dict, metadata: Optional[dict] = None) -> str:
    payload = {
        "metadata": metadata or {},
        "evidence": evidence,
    }
    normalized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _expected_audit_hash(snapshot: dict) -> str:
    normalized = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _expected_json_hash(payload) -> str:
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
        initiated_by="controller",
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
    assert reloaded_target.scans[0].findings[0].evidence_hash == _expected_finding_hash(
        {"request": "GET /?q=<script>"}
    )


def test_finding_evidence_is_immutable(session: Session) -> None:
    target = Target(name="API", scope="api.medusa", is_authorized=True)
    session.add(target)
    session.flush()

    scan = Scan(
        target_id=target.id, scanner="zap", parameters={}, initiated_by="controller"
    )
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

    assert finding.evidence_hash == _expected_finding_hash(evidence_payload)

    with pytest.raises(ValueError):
        finding.evidence = {"response_code": 200}
        session.flush()
    session.rollback()

    with pytest.raises(ValueError):
        finding.metadata_json = {"response_code": 200}
        session.flush()
    session.rollback()


def test_audit_log_evidence_is_immutable(session: Session) -> None:
    target = Target(name="Staging", scope="10.10.0.5", is_authorized=True)
    session.add(target)
    session.flush()

    scan = Scan(
        target_id=target.id,
        scanner="custom",
        parameters={},
        initiated_by="controller",
    )
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

    assert log.evidence_hash == _expected_audit_hash({"status": "queued"})

    with pytest.raises(ValueError):
        log.evidence_snapshot = {"status": "updated"}
        session.flush()
    session.rollback()


def test_finding_enrichment_hashes_and_immutability(session: Session) -> None:
    target = Target(name="Scope", scope="scope.example", is_authorized=True)
    session.add(target)
    session.flush()

    scan = Scan(
        target_id=target.id,
        scanner="nuclei",
        parameters={},
        initiated_by="controller",
        status="completed",
    )
    session.add(scan)
    session.flush()

    finding = Finding(
        scan_id=scan.id,
        title="Example",
        severity="medium",
        cve_id="CVE-2024-1111",
        description="Example",
        evidence={"path": "/"},
        evidence_hash="",
    )
    session.add(finding)
    session.flush()

    advisories = [
        {
            "source": "nvd",
            "identifier": "CVE-2024-1111",
            "references": ["https://example.com"],
            "raw": {"id": "CVE-2024-1111"},
        }
    ]
    errors = {"circl": "timeout"}
    provenance = {
        "worker_subject": "worker:enrichment",
        "received_at": datetime.now(timezone.utc).isoformat(),
    }

    enrichment = FindingEnrichment(
        finding_id=finding.id,
        job_id="job-orm-1",
        generated_at=datetime.now(timezone.utc),
        advisories=advisories,
        advisories_hash="",
        errors=errors,
        errors_hash="",
        provenance=provenance,
        provenance_hash="",
        payload_hash="",
    )
    session.add(enrichment)
    session.commit()

    assert enrichment.advisories_hash == _expected_json_hash(advisories)
    assert enrichment.errors_hash == _expected_json_hash(errors)
    assert enrichment.provenance_hash == _expected_json_hash(provenance)
    composite = {
        "advisories": enrichment.advisories_hash,
        "errors": enrichment.errors_hash,
        "provenance": enrichment.provenance_hash,
    }
    assert enrichment.payload_hash == _expected_json_hash(composite)

    with pytest.raises(ValueError):
        enrichment.errors = {}
        session.flush()
    session.rollback()
