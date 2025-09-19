from datetime import datetime, timedelta, timezone
import uuid
from typing import Tuple

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

import jwt
from controller.db.models import (
    AuditLog,
    Base,
    BinaryFuzzingFinding,
    BinarySample,
    BinaryStaticAnalysisFinding,
    Finding,
    FindingEnrichment,
    PrincipalCredential,
    Scan,
    Target,
)
from controller.main import (
    DEFAULT_ADMIN_ROLES,
    DEFAULT_ANALYST_ROLES,
    NUCLEI_TEMPLATE_PROFILES,
    Settings,
    _hash_secret,
    app,
)
from controller.tests.conftest import InMemoryQueue


def auth_headers() -> dict[str, str]:
    return {"X-API-Key": "test-key"}


def enrichment_headers() -> dict[str, str]:
    return {"X-Callback-Token": "enrichment-secret"}


def binary_static_headers() -> dict[str, str]:
    return {"X-Callback-Token": "binary-static-secret"}


def binary_fuzzing_headers() -> dict[str, str]:
    return {"X-Callback-Token": "binary-fuzzing-secret"}


def validator_headers() -> dict[str, str]:
    return {"X-Callback-Token": "validator-secret"}


def _create_finding_record(session_factory: sessionmaker) -> str:
    """Persist a minimal target/scan/finding for RBAC regression tests."""

    with session_factory() as session:
        target = Target(name="RBAC Target", scope="rbac.example", is_authorized=True)
        session.add(target)
        session.flush()

        scan = Scan(
            target_id=target.id,
            scanner="nuclei",
            initiated_by="rbac-tester",
            status="completed",
            parameters={"profile": "regression"},
        )
        session.add(scan)
        session.flush()

        finding = Finding(
            scan_id=scan.id,
            title="Synthetic SQL Injection",
            severity="high",
            cve_id="CVE-2099-0001",
            description="Regression finding for RBAC coverage.",
            metadata_json={"vector": "GET /?id=1"},
            evidence={"proof": "error-based"},
            evidence_hash="",
        )
        session.add(finding)
        session.commit()

        return str(finding.id)


def _provision_principal(
    client: TestClient, subject: str, roles: list[str]
) -> Tuple[str, dict[str, str]]:
    """Create a new API key credential and return the secret and auth header."""

    response = client.post(
        "/principals",
        json={
            "subject": subject,
            "auth_method": "api_key",
            "roles": roles,
            "description": "rbac-regression",
        },
        headers=auth_headers(),
    )
    assert response.status_code == 201, response.text
    payload = response.json()
    secret = payload["secret"]
    fingerprint = payload["key_fingerprint"]
    assert isinstance(fingerprint, str) and fingerprint
    return secret, {"X-API-Key": secret}


def test_target_create_and_scan_flow(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings],
) -> None:
    client, queue, _session_factory, _settings = api_client

    response = client.post(
        "/targets",
        json={"name": "Prod API", "scope": "prod.example.com"},
        headers=auth_headers(),
    )
    assert response.status_code == 201, response.text
    target_payload = response.json()

    assert isinstance(target_payload["id"], str)
    assert target_payload["scope"] == "prod.example.com"
    assert target_payload["is_authorized"] is True

    scan_response = client.post(
        "/scan",
        json={
            "target_id": target_payload["id"],
            "scanner": "nuclei",
            "parameters": {"profile": "full"},
        },
        headers=auth_headers(),
    )
    assert scan_response.status_code == 202, scan_response.text
    scan_payload = scan_response.json()

    assert scan_payload["target"] == "prod.example.com"
    assert scan_payload["scanner"] == "nuclei"
    assert scan_payload["status"] == "queued"
    assert scan_payload["findings_count"] == 0
    assert isinstance(scan_payload["created_at"], str)
    assert isinstance(scan_payload["updated_at"], str)

    assert queue.messages, "enqueue should push a job to the queue"
    channel, job = queue.messages[-1]
    assert channel == "nuclei:test"
    assert uuid.UUID(job["job_id"]).version == 4
    assert job["scan_id"] == scan_payload["id"]
    assert job["target"] == target_payload["scope"]
    assert job["target_id"] == target_payload["id"]


def test_preprocess_enqueue_flow(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings],
) -> None:
    client, queue, session_factory, settings = api_client

    target_response = client.post(
        "/targets",
        json={"name": "Firmware", "scope": "firmware.example.com"},
        headers=auth_headers(),
    )
    assert target_response.status_code == 201, target_response.text
    target_payload = target_response.json()

    preprocess_response = client.post(
        "/preprocess",
        json={
            "target_id": target_payload["id"],
            "object_bucket": "binary-uploads",
            "object_key": "uploads/sample.bin",
            "file_name": "sample.bin",
            "expected_scope": "firmware.example.com",
            "metadata": {"sha256": "deadbeef"},
        },
        headers=auth_headers(),
    )
    assert preprocess_response.status_code == 202, preprocess_response.text
    payload = preprocess_response.json()
    assert payload["scanner"] == "binary_preprocess"
    assert payload["target"] == "firmware.example.com"

    assert queue.messages, "enqueue should push a job to the queue"
    channel, job = queue.messages[-1]
    assert channel == settings.binary_preprocess_queue_channel
    assert job["target_id"] == target_payload["id"]
    assert job["object_bucket"] == "binary-uploads"
    assert job["metadata"]["target_scope"] == "firmware.example.com"

    with session_factory() as session:
        audit_entry = (
            session.query(AuditLog)
            .filter(AuditLog.action == "enqueue_binary_preprocess")
            .order_by(AuditLog.created_at.desc())
            .first()
        )

        assert audit_entry is not None
        snapshot = audit_entry.evidence_snapshot
        assert snapshot.get("resource_id") == payload["id"]
        assert snapshot.get("object_bucket") == "binary-uploads"


def test_preprocess_scope_mismatch_audited(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings],
) -> None:
    client, queue, session_factory, _settings = api_client

    target_response = client.post(
        "/targets",
        json={"name": "Firmware", "scope": "firmware.example.com"},
        headers=auth_headers(),
    )
    target_payload = target_response.json()

    response = client.post(
        "/preprocess",
        json={
            "target_id": target_payload["id"],
            "object_bucket": "binary-uploads",
            "object_key": "uploads/sample.bin",
            "expected_scope": "attacker.example.com",
        },
        headers=auth_headers(),
    )
    assert response.status_code == 400, response.text
    assert not queue.messages

    with session_factory() as session:
        audit_entries = (
            session.query(AuditLog)
            .filter(AuditLog.action == "preprocess_scope_mismatch")
            .all()
        )
        assert audit_entries, "scope mismatches should be audited"


def test_static_analysis_enqueue_flow(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings],
) -> None:
    client, queue, session_factory, settings = api_client

    target_response = client.post(
        "/targets",
        json={"name": "Firmware", "scope": "firmware.example.com"},
        headers=auth_headers(),
    )
    assert target_response.status_code == 201, target_response.text
    target_payload = target_response.json()

    with session_factory() as session:
        preprocess_scan = Scan(
            target_id=target_payload["id"],
            scanner="binary_preprocess",
            initiated_by="tester",
            status="completed",
            parameters={},
        )
        session.add(preprocess_scan)
        session.flush()

        sample = BinarySample(
            scan_id=preprocess_scan.id,
            target_id=target_payload["id"],
            file_name="sample.bin",
            sha256="ab" * 32,
            file_size=1024,
            mime_type="application/octet-stream",
            magic_type="ELF 64-bit",
            policy_status="allowed",
            policy_reasons=[],
            storage_bucket="binary-uploads",
            storage_key="uploads/sample.bin",
            metadata_json={"sha256": "ab" * 32},
            metadata_hash="",
            processed_at=datetime.now(tz=timezone.utc),
        )
        session.add(sample)
        session.commit()
        sample_id = sample.id

    response = client.post(
        "/binary/static-analysis",
        json={
            "sample_id": sample_id,
            "target_id": target_payload["id"],
            "metadata": {"profile": "baseline"},
        },
        headers=auth_headers(),
    )
    assert response.status_code == 202, response.text
    payload = response.json()
    assert payload["scanner"] == "binary_static_analysis"

    assert queue.messages, "static analysis enqueue should push a job"
    channel, job = queue.messages[-1]
    assert channel == settings.binary_static_analysis_queue_channel
    assert job["sample_id"] == sample_id
    assert job["callback_url"].endswith("/internal/binary/static-analysis/callback")
    assert job["metadata"]["target_id"] == target_payload["id"]


def test_binary_static_analysis_callback_persists_findings(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings],
) -> None:
    client, _queue, session_factory, _settings = api_client

    with session_factory() as session:
        target = Target(
            name="Firmware", scope="firmware.example.com", is_authorized=True
        )
        session.add(target)
        session.flush()

        preprocess_scan = Scan(
            target_id=target.id,
            scanner="binary_preprocess",
            initiated_by="tester",
            status="completed",
            parameters={},
        )
        session.add(preprocess_scan)
        session.flush()

        sample = BinarySample(
            scan_id=preprocess_scan.id,
            target_id=target.id,
            file_name="sample.bin",
            sha256="cd" * 32,
            file_size=2048,
            mime_type="application/octet-stream",
            magic_type="ELF 64-bit",
            policy_status="allowed",
            policy_reasons=[],
            storage_bucket="binary-uploads",
            storage_key="uploads/sample.bin",
            metadata_json={},
            metadata_hash="",
            processed_at=datetime.now(tz=timezone.utc),
        )
        session.add(sample)
        session.flush()

        analysis_scan = Scan(
            target_id=target.id,
            scanner="binary_static_analysis",
            initiated_by="tester",
            status="running",
            parameters={"sample_id": sample.id},
        )
        session.add(analysis_scan)
        session.commit()

        sample_id = sample.id
        scan_id = analysis_scan.id

    executed_at = datetime.now(tz=timezone.utc)
    response = client.post(
        "/internal/binary/static-analysis/callback",
        json={
            "job_id": "job-static-1",
            "scan_id": scan_id,
            "sample_id": sample_id,
            "status": "completed",
            "processed_at": executed_at.isoformat(),
            "findings": [
                {
                    "tool": "checksec",
                    "severity": "high",
                    "title": "NX disabled",
                    "description": "Executable is missing NX",
                    "metadata": {"feature": "nx", "state": "no"},
                    "evidence": {"raw": {"nx": "no"}},
                    "artifact_bucket": "analysis",
                    "artifact_key": "reports/checksec.json",
                    "executed_at": executed_at.isoformat(),
                }
            ],
            "artifacts": [
                {
                    "tool": "checksec",
                    "bucket": "analysis",
                    "key": "reports/checksec.json",
                }
            ],
            "reports": [],
            "metadata": {},
        },
        headers=binary_static_headers(),
    )
    assert response.status_code == 204, response.text

    with session_factory() as session:
        findings = (
            session.query(BinaryStaticAnalysisFinding)
            .filter(BinaryStaticAnalysisFinding.scan_id == scan_id)
            .all()
        )
        assert len(findings) == 1
        finding = findings[0]
        assert finding.tool == "checksec"
        assert finding.severity == "high"
        assert finding.artifact_bucket == "analysis"
        assert finding.artifact_key == "reports/checksec.json"

        scan = session.get(Scan, scan_id)
        assert scan is not None
        assert scan.status == "completed"
        assert scan.completed_at is not None


def test_binary_fuzzing_enqueue(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings],
) -> None:
    client, queue, session_factory, settings = api_client

    with session_factory() as session:
        target = Target(
            name="Firmware", scope="firmware.example.com", is_authorized=True
        )
        session.add(target)
        session.flush()

        preprocess_scan = Scan(
            target_id=target.id,
            scanner="binary_preprocess",
            initiated_by="tester",
            status="completed",
            parameters={},
        )
        session.add(preprocess_scan)
        session.flush()

        sample = BinarySample(
            scan_id=preprocess_scan.id,
            target_id=target.id,
            file_name="sample.bin",
            sha256="ab" * 32,
            file_size=4096,
            mime_type="application/octet-stream",
            magic_type="ELF 64-bit",
            policy_status="allowed",
            policy_reasons=[],
            storage_bucket="binary-uploads",
            storage_key="uploads/sample.bin",
            metadata_json={},
            metadata_hash="",
            processed_at=datetime.now(tz=timezone.utc),
        )
        session.add(sample)
        session.commit()

        sample_id = sample.id
        target_payload = {"id": target.id}

    response = client.post(
        "/binary/fuzzing",
        json={
            "sample_id": sample_id,
            "target_id": target_payload["id"],
            "fuzz_duration_seconds": 120,
            "metadata": {"profile": "quick"},
        },
        headers=auth_headers(),
    )
    assert response.status_code == 202, response.text
    payload = response.json()
    assert payload["scanner"] == "binary_fuzzing"

    assert queue.messages, "fuzzing enqueue should push a job"
    channel, job = queue.messages[-1]
    assert channel == settings.binary_fuzzing_queue_channel
    assert job["sample_id"] == sample_id
    assert job["callback_url"].endswith("/internal/binary/fuzzing/callback")
    assert job["metadata"]["target_id"] == target_payload["id"]
    assert job["max_duration_seconds"] == 120


def test_binary_fuzzing_callback_persists_findings(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings],
) -> None:
    client, _queue, session_factory, _settings = api_client

    with session_factory() as session:
        target = Target(
            name="Firmware", scope="firmware.example.com", is_authorized=True
        )
        session.add(target)
        session.flush()

        preprocess_scan = Scan(
            target_id=target.id,
            scanner="binary_preprocess",
            initiated_by="tester",
            status="completed",
            parameters={},
        )
        session.add(preprocess_scan)
        session.flush()

        sample = BinarySample(
            scan_id=preprocess_scan.id,
            target_id=target.id,
            file_name="sample.bin",
            sha256="ef" * 32,
            file_size=8192,
            mime_type="application/octet-stream",
            magic_type="ELF 64-bit",
            policy_status="allowed",
            policy_reasons=[],
            storage_bucket="binary-uploads",
            storage_key="uploads/sample.bin",
            metadata_json={},
            metadata_hash="",
            processed_at=datetime.now(tz=timezone.utc),
        )
        session.add(sample)
        session.flush()

        fuzz_scan = Scan(
            target_id=target.id,
            scanner="binary_fuzzing",
            initiated_by="tester",
            status="running",
            parameters={"sample_id": sample.id},
        )
        session.add(fuzz_scan)
        session.commit()

        sample_id = sample.id
        scan_id = fuzz_scan.id

    executed_at = datetime.now(tz=timezone.utc)
    response = client.post(
        "/internal/binary/fuzzing/callback",
        json={
            "job_id": "job-fuzz-1",
            "scan_id": scan_id,
            "sample_id": sample_id,
            "status": "completed",
            "processed_at": executed_at.isoformat(),
            "findings": [
                {
                    "tool": "afl",
                    "severity": "high",
                    "title": "Crash detected",
                    "description": "AFL discovered a crash",
                    "metadata": {"crash_id": "id-1"},
                    "evidence": {"input": "AAAA"},
                    "artifact_bucket": "analysis",
                    "artifact_key": "fuzzing/afl.json",
                    "executed_at": executed_at.isoformat(),
                    "crash_type": "SEGV",
                }
            ],
            "artifacts": [
                {
                    "tool": "afl",
                    "bucket": "analysis",
                    "key": "fuzzing/afl.json",
                }
            ],
            "runs": [],
            "metadata": {},
        },
        headers=binary_fuzzing_headers(),
    )
    assert response.status_code == 204, response.text

    with session_factory() as session:
        findings = (
            session.query(BinaryFuzzingFinding)
            .filter(BinaryFuzzingFinding.scan_id == scan_id)
            .all()
        )
        assert len(findings) == 1
        finding = findings[0]
        assert finding.tool == "afl"
        assert finding.metadata_json.get("crash_id") == "id-1"
        assert finding.artifact_key == "fuzzing/afl.json"

        scan = session.get(Scan, scan_id)
        assert scan is not None
        assert scan.status == "completed"
        assert scan.completed_at is not None


def test_validation_enqueue_and_callback(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings]
) -> None:
    client, queue, session_factory, settings = api_client
    finding_id = _create_finding_record(session_factory)

    enqueue_response = client.post(
        "/validate",
        json={"finding_id": finding_id},
        headers=auth_headers(),
    )
    assert enqueue_response.status_code == 202, enqueue_response.text
    enqueue_payload = enqueue_response.json()
    assert enqueue_payload["status"] == "queued"

    assert queue.messages, "validator enqueue should push a job"
    channel, job_payload = queue.messages[-1]
    assert channel == settings.validator_queue_channel
    assert job_payload["validation_id"] == enqueue_payload["validation_id"]

    callback_payload = {
        "validation_id": enqueue_payload["validation_id"],
        "finding_id": finding_id,
        "job_id": job_payload["job_id"],
        "status": "completed",
        "processed_at": datetime.now(timezone.utc).isoformat(),
        "outcome": "confirmed",
        "attempts": 0,
        "observations": {"status_code": 200},
        "evidence": {"response_snippet": "validator-confirmed"},
    }

    callback_response = client.post(
        "/internal/validate/callback",
        json=callback_payload,
        headers=validator_headers(),
    )
    assert callback_response.status_code == 204, callback_response.text

    finding_response = client.get(
        f"/findings/{finding_id}", headers=auth_headers()
    )
    assert finding_response.status_code == 200, finding_response.text
    finding_payload = finding_response.json()["data"]
    validation_summary = finding_payload.get("validation")
    assert validation_summary is not None
    assert validation_summary["status"] == "completed"
    assert validation_summary["outcome"] == "confirmed"


def test_scan_requested_hosts_scope_enforcement(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings],
) -> None:
    client, queue, session_factory, _settings = api_client

    with session_factory() as session:
        target = Target(name="Authorized", scope="demo.medusa", is_authorized=True)
        session.add(target)
        session.commit()
        target_id = target.id

    response = client.post(
        "/scan",
        json={
            "target_id": target_id,
            "scanner": "nuclei",
            "parameters": {
                "requested_hosts": [
                    "api.demo.medusa",
                    "API.DEMO.MEDUSA",
                    "db.demo.medusa.",
                    "malicious.example.com",
                ]
            },
        },
        headers=auth_headers(),
    )

    assert response.status_code == 202, response.text
    payload = response.json()

    sanitized_hosts = ["api.demo.medusa", "db.demo.medusa"]
    assert queue.messages, "expected sanitized scan to enqueue"
    _, job_payload = queue.messages[-1]
    assert job_payload["parameters"]["requested_hosts"] == sanitized_hosts

    with session_factory() as session:
        scan = session.query(Scan).filter(Scan.id == payload["id"]).one()
        assert scan.parameters["requested_hosts"] == sanitized_hosts

        audit_entry = (
            session.query(AuditLog)
            .filter(
                AuditLog.scan_id == scan.id,
                AuditLog.action == "enqueue_scan",
            )
            .one()
        )
        snapshot = audit_entry.evidence_snapshot
        assert snapshot["requested_hosts"] == sanitized_hosts
        assert snapshot["rejected_hosts"] == ["malicious.example.com"]


def test_scan_rejects_out_of_scope_hosts(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings],
) -> None:
    client, queue, session_factory, _settings = api_client

    with session_factory() as session:
        target = Target(name="Authorized", scope="demo.medusa", is_authorized=True)
        session.add(target)
        session.commit()
        target_id = target.id

    response = client.post(
        "/scan",
        json={
            "target_id": target_id,
            "scanner": "nuclei",
            "parameters": {"requested_hosts": ["malicious.example.com"]},
        },
        headers=auth_headers(),
    )

    assert response.status_code == 400
    assert (
        response.json()["detail"]
        == "No requested hosts remain within the authorized target scope"
    )
    assert not queue.messages

    with session_factory() as session:
        assert session.query(Scan).count() == 0
        assert session.query(AuditLog).count() == 0


def test_principal_rotation_flow(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings],
) -> None:
    client, _queue, session_factory, _settings = api_client
    subject = "rotate-svc"

    create_response = client.post(
        "/principals",
        json={
            "subject": subject,
            "auth_method": "api_key",
            "roles": ["analyst"],
            "description": "rotation-test",
        },
        headers=auth_headers(),
    )
    assert create_response.status_code == 201, create_response.text
    first_payload = create_response.json()
    first_secret = first_payload["secret"]
    assert isinstance(first_secret, str) and first_secret
    first_id = first_payload["id"]
    assert first_payload["revoked_at"] is None
    first_fingerprint = first_payload["key_fingerprint"]
    assert first_fingerprint == _hash_secret(first_secret)[:12]

    revoke_response = client.post(
        f"/principals/{first_id}/revoke", headers=auth_headers()
    )
    assert revoke_response.status_code == 200, revoke_response.text
    revoked_payload = revoke_response.json()
    assert revoked_payload["revoked_at"] is not None
    assert revoked_payload["key_fingerprint"] == first_fingerprint

    rotate_response = client.post(
        "/principals",
        json={
            "subject": subject,
            "auth_method": "api_key",
            "roles": ["analyst"],
            "description": "rotation-test",
        },
        headers=auth_headers(),
    )
    assert rotate_response.status_code == 201, rotate_response.text
    second_payload = rotate_response.json()
    second_secret = second_payload["secret"]
    assert isinstance(second_secret, str) and second_secret
    assert second_secret != first_secret
    assert second_payload["id"] != first_id
    assert second_payload["revoked_at"] is None
    second_fingerprint = second_payload["key_fingerprint"]
    assert second_fingerprint == _hash_secret(second_secret)[:12]

    with session_factory() as session:
        records = (
            session.query(PrincipalCredential)
            .filter(PrincipalCredential.subject == subject)
            .order_by(PrincipalCredential.id.asc())
            .all()
        )

        assert len(records) == 2
        active = [record for record in records if record.revoked_at is None]
        revoked = [record for record in records if record.revoked_at is not None]
        assert len(active) == 1
        assert len(revoked) == 1
        assert active[0].key_hash == _hash_secret(second_secret)
        assert revoked[0].key_hash == _hash_secret(first_secret)

        create_events = (
            session.query(AuditLog).filter(AuditLog.action == "create_principal").all()
        )
        fingerprints = {
            event.evidence_snapshot.get("rotation", {}).get("key_fingerprint")
            for event in create_events
        }
        assert first_fingerprint in fingerprints
        assert second_fingerprint in fingerprints

        revoke_event = (
            session.query(AuditLog).filter(AuditLog.action == "revoke_principal").one()
        )
        rotation_meta = revoke_event.evidence_snapshot.get("rotation", {})
        assert rotation_meta.get("key_fingerprint") == first_fingerprint
        assert first_secret not in str(revoke_event.evidence_snapshot)
        assert second_secret not in str(revoke_event.evidence_snapshot)


def test_principal_management_requires_admin(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings],
) -> None:
    client, _queue, session_factory, _settings = api_client

    _secret, analyst_headers = _provision_principal(
        client, subject="analyst-rbac", roles=["analyst"]
    )

    list_response = client.get("/principals", headers=analyst_headers)
    assert list_response.status_code == 403

    create_attempt = client.post(
        "/principals",
        json={
            "subject": "unauthorized-issue",
            "auth_method": "api_key",
            "roles": ["analyst"],
        },
        headers=analyst_headers,
    )
    assert create_attempt.status_code == 403

    with session_factory() as session:
        analyst_record = (
            session.query(PrincipalCredential)
            .filter(PrincipalCredential.subject == "analyst-rbac")
            .one()
        )
        analyst_id = analyst_record.id

    revoke_attempt = client.post(
        f"/principals/{analyst_id}/revoke", headers=analyst_headers
    )
    assert revoke_attempt.status_code == 403

    with session_factory() as session:
        access_denied_entries = (
            session.query(AuditLog)
            .filter(
                AuditLog.actor == "analyst-rbac",
                AuditLog.action == "access_denied",
            )
            .order_by(AuditLog.created_at.asc())
            .all()
        )

        assert len(access_denied_entries) == 3
        resources = [
            entry.evidence_snapshot.get("resource_id")
            for entry in access_denied_entries
        ]
        assert resources.count("/principals") == 2
        assert f"/principals/{analyst_id}/revoke" in resources
        reasons = {
            entry.evidence_snapshot.get("reason") for entry in access_denied_entries
        }
        assert reasons == {"missing_required_roles"}


def test_revoked_api_key_denied_with_audit_trail(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings],
) -> None:
    client, _queue, session_factory, _settings = api_client
    subject = "revoked-svc"

    create_response = client.post(
        "/principals",
        json={
            "subject": subject,
            "auth_method": "api_key",
            "roles": ["analyst"],
        },
        headers=auth_headers(),
    )
    assert create_response.status_code == 201, create_response.text
    payload = create_response.json()
    secret = payload["secret"]
    fingerprint = payload["key_fingerprint"]
    revoked_headers = {"X-API-Key": secret}

    baseline = client.get("/targets", headers=revoked_headers)
    assert baseline.status_code == 200, baseline.text

    with session_factory() as session:
        record = (
            session.query(PrincipalCredential)
            .filter(PrincipalCredential.subject == subject)
            .one()
        )
        credential_id = record.id

    revoke_response = client.post(
        f"/principals/{credential_id}/revoke", headers=auth_headers()
    )
    assert revoke_response.status_code == 200, revoke_response.text

    denied = client.get("/targets", headers=revoked_headers)
    assert denied.status_code == 401
    assert denied.json()["detail"] == "API key revoked"

    with session_factory() as session:
        audit_entry = (
            session.query(AuditLog)
            .filter(
                AuditLog.actor == subject,
                AuditLog.action == "access_denied",
            )
            .order_by(AuditLog.created_at.desc())
            .first()
        )

        assert audit_entry is not None
        snapshot = audit_entry.evidence_snapshot
        assert snapshot.get("reason") == "credential_revoked"
        assert snapshot.get("key_fingerprint") == fingerprint
        assert snapshot.get("credential_status") == "revoked"


def test_finding_contracts(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings],
) -> None:
    client, _, session_factory, _settings = api_client

    with session_factory() as session:
        target = Target(name="Prod API", scope="prod.example.com", is_authorized=True)
        session.add(target)
        session.flush()

        scan = Scan(
            target_id=target.id,
            scanner="nuclei",
            status="completed",
            initiated_by="tester",
            parameters={"profile": "full"},
        )
        session.add(scan)
        session.flush()

        finding = Finding(
            scan_id=scan.id,
            title="SQL injection",
            severity="high",
            cve_id="CVE-2024-0001",
            description="Unsanitised input",
            evidence={"request": "GET /?id='"},
            evidence_hash="",
        )
        session.add(finding)
        session.commit()
        finding_id = finding.id
        scan_id = scan.id

    list_response = client.get("/findings", headers=auth_headers())
    assert list_response.status_code == 200
    findings_payload = list_response.json()
    assert findings_payload["data"], "findings collection should not be empty"

    finding_item = findings_payload["data"][0]
    assert finding_item["id"] == finding_id
    assert finding_item["scan_id"] == scan_id
    assert finding_item["severity"] == "high"
    assert finding_item["status"] == "open"
    assert finding_item["template_id"] == "CVE-2024-0001"
    assert finding_item["evidence"]
    assert finding_item["enrichments"] == []
    assert finding_item["scanner"] == "nuclei"
    assert finding_item["category"] == "web"
    assert finding_item["tool"] == "nuclei"
    assert finding_item["sample_id"] is None
    datetime.fromisoformat(finding_item["detected_at"])  # raises on invalid format

    detail_response = client.get(f"/findings/{finding_id}", headers=auth_headers())
    assert detail_response.status_code == 200
    detail_payload = detail_response.json()
    assert detail_payload["data"]["id"] == finding_id
    assert detail_payload["data"]["enrichments"] == []
    assert detail_payload["data"]["category"] == "web"


def test_audit_log_rbac_regression(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings],
) -> None:
    client, _queue, _session_factory, _settings = api_client

    _secret, limited_headers = _provision_principal(
        client, subject="audit-rbac", roles=["scan:enqueue"]
    )

    forbidden = client.get("/audit-log", headers=limited_headers)
    assert forbidden.status_code == 403

    allowed = client.get("/audit-log", headers=auth_headers())
    assert allowed.status_code == 200, allowed.text
    payload = allowed.json()
    assert "data" in payload


def test_findings_list_rbac_regression(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings],
) -> None:
    client, _queue, session_factory, _settings = api_client
    finding_id = _create_finding_record(session_factory)

    _secret, limited_headers = _provision_principal(
        client, subject="findings-rbac", roles=["scan:enqueue"]
    )

    forbidden = client.get("/findings", headers=limited_headers)
    assert forbidden.status_code == 403

    response = client.get("/findings", headers=auth_headers())
    assert response.status_code == 200, response.text
    payload = response.json()
    assert any(item["id"] == finding_id for item in payload.get("data", []))


def test_findings_detail_rbac_regression(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings],
) -> None:
    client, _queue, session_factory, _settings = api_client
    finding_id = _create_finding_record(session_factory)

    _secret, limited_headers = _provision_principal(
        client, subject="finding-detail-rbac", roles=["scan:enqueue"]
    )

    forbidden = client.get(f"/findings/{finding_id}", headers=limited_headers)
    assert forbidden.status_code == 403

    response = client.get(f"/findings/{finding_id}", headers=auth_headers())
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["data"]["id"] == finding_id


def _persist_sample_finding(session_factory: sessionmaker) -> tuple[str, str]:
    with session_factory() as session:
        target = Target(name="Prod API", scope="prod.example.com", is_authorized=True)
        session.add(target)
        session.flush()

        scan = Scan(
            target_id=target.id,
            scanner="nuclei",
            status="completed",
            initiated_by="tester",
            parameters={},
        )
        session.add(scan)
        session.flush()

        finding = Finding(
            scan_id=scan.id,
            title="SQL injection",
            severity="high",
            cve_id="CVE-2024-9999",
            description="Unsanitised input",
            metadata_json={"template": "cve"},
            evidence={"request": "GET /?id='"},
            evidence_hash="",
        )
        session.add(finding)
        session.commit()
        return finding.id, scan.id


def test_enrichment_callback_persists_results(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings],
) -> None:
    client, _queue, session_factory, _settings = api_client
    finding_id, _scan_id = _persist_sample_finding(session_factory)

    payload = {
        "job_id": "job-success-1",
        "finding_id": finding_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "advisories": [
            {
                "source": "nvd",
                "identifier": "CVE-2024-9999",
                "summary": "Example summary",
                "severity": "HIGH",
                "cvss_score": 8.9,
                "published": "2024-02-01T00:00:00+00:00",
                "modified": "2024-02-02T00:00:00+00:00",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-9999"],
                "raw": {"id": "CVE-2024-9999"},
            }
        ],
        "errors": {},
    }

    response = client.post(
        "/internal/enrich/callback",
        json=payload,
        headers=enrichment_headers(),
    )
    assert response.status_code == 204, response.text

    with session_factory() as session:
        enrichment = (
            session.query(FindingEnrichment)
            .filter(FindingEnrichment.job_id == payload["job_id"])
            .one()
        )
        assert enrichment.payload_hash
        assert enrichment.provenance["worker_subject"] == "worker:enrichment"

        audit = (
            session.query(AuditLog)
            .filter(
                AuditLog.action == "enrichment_callback",
                AuditLog.finding_id == finding_id,
            )
            .first()
        )
        assert audit is not None

    detail = client.get(f"/findings/{finding_id}", headers=auth_headers())
    assert detail.status_code == 200
    detail_payload = detail.json()["data"]
    assert detail_payload["enrichments"], detail_payload
    latest = detail_payload["enrichments"][0]
    assert latest["job_id"] == payload["job_id"]
    assert latest["advisories"][0]["identifier"] == "CVE-2024-9999"


def test_enrichment_callback_records_errors(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings],
) -> None:
    client, _queue, session_factory, _settings = api_client
    finding_id, _scan_id = _persist_sample_finding(session_factory)

    payload = {
        "job_id": "job-error-1",
        "finding_id": finding_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "advisories": [],
        "errors": {"nvd": "timeout"},
    }

    response = client.post(
        "/internal/enrich/callback",
        json=payload,
        headers=enrichment_headers(),
    )
    assert response.status_code == 204, response.text

    with session_factory() as session:
        enrichment = (
            session.query(FindingEnrichment)
            .filter(FindingEnrichment.job_id == payload["job_id"])
            .one()
        )
        assert enrichment.errors["nvd"] == "timeout"
        assert enrichment.errors_hash

    listing = client.get("/findings", headers=auth_headers())
    assert listing.status_code == 200
    listing_payload = listing.json()["data"]
    assert listing_payload[0]["enrichments"][0]["errors"]["nvd"] == "timeout"

    detail = client.get(f"/findings/{finding_id}", headers=auth_headers())
    assert detail.status_code == 200

    with session_factory() as session:
        audit_entries = session.query(AuditLog).all()
        assert any(entry.action == "list_findings" for entry in audit_entries)
        assert any(entry.action == "get_finding" for entry in audit_entries)


def test_rbac_denial_is_audited(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings],
) -> None:
    client, _queue, session_factory, _settings = api_client

    analyst_key = "analyst-denied"
    with session_factory() as session:
        session.add(
            PrincipalCredential(
                subject="analyst-denied",
                auth_method="api_key",
                key_hash=_hash_secret(analyst_key),
                roles=list(DEFAULT_ANALYST_ROLES),
            )
        )
        session.commit()

    with session_factory() as session:
        before = session.query(AuditLog).count()

    response = client.get("/principals", headers={"X-API-Key": analyst_key})
    assert response.status_code == 403

    with session_factory() as session:
        after = session.query(AuditLog).count()
        assert after == before + 1
        entry = (
            session.query(AuditLog)
            .filter(AuditLog.actor == "analyst-denied")
            .order_by(AuditLog.created_at.desc())
            .first()
        )

    assert entry is not None
    assert entry.action == "access_denied"
    snapshot = entry.evidence_snapshot
    assert snapshot["reason"] == "missing_required_roles"
    assert snapshot["required_roles"] == ["admin"]
    assert snapshot["missing_roles"] == ["admin"]
    assert snapshot["granted_roles"] == sorted(set(DEFAULT_ANALYST_ROLES))
    assert snapshot["auth_method"] == "api_key"


def test_revoked_api_key_denial_is_audited(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings],
) -> None:
    client, _queue, session_factory, _settings = api_client

    revoked_key = "revoked-key"
    now = datetime.now(tz=timezone.utc)
    with session_factory() as session:
        credential = PrincipalCredential(
            subject="revoked-user",
            auth_method="api_key",
            key_hash=_hash_secret(revoked_key),
            roles=list(DEFAULT_ANALYST_ROLES),
            revoked_at=now,
        )
        session.add(credential)
        session.commit()

    with session_factory() as session:
        before = session.query(AuditLog).count()

    response = client.get("/targets", headers={"X-API-Key": revoked_key})
    assert response.status_code == 401

    with session_factory() as session:
        after = session.query(AuditLog).count()
        assert after == before + 1
        entry = (
            session.query(AuditLog)
            .filter(AuditLog.actor == "revoked-user")
            .order_by(AuditLog.created_at.desc())
            .first()
        )

    assert entry is not None
    assert entry.action == "access_denied"
    snapshot = entry.evidence_snapshot
    assert snapshot["reason"] == "credential_revoked"
    assert snapshot["required_roles"] == []
    assert snapshot["granted_roles"] == sorted(set(DEFAULT_ANALYST_ROLES))
    assert snapshot["auth_method"] == "api_key"
    assert snapshot["credential_status"] == "revoked"


def test_targets_listing_requires_read_role(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings],
) -> None:
    client, _queue, session_factory, settings = api_client

    create_response = client.post(
        "/targets",
        json={"name": "Prod API", "scope": "prod.example.com"},
        headers=auth_headers(),
    )
    assert create_response.status_code == 201

    list_response = client.get("/targets", headers=auth_headers())
    assert list_response.status_code == 200
    payload = list_response.json()
    assert payload["data"], "expected at least one target in collection"

    with session_factory() as session:
        credential = PrincipalCredential(
            subject="limited@example.com",
            auth_method="jwt",
            roles=["findings:read"],
        )
        session.add(credential)
        session.commit()

    limited_token = jwt.encode(
        {"sub": "limited@example.com"}, settings.jwt_secret, algorithm="HS256"
    )

    unauthorized_response = client.get(
        "/targets",
        headers={"Authorization": f"Bearer {limited_token}"},
    )
    assert unauthorized_response.status_code == 403


def test_scans_listing_enforces_role_requirements(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings],
) -> None:
    client, _queue, session_factory, settings = api_client

    with session_factory() as session:
        target = Target(name="Authorized", scope="demo.medusa", is_authorized=True)
        session.add(target)
        session.flush()
        scan = Scan(
            target_id=target.id,
            scanner="nuclei",
            parameters={"profile": "baseline"},
            initiated_by="controller",
        )
        session.add(scan)
        session.commit()

    with session_factory() as session:
        credential = PrincipalCredential(
            subject="restricted@example.com",
            auth_method="jwt",
            roles=["findings:read"],
        )
        session.add(credential)
        session.commit()

    restricted_token = jwt.encode(
        {"sub": "restricted@example.com"}, settings.jwt_secret, algorithm="HS256"
    )

    response = client.get(
        "/scans", headers={"Authorization": f"Bearer {restricted_token}"}
    )
    assert response.status_code == 403

    analyst_credential = client.post(
        "/principals",
        json={
            "subject": "analyst@example.com",
            "auth_method": "jwt",
            "roles": ["analyst"],
        },
        headers=auth_headers(),
    )
    assert analyst_credential.status_code == 201
    analyst_token = jwt.encode(
        {"sub": "analyst@example.com"}, settings.jwt_secret, algorithm="HS256"
    )
    analyst_response = client.get(
        "/scans", headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert analyst_response.status_code == 200


def test_audit_log_listing_filters_and_audits(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings],
) -> None:
    client, _queue, session_factory, _settings = api_client

    now = datetime.now(tz=timezone.utc)

    with session_factory() as session:
        target = Target(name="Audit Target", scope="audit.example", is_authorized=True)
        session.add(target)
        session.flush()

        scan = Scan(
            target_id=target.id,
            scanner="nuclei",
            parameters={"profile": "full"},
            initiated_by="bootstrap-admin",
        )
        session.add(scan)
        session.flush()

        entries = [
            AuditLog(
                actor="bootstrap-admin",
                action="create_target",
                message="seed entry",
                evidence_snapshot={"resource_type": "target", "resource_id": target.id},
                evidence_hash="",
                created_at=now - timedelta(minutes=5),
            ),
            AuditLog(
                actor="auditor@example.com",
                action="list_findings",
                message="read findings",
                scan_id=scan.id,
                evidence_snapshot={
                    "resource_type": "finding",
                    "scan_id": scan.id,
                    "note": "seed",
                },
                evidence_hash="",
                created_at=now - timedelta(minutes=3),
            ),
            AuditLog(
                actor="bootstrap-admin",
                action="delete_target",
                message="cleanup",
                evidence_snapshot={"resource_type": "target", "resource_id": "old-id"},
                evidence_hash="",
                created_at=now - timedelta(minutes=1),
            ),
        ]
        session.add_all(entries)
        session.commit()
        scan_id = scan.id

    response = client.get("/audit-log", headers=auth_headers())
    assert response.status_code == 200
    payload = response.json()

    assert payload["meta"] == {"total": 3, "limit": 50, "offset": 0}
    returned_timestamps = [
        datetime.fromisoformat(item["created_at"]) for item in payload["data"]
    ]
    assert returned_timestamps == sorted(returned_timestamps, reverse=True)
    assert payload["data"][0]["action"] == "delete_target"
    assert payload["data"][0]["actor"] == "bootstrap-admin"

    actor_response = client.get(
        "/audit-log",
        params={"actor": "auditor@example.com"},
        headers=auth_headers(),
    )
    assert actor_response.status_code == 200
    actor_payload = actor_response.json()
    assert actor_payload["meta"]["total"] == 1
    assert all(
        entry["actor"] == "auditor@example.com" for entry in actor_payload["data"]
    )

    action_response = client.get(
        "/audit-log",
        params={"action": "delete_target"},
        headers=auth_headers(),
    )
    assert action_response.status_code == 200
    action_payload = action_response.json()
    assert action_payload["meta"]["total"] == 1
    assert action_payload["data"][0]["action"] == "delete_target"

    scan_response = client.get(
        "/audit-log",
        params={"scan_id": scan_id},
        headers=auth_headers(),
    )
    assert scan_response.status_code == 200
    scan_payload = scan_response.json()
    assert scan_payload["meta"]["total"] == 1
    assert all(entry["scan_id"] == scan_id for entry in scan_payload["data"])

    with session_factory() as session:
        recorded_actions = [entry.action for entry in session.query(AuditLog).all()]
    assert "list_audit_log" in recorded_actions


def test_audit_log_requires_admin_role(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings],
) -> None:
    client, _queue, _session_factory, settings = api_client

    analyst_response = client.post(
        "/principals",
        json={
            "subject": "audit-analyst@example.com",
            "auth_method": "jwt",
            "roles": ["analyst"],
        },
        headers=auth_headers(),
    )
    assert analyst_response.status_code == 201

    analyst_token = jwt.encode(
        {"sub": "audit-analyst@example.com"},
        settings.jwt_secret,
        algorithm="HS256",
    )

    response = client.get(
        "/audit-log", headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert response.status_code == 403


def test_principal_creation_validates_and_expands_roles(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings],
) -> None:
    client, _queue, _session_factory, _settings = api_client

    invalid_response = client.post(
        "/principals",
        json={
            "subject": "invalid@example.com",
            "auth_method": "jwt",
            "roles": ["unknown"],
        },
        headers=auth_headers(),
    )
    assert invalid_response.status_code == 422

    analyst_response = client.post(
        "/principals",
        json={
            "subject": "analyst-role@example.com",
            "auth_method": "jwt",
            "roles": ["analyst"],
        },
        headers=auth_headers(),
    )
    assert analyst_response.status_code == 201
    analyst_payload = analyst_response.json()
    assert sorted(analyst_payload["roles"]) == sorted(
        [
            "analyst",
            "findings:read",
            "scan:enqueue",
            "scans:read",
            "binary:preprocess",
            "binary:static-analysis",
            "binary:fuzzing",
            "targets:read",
            "enrich:enqueue",
            "report:export",
            "finding:validate",
        ]
    )

    admin_response = client.post(
        "/principals",
        json={
            "subject": "admin-role@example.com",
            "auth_method": "api_key",
            "roles": ["admin"],
        },
        headers=auth_headers(),
    )
    assert admin_response.status_code == 201
    admin_payload = admin_response.json()
    assert "secret" in admin_payload
    assert sorted(admin_payload["roles"]) == sorted(
        [
            "admin",
            "findings:read",
            "scan:enqueue",
            "scans:read",
            "binary:preprocess",
            "binary:static-analysis",
            "binary:fuzzing",
            "targets:read",
            "targets:write",
            "enrich:enqueue",
            "report:export",
            "ticket:create",
            "finding:validate",
        ]
    )


def test_api_key_revocation_enforced_and_audited(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings],
) -> None:
    client, _queue, session_factory, _settings = api_client

    response = client.get("/targets", headers=auth_headers())
    assert response.status_code == 200

    with session_factory() as session:
        audit_entries = session.query(AuditLog).all()
        assert any(entry.action == "list_targets" for entry in audit_entries)
        initial_audit_count = len(audit_entries)

        revoked_credential = PrincipalCredential(
            subject="revoked-service",
            auth_method="api_key",
            key_hash=_hash_secret("revoked-key"),
            roles=list(DEFAULT_ANALYST_ROLES),
            revoked_at=datetime.now(tz=timezone.utc),
        )
        session.add(revoked_credential)
        session.commit()

    revoked_response = client.get("/targets", headers={"X-API-Key": "revoked-key"})
    assert revoked_response.status_code == 401

    with session_factory() as session:
        audit_actions = [entry.action for entry in session.query(AuditLog).all()]
    assert audit_actions.count("list_targets") == initial_audit_count

def test_finding_workflow_and_reporting(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings]
) -> None:
    client, _queue, session_factory, _settings = api_client

    finding_id = _create_finding_record(session_factory)

    assign_response = client.post(
        f"/findings/{finding_id}/assign",
        json={"assignee": "analyst.one"},
        headers=auth_headers(),
    )
    assert assign_response.status_code == 200, assign_response.text
    assign_payload = assign_response.json()
    assert assign_payload["data"]["assigned_to"] == "analyst.one"
    assert assign_payload["data"]["status"] == "acknowledged"

    status_response = client.post(
        f"/findings/{finding_id}/status",
        json={"status": "resolved"},
        headers=auth_headers(),
    )
    assert status_response.status_code == 200, status_response.text
    assert status_response.json()["data"]["status"] == "resolved"

    tags_response = client.post(
        f"/findings/{finding_id}/tags",
        json={"tags": ["workflow:triage", "scope:demo"]},
        headers=auth_headers(),
    )
    assert tags_response.status_code == 200, tags_response.text
    tags_payload = tags_response.json()["data"]["tags"]
    assert "workflow:triage" in tags_payload

    comment_response = client.post(
        f"/findings/{finding_id}/comments",
        json={"message": "Investigated root cause."},
        headers=auth_headers(),
    )
    assert comment_response.status_code == 201, comment_response.text

    comments_list = client.get(
        f"/findings/{finding_id}/comments", headers=auth_headers()
    )
    assert comments_list.status_code == 200
    assert comments_list.json()["data"][0]["message"].startswith("Investigated")

    timeline_response = client.get(
        f"/findings/{finding_id}/timeline", headers=auth_headers()
    )
    assert timeline_response.status_code == 200
    timeline_events = timeline_response.json()["data"]
    assert len(timeline_events) >= 1

    jira_response = client.post(
        "/tickets/jira",
        json={
            "finding_id": finding_id,
            "project_key": "SEC",
            "issue_type": "Bug",
            "summary": "Investigate synthetic finding",
            "description": "Ensure deterministic workflow",
        },
        headers=auth_headers(),
    )
    assert jira_response.status_code == 201, jira_response.text
    jira_payload = jira_response.json()
    assert jira_payload["integration"] == "jira"

    export_response = client.post(
        "/reports/export",
        json={"finding_ids": [finding_id], "format": "html"},
        headers=auth_headers(),
    )
    assert export_response.status_code == 200, export_response.text
    report_payload = export_response.json()
    assert report_payload["format"] == "html"
    assert report_payload["content"]

    filtered = client.get(
        "/findings",
        params={"tag": "workflow:triage"},
        headers=auth_headers(),
    )
    assert filtered.status_code == 200
    assert any(item["id"] == finding_id for item in filtered.json()["data"])

    timeline = client.get(
        "/findings/timeline",
        params={"tag": "workflow:triage"},
        headers=auth_headers(),
    )
    assert timeline.status_code == 200
    timeline_payload = timeline.json()["data"]
    assert isinstance(timeline_payload, list)
