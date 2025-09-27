import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Generator, Optional, Tuple

from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

import jwt
import pytest
from controller.db.models import (
    AuditLog,
    AnomalyEvent,
    Base,
    BinaryFuzzingFinding,
    BinarySample,
    BinaryStaticAnalysisFinding,
    BinarySymbolicExecutionFinding,
    Finding,
    FindingEnrichment,
    FindingComment,
    FindingTicket,
    FindingValidation,
    PrincipalCredential,
    Scan,
    Target,
)
from controller.main import (
    CALLBACK_TOKEN_HEADER,
    DEFAULT_ADMIN_ROLES,
    DEFAULT_ANALYST_ROLES,
    NUCLEI_TEMPLATE_PROFILES,
    Settings,
    _hash_json_payload,
    _hash_secret,
    app,
    get_db_session,
    get_notification_service,
    get_queue_client,
    ROLE_FINDINGS_READ,
    ROLE_REPORT_EXPORT,
    get_settings,
)
from controller.notifications import (
    AnomalyNotification,
    CriticalFindingNotification,
    NotificationService,
)
from controller.tests.conftest import InMemoryQueue


class DummyNotificationService(NotificationService):
    def __init__(self) -> None:
        super().__init__(
            slack_webhook=None,
            email_sender=None,
            email_recipients=[],
            smtp_host=None,
            smtp_port=None,
            smtp_username=None,
            smtp_password=None,
            smtp_use_tls=False,
        )
        self.anomaly_notifications: list[AnomalyNotification] = []

    def notify_critical_finding(  # type: ignore[override]
        self, payload: CriticalFindingNotification
    ) -> None:
        return

    def notify_anomaly(  # type: ignore[override]
        self, payload: AnomalyNotification
    ) -> None:
        self.anomaly_notifications.append(payload)


@pytest.fixture()
def api_client() -> (
    Generator[Tuple[TestClient, InMemoryQueue, sessionmaker, Settings], None, None]
):
    get_settings.cache_clear()  # type: ignore[attr-defined]
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        redis_url="redis://localhost:6379/0",
        nuclei_queue_channel="nuclei:test",
        zap_queue_channel="zap:test",
        sqlmap_queue_channel="sqlmap:test",
        validator_queue_channel="validator:test",
        jwt_secret="unit-test-secret",
        nuclei_callback_token="callback-secret",
        zap_callback_token="zap-callback",
        sqlmap_callback_token="sqlmap-callback",
        validator_callback_token="validator-secret",
        anomaly_callback_token="anomaly-secret",
        enrichment_callback_token="enrichment-secret",
        binary_static_analysis_queue_channel="binary-static:test",
        binary_static_analysis_callback_token="binary-static-secret",
        binary_fuzzing_queue_channel="binary-fuzzing:test",
        binary_fuzzing_callback_token="binary-fuzzing-secret",
        binary_symbolic_execution_queue_channel="binary-symbolic:test",
        binary_symbolic_execution_callback_token="binary-symbolic-secret",
        recon_queue_channel="recon:test",
        recon_callback_token="recon-secret",
    )

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    SessionFactory = sessionmaker(bind=engine, expire_on_commit=False)

    queue = InMemoryQueue()
    notification_service = DummyNotificationService()

    with SessionFactory() as session:
        bootstrap_credential = PrincipalCredential(
            subject="bootstrap-admin",
            auth_method="api_key",
            key_hash=_hash_secret("test-key"),
            roles=list(DEFAULT_ADMIN_ROLES),
        )
        session.add(bootstrap_credential)
        session.commit()

    def override_settings() -> Settings:
        return settings

    def override_session() -> Generator[Session, None, None]:
        session = SessionFactory()
        try:
            yield session
        finally:
            session.close()

    def override_queue() -> InMemoryQueue:
        return queue

    def override_notification() -> DummyNotificationService:
        return notification_service

    app.dependency_overrides[get_settings] = override_settings
    app.dependency_overrides[get_db_session] = override_session
    app.dependency_overrides[get_queue_client] = override_queue
    app.dependency_overrides[get_notification_service] = override_notification

    with TestClient(app) as client:
        yield client, queue, SessionFactory, settings

    app.dependency_overrides.clear()
    get_settings.cache_clear()  # type: ignore[attr-defined]
    Base.metadata.drop_all(engine)
    engine.dispose()


def auth_headers() -> dict[str, str]:
    return {"X-API-Key": "test-key"}


def enrichment_headers() -> dict[str, str]:
    return {"X-Callback-Token": "enrichment-secret"}


def binary_static_headers() -> dict[str, str]:
    return {"X-Callback-Token": "binary-static-secret"}


def binary_fuzzing_headers() -> dict[str, str]:
    return {"X-Callback-Token": "binary-fuzzing-secret"}


def binary_symbolic_headers() -> dict[str, str]:
    return {"X-Callback-Token": "binary-symbolic-secret"}


def anomaly_headers() -> dict[str, str]:
    return {"X-Callback-Token": "anomaly-secret"}


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

        evidence_payload = {"proof": "error-based"}
        finding = Finding(
            scan_id=scan.id,
            title="Synthetic SQL Injection",
            severity="high",
            cve_id="CVE-2099-0001",
            description="Regression finding for RBAC coverage.",
            metadata_json={"vector": "GET /?id=1"},
            evidence=evidence_payload,
            evidence_hash=_hash_json_payload(evidence_payload),
        )
        session.add(finding)
        session.commit()

        return str(finding.id)


def _create_anomaly_event(
    session_factory: sessionmaker,
    *,
    anomaly_type: str = "login_spike",
    actor: str = "analyst@example.com",
    source: str = "auth-gateway",
    metadata: Optional[dict[str, Any]] = None,
) -> str:
    """Persist an anomaly event for API regression tests."""

    detected_at = datetime.now(timezone.utc)
    with session_factory() as session:
        event = AnomalyEvent(
            anomaly_type=anomaly_type,
            actor=actor,
            source=source,
            detected_at=detected_at,
            first_seen=detected_at - timedelta(minutes=15),
            last_seen=detected_at,
            count=5,
            window_seconds=900,
            metadata_json=metadata or {},
        )
        session.add(event)
        session.commit()
        return str(event.id)


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

        sample_metadata = {"sha256": "ab" * 32}
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
            metadata_json=sample_metadata,
            metadata_hash=_hash_json_payload(sample_metadata),
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


def test_symbolic_execution_enqueue_flow(
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

        sample_metadata = {"sha256": "ef" * 32}
        sample = BinarySample(
            scan_id=preprocess_scan.id,
            target_id=target_payload["id"],
            file_name="sample.bin",
            sha256="ef" * 32,
            file_size=2048,
            mime_type="application/octet-stream",
            magic_type="ELF 64-bit",
            policy_status="allowed",
            policy_reasons=[],
            storage_bucket="binary-uploads",
            storage_key="uploads/sample.bin",
            metadata_json=sample_metadata,
            metadata_hash=_hash_json_payload(sample_metadata),
            processed_at=datetime.now(tz=timezone.utc),
        )
        session.add(sample)
        session.commit()
        sample_id = sample.id

    response = client.post(
        "/binary/symbolic-execution",
        json={
            "sample_id": sample_id,
            "target_id": target_payload["id"],
            "analysis_depth": 256,
            "timeout_seconds": 600,
            "metadata": {"strategy": "dfs"},
        },
        headers=auth_headers(),
    )
    assert response.status_code == 202, response.text
    payload = response.json()
    assert payload["scanner"] == "binary_symbolic_execution"

    assert queue.messages, "symbolic execution enqueue should push a job"
    channel, job = queue.messages[-1]
    assert channel == settings.binary_symbolic_execution_queue_channel
    assert job["sample_id"] == sample_id
    assert job["metadata"]["analysis_depth"] == 256
    assert job["metadata"]["timeout_seconds"] == 600
    assert job["object_bucket"] == "binary-uploads"
    assert job["object_key"] == "uploads/sample.bin"
    assert job["attempts"] == 0
    assert job["metadata"]["target_scope"] == target_payload["scope"]
    assert job["metadata"]["initiated_by"] == "bootstrap-admin"
    assert job["metadata"]["analyst_metadata"] == {"strategy": "dfs"}
    assert job["callback_url"].endswith(
        "/internal/binary/symbolic-execution/callback"
    )


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

        sample_metadata: dict[str, Any] = {}
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
            metadata_json=sample_metadata,
            metadata_hash=_hash_json_payload(sample_metadata),
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


def test_binary_symbolic_execution_callback_persists_findings(
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

        sample_metadata: dict[str, Any] = {}
        sample = BinarySample(
            scan_id=preprocess_scan.id,
            target_id=target.id,
            file_name="sample.bin",
            sha256="12" * 32,
            file_size=4096,
            mime_type="application/octet-stream",
            magic_type="ELF 64-bit",
            policy_status="allowed",
            policy_reasons=[],
            storage_bucket="binary-uploads",
            storage_key="uploads/sample.bin",
            metadata_json=sample_metadata,
            metadata_hash=_hash_json_payload(sample_metadata),
            processed_at=datetime.now(tz=timezone.utc),
        )
        session.add(sample)
        session.flush()

        analysis_scan = Scan(
            target_id=target.id,
            scanner="binary_symbolic_execution",
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
        "/internal/binary/symbolic-execution/callback",
        json={
            "job_id": "job-angr-1",
            "scan_id": scan_id,
            "sample_id": sample_id,
            "status": "completed",
            "processed_at": executed_at.isoformat(),
            "findings": [
                {
                    "tool": "angr",
                    "severity": "medium",
                    "title": "Reachable strcpy",
                    "description": "User controlled path to strcpy",
                    "metadata": {"sink": "strcpy"},
                    "evidence": {"input": "AAAA"},
                    "artifact_bucket": "analysis",
                    "artifact_key": "symbolic/path.json",
                    "executed_at": executed_at.isoformat(),
                }
            ],
            "artifacts": [
                {
                    "tool": "angr",
                    "bucket": "analysis",
                    "key": "symbolic/path.json",
                }
            ],
            "reports": [
                {
                    "tool": "angr",
                    "status": "completed",
                    "exit_code": 0,
                    "stdout": "{}",
                    "stderr": "",
                    "raw_output": {"metadata": {"paths": 1}},
                    "executed_at": executed_at.isoformat(),
                    "duration_seconds": 2.5,
                }
            ],
            "metadata": {"paths": 1},
        },
        headers=binary_symbolic_headers(),
    )
    assert response.status_code == 204, response.text

    with session_factory() as session:
        findings = (
            session.query(BinarySymbolicExecutionFinding)
            .filter(BinarySymbolicExecutionFinding.scan_id == scan_id)
            .all()
        )
        assert len(findings) == 1
        finding = findings[0]
        assert finding.title == "Reachable strcpy"
        assert finding.metadata_json["sink"] == "strcpy"
        assert finding.scan_id == scan_id


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

        sample_metadata: dict[str, Any] = {}
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
            metadata_json=sample_metadata,
            metadata_hash=_hash_json_payload(sample_metadata),
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

        sample_metadata: dict[str, Any] = {}
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
            metadata_json=sample_metadata,
            metadata_hash=_hash_json_payload(sample_metadata),
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

        evidence_payload = {"request": "GET /?id='"}
        finding = Finding(
            scan_id=scan.id,
            title="SQL injection",
            severity="high",
            cve_id="CVE-2024-0001",
            description="Unsanitised input",
            evidence=evidence_payload,
            evidence_hash=_hash_json_payload(evidence_payload),
        )
        session.add(finding)
        session.commit()
        finding_id = finding.id
        scan_id = scan.id

    list_response = client.get("/findings", headers=auth_headers())
    assert list_response.status_code == 200
    findings_payload = list_response.json()
    assert findings_payload["data"], "findings collection should not be empty"
    assert findings_payload["meta"] == {"total": 1, "limit": 50, "offset": 0}

    finding_item = findings_payload["data"][0]
    assert finding_item["id"] == finding_id
    assert finding_item["scan_id"] == scan_id
    assert finding_item["severity"] == "high"
    assert finding_item["status"] == "pending_validation"
    assert finding_item["template_id"] == "CVE-2024-0001"
    assert finding_item["evidence"]
    assert finding_item["enrichments"] == []
    assert finding_item["scanner"] == "nuclei"
    assert finding_item["category"] == "web"
    assert finding_item["tool"] == "nuclei"
    assert finding_item["sample_id"] is None
    assert finding_item["validation_status"] == "pending"
    assert finding_item["validated_at"] is None
    assert finding_item["validations"] == []
    assert isinstance(finding_item["cvss"], float)
    assert finding_item["scope_status"] == "unknown"
    datetime.fromisoformat(finding_item["detected_at"])  # raises on invalid format

    detail_response = client.get(f"/findings/{finding_id}", headers=auth_headers())
    assert detail_response.status_code == 200
    detail_payload = detail_response.json()
    assert detail_payload["data"]["id"] == finding_id
    assert detail_payload["data"]["enrichments"] == []
    assert detail_payload["data"]["category"] == "web"
    assert detail_payload["data"]["validation_status"] == "pending"
    assert detail_payload["data"]["validations"] == []
    assert detail_payload["data"]["scope_status"] == "unknown"


def test_validation_enqueue_flow(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings]
) -> None:
    client, queue, session_factory, settings = api_client

    with session_factory() as session:
        target = Target(name="Validation", scope="val.example", is_authorized=True)
        session.add(target)
        session.flush()

        scan = Scan(
            target_id=target.id,
            scanner="nuclei",
            status="completed",
            initiated_by="validator@test",
            parameters={"profile": "baseline"},
        )
        session.add(scan)
        session.flush()

        evidence_payload = {"url": "https://val.example/login"}
        finding = Finding(
            scan_id=scan.id,
            title="Critical Exposure",
            severity="critical",
            description="demo",
            evidence=evidence_payload,
            evidence_hash=_hash_json_payload(evidence_payload),
        )
        session.add(finding)
        session.commit()
        finding_id = finding.id

    response = client.post(
        "/validate",
        json={"finding_id": finding_id, "notes": "double-check"},
        headers=auth_headers(),
    )
    assert response.status_code == 202, response.text
    payload = response.json()
    assert payload["status"] == "queued"

    assert queue.messages, "validator job should be queued"
    channel, job_payload = queue.messages[-1]
    assert channel == settings.validator_queue_channel
    assert job_payload["finding_id"] == finding_id
    assert job_payload["metadata"]["analyst_notes"] == "double-check"

    with session_factory() as session:
        refreshed = session.get(Finding, finding_id)
        assert refreshed is not None
        assert refreshed.validation_status == "queued"


def test_validation_force_allows_requeue(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings]
) -> None:
    client, queue, session_factory, _settings = api_client

    with session_factory() as session:
        target = Target(name="Requeue", scope="force.example", is_authorized=True)
        session.add(target)
        session.flush()

        scan = Scan(
            target_id=target.id,
            scanner="sqlmap",
            status="completed",
            initiated_by="validator@test",
            parameters={},
        )
        session.add(scan)
        session.flush()

        evidence_payload = {"vector": "id=1"}
        finding = Finding(
            scan_id=scan.id,
            title="SQLi",
            severity="high",
            description="demo",
            evidence=evidence_payload,
            evidence_hash=_hash_json_payload(evidence_payload),
            validation_status="passed",
            validated_at=datetime.now(timezone.utc),
        )
        session.add(finding)
        session.commit()
        finding_id = finding.id

    denied = client.post(
        "/validate",
        json={"finding_id": finding_id},
        headers=auth_headers(),
    )
    assert denied.status_code == 409

    forced = client.post(
        "/validate",
        json={"finding_id": finding_id, "force": True},
        headers=auth_headers(),
    )
    assert forced.status_code == 202
    assert queue.messages[-1][1]["finding_id"] == finding_id


def test_validator_callback_records_validation(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings],
    monkeypatch,
) -> None:
    client, queue, session_factory, settings = api_client
    settings.slack_webhook_url = "https://hooks.slack.test"
    settings.email_smtp_host = "smtp.test"
    settings.email_from = "alerts@example.com"
    settings.email_recipients = ["sec@example.com"]

    slack_calls: list[dict] = []
    email_calls: list[tuple[str, str]] = []

    def _fake_slack(url: str, payload: dict) -> None:
        slack_calls.append({"url": url, "payload": payload})

    def _fake_email(local_settings, subject: str, body: str) -> None:
        email_calls.append((subject, body))

    monkeypatch.setattr("controller.main._post_slack_notification", _fake_slack)
    monkeypatch.setattr("controller.main._send_email_notification", _fake_email)

    with session_factory() as session:
        target = Target(name="Callback", scope="cb.example", is_authorized=True)
        session.add(target)
        session.flush()

        scan = Scan(
            target_id=target.id,
            scanner="nuclei",
            status="completed",
            initiated_by="validator@test",
            parameters={},
        )
        session.add(scan)
        session.flush()

        evidence_payload = {"endpoint": "/admin"}
        finding = Finding(
            scan_id=scan.id,
            title="Critical Exposure",
            severity="critical",
            description="demo",
            evidence=evidence_payload,
            evidence_hash=_hash_json_payload(evidence_payload),
        )
        session.add(finding)
        session.commit()
        finding_id = finding.id

    enqueue = client.post(
        "/validate",
        json={"finding_id": finding_id},
        headers=auth_headers(),
    )
    assert enqueue.status_code == 202
    job_payload = queue.messages[-1][1]
    job_id = job_payload["job_id"]

    executed_at = datetime.now(timezone.utc).isoformat()
    callback_response = client.post(
        "/internal/validator/callback",
        json={
            "job_id": job_id,
            "finding_id": finding_id,
            "status": "passed",
            "validator": "retest-agent",
            "executed_at": executed_at,
            "metadata": {"notes": "all clear"},
            "evidence": {"status": 200},
        },
        headers={"X-Callback-Token": "validator-secret"},
    )
    assert callback_response.status_code == 202, callback_response.text
    body = callback_response.json()
    assert body["data"]["validation_status"] == "passed"
    assert body["data"]["validations"], "validation history should include new record"

    with session_factory() as session:
        stored = session.get(Finding, finding_id)
        assert stored is not None
        assert stored.validation_status == "passed"
        validations = session.query(FindingValidation).filter_by(finding_id=finding_id).all()
        assert len(validations) == 1
        assert validations[0].validator == "retest-agent"
        assert len(validations[0].evidence_hash) == 64
        assert len(validations[0].metadata_hash) == 64

    assert slack_calls, "Slack notification should be dispatched for critical findings"
    assert email_calls, "Email notification should be dispatched for critical findings"


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
    assert payload["meta"] == {"total": 1, "limit": 50, "offset": 0}
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


def test_anomalies_list_filters_and_audit(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings]
) -> None:
    client, _queue, session_factory, _settings = api_client

    metadata = {
        "raw": "<script>alert('x')</script>",
        "details": {"ip": "203.0.113.5", "payload": "<img src=x>"},
        "actors": ["analyst<script>", "ops"],
    }
    anomaly_id = _create_anomaly_event(session_factory, metadata=metadata)
    _create_anomaly_event(
        session_factory,
        anomaly_type="network_spike",
        actor="systemd",
        source="sensor",
        metadata={"raw": "benign"},
    )

    response = client.get(
        "/anomalies",
        params={"type": "login_spike", "limit": 10, "offset": 0},
        headers=auth_headers(),
    )
    assert response.status_code == 200, response.text
    payload = response.json()

    assert payload["meta"] == {"total": 1, "limit": 10, "offset": 0}
    assert len(payload["data"]) == 1
    event = payload["data"][0]
    assert event["id"] == anomaly_id

    sanitized_metadata = event["metadata"]
    assert "<" not in sanitized_metadata["raw"]
    assert "&lt;" in sanitized_metadata["raw"]
    assert "<" not in sanitized_metadata["details"]["payload"]
    assert "<" not in sanitized_metadata["actors"][0]

    with session_factory() as session:
        audit_entries = session.query(AuditLog).filter(AuditLog.action == "list_anomalies").all()
        assert len(audit_entries) == 1
        snapshot = audit_entries[0].evidence_snapshot
        assert snapshot["filters"]["anomaly_type"] == "login_spike"
        assert snapshot["returned"] == 1


def test_anomaly_detail_sanitizes_metadata_and_audits(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings]
) -> None:
    client, _queue, session_factory, _settings = api_client

    anomaly_id = _create_anomaly_event(
        session_factory,
        metadata={"note": "<b>alert</b>", "count": 7},
    )

    response = client.get(f"/anomalies/{anomaly_id}", headers=auth_headers())
    assert response.status_code == 200, response.text
    payload = response.json()["data"]
    assert payload["id"] == anomaly_id
    assert payload["metadata"]["note"].startswith("&lt;b&gt;")
    assert payload["metadata"]["count"] == 7

    with session_factory() as session:
        audit_entry = (
            session.query(AuditLog)
            .filter(AuditLog.action == "view_anomaly")
            .one()
        )
        snapshot = audit_entry.evidence_snapshot
        assert snapshot.get("resource_id") == anomaly_id
        assert snapshot.get("anomaly_type") == "login_spike"


def test_anomalies_require_finding_roles(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings]
) -> None:
    client, _queue, session_factory, _settings = api_client
    anomaly_id = _create_anomaly_event(session_factory)

    _secret, limited_headers = _provision_principal(
        client, subject="anomaly-rbac", roles=["scans:read"]
    )

    forbidden_list = client.get("/anomalies", headers=limited_headers)
    assert forbidden_list.status_code == 403

    forbidden_detail = client.get(
        f"/anomalies/{anomaly_id}", headers=limited_headers
    )
    assert forbidden_detail.status_code == 403


def test_findings_scope_filter(api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings]) -> None:
    client, _queue, session_factory, _settings = api_client

    with session_factory() as session:
        target = Target(name="Scope Filter", scope="corp.example", is_authorized=True)
        session.add(target)
        session.flush()

        in_scope_scan = Scan(target_id=target.id, scanner="nuclei", status="completed")
        out_scope_scan = Scan(target_id=target.id, scanner="nuclei", status="completed")
        session.add_all([in_scope_scan, out_scope_scan])
        session.flush()

        in_scope_evidence = {"url": "https://app.corp.example/login"}
        in_scope_finding = Finding(
            scan_id=in_scope_scan.id,
            title="Compliant",
            severity="medium",
            description="Within authorized scope",
            metadata_json={"host": "app.corp.example"},
            evidence=in_scope_evidence,
            evidence_hash=_hash_json_payload(in_scope_evidence),
            scope_status="in_scope",
            status="open",
        )
        out_scope_evidence = {"url": "http://attacker.example"}
        out_scope_finding = Finding(
            scan_id=out_scope_scan.id,
            title="Drift",
            severity="medium",
            description="Out-of-scope artifact",
            metadata_json={"host": "attacker.example"},
            evidence=out_scope_evidence,
            evidence_hash=_hash_json_payload(out_scope_evidence),
            scope_status="out_of_scope",
            status="open",
        )
        session.add_all([in_scope_finding, out_scope_finding])
        session.commit()

        in_scope_id = str(in_scope_finding.id)
        out_scope_id = str(out_scope_finding.id)

    out_response = client.get(
        "/findings", params={"scope": "out_of_scope"}, headers=auth_headers()
    )
    assert out_response.status_code == 200, out_response.text
    out_payload = out_response.json()
    assert out_payload["meta"] == {"total": 1, "limit": 50, "offset": 0}
    assert all(item["scope_status"] == "out_of_scope" for item in out_payload["data"])
    assert {item["id"] for item in out_payload["data"]} == {out_scope_id}

    in_response = client.get(
        "/findings", params={"scope": "in_scope"}, headers=auth_headers()
    )
    assert in_response.status_code == 200, in_response.text
    in_payload = in_response.json()
    assert in_payload["meta"] == {"total": 1, "limit": 50, "offset": 0}
    assert all(item["scope_status"] == "in_scope" for item in in_payload["data"])
    assert {item["id"] for item in in_payload["data"]} == {in_scope_id}

    scope_endpoint = client.get(
        "/findings/scope", params={"scope": "out_of_scope"}, headers=auth_headers()
    )
    assert scope_endpoint.status_code == 200, scope_endpoint.text
    scope_payload = scope_endpoint.json()
    assert scope_payload["meta"] == {"total": 1, "limit": 50, "offset": 0}
    assert {item["id"] for item in scope_payload["data"]} == {out_scope_id}

    out_timeline = client.get(
        "/findings/timeline",
        params={"scope": "out_of_scope"},
        headers=auth_headers(),
    )
    assert out_timeline.status_code == 200, out_timeline.text
    out_timeline_payload = out_timeline.json()["data"]
    assert sum(bucket["total"] for bucket in out_timeline_payload) == 1
    assert all(bucket["open"] == bucket["total"] for bucket in out_timeline_payload)

    in_timeline = client.get(
        "/findings/timeline",
        params={"scope": "in_scope"},
        headers=auth_headers(),
    )
    assert in_timeline.status_code == 200, in_timeline.text
    in_timeline_payload = in_timeline.json()["data"]
    assert sum(bucket["total"] for bucket in in_timeline_payload) == 1
    assert all(bucket["open"] == bucket["total"] for bucket in in_timeline_payload)


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

        evidence_payload = {"request": "GET /?id='"}
        finding = Finding(
            scan_id=scan.id,
            title="SQL injection",
            severity="high",
            cve_id="CVE-2024-9999",
            description="Unsanitised input",
            metadata_json={"template": "cve"},
            evidence=evidence_payload,
            evidence_hash=_hash_json_payload(evidence_payload),
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
        assert len(enrichment.advisories_hash) == 64
        assert len(enrichment.errors_hash) == 64
        assert len(enrichment.provenance_hash) == 64
        assert len(enrichment.payload_hash) == 64
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
    listing_payload = listing.json()
    assert listing_payload["meta"]["total"] == 1
    assert listing_payload["data"][0]["enrichments"][0]["errors"]["nvd"] == "timeout"

    detail = client.get(f"/findings/{finding_id}", headers=auth_headers())
    assert detail.status_code == 200

    with session_factory() as session:
        audit_entries = session.query(AuditLog).all()
        assert any(entry.action == "list_findings" for entry in audit_entries)
        assert any(entry.action == "get_finding" for entry in audit_entries)


def test_anomaly_callback_persists_events_and_notifies(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings],
) -> None:
    client, _queue, session_factory, _settings = api_client
    detected_at = datetime.now(timezone.utc)
    first_seen = detected_at - timedelta(minutes=1)
    last_seen = detected_at

    payload = {
        "source": "worker:anomaly",
        "detected_at": detected_at.isoformat(),
        "anomalies": [
            {
                "anomaly_type": "excessive_access_denied",
                "actor": "svc-tester",
                "first_seen": first_seen.isoformat(),
                "last_seen": last_seen.isoformat(),
                "count": 5,
                "window_seconds": 600,
                "metadata": {"reason_counts": {"missing_required_roles": 5}},
            }
        ],
    }

    response = client.post(
        "/internal/anomalies",
        json=payload,
        headers=anomaly_headers(),
    )
    assert response.status_code == 204, response.text

    with session_factory() as session:
        event = session.query(AnomalyEvent).one()
        assert event.anomaly_type == "excessive_access_denied"
        assert event.actor == "svc-tester"
        assert event.metadata_json["reason_counts"]["missing_required_roles"] == 5

    notification_service = app.dependency_overrides[get_notification_service]()
    assert notification_service.anomaly_notifications
    message = notification_service.anomaly_notifications[-1]
    assert message.anomaly_type == "excessive_access_denied"
    assert message.actor == "svc-tester"


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
    analyst_payload = analyst_response.json()
    assert analyst_payload["meta"] == {"total": 1, "limit": 50, "offset": 0}
    assert isinstance(analyst_payload["data"], list)


def test_scans_listing_applies_limit_offset_and_returns_metadata(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings],
) -> None:
    client, _queue, session_factory, settings = api_client

    now = datetime.now(tz=timezone.utc)

    with session_factory() as session:
        target = Target(name="Paginated Target", scope="paginate.example", is_authorized=True)
        session.add(target)
        session.flush()

        for index in range(5):
            created_at = now - timedelta(minutes=index)
            session.add(
                Scan(
                    target_id=target.id,
                    scanner="nuclei",
                    parameters={"profile": "baseline"},
                    initiated_by="controller",
                    status="completed",
                    created_at=created_at,
                    updated_at=created_at,
                )
            )

        session.commit()

    response = client.post(
        "/principals",
        json={
            "subject": "pager@example.com",
            "auth_method": "jwt",
            "roles": ["analyst"],
        },
        headers=auth_headers(),
    )
    assert response.status_code == 201

    token = jwt.encode({"sub": "pager@example.com"}, settings.jwt_secret, algorithm="HS256")

    paged_response = client.get(
        "/scans",
        params={"limit": 2, "offset": 1},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert paged_response.status_code == 200

    payload = paged_response.json()
    assert payload["meta"] == {"total": 5, "limit": 2, "offset": 1}
    assert len(payload["data"]) == 2

    # Scans are returned in descending creation order, so the second most recent scan
    # should be first when applying an offset of one.
    first_scan_created = datetime.fromisoformat(payload["data"][0]["created_at"])
    second_scan_created = datetime.fromisoformat(payload["data"][1]["created_at"])
    assert first_scan_created >= second_scan_created


def test_findings_listing_applies_limit_offset_and_returns_metadata(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings],
) -> None:
    client, _queue, session_factory, _settings = api_client

    now = datetime.now(tz=timezone.utc)

    with session_factory() as session:
        target = Target(name="Paginated Findings", scope="paginate.findings", is_authorized=True)
        session.add(target)
        session.flush()

        scan = Scan(target_id=target.id, scanner="nuclei", status="completed")
        session.add(scan)
        session.flush()

        for index in range(5):
            created_at = now - timedelta(minutes=index)
            evidence_payload = {"url": f"https://paginate.findings/{index}"}
            finding = Finding(
                scan_id=scan.id,
                title=f"Finding {index}",
                severity="medium",
                description="Synthetic pagination coverage",
                metadata_json={"scanner": "nuclei", "tool": "nuclei"},
                evidence=evidence_payload,
                evidence_hash=_hash_json_payload(evidence_payload),
                status="open",
            )
            finding.created_at = created_at
            finding.updated_at = created_at
            session.add(finding)

        session.commit()

    response = client.get(
        "/findings",
        params={"limit": 2, "offset": 1},
        headers=auth_headers(),
    )
    assert response.status_code == 200, response.text

    payload = response.json()
    assert payload["meta"] == {"total": 5, "limit": 2, "offset": 1}
    assert len(payload["data"]) == 2

    first_detected = datetime.fromisoformat(payload["data"][0]["detected_at"])
    second_detected = datetime.fromisoformat(payload["data"][1]["detected_at"])
    assert first_detected >= second_detected

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

        seed_snapshot = {"resource_type": "target", "resource_id": target.id}
        finding_snapshot = {
            "resource_type": "finding",
            "scan_id": scan.id,
            "note": "seed",
        }
        cleanup_snapshot = {"resource_type": "target", "resource_id": "old-id"}
        entries = [
            AuditLog(
                actor="bootstrap-admin",
                action="create_target",
                message="seed entry",
                evidence_snapshot=seed_snapshot,
                evidence_hash=_hash_json_payload(seed_snapshot),
                created_at=now - timedelta(minutes=5),
            ),
            AuditLog(
                actor="auditor@example.com",
                action="list_findings",
                message="read findings",
                scan_id=scan.id,
                evidence_snapshot=finding_snapshot,
                evidence_hash=_hash_json_payload(finding_snapshot),
                created_at=now - timedelta(minutes=3),
            ),
            AuditLog(
                actor="bootstrap-admin",
                action="delete_target",
                message="cleanup",
                evidence_snapshot=cleanup_snapshot,
                evidence_hash=_hash_json_payload(cleanup_snapshot),
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
            "binary:symbolic-execution",
            "targets:read",
            "enrich:enqueue",
            "validation:enqueue",
            "report:export",
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
            "binary:symbolic-execution",
            "targets:read",
            "targets:write",
            "enrich:enqueue",
            "validation:enqueue",
            "report:export",
            "ticket:create",
            "recon:enqueue",
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

    with session_factory() as session:
        stored_comment = (
            session.query(FindingComment)
            .filter(FindingComment.finding_id == finding_id)
            .order_by(FindingComment.created_at.desc())
            .first()
        )
        assert stored_comment is not None
        assert len(stored_comment.metadata_hash) == 64

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

    with session_factory() as session:
        jira_ticket = (
            session.query(FindingTicket)
            .filter(FindingTicket.reference == jira_payload["reference"])
            .one()
        )
        assert len(jira_ticket.payload_hash) == 64

    export_response = client.post(
        "/reports/export",
        json={"finding_ids": [finding_id], "format": "html"},
        headers=auth_headers(),
    )
    assert export_response.status_code == 200, export_response.text
    report_payload = export_response.json()
    assert report_payload["format"] == "html"
    assert report_payload["storage"]["bucket"]
    assert len(report_payload["checksum"]) == 64

    download_response = client.get(
        f"/reports/{report_payload['report_id']}",
        headers=auth_headers(),
    )
    assert download_response.status_code == 200
    assert download_response.headers["content-type"].startswith("text/html")
    assert hashlib.sha256(download_response.content).hexdigest() == report_payload["checksum"]

    history_response = client.get(
        "/reports/export",
        headers=auth_headers(),
    )
    assert history_response.status_code == 200
    history_payload = history_response.json()
    assert any(
        item["report_id"] == report_payload["report_id"]
        for item in history_payload["data"]
    )

    filtered = client.get(
        "/findings",
        params={"tag": "workflow:triage"},
        headers=auth_headers(),
    )
    assert filtered.status_code == 200
    filtered_payload = filtered.json()
    assert filtered_payload["meta"]["offset"] == 0
    assert filtered_payload["meta"]["limit"] == 50
    assert filtered_payload["meta"]["total"] >= 1
    assert any(item["id"] == finding_id for item in filtered_payload["data"])

    timeline = client.get(
        "/findings/timeline",
        params={"tag": "workflow:triage"},
        headers=auth_headers(),
    )
    assert timeline.status_code == 200
    timeline_payload = timeline.json()["data"]
    assert isinstance(timeline_payload, list)


def test_report_download_requires_export_role(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings]
) -> None:
    client, _queue, session_factory, _settings = api_client

    finding_id = _create_finding_record(session_factory)
    export_response = client.post(
        "/reports/export",
        json={"finding_ids": [finding_id], "format": "pdf"},
        headers=auth_headers(),
    )
    assert export_response.status_code == 200, export_response.text
    report_payload = export_response.json()

    limited_key = "limited-viewer"
    with session_factory() as session:
        credential = PrincipalCredential(
            subject="limited-viewer",
            auth_method="api_key",
            key_hash=_hash_secret(limited_key),
            roles=[ROLE_FINDINGS_READ],
        )
        session.add(credential)
        session.commit()

    limited_headers = {"X-API-Key": limited_key}
    forbidden_download = client.get(
        f"/reports/{report_payload['report_id']}",
        headers=limited_headers,
    )
    assert forbidden_download.status_code == status.HTTP_403_FORBIDDEN

    with session_factory() as session:
        credential = (
            session.query(PrincipalCredential)
            .filter(PrincipalCredential.subject == "limited-viewer")
            .one()
        )
        credential.roles = [ROLE_FINDINGS_READ, ROLE_REPORT_EXPORT]
        session.add(credential)
        session.commit()

    allowed_download = client.get(
        f"/reports/{report_payload['report_id']}",
        headers=limited_headers,
    )
    assert allowed_download.status_code == status.HTTP_200_OK
    assert allowed_download.headers["content-type"].startswith("application/pdf")


def test_finding_detail_includes_ticket_sync_state(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings]
) -> None:
    client, _queue, session_factory, _settings = api_client

    finding_id = _create_finding_record(session_factory)
    synced_at = datetime.now(timezone.utc)

    with session_factory() as session:
        payload = {"project_key": "SEC"}
        ticket = FindingTicket(
            finding_id=finding_id,
            integration="jira",
            reference="SEC-4242",
            url="https://jira.example.com/browse/SEC-4242",
            status="In Progress",
            payload=payload,
            payload_hash=_hash_json_payload(payload),
            created_by="sync-tester",
            synced_at=synced_at,
            remote_metadata={
                "status_category": "In Progress",
                "assignee": "analyst.one",
            },
        )
        session.add(ticket)
        session.commit()

    response = client.get(f"/findings/{finding_id}", headers=auth_headers())
    assert response.status_code == 200, response.text

    response_payload = response.json()["data"]
    assert response_payload["id"] == finding_id
    assert len(response_payload["tickets"]) == 1

    ticket_payload = response_payload["tickets"][0]
    assert ticket_payload["status"].lower() == "in progress"
    assert ticket_payload["url"] == "https://jira.example.com/browse/SEC-4242"
    assert ticket_payload["synced_at"] is not None
    assert ticket_payload["metadata"]["status_category"] == "In Progress"
    assert ticket_payload["metadata"]["assignee"] == "analyst.one"


def test_recon_active_job_flow(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker, Settings]
) -> None:
    client, queue, session_factory, settings = api_client

    with session_factory() as session:
        target = Target(name="Example", scope="example.com", is_authorized=True)
        session.add(target)
        session.commit()
        target_id = target.id

    enqueue_response = client.post(
        "/recon/jobs",
        json={
            "source": "operations:test",
            "mode": "active",
            "targets": [
                {
                    "target_id": target_id,
                    "scope": "example.com",
                    "asset_type": "domain",
                    "seed_assets": ["Portal.Example.com"],
                }
            ],
            "tools": {"subfinder": True, "amass": True, "httpx": {"enabled": True, "httpx_ports": [80]}},
            "labels": ["attack-surface"],
        },
        headers=auth_headers(),
    )
    assert enqueue_response.status_code == 202, enqueue_response.text
    job_response = enqueue_response.json()
    assert job_response["mode"] == "active"
    assert job_response["targets"][0]["target_id"] == target_id

    assert queue.messages, "Recon job should be enqueued"
    channel, job_payload = queue.messages.pop()
    assert channel == settings.recon_queue_channel
    assert job_payload["execution"]["mode"] == "active"
    assert job_payload["execution"]["targets"][0]["seed_assets"] == [
        "portal.example.com"
    ]

    now = datetime.now(tz=timezone.utc).isoformat()
    callback_payload = {
        "job_id": job_payload["job_id"],
        "source": "operations:test",
        "retrieved_at": now,
        "authorized_scopes": job_payload["authorized_scopes"],
        "execution": {
            "mode": "active",
            "targets": job_payload["execution"]["targets"],
            "tools": job_payload["execution"]["tools"],
        },
        "assets": [
            {
                "asset_type": "domain",
                "normalized_value": "api.example.com",
                "raw_value": "API.example.com",
                "matched_scope": "example.com",
                "metadata": {"sources": ["subfinder"], "target_id": target_id},
                "first_seen": now,
                "last_seen": now,
                "occurrences": 1,
            },
            {
                "asset_type": "url",
                "normalized_value": "https://api.example.com",
                "raw_value": "https://api.example.com",
                "matched_scope": "example.com",
                "metadata": {
                    "sources": ["httpx"],
                    "target_id": target_id,
                    "port": 443,
                    "service": {"status_code": 200, "technologies": ["Go"]},
                },
                "first_seen": now,
                "last_seen": now,
                "occurrences": 1,
            },
        ],
    }

    callback_response = client.post(
        "/internal/recon",
        json=callback_payload,
        headers={CALLBACK_TOKEN_HEADER: settings.recon_callback_token},
    )
    assert callback_response.status_code == 204, callback_response.text

    discoveries_response = client.get("/recon/discoveries", headers=auth_headers())
    assert discoveries_response.status_code == 200
    discoveries = discoveries_response.json()["data"]
    assert len(discoveries) >= 1
    assert discoveries[0]["diff_status"] in {
        "in_scope",
        "scope_extension",
        "approved",
        "unmatched",
    }

    runs_response = client.get("/recon/runs", headers=auth_headers())
    assert runs_response.status_code == 200
    runs = runs_response.json()["data"]
    assert runs, "Recon run should be recorded"
    run_id = runs[0]["id"]
    assert runs[0]["observation_count"] == 2

    observations_response = client.get(
        f"/recon/runs/{run_id}/observations", headers=auth_headers()
    )
    assert observations_response.status_code == 200
    observations = observations_response.json()["data"]
    assert len(observations) == 2
    assert any(item["asset_type"] == "url" for item in observations)


def test_hash_json_payload_handles_empty_structures() -> None:
    empty_dict_hash = _hash_json_payload({})
    empty_list_hash = _hash_json_payload([])
    assert len(empty_dict_hash) == 64
    assert len(empty_list_hash) == 64
    assert empty_dict_hash != empty_list_hash


def test_hash_json_payload_ignores_dict_key_order() -> None:
    payload_a = {
        "alpha": 1,
        "nested": {"beta": 2, "gamma": 3},
        "items": [
            {"name": "first", "value": 1},
            {"name": "second", "value": 2},
        ],
    }
    payload_b = {
        "items": [
            {"value": 1, "name": "first"},
            {"value": 2, "name": "second"},
        ],
        "nested": {"gamma": 3, "beta": 2},
        "alpha": 1,
    }
    assert _hash_json_payload(payload_a) == _hash_json_payload(payload_b)


def test_hash_json_payload_respects_list_order() -> None:
    ascending = [1, 2, 3]
    descending = list(reversed(ascending))
    assert _hash_json_payload(ascending) != _hash_json_payload(descending)
