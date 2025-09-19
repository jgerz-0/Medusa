from datetime import datetime, timedelta, timezone
from typing import Generator, Tuple

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

import jwt

from controller.db.models import AuditLog, Base, Finding, PrincipalCredential, Scan, Target
from controller.main import (
    DEFAULT_ADMIN_ROLES,
    DEFAULT_ANALYST_ROLES,
    QueueClient,
    Settings,
    _hash_secret,
    app,
    get_db_session,
    get_queue_client,
    get_settings,
)


class InMemoryQueue(QueueClient):
    def __init__(self) -> None:
        self.messages: list[Tuple[str, dict]] = []

    def enqueue(self, channel: str, payload: dict) -> None:  # type: ignore[override]
        self.messages.append((channel, payload))


@pytest.fixture()
def api_client() -> (
    Generator[Tuple[TestClient, InMemoryQueue, sessionmaker, Settings], None, None]
):
    get_settings.cache_clear()  # type: ignore[attr-defined]
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        redis_url="redis://localhost:6379/0",
        nuclei_queue_channel="nuclei:test",
        jwt_secret="unit-test-secret",
        nuclei_callback_token="callback-secret",
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

    app.dependency_overrides[get_settings] = override_settings
    app.dependency_overrides[get_db_session] = override_session
    app.dependency_overrides[get_queue_client] = override_queue

    with TestClient(app) as client:
        yield client, queue, SessionFactory, settings

    app.dependency_overrides.clear()
    get_settings.cache_clear()  # type: ignore[attr-defined]
    Base.metadata.drop_all(engine)
    engine.dispose()


def auth_headers() -> dict[str, str]:
    return {"X-API-Key": "test-key"}


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
    assert job["target_id"] == target_payload["id"]
    assert job["scanner"] == "nuclei"
    assert job["parameters"] == {"profile": "full"}

    scans_collection = client.get("/scans", headers=auth_headers())
    assert scans_collection.status_code == 200
    collection_payload = scans_collection.json()
    assert "data" in collection_payload
    assert len(collection_payload["data"]) == 1
    assert collection_payload["data"][0]["id"] == scan_payload["id"]


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

    revoke_response = client.post(
        f"/principals/{first_id}/revoke", headers=auth_headers()
    )
    assert revoke_response.status_code == 200, revoke_response.text
    revoked_payload = revoke_response.json()
    assert revoked_payload["revoked_at"] is not None

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
    datetime.fromisoformat(finding_item["detected_at"])  # raises on invalid format

    detail_response = client.get(f"/findings/{finding_id}", headers=auth_headers())
    assert detail_response.status_code == 200
    detail_payload = detail_response.json()
    assert detail_payload["data"]["id"] == finding_id

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
    assert response.status_code == 403

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
        datetime.fromisoformat(item["created_at"])
        for item in payload["data"]
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
            "targets:read",
            "enrich:enqueue",
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
            "targets:read",
            "targets:write",
            "enrich:enqueue",
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

    revoked_response = client.get(
        "/targets", headers={"X-API-Key": "revoked-key"}
    )
    assert revoked_response.status_code == 403

    with session_factory() as session:
        audit_actions = [entry.action for entry in session.query(AuditLog).all()]
    assert audit_actions.count("list_targets") == initial_audit_count
