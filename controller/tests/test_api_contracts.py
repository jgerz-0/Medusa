from datetime import datetime
from typing import Generator, Tuple

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

import jwt

from controller.db.models import AuditLog, Base, Finding, PrincipalCredential, Scan, Target
from controller.main import (
    QueueClient,
    Settings,
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
        api_keys=["test-key"],
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
