import logging
from typing import Generator, Tuple

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from controller.main import (
    AuditEvent,
    Base,
    Finding,
    QueueClient,
    Scan,
    Settings,
    Target,
    _engine_from_url,
    _session_factory_from_url,
    app,
    get_db_session,
    get_queue_client,
    get_settings,
)


class FakeQueueClient(QueueClient):
    def __init__(self) -> None:
        self.calls = []

    def enqueue(self, channel: str, payload):  # type: ignore[override]
        self.calls.append((channel, payload))


@pytest.fixture()
def client() -> Generator[Tuple[TestClient, FakeQueueClient, sessionmaker], None, None]:
    get_settings.cache_clear()  # type: ignore[attr-defined]
    _engine_from_url.cache_clear()  # type: ignore[attr-defined]
    _session_factory_from_url.cache_clear()  # type: ignore[attr-defined]
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        redis_url="redis://localhost:6379/0",
        nuclei_queue_channel="test-nuclei",
        jwt_secret="unit-test-secret",
        api_keys=["test-key"],
    )

    engine = create_engine(settings.database_url, future=True)
    TestingSessionLocal = sessionmaker(bind=engine, expire_on_commit=False, class_=Session)
    Base.metadata.create_all(bind=engine)

    queue = FakeQueueClient()

    def override_settings() -> Settings:
        return settings

    def override_db() -> Generator[Session, None, None]:
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.close()

    def override_queue() -> FakeQueueClient:
        return queue

    app.dependency_overrides[get_settings] = override_settings
    app.dependency_overrides[get_db_session] = override_db
    app.dependency_overrides[get_queue_client] = override_queue

    with TestClient(app) as test_client:
        yield test_client, queue, TestingSessionLocal

    app.dependency_overrides.clear()
    get_settings.cache_clear()  # type: ignore[attr-defined]
    _session_factory_from_url.cache_clear()  # type: ignore[attr-defined]
    _engine_from_url.cache_clear()  # type: ignore[attr-defined]


def auth_headers() -> dict[str, str]:
    return {"X-API-Key": "test-key"}


def test_target_scope_validation_rejects_out_of_scope(client):
    test_client, _, _ = client

    response = test_client.post(
        "/targets",
        json={
            "name": "prod-web",
            "url": "https://prod.internal.example.com",
            "scope": {"allowed_hosts": ["staging.internal.example.com"]},
        },
        headers=auth_headers(),
    )

    assert response.status_code == 422


def test_scan_enqueue_pushes_job(client):
    test_client, queue, session_factory = client

    create_resp = test_client.post(
        "/targets",
        json={
            "name": "prod-web",
            "url": "https://prod.internal.example.com",
            "scope": {"allowed_hosts": ["prod.internal.example.com"]},
        },
        headers=auth_headers(),
    )
    assert create_resp.status_code == 201, create_resp.text
    target_id = create_resp.json()["id"]

    scan_resp = test_client.post(
        "/scan",
        json={
            "target_id": target_id,
            "profile": "full",
            "requested_hosts": ["prod.internal.example.com"],
        },
        headers=auth_headers(),
    )

    assert scan_resp.status_code == 202, scan_resp.text
    payload = scan_resp.json()
    assert payload["target"] == "https://prod.internal.example.com"
    assert payload["findings_count"] == 0
    assert "updated_at" in payload

    assert queue.calls
    channel, payload = queue.calls[-1]
    assert channel == "test-nuclei"
    assert payload["target_id"] == target_id
    assert payload["profile"] == "full"

    with session_factory() as session:
        db_target = session.query(Target).get(target_id)
        assert db_target is not None
        assert db_target.scope["allowed_hosts"] == ["prod.internal.example.com"]


def test_audit_logging_records_events(client, caplog):
    caplog.set_level(logging.INFO, logger="medusa.audit")
    test_client, _, session_factory = client

    # seed target directly in DB for the read-only route
    with session_factory() as session:
        target = Target(name="prod-web", url="https://prod.internal.example.com", scope={"allowed_hosts": ["prod.internal.example.com"]})
        session.add(target)
        session.commit()

    response = test_client.get("/findings", headers=auth_headers())
    assert response.status_code == 200
    assert response.json() == {"data": []}

    with session_factory() as session:
        events = session.query(AuditEvent).filter(AuditEvent.action == "list_findings").all()
        assert len(events) == 1
        assert events[0].actor.startswith("apikey:")

    assert any(record.action == "list_findings" for record in caplog.records)


def test_list_scans_returns_enriched_payload(client):
    test_client, _, session_factory = client

    with session_factory() as session:
        target = Target(
            name="prod-web",
            url="https://prod.internal.example.com",
            scope={"allowed_hosts": ["prod.internal.example.com"]},
        )
        session.add(target)
        session.commit()
        session.refresh(target)

        scan = Scan(
            target_id=target.id,
            profile="full",
            status="completed",
            requested_hosts=["prod.internal.example.com"],
            initiated_by="system",
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)

        finding = Finding(
            scan_id=scan.id,
            severity="high",
            title="Expired certificate",
            description="cert expired",
        )
        session.add(finding)
        session.commit()

        target_url = target.url
        scan_id = scan.id

    response = test_client.get("/scans", headers=auth_headers())
    assert response.status_code == 200

    payload = response.json()
    assert set(payload.keys()) == {"data"}
    assert len(payload["data"]) == 1

    scan_payload = payload["data"][0]
    assert scan_payload["id"] == scan_id
    assert scan_payload["target"] == target_url
    assert scan_payload["findings_count"] == 1
    assert scan_payload["status"] == "completed"
    assert scan_payload["updated_at"] == scan_payload["created_at"]

    with session_factory() as session:
        audit_events = session.query(AuditEvent).filter(AuditEvent.action == "list_scans").all()
        assert len(audit_events) == 1


def test_list_findings_returns_enriched_payload(client):
    test_client, _, session_factory = client

    with session_factory() as session:
        target = Target(
            name="prod-web",
            url="https://prod.internal.example.com",
            scope={"allowed_hosts": ["prod.internal.example.com"]},
        )
        session.add(target)
        session.commit()
        session.refresh(target)

        scan = Scan(
            target_id=target.id,
            profile="full",
            status="running",
            requested_hosts=["prod.internal.example.com"],
            initiated_by="system",
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)

        finding = Finding(
            scan_id=scan.id,
            severity="critical",
            title="SQLi",
            description="Detected via nuclei",
        )
        session.add(finding)
        session.commit()

        finding_id = finding.id
        scan_id = scan.id

    response = test_client.get("/findings", headers=auth_headers())
    assert response.status_code == 200

    payload = response.json()
    assert len(payload["data"]) == 1

    finding_payload = payload["data"][0]
    assert finding_payload["id"] == finding_id
    assert finding_payload["scan_id"] == scan_id
    assert finding_payload["status"] == "open"
    assert finding_payload["template_id"] == "nuclei:unspecified"
    assert finding_payload["detected_at"] == finding_payload["updated_at"]
    assert finding_payload["evidence"] == "Detected via nuclei"
