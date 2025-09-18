import logging
from typing import Generator, Tuple

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from controller.main import (
    AuditEvent,
    Base,
    PrincipalCredential,
    QueueClient,
    Settings,
    Target,
    _engine_from_url,
    _hash_secret,
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
        api_keys=[],
    )

    engine = create_engine(settings.database_url, future=True)
    TestingSessionLocal = sessionmaker(bind=engine, expire_on_commit=False, class_=Session)
    Base.metadata.create_all(bind=engine)

    with TestingSessionLocal() as session:
        session.add_all(
            [
                PrincipalCredential(
                    subject="svc-admin",
                    auth_method="api_key",
                    key_hash=_hash_secret("test-key"),
                    roles=["admin", "scan:enqueue", "targets:write", "findings:read"],
                ),
                PrincipalCredential(
                    subject="svc-analyst",
                    auth_method="api_key",
                    key_hash=_hash_secret("analyst-key"),
                    roles=["analyst", "findings:read"],
                ),
            ]
        )
        session.commit()

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


def auth_headers(api_key: str = "test-key") -> dict[str, str]:
    return {"X-API-Key": api_key}


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
    assert queue.calls
    channel, payload = queue.calls[-1]
    assert channel == "test-nuclei"
    assert payload["target_id"] == target_id
    assert payload["profile"] == "full"

    with session_factory() as session:
        db_target = session.query(Target).get(target_id)
        assert db_target is not None
        assert db_target.scope["allowed_hosts"] == ["prod.internal.example.com"]


def test_scan_enqueue_requires_role(client):
    test_client, queue, _ = client

    create_resp = test_client.post(
        "/targets",
        json={
            "name": "prod-web",
            "url": "https://prod.internal.example.com",
            "scope": {"allowed_hosts": ["prod.internal.example.com"]},
        },
        headers=auth_headers(),
    )
    assert create_resp.status_code == 201
    target_id = create_resp.json()["id"]

    denied_resp = test_client.post(
        "/scan",
        json={
            "target_id": target_id,
            "profile": "full",
            "requested_hosts": ["prod.internal.example.com"],
        },
        headers=auth_headers("analyst-key"),
    )

    assert denied_resp.status_code == 403
    assert not queue.calls


def test_invalid_api_key_rejected(client):
    test_client, _, _ = client

    response = test_client.get("/findings", headers=auth_headers("bad-key"))

    assert response.status_code == 401


def test_audit_logging_records_events(client, caplog):
    caplog.set_level(logging.INFO, logger="medusa.audit")
    test_client, _, session_factory = client

    with session_factory() as session:
        target = Target(
            name="prod-web",
            url="https://prod.internal.example.com",
            scope={"allowed_hosts": ["prod.internal.example.com"]},
        )
        session.add(target)
        session.commit()

    response = test_client.get("/findings", headers=auth_headers("analyst-key"))
    assert response.status_code == 200

    with session_factory() as session:
        events = session.query(AuditEvent).filter(AuditEvent.action == "list_findings").all()
        assert len(events) == 1
        assert events[0].actor == "svc-analyst"

    assert any(record.action == "list_findings" for record in caplog.records)
