import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from controller.db.models import Base, PrincipalCredential
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


class FakeQueueClient(QueueClient):
    def __init__(self) -> None:
        self.calls = []

    def enqueue(self, channel: str, payload):  # type: ignore[override]
        self.calls.append((channel, payload))


@pytest.fixture()
def client():
    get_settings.cache_clear()  # type: ignore[attr-defined]

    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        redis_url="redis://localhost:6379/0",
        nuclei_queue_channel="test-nuclei",
        zap_queue_channel="test-zap",
        sqlmap_queue_channel="test-sqlmap",
        cve_enrichment_queue_channel="test-enrichment",
        jwt_secret="unit-test-secret",
        nuclei_callback_token="callback-secret",
        zap_callback_token="zap-secret",
        sqlmap_callback_token="sqlmap-secret",
        enrichment_callback_token="enrichment-secret",
        binary_static_analysis_callback_token="static-secret",
    )

    engine = create_engine(
        settings.database_url,
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(bind=engine, expire_on_commit=False, class_=Session)
    Base.metadata.create_all(bind=engine)

    with TestingSessionLocal() as session:
        session.add_all(
            [
                PrincipalCredential(
                    subject="svc-admin",
                    auth_method="api_key",
                    key_hash=_hash_secret("test-key"),
                    roles=list(DEFAULT_ADMIN_ROLES),
                    description="Controller admin",
                ),
                PrincipalCredential(
                    subject="svc-analyst",
                    auth_method="api_key",
                    key_hash=_hash_secret("analyst-key"),
                    roles=list(DEFAULT_ANALYST_ROLES),
                    description="Read-only analyst",
                ),
                PrincipalCredential(
                    subject="jwt-admin",
                    auth_method="jwt",
                    roles=["admin"],
                    description="JWT admin",
                ),
                PrincipalCredential(
                    subject="jwt-analyst",
                    auth_method="jwt",
                    roles=["analyst"],
                    description="JWT analyst",
                ),
            ]
        )
        session.commit()

    queue = FakeQueueClient()

    def override_settings() -> Settings:
        return settings

    def override_db():
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
        yield test_client, settings, TestingSessionLocal, queue

    app.dependency_overrides.clear()
    get_settings.cache_clear()  # type: ignore[attr-defined]
