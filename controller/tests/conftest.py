from __future__ import annotations

from typing import Generator, Tuple

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from controller.db.models import Base, PrincipalCredential
from controller.main import (
    DEFAULT_ADMIN_ROLES,
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
        zap_queue_channel="zap:test",
        sqlmap_queue_channel="sqlmap:test",
        validator_queue_channel="validator:test",
        jwt_secret="unit-test-secret",
        nuclei_callback_token="callback-secret",
        zap_callback_token="zap-callback",
        sqlmap_callback_token="sqlmap-callback",
        enrichment_callback_token="enrichment-secret",
        anomaly_callback_token="anomaly-secret",
        validator_callback_token="validator-secret",
        binary_static_analysis_queue_channel="binary-static:test",
        binary_static_analysis_callback_token="binary-static-secret",
        binary_fuzzing_queue_channel="binary-fuzzing:test",
        binary_fuzzing_callback_token="binary-fuzzing-secret",
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
