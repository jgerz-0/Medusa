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
    get_notification_service,
    get_queue_client,
    get_settings,
)
from controller.notifications import (
    AnomalyNotification,
    CriticalFindingNotification,
    NotificationService,
)


class FakeQueueClient(QueueClient):
    def __init__(self) -> None:
        self.calls = []

    def enqueue(self, channel: str, payload):  # type: ignore[override]
        self.calls.append((channel, payload))


class FakeNotificationService(NotificationService):
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
        self.notifications: list[CriticalFindingNotification] = []
        self.anomaly_notifications: list[AnomalyNotification] = []

    def notify_critical_finding(  # type: ignore[override]
        self, payload: CriticalFindingNotification
    ) -> None:
        self.notifications.append(payload)

    def notify_anomaly(  # type: ignore[override]
        self, payload: AnomalyNotification
    ) -> None:
        self.anomaly_notifications.append(payload)


@pytest.fixture()
def client():
    get_settings.cache_clear()  # type: ignore[attr-defined]

    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        redis_url="redis://localhost:6379/0",
        nuclei_queue_channel="test-nuclei",
        zap_queue_channel="test-zap",
        sqlmap_queue_channel="test-sqlmap",
        validator_queue_channel="test-validator",
        cve_enrichment_queue_channel="test-enrichment",
        jwt_secret="unit-test-secret",
        nuclei_callback_token="callback-secret",
        zap_callback_token="zap-secret",
        sqlmap_callback_token="sqlmap-secret",
        enrichment_callback_token="enrichment-secret",
        validator_callback_token="validator-secret",
        anomaly_callback_token="anomaly-secret",
        binary_static_analysis_callback_token="static-secret",
        binary_fuzzing_queue_channel="test-binary-fuzzing",
        binary_fuzzing_callback_token="fuzzing-secret",
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
    notification_service = FakeNotificationService()

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

    def override_notification_service() -> FakeNotificationService:
        return notification_service

    app.dependency_overrides[get_settings] = override_settings
    app.dependency_overrides[get_db_session] = override_db
    app.dependency_overrides[get_queue_client] = override_queue
    app.dependency_overrides[get_notification_service] = override_notification_service

    with TestClient(app) as test_client:
        yield test_client, settings, TestingSessionLocal, queue, notification_service

    app.dependency_overrides.clear()
    get_settings.cache_clear()  # type: ignore[attr-defined]
