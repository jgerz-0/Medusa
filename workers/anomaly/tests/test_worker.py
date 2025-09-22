from __future__ import annotations

from datetime import datetime, timezone

from controller.db.models import AnomalyEvent as ORMAnomalyEvent
from workers.anomaly.detector import AnomalyEvent
from workers.anomaly.worker import AnomalyWorker, WorkerConfig

pytest_plugins = ["controller.tests.conftest"]


def test_anomaly_worker_dispatches_with_callback_token(api_client) -> None:
    """Ensure the worker posts authenticated callbacks to the controller."""

    client, _queue, session_factory, settings = api_client
    config = WorkerConfig(
        database_url=settings.database_url,
        redis_url=None,
        callback_url=f"{client.base_url}/internal/anomalies",
        callback_token=settings.anomaly_callback_token,
        http_timeout=5,
        source="worker:anomaly-integration",
    )
    worker = AnomalyWorker(config)
    worker._http = client  # type: ignore[assignment]

    now = datetime.now(timezone.utc)
    event = AnomalyEvent(
        anomaly_type="excessive_access_denied",
        actor="svc-worker",
        first_seen=now,
        last_seen=now,
        count=3,
        window_seconds=600,
        metadata={"reason_counts": {"missing_required_roles": 3}},
    )

    worker._dispatch([event])

    with session_factory() as session:
        stored = session.query(ORMAnomalyEvent).one()
        assert stored.anomaly_type == event.anomaly_type
        assert stored.actor == event.actor
        assert stored.source == config.source
        assert stored.count == event.count
        assert stored.metadata_json["reason_counts"]["missing_required_roles"] == 3
