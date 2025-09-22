from __future__ import annotations

from sqlalchemy.orm import Session

from controller.db.models import (
    AnomalyEvent as ORMAnomalyEvent,
    AuditLog,
    Finding,
    Scan,
    Target,
)
from controller.main import FINDING_SCOPE_STATUS_OUT_OF_SCOPE
from workers.scope.worker import ScopeMonitorWorker, WorkerConfig

pytest_plugins = ["controller.tests.conftest"]


def _seed_out_of_scope_finding(session: Session) -> None:
    target = Target(
        id="target-1", name="Authorized", scope="example.com", is_authorized=True
    )
    scan = Scan(id="scan-1", target=target, scanner="nuclei", status="completed")
    finding = Finding(
        id="finding-out",
        scan=scan,
        title="SQL injection",
        severity="high",
        description="Union-based SQL injection",
        metadata_json={"url": "http://evil.example.net/login"},
        evidence={"host": "evil.example.net"},
        evidence_hash="deadbeef" * 8,
        status="open",
        validation_status="pending",
        validation_metadata={},
        tags=[],
    )
    session.add(finding)
    session.commit()


def test_scope_monitor_dispatches_anomalies(api_client, monkeypatch) -> None:
    """Out-of-scope findings should yield persisted anomaly events."""

    client, _queue, session_factory, settings = api_client

    with session_factory() as session:
        engine = session.get_bind()

    monkeypatch.setattr(
        "workers.scope.worker.create_db_engine",
        lambda url, **kwargs: engine,
    )

    with session_factory() as session:
        _seed_out_of_scope_finding(session)

    config = WorkerConfig(
        database_url=settings.database_url,
        redis_url=None,
        callback_url=f"{client.base_url}/internal/anomalies",
        callback_token=settings.anomaly_callback_token,
        poll_interval=0,
        batch_size=5,
        lookback_seconds=86400,
        http_timeout=5,
        source="worker:scope-monitor-integration",
        audit_actor="worker:scope-monitor-integration",
    )
    worker = ScopeMonitorWorker(config)
    worker._http = client  # type: ignore[assignment]

    events = worker.poll_once()
    assert len(events) == 1
    event = events[0]
    assert event.scope_status == FINDING_SCOPE_STATUS_OUT_OF_SCOPE
    assert event.rejected_hosts == ["evil.example.net"]

    with session_factory() as session:
        stored_finding = session.get(Finding, "finding-out")
        assert stored_finding is not None
        assert stored_finding.scope_status == FINDING_SCOPE_STATUS_OUT_OF_SCOPE

        audits = session.query(AuditLog).all()
        assert len(audits) == 1
        assert audits[0].actor == config.audit_actor
        assert audits[0].evidence_snapshot["rejected_hosts"] == ["evil.example.net"]

        stored_anomalies = session.query(ORMAnomalyEvent).all()
        assert len(stored_anomalies) == 1
        anomaly = stored_anomalies[0]
        assert anomaly.anomaly_type == "scope_drift_detected"
        assert anomaly.source == config.source
        assert anomaly.metadata_json["finding_id"] == "finding-out"
        assert anomaly.metadata_json["rejected_hosts"] == ["evil.example.net"]
