from datetime import datetime, timedelta, timezone

import pytest

from workers.anomaly.detector import AnomalyDetector, AuditEvent


@pytest.fixture
def base_event() -> AuditEvent:
    return AuditEvent(
        id="event-1",
        actor="principal-1",
        action="access_denied",
        created_at=datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc),
        metadata={"reason": "missing_required_roles", "resource_id": "endpoint:/targets"},
    )


def test_access_denied_heuristic_triggers(base_event: AuditEvent) -> None:
    detector = AnomalyDetector(access_denied_threshold=3, access_denied_window=timedelta(minutes=5))

    anomalies = []
    for index in range(3):
        event = AuditEvent(
            id=f"event-{index}",
            actor=base_event.actor,
            action="access_denied",
            created_at=base_event.created_at + timedelta(seconds=index * 30),
            metadata=base_event.metadata,
        )
        anomalies.extend(detector.ingest(event))

    assert len(anomalies) == 1
    anomaly = anomalies[0]
    assert anomaly.anomaly_type == "excessive_access_denied"
    assert anomaly.count == 3
    assert anomaly.metadata["reason_counts"]["missing_required_roles"] == 3


def test_rate_limit_detection_requires_reason(base_event: AuditEvent) -> None:
    detector = AnomalyDetector(rate_limit_threshold=2, rate_limit_window=timedelta(minutes=5))

    # First ingest events that do not carry the rate limit reason
    detector.ingest(base_event)
    detector.ingest(
        AuditEvent(
            id="event-2",
            actor=base_event.actor,
            action="access_denied",
            created_at=base_event.created_at + timedelta(minutes=1),
            metadata={"reason": "rate_limit_exceeded", "client_host": "10.0.0.1"},
        )
    )
    # Second rate-limited event should trigger the anomaly
    anomalies = detector.ingest(
        AuditEvent(
            id="event-3",
            actor=base_event.actor,
            action="access_denied",
            created_at=base_event.created_at + timedelta(minutes=1, seconds=30),
            metadata={"reason": "rate_limit_exceeded", "client_host": "10.0.0.2"},
        )
    )

    assert len(anomalies) == 1
    anomaly = anomalies[0]
    assert anomaly.anomaly_type == "repeated_rate_limit"
    assert anomaly.metadata["client_hosts"]["10.0.0.1"] == 1
    assert anomaly.metadata["client_hosts"]["10.0.0.2"] == 1


def test_scope_mismatch_detection_requires_multiple_events(base_event: AuditEvent) -> None:
    detector = AnomalyDetector(scope_mismatch_threshold=2, scope_mismatch_window=timedelta(minutes=10))

    first = AuditEvent(
        id="scope-1",
        actor="binary-preprocessor",
        action="preprocess_scope_mismatch",
        created_at=base_event.created_at,
        metadata={"provided_scope": "evil.example", "expected_scope": "prod.example"},
    )
    second = AuditEvent(
        id="scope-2",
        actor="binary-preprocessor",
        action="preprocess_scope_mismatch",
        created_at=base_event.created_at + timedelta(minutes=2),
        metadata={"provided_scope": "prod2.example", "expected_scope": "prod.example"},
    )

    assert detector.ingest(first) == []
    anomalies = detector.ingest(second)
    assert len(anomalies) == 1
    assert anomalies[0].anomaly_type == "scope_assertion_failures"
    assert len(anomalies[0].metadata["scope_examples"]) == 2
