import json
from datetime import datetime, timezone

import pytest

from workers.validator import worker


def _build_payload(**overrides):
    payload = {
        "job_id": "job-123",
        "validation_id": "val-456",
        "finding_id": "finding-1",
        "scan_id": "scan-2",
        "target_id": "target-3",
        "target": "https://example.com",
        "severity": "high",
        "validator": "http",
        "probe": {"url": "https://example.com", "method": "GET"},
        "callback_url": "https://controller/callback",
        "attempts": 0,
        "metadata": {"initiated_by": "tester"},
    }
    payload.update(overrides)
    return payload


def test_validation_job_from_json_parses_payload() -> None:
    payload = _build_payload()
    job = worker.ValidationJob.from_json(json.dumps(payload))

    assert job.job_id == "job-123"
    assert job.validation_id == "val-456"
    assert job.probe["url"] == "https://example.com"
    assert job.metadata["initiated_by"] == "tester"


def test_execute_validation_noop_returns_inconclusive() -> None:
    config = worker.WorkerConfig()
    job_payload = _build_payload(validator="noop", probe={"type": "noop"})
    job = worker.ValidationJob.from_json(json.dumps(job_payload))

    result = worker.execute_validation(job, config)

    assert result.status == "completed"
    assert result.outcome == "inconclusive"
    assert result.observations["probe"] == "noop"


def test_execute_validation_http_success(monkeypatch: pytest.MonkeyPatch) -> None:
    config = worker.WorkerConfig()
    job_payload = _build_payload(
        probe={"url": "https://example.com", "method": "GET", "expected_status": 200, "match": "hello"}
    )
    job = worker.ValidationJob.from_json(json.dumps(job_payload))

    class DummyResponse:
        status_code = 200
        content = b"hello world"
        text = "hello world"

    class DummySession:
        def request(self, method, url, timeout, verify):
            assert method == "GET"
            assert url == "https://example.com"
            return DummyResponse()

    monkeypatch.setattr(worker, "_create_http_session", lambda: DummySession())

    result = worker.execute_validation(job, config)

    assert result.status == "completed"
    assert result.outcome == "confirmed"
    assert result.observations["status_code"] == 200
    assert "response_snippet" in result.evidence


def test_validation_result_payload_serialization() -> None:
    job = worker.ValidationJob.from_json(json.dumps(_build_payload()))
    processed_at = datetime.now(tz=timezone.utc)
    result = worker.ValidationResult(
        status="completed",
        outcome="confirmed",
        processed_at=processed_at,
        attempts=1,
        observations={"probe": "http"},
        evidence={"status_code": 200},
        error=None,
    )

    payload = result.to_payload(job)

    assert payload["validation_id"] == job.validation_id
    assert payload["status"] == "completed"
    assert payload["observations"]["probe"] == "http"
