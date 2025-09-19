import json
from datetime import datetime
from unittest import mock

import pytest
import requests

from workers.validator import worker


@pytest.fixture
def sample_payload() -> dict:
    return {
        "job_id": "job-001",
        "finding_id": "finding-123",
        "scan_id": "scan-abc",
        "severity": "CRITICAL",
        "callback_url": "https://controller.local/internal/validator/callback",
        "metadata": {
            "expected_status": 200,
            "observed_status": 200,
        },
        "evidence": {"url": "https://target/login"},
    }


def test_validation_job_from_json(sample_payload: dict) -> None:
    payload_json = json.dumps(sample_payload)
    job = worker.ValidationJob.from_json(payload_json)
    assert job.job_id == "job-001"
    assert job.severity == "critical"


def test_evaluate_job_marks_failures(sample_payload: dict) -> None:
    sample_payload["metadata"]["observed_status"] = 500
    job = worker.ValidationJob(**sample_payload)
    result = worker._evaluate_job(job)
    assert result["status"] == "failed"
    assert "500" in result["notes"]


def test_process_job_posts_callback(sample_payload: dict) -> None:
    job = worker.ValidationJob(**sample_payload)
    config = worker.WorkerConfig(callback_token="secret-token")

    fake_session = mock.create_autospec(requests.Session, instance=True)
    fake_response = mock.Mock()
    fake_response.raise_for_status.return_value = None
    fake_session.post.return_value = fake_response

    worker.process_job(job, config, http_session=fake_session)

    fake_session.post.assert_called_once()
    args, kwargs = fake_session.post.call_args
    assert args[0] == job.callback_url
    assert kwargs["headers"]["X-Callback-Token"] == "secret-token"
    payload = kwargs["json"]
    assert payload["status"] == "passed"
    assert payload["finding_id"] == job.finding_id
    datetime.fromisoformat(payload["executed_at"])  # raises on invalid format
