import json
from datetime import datetime, timezone

from workers.validator.worker import HttpVerificationStep, ValidatorJob


def test_validator_job_from_json_parses_http_steps():
    submitted = datetime.now(timezone.utc).isoformat()
    payload = {
        "job_id": "job-1",
        "finding_id": "finding-1",
        "scan_id": "scan-1",
        "target_id": "target-1",
        "target_scope": "https://example.com",
        "callback_url": "https://controller.local/internal/validator/callback",
        "severity": "critical",
        "evidence_hash": "abc123",
        "submitted_at": submitted,
        "metadata": {"source_worker": "zap"},
        "verification": {
            "http": [
                {"method": "get", "url": "https://example.com", "expected_status": 200},
                {"method": "post", "url": "https://example.com/login", "expected_status": 302},
                {"method": "GET", "url": "invalid://ignored"},
            ]
        },
    }

    job = ValidatorJob.from_json(json.dumps(payload))

    assert job.job_id == "job-1"
    assert job.finding_id == "finding-1"
    assert job.submitted_at.tzinfo is not None
    assert isinstance(job.http_steps, list)
    assert len(job.http_steps) == 2
    assert job.http_steps[0] == HttpVerificationStep(method="GET", url="https://example.com", expected_status=200)
    assert job.http_steps[1] == HttpVerificationStep(method="POST", url="https://example.com/login", expected_status=302)
