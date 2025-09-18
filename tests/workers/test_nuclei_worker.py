import json
from unittest import mock

import pytest

from workers.web.nuclei import worker


@pytest.fixture
def sample_job():
    payload = json.dumps(
        {
            "job_id": "job-123",
            "target": "https://example.com",
            "templates": ["cves/2023/CVE-2023-9999.yaml"],
            "callback_url": "https://controller.local/callback",
            "tags": ["web"],
            "metadata": {"scan_id": "scan-777"},
        }
    )
    return worker.NucleiJob.from_json(payload)


def test_normalize_findings(sample_job):
    raw_records = [
        {
            "templateID": "CVE-2023-9999",
            "info": {"name": "Example Finding", "severity": "high", "description": "demo"},
            "matched-at": "https://example.com/login",
            "extracted-results": ["username"],
            "curl-command": "curl https://example.com",
        },
        {
            "template-id": "generic-misconfig",
            "info": {"name": "Misconfig", "severity": "medium"},
            "matchedAt": "https://example.com",
        },
    ]

    findings = worker.normalize_findings(raw_records, sample_job)
    assert findings == [
        {
            "job_id": "job-123",
            "target": "https://example.com",
            "template_id": "CVE-2023-9999",
            "name": "Example Finding",
            "description": "demo",
            "severity": "HIGH",
            "tags": ["web"],
            "evidence": {
                "matched_at": "https://example.com/login",
                "extracted_results": ["username"],
                "curl_command": "curl https://example.com",
            },
        },
        {
            "job_id": "job-123",
            "target": "https://example.com",
            "template_id": "generic-misconfig",
            "name": "Misconfig",
            "description": None,
            "severity": "MEDIUM",
            "tags": ["web"],
            "evidence": {
                "matched_at": "https://example.com",
            },
        },
    ]


def test_process_job_posts_callback(sample_job):
    config = worker.WorkerConfig()
    config.artifact_bucket = "medusa-artifacts"
    queue = mock.create_autospec(worker.RedisQueue, instance=True)

    scan_result = worker.ScanResult(
        records=[
            {
                "templateID": "CVE-2023-9999",
                "info": {"name": "Example Finding", "severity": "high"},
            }
        ],
        stdout="log line",
        stderr="",
        exit_code=0,
        duration_seconds=1.23,
    )

    mock_session = mock.create_autospec(worker.Session, instance=True)
    mock_response = mock.Mock()
    mock_response.raise_for_status.return_value = None
    mock_session.post.return_value = mock_response

    mock_s3 = mock.Mock()

    worker.process_job(
        sample_job,
        config,
        queue,
        run_scan=mock.Mock(return_value=scan_result),
        session=mock_session,
        s3_client=mock_s3,
    )

    # Ensure findings were normalized and callback invoked with expected payload.
    assert mock_session.post.called
    args, kwargs = mock_session.post.call_args
    assert args[0] == sample_job.callback_url
    payload = kwargs["json"]
    assert payload["status"] == "succeeded"
    assert payload["job_id"] == sample_job.job_id
    assert payload["findings"][0]["severity"] == "HIGH"
    assert "stdout" in payload["artifacts"]

    # stdout upload attempted because stdout is populated
    mock_s3.put_object.assert_called()
