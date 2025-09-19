import json
from datetime import datetime
from unittest import mock

import pytest
from controller.main import NucleiCallbackRequest
from controller.main import CallbackFinding
from workers.web.nuclei import worker


@pytest.fixture
def sample_job():
    payload = json.dumps(
        {
            "job_id": "job-123",
            "scan_id": 42,
            "target": "https://example.com",
            "templates": ["cves/2023/CVE-2023-9999.yaml"],
            "callback_url": "https://controller.local/callback",
            "tags": ["web"],
            "metadata": {"scope": "production"},
        }
    )
    return worker.NucleiJob.from_json(payload)


def test_nuclei_job_from_json_normalizes_scan_id(sample_job):
    assert sample_job.scan_id == "42"
    assert isinstance(sample_job.scan_id, str)


def test_nuclei_job_from_json_supports_metadata_scan_id():
    payload = json.dumps(
        {
            "job_id": "job-456",
            "target": "https://service.example.com",
            "templates": ["http/default-logins"],
            "callback_url": "https://controller.local/callback",
            "metadata": {"scan_id": "scan-777"},
        }
    )
    job = worker.NucleiJob.from_json(payload)
    assert job.scan_id == "scan-777"


def test_normalize_findings(sample_job):
    raw_records = [
        {
            "templateID": "CVE-2023-9999",
            "info": {
                "name": "Example Finding",
                "severity": "high",
                "description": "demo",
            },
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
    assert findings[0]["title"] == "Example Finding"
    assert findings[0]["severity"] == "high"
    assert findings[0]["description"] == "demo"
    assert findings[0]["evidence"]["matched_at"] == "https://example.com/login"
    assert set(findings[0].keys()) == {
        "title",
        "severity",
        "description",
        "cve_id",
        "metadata",
        "evidence",
        "artifacts",
    }

    assert findings[0]["artifacts"] == []

    assert findings[1]["title"] == "Misconfig"
    assert findings[1]["severity"] == "medium"
    assert "finding" in findings[1]["description"].lower()
    assert findings[1]["evidence"]["matched_at"] == "https://example.com"
    assert set(findings[1].keys()) == {
        "title",
        "severity",
        "description",
        "cve_id",
        "metadata",
        "evidence",
        "artifacts",
    }

    # Ensure the payload satisfies the controller schema expectations.
    for finding in findings:
        CallbackFinding(**finding)


def test_normalize_findings_with_unknown_severity(sample_job):
    raw_records = [
        {
            "templateID": "tmpl-1",
            "info": {"name": "Unknown Severity", "severity": "weird"},
        }
    ]

    findings = worker.normalize_findings(raw_records, sample_job)
    assert findings[0]["severity"] == "info"
    CallbackFinding(**findings[0])
    assert findings[0].get("artifacts", []) == []


def test_process_job_posts_callback(sample_job):
    config = worker.WorkerConfig()
    config.artifact_bucket = "medusa-artifacts"
    config.callback_token = "shared-secret"
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
    assert payload["status"] == "completed"
    assert payload["scan_id"] == str(sample_job.scan_id)
    assert payload["findings"][0]["severity"] == "high"
    assert payload["error"] is None
    completed_at = payload["completed_at"]
    assert isinstance(completed_at, str)
    parsed_completed_at = datetime.fromisoformat(completed_at)
    assert parsed_completed_at.tzinfo is not None
    metadata = payload["worker_metadata"]
    assert metadata["artifacts"]["stdout"].endswith("stdout.log")
    assert metadata["job_id"] == sample_job.job_id
    artifact_locations = payload.get("artifact_locations")
    assert artifact_locations is not None
    assert artifact_locations["stdout"].endswith("stdout.log")

    headers = kwargs["headers"]
    assert headers["X-Callback-Token"] == "shared-secret"

    # stdout upload attempted because stdout is populated
    mock_s3.put_object.assert_called()

    # Validate payload against controller schema (extras ignored by design).
    model = NucleiCallbackRequest.model_validate(payload)
    assert model.scan_id == payload["scan_id"]
    assert model.status == "completed"


def test_post_callback_includes_token(sample_job):
    config = worker.WorkerConfig()
    config.callback_token = "shared-secret"

    mock_session = mock.create_autospec(worker.Session, instance=True)
    mock_response = mock.Mock()
    mock_response.raise_for_status.return_value = None
    mock_session.post.return_value = mock_response

    payload = {
        "scan_id": sample_job.scan_id,
        "status": "completed",
        "findings": [],
        "worker_metadata": {},
        "error": None,
        "completed_at": "2023-01-01T00:00:00+00:00",
    }

    worker.post_callback(sample_job, config, payload, session=mock_session)

    assert mock_session.post.called
    _, kwargs = mock_session.post.call_args
    headers = kwargs["headers"]
    assert headers["X-Callback-Token"] == "shared-secret"


def test_notify_failure_emits_error(sample_job):
    config = worker.WorkerConfig()
    config.callback_token = "shared-secret"
    mock_session = mock.create_autospec(worker.Session, instance=True)
    mock_response = mock.Mock()
    mock_response.raise_for_status.return_value = None
    mock_session.post.return_value = mock_response

    worker.notify_failure(
        sample_job, config, "controller unavailable", session=mock_session
    )

    args, kwargs = mock_session.post.call_args
    payload = kwargs["json"]
    assert payload["status"] == "failed"
    assert payload["error"] == "controller unavailable"
    assert payload["scan_id"] == sample_job.scan_id


def test_worker_loop_retries_on_callback_failure(monkeypatch, sample_job):
    config = worker.WorkerConfig()
    config.max_retries = 2
    config.callback_token = "shared-secret"

    mock_queue = mock.create_autospec(worker.RedisQueue, instance=True)
    mock_queue.fetch.side_effect = [sample_job, KeyboardInterrupt()]

    monkeypatch.setattr(
        worker, "WorkerConfig", mock.Mock(load=mock.Mock(return_value=config))
    )
    monkeypatch.setattr(worker, "RedisQueue", mock.Mock(return_value=mock_queue))
    monkeypatch.setattr(worker, "build_s3_client", mock.Mock(return_value=None))

    mock_session = mock.create_autospec(worker.Session, instance=True)
    mock_session.post.side_effect = worker.RequestException("boom")
    monkeypatch.setattr(
        worker, "requests", mock.Mock(Session=mock.Mock(return_value=mock_session))
    )

    scan_result = worker.ScanResult(
        records=[], stdout="", stderr="", exit_code=0, duration_seconds=0.5
    )
    original_process_job = worker.process_job

    def wrapped_process_job(job, cfg, queue_obj, *, session=None, s3_client=None):
        return original_process_job(
            job,
            cfg,
            queue_obj,
            run_scan=mock.Mock(return_value=scan_result),
            session=session,
            s3_client=s3_client,
        )

    monkeypatch.setattr(worker, "process_job", wrapped_process_job)

    worker.worker_loop()

    mock_queue.retry.assert_called()
    mock_queue.dead_letter.assert_not_called()


def test_worker_loop_dead_letters_after_max_retries(monkeypatch, sample_job):
    config = worker.WorkerConfig()
    config.max_retries = 1
    config.callback_token = "shared-secret"

    job_with_attempt = sample_job.with_attempt(config.max_retries)

    mock_queue = mock.create_autospec(worker.RedisQueue, instance=True)
    mock_queue.fetch.side_effect = [job_with_attempt, KeyboardInterrupt()]

    monkeypatch.setattr(
        worker, "WorkerConfig", mock.Mock(load=mock.Mock(return_value=config))
    )
    monkeypatch.setattr(worker, "RedisQueue", mock.Mock(return_value=mock_queue))
    monkeypatch.setattr(worker, "build_s3_client", mock.Mock(return_value=None))

    mock_session = mock.create_autospec(worker.Session, instance=True)
    mock_session.post.side_effect = worker.RequestException("boom")
    monkeypatch.setattr(
        worker, "requests", mock.Mock(Session=mock.Mock(return_value=mock_session))
    )

    scan_result = worker.ScanResult(
        records=[], stdout="", stderr="", exit_code=0, duration_seconds=0.5
    )
    original_process_job = worker.process_job

    def wrapped_process_job(job, cfg, queue_obj, *, session=None, s3_client=None):
        return original_process_job(
            job,
            cfg,
            queue_obj,
            run_scan=mock.Mock(return_value=scan_result),
            session=session,
            s3_client=s3_client,
        )

    monkeypatch.setattr(worker, "process_job", wrapped_process_job)

    notify_failure_mock = mock.Mock()
    monkeypatch.setattr(worker, "notify_failure", notify_failure_mock)

    worker.worker_loop()

    mock_queue.dead_letter.assert_called()
    notify_failure_mock.assert_called()
