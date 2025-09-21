import json

import pytest

from controller.main import Settings
from workers.web.sqlmap import worker


@pytest.fixture
def sqlmap_job_payload() -> dict:
    return {
        "job_id": "sqlmap-job-1",
        "scan_id": "scan-456",
        "target": "https://db.example",
        "callback_url": "https://controller.local/internal/sqlmap/callback",
        "scanner": "sqlmap",
        "parameters": {"risk": 2, "level": 3, "techniques": ["boolean", "time"], "request_delay": 0.5},
        "tags": ["sqlmap", "risk:2"],
        "metadata": {"scan_id": "scan-456"},
    }


def test_sqlmap_worker_config_defaults(monkeypatch):
    for env_var in ("SQLMAP_QUEUE_KEY", "MEDUSA_SQLMAP_QUEUE_CHANNEL"):
        monkeypatch.delenv(env_var, raising=False)

    config = worker.WorkerConfig.load()
    settings = Settings(
        jwt_secret="test-jwt",
        nuclei_callback_token="nuclei-token",
        zap_callback_token="zap-token",
        sqlmap_callback_token="sqlmap-token",
        enrichment_callback_token="enrichment-token",
        validator_callback_token="validator-secret",
        anomaly_callback_token="anomaly-secret",
        binary_static_analysis_callback_token="static-secret",
        binary_fuzzing_callback_token="fuzzing-secret",
        recon_callback_token="recon-secret",
    )
    assert config.queue_key == settings.sqlmap_queue_channel
    assert config.dead_letter_key == "queues:sqlmap:dead"


def test_sqlmap_job_from_json(sqlmap_job_payload):
    job = worker.SqlmapJob.from_json(json.dumps(sqlmap_job_payload))
    assert job.job_id == "sqlmap-job-1"
    assert job.parameters["risk"] == 2
    assert job.parameters["level"] == 3
    assert job.tags == ["sqlmap", "risk:2"]


def test_build_sqlmap_command_enforces_flags(tmp_path, sqlmap_job_payload):
    config = worker.WorkerConfig.load()
    config.work_dir = str(tmp_path)
    job = worker.SqlmapJob.from_json(json.dumps(sqlmap_job_payload))

    command = worker.build_sqlmap_command(job, config)
    assert command[0] == config.sqlmap_binary
    assert "--batch" in command
    assert "-u" in command
    for arg in command:
        if isinstance(arg, str) and arg.startswith("-"):
            assert arg in worker.ALLOWED_SQLMAP_FLAGS


def test_normalize_vulnerabilities_generates_metadata(sqlmap_job_payload):
    job = worker.SqlmapJob.from_json(json.dumps(sqlmap_job_payload))
    records = [
        {
            "title": "Boolean-based SQLi",
            "risk": 2,
            "level": 3,
            "parameter": "id",
            "vector": "GET parameter 'id'",
            "payload": "' OR '1'='1",
            "technique": "boolean",
            "dbms": "PostgreSQL",
        }
    ]

    findings = worker.normalize_vulnerabilities(records, job)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "medium"
    assert finding["metadata"]["scanner"] == "sqlmap"
    assert finding["metadata"]["rule_id"].startswith("sqlmap:")
    assert finding["evidence"]["parameter"] == "id"
