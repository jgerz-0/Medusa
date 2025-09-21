import json

import pytest

from controller.main import Settings
from workers.web.zap import worker


@pytest.fixture
def zap_job_payload() -> dict:
    return {
        "job_id": "zap-job-1",
        "scan_id": "scan-123",
        "target": "https://app.example",
        "callback_url": "https://controller.local/internal/zap/callback",
        "scanner": "zap",
        "parameters": {"policy": "full", "mode": "full", "include_paths": ["/admin"]},
        "tags": ["zap", "policy:full"],
        "metadata": {"scan_id": "scan-123"},
    }


def test_zap_worker_config_defaults(monkeypatch):
    for env_var in ("ZAP_QUEUE_KEY", "MEDUSA_ZAP_QUEUE_CHANNEL"):
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
        binary_symbolic_execution_callback_token="binary-symbolic-secret",
        recon_callback_token="recon-secret",
    )
    assert config.queue_key == settings.zap_queue_channel
    assert config.dead_letter_key == "queues:zap:dead"


def test_zap_job_from_json_normalizes_fields(zap_job_payload):
    payload = json.dumps(zap_job_payload)
    job = worker.ZapJob.from_json(payload)

    assert job.job_id == "zap-job-1"
    assert job.scan_id == "scan-123"
    assert job.target == "https://app.example"
    assert job.parameters["policy"] == "full"
    assert job.tags == ["zap", "policy:full"]


def test_build_zap_command_only_allows_known_flags(tmp_path, zap_job_payload):
    config = worker.WorkerConfig.load()
    config.work_dir = str(tmp_path)
    job = worker.ZapJob.from_json(json.dumps(zap_job_payload))

    command = worker.build_zap_command(job, config)
    assert command[0] == config.zap_binary
    assert "-policy" in command
    assert "-quickurl" in command
    for arg in command:
        if arg.startswith("-"):
            assert arg in worker.ALLOWED_ZAP_FLAGS


def test_normalize_alerts_includes_metadata(zap_job_payload):
    job = worker.ZapJob.from_json(json.dumps(zap_job_payload))
    records = [
        {
            "alert": "Cross-Site Scripting",
            "riskcode": "3",
            "pluginid": "40012",
            "description": "Reflected payload detected",
            "tags": ["xss"],
            "instances": [
                {
                    "uri": "https://app.example/login",
                    "method": "GET",
                    "evidence": "<script>alert(1)</script>",
                }
            ],
        }
    ]

    findings = worker.normalize_alerts(records, job)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "high"
    assert finding["metadata"]["scanner"] == "zap"
    assert finding["metadata"]["rule_id"] == "zap:40012"
    assert finding["evidence"]["uri"] == "https://app.example/login"
