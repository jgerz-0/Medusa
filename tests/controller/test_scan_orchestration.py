import json
from datetime import datetime, timezone

import pytest

from controller.db.models import Scan, Target
from workers.web.sqlmap import worker as sqlmap_worker
from workers.web.zap import worker as zap_worker


@pytest.mark.usefixtures("client")
def test_zap_scan_flow(client):
    test_client, settings, SessionLocal, queue, notification_service = client

    with SessionLocal() as session:
        target = Target(name="ZAP target", scope="https://zap.local", is_authorized=True)
        session.add(target)
        session.commit()
        session.refresh(target)
        target_id = target.id

    response = test_client.post(
        "/scan",
        json={"target_id": target_id, "scanner": "zap", "parameters": {"policy": "full"}},
        headers={"X-API-Key": "test-key"},
    )
    assert response.status_code == 202, response.text

    assert queue.calls, "ZAP job was not enqueued"
    channel, job_payload = queue.calls[-1]
    assert channel == settings.zap_queue_channel
    assert job_payload["scanner"] == "zap"
    assert job_payload["parameters"]["policy"] == "full"

    job = zap_worker.ZapJob.from_json(json.dumps(job_payload))
    alerts = [
        {
            "alert": "Reflected XSS",
            "riskcode": "3",
            "description": "Reflected payload detected",
            "pluginid": "40012",
            "instances": [
                {
                    "uri": "https://zap.local/login",
                    "method": "GET",
                    "evidence": "<script>alert(1)</script>",
                }
            ],
        }
    ]
    findings = zap_worker.normalize_alerts(alerts, job)

    callback_payload = {
        "scan_id": job_payload["scan_id"],
        "status": "completed",
        "findings": findings,
    }
    callback_response = test_client.post(
        "/internal/zap/callback",
        json=callback_payload,
        headers={"X-Callback-Token": settings.zap_callback_token},
    )
    assert callback_response.status_code == 204, callback_response.text

    with SessionLocal() as session:
        scan = session.get(Scan, job_payload["scan_id"])
        assert scan is not None
        assert scan.status == "completed"
        assert scan.findings, "Callback did not persist findings"
        finding = scan.findings[0]
        assert finding.metadata_json.get("scanner") == "zap"
        assert finding.metadata_json.get("rule_id").startswith("zap:")
        assert finding.status == "pending_validation"
        assert finding.validation_status == "pending"

    validator_calls = [
        call for call in queue.calls if call[0] == settings.validator_queue_channel
    ]
    assert validator_calls, "Validator job was not enqueued"
    _validator_channel, validator_payload = validator_calls[-1]

    validation_response = test_client.post(
        "/internal/validator/callback",
        json={
            "job_id": validator_payload["job_id"],
            "status": "completed",
            "processed_at": datetime.now(timezone.utc).isoformat(),
            "findings": [
                {
                    "finding_id": validator_payload["finding_id"],
                    "status": "passed",
                    "observed_at": datetime.now(timezone.utc).isoformat(),
                    "evidence_hash": validator_payload.get("evidence_hash"),
                    "details": {"retest": "successful"},
                }
            ],
        },
        headers={"X-Callback-Token": settings.validator_callback_token},
    )
    assert validation_response.status_code == 204, validation_response.text

    with SessionLocal() as session:
        scan = session.get(Scan, job_payload["scan_id"])
        assert scan is not None
        finding = scan.findings[0]
        assert finding.status == "open"
        assert finding.validation_status == "passed"
        assert finding.validated_at is not None

    assert not notification_service.notifications


@pytest.mark.usefixtures("client")
def test_sqlmap_scan_flow(client):
    test_client, settings, SessionLocal, queue, _notification_service = client

    with SessionLocal() as session:
        target = Target(name="SQLMap target", scope="https://db.local", is_authorized=True)
        session.add(target)
        session.commit()
        session.refresh(target)
        target_id = target.id

    response = test_client.post(
        "/scan",
        json={
            "target_id": target_id,
            "scanner": "sqlmap",
            "parameters": {"risk": 2, "level": 3, "techniques": ["boolean"]},
        },
        headers={"X-API-Key": "test-key"},
    )
    assert response.status_code == 202, response.text

    assert queue.calls, "SQLMap job was not enqueued"
    channel, job_payload = queue.calls[-1]
    assert channel == settings.sqlmap_queue_channel
    assert job_payload["parameters"]["risk"] == 2
    assert job_payload["parameters"]["level"] == 3

    job = sqlmap_worker.SqlmapJob.from_json(json.dumps(job_payload))
    vulnerabilities = [
        {
            "title": "Boolean-based SQLi",
            "risk": 2,
            "level": 3,
            "parameter": "id",
            "vector": "GET parameter 'id'",
            "payload": "' OR '1'='1",
            "technique": "boolean",
            "dbms": "MySQL",
        }
    ]
    findings = sqlmap_worker.normalize_vulnerabilities(vulnerabilities, job)

    callback_payload = {
        "scan_id": job_payload["scan_id"],
        "status": "completed",
        "findings": findings,
    }
    callback_response = test_client.post(
        "/internal/sqlmap/callback",
        json=callback_payload,
        headers={"X-Callback-Token": settings.sqlmap_callback_token},
    )
    assert callback_response.status_code == 204, callback_response.text

    with SessionLocal() as session:
        scan = session.get(Scan, job_payload["scan_id"])
        assert scan is not None
        assert scan.status == "completed"
        assert len(scan.findings) == 1
        finding = scan.findings[0]
        assert finding.metadata_json.get("scanner") == "sqlmap"
        assert finding.metadata_json.get("rule_id").startswith("sqlmap:")
        assert finding.status == "pending_validation"


@pytest.mark.usefixtures("client")
def test_zap_scope_enforcement(client):
    test_client, _settings, SessionLocal, queue, _notification_service = client
    with SessionLocal() as session:
        target = Target(name="invalid", scope="zap.local", is_authorized=True)
        session.add(target)
        session.commit()
        session.refresh(target)
        target_id = target.id

    response = test_client.post(
        "/scan",
        json={"target_id": target_id, "scanner": "zap", "parameters": {}},
        headers={"X-API-Key": "test-key"},
    )
    assert response.status_code == 400
    initial_calls = [call for call in queue.calls if call[0] == _settings.zap_queue_channel]
    assert not initial_calls


@pytest.mark.usefixtures("client")
def test_sqlmap_scope_enforcement(client):
    test_client, _settings, SessionLocal, queue, _notification_service = client
    with SessionLocal() as session:
        target = Target(name="invalid", scope="db.local", is_authorized=True)
        session.add(target)
        session.commit()
        session.refresh(target)
        target_id = target.id

    response = test_client.post(
        "/scan",
        json={"target_id": target_id, "scanner": "sqlmap", "parameters": {}},
        headers={"X-API-Key": "test-key"},
    )
    assert response.status_code == 400
    initial_calls = [call for call in queue.calls if call[0] == _settings.sqlmap_queue_channel]
    assert not initial_calls


@pytest.mark.usefixtures("client")
def test_validator_notifies_on_critical(client):
    test_client, settings, SessionLocal, queue, notification_service = client

    with SessionLocal() as session:
        target = Target(name="Nuclei target", scope="https://nuclei.local", is_authorized=True)
        session.add(target)
        session.commit()
        session.refresh(target)
        target_id = target.id

    response = test_client.post(
        "/scan",
        json={"target_id": target_id, "scanner": "nuclei", "parameters": {}},
        headers={"X-API-Key": "test-key"},
    )
    assert response.status_code == 202, response.text

    nuclei_calls = [call for call in queue.calls if call[0] == settings.nuclei_queue_channel]
    assert nuclei_calls, "Nuclei job was not enqueued"
    _nuclei_channel, nuclei_job = nuclei_calls[-1]

    callback_payload = {
        "scan_id": nuclei_job["scan_id"],
        "status": "completed",
        "findings": [
            {
                "title": "Remote Code Execution",
                "severity": "critical",
                "description": "Nuclei detected a critical remote code execution path",
                "cve_id": "CVE-2024-0001",
                "metadata": {"template_id": "cves/2024/example"},
                "evidence": {"uri": "https://nuclei.local/admin", "method": "GET"},
            }
        ],
    }
    nuclei_callback = test_client.post(
        "/internal/nuclei/callback",
        json=callback_payload,
        headers={"X-Callback-Token": settings.nuclei_callback_token},
    )
    assert nuclei_callback.status_code == 204, nuclei_callback.text

    validator_calls = [
        call for call in queue.calls if call[0] == settings.validator_queue_channel
    ]
    assert validator_calls, "Validator job was not enqueued for nuclei finding"
    _validator_channel, validator_payload = validator_calls[-1]

    validation_payload = {
        "job_id": validator_payload["job_id"],
        "status": "completed",
        "processed_at": datetime.now(timezone.utc).isoformat(),
        "findings": [
            {
                "finding_id": validator_payload["finding_id"],
                "status": "passed",
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "evidence_hash": validator_payload.get("evidence_hash"),
                "details": {"proof": "reproduced"},
            }
        ],
    }
    validation_response = test_client.post(
        "/internal/validator/callback",
        json=validation_payload,
        headers={"X-Callback-Token": settings.validator_callback_token},
    )
    assert validation_response.status_code == 204, validation_response.text

    with SessionLocal() as session:
        scan = session.get(Scan, nuclei_job["scan_id"])
        assert scan is not None
        finding = scan.findings[0]
        assert finding.status == "open"
        assert finding.severity == "critical"
        assert finding.validation_status == "passed"

    assert notification_service.notifications
    notification = notification_service.notifications[-1]
    assert notification.finding_id == validator_payload["finding_id"]
    assert notification.severity == "critical"
