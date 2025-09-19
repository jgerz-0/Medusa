import json

import pytest

from controller.db.models import Scan, Target
from workers.web.sqlmap import worker as sqlmap_worker
from workers.web.zap import worker as zap_worker


@pytest.mark.usefixtures("client")
def test_zap_scan_flow(client):
    test_client, settings, SessionLocal, queue = client

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


@pytest.mark.usefixtures("client")
def test_sqlmap_scan_flow(client):
    test_client, settings, SessionLocal, queue = client

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


@pytest.mark.usefixtures("client")
def test_zap_scope_enforcement(client):
    test_client, _settings, SessionLocal, queue = client
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
    test_client, _settings, SessionLocal, queue = client
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
