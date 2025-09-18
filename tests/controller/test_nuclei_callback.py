import hashlib
import json
from datetime import datetime, timezone
from typing import Dict

import pytest

from controller.main import AuditEvent, Finding, FindingArtifact, Scan, Target
from tests.controller.test_main import auth_headers


@pytest.fixture()
def callback_headers() -> Dict[str, str]:
    return {"X-Callback-Token": "callback-secret"}


def _hash_payload(payload: Dict) -> str:
    normalized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _bootstrap_scan(session_factory, *, scope: str) -> str:
    with session_factory() as session:
        target = Target(name="api", url=f"https://{scope}", scope={"allowed_hosts": [scope]})
        session.add(target)
        session.commit()
        session.refresh(target)

        scan = Scan(
            target_id=target.id,
            profile="full",
            status="queued",
            requested_hosts=[scope],
            initiated_by="system",
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)
        return scan.id


def test_nuclei_callback_persists_findings_and_artifacts(client, callback_headers):
    test_client, _, session_factory = client
    scan_id = _bootstrap_scan(session_factory, scope="api.internal.example.com")

    completed_at = datetime.now(tz=timezone.utc).isoformat()
    payload = {
        "scan_id": scan_id,
        "status": "completed",
        "completed_at": completed_at,
        "worker_metadata": {"templates": 5, "duration_seconds": 2.5},
        "findings": [
            {
                "title": "SQL Injection",
                "severity": "high",
                "description": "Error-based SQL injection observed",
                "cve_id": "CVE-2024-9999",
                "metadata": {"template": "nuclei/sql/error"},
                "evidence": {"request": "GET /?id=1'"},
                "artifacts": [
                    {
                        "name": "http-request",
                        "artifact_type": "http",
                        "content_type": "text/plain",
                        "data": "GET /?id=1' HTTP/1.1\nHost: api.internal.example.com",
                        "metadata": {"direction": "request"},
                    }
                ],
            }
        ],
    }

    response = test_client.post("/internal/nuclei/callback", json=payload, headers=callback_headers)
    assert response.status_code == 200, response.text

    with session_factory() as session:
        scan = session.get(Scan, scan_id)
        assert scan is not None
        assert scan.status == "completed"
        assert scan.worker_metadata == {"templates": 5, "duration_seconds": 2.5}
        assert scan.worker_error is None
        assert scan.completed_at is not None

        findings = session.query(Finding).filter(Finding.scan_id == scan_id).all()
        assert len(findings) == 1
        finding = findings[0]
        assert finding.metadata_json == {"template": "nuclei/sql/error"}
        assert finding.evidence == {"request": "GET /?id=1'"}
        assert finding.cve_id == "CVE-2024-9999"
        assert finding.evidence_hash == _hash_payload(
            {"metadata": finding.metadata_json, "evidence": finding.evidence}
        )

        artifacts = session.query(FindingArtifact).filter(FindingArtifact.finding_id == finding.id).all()
        assert len(artifacts) == 1
        artifact = artifacts[0]
        assert artifact.metadata_json == {"direction": "request"}
        assert artifact.data_hash == hashlib.sha256(artifact.data.encode("utf-8")).hexdigest()

        audit = (
            session.query(AuditEvent)
            .filter(AuditEvent.action == "nuclei_callback", AuditEvent.resource_id == str(scan_id))
            .one()
        )
        assert audit.metadata_json == {"status": "completed", "findings_count": 1, "error": None}


def test_nuclei_callback_requires_token(client):
    test_client, _, _ = client
    response = test_client.post(
        "/internal/nuclei/callback",
        json={"scan_id": "missing", "status": "completed", "findings": []},
    )
    assert response.status_code == 401


def test_nuclei_callback_handles_missing_scan(client, callback_headers):
    test_client, _, _ = client
    response = test_client.post(
        "/internal/nuclei/callback",
        json={"scan_id": "does-not-exist", "status": "completed", "findings": []},
        headers=callback_headers,
    )
    assert response.status_code == 404


def test_nuclei_callback_is_idempotent_per_scan(client, callback_headers):
    test_client, _, session_factory = client
    scan_id = _bootstrap_scan(session_factory, scope="blog.internal.example.com")

    payload = {
        "scan_id": scan_id,
        "status": "completed",
        "findings": [],
    }

    first = test_client.post("/internal/nuclei/callback", json=payload, headers=callback_headers)
    assert first.status_code == 200, first.text

    second = test_client.post("/internal/nuclei/callback", json=payload, headers=callback_headers)
    assert second.status_code == 409
