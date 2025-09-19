from datetime import datetime

import pytest

from controller.db.models import Finding, Scan, Target


@pytest.mark.usefixtures("client")
def test_enqueue_enrichment_job(client):
    test_client, settings, SessionLocal, queue = client
    with SessionLocal() as session:
        target = Target(name="demo", scope="demo.example", is_authorized=True)
        session.add(target)
        session.flush()

        scan = Scan(
            target_id=target.id,
            scanner="nuclei",
            initiated_by="svc-admin",
            parameters={},
            status="completed",
        )
        session.add(scan)
        session.flush()

        finding = Finding(
            scan_id=scan.id,
            title="Example finding",
            severity="high",
            cve_id="CVE-2023-1234",
            description="Example description",
            metadata_json={"cpe": ["cpe:/a:demo"]},
            evidence={"matched": "https://demo"},
            evidence_hash="",
        )
        session.add(finding)
        session.commit()
        session.refresh(finding)

    response = test_client.post(
        "/enrich",
        json={"finding_id": finding.id, "sources": ["nvd", "circl"]},
        headers={"X-API-Key": "legacy-key"},
    )
    assert response.status_code == 202
    payload = response.json()
    assert payload["finding_id"] == finding.id
    assert "job_id" in payload
    queued_at = datetime.fromisoformat(payload["queued_at"])
    assert queued_at.tzinfo is not None
    assert payload["sources"] == ["nvd", "circl"]

    assert queue.calls, "Enrichment job was not enqueued"
    channel, job_payload = queue.calls[-1]
    assert channel == settings.cve_enrichment_queue_channel
    assert job_payload["job_id"] == payload["job_id"]
    assert job_payload["finding_id"] == finding.id
    assert job_payload["sources"] == ["nvd", "circl"]


def test_enqueue_enrichment_missing_finding(client):
    test_client, settings, SessionLocal, queue = client

    response = test_client.post(
        "/enrich",
        json={"finding_id": "missing"},
        headers={"X-API-Key": "legacy-key"},
    )
    assert response.status_code == 404
    assert not queue.calls


def test_enqueue_enrichment_rejects_unknown_source(client):
    test_client, settings, SessionLocal, queue = client

    # ensure queue remains untouched when validation fails
    response = test_client.post(
        "/enrich",
        json={"finding_id": "anything", "sources": ["unknown"]},
        headers={"X-API-Key": "legacy-key"},
    )
    assert response.status_code == 422
    assert not queue.calls

