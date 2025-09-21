from datetime import datetime, timezone

from controller.db.models import AuditLog, ReconDiscovery, Target


def _auth_headers() -> dict[str, str]:
    return {"X-API-Key": "test-key"}


def test_schedule_recon_job(client):
    test_client, settings, SessionLocal, queue, _notifications = client

    response = test_client.post(
        "/recon/jobs",
        json={
            "source": "inventory:web",
            "feed": {
                "type": "csv",
                "url": "https://inventory.local/assets.csv",
                "asset_column": "asset",
                "asset_type_column": "asset_type",
            },
            "authorized_scopes": ["example.com"],
            "labels": ["web"],
        },
        headers=_auth_headers(),
    )
    assert response.status_code == 202, response.text

    assert queue.calls, "Recon job was not enqueued"
    channel, payload = queue.calls[-1]
    assert channel == settings.recon_queue_channel
    assert payload["source"] == "inventory:web"
    assert payload["callback_url"].endswith("/internal/recon")
    assert payload["authorized_scopes"] == ["example.com"]

    with SessionLocal() as session:
        audit_entries = session.query(AuditLog).filter(
            AuditLog.action == "enqueue_recon_job"
        )
        assert audit_entries.count() == 1


def test_recon_callback_deduplicates(client):
    test_client, settings, SessionLocal, _queue, _notifications = client

    observed_at = datetime.now(tz=timezone.utc)
    payload = {
        "job_id": "job-123",
        "source": "inventory:web",
        "retrieved_at": observed_at.isoformat(),
        "assets": [
            {
                "asset_type": "domain",
                "normalized_value": "app.example.com",
                "raw_value": "App.Example.com",
                "matched_scope": "example.com",
                "metadata": {"labels": ["web"]},
                "first_seen": observed_at.isoformat(),
                "last_seen": observed_at.isoformat(),
                "occurrences": 1,
            },
            {
                "asset_type": "domain",
                "normalized_value": "app.example.com",
                "raw_value": "app.example.com",
                "matched_scope": "example.com",
                "metadata": {},
                "first_seen": observed_at.isoformat(),
                "last_seen": observed_at.isoformat(),
                "occurrences": 2,
            },
        ],
    }

    response = test_client.post(
        "/internal/recon",
        json=payload,
        headers={"X-Callback-Token": settings.recon_callback_token},
    )
    assert response.status_code == 204, response.text

    with SessionLocal() as session:
        discoveries = session.query(ReconDiscovery).all()
        assert len(discoveries) == 1
        discovery = discoveries[0]
        assert discovery.occurrences == 3
        assert discovery.matched_scope == "example.com"
        assert discovery.status == "new"

    # Submit a follow-up callback with updated timestamps to ensure deduplication.
    follow_up = payload | {
        "retrieved_at": datetime.now(tz=timezone.utc).isoformat(),
        "assets": [
            {
                "asset_type": "domain",
                "normalized_value": "app.example.com",
                "raw_value": "APP.example.com",
                "matched_scope": "example.com",
                "metadata": {},
                "first_seen": observed_at.isoformat(),
                "last_seen": datetime.now(tz=timezone.utc).isoformat(),
                "occurrences": 1,
            }
        ],
    }

    second = test_client.post(
        "/internal/recon",
        json=follow_up,
        headers={"X-Callback-Token": settings.recon_callback_token},
    )
    assert second.status_code == 204, second.text

    with SessionLocal() as session:
        discovery = session.query(ReconDiscovery).one()
        assert discovery.occurrences == 4
        assert discovery.metadata_json.get("labels") == ["web"]


def test_approve_recon_discovery_creates_target(client):
    test_client, settings, SessionLocal, _queue, _notifications = client

    observed_at = datetime.now(tz=timezone.utc)
    callback_payload = {
        "job_id": "job-approve",
        "source": "inventory:web",
        "retrieved_at": observed_at.isoformat(),
        "assets": [
            {
                "asset_type": "domain",
                "normalized_value": "app.example.com",
                "raw_value": "app.example.com",
                "matched_scope": "example.com",
                "metadata": {"labels": ["web"]},
                "first_seen": observed_at.isoformat(),
                "last_seen": observed_at.isoformat(),
                "occurrences": 1,
            }
        ],
    }

    response = test_client.post(
        "/internal/recon",
        json=callback_payload,
        headers={"X-Callback-Token": settings.recon_callback_token},
    )
    assert response.status_code == 204, response.text

    with SessionLocal() as session:
        discovery = session.query(ReconDiscovery).one()
        discovery_id = discovery.id

    approval = test_client.post(
        f"/recon/discoveries/{discovery_id}/approve",
        json={"target_name": "Example Service"},
        headers=_auth_headers(),
    )
    assert approval.status_code == 201, approval.text
    target_payload = approval.json()
    assert target_payload["name"] == "Example Service"

    with SessionLocal() as session:
        target = session.query(Target).filter(Target.id == target_payload["id"]).one()
        discovery = session.query(ReconDiscovery).filter(ReconDiscovery.id == discovery_id).one()
        assert target.scope == "app.example.com"
        assert discovery.status == "approved"
        assert discovery.approved_target_id == target.id
        assert discovery.metadata_json["approved_scope"] == target.scope

    # Attempting to approve outside the authorized scope should be rejected.
    with SessionLocal() as session:
        new_discovery = ReconDiscovery(
            source="inventory:web",
            asset_type="domain",
            value="db.example.com",
            raw_value="db.example.com",
            matched_scope="example.com",
            metadata_json={},
            status="new",
            first_seen=datetime.now(tz=timezone.utc),
            last_seen=datetime.now(tz=timezone.utc),
            occurrences=1,
        )
        session.add(new_discovery)
        session.commit()
        session.refresh(new_discovery)
        invalid_id = new_discovery.id

    rejection = test_client.post(
        f"/recon/discoveries/{invalid_id}/approve",
        json={"target_name": "DB", "scope": "evil.com"},
        headers=_auth_headers(),
    )
    assert rejection.status_code == 400
