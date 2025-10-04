import pytest
from sqlalchemy import event

from controller.db.models import Finding, Scan, Target


@pytest.mark.usefixtures("client")
def test_list_findings_pagination_query_count(client):
    test_client, _settings, SessionLocal, _queue, _notification_service = client

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

        for index in range(30):
            session.add(
                Finding(
                    scan_id=scan.id,
                    title=f"Finding {index}",
                    severity="medium",
                    description="Example finding",
                    metadata_json={"example": True},
                    evidence={},
                    evidence_hash=f"hash-{index}",
                )
            )

        session.commit()

    engine = SessionLocal.kw["bind"]

    def perform(limit: int) -> int:
        query_count = 0

        def before_execute(*_args, **_kwargs):
            nonlocal query_count
            query_count += 1

        event.listen(engine, "before_cursor_execute", before_execute)
        try:
            response = test_client.get(
                "/findings",
                params={"limit": limit, "offset": 0},
                headers={"X-API-Key": "test-key"},
            )
        finally:
            event.remove(engine, "before_cursor_execute", before_execute)

        assert response.status_code == 200
        payload = response.json()
        assert payload["meta"]["limit"] == limit
        assert payload["meta"]["offset"] == 0
        assert payload["meta"]["total"] == 30

        return query_count

    counts = [perform(limit) for limit in (1, 10, 25)]
    assert counts[0] == counts[1] == counts[2]
