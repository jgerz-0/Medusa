"""Tests for the findings timeline aggregation helpers and related filters.

The unit tests validate that pre-aggregated SQL rows are transformed into
``FindingTimelineBucket`` responses with proper zero padding.  Regression
coverage exercises the controller endpoint to confirm the SQL-backed
aggregation respects filters and binary inclusion rules.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List, Tuple

import pytest

from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from controller.db.models import (
    BinaryFuzzingFinding,
    BinarySample,
    BinaryStaticAnalysisFinding,
    Finding,
    Scan,
    Target,
)
from controller.main import (
    FINDING_SCOPE_STATUS_IN_SCOPE,
    FINDING_STATUS_ACKNOWLEDGED,
    FINDING_STATUS_INVALIDATED,
    FINDING_STATUS_OPEN,
    FINDING_STATUS_PENDING_VALIDATION,
    FINDING_STATUS_RESOLVED,
    _build_timeline_buckets,
    _hash_json_payload,
)


def _build_row(*, bucket: datetime, status: str, count: int) -> Tuple[datetime, str, int]:
    """Return a synthetic SQL aggregation row for bucket unit tests."""

    return bucket, status, count


@pytest.mark.parametrize(
    "rows,expected",
    [
        (
            [
                _build_row(
                    bucket=datetime(2024, 1, 1, tzinfo=timezone.utc),
                    status=FINDING_STATUS_PENDING_VALIDATION,
                    count=1,
                ),
                _build_row(
                    bucket=datetime(2024, 1, 1, tzinfo=timezone.utc),
                    status=FINDING_STATUS_OPEN,
                    count=2,
                ),
                _build_row(
                    bucket=datetime(2024, 1, 1, tzinfo=timezone.utc),
                    status=FINDING_STATUS_INVALIDATED,
                    count=1,
                ),
                _build_row(
                    bucket=datetime(2024, 1, 2, tzinfo=timezone.utc),
                    status=FINDING_STATUS_ACKNOWLEDGED,
                    count=1,
                ),
                _build_row(
                    bucket=datetime(2024, 1, 2, tzinfo=timezone.utc),
                    status=FINDING_STATUS_RESOLVED,
                    count=1,
                ),
                _build_row(
                    bucket=datetime(2024, 1, 2, tzinfo=timezone.utc),
                    status=FINDING_STATUS_OPEN,
                    count=1,
                ),
            ],
            {
                datetime(2024, 1, 1, tzinfo=timezone.utc): {
                    "pending_validation": 1,
                    "open": 2,
                    "invalidated": 1,
                    "acknowledged": 0,
                    "resolved": 0,
                    "total": 4,
                },
                datetime(2024, 1, 2, tzinfo=timezone.utc): {
                    "pending_validation": 0,
                    "open": 1,
                    "invalidated": 0,
                    "acknowledged": 1,
                    "resolved": 1,
                    "total": 3,
                },
            },
        ),
    ],
)
def test_build_timeline_buckets_counts_statuses(
    rows: List[Tuple[datetime, str, int]],
    expected: dict[datetime, dict[str, int]],
) -> None:
    buckets = _build_timeline_buckets(rows)

    assert len(buckets) == len(expected)

    for bucket in buckets:
        values = expected[bucket.date]
        assert bucket.pending_validation == values["pending_validation"]
        assert bucket.open == values["open"]
        assert bucket.invalidated == values["invalidated"]
        assert bucket.acknowledged == values["acknowledged"]
        assert bucket.resolved == values["resolved"]
        assert bucket.total == values["total"]


def test_build_timeline_buckets_normalizes_timezones() -> None:
    bucket = datetime(
        2024,
        1,
        2,
        tzinfo=timezone(timedelta(hours=-5)),
    )
    rows = [
        _build_row(
            bucket=bucket,
            status=FINDING_STATUS_RESOLVED,
            count=1,
        )
    ]

    buckets = _build_timeline_buckets(rows)

    assert len(buckets) == 1
    bucket = buckets[0]
    assert bucket.date == datetime(2024, 1, 2, tzinfo=timezone.utc)
    assert bucket.resolved == 1
    assert bucket.pending_validation == 0
    assert bucket.open == 0
    assert bucket.invalidated == 0
    assert bucket.acknowledged == 0
    assert bucket.total == 1


def _seed_filtered_findings(
    session_factory: sessionmaker,
) -> dict[str, object]:
    """Persist mixed findings for API filter regression tests."""

    base_time = datetime(2024, 1, 1, tzinfo=timezone.utc)
    with session_factory() as session:
        target = Target(name="Filter Target", scope="filter.example", is_authorized=True)
        session.add(target)
        session.flush()

        scan = Scan(
            target_id=target.id,
            scanner="nuclei",
            initiated_by="filter-suite",
            status="completed",
            parameters={"profile": "filters"},
            created_at=base_time,
            updated_at=base_time,
        )
        session.add(scan)
        session.flush()

        recent_detected = base_time + timedelta(days=3)
        latest_evidence = {"poc": "latest"}
        recent = Finding(
            scan_id=scan.id,
            title="Recent high severity web finding",
            severity="high",
            cve_id=None,
            description="Seeded for pagination regression.",
            metadata_json={"scanner": "nuclei"},
            evidence=latest_evidence,
            evidence_hash=_hash_json_payload(latest_evidence),
            status=FINDING_STATUS_OPEN,
            assigned_to="analyst-1",
            tags=["prod"],
            scope_status=FINDING_SCOPE_STATUS_IN_SCOPE,
            created_at=recent_detected,
            updated_at=recent_detected,
        )
        session.add(recent)

        ack_detected = base_time + timedelta(days=1)
        ack_evidence = {"poc": "acknowledged"}
        acknowledged = Finding(
            scan_id=scan.id,
            title="Acknowledged high severity finding",
            severity="high",
            cve_id=None,
            description="Seeded to verify status filters.",
            metadata_json={"scanner": "nuclei"},
            evidence=ack_evidence,
            evidence_hash=_hash_json_payload(ack_evidence),
            status=FINDING_STATUS_ACKNOWLEDGED,
            assigned_to=None,
            tags=["archive"],
            scope_status=FINDING_SCOPE_STATUS_IN_SCOPE,
            created_at=ack_detected,
            updated_at=ack_detected,
        )
        session.add(acknowledged)

        sample = BinarySample(
            scan_id=scan.id,
            target_id=target.id,
            file_name="sample.bin",
            sha256="a" * 64,
            file_size=2048,
            mime_type="application/octet-stream",
            magic_type="ELF 64-bit",
            storage_bucket="samples",
            storage_key="sample.bin",
            metadata_json={},
            metadata_hash=_hash_json_payload({}),
            created_at=base_time,
            updated_at=base_time,
        )
        session.add(sample)
        session.flush()

        static_detected = base_time + timedelta(days=2)
        static_evidence = {"analysis": "overflow"}
        static_finding = BinaryStaticAnalysisFinding(
            sample_id=sample.id,
            scan_id=scan.id,
            job_id="static-job-1",
            tool="ghidra",
            severity="high",
            title="Static overflow",
            description="Seeded for SQL pagination regression.",
            metadata_json={},
            evidence=static_evidence,
            evidence_hash=_hash_json_payload(static_evidence),
            artifact_bucket="samples",
            artifact_key="analysis.json",
            executed_at=static_detected,
            created_at=static_detected,
            updated_at=static_detected,
        )
        session.add(static_finding)
        session.commit()

        return {
            "web_recent": str(recent.id),
            "web_ack": str(acknowledged.id),
            "static": str(static_finding.id),
            "recent_detected": recent_detected,
            "static_detected": static_detected,
            "ack_detected": ack_detected,
        }


def _seed_timeline_sql_findings(session_factory: sessionmaker) -> None:
    """Persist findings covering all timeline statuses and binary inclusion."""

    base_time = datetime(2024, 2, 1, tzinfo=timezone.utc)
    with session_factory() as session:
        target = Target(name="Timeline Target", scope="timeline.example", is_authorized=True)
        session.add(target)
        session.flush()

        scan = Scan(
            target_id=target.id,
            scanner="nuclei",
            initiated_by="timeline-suite",
            status="completed",
            parameters={"profile": "timeline"},
            created_at=base_time,
            updated_at=base_time,
        )
        session.add(scan)
        session.flush()

        schedule = [
            (FINDING_STATUS_PENDING_VALIDATION, base_time + timedelta(hours=1)),
            (FINDING_STATUS_OPEN, base_time + timedelta(hours=3)),
            (FINDING_STATUS_INVALIDATED, base_time + timedelta(days=1, hours=2)),
            (FINDING_STATUS_ACKNOWLEDGED, base_time + timedelta(days=2, hours=1)),
            (FINDING_STATUS_RESOLVED, base_time + timedelta(days=2, hours=3)),
        ]

        for index, (status, detected_at) in enumerate(schedule, start=1):
            evidence = {"poc": f"timeline-web-{index}"}
            finding = Finding(
                scan_id=scan.id,
                title=f"Timeline web finding {index}",
                severity="medium",
                cve_id=None,
                description="Seeded for SQL aggregation validation.",
                metadata_json={"scanner": "nuclei"},
                evidence=evidence,
                evidence_hash=_hash_json_payload(evidence),
                status=status,
                assigned_to=None,
                tags=[],
                scope_status=FINDING_SCOPE_STATUS_IN_SCOPE,
                created_at=detected_at,
                updated_at=detected_at,
            )
            session.add(finding)

        sample_metadata: dict[str, str] = {"origin": "timeline"}
        sample = BinarySample(
            scan_id=scan.id,
            target_id=target.id,
            file_name="timeline.bin",
            sha256="b" * 64,
            file_size=4096,
            mime_type="application/octet-stream",
            magic_type="ELF 64-bit",
            storage_bucket="samples",
            storage_key="timeline.bin",
            metadata_json=sample_metadata,
            metadata_hash=_hash_json_payload(sample_metadata),
            created_at=base_time,
            updated_at=base_time,
        )
        session.add(sample)
        session.flush()

        static_time = base_time + timedelta(hours=5)
        static_evidence = {"analysis": "timeline-static"}
        static_finding = BinaryStaticAnalysisFinding(
            sample_id=sample.id,
            scan_id=scan.id,
            job_id="timeline-static-job",
            tool="ghidra",
            severity="medium",
            title="Timeline static binary finding",
            description="Binary static finding for SQL aggregation tests.",
            metadata_json={},
            evidence=static_evidence,
            evidence_hash=_hash_json_payload(static_evidence),
            artifact_bucket="samples",
            artifact_key="timeline-static.json",
            executed_at=static_time,
            created_at=static_time,
            updated_at=static_time,
        )
        session.add(static_finding)

        fuzz_time = base_time + timedelta(days=1, hours=4)
        fuzz_evidence = {"crash": "timeline-fuzz"}
        fuzzing_finding = BinaryFuzzingFinding(
            sample_id=sample.id,
            scan_id=scan.id,
            job_id="timeline-fuzz-job",
            tool="libafl",
            severity="medium",
            title="Timeline fuzzing binary finding",
            description="Binary fuzzing finding for SQL aggregation tests.",
            metadata_json={},
            evidence=fuzz_evidence,
            evidence_hash=_hash_json_payload(fuzz_evidence),
            artifact_bucket="samples",
            artifact_key="timeline-fuzz.json",
            executed_at=fuzz_time,
            created_at=fuzz_time,
            updated_at=fuzz_time,
        )
        session.add(fuzzing_finding)

        session.commit()


def test_list_findings_orders_and_paginates_filtered_results(
    api_client: Tuple[TestClient, object, sessionmaker, object]
) -> None:
    client, _queue, session_factory, _settings = api_client
    seeded = _seed_filtered_findings(session_factory)

    response = client.get(
        "/findings",
        params={"severity": "high", "limit": 2, "offset": 0},
        headers={"X-API-Key": "test-key"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["meta"]["total"] == 3
    assert [entry["id"] for entry in payload["data"]] == [
        seeded["web_recent"],
        seeded["static"],
    ]
    assert [entry["category"] for entry in payload["data"]] == [
        "web",
        "binary_static",
    ]

    second_page = client.get(
        "/findings",
        params={"severity": "high", "limit": 2, "offset": 2},
        headers={"X-API-Key": "test-key"},
    )
    assert second_page.status_code == 200, second_page.text
    second_payload = second_page.json()
    assert second_payload["meta"]["total"] == 3
    assert [entry["id"] for entry in second_payload["data"]] == [
        seeded["web_ack"],
    ]

    tag_filtered = client.get(
        "/findings",
        params={"tag": "prod"},
        headers={"X-API-Key": "test-key"},
    )
    assert tag_filtered.status_code == 200, tag_filtered.text
    tag_payload = tag_filtered.json()
    assert tag_payload["meta"]["total"] == 1
    assert tag_payload["data"][0]["id"] == seeded["web_recent"]
    assert tag_payload["data"][0]["category"] == "web"


def test_findings_timeline_sql_aggregates_counts(
    api_client: Tuple[TestClient, object, sessionmaker, object]
) -> None:
    client, _queue, session_factory, _settings = api_client
    _seed_timeline_sql_findings(session_factory)

    response = client.get(
        "/findings/timeline",
        headers={"X-API-Key": "test-key"},
    )
    assert response.status_code == 200, response.text

    payload = response.json()["data"]
    assert len(payload) == 3

    buckets = {
        datetime.fromisoformat(entry["date"]): entry for entry in payload
    }

    day_one = datetime(2024, 2, 1, tzinfo=timezone.utc)
    day_two = datetime(2024, 2, 2, tzinfo=timezone.utc)
    day_three = datetime(2024, 2, 3, tzinfo=timezone.utc)

    assert day_one in buckets
    first = buckets[day_one]
    assert first["pending_validation"] == 1
    assert first["open"] == 2  # Web + binary static
    assert first["invalidated"] == 0
    assert first["acknowledged"] == 0
    assert first["resolved"] == 0
    assert first["total"] == 3

    assert day_two in buckets
    second = buckets[day_two]
    assert second["pending_validation"] == 0
    assert second["open"] == 1  # Binary fuzzing finding only
    assert second["invalidated"] == 1
    assert second["acknowledged"] == 0
    assert second["resolved"] == 0
    assert second["total"] == 2

    assert day_three in buckets
    third = buckets[day_three]
    assert third["pending_validation"] == 0
    assert third["open"] == 0
    assert third["invalidated"] == 0
    assert third["acknowledged"] == 1
    assert third["resolved"] == 1
    assert third["total"] == 2


def test_findings_timeline_honors_status_filter(
    api_client: Tuple[TestClient, object, sessionmaker, object]
) -> None:
    client, _queue, session_factory, _settings = api_client
    seeded = _seed_filtered_findings(session_factory)

    response = client.get(
        "/findings/timeline",
        params={"status": "open"},
        headers={"X-API-Key": "test-key"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()["data"]
    assert len(payload) == 2

    totals = {bucket["date"]: bucket["total"] for bucket in payload}
    assert sum(totals.values()) == 2

    returned_dates = {
        datetime.fromisoformat(bucket["date"]).date() for bucket in payload
    }
    assert seeded["ack_detected"].date() not in returned_dates

    for bucket in payload:
        assert bucket["acknowledged"] == 0
