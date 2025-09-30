"""Tests for the findings timeline aggregation helpers and related filters.

These tests build synthetic ``FindingResponse`` records and ensure that
``_build_timeline_buckets`` groups and counts them correctly.  The
regression coverage also exercises the controller endpoints to confirm SQL
filtering and ordering operate as expected after refactors.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterable, Tuple

import pytest

from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from controller.db.models import (
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
    VALIDATION_STATUS_PENDING,
    FindingResponse,
    _build_timeline_buckets,
    _hash_json_payload,
)


def _build_response(
    *,
    identifier: str,
    status: str,
    detected_at: datetime,
) -> FindingResponse:
    """Return a minimal ``FindingResponse`` for timeline aggregation tests."""

    return FindingResponse(
        id=identifier,
        scan_id="scan-1",
        title=f"Synthetic finding {identifier}",
        severity="medium",
        cve_id=None,
        description="Generated for timeline bucketing tests.",
        detected_at=detected_at,
        updated_at=detected_at,
        status=status,
        template_id="tpl-1",
        evidence=None,
        remediation=None,
        metadata={},
        scanner="nuclei",
        category="web",
        assigned_to=None,
        validation_status=VALIDATION_STATUS_PENDING,
        cvss=5.0,
        scope_status=FINDING_SCOPE_STATUS_IN_SCOPE,
    )


@pytest.mark.parametrize(
    "responses,expected",
    [
        (
            [
                _build_response(
                    identifier="f-1",
                    status=FINDING_STATUS_PENDING_VALIDATION,
                    detected_at=datetime(2024, 1, 1, 9, 30, tzinfo=timezone.utc),
                ),
                _build_response(
                    identifier="f-2",
                    status=FINDING_STATUS_OPEN,
                    detected_at=datetime(2024, 1, 1, 10, 0, tzinfo=timezone.utc),
                ),
                _build_response(
                    identifier="f-3",
                    status=FINDING_STATUS_OPEN,
                    detected_at=datetime(2024, 1, 1, 11, 15, tzinfo=timezone.utc),
                ),
                _build_response(
                    identifier="f-4",
                    status=FINDING_STATUS_INVALIDATED,
                    detected_at=datetime(2024, 1, 1, 14, 0, tzinfo=timezone.utc),
                ),
                _build_response(
                    identifier="f-5",
                    status=FINDING_STATUS_ACKNOWLEDGED,
                    detected_at=datetime(2024, 1, 2, 8, 45, tzinfo=timezone.utc),
                ),
                _build_response(
                    identifier="f-6",
                    status=FINDING_STATUS_RESOLVED,
                    detected_at=datetime(2024, 1, 2, 9, 0, tzinfo=timezone.utc),
                ),
                _build_response(
                    identifier="f-7",
                    status=FINDING_STATUS_OPEN,
                    detected_at=datetime(2024, 1, 2, 12, 30, tzinfo=timezone.utc),
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
    responses: Iterable[FindingResponse],
    expected: dict[datetime, dict[str, int]],
) -> None:
    buckets = _build_timeline_buckets(responses)

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
    local_time = datetime(
        2024,
        1,
        1,
        23,
        30,
        tzinfo=timezone(timedelta(hours=-5)),
    )
    responses = [
        _build_response(
            identifier="offset",
            status=FINDING_STATUS_RESOLVED,
            detected_at=local_time,
        )
    ]

    buckets = _build_timeline_buckets(responses)

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
