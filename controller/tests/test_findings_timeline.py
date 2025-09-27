"""Tests for the findings timeline aggregation helpers.

These tests build synthetic ``FindingResponse`` records and ensure that
``_build_timeline_buckets`` groups and counts them correctly.  The
scenarios focus on the security workflow statuses our controller exposes.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterable

import pytest

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
