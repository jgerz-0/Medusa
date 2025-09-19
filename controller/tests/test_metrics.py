from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Tuple

import pytest
from fastapi.testclient import TestClient

from controller.tests.test_api_contracts import (
    auth_headers,
    enrichment_headers,
    _persist_sample_finding,
)


def _read_metric_value(metrics_text: str, metric_name: str, labels: Dict[str, str]) -> float:
    for line in metrics_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, parsed_labels, value = _parse_metric_line(line)
        if name != metric_name:
            continue
        if all(parsed_labels.get(k) == v for k, v in labels.items()):
            return value
    return 0.0


def _parse_metric_line(line: str) -> Tuple[str, Dict[str, str], float]:
    name_and_labels, value_str = line.rsplit(" ", 1)
    labels = {}
    if "{" in name_and_labels:
        name, label_block = name_and_labels.split("{", 1)
        label_str = label_block.rstrip("}")
        for part in label_str.split(","):
            if not part:
                continue
            key, raw_value = part.split("=", 1)
            labels[key] = raw_value.strip('"')
    else:
        name = name_and_labels
    value = float(value_str.strip())
    return name, labels, value


def test_metrics_endpoint_is_public(
    api_client: Tuple[TestClient, object, object, object]
) -> None:
    client, _queue, _session_factory, _settings = api_client

    response = client.get("/metrics")

    assert response.status_code == 200
    assert "medusa_controller_http_requests_total" in response.text


def test_metrics_record_scan_jobs_and_audit_events(
    api_client: Tuple[TestClient, object, object, object]
) -> None:
    client, _queue, _session_factory, _settings = api_client

    create_target_response = client.post(
        "/targets",
        json={"name": "Metrics API", "scope": "metrics.example"},
        headers=auth_headers(),
    )
    assert create_target_response.status_code == 201, create_target_response.text
    target_id = create_target_response.json()["id"]

    baseline_metrics = client.get("/metrics")
    assert baseline_metrics.status_code == 200

    baseline_jobs = _read_metric_value(
        baseline_metrics.text,
        "medusa_jobs_enqueued_total",
        {"job_type": "nuclei"},
    )
    baseline_audits = _read_metric_value(
        baseline_metrics.text,
        "medusa_audit_events_total",
        {"action": "enqueue_scan"},
    )

    scan_response = client.post(
        "/scan",
        json={
            "target_id": target_id,
            "scanner": "nuclei",
            "parameters": {"profile": "web-baseline"},
        },
        headers=auth_headers(),
    )
    assert scan_response.status_code == 202, scan_response.text

    updated_metrics = client.get("/metrics")
    assert updated_metrics.status_code == 200

    updated_jobs = _read_metric_value(
        updated_metrics.text,
        "medusa_jobs_enqueued_total",
        {"job_type": "nuclei"},
    )
    updated_audits = _read_metric_value(
        updated_metrics.text,
        "medusa_audit_events_total",
        {"action": "enqueue_scan"},
    )

    assert pytest.approx(updated_jobs) == baseline_jobs + 1
    assert pytest.approx(updated_audits) == baseline_audits + 1


def test_metrics_track_enrichment_callback(
    api_client: Tuple[TestClient, object, object, object]
) -> None:
    client, _queue, session_factory, _settings = api_client
    finding_id, _scan_id = _persist_sample_finding(session_factory)

    baseline_metrics = client.get("/metrics")
    assert baseline_metrics.status_code == 200

    baseline_callbacks = _read_metric_value(
        baseline_metrics.text,
        "medusa_worker_callbacks_total",
        {"worker": "enrichment"},
    )
    baseline_items = _read_metric_value(
        baseline_metrics.text,
        "medusa_worker_callback_items_total",
        {"worker": "enrichment"},
    )

    payload = {
        "job_id": "metrics-job-1",
        "finding_id": finding_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "advisories": [
            {
                "source": "nvd",
                "identifier": "CVE-2024-0001",
                "summary": "Metrics enrichment", 
                "severity": "MEDIUM",
                "cvss_score": 5.0,
                "published": datetime.now(timezone.utc).isoformat(),
                "modified": datetime.now(timezone.utc).isoformat(),
                "references": ["https://example.com/cve"],
                "raw": {"id": "CVE-2024-0001"},
            }
        ],
        "errors": {},
    }

    callback_response = client.post(
        "/internal/enrich/callback",
        json=payload,
        headers=enrichment_headers(),
    )
    assert callback_response.status_code == 204, callback_response.text

    updated_metrics = client.get("/metrics")
    assert updated_metrics.status_code == 200

    updated_callbacks = _read_metric_value(
        updated_metrics.text,
        "medusa_worker_callbacks_total",
        {"worker": "enrichment"},
    )
    updated_items = _read_metric_value(
        updated_metrics.text,
        "medusa_worker_callback_items_total",
        {"worker": "enrichment"},
    )

    assert pytest.approx(updated_callbacks) == baseline_callbacks + 1
    assert pytest.approx(updated_items) == baseline_items + 1
