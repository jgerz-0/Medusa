from typing import Dict, Tuple

import pytest
from fastapi import status
from fastapi.testclient import TestClient
from requests import Response
from sqlalchemy.orm import sessionmaker

from controller.db.models import AuditLog, Finding, ReportExport, Scan, Target
from controller.main import _hash_json_payload
from controller.storage import (
    ReportStorageError,
    ReportStorageReference,
)
from controller.tests.conftest import InMemoryReportStorage


def _create_finding(
    session_factory: sessionmaker,
    *,
    severity: str = "medium",
    status_value: str = "pending_validation",
    title: str = "Synthetic finding",
) -> str:
    """Persist a minimal target/scan/finding triple for report exports."""

    with session_factory() as session:
        target = Target(name="Report Target", scope="reports.example", is_authorized=True)
        session.add(target)
        session.flush()

        scan = Scan(
            target_id=target.id,
            scanner="nuclei",
            initiated_by="reporter",
            status="completed",
            parameters={"profile": "regression"},
        )
        session.add(scan)
        session.flush()

        evidence_payload = {"proof": "GET /?id=1"}
        finding = Finding(
            scan_id=scan.id,
            title=title,
            severity=severity,
            cve_id="CVE-2099-0001",
            description="Regression finding used for export coverage.",
            metadata_json={"scanner": "nuclei"},
            evidence=evidence_payload,
            evidence_hash=_hash_json_payload(evidence_payload),
            status=status_value,
            tags=["regression"],
        )
        session.add(finding)
        session.commit()
        return str(finding.id)


def _export_report(
    client: TestClient,
    *,
    format_: str,
    finding_ids: Tuple[str, ...],
) -> Response:
    response = client.post(
        "/reports/export",
        json={"format": format_, "finding_ids": list(finding_ids)},
        headers={"X-API-Key": "test-key"},
    )
    assert response.status_code == status.HTTP_200_OK
    return response


def test_export_report_html_success_records_audit(
    api_client: Tuple[TestClient, object, sessionmaker, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _queue, session_factory, _settings = api_client
    finding_id = _create_finding(session_factory)

    captured: Dict[str, object] = {}

    def fake_store(
        self: InMemoryReportStorage,
        *,
        report_id: str,
        data: bytes,
        content_type: str,
        extension: str,
    ) -> ReportStorageReference:
        captured["report_id"] = report_id
        captured["data"] = data
        captured["content_type"] = content_type
        captured["extension"] = extension
        return ReportStorageReference(
            bucket="unit-test-bucket",
            key=f"exports/{report_id}.{extension}",
            content_type=content_type,
        )

    monkeypatch.setattr(InMemoryReportStorage, "store", fake_store)

    response = _export_report(client, format_="html", finding_ids=(finding_id,))
    payload = response.json()

    assert payload["format"] == "html"
    assert payload["finding_count"] == 1
    assert payload["storage"]["bucket"] == "unit-test-bucket"
    assert payload["storage"]["key"].endswith(".html")
    assert payload["metadata"]["severity_counts"]["medium"] == 1
    assert payload["metadata"]["status_counts"]["pending_validation"] == 1

    assert captured["extension"] == "html"
    assert captured["content_type"] == "text/html; charset=utf-8"
    assert captured["report_id"] == payload["report_id"]
    assert captured["data"].startswith(b"<!DOCTYPE html>")

    with session_factory() as session:
        export_records = session.query(ReportExport).all()
        assert len(export_records) == 1
        record = export_records[0]
        assert record.id == payload["report_id"]
        assert record.format == "html"
        assert record.metadata_json["severity_counts"]["medium"] == 1

        audit_entries = session.query(AuditLog).all()
        assert len(audit_entries) == 1
        audit_entry = audit_entries[0]
        assert audit_entry.action == "export_report"
        assert audit_entry.actor == "bootstrap-admin"
        assert audit_entry.evidence_snapshot["checksum"] == payload["checksum"]


def test_export_report_pdf_and_download_workflow(
    api_client: Tuple[TestClient, object, sessionmaker, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _queue, session_factory, _settings = api_client
    primary_finding = _create_finding(
        session_factory,
        severity="high",
        status_value="open",
        title="High severity finding",
    )
    secondary_finding = _create_finding(
        session_factory,
        severity="low",
        status_value="resolved",
        title="Low severity finding",
    )

    captured: Dict[str, object] = {}

    def fake_store(
        self: InMemoryReportStorage,
        *,
        report_id: str,
        data: bytes,
        content_type: str,
        extension: str,
    ) -> ReportStorageReference:
        captured["data"] = data
        captured["reference"] = ReportStorageReference(
            bucket="unit-test-bucket",
            key=f"exports/{report_id}.{extension}",
            content_type=content_type,
        )
        return captured["reference"]

    def fake_fetch(
        self: InMemoryReportStorage, reference: ReportStorageReference
    ) -> bytes:
        captured["fetched_reference"] = reference
        return captured["data"]

    monkeypatch.setattr(InMemoryReportStorage, "store", fake_store)
    monkeypatch.setattr(InMemoryReportStorage, "fetch", fake_fetch)

    response = _export_report(
        client,
        format_="pdf",
        finding_ids=(primary_finding, secondary_finding),
    )
    payload = response.json()

    assert payload["format"] == "pdf"
    assert payload["finding_count"] == 2
    assert payload["storage"]["key"].endswith(".pdf")
    assert payload["metadata"]["severity_counts"] == {"high": 1, "low": 1}
    assert payload["metadata"]["status_counts"] == {"open": 1, "resolved": 1}

    report_id = payload["report_id"]
    download = client.get(
        f"/reports/{report_id}",
        headers={"X-API-Key": "test-key"},
    )
    assert download.status_code == status.HTTP_200_OK
    assert download.headers["Content-Type"] == "application/pdf"
    assert download.headers["X-Report-Checksum"] == payload["checksum"]
    assert download.content == captured["data"]
    assert captured["fetched_reference"] == captured["reference"]

    listing = client.get(
        "/reports/export",
        params={"findingId": primary_finding},
        headers={"X-API-Key": "test-key"},
    )
    assert listing.status_code == status.HTTP_200_OK
    items = listing.json()["data"]
    assert len(items) == 1
    assert items[0]["report_id"] == report_id

    empty_listing = client.get(
        "/reports/export",
        params={"findingId": "non-existent"},
        headers={"X-API-Key": "test-key"},
    )
    assert empty_listing.status_code == status.HTTP_200_OK
    assert empty_listing.json()["data"] == []

    with session_factory() as session:
        audit_actions = [
            entry.action
            for entry in session.query(AuditLog).order_by(AuditLog.created_at.asc()).all()
        ]
        assert audit_actions == ["export_report", "download_report"]

        download_entry = (
            session.query(AuditLog)
            .filter(AuditLog.action == "download_report")
            .order_by(AuditLog.created_at.desc())
            .one()
        )
        assert download_entry.evidence_snapshot["format"] == "pdf"
        assert download_entry.evidence_snapshot["report_id"] == report_id


def test_export_report_storage_failure_returns_502(
    api_client: Tuple[TestClient, object, sessionmaker, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _queue, session_factory, _settings = api_client
    finding_id = _create_finding(session_factory)

    def failing_store(
        self: InMemoryReportStorage,
        *,
        report_id: str,
        data: bytes,
        content_type: str,
        extension: str,
    ) -> ReportStorageReference:
        raise ReportStorageError("object storage unavailable")

    monkeypatch.setattr(InMemoryReportStorage, "store", failing_store)

    response = client.post(
        "/reports/export",
        json={"format": "html", "finding_ids": [finding_id]},
        headers={"X-API-Key": "test-key"},
    )
    assert response.status_code == status.HTTP_502_BAD_GATEWAY
    assert response.json()["detail"] == "Unable to persist report export"

    with session_factory() as session:
        assert session.query(ReportExport).count() == 0
        assert session.query(AuditLog).count() == 0


def test_download_report_checksum_mismatch_returns_500(
    api_client: Tuple[TestClient, object, sessionmaker, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _queue, session_factory, _settings = api_client
    finding_id = _create_finding(session_factory)

    def fake_fetch(
        self: InMemoryReportStorage, reference: ReportStorageReference
    ) -> bytes:
        return b"tampered-data"

    monkeypatch.setattr(InMemoryReportStorage, "fetch", fake_fetch)

    response = _export_report(client, format_="html", finding_ids=(finding_id,))
    payload = response.json()

    download = client.get(
        f"/reports/{payload['report_id']}",
        headers={"X-API-Key": "test-key"},
    )
    assert download.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert download.json()["detail"] == "Stored report failed integrity verification"

    with session_factory() as session:
        audit_actions = [entry.action for entry in session.query(AuditLog).all()]
        # Only the export should have been recorded because the download failed checksum validation.
        assert audit_actions == ["export_report"]
