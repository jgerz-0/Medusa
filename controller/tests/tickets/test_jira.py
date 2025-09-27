from __future__ import annotations

from typing import Tuple

import pytest
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from controller.db.models import AuditLog, Finding, FindingTicket, Scan, Target
from controller.main import Settings, _hash_json_payload

from ..conftest import InMemoryQueue
from ..test_api_contracts import auth_headers


def _create_finding(
    session_factory: sessionmaker[Session], *, is_authorized: bool = True
) -> str:
    with session_factory() as session:
        target = Target(
            name="Ticket Target",
            scope="ticketing.example.com",
            is_authorized=is_authorized,
        )
        session.add(target)
        session.flush()

        scan = Scan(
            target_id=target.id,
            scanner="nuclei",
            status="completed",
            initiated_by="ticket-test",
            parameters={"profile": "ticketing"},
        )
        session.add(scan)
        session.flush()

        evidence_payload = {"proof": "ticket"}
        finding = Finding(
            scan_id=scan.id,
            title="Synthetic ticketable finding",
            severity="high",
            cve_id=None,
            description="Ticket dispatch regression fixture",
            metadata_json={"vector": "GET /tickets"},
            evidence=evidence_payload,
            evidence_hash=_hash_json_payload(evidence_payload),
        )
        session.add(finding)
        session.commit()
        return str(finding.id)


def _provision_principal(
    client: TestClient, *, subject: str, roles: list[str]
) -> tuple[str, dict[str, str]]:
    response = client.post(
        "/principals",
        json={
            "subject": subject,
            "auth_method": "api_key",
            "roles": roles,
            "description": "ticketing-rbac",
        },
        headers=auth_headers(),
    )
    assert response.status_code == status.HTTP_201_CREATED, response.text
    payload = response.json()
    secret = payload["secret"]
    return secret, {"X-API-Key": secret}


@pytest.mark.parametrize(
    "roles,missing",
    [(["findings:read"], "ticket:create"), (["ticket:create"], "findings:read")],
)
def test_create_jira_ticket_enforces_rbac(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker[Session], Settings],
    roles: list[str],
    missing: str,
) -> None:
    client, queue, session_factory, _settings = api_client
    finding_id = _create_finding(session_factory)
    subject = f"analyst-missing-{missing.split(':')[0]}"
    _secret, headers = _provision_principal(client, subject=subject, roles=roles)

    response = client.post(
        "/tickets/jira",
        json={
            "finding_id": finding_id,
            "project_key": "SEC",
            "issue_type": "Bug",
            "summary": "Denied access should be audited",
        },
        headers=headers,
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert not queue.messages

    with session_factory() as session:
        audit_entries = (
            session.query(AuditLog)
            .filter(
                AuditLog.actor == subject,
                AuditLog.action == "access_denied",
            )
            .order_by(AuditLog.created_at.desc())
            .all()
        )
        assert audit_entries, "RBAC denials must be audited"
        snapshot = audit_entries[0].evidence_snapshot
        assert snapshot.get("resource_id") == "/tickets/jira"
        assert missing in snapshot.get("missing_roles", [])


def test_create_jira_ticket_rejects_invalid_project_key(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker[Session], Settings]
) -> None:
    client, queue, session_factory, _settings = api_client
    finding_id = _create_finding(session_factory)

    response = client.post(
        "/tickets/jira",
        json={
            "finding_id": finding_id,
            "project_key": "A",
            "issue_type": "Bug",
            "summary": "Invalid project key should fail",
        },
        headers=auth_headers(),
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert not queue.messages


def test_create_jira_ticket_rejects_finding_outside_scope(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker[Session], Settings]
) -> None:
    client, queue, session_factory, _settings = api_client
    finding_id = _create_finding(session_factory, is_authorized=False)

    response = client.post(
        "/tickets/jira",
        json={
            "finding_id": finding_id,
            "project_key": "SEC",
            "issue_type": "Bug",
            "summary": "Scope enforcement regression",
        },
        headers=auth_headers(),
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()["detail"].startswith("Target scope is not authorized")
    assert not queue.messages


def test_create_jira_ticket_records_hash_and_audit(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker[Session], Settings]
) -> None:
    client, queue, session_factory, settings = api_client
    finding_id = _create_finding(session_factory)

    response = client.post(
        "/tickets/jira",
        json={
            "finding_id": finding_id,
            "project_key": "sec",
            "issue_type": "Bug",
            "summary": "Queue Jira ticket for dispatcher",
            "description": "Ensure metadata normalization",
        },
        headers=auth_headers(),
    )

    assert response.status_code == status.HTTP_201_CREATED, response.text
    payload = response.json()
    ticket_id = payload["id"]

    assert queue.messages, "Ticket creation must enqueue a dispatcher job"
    channel, job_payload = queue.messages[-1]
    assert channel == settings.ticket_dispatch_queue_channel
    assert job_payload == {"ticket_id": ticket_id, "integration": "jira"}

    with session_factory() as session:
        record = session.get(FindingTicket, ticket_id)
        assert record is not None
        assert record.integration == "jira"
        assert record.payload_hash and len(record.payload_hash) == 64
        assert record.payload["project_key"] == "SEC"

        audit_entry = (
            session.query(AuditLog)
            .filter(
                AuditLog.action == "create_jira_ticket",
                AuditLog.finding_id == finding_id,
            )
            .order_by(AuditLog.created_at.desc())
            .first()
        )
        assert audit_entry is not None
        snapshot = audit_entry.evidence_snapshot
        assert snapshot.get("reference") == payload["reference"]
        assert snapshot.get("queue_channel") == settings.ticket_dispatch_queue_channel


def test_create_jira_ticket_surfaces_queue_failures(
    api_client: Tuple[TestClient, InMemoryQueue, sessionmaker[Session], Settings]
) -> None:
    client, queue, session_factory, _settings = api_client
    finding_id = _create_finding(session_factory)
    queue.raise_next = RuntimeError("redis unreachable")

    response = client.post(
        "/tickets/jira",
        json={
            "finding_id": finding_id,
            "project_key": "SEC",
            "issue_type": "Bug",
            "summary": "Queue failure should bubble up",
        },
        headers=auth_headers(),
    )

    assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    assert response.json()["detail"] == "Failed to enqueue Jira ticket for dispatch"
    assert not queue.messages

    with session_factory() as session:
        tickets = (
            session.query(FindingTicket)
            .filter(FindingTicket.finding_id == finding_id)
            .all()
        )
        assert tickets, "Ticket record should persist for dispatcher polling"
        assert not session.query(AuditLog).filter(
            AuditLog.action == "create_jira_ticket",
            AuditLog.finding_id == finding_id,
        ).count()
