from __future__ import annotations

from typing import Tuple

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from controller.db.models import Finding, FindingTicket, Scan, Target
from controller.main import Settings
from workers.ticketing.dispatcher import (
    TicketDispatchError,
    TicketDispatchResult,
    TicketDispatcher,
    TicketDispatcherConfig,
)

from .test_api_contracts import auth_headers


def _create_finding(session_factory: sessionmaker[Session]) -> str:
    with session_factory() as session:
        target = Target(
            name="Integration Target", scope="integration.example", is_authorized=True
        )
        session.add(target)
        session.flush()

        scan = Scan(
            target_id=target.id,
            scanner="nuclei",
            status="completed",
            initiated_by="integration-test",
            parameters={"profile": "integration"},
        )
        session.add(scan)
        session.flush()

        finding = Finding(
            scan_id=scan.id,
            title="Integration finding",
            severity="medium",
            cve_id=None,
            description="Integration dispatch test",
            metadata_json={},
            evidence={"proof": "integration"},
            evidence_hash="",
        )
        session.add(finding)
        session.commit()
        return finding.id


@pytest.mark.integration()
def test_ticket_dispatcher_processes_jira_ticket(
    api_client: Tuple[TestClient, object, sessionmaker[Session], Settings],
) -> None:
    client, _queue, session_factory, settings = api_client
    finding_id = _create_finding(session_factory)

    response = client.post(
        "/tickets/jira",
        json={
            "finding_id": finding_id,
            "project_key": "SEC",
            "issue_type": "Bug",
            "summary": "Synthetic integration ticket",
            "description": "Ensure dispatcher updates records",
        },
        headers=auth_headers(),
    )
    assert response.status_code == 201, response.text
    payload = response.json()
    ticket_id = payload["id"]

    class StubClient:
        def __init__(self) -> None:
            self.calls = 0

        def dispatch(self, queued_ticket: FindingTicket) -> TicketDispatchResult:
            self.calls += 1
            assert queued_ticket.payload["summary"] == "Synthetic integration ticket"
            return TicketDispatchResult(
                url="https://jira.integration.local/browse/SEC-100",
                payload_hash="9" * 64,
            )

    dispatcher = TicketDispatcher(
        TicketDispatcherConfig(database_url=settings.database_url),
        session_factory=session_factory,
        clients={"jira": StubClient()},
    )

    processed = dispatcher.dispatch_once()
    assert processed == 1

    with session_factory() as session:
        record = session.get(FindingTicket, ticket_id)
        assert record is not None
        assert record.status == "completed"
        assert record.url == "https://jira.integration.local/browse/SEC-100"
        assert record.payload_hash == "9" * 64


@pytest.mark.integration()
def test_ticket_dispatcher_marks_failed_after_retries(
    api_client: Tuple[TestClient, object, sessionmaker[Session], Settings],
) -> None:
    client, _queue, session_factory, settings = api_client
    finding_id = _create_finding(session_factory)

    response = client.post(
        "/tickets/github",
        json={
            "finding_id": finding_id,
            "repository": "medusa/security",
            "title": "Integration retry flow",
            "body": "Validate retry exhaustion",
        },
        headers=auth_headers(),
    )
    assert response.status_code == 201, response.text
    ticket_id = response.json()["id"]

    class UnstableClient:
        def __init__(self) -> None:
            self.calls = 0

        def dispatch(self, queued_ticket: FindingTicket) -> TicketDispatchResult:
            self.calls += 1
            raise TicketDispatchError("remote failure", retryable=True)

    client_impl = UnstableClient()
    dispatcher = TicketDispatcher(
        TicketDispatcherConfig(database_url=settings.database_url, max_attempts=2),
        session_factory=session_factory,
        clients={"github": client_impl},
    )

    dispatcher.dispatch_once()
    assert dispatcher.attempts_for(ticket_id) == 1

    with session_factory() as session:
        interim = session.get(FindingTicket, ticket_id)
        assert interim is not None
        assert interim.status == "queued"

    dispatcher.dispatch_once()
    assert dispatcher.attempts_for(ticket_id) == 0

    with session_factory() as session:
        failed = session.get(FindingTicket, ticket_id)
        assert failed is not None
        assert failed.status == "failed"
