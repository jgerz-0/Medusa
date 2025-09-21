import json
from dataclasses import dataclass
from typing import Dict

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from controller.db.models import Base, Finding, FindingTicket, Scan, Target
from controller.main import _hash_json_payload
from workers.ticketing.dispatcher import (
    GitHubClient,
    JiraClient,
    TicketDispatchError,
    TicketDispatchResult,
    TicketDispatcher,
    TicketDispatcherConfig,
)


@pytest.fixture()
def session_factory() -> sessionmaker[Session]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False, class_=Session)
    try:
        yield factory
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def _bootstrap_finding(session: Session) -> str:
    target = Target(name="Ticket Target", scope="tickets.example", is_authorized=True)
    session.add(target)
    session.flush()

    scan = Scan(
        target_id=target.id,
        scanner="nuclei",
        status="completed",
        initiated_by="tester",
        parameters={"profile": "unit"},
    )
    session.add(scan)
    session.flush()

    finding = Finding(
        scan_id=scan.id,
        title="Synthetic vulnerability",
        severity="high",
        cve_id=None,
        description="Triggered for ticket dispatcher testing",
        metadata_json={},
        evidence={"proof": "example"},
        evidence_hash="",
    )
    session.add(finding)
    session.commit()
    return finding.id


def test_dispatcher_updates_ticket_on_success(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        finding_id = _bootstrap_finding(session)
        ticket = FindingTicket(
            finding_id=finding_id,
            integration="jira",
            reference="SEC-1",
            url=None,
            status="queued",
            payload={
                "project_key": "SEC",
                "issue_type": "Bug",
                "summary": "Investigate synthetic vulnerability",
                "description": "Ensure deterministic workflow",
                "severity": "high",
                "finding_id": finding_id,
            },
            payload_hash="seed",
            created_by="tester",
        )
        session.add(ticket)
        session.commit()
        ticket_id = ticket.id

    class StubClient:
        def dispatch(self, queued_ticket: FindingTicket) -> TicketDispatchResult:
            assert (
                queued_ticket.payload["summary"]
                == "Investigate synthetic vulnerability"
            )
            return TicketDispatchResult(
                url="https://jira.example.com/browse/SEC-1",
                payload_hash="f" * 64,
            )

    config = TicketDispatcherConfig(database_url="sqlite+pysqlite:///:memory:")
    dispatcher = TicketDispatcher(
        config,
        session_factory=session_factory,
        clients={"jira": StubClient()},
    )

    processed = dispatcher.dispatch_once()
    assert processed == 1

    with session_factory() as session:
        updated = session.get(FindingTicket, ticket_id)
        assert updated is not None
        assert updated.status == "completed"
        assert updated.url == "https://jira.example.com/browse/SEC-1"
        assert updated.payload_hash == "f" * 64


def test_dispatcher_marks_ticket_failed_after_max_attempts(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        finding_id = _bootstrap_finding(session)
        ticket = FindingTicket(
            finding_id=finding_id,
            integration="github",
            reference="GH-1",
            url=None,
            status="queued",
            payload={
                "repository": "medusa/security",
                "title": "Dispatch failure path",
                "body": "Reproduce retry logic",
                "severity": "medium",
                "finding_id": finding_id,
            },
            payload_hash="seed",
            created_by="tester",
        )
        session.add(ticket)
        session.commit()
        ticket_id = ticket.id

    class FlakyClient:
        def __init__(self) -> None:
            self.calls = 0

        def dispatch(self, queued_ticket: FindingTicket) -> TicketDispatchResult:
            self.calls += 1
            raise TicketDispatchError("integration offline", retryable=True)

    config = TicketDispatcherConfig(
        database_url="sqlite+pysqlite:///:memory:", max_attempts=2
    )
    client = FlakyClient()
    dispatcher = TicketDispatcher(
        config,
        session_factory=session_factory,
        clients={"github": client},
    )

    dispatcher.dispatch_once()
    assert dispatcher.attempts_for(ticket_id) == 1
    assert client.calls == 1

    with session_factory() as session:
        interim = session.get(FindingTicket, ticket_id)
        assert interim is not None
        assert interim.status == "queued"

    dispatcher.dispatch_once()
    assert dispatcher.attempts_for(ticket_id) == 0
    assert client.calls == 2

    with session_factory() as session:
        failed = session.get(FindingTicket, ticket_id)
        assert failed is not None
        assert failed.status == "failed"


@dataclass
class _StubTicket:
    payload: Dict[str, str]
    finding_id: str = "finding-123"
    id: str = "ticket-123"


class _FakeResponse:
    def __init__(self, status_code: int, payload: Dict[str, str]) -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = json.dumps(payload)

    def json(self) -> Dict[str, str]:
        return self._payload


class _FakeSession:
    def __init__(self, response: _FakeResponse) -> None:
        self.response = response
        self.last_request: Dict[str, object] | None = None

    def post(
        self, url: str, json: Dict[str, object], timeout: int, **kwargs: object
    ) -> _FakeResponse:
        self.last_request = {
            "url": url,
            "json": json,
            "timeout": timeout,
            "kwargs": kwargs,
        }
        return self.response


def test_jira_client_dispatch_builds_expected_payload() -> None:
    response = _FakeResponse(
        201, {"key": "SEC-42", "self": "https://jira.example.com/rest/api/3/issue/100"}
    )
    fake_session = _FakeSession(response)
    client = JiraClient(
        base_url="https://jira.example.com",
        email="analyst@example.com",
        token="api-token",
        http=fake_session,  # type: ignore[arg-type]
        timeout=12,
    )

    ticket = _StubTicket(
        payload={
            "project_key": "SEC",
            "issue_type": "Bug",
            "summary": "Escalate",
            "description": "Deterministic reproduction",
            "severity": "critical",
        }
    )

    result = client.dispatch(ticket)  # type: ignore[arg-type]

    assert fake_session.last_request is not None
    assert (
        fake_session.last_request["url"] == "https://jira.example.com/rest/api/3/issue"
    )
    request_payload = fake_session.last_request["json"]
    assert isinstance(request_payload, dict)
    assert request_payload["fields"]["project"]["key"] == "SEC"
    assert "medusa" in request_payload["fields"]["labels"]
    assert result.url == "https://jira.example.com/browse/SEC-42"
    assert result.payload_hash == _hash_json_payload(request_payload)


def test_github_client_dispatch_returns_issue_url() -> None:
    response = _FakeResponse(
        201, {"html_url": "https://github.com/medusa/security/issues/1"}
    )
    fake_session = _FakeSession(response)
    client = GitHubClient(
        base_url="https://api.github.com",
        token="ghp_example",
        http=fake_session,  # type: ignore[arg-type]
        timeout=8,
    )

    ticket = _StubTicket(
        payload={
            "repository": "medusa/security",
            "title": "Create tracking issue",
            "body": "Ensure audit trail",
            "severity": "high",
        }
    )

    result = client.dispatch(ticket)  # type: ignore[arg-type]

    assert fake_session.last_request is not None
    assert (
        fake_session.last_request["url"]
        == "https://api.github.com/repos/medusa/security/issues"
    )
    request_payload = fake_session.last_request["json"]
    assert isinstance(request_payload, dict)
    assert "medusa" in request_payload["labels"]
    assert result.url == "https://github.com/medusa/security/issues/1"
    assert result.payload_hash == _hash_json_payload(request_payload)
