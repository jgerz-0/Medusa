"""Dispatcher that propagates queued finding tickets to external trackers."""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Protocol

from sqlalchemy import select, update
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

try:  # pragma: no cover - optional dependency during static analysis
    import requests
    from requests import Response
    from requests.auth import HTTPBasicAuth
    from requests.exceptions import RequestException
except ImportError:  # pragma: no cover - handled defensively at runtime
    requests = None  # type: ignore

    class Response:  # type: ignore
        ...

    class HTTPBasicAuth:  # type: ignore
        def __init__(self, *_: Any, **__: Any) -> None:
            raise RuntimeError("requests is required for ticket dispatch")

    class RequestException(Exception): ...


from controller.db.models import FindingTicket
from controller.db.session import create_db_engine
from controller.main import _hash_json_payload

LOG = logging.getLogger("medusa.workers.ticketing")


@dataclass
class TicketDispatcherConfig:
    """Runtime configuration for the ticket dispatcher."""

    database_url: str = field(
        default_factory=lambda: os.getenv(
            "DATABASE_URL", "postgresql+psycopg2://medusa:medusa@postgres:5432/medusa"
        )
    )
    poll_interval: int = field(
        default_factory=lambda: int(os.getenv("TICKETING_POLL_INTERVAL", "5"))
    )
    batch_size: int = field(
        default_factory=lambda: int(os.getenv("TICKETING_BATCH_SIZE", "10"))
    )
    max_attempts: int = field(
        default_factory=lambda: int(os.getenv("TICKETING_MAX_ATTEMPTS", "3"))
    )
    http_timeout: int = field(
        default_factory=lambda: int(os.getenv("TICKETING_HTTP_TIMEOUT", "10"))
    )
    jira_base_url: Optional[str] = field(
        default_factory=lambda: os.getenv("TICKETING_JIRA_BASE_URL")
        or os.getenv("MEDUSA_TICKETING_JIRA_BASE_URL")
    )
    jira_email: Optional[str] = field(
        default_factory=lambda: os.getenv("TICKETING_JIRA_USER")
        or os.getenv("TICKETING_JIRA_EMAIL")
    )
    jira_token: Optional[str] = field(
        default_factory=lambda: os.getenv("TICKETING_JIRA_API_TOKEN")
    )
    github_base_url: str = field(
        default_factory=lambda: os.getenv(
            "TICKETING_GITHUB_BASE_URL", "https://api.github.com"
        )
    )
    github_token: Optional[str] = field(
        default_factory=lambda: os.getenv("TICKETING_GITHUB_TOKEN")
    )

    @classmethod
    def load(cls) -> "TicketDispatcherConfig":
        config = cls()
        LOG.debug(
            "Loaded ticket dispatcher config",
            extra={
                "poll_interval": config.poll_interval,
                "batch_size": config.batch_size,
                "max_attempts": config.max_attempts,
                "configured_integrations": {
                    "jira": bool(
                        config.jira_base_url and config.jira_email and config.jira_token
                    ),
                    "github": bool(config.github_token),
                },
            },
        )
        return config


@dataclass
class TicketDispatchResult:
    """Result metadata emitted by an integration client."""

    url: str
    payload_hash: str


class TicketDispatchError(Exception):
    """Raised when an integration call fails."""

    def __init__(self, message: str, *, retryable: bool = True) -> None:
        super().__init__(message)
        self.retryable = retryable


class TicketClient(Protocol):
    """Integration client contract used by the dispatcher."""

    def dispatch(self, ticket: FindingTicket) -> TicketDispatchResult: ...


class JiraClient:
    """Create Jira issues from queued finding tickets."""

    def __init__(
        self,
        base_url: str,
        email: str,
        token: str,
        *,
        http: Optional[requests.Session] = None,
        timeout: int = 10,
    ) -> None:
        if requests is None:  # pragma: no cover - runtime guard
            raise RuntimeError(
                "requests package is required to run the ticket dispatcher"
            )
        if not base_url or not email or not token:
            raise ValueError("Jira client requires base URL, user email, and API token")

        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._http = http or requests.Session()
        self._auth = HTTPBasicAuth(email, token)

    def dispatch(self, ticket: FindingTicket) -> TicketDispatchResult:
        payload = ticket.payload or {}
        project_key = str(payload.get("project_key") or "").strip().upper()
        issue_type = str(payload.get("issue_type") or "Task").strip()
        summary = str(payload.get("summary") or "").strip()
        description = str(payload.get("description") or "").strip()
        severity = str(payload.get("severity") or "medium").lower()
        cvss = payload.get("cvss")
        finding_id = str(payload.get("finding_id") or ticket.finding_id)

        if not project_key or not summary:
            raise TicketDispatchError(
                "Queued Jira ticket payload is missing required fields", retryable=False
            )

        fields: Dict[str, Any] = {
            "project": {"key": project_key},
            "issuetype": {"name": issue_type or "Task"},
            "summary": summary,
            "description": description,
            "labels": ["medusa", f"severity:{severity}"],
        }
        if severity:
            fields["priority"] = {"name": severity.upper()}
        if finding_id:
            fields.setdefault("labels", []).append(f"finding:{finding_id}")
        if cvss is not None:
            fields.setdefault("labels", []).append(f"cvss:{cvss}")

        request_body = {"fields": fields}
        url = f"{self._base_url}/rest/api/3/issue"

        try:
            response = self._http.post(
                url,
                json=request_body,
                timeout=self._timeout,
                auth=self._auth,
                headers={"Content-Type": "application/json"},
            )
        except RequestException as exc:  # pragma: no cover - network dependent
            raise TicketDispatchError(f"Jira request failed: {exc}") from exc

        if response.status_code >= 500:
            raise TicketDispatchError(
                f"Jira API unavailable (status {response.status_code})",
                retryable=True,
            )
        if response.status_code >= 400:
            raise TicketDispatchError(
                f"Jira API rejected payload (status {response.status_code})",
                retryable=False,
            )

        try:
            payload_json = response.json()
        except json.JSONDecodeError as exc:
            raise TicketDispatchError(
                "Invalid Jira response payload", retryable=True
            ) from exc

        issue_key = payload_json.get("key")
        browse_url = payload_json.get("self")
        if issue_key:
            browse_url = f"{self._base_url}/browse/{issue_key}"
        if not browse_url:
            raise TicketDispatchError(
                "Jira response missing issue locator", retryable=False
            )

        payload_hash = _hash_json_payload(request_body)
        return TicketDispatchResult(url=browse_url, payload_hash=payload_hash)


class GitHubClient:
    """Create GitHub issues for queued findings."""

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        http: Optional[requests.Session] = None,
        timeout: int = 10,
    ) -> None:
        if requests is None:  # pragma: no cover - runtime guard
            raise RuntimeError(
                "requests package is required to run the ticket dispatcher"
            )
        if not token:
            raise ValueError("GitHub client requires a personal access token")

        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._http = http or requests.Session()
        self._token = token

    def dispatch(self, ticket: FindingTicket) -> TicketDispatchResult:
        payload = ticket.payload or {}
        repository = str(payload.get("repository") or "").strip()
        title = str(payload.get("title") or "").strip()
        body = str(payload.get("body") or "").strip()
        severity = str(payload.get("severity") or "medium").lower()
        finding_id = str(payload.get("finding_id") or ticket.finding_id)

        if not repository or not title:
            raise TicketDispatchError(
                "Queued GitHub ticket payload is missing required fields",
                retryable=False,
            )

        api_url = f"{self._base_url}/repos/{repository}/issues"
        labels = ["medusa"]
        if severity:
            labels.append(f"severity:{severity}")
        if finding_id:
            labels.append(f"finding:{finding_id}")

        request_body: Dict[str, Any] = {
            "title": title,
            "body": body,
            "labels": labels,
        }

        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._token}",
            "User-Agent": "medusa-ticketing-worker",
        }

        try:
            response = self._http.post(
                api_url,
                json=request_body,
                headers=headers,
                timeout=self._timeout,
            )
        except RequestException as exc:  # pragma: no cover - network dependent
            raise TicketDispatchError(f"GitHub request failed: {exc}") from exc

        if response.status_code >= 500:
            raise TicketDispatchError(
                f"GitHub API unavailable (status {response.status_code})",
                retryable=True,
            )
        if response.status_code >= 400:
            raise TicketDispatchError(
                f"GitHub API rejected payload (status {response.status_code})",
                retryable=False,
            )

        try:
            payload_json = response.json()
        except json.JSONDecodeError as exc:
            raise TicketDispatchError(
                "Invalid GitHub response payload", retryable=True
            ) from exc

        issue_url = payload_json.get("html_url") or payload_json.get("url")
        if not issue_url:
            raise TicketDispatchError(
                "GitHub response missing issue URL", retryable=False
            )

        payload_hash = _hash_json_payload(request_body)
        return TicketDispatchResult(url=issue_url, payload_hash=payload_hash)


class TicketDispatcher:
    """Worker that propagates queued tickets to third-party trackers."""

    def __init__(
        self,
        config: TicketDispatcherConfig,
        *,
        session_factory: Optional[sessionmaker] = None,
        clients: Optional[Dict[str, TicketClient]] = None,
    ) -> None:
        self._config = config
        self._attempts: Dict[str, int] = {}
        if session_factory is None:
            engine: Engine = create_db_engine(config.database_url)
            self._session_factory = sessionmaker(
                bind=engine, expire_on_commit=False, class_=Session
            )
        else:
            self._session_factory = session_factory

        self._clients = clients or self._build_default_clients()

    def _build_default_clients(self) -> Dict[str, TicketClient]:
        clients: Dict[str, TicketClient] = {}
        if (
            self._config.jira_base_url
            and self._config.jira_email
            and self._config.jira_token
        ):
            try:
                clients["jira"] = JiraClient(
                    self._config.jira_base_url,
                    self._config.jira_email,
                    self._config.jira_token,
                    timeout=self._config.http_timeout,
                )
            except Exception:
                LOG.exception("Failed to initialise Jira client")
        else:
            LOG.debug("Jira client disabled due to missing configuration")
        if self._config.github_token:
            try:
                clients["github"] = GitHubClient(
                    self._config.github_base_url,
                    self._config.github_token,
                    timeout=self._config.http_timeout,
                )
            except Exception:
                LOG.exception("Failed to initialise GitHub client")
        else:
            LOG.debug("GitHub client disabled due to missing configuration")
        return clients

    def run_forever(self) -> None:
        LOG.info(
            "Starting ticket dispatcher loop",
            extra={
                "poll_interval": self._config.poll_interval,
                "batch_size": self._config.batch_size,
            },
        )
        while True:
            try:
                processed = self.dispatch_once()
                if processed == 0:
                    LOG.debug(
                        "No queued tickets discovered; sleeping",
                        extra={"poll_interval": self._config.poll_interval},
                    )
            except (
                Exception
            ):  # pragma: no cover - defensive logging for runtime crashes
                LOG.exception("Ticket dispatcher iteration failed")
            time.sleep(max(1, self._config.poll_interval))

    def dispatch_once(self) -> int:
        """Process a single batch of queued tickets."""

        with self._session_factory() as session:
            tickets = (
                session.execute(
                    select(FindingTicket)
                    .where(FindingTicket.status == "queued")
                    .order_by(FindingTicket.created_at)
                    .limit(self._config.batch_size)
                )
                .scalars()
                .all()
            )

            processed = 0
            for ticket in tickets:
                processed += self._handle_ticket(session, ticket)

            session.commit()
            return processed

    def _handle_ticket(self, session: Session, ticket: FindingTicket) -> int:
        client = self._clients.get(ticket.integration)
        if client is None:
            LOG.warning(
                "No ticket client configured for integration",
                extra={"integration": ticket.integration},
            )
            self._mark_failed(session, ticket.id)
            return 0

        try:
            result = client.dispatch(ticket)
        except TicketDispatchError as error:
            self._handle_failure(session, ticket.id, error)
            return 0
        except Exception as exc:  # pragma: no cover - defensive guard
            LOG.exception(
                "Unexpected ticket dispatch failure", extra={"ticket_id": ticket.id}
            )
            self._handle_failure(
                session,
                ticket.id,
                TicketDispatchError(str(exc), retryable=True),
            )
            return 0

        self._handle_success(session, ticket.id, result)
        return 1

    def _handle_success(
        self, session: Session, ticket_id: str, result: TicketDispatchResult
    ) -> None:
        self._attempts.pop(ticket_id, None)
        session.execute(
            update(FindingTicket)
            .where(FindingTicket.id == ticket_id)
            .values(
                status="completed",
                url=result.url,
                payload_hash=result.payload_hash,
                updated_at=datetime.now(timezone.utc),
            )
        )

    def _handle_failure(
        self, session: Session, ticket_id: str, error: TicketDispatchError
    ) -> None:
        attempts = self._attempts.get(ticket_id, 0) + 1
        terminal = attempts >= self._config.max_attempts
        if not error.retryable or terminal:
            LOG.warning(
                "Ticket dispatch failed permanently",
                extra={
                    "ticket_id": ticket_id,
                    "error": str(error),
                    "attempts": attempts,
                },
            )
            self._attempts.pop(ticket_id, None)
            self._mark_failed(session, ticket_id)
            return

        self._attempts[ticket_id] = attempts
        LOG.info(
            "Ticket dispatch failed; will retry",
            extra={"ticket_id": ticket_id, "error": str(error), "attempts": attempts},
        )

    def _mark_failed(self, session: Session, ticket_id: str) -> None:
        session.execute(
            update(FindingTicket)
            .where(FindingTicket.id == ticket_id)
            .values(status="failed", updated_at=datetime.now(timezone.utc))
        )

    def attempts_for(self, ticket_id: str) -> int:
        """Expose retry counters for observability and tests."""

        return self._attempts.get(ticket_id, 0)


def main() -> None:
    config = TicketDispatcherConfig.load()
    dispatcher = TicketDispatcher(config)
    dispatcher.run_forever()


if __name__ == "__main__":  # pragma: no cover - manual execution path
    main()
