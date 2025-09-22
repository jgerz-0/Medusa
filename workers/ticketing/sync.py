"""Background worker that reconciles ticket status with remote trackers."""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from sqlalchemy import or_, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from controller.db.models import FindingTicket
from controller.db.session import create_db_engine
from controller.main import Principal, record_audit_event

from .dispatcher import (
    GitHubClient,
    JiraClient,
    TicketSyncClient,
    TicketSyncError,
    TicketSyncResult,
)

LOG = logging.getLogger("medusa.workers.ticketing.sync")


@dataclass
class TicketSyncConfig:
    """Runtime configuration for the ticket synchronization worker."""

    database_url: str = field(
        default_factory=lambda: os.getenv(
            "DATABASE_URL", "postgresql+psycopg2://medusa:medusa@postgres:5432/medusa"
        )
    )
    poll_interval: int = field(
        default_factory=lambda: int(os.getenv("TICKETING_SYNC_POLL_INTERVAL", "60"))
    )
    batch_size: int = field(
        default_factory=lambda: int(os.getenv("TICKETING_SYNC_BATCH_SIZE", "25"))
    )
    min_sync_interval: int = field(
        default_factory=lambda: int(os.getenv("TICKETING_SYNC_MIN_INTERVAL", "300"))
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
    def load(cls) -> "TicketSyncConfig":
        config = cls()
        LOG.debug(
            "Loaded ticket sync config",
            extra={
                "poll_interval": config.poll_interval,
                "batch_size": config.batch_size,
                "min_sync_interval": config.min_sync_interval,
                "configured_integrations": {
                    "jira": bool(
                        config.jira_base_url and config.jira_email and config.jira_token
                    ),
                    "github": bool(config.github_token),
                },
            },
        )
        return config


class TicketSyncer:
    """Poll third-party trackers to keep ticket state authoritative."""

    def __init__(
        self,
        config: TicketSyncConfig,
        *,
        session_factory: Optional[sessionmaker] = None,
        clients: Optional[Dict[str, TicketSyncClient]] = None,
    ) -> None:
        self._config = config
        self._principal = Principal(
            subject="ticketing-sync@system", auth_method="service", roles=[]
        )
        if session_factory is None:
            engine: Engine = create_db_engine(config.database_url)
            self._session_factory = sessionmaker(
                bind=engine, expire_on_commit=False, class_=Session
            )
        else:
            self._session_factory = session_factory

        self._clients = clients or self._build_default_clients()

    def _build_default_clients(self) -> Dict[str, TicketSyncClient]:
        clients: Dict[str, TicketSyncClient] = {}
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
            except Exception:  # pragma: no cover - defensive logging
                LOG.exception("Failed to initialise Jira sync client")
        else:
            LOG.debug("Jira sync client disabled due to missing configuration")

        if self._config.github_token:
            try:
                clients["github"] = GitHubClient(
                    self._config.github_base_url,
                    self._config.github_token,
                    timeout=self._config.http_timeout,
                )
            except Exception:  # pragma: no cover - defensive logging
                LOG.exception("Failed to initialise GitHub sync client")
        else:
            LOG.debug("GitHub sync client disabled due to missing configuration")

        return clients

    def sync_forever(self) -> None:
        LOG.info(
            "Starting ticket synchronization loop",
            extra={
                "poll_interval": self._config.poll_interval,
                "batch_size": self._config.batch_size,
            },
        )
        while True:
            try:
                processed = self.sync_once()
                if processed == 0:
                    LOG.debug(
                        "No tickets required synchronization; sleeping",
                        extra={"poll_interval": self._config.poll_interval},
                    )
            except Exception:  # pragma: no cover - defensive logging
                LOG.exception("Ticket synchronization iteration failed")
            time.sleep(max(1, self._config.poll_interval))

    def sync_once(self) -> int:
        """Process a batch of tickets that require reconciliation."""

        if not self._clients:
            LOG.debug("Ticket synchronization disabled; no clients configured")
            return 0

        with self._session_factory() as session:
            now = datetime.now(timezone.utc)
            cutoff = now - timedelta(seconds=max(1, self._config.min_sync_interval))
            tickets = (
                session.execute(
                    select(FindingTicket)
                    .where(
                        FindingTicket.url.isnot(None),
                        FindingTicket.integration.in_(tuple(self._clients.keys())),
                        FindingTicket.status != "failed",
                        or_(
                            FindingTicket.synced_at.is_(None),
                            FindingTicket.synced_at < cutoff,
                        ),
                    )
                    .order_by(FindingTicket.updated_at.desc())
                    .limit(self._config.batch_size)
                )
                .scalars()
                .all()
            )

            processed = 0
            for ticket in tickets:
                processed += self._sync_ticket(session, ticket)

            return processed

    def _sync_ticket(self, session: Session, ticket: FindingTicket) -> int:
        client = self._clients.get(ticket.integration)
        if client is None:
            LOG.warning(
                "No synchronization client configured for integration",
                extra={"integration": ticket.integration, "ticket_id": ticket.id},
            )
            return 0

        try:
            result = client.sync(ticket)
        except TicketSyncError as error:
            self._handle_failure(session, ticket, error)
            return 1
        except Exception as exc:  # pragma: no cover - defensive logging
            LOG.exception(
                "Unexpected ticket synchronization failure",
                extra={"ticket_id": ticket.id},
            )
            self._handle_failure(
                session,
                ticket,
                TicketSyncError(str(exc), retryable=True),
            )
            return 1

        self._handle_success(session, ticket, result)
        return 1

    def _handle_success(
        self, session: Session, ticket: FindingTicket, result: TicketSyncResult
    ) -> None:
        now = datetime.now(timezone.utc)
        ticket.status = (result.status or ticket.status).strip() or ticket.status
        ticket.url = result.url or ticket.url
        ticket.remote_metadata = result.metadata or {}
        ticket.synced_at = now
        ticket.sync_error = None
        ticket.updated_at = now
        session.add(ticket)
        session.flush()

        metadata = {
            "ticket_id": ticket.id,
            "integration": ticket.integration,
            "status": ticket.status,
            "url": ticket.url,
        }

        record_audit_event(
            session,
            actor=self._principal,
            action="ticket_sync_success",
            resource_type="finding_ticket",
            resource_id=ticket.id,
            finding_id=ticket.finding_id,
            metadata=metadata,
        )
        session.refresh(ticket)

    def _handle_failure(
        self, session: Session, ticket: FindingTicket, error: TicketSyncError
    ) -> None:
        message = str(error).strip() or "unknown error"
        if len(message) > 250:
            message = message[:250]

        now = datetime.now(timezone.utc)
        ticket.synced_at = now
        ticket.sync_error = message
        ticket.updated_at = now
        session.add(ticket)
        session.flush()

        record_audit_event(
            session,
            actor=self._principal,
            action="ticket_sync_failed",
            resource_type="finding_ticket",
            resource_id=ticket.id,
            finding_id=ticket.finding_id,
            metadata={
                "ticket_id": ticket.id,
                "integration": ticket.integration,
                "error": message,
                "retryable": error.retryable,
            },
        )
        session.refresh(ticket)


def main() -> None:
    config = TicketSyncConfig.load()
    syncer = TicketSyncer(config)
    syncer.sync_forever()


if __name__ == "__main__":  # pragma: no cover - manual execution path
    main()
