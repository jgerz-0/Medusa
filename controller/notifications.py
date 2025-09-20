"""Notification helpers for Medusa controller events."""

from __future__ import annotations

import json
import logging
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Dict, Iterable, Optional, Sequence
from urllib import error as urllib_error
from urllib import request as urllib_request

LOGGER = logging.getLogger("medusa.notifications")


@dataclass
class CriticalFindingNotification:
    """Structured payload describing a validated critical finding."""

    finding_id: str
    title: str
    severity: str
    target: Optional[str]
    scanner: Optional[str]
    validation_status: str
    validated_at: Optional[str]
    evidence_hash: str
    metadata: Dict[str, str]


@dataclass
class AnomalyNotification:
    """Structured payload for audit-log driven anomaly detection."""

    anomaly_type: str
    actor: str
    source: str
    count: int
    window_seconds: int
    first_seen: str
    last_seen: str
    metadata: Dict[str, object]


class NotificationService:
    """Dispatch Slack and email notifications for critical findings."""

    def __init__(
        self,
        *,
        slack_webhook: Optional[str],
        email_sender: Optional[str],
        email_recipients: Sequence[str],
        smtp_host: Optional[str],
        smtp_port: Optional[int],
        smtp_username: Optional[str],
        smtp_password: Optional[str],
        smtp_use_tls: bool,
    ) -> None:
        self._slack_webhook = slack_webhook
        self._email_sender = email_sender
        self._email_recipients = [recipient for recipient in email_recipients if recipient]
        self._smtp_host = smtp_host
        self._smtp_port = smtp_port or 25
        self._smtp_username = smtp_username
        self._smtp_password = smtp_password
        self._smtp_use_tls = smtp_use_tls

    def notify_critical_finding(self, payload: CriticalFindingNotification) -> None:
        """Send Slack and email alerts for a validated critical finding."""

        message_lines = [
            "Medusa validated a critical finding:",
            f"• Finding: {payload.title} ({payload.finding_id})",
        ]
        if payload.target:
            message_lines.append(f"• Target: {payload.target}")
        if payload.scanner:
            message_lines.append(f"• Scanner: {payload.scanner}")
        message_lines.append(f"• Validation status: {payload.validation_status}")
        if payload.validated_at:
            message_lines.append(f"• Validated at: {payload.validated_at}")
        message_lines.append(f"• Evidence hash: {payload.evidence_hash}")
        if payload.metadata:
            message_lines.append("• Metadata:")
            for key, value in payload.metadata.items():
                message_lines.append(f"    - {key}: {value}")

        message_body = "\n".join(message_lines)

        if self._slack_webhook:
            self._dispatch_slack(message_body)
        if self._email_sender and self._email_recipients and self._smtp_host:
            self._dispatch_email("Medusa critical finding validated", message_body)

    def notify_anomaly(self, payload: AnomalyNotification) -> None:
        """Deliver anomaly notifications via Slack and email."""

        message_lines = [
            "Medusa detected an audit anomaly:",
            f"• Type: {payload.anomaly_type}",
            f"• Actor: {payload.actor}",
            f"• Source: {payload.source}",
            f"• Events observed: {payload.count} in {payload.window_seconds} seconds",
            f"• First seen: {payload.first_seen}",
            f"• Last seen: {payload.last_seen}",
        ]
        if payload.metadata:
            metadata_json = json.dumps(payload.metadata, sort_keys=True)
            message_lines.append(f"• Metadata: {metadata_json}")

        message_body = "\n".join(message_lines)

        if self._slack_webhook:
            self._dispatch_slack(message_body)
        if self._email_sender and self._email_recipients and self._smtp_host:
            self._dispatch_email("Medusa anomaly detected", message_body)

    def _dispatch_slack(self, message: str) -> None:
        data = json.dumps({"text": message}).encode("utf-8")
        request = urllib_request.Request(
            self._slack_webhook, data=data, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib_request.urlopen(request, timeout=10):
                LOGGER.info("Delivered Slack notification")
        except urllib_error.URLError as exc:  # pragma: no cover - best effort logging
            LOGGER.warning("Failed to deliver Slack notification", extra={"error": str(exc)})

    def _dispatch_email(self, subject: str, message: str) -> None:
        email = EmailMessage()
        email["Subject"] = subject
        email["From"] = self._email_sender  # type: ignore[assignment]
        email["To"] = ", ".join(self._email_recipients)
        email.set_content(message)

        try:
            with smtplib.SMTP(self._smtp_host, self._smtp_port, timeout=10) as client:
                if self._smtp_use_tls:
                    client.starttls()
                if self._smtp_username and self._smtp_password:
                    client.login(self._smtp_username, self._smtp_password)
                client.send_message(email)
                LOGGER.info("Delivered email notification", extra={"recipients": self._email_recipients})
        except smtplib.SMTPException as exc:  # pragma: no cover - best effort logging
            LOGGER.warning("Failed to deliver email notification", extra={"error": str(exc)})


def build_notification_service(
    *,
    slack_webhook: Optional[str],
    email_sender: Optional[str],
    email_recipients: Iterable[str],
    smtp_host: Optional[str],
    smtp_port: Optional[int],
    smtp_username: Optional[str],
    smtp_password: Optional[str],
    smtp_use_tls: bool,
) -> NotificationService:
    """Factory used by FastAPI dependency overrides."""

    return NotificationService(
        slack_webhook=slack_webhook,
        email_sender=email_sender,
        email_recipients=list(email_recipients),
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        smtp_username=smtp_username,
        smtp_password=smtp_password,
        smtp_use_tls=smtp_use_tls,
    )
