"""SQLAlchemy models for Medusa controller persistence."""
from __future__ import annotations

import datetime
import hashlib
import json
import uuid
from typing import Any, Dict, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    String,
    Text,
    event,
    inspect,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base declarative class used by all ORM models."""


def _default_uuid() -> str:
    """Generate a random UUID4 string for primary keys."""

    return str(uuid.uuid4())


def _coerce_evidence(payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Normalize evidence payloads into deterministic dictionaries."""

    if payload is None:
        return {}
    return payload


def _hash_evidence(payload: Dict[str, Any]) -> str:
    """Create a SHA-256 hash of evidence JSON for immutability guarantees."""

    normalized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


class TimestampMixin:
    """Reusable timestamp columns."""

    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), onupdate=func.now(), nullable=False
    )


class Target(TimestampMixin, Base):
    """Authorized scope target that scans are executed against."""

    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_default_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    scope: Mapped[str] = mapped_column(String(255), nullable=False)
    is_authorized: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    scans: Mapped[list["Scan"]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )


class Scan(TimestampMixin, Base):
    """Scan job executed by a worker against a target."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_default_uuid)
    target_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    scanner: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="queued", nullable=False)
    parameters: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    started_at: Mapped[Optional[datetime.datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[Optional[datetime.datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    target: Mapped["Target"] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    audit_entries: Mapped[list["AuditLog"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class Finding(TimestampMixin, Base):
    """Single vulnerability finding emitted by a scan."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_default_uuid)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    cve_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    scan: Mapped["Scan"] = relationship(back_populates="findings")
    audit_entries: Mapped[list["AuditLog"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class AuditLog(Base):
    """Immutable log capturing security-sensitive actions."""

    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_default_uuid)
    scan_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    finding_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="SET NULL"), nullable=True
    )
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence_snapshot: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), nullable=False
    )

    scan: Mapped[Optional["Scan"]] = relationship(back_populates="audit_entries")
    finding: Mapped[Optional["Finding"]] = relationship(back_populates="audit_entries")


@event.listens_for(Finding, "before_insert", propagate=True)
def _finding_set_hash(mapper, connection, target: Finding) -> None:
    target.evidence = _coerce_evidence(target.evidence)
    if not target.evidence_hash:
        target.evidence_hash = _hash_evidence(target.evidence)


@event.listens_for(Finding, "before_update", propagate=True)
def _finding_prevent_evidence_mutation(mapper, connection, target: Finding) -> None:
    state = inspect(target)
    evidence_attr = state.attrs.evidence
    hash_attr = state.attrs.evidence_hash
    if evidence_attr.history.has_changes() or hash_attr.history.has_changes():
        raise ValueError("Finding evidence payloads are immutable once persisted.")


@event.listens_for(AuditLog, "before_insert", propagate=True)
def _auditlog_set_hash(mapper, connection, target: AuditLog) -> None:
    target.evidence_snapshot = _coerce_evidence(target.evidence_snapshot)
    if not target.evidence_hash:
        target.evidence_hash = _hash_evidence(target.evidence_snapshot)


@event.listens_for(AuditLog, "before_update", propagate=True)
def _auditlog_prevent_evidence_mutation(mapper, connection, target: AuditLog) -> None:
    state = inspect(target)
    evidence_attr = state.attrs.evidence_snapshot
    hash_attr = state.attrs.evidence_hash
    if evidence_attr.history.has_changes() or hash_attr.history.has_changes():
        raise ValueError("Audit log evidence is immutable by design.")
