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
    Index,
    Integer,
    ForeignKey,
    String,
    Text,
    event,
    func,
    inspect,
    text,
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


def _hash_json(payload: Any) -> str:
    """Create a SHA-256 hash of arbitrary JSON-serialisable payloads."""

    normalized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _hash_evidence(payload: Dict[str, Any]) -> str:
    """Create a SHA-256 hash of evidence JSON for immutability guarantees."""

    return _hash_json(payload)


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
    binary_samples: Mapped[list["BinarySample"]] = relationship(
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
    initiated_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="queued", nullable=False)
    parameters: Mapped[Dict[str, Any]] = mapped_column(
        JSON, default=dict, nullable=False
    )
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
    binary_samples: Mapped[list["BinarySample"]] = relationship(
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
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(
        "metadata", JSON, default=dict, nullable=False
    )
    evidence: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    scan: Mapped["Scan"] = relationship(back_populates="findings")
    audit_entries: Mapped[list["AuditLog"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    enrichments: Mapped[list["FindingEnrichment"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class FindingEnrichment(TimestampMixin, Base):
    """Immutable enrichment payloads linked to findings."""

    __tablename__ = "finding_enrichments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_default_uuid)
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    job_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    generated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    advisories: Mapped[list[Dict[str, Any]]] = mapped_column(
        JSON, default=list, nullable=False
    )
    advisories_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    errors: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    errors_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    provenance: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    provenance_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    finding: Mapped["Finding"] = relationship(back_populates="enrichments")


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
    evidence_snapshot: Mapped[Dict[str, Any]] = mapped_column(
        JSON, default=dict, nullable=False
    )
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), nullable=False
    )

    scan: Mapped[Optional["Scan"]] = relationship(back_populates="audit_entries")
    finding: Mapped[Optional["Finding"]] = relationship(back_populates="audit_entries")


class BinarySample(TimestampMixin, Base):
    """Normalized metadata about uploaded binaries produced by preprocessing."""

    __tablename__ = "binary_samples"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_default_uuid)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    target_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, nullable=False)
    mime_type: Mapped[str] = mapped_column(String(128), nullable=False)
    magic_type: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    policy_status: Mapped[str] = mapped_column(String(32), default="allowed", nullable=False)
    policy_reasons: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    storage_bucket: Mapped[str] = mapped_column(String(128), nullable=False)
    storage_key: Mapped[str] = mapped_column(String(512), nullable=False)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(
        JSON, default=dict, nullable=False
    )
    metadata_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    processed_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), nullable=False
    )

    scan: Mapped["Scan"] = relationship(back_populates="binary_samples")
    target: Mapped["Target"] = relationship(back_populates="binary_samples")


@event.listens_for(BinarySample, "before_insert", propagate=True)
def _binary_sample_set_hash(mapper, connection, target: BinarySample) -> None:
    target.metadata_json = _coerce_evidence(target.metadata_json)
    target.policy_reasons = list(dict.fromkeys(target.policy_reasons or []))
    if not target.metadata_hash:
        target.metadata_hash = _hash_json(target.metadata_json)


@event.listens_for(BinarySample, "before_update", propagate=True)
def _binary_sample_update_hash(mapper, connection, target: BinarySample) -> None:
    target.metadata_json = _coerce_evidence(target.metadata_json)
    target.policy_reasons = list(dict.fromkeys(target.policy_reasons or []))
    target.metadata_hash = _hash_json(target.metadata_json)


@event.listens_for(Finding, "before_insert", propagate=True)
def _finding_set_hash(mapper, connection, target: Finding) -> None:
    target.metadata_json = _coerce_evidence(target.metadata_json)
    target.evidence = _coerce_evidence(target.evidence)
    if not target.evidence_hash:
        payload = {
            "metadata": target.metadata_json,
            "evidence": target.evidence,
        }
        target.evidence_hash = _hash_evidence(payload)


@event.listens_for(Finding, "before_update", propagate=True)
def _finding_prevent_evidence_mutation(mapper, connection, target: Finding) -> None:
    state = inspect(target)
    metadata_attr = state.attrs.metadata_json
    evidence_attr = state.attrs.evidence
    hash_attr = state.attrs.evidence_hash
    if (
        metadata_attr.history.has_changes()
        or evidence_attr.history.has_changes()
        or hash_attr.history.has_changes()
    ):
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


def _normalize_json_payload(value: Any, default_factory):
    """Ensure JSON payloads stored in enrichment rows are deterministic."""

    if value is None:
        return default_factory()
    return value


@event.listens_for(FindingEnrichment, "before_insert", propagate=True)
def _finding_enrichment_set_hash(
    mapper, connection, target: FindingEnrichment
) -> None:
    target.advisories = list(_normalize_json_payload(target.advisories, list))
    target.errors = dict(_normalize_json_payload(target.errors, dict))
    target.provenance = dict(_normalize_json_payload(target.provenance, dict))

    if not target.advisories_hash:
        target.advisories_hash = _hash_json(target.advisories)
    if not target.errors_hash:
        target.errors_hash = _hash_json(target.errors)
    if not target.provenance_hash:
        target.provenance_hash = _hash_json(target.provenance)

    if not target.payload_hash:
        payload = {
            "advisories": target.advisories_hash,
            "errors": target.errors_hash,
            "provenance": target.provenance_hash,
        }
        target.payload_hash = _hash_json(payload)


@event.listens_for(FindingEnrichment, "before_update", propagate=True)
def _finding_enrichment_prevent_mutation(
    mapper, connection, target: FindingEnrichment
) -> None:
    state = inspect(target)
    changed = any(
        state.attrs[column].history.has_changes()
        for column in (
            "advisories",
            "errors",
            "provenance",
            "advisories_hash",
            "errors_hash",
            "provenance_hash",
            "payload_hash",
        )
    )
    if changed:
        raise ValueError("Finding enrichment payloads are immutable once recorded.")

class PrincipalCredential(Base):
    """Authentication material for API keys and JWT principals."""

    __tablename__ = "principal_credentials"

    __table_args__ = (
        # Ensure only one active credential per subject while retaining
        # historical, revoked rows for forensic review.
        Index(
            "ux_principal_credentials_active_subject",
            "subject",
            unique=True,
            sqlite_where=text("revoked_at IS NULL"),
            postgresql_where=text("revoked_at IS NULL"),
        ),
    )
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    auth_method: Mapped[str] = mapped_column(String(32), nullable=False)
    key_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    roles: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), nullable=False
    )
    revoked_at: Mapped[Optional[datetime.datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
