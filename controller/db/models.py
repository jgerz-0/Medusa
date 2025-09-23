"""SQLAlchemy models for Medusa controller persistence."""

from __future__ import annotations

import datetime
import hashlib
import json
import uuid
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Index,
    Integer,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
    event,
    func,
    inspect,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from controller.severity import normalize_severity


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


def _normalize_tags(value: Optional[Iterable[str]]) -> list[str]:
    """Normalize analyst-supplied tags into a deterministic list."""

    if not value:
        return []
    normalized: list[str] = []
    for raw in value:
        if not isinstance(raw, str):
            continue
        candidate = raw.strip().lower()
        if not candidate:
            continue
        if candidate not in normalized:
            normalized.append(candidate)
    return normalized


def _normalize_status(value: Optional[str]) -> str:
    """Clamp finding workflow status to the supported vocabulary."""

    allowed = {
        "pending_validation",
        "open",
        "invalidated",
        "acknowledged",
        "resolved",
    }
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in allowed:
            return lowered
    return "pending_validation"


def _normalize_validation_status(value: Optional[str]) -> str:
    """Clamp validation lifecycle state to the supported vocabulary."""

    allowed = {"pending", "queued", "running", "passed", "failed"}
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in allowed:
            return lowered
    return "pending"


def _normalize_scope_status(value: Optional[str]) -> str:
    """Normalize scope compliance annotations for findings."""

    allowed = {"unknown", "in_scope", "out_of_scope", "mixed"}
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in allowed:
            return lowered
    return "unknown"


def _normalize_recon_status(value: Optional[str]) -> str:
    """Clamp recon discovery workflow state to the supported vocabulary."""

    allowed = {"new", "approved", "rejected"}
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in allowed:
            return lowered
    return "new"


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
    binary_analysis_findings: Mapped[list["BinaryStaticAnalysisFinding"]] = (
        relationship(back_populates="scan", cascade="all, delete-orphan")
    )
    binary_symbolic_execution_findings: Mapped[
        list["BinarySymbolicExecutionFinding"]
    ] = relationship(back_populates="scan", cascade="all, delete-orphan")
    binary_fuzzing_findings: Mapped[list["BinaryFuzzingFinding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class ReconDiscovery(TimestampMixin, Base):
    """Pending recon assets awaiting analyst approval."""

    __tablename__ = "recon_discoveries"

    __table_args__ = (
        UniqueConstraint("asset_type", "value", name="ux_recon_discovery_asset"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_default_uuid)
    source: Mapped[str] = mapped_column(String(128), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(32), nullable=False)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    raw_value: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    matched_scope: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(
        "metadata", JSON, default=dict, nullable=False
    )
    status: Mapped[str] = mapped_column(String(32), default="new", nullable=False)
    first_seen: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_seen: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    occurrences: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    approved_at: Mapped[Optional[datetime.datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    approved_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    approved_target_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("targets.id", ondelete="SET NULL"), nullable=True
    )

    approved_target: Mapped[Optional[Target]] = relationship(back_populates=None)


class ReconRun(TimestampMixin, Base):
    """Single recon worker execution and the tooling profile used."""

    __tablename__ = "recon_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_default_uuid)
    job_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    source: Mapped[str] = mapped_column(String(128), nullable=False)
    mode: Mapped[str] = mapped_column(String(16), default="feed", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="completed", nullable=False)
    retrieved_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    authorized_scopes: Mapped[List[str]] = mapped_column(
        JSON, default=list, nullable=False
    )
    tooling: Mapped[Dict[str, Any]] = mapped_column(
        JSON, default=dict, nullable=False
    )
    targets: Mapped[List[Dict[str, Any]]] = mapped_column(
        JSON, default=list, nullable=False
    )
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(
        "metadata", JSON, default=dict, nullable=False
    )

    observations: Mapped[List["ReconObservation"]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )


class ReconObservation(TimestampMixin, Base):
    """Per-run assets emitted by recon tooling before analyst review."""

    __tablename__ = "recon_observations"

    __table_args__ = (
        UniqueConstraint(
            "run_id",
            "asset_type",
            "normalized_value",
            "port",
            name="ux_recon_observation_asset",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_default_uuid)
    run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("recon_runs.id", ondelete="CASCADE"), nullable=False
    )
    target_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("targets.id", ondelete="SET NULL"), nullable=True
    )
    asset_type: Mapped[str] = mapped_column(String(32), nullable=False)
    normalized_value: Mapped[str] = mapped_column(String(1024), nullable=False)
    raw_value: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    matched_scope: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    occurrences: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(
        "metadata", JSON, default=dict, nullable=False
    )
    first_seen: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_seen: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    run: Mapped[ReconRun] = relationship(back_populates="observations")
    target: Mapped[Optional[Target]] = relationship(back_populates=None)


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
    status: Mapped[str] = mapped_column(
        String(32), default="pending_validation", nullable=False
    )
    validated_at: Mapped[Optional[datetime.datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    validation_status: Mapped[str] = mapped_column(
        String(32), default="pending", nullable=False
    )
    validation_metadata: Mapped[Dict[str, Any]] = mapped_column(
        JSON, default=dict, nullable=False
    )
    assigned_to: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    scope_status: Mapped[str] = mapped_column(
        String(32), default="unknown", nullable=False
    )

    scan: Mapped["Scan"] = relationship(back_populates="findings")
    audit_entries: Mapped[list["AuditLog"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    enrichments: Mapped[list["FindingEnrichment"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    comments: Mapped[list["FindingComment"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    tickets: Mapped[list["FindingTicket"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    validations: Mapped[list["FindingValidation"]] = relationship(
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
    provenance: Mapped[Dict[str, Any]] = mapped_column(
        JSON, default=dict, nullable=False
    )
    provenance_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    finding: Mapped["Finding"] = relationship(back_populates="enrichments")


class FindingValidation(TimestampMixin, Base):
    """Validator agent retest results for findings."""

    __tablename__ = "finding_validations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_default_uuid)
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    job_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    validator: Mapped[str] = mapped_column(String(128), nullable=False)
    executed_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    requested_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    requested_at: Mapped[Optional[datetime.datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(
        "metadata", JSON, default=dict, nullable=False
    )
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    metadata_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    finding: Mapped["Finding"] = relationship(back_populates="validations")


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


class AnomalyEvent(Base):
    """Structured anomaly callback emitted by the anomaly worker."""

    __tablename__ = "anomaly_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_default_uuid)
    anomaly_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    source: Mapped[str] = mapped_column(String(128), nullable=False)
    detected_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    first_seen: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_seen: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    count: Mapped[int] = mapped_column(Integer, nullable=False)
    window_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(
        "metadata", JSON, default=dict, nullable=False
    )


class FindingComment(Base):
    """Immutable analyst commentary linked to findings."""

    __tablename__ = "finding_comments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_default_uuid)
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    author: Mapped[str] = mapped_column(String(128), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(
        JSON, default=dict, nullable=False
    )
    metadata_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), nullable=False
    )

    finding: Mapped["Finding"] = relationship(back_populates="comments")


class FindingTicket(TimestampMixin, Base):
    """Deterministic ticket metadata for external integrations."""

    __tablename__ = "finding_tickets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_default_uuid)
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    integration: Mapped[str] = mapped_column(String(32), nullable=False)
    reference: Mapped[str] = mapped_column(String(128), nullable=False)
    url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="queued", nullable=False)
    payload: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    synced_at: Mapped[Optional[datetime.datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    sync_error: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    remote_metadata: Mapped[Dict[str, Any]] = mapped_column(
        JSON, default=dict, nullable=False
    )

    finding: Mapped["Finding"] = relationship(back_populates="tickets")


class ReportExport(TimestampMixin, Base):
    """Persistent record of generated report artifacts stored in object storage."""

    __tablename__ = "report_exports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_default_uuid)
    format: Mapped[str] = mapped_column(String(8), nullable=False)
    content_type: Mapped[str] = mapped_column(String(64), nullable=False)
    content_length: Mapped[int] = mapped_column(Integer, nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    storage_bucket: Mapped[str] = mapped_column(String(128), nullable=False)
    storage_key: Mapped[str] = mapped_column(String(512), nullable=False)
    requested_by: Mapped[str] = mapped_column(String(128), nullable=False)
    generated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), nullable=False
    )
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False)
    scan_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    finding_ids: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(
        "metadata", JSON, default=dict, nullable=False
    )


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
    policy_status: Mapped[str] = mapped_column(
        String(32), default="allowed", nullable=False
    )
    policy_reasons: Mapped[list[str]] = mapped_column(
        JSON, default=list, nullable=False
    )
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
    analysis_findings: Mapped[list["BinaryStaticAnalysisFinding"]] = relationship(
        back_populates="sample", cascade="all, delete-orphan"
    )
    symbolic_findings: Mapped[list["BinarySymbolicExecutionFinding"]] = relationship(
        back_populates="sample", cascade="all, delete-orphan"
    )
    fuzzing_findings: Mapped[list["BinaryFuzzingFinding"]] = relationship(
        back_populates="sample", cascade="all, delete-orphan"
    )


class BinaryStaticAnalysisFinding(TimestampMixin, Base):
    """Static analysis findings associated with binary samples."""

    __tablename__ = "binary_static_analysis_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_default_uuid)
    sample_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("binary_samples.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    job_id: Mapped[str] = mapped_column(String(64), nullable=False)
    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(
        JSON, default=dict, nullable=False
    )
    evidence: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    artifact_bucket: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    artifact_key: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    executed_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    sample: Mapped["BinarySample"] = relationship(back_populates="analysis_findings")
    scan: Mapped["Scan"] = relationship(back_populates="binary_analysis_findings")


class BinarySymbolicExecutionFinding(TimestampMixin, Base):
    """Symbolic execution findings produced by angr workers."""

    __tablename__ = "binary_symbolic_execution_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_default_uuid)
    sample_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("binary_samples.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    job_id: Mapped[str] = mapped_column(String(64), nullable=False)
    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(
        JSON, default=dict, nullable=False
    )
    evidence: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    artifact_bucket: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    artifact_key: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    executed_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    sample: Mapped["BinarySample"] = relationship(back_populates="symbolic_findings")
    scan: Mapped["Scan"] = relationship(
        back_populates="binary_symbolic_execution_findings"
    )


class BinaryFuzzingFinding(TimestampMixin, Base):
    """Findings produced by binary fuzzing workers."""

    __tablename__ = "binary_fuzzing_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_default_uuid)
    sample_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("binary_samples.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    job_id: Mapped[str] = mapped_column(String(64), nullable=False)
    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(
        JSON, default=dict, nullable=False
    )
    evidence: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    artifact_bucket: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    artifact_key: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    executed_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    sample: Mapped["BinarySample"] = relationship(back_populates="fuzzing_findings")
    scan: Mapped["Scan"] = relationship(back_populates="binary_fuzzing_findings")


@event.listens_for(ReconDiscovery, "before_insert", propagate=True)
def _recon_discovery_prepare_insert(mapper, connection, target: ReconDiscovery) -> None:
    target.metadata_json = _coerce_evidence(target.metadata_json)
    target.status = _normalize_recon_status(target.status)
    if target.asset_type:
        target.asset_type = target.asset_type.strip().lower()
    if target.value:
        target.value = target.value.strip()
    if target.raw_value:
        target.raw_value = target.raw_value.strip()
    if target.matched_scope:
        target.matched_scope = target.matched_scope.strip()
    if target.approved_by:
        target.approved_by = target.approved_by.strip()
    if target.first_seen is None:
        target.first_seen = datetime.datetime.now(datetime.timezone.utc)
    if target.first_seen.tzinfo is None:
        target.first_seen = target.first_seen.replace(tzinfo=datetime.timezone.utc)
    if target.last_seen is None:
        target.last_seen = target.first_seen
    if target.last_seen.tzinfo is None:
        target.last_seen = target.last_seen.replace(tzinfo=datetime.timezone.utc)
    if target.last_seen < target.first_seen:
        target.last_seen = target.first_seen
    if target.occurrences is None or target.occurrences <= 0:
        target.occurrences = 1


@event.listens_for(ReconDiscovery, "before_update", propagate=True)
def _recon_discovery_prepare_update(mapper, connection, target: ReconDiscovery) -> None:
    target.metadata_json = _coerce_evidence(target.metadata_json)
    target.status = _normalize_recon_status(target.status)
    if target.asset_type:
        target.asset_type = target.asset_type.strip().lower()
    if target.value:
        target.value = target.value.strip()
    if target.raw_value:
        target.raw_value = target.raw_value.strip()
    if target.matched_scope:
        target.matched_scope = target.matched_scope.strip()
    if target.approved_by:
        target.approved_by = target.approved_by.strip()
    if target.first_seen is None:
        target.first_seen = datetime.datetime.now(datetime.timezone.utc)
    if target.first_seen.tzinfo is None:
        target.first_seen = target.first_seen.replace(tzinfo=datetime.timezone.utc)
    if target.last_seen is None:
        target.last_seen = target.first_seen
    if target.last_seen.tzinfo is None:
        target.last_seen = target.last_seen.replace(tzinfo=datetime.timezone.utc)
    if target.last_seen < target.first_seen:
        target.last_seen = target.first_seen
    if target.occurrences is None or target.occurrences <= 0:
        target.occurrences = 1


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


@event.listens_for(BinaryStaticAnalysisFinding, "before_insert", propagate=True)
def _binary_static_analysis_set_hash(
    mapper, connection, target: BinaryStaticAnalysisFinding
) -> None:
    target.severity = normalize_severity(target.severity)
    target.metadata_json = _coerce_evidence(target.metadata_json)
    target.evidence = _coerce_evidence(target.evidence)
    if not target.evidence_hash:
        payload = {
            "metadata": target.metadata_json,
            "evidence": target.evidence,
        }
        target.evidence_hash = _hash_evidence(payload)


@event.listens_for(BinarySymbolicExecutionFinding, "before_insert", propagate=True)
def _binary_symbolic_execution_set_hash(
    mapper, connection, target: BinarySymbolicExecutionFinding
) -> None:
    target.severity = normalize_severity(target.severity)
    target.metadata_json = _coerce_evidence(target.metadata_json)
    target.evidence = _coerce_evidence(target.evidence)
    if not target.evidence_hash:
        payload = {
            "metadata": target.metadata_json,
            "evidence": target.evidence,
        }
        target.evidence_hash = _hash_evidence(payload)


@event.listens_for(BinaryFuzzingFinding, "before_insert", propagate=True)
def _binary_fuzzing_set_hash(mapper, connection, target: BinaryFuzzingFinding) -> None:
    target.severity = normalize_severity(target.severity)
    target.metadata_json = _coerce_evidence(target.metadata_json)
    target.evidence = _coerce_evidence(target.evidence)
    if not target.evidence_hash:
        payload = {
            "metadata": target.metadata_json,
            "evidence": target.evidence,
        }
        target.evidence_hash = _hash_evidence(payload)


@event.listens_for(BinaryFuzzingFinding, "before_update", propagate=True)
def _binary_fuzzing_prevent_mutation(
    mapper, connection, target: BinaryFuzzingFinding
) -> None:
    state = inspect(target)
    metadata_attr = state.attrs.metadata_json
    evidence_attr = state.attrs.evidence
    hash_attr = state.attrs.evidence_hash
    if (
        metadata_attr.history.has_changes()
        or evidence_attr.history.has_changes()
        or hash_attr.history.has_changes()
    ):
        raise ValueError("Fuzzing evidence payloads are immutable once persisted.")


@event.listens_for(BinarySymbolicExecutionFinding, "before_update", propagate=True)
def _binary_symbolic_prevent_mutation(
    mapper, connection, target: BinarySymbolicExecutionFinding
) -> None:
    state = inspect(target)
    metadata_attr = state.attrs.metadata_json
    evidence_attr = state.attrs.evidence
    hash_attr = state.attrs.evidence_hash
    if (
        metadata_attr.history.has_changes()
        or evidence_attr.history.has_changes()
        or hash_attr.history.has_changes()
    ):
        raise ValueError(
            "Symbolic execution evidence payloads are immutable once persisted."
        )


@event.listens_for(BinaryStaticAnalysisFinding, "before_update", propagate=True)
def _binary_static_analysis_prevent_mutation(
    mapper, connection, target: BinaryStaticAnalysisFinding
) -> None:
    state = inspect(target)
    metadata_attr = state.attrs.metadata_json
    evidence_attr = state.attrs.evidence
    hash_attr = state.attrs.evidence_hash
    if (
        metadata_attr.history.has_changes()
        or evidence_attr.history.has_changes()
        or hash_attr.history.has_changes()
    ):
        raise ValueError(
            "Static analysis evidence payloads are immutable once persisted."
        )


@event.listens_for(Finding, "before_insert", propagate=True)
def _finding_set_hash(mapper, connection, target: Finding) -> None:
    target.severity = normalize_severity(target.severity)
    target.metadata_json = _coerce_evidence(target.metadata_json)
    target.evidence = _coerce_evidence(target.evidence)
    target.validation_metadata = _coerce_evidence(target.validation_metadata)
    target.tags = _normalize_tags(target.tags)
    target.status = _normalize_status(target.status)
    target.validation_status = _normalize_validation_status(target.validation_status)
    target.scope_status = _normalize_scope_status(target.scope_status)
    if target.assigned_to:
        target.assigned_to = target.assigned_to.strip()
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
    target.tags = _normalize_tags(target.tags)
    target.status = _normalize_status(target.status)
    target.validation_status = _normalize_validation_status(target.validation_status)
    target.scope_status = _normalize_scope_status(target.scope_status)
    if target.assigned_to:
        target.assigned_to = target.assigned_to.strip()
    if (
        metadata_attr.history.has_changes()
        or evidence_attr.history.has_changes()
        or hash_attr.history.has_changes()
    ):
        raise ValueError("Finding evidence payloads are immutable once persisted.")


@event.listens_for(FindingComment, "before_insert", propagate=True)
def _finding_comment_set_hash(mapper, connection, target: FindingComment) -> None:
    target.metadata_json = _coerce_evidence(target.metadata_json)
    if not target.metadata_hash:
        target.metadata_hash = _hash_json(target.metadata_json)


@event.listens_for(FindingComment, "before_update", propagate=True)
def _finding_comment_immutable(mapper, connection, target: FindingComment) -> None:
    state = inspect(target)
    if (
        state.attrs.message.history.has_changes()
        or state.attrs.metadata_json.history.has_changes()
    ):
        raise ValueError("Finding comments are immutable once persisted.")


@event.listens_for(FindingTicket, "before_insert", propagate=True)
def _finding_ticket_set_hash(mapper, connection, target: FindingTicket) -> None:
    target.payload = _coerce_evidence(target.payload)
    target.payload_hash = target.payload_hash or _hash_json(target.payload)
    if target.integration:
        target.integration = target.integration.strip().lower()
    if target.reference:
        target.reference = target.reference.strip()
    if target.status:
        target.status = target.status.strip().lower()


@event.listens_for(FindingTicket, "before_update", propagate=True)
def _finding_ticket_prevent_payload_mutation(
    mapper, connection, target: FindingTicket
) -> None:
    state = inspect(target)
    payload_attr = state.attrs.payload
    payload_hash_attr = state.attrs.payload_hash
    if payload_attr.history.has_changes() or payload_hash_attr.history.has_changes():
        raise ValueError("Ticket payloads are immutable once recorded.")
    if target.integration:
        target.integration = target.integration.strip().lower()
    if target.reference:
        target.reference = target.reference.strip()
    if target.status:
        target.status = target.status.strip().lower()


@event.listens_for(FindingValidation, "before_insert", propagate=True)
def _finding_validation_set_hash(mapper, connection, target: FindingValidation) -> None:
    target.metadata_json = _coerce_evidence(target.metadata_json)
    target.evidence = _coerce_evidence(target.evidence)
    target.status = _normalize_validation_status(target.status)
    if target.validator:
        target.validator = target.validator.strip()
    if target.requested_by:
        target.requested_by = target.requested_by.strip()
    if target.notes:
        target.notes = target.notes.strip()
    if not target.evidence_hash:
        target.evidence_hash = _hash_evidence(target.evidence)
    if not target.metadata_hash:
        target.metadata_hash = _hash_json(target.metadata_json)


@event.listens_for(FindingValidation, "before_update", propagate=True)
def _finding_validation_prevent_mutation(
    mapper, connection, target: FindingValidation
) -> None:
    state = inspect(target)
    immutable_changed = any(
        state.attrs[column].history.has_changes()
        for column in ("evidence", "metadata_json", "evidence_hash", "metadata_hash")
    )
    if immutable_changed:
        raise ValueError("Validation evidence is immutable once recorded.")
    target.status = _normalize_validation_status(target.status)
    if target.validator:
        target.validator = target.validator.strip()
    if target.requested_by:
        target.requested_by = target.requested_by.strip()
    if target.notes:
        target.notes = target.notes.strip()


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
def _finding_enrichment_set_hash(mapper, connection, target: FindingEnrichment) -> None:
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


@event.listens_for(ReportExport, "before_insert", propagate=True)
def _report_export_normalize(mapper, connection, target: ReportExport) -> None:
    if target.metadata_json is None:
        target.metadata_json = {}
    if target.finding_ids is None:
        target.finding_ids = []
    if not isinstance(target.finding_ids, list):
        target.finding_ids = list(target.finding_ids)


class PrincipalCredential(Base):
    """Authentication material for API keys, JWT, and OIDC principals."""

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
    expires_at: Mapped[Optional[datetime.datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_at: Mapped[Optional[datetime.datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    source: Mapped[str] = mapped_column(String(64), default="manual", nullable=False)
