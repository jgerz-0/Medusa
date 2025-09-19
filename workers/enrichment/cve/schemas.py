"""Pydantic models describing CVE enrichment job contracts."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, validator


class CVESource(str, Enum):
    """Supported deterministic advisory sources."""

    NVD = "nvd"
    CIRCL = "circl"


DEFAULT_SOURCES: List[CVESource] = [CVESource.NVD, CVESource.CIRCL]


class CVEEnrichmentJob(BaseModel):
    """Serialized payload describing a CVE enrichment task."""

    job_id: str = Field(..., description="Unique identifier for the enrichment job")
    finding_id: str = Field(..., description="Finding identifier in the controller database")
    scan_id: Optional[str] = Field(
        default=None, description="Scan identifier linked to the finding"
    )
    cve_id: Optional[str] = Field(
        default=None,
        description="Primary CVE identifier extracted from the finding metadata",
    )
    title: str = Field(..., description="Finding title for analyst context")
    severity: str = Field(..., description="Scanner-reported severity value")
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Scanner-specific metadata used to improve lookup accuracy",
    )
    sources: List[CVESource] = Field(
        default_factory=lambda: list(DEFAULT_SOURCES),
        description="Deterministic advisory feeds to consult",
    )
    requested_by: str = Field(..., description="Principal requesting enrichment")
    requested_at: datetime = Field(..., description="UTC timestamp when the job was queued")

    @validator("cve_id")
    def _normalize_cve(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        normalized = value.strip().upper()
        return normalized or None

    @validator("requested_at", pre=True, always=True)
    def _ensure_requested_at_tz(cls, value: Any) -> datetime:
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        if isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:  # pragma: no cover - validated in tests
                raise ValueError("requested_at must be an ISO-8601 datetime") from exc
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        raise ValueError("requested_at must be a datetime")

    @validator("sources", pre=True)
    def _coerce_sources(cls, value: Any) -> List[CVESource]:
        if value is None:
            return list(DEFAULT_SOURCES)
        if isinstance(value, (str, CVESource)):
            return [CVESource(value)]
        return [CVESource(item) for item in value]


class CVEAdvisory(BaseModel):
    """Normalized advisory payload returned by external sources."""

    source: CVESource
    identifier: str = Field(..., description="CVE identifier confirmed by the source")
    summary: Optional[str] = Field(
        default=None, description="Human-readable summary provided by the source"
    )
    severity: Optional[str] = Field(
        default=None, description="Highest severity reported by the source"
    )
    cvss_score: Optional[float] = Field(
        default=None, description="Deterministic CVSS score when supplied"
    )
    published: Optional[datetime] = Field(
        default=None, description="Original publication timestamp"
    )
    modified: Optional[datetime] = Field(
        default=None, description="Last modification timestamp"
    )
    references: List[str] = Field(
        default_factory=list,
        description="List of URLs referenced by the advisory",
    )
    raw: Dict[str, Any] = Field(
        default_factory=dict,
        description="Deterministically sorted source payload for auditing",
    )


class CVEEnrichmentResult(BaseModel):
    """Aggregated output posted back to the controller."""

    job_id: str
    finding_id: str
    advisories: List[CVEAdvisory] = Field(
        default_factory=list, description="Normalized advisory documents"
    )
    errors: Dict[CVESource, str] = Field(
        default_factory=dict, description="Sources that failed with reason"
    )
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when enrichment completed",
    )

    class Config:
        use_enum_values = True

