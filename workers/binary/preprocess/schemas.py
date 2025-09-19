"""Pydantic schemas shared between the binary preprocess controller and worker."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class BinaryPreprocessJob(BaseModel):
    """Controller-issued job payload consumed by the preprocess worker."""

    job_id: str = Field(..., description="Unique identifier for this preprocessing task")
    scan_id: str = Field(..., description="Scan record identifier associated with the upload")
    target_id: str = Field(..., description="Target identifier" )
    target_scope: str = Field(..., description="Scope string validated by the controller")
    object_bucket: str = Field(..., description="S3/MinIO bucket housing the artifact to inspect")
    object_key: str = Field(..., description="Object key referencing the uploaded artifact")
    file_name: Optional[str] = Field(
        default=None, description="Analyst-provided filename for display purposes"
    )
    submitted_by: Optional[str] = Field(
        default=None, description="Principal initiating the preprocessing request"
    )
    submitted_at: Optional[datetime] = Field(
        default=None, description="UTC timestamp recorded by the controller"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary contextual metadata forwarded to the worker",
    )


class PolicyDecision(BaseModel):
    """Result emitted by a triage policy evaluation."""

    allowed: bool = Field(default=True, description="Whether the artifact is allowed to proceed")
    reasons: list[str] = Field(
        default_factory=list,
        description="Human-readable reasons describing policy decisions",
    )

    def merge(self, other: "PolicyDecision") -> "PolicyDecision":
        """Combine two policy decisions deterministically."""

        combined = PolicyDecision()
        combined.allowed = self.allowed and other.allowed
        combined.reasons = list(dict.fromkeys([*self.reasons, *other.reasons]))
        return combined


class NormalizedBinaryMetadata(BaseModel):
    """Normalized metadata persisted for downstream analysis."""

    job_id: str
    scan_id: str
    target_id: str
    target_scope: str
    file_name: str
    sha256: str
    file_size: int
    mime_type: str
    magic_label: Optional[str] = None
    policy_status: str
    policy_reasons: list[str] = Field(default_factory=list)
    storage_bucket: str
    storage_key: str
    inspected_at: datetime
    submitted_by: Optional[str] = None
    extra_metadata: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        json_encoders = {
            datetime: lambda value: value.isoformat(),
        }
