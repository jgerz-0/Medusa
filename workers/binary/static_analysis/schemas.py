"""Pydantic models shared by the static analysis worker."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, HttpUrl

Severity = Literal["info", "low", "medium", "high", "critical"]


class StaticAnalysisJob(BaseModel):
    """Job payload delivered by the controller via Redis."""

    job_id: str
    scan_id: str
    sample_id: str
    target_id: str
    object_bucket: str
    object_key: str
    file_name: str
    callback_url: HttpUrl
    attempts: int = 0
    submitted_at: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AnalysisArtifact(BaseModel):
    """Reference to a JSON artifact stored in MinIO."""

    tool: str
    bucket: str
    key: str


class AnalysisFinding(BaseModel):
    """Normalized finding emitted by a static analysis tool."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool: str
    severity: Severity
    title: str
    description: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    artifact_bucket: Optional[str] = None
    artifact_key: Optional[str] = None
    executed_at: datetime


class AnalysisToolReport(BaseModel):
    """Detailed execution report for a single tool run."""

    tool: str
    status: Literal["completed", "failed"]
    exit_code: int
    stdout: str
    stderr: str
    raw_output: Dict[str, Any] = Field(default_factory=dict)
    findings: List[AnalysisFinding] = Field(default_factory=list)
    artifact: Optional[AnalysisArtifact] = None
    executed_at: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))


class StaticAnalysisResult(BaseModel):
    """Aggregate result emitted after all tools run."""

    status: Literal["completed", "failed"]
    job_id: str
    scan_id: str
    sample_id: str
    processed_at: datetime
    findings: List[AnalysisFinding] = Field(default_factory=list)
    reports: List[AnalysisToolReport] = Field(default_factory=list)
    artifacts: List[AnalysisArtifact] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None
