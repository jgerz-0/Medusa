"""Pydantic models for angr symbolic execution jobs and results."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, HttpUrl

Severity = Literal["info", "low", "medium", "high", "critical"]


class AngrJob(BaseModel):
    """Job payload submitted by the controller for symbolic execution."""

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


class AngrArtifact(BaseModel):
    """Reference to an analysis artifact persisted to object storage."""

    tool: str
    bucket: str
    key: str


class AngrFinding(BaseModel):
    """Normalized symbolic execution finding."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool: str = "angr"
    severity: Severity
    title: str
    description: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    artifact_bucket: Optional[str] = None
    artifact_key: Optional[str] = None
    executed_at: datetime


class AngrExecutionReport(BaseModel):
    """Detailed execution metadata emitted by the angr harness."""

    status: Literal["completed", "failed"]
    exit_code: int
    stdout: str
    stderr: str
    raw_output: Dict[str, Any] = Field(default_factory=dict)
    executed_at: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))
    duration_seconds: Optional[float] = None


class AngrResult(BaseModel):
    """Aggregate result published back to the controller."""

    status: Literal["completed", "failed"]
    job_id: str
    scan_id: str
    sample_id: str
    processed_at: datetime
    findings: List[AngrFinding] = Field(default_factory=list)
    reports: List[AngrExecutionReport] = Field(default_factory=list)
    artifacts: List[AngrArtifact] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None
