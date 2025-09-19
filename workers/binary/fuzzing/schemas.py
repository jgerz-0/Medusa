"""Pydantic models used by the binary fuzzing worker."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, HttpUrl

from workers.binary.static_analysis.schemas import (  # Reuse shared artifacts
    AnalysisArtifact,
    AnalysisFinding,
)


class FuzzingJob(BaseModel):
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
    max_duration_seconds: Optional[int] = Field(
        default=None, description="Optional hard limit for fuzzing runtime"
    )


class FuzzingRunSummary(BaseModel):
    """Execution metadata for a fuzzing harness invocation."""

    tool: str
    status: str
    exit_code: int
    stdout: str
    stderr: str
    raw_output: Dict[str, Any] = Field(default_factory=dict)
    findings: List[AnalysisFinding] = Field(default_factory=list)
    artifact: Optional[AnalysisArtifact] = None
    executed_at: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))
    duration_seconds: Optional[int] = None


class FuzzingResult(BaseModel):
    """Aggregate result emitted after all fuzzers complete."""

    status: str
    job_id: str
    scan_id: str
    sample_id: str
    processed_at: datetime
    findings: List[AnalysisFinding] = Field(default_factory=list)
    runs: List[FuzzingRunSummary] = Field(default_factory=list)
    artifacts: List[AnalysisArtifact] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None

