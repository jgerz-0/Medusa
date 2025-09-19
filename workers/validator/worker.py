"""Validator worker that performs deterministic retests before promotion."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests
from pydantic import BaseModel, Field, validator

LOGGER = logging.getLogger("medusa.validator")


class ValidationJob(BaseModel):
    """Normalized payload delivered by the controller."""

    job_id: str
    finding_id: str
    scan_id: str
    severity: str
    callback_url: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    evidence: Dict[str, Any] = Field(default_factory=dict)

    @validator("severity")
    def _normalize_severity(cls, value: str) -> str:  # noqa: D401
        lowered = value.lower().strip()
        allowed = {"critical", "high", "medium", "low", "info"}
        if lowered not in allowed:
            raise ValueError(f"Unsupported severity: {value}")
        return lowered

    @classmethod
    def from_json(cls, payload: str) -> "ValidationJob":
        document = json.loads(payload)
        return cls(**document)


@dataclass
class WorkerConfig:
    """Runtime configuration for the validator worker."""

    queue_key: str = "queues:validator:jobs"
    dead_letter_key: str = "queues:validator:dead"
    callback_token: Optional[str] = None
    http_timeout_seconds: int = 10


def _evaluate_job(job: ValidationJob) -> Dict[str, Any]:
    """Perform a deterministic retest decision using supplied metadata."""

    metadata = job.metadata
    expected_status = metadata.get("expected_status")
    observed_status = metadata.get("observed_status")
    force_fail = metadata.get("force_fail", False)

    status = "passed"
    notes = []

    if force_fail:
        status = "failed"
        notes.append("force_fail flag triggered")
    elif expected_status is not None and observed_status is not None:
        if str(expected_status) != str(observed_status):
            status = "failed"
            notes.append(
                f"expected status {expected_status} but observed {observed_status}"
            )

    return {
        "status": status,
        "notes": "; ".join(notes) if notes else None,
    }


def process_job(
    job: ValidationJob,
    config: WorkerConfig,
    *,
    http_session: Optional[requests.Session] = None,
) -> None:
    """Execute a validation job and report the outcome to the controller."""

    result = _evaluate_job(job)
    payload = {
        "job_id": job.job_id,
        "finding_id": job.finding_id,
        "status": result["status"],
        "validator": "validator-worker",
        "executed_at": datetime.now(tz=timezone.utc).isoformat(),
        "metadata": job.metadata,
        "evidence": job.evidence,
    }
    if result.get("notes"):
        payload["notes"] = result["notes"]

    headers = {"X-Callback-Token": config.callback_token or ""}
    session = http_session or requests.Session()
    try:
        response = session.post(
            job.callback_url,
            json=payload,
            headers=headers,
            timeout=config.http_timeout_seconds,
        )
        response.raise_for_status()
    except requests.RequestException as exc:  # pragma: no cover - network failures
        LOGGER.exception("validator callback failed", extra={"job_id": job.job_id})
        raise RuntimeError("validator callback failed") from exc
    finally:
        if http_session is None:
            session.close()


def main() -> None:  # pragma: no cover - CLI entry point
    raise SystemExit("Run the validator worker via the orchestrator entry point")


__all__ = ["ValidationJob", "WorkerConfig", "process_job"]
