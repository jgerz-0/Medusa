"""Severity normalization and scoring helpers for Medusa findings."""

from __future__ import annotations

from typing import Dict

SEVERITY_LEVELS = ("critical", "high", "medium", "low", "info")

_SEVERITY_SCORES: Dict[str, int] = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25,
    "info": 0,
}


def normalize_severity(value: str) -> str:
    """Return a normalized severity string constrained to supported levels."""

    candidate = (value or "").strip().lower()
    if candidate not in SEVERITY_LEVELS:
        raise ValueError(f"Unsupported severity level: {value!r}")
    return candidate


def severity_score(value: str) -> int:
    """Return a deterministic numeric score for a severity label."""

    normalized = normalize_severity(value)
    return _SEVERITY_SCORES[normalized]
