"""Utilities for normalizing and comparing severity levels across agents."""

from __future__ import annotations

from typing import Iterable, Literal, Mapping, Optional, Tuple

SeverityLevel = Literal["critical", "high", "medium", "low", "info"]

_SEVERITY_ALIASES: Mapping[str, SeverityLevel] = {
    "critical": "critical",
    "crit": "critical",
    "sev1": "critical",
    "high": "high",
    "sev2": "high",
    "medium": "medium",
    "med": "medium",
    "moderate": "medium",
    "sev3": "medium",
    "low": "low",
    "sev4": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "none": "info",
}

SEVERITY_LEVELS: Tuple[SeverityLevel, ...] = (
    "critical",
    "high",
    "medium",
    "low",
    "info",
)

_SEVERITY_RANK: Mapping[SeverityLevel, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def normalize_severity(
    value: object,
    *,
    default: Optional[SeverityLevel] = None,
) -> Optional[SeverityLevel]:
    """Normalize arbitrary severity inputs into the canonical vocabulary."""

    if value is None:
        return default

    if isinstance(value, str):
        normalized = value.strip().lower()
        if not normalized:
            return default
        direct = _SEVERITY_ALIASES.get(normalized)
        if direct:
            return direct
        try:
            numeric_value = float(normalized)
        except ValueError:
            return default
        return severity_from_numeric(numeric_value, default=default)

    if isinstance(value, (int, float)):
    return severity_from_numeric(float(value), default=default)

    return default


def ensure_severity(value: object) -> SeverityLevel:
    """Return a normalized severity or raise a ``ValueError`` when invalid."""

    normalized = normalize_severity(value)
    if normalized is None:
        raise ValueError("Unsupported severity level")
    return normalized


def severity_from_numeric(
    value: float, *, default: Optional[SeverityLevel] = None
) -> Optional[SeverityLevel]:
    """Derive a severity from numeric inputs (risk codes or CVSS scores)."""

    if value != value:  # NaN check
        return default

    if value in {0, 1, 2, 3}:
        mapping: Mapping[int, SeverityLevel] = {
            0: "info",
            1: "low",
            2: "medium",
            3: "high",
        }
        return mapping[int(value)]

    if value < 0:
        return default

    return severity_from_cvss(value, default=default)


def severity_from_cvss(
    value: float, *, default: Optional[SeverityLevel] = None
) -> Optional[SeverityLevel]:
    """Convert a CVSS score into Medusa's severity vocabulary."""

    if value is None or value != value:  # guard against None/NaN
        return default

    if value >= 9.0:
        return "critical"
    if value >= 7.0:
        return "high"
    if value >= 4.0:
        return "medium"
    if value > 0:
        return "low"
    return "info"


def severity_to_cvss(value: object) -> float:
    """Return the representative CVSS score for a severity label."""

    normalized = normalize_severity(value)
    if normalized is None:
        return 0.0
    mapping = {
        "critical": 9.5,
        "high": 8.0,
        "medium": 6.0,
        "low": 3.0,
        "info": 0.0,
    }
    return mapping.get(normalized, 0.0)


def maximum_severity(
    values: Iterable[object], *, default: SeverityLevel = "info"
) -> SeverityLevel:
    """Return the highest severity present in the iterable."""

    best_rank = _SEVERITY_RANK[default]
    best = default
    for candidate in values:
        normalized = normalize_severity(candidate)
        if not normalized:
            continue
        rank = _SEVERITY_RANK.get(normalized, 0)
        if rank > best_rank:
            best = normalized
            best_rank = rank
    return best


__all__ = [
    "SEVERITY_LEVELS",
    "normalize_severity",
    "ensure_severity",
    "severity_from_numeric",
    "severity_from_cvss",
    "severity_to_cvss",
    "maximum_severity",
]
