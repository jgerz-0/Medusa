"""FastAPI controller for coordinating scan orchestration and persistence."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import time
import uuid
from copy import deepcopy
from datetime import datetime, timezone, date
from io import BytesIO
import html
import textwrap
from functools import lru_cache
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from typing import Any, Dict, Iterable, Iterator, List, Literal, Optional, Tuple, Union

import jwt
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network

try:  # pragma: no cover - compatibility shim for environments without pydantic-settings
    from pydantic_settings import BaseSettings
except ModuleNotFoundError:  # pragma: no cover

    class BaseSettings(BaseModel):  # type: ignore[override]
        """Minimal stand-in when pydantic-settings is unavailable."""

        class Config:
            arbitrary_types_allowed = True


from redis import Redis
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, selectinload

from controller import metrics
from controller.db.models import (
    AuditLog,
    BinaryFuzzingFinding,
    BinarySample,
    BinaryStaticAnalysisFinding,
    Finding,
    FindingEnrichment,
    FindingComment,
    FindingTicket,
    PrincipalCredential,
    Scan,
    Target,
)
from controller.db.session import SessionLocal
from workers.enrichment.cve.schemas import CVEEnrichmentResult


LOGGER = logging.getLogger("medusa.controller")
AUDIT_LOGGER = logging.getLogger("medusa.audit")

ROLE_ADMIN = "admin"
ROLE_ANALYST = "analyst"
ROLE_FINDINGS_READ = "findings:read"
ROLE_SCANS_READ = "scans:read"
ROLE_SCAN_ENQUEUE = "scan:enqueue"
ROLE_BINARY_PREPROCESS_ENQUEUE = "binary:preprocess"
ROLE_BINARY_STATIC_ANALYSIS_ENQUEUE = "binary:static-analysis"
ROLE_BINARY_FUZZING_ENQUEUE = "binary:fuzzing"
ROLE_TARGETS_READ = "targets:read"
ROLE_TARGETS_WRITE = "targets:write"
ROLE_ENRICHMENT_ENQUEUE = "enrich:enqueue"
ROLE_REPORT_EXPORT = "report:export"
ROLE_TICKETING_CREATE = "ticket:create"

ALLOWED_ROLES = {
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_FINDINGS_READ,
    ROLE_SCANS_READ,
    ROLE_SCAN_ENQUEUE,
    ROLE_BINARY_PREPROCESS_ENQUEUE,
    ROLE_BINARY_STATIC_ANALYSIS_ENQUEUE,
    ROLE_BINARY_FUZZING_ENQUEUE,
    ROLE_TARGETS_READ,
    ROLE_TARGETS_WRITE,
    ROLE_ENRICHMENT_ENQUEUE,
    ROLE_REPORT_EXPORT,
    ROLE_TICKETING_CREATE,
}

DEFAULT_ANALYST_ROLES = [
    ROLE_ANALYST,
    ROLE_FINDINGS_READ,
    ROLE_SCANS_READ,
    ROLE_SCAN_ENQUEUE,
    ROLE_BINARY_PREPROCESS_ENQUEUE,
    ROLE_BINARY_STATIC_ANALYSIS_ENQUEUE,
    ROLE_BINARY_FUZZING_ENQUEUE,
    ROLE_TARGETS_READ,
    ROLE_ENRICHMENT_ENQUEUE,
    ROLE_REPORT_EXPORT,
]

DEFAULT_ADMIN_ROLES = [
    ROLE_ADMIN,
    ROLE_FINDINGS_READ,
    ROLE_SCANS_READ,
    ROLE_SCAN_ENQUEUE,
    ROLE_BINARY_PREPROCESS_ENQUEUE,
    ROLE_BINARY_STATIC_ANALYSIS_ENQUEUE,
    ROLE_BINARY_FUZZING_ENQUEUE,
    ROLE_TARGETS_READ,
    ROLE_TARGETS_WRITE,
    ROLE_ENRICHMENT_ENQUEUE,
    ROLE_REPORT_EXPORT,
    ROLE_TICKETING_CREATE,
]

CALLBACK_TOKEN_HEADER = "X-Callback-Token"

# Hardened nuclei configuration shared with workers.  Templates are pinned to
# known-good nuclei definitions to avoid arbitrary execution of user-supplied
# YAML.  Profiles may only reference templates within the approved prefixes and
# default to a conservative "baseline" crawl.
NUCLEI_BASELINE_TEMPLATES: Tuple[str, ...] = (
    "http/exposures/configs/phpinfo-detect.yaml",
    "http/exposed-panels/jenkins-login.yaml",
    "network/dns/dns-zone-transfer.yaml",
)

# Profiles expand the baseline with curated nuclei templates to keep behavior
# deterministic.  Names align with the frontend presets so analysts can audit
# exactly which template families execute for each queue request.
NUCLEI_WEB_BASELINE_TEMPLATES: Tuple[str, ...] = NUCLEI_BASELINE_TEMPLATES

NUCLEI_API_DEEP_DIVE_TEMPLATES: Tuple[str, ...] = NUCLEI_WEB_BASELINE_TEMPLATES + (
    "http/exposed-panels/swagger-ui.yaml",
    "http/exposures/apis/postman-documenter.yaml",
)

NUCLEI_EXTERNAL_ATTACK_SURFACE_TEMPLATES: Tuple[str, ...] = (
    NUCLEI_WEB_BASELINE_TEMPLATES
    + (
        "http/cves/2023/CVE-2023-34362.yaml",
        "http/cves/2023/CVE-2023-50164.yaml",
        "network/exposed-services/ssh/weak-ciphers.yaml",
    )
)

NUCLEI_TEMPLATE_PROFILES: Dict[str, Tuple[str, ...]] = {
    "baseline": NUCLEI_BASELINE_TEMPLATES,
    "web-baseline": NUCLEI_WEB_BASELINE_TEMPLATES,
    "api-deep-dive": NUCLEI_API_DEEP_DIVE_TEMPLATES,
    "external-attack-surface": NUCLEI_EXTERNAL_ATTACK_SURFACE_TEMPLATES,
    "full": NUCLEI_EXTERNAL_ATTACK_SURFACE_TEMPLATES,
}

DEFAULT_NUCLEI_TEMPLATE_PROFILE = "web-baseline"

ALLOWED_NUCLEI_TEMPLATE_PREFIXES: Tuple[str, ...] = (
    "cves/",
    "http/",
    "network/",
    "dns/",
    "ssl/",
    "tcp/",
    "udp/",
)


SCAN_TYPE_NUCLEI = "nuclei"
SCAN_TYPE_ZAP = "zap"
SCAN_TYPE_SQLMAP = "sqlmap"
SCAN_TYPE_BINARY_STATIC = "binary_static_analysis"
SCAN_TYPE_BINARY_FUZZING = "binary_fuzzing"

ALLOWED_SCANNERS: Tuple[str, ...] = (
    SCAN_TYPE_NUCLEI,
    SCAN_TYPE_ZAP,
    SCAN_TYPE_SQLMAP,
)

DEFAULT_ZAP_POLICY = "baseline"
ALLOWED_ZAP_POLICIES: Tuple[str, ...] = ("baseline", "full")
DEFAULT_ZAP_RATE_LIMIT = "5"
ALLOWED_ZAP_MODES: Tuple[str, ...] = ("baseline", "full")

DEFAULT_SQLMAP_LEVEL = 1
DEFAULT_SQLMAP_RISK = 1
ALLOWED_SQLMAP_TECHNIQUES: Tuple[str, ...] = (
    "boolean",
    "error",
    "stacked",
    "time",
    "union",
)
ALLOWED_SQLMAP_TAMPER_SCRIPTS: Tuple[str, ...] = (
    "between",
    "charunicodeencode",
    "equaltolike",
    "modsecurityversioned",
    "space2comment",
)


def _normalize_profile(requested_profile: Any) -> str:
    if isinstance(requested_profile, str):
        candidate = requested_profile.strip().lower()
        if candidate in NUCLEI_TEMPLATE_PROFILES:
            return candidate
    return DEFAULT_NUCLEI_TEMPLATE_PROFILE


def _sanitize_template_name(candidate: Any) -> Optional[str]:
    if not isinstance(candidate, str):
        return None
    value = candidate.strip()
    if not value:
        return None
    lowered = value.lower()
    if ".." in lowered or lowered.startswith(("/", "\\")):
        return None
    if not any(
        lowered.startswith(prefix) for prefix in ALLOWED_NUCLEI_TEMPLATE_PREFIXES
    ):
        return None
    return value


def _sanitize_tags(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    normalized = []
    for item in value:
        if isinstance(item, str):
            tag = item.strip().lower()
            if tag:
                normalized.append(tag)
    return sorted(dict.fromkeys(normalized))


def _merge_templates(
    base_templates: Iterable[str], additional_templates: Iterable[str]
) -> List[str]:
    seen: set[str] = set()
    merged: List[str] = []
    for template in base_templates:
        if template not in seen:
            merged.append(template)
            seen.add(template)
    for template in additional_templates:
        if template not in seen:
            merged.append(template)
            seen.add(template)
    return merged


def resolve_nuclei_job_configuration(
    target_scope: str, parameters: Optional[Dict[str, Any]]
) -> Tuple[str, List[str], List[str], Dict[str, Any], Dict[str, Any]]:
    """Return sanitized nuclei configuration and metadata for auditing."""

    raw_parameters: Dict[str, Any] = dict(parameters or {})

    profile = _normalize_profile(raw_parameters.get("profile"))
    base_templates = NUCLEI_TEMPLATE_PROFILES[profile]

    requested_templates: List[str] = []
    for key in ("extra_templates", "templates"):
        value = raw_parameters.get(key)
        if isinstance(value, list):
            for item in value:
                sanitized = _sanitize_template_name(item)
                if sanitized:
                    requested_templates.append(sanitized)

    sanitized_requested = sorted(dict.fromkeys(requested_templates))
    templates = _merge_templates(base_templates, sanitized_requested)

    user_tags = _sanitize_tags(raw_parameters.get("tags"))
    tags = sorted({*user_tags, f"profile:{profile}"})

    requested_hosts_value = (
        raw_parameters.get("requested_hosts")
        or raw_parameters.get("allowed_hosts")
        or []
    )
    normalized_hosts = _coerce_requested_hosts(requested_hosts_value)
    allowed_hosts, rejected_hosts = _filter_hosts_for_scope(
        target_scope, normalized_hosts
    )

    sanitized_parameters: Dict[str, Any] = {"profile": profile}
    if sanitized_requested:
        sanitized_parameters["requested_templates"] = sanitized_requested
    if user_tags:
        sanitized_parameters["tags"] = user_tags

    rate_limit = raw_parameters.get("rate_limit")
    if isinstance(rate_limit, (int, float)):
        sanitized_parameters["rate_limit"] = str(rate_limit)
    elif isinstance(rate_limit, str) and rate_limit.strip():
        sanitized_parameters["rate_limit"] = rate_limit.strip()

    severity = raw_parameters.get("severity")
    if isinstance(severity, str) and severity.strip():
        sanitized_parameters["severity"] = severity.strip().lower()

    if allowed_hosts:
        sanitized_parameters["requested_hosts"] = allowed_hosts

    metadata: Dict[str, Any] = {}
    if normalized_hosts:
        metadata["requested_host_count"] = len(normalized_hosts)
    if rejected_hosts:
        metadata["rejected_hosts"] = rejected_hosts

    return profile, templates, tags, sanitized_parameters, metadata


def _sanitize_rate_limit(value: Any, *, default: str) -> str:
    if isinstance(value, (int, float)):
        if value <= 0:
            return default
        return f"{value:.2f}".rstrip("0").rstrip(".")
    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            return default
        try:
            parsed = float(candidate)
        except ValueError:
            return default
        if parsed <= 0:
            return default
        return f"{parsed:.2f}".rstrip("0").rstrip(".")
    return default


def _sanitize_boolean(value: Any, *, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    return default


def resolve_zap_job_configuration(
    target_scope: str, parameters: Optional[Dict[str, Any]]
) -> Tuple[Dict[str, Any], List[str], Dict[str, Any]]:
    """Return sanitized configuration for Zap-based crawls."""

    raw_parameters: Dict[str, Any] = dict(parameters or {})

    requested_policy = str(raw_parameters.get("policy") or "").strip().lower()
    if requested_policy not in ALLOWED_ZAP_POLICIES:
        policy = DEFAULT_ZAP_POLICY
    else:
        policy = requested_policy

    requested_mode = str(raw_parameters.get("mode") or "").strip().lower()
    if requested_mode not in ALLOWED_ZAP_MODES:
        mode = DEFAULT_ZAP_POLICY
    else:
        mode = requested_mode

    rate_limit = _sanitize_rate_limit(
        raw_parameters.get("rate_limit"), default=DEFAULT_ZAP_RATE_LIMIT
    )

    include_paths: List[str] = []
    include_value = raw_parameters.get("include_paths")
    if isinstance(include_value, str):
        include_paths = [
            segment.strip() for segment in include_value.split(",") if segment.strip()
        ]
    elif isinstance(include_value, Iterable) and not isinstance(
        include_value, (bytes, bytearray, dict)
    ):
        include_paths = [
            str(item).strip() for item in include_value if str(item).strip()
        ]

    exclude_paths: List[str] = []
    exclude_value = raw_parameters.get("exclude_paths")
    if isinstance(exclude_value, str):
        exclude_paths = [
            segment.strip() for segment in exclude_value.split(",") if segment.strip()
        ]
    elif isinstance(exclude_value, Iterable) and not isinstance(
        exclude_value, (bytes, bytearray, dict)
    ):
        exclude_paths = [
            str(item).strip() for item in exclude_value if str(item).strip()
        ]

    requested_hosts = raw_parameters.get("allowed_hosts") or []
    allowed_hosts, rejected_hosts = _filter_hosts_for_scope(
        target_scope, _coerce_requested_hosts(requested_hosts)
    )

    ajax_spider = _sanitize_boolean(raw_parameters.get("ajax_spider"), default=False)

    tags = sorted(
        {
            f"zap:mode:{mode}",
            f"zap:policy:{policy}",
        }
    )

    sanitized_parameters: Dict[str, Any] = {
        "policy": policy,
        "mode": mode,
        "rate_limit": rate_limit,
        "ajax_spider": ajax_spider,
    }
    if include_paths:
        sanitized_parameters["include_paths"] = include_paths
    if exclude_paths:
        sanitized_parameters["exclude_paths"] = exclude_paths
    if allowed_hosts:
        sanitized_parameters["allowed_hosts"] = allowed_hosts

    metadata: Dict[str, Any] = {}
    if rejected_hosts:
        metadata["rejected_hosts"] = rejected_hosts

    return sanitized_parameters, tags, metadata


def resolve_sqlmap_job_configuration(
    target_scope: str, parameters: Optional[Dict[str, Any]]
) -> Tuple[Dict[str, Any], List[str], Dict[str, Any]]:
    """Return sanitized configuration for SQLMap injections."""

    raw_parameters: Dict[str, Any] = dict(parameters or {})

    try:
        requested_level = int(raw_parameters.get("level", DEFAULT_SQLMAP_LEVEL))
    except (TypeError, ValueError):
        requested_level = DEFAULT_SQLMAP_LEVEL
    level = max(1, min(5, requested_level))

    try:
        requested_risk = int(raw_parameters.get("risk", DEFAULT_SQLMAP_RISK))
    except (TypeError, ValueError):
        requested_risk = DEFAULT_SQLMAP_RISK
    risk = max(0, min(3, requested_risk))

    techniques_value = raw_parameters.get("techniques")
    techniques: List[str] = []
    if isinstance(techniques_value, str):
        candidates = [
            segment.strip().lower() for segment in techniques_value.split(",")
        ]
        techniques = [item for item in candidates if item in ALLOWED_SQLMAP_TECHNIQUES]
    elif isinstance(techniques_value, Iterable) and not isinstance(
        techniques_value, (bytes, bytearray, dict)
    ):
        techniques = [
            str(item).strip().lower()
            for item in techniques_value
            if str(item).strip().lower() in ALLOWED_SQLMAP_TECHNIQUES
        ]

    tamper_value = raw_parameters.get("tamper")
    tamper_scripts: List[str] = []
    if isinstance(tamper_value, str):
        tamper_scripts = [
            segment.strip().lower()
            for segment in tamper_value.split(",")
            if segment.strip().lower() in ALLOWED_SQLMAP_TAMPER_SCRIPTS
        ]
    elif isinstance(tamper_value, Iterable) and not isinstance(
        tamper_value, (bytes, bytearray, dict)
    ):
        tamper_scripts = [
            str(item).strip().lower()
            for item in tamper_value
            if str(item).strip().lower() in ALLOWED_SQLMAP_TAMPER_SCRIPTS
        ]

    delay = _sanitize_rate_limit(raw_parameters.get("request_delay"), default="0")

    requested_hosts = raw_parameters.get("allowed_hosts") or []
    allowed_hosts, rejected_hosts = _filter_hosts_for_scope(
        target_scope, _coerce_requested_hosts(requested_hosts)
    )

    sanitized_parameters: Dict[str, Any] = {
        "level": level,
        "risk": risk,
        "request_delay": delay,
    }
    if techniques:
        sanitized_parameters["techniques"] = techniques
    if tamper_scripts:
        sanitized_parameters["tamper"] = tamper_scripts
    if allowed_hosts:
        sanitized_parameters["allowed_hosts"] = allowed_hosts

    tags = sorted(
        {
            f"sqlmap:level:{level}",
            f"sqlmap:risk:{risk}",
        }
    )

    metadata: Dict[str, Any] = {}
    if rejected_hosts:
        metadata["rejected_hosts"] = rejected_hosts

    return sanitized_parameters, tags, metadata


def _is_http_target(scope: str) -> bool:
    value = scope.strip().lower()
    return value.startswith("http://") or value.startswith("https://")


class Settings(BaseSettings):
    """Runtime configuration for the controller service."""

    database_url: str = Field(
        "postgresql+psycopg2://medusa:medusa@localhost:5432/medusa",
        description="SQLAlchemy URL for the Postgres database.",
    )
    redis_url: str = Field(
        "redis://localhost:6379/0",
        description="Connection string for Redis queue backend.",
    )
    nuclei_queue_channel: str = Field(
        "queues:nuclei:jobs", description="Redis list channel for nuclei scan jobs."
    )
    zap_queue_channel: str = Field(
        "queues:zap:jobs", description="Redis list channel for ZAP scan jobs."
    )
    sqlmap_queue_channel: str = Field(
        "queues:sqlmap:jobs", description="Redis list channel for SQLMap scan jobs."
    )
    jwt_secret: str = Field(
        ..., description="JWT secret used to validate bearer tokens."
    )
    api_keys: List[str] = Field(
        default_factory=list,
        description="Static API keys for service accounts granted admin roles by default.",
    )
    cve_enrichment_queue_channel: str = Field(
        "queues:enrichment:cve",
        description="Redis list channel for CVE enrichment jobs.",
    )
    binary_preprocess_queue_channel: str = Field(
        "queues:binary:preprocess",
        description="Redis list channel for binary preprocessing jobs.",
    )
    binary_static_analysis_queue_channel: str = Field(
        "queues:binary:static-analysis",
        description="Redis list channel for binary static analysis jobs.",
    )
    binary_fuzzing_queue_channel: str = Field(
        "queues:binary:fuzzing",
        description="Redis list channel for binary fuzzing jobs.",
    )
    cve_enrichment_qdrant_url: Optional[str] = Field(
        default=None,
        description="Base URL for the Qdrant vector collection used by enrichment workers.",
    )
    cve_enrichment_qdrant_collection: Optional[str] = Field(
        default=None,
        description="Collection name that stores advisory embeddings.",
    )
    nuclei_callback_token: str = Field(
        ..., description="Shared secret token required for nuclei worker callbacks."
    )
    zap_callback_token: str = Field(
        ..., description="Shared secret token required for ZAP worker callbacks."
    )
    sqlmap_callback_token: str = Field(
        ..., description="Shared secret token required for SQLMap worker callbacks."
    )
    enrichment_callback_token: str = Field(
        ..., description="Shared secret required for enrichment worker callbacks."
    )
    binary_static_analysis_callback_token: str = Field(
        ...,
        description="Shared secret required for binary static analysis worker callbacks.",
    )
    binary_fuzzing_callback_token: str = Field(
        ..., description="Shared secret required for binary fuzzing worker callbacks."
    )

    model_config = ConfigDict(env_prefix="MEDUSA_", case_sensitive=False)


@lru_cache()
def get_settings() -> Settings:
    """Return cached settings instance loaded from environment."""

    return Settings()


security_scheme = HTTPBearer(auto_error=False)


def _normalize_payload(payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Ensure JSON payloads are deterministic dictionaries."""

    if payload is None:
        return {}
    return payload


Network = Union[IPv4Network, IPv6Network]


def _normalize_hostname(value: str) -> str:
    """Return a lowercase hostname without trailing dots or wildcard prefixes."""

    normalized = value.strip().lower().rstrip(".")
    if normalized.startswith("*."):
        normalized = normalized[2:]
    return normalized


def _hash_secret(secret: str) -> str:
    """Return a SHA-256 hash of the provided secret."""

    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


KEY_FINGERPRINT_LENGTH = 12


def _fingerprint_from_hash(key_hash: Optional[str]) -> Optional[str]:
    """Return a short fingerprint derived from a credential hash."""

    if not key_hash:
        return None
    return key_hash[:KEY_FINGERPRINT_LENGTH]


def _scope_to_network(scope: str) -> Optional[Network]:
    """Attempt to parse the target scope as an IP network."""

    try:
        return ip_network(scope, strict=False)
    except ValueError:
        return None


def _coerce_requested_hosts(value: Any) -> List[str]:
    """Normalize arbitrary iterables into a list of host strings."""

    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, dict)):
        return [str(item) for item in value]
    raise TypeError("requested_hosts must be an iterable of host strings")


def _filter_hosts_for_scope(
    scope: str, requested_hosts: Iterable[str]
) -> Tuple[List[str], List[str]]:
    """Return hosts within scope alongside those rejected."""

    network = _scope_to_network(scope)
    normalized_scope = _normalize_hostname(scope) if network is None else ""

    allowed: List[str] = []
    rejected: List[str] = []
    allowed_seen: set[str] = set()
    rejected_seen: set[str] = set()

    for raw in requested_hosts:
        candidate = _normalize_hostname(str(raw))
        if not candidate:
            continue

        if network is not None:
            try:
                ip_value = ip_address(candidate)
            except ValueError:
                if candidate not in rejected_seen:
                    rejected.append(candidate)
                    rejected_seen.add(candidate)
                continue

            canonical = str(ip_value)
            if ip_value in network:
                if canonical not in allowed_seen:
                    allowed.append(canonical)
                    allowed_seen.add(canonical)
            else:
                if canonical not in rejected_seen:
                    rejected.append(canonical)
                    rejected_seen.add(canonical)
            continue

        if candidate == normalized_scope or candidate.endswith(f".{normalized_scope}"):
            if candidate not in allowed_seen:
                allowed.append(candidate)
                allowed_seen.add(candidate)
        else:
            if candidate not in rejected_seen:
                rejected.append(candidate)
                rejected_seen.add(candidate)

    return allowed, rejected


class TargetCreateRequest(BaseModel):
    name: str = Field(
        ..., min_length=1, max_length=255, description="Friendly target name"
    )
    scope: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Scoped asset identifier (FQDN, CIDR, or service descriptor)",
    )
    is_authorized: bool = Field(
        default=True,
        description="Whether the asset remains within the approved engagement scope",
    )


class TargetResponse(BaseModel):
    id: str
    name: str
    scope: str
    is_authorized: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TargetCollectionResponse(BaseModel):
    data: List[TargetResponse]


class ScanRequest(BaseModel):
    target_id: str
    scanner: Literal[SCAN_TYPE_NUCLEI, SCAN_TYPE_ZAP, SCAN_TYPE_SQLMAP] = Field(
        description="Scanner identifier"
    )
    parameters: Dict[str, Any] = Field(
        default_factory=dict, description="Scanner-specific configuration payload"
    )


class BinaryPreprocessRequest(BaseModel):
    target_id: str
    object_bucket: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Bucket containing the uploaded artifact",
    )
    object_key: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description="Object key referencing the uploaded artifact",
    )
    file_name: Optional[str] = Field(
        default=None,
        max_length=255,
        description="Optional analyst-supplied filename to retain for context",
    )
    expected_scope: Optional[str] = Field(
        default=None,
        description="Optional assertion matching the controller's stored target scope",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary metadata forwarded to the preprocess worker",
    )


class BinaryStaticAnalysisRequest(BaseModel):
    sample_id: str = Field(
        ..., description="Identifier of the normalized binary sample to analyze"
    )
    target_id: Optional[str] = Field(
        default=None,
        description="Optional assertion ensuring the sample belongs to the expected target",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Operator-provided hints recorded with the analysis job",
    )


class BinaryFuzzingRequest(BaseModel):
    sample_id: str = Field(
        ..., description="Identifier of the normalized binary sample to fuzz"
    )
    target_id: Optional[str] = Field(
        default=None,
        description="Optional assertion ensuring the sample belongs to the expected target",
    )
    fuzz_duration_seconds: Optional[int] = Field(
        default=None,
        ge=60,
        le=86400,
        description="Optional override for the maximum fuzzing duration in seconds",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Operator-provided hints recorded with the fuzzing job",
    )


class ScanResponse(BaseModel):
    id: str
    target_id: str
    target: str
    scanner: str
    status: str
    initiated_by: Optional[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    findings_count: int

    model_config = ConfigDict(from_attributes=True)


class ScanCollectionResponse(BaseModel):
    data: List[ScanResponse]


class AuditLogResponse(BaseModel):
    id: str
    actor: str
    action: str
    message: Optional[str]
    scan_id: Optional[str]
    finding_id: Optional[str]
    evidence_snapshot: Dict[str, Any]
    evidence_hash: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PaginationMetadata(BaseModel):
    total: int
    limit: int
    offset: int


class AuditLogCollectionResponse(BaseModel):
    data: List[AuditLogResponse]
    meta: PaginationMetadata


class StaticAnalysisArtifactPayload(BaseModel):
    tool: str
    bucket: str
    key: str


class StaticAnalysisFindingPayload(BaseModel):
    tool: str
    severity: str
    title: str
    description: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    artifact_bucket: Optional[str] = None
    artifact_key: Optional[str] = None
    executed_at: datetime


class StaticAnalysisReportPayload(BaseModel):
    tool: str
    status: Literal["completed", "failed"]
    exit_code: int
    stdout: str
    stderr: str
    raw_output: Dict[str, Any] = Field(default_factory=dict)
    findings: List[StaticAnalysisFindingPayload] = Field(default_factory=list)
    artifact: Optional[StaticAnalysisArtifactPayload] = None
    executed_at: Optional[datetime] = None


class StaticAnalysisCallbackRequest(BaseModel):
    job_id: str
    scan_id: str
    sample_id: str
    status: Literal["completed", "failed"]
    processed_at: datetime
    findings: List[StaticAnalysisFindingPayload] = Field(default_factory=list)
    artifacts: List[StaticAnalysisArtifactPayload] = Field(default_factory=list)
    reports: List[StaticAnalysisReportPayload] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None


class FuzzingArtifactPayload(BaseModel):
    tool: str
    bucket: str
    key: str


class FuzzingFindingPayload(BaseModel):
    tool: str
    severity: str
    title: str
    description: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    artifact_bucket: Optional[str] = None
    artifact_key: Optional[str] = None
    executed_at: datetime
    crash_type: Optional[str] = None

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        allowed = {"critical", "high", "medium", "low", "info"}
        lowered = value.lower()
        if lowered not in allowed:
            raise ValueError("Unsupported severity level")
        return lowered


class FuzzingRunPayload(BaseModel):
    tool: str
    status: Literal["completed", "failed"]
    exit_code: int
    stdout: str
    stderr: str
    raw_output: Dict[str, Any] = Field(default_factory=dict)
    findings: List[FuzzingFindingPayload] = Field(default_factory=list)
    artifact: Optional[FuzzingArtifactPayload] = None
    executed_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None


class FuzzingCallbackRequest(BaseModel):
    job_id: str
    scan_id: str
    sample_id: str
    status: Literal["completed", "failed"]
    processed_at: datetime
    findings: List[FuzzingFindingPayload] = Field(default_factory=list)
    artifacts: List[FuzzingArtifactPayload] = Field(default_factory=list)
    runs: List[FuzzingRunPayload] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None


SUPPORTED_ENRICHMENT_SOURCES = {"nvd", "circl"}
DEFAULT_ENRICHMENT_SOURCES = ["nvd", "circl"]


class EnrichmentRequest(BaseModel):
    finding_id: str = Field(
        ..., description="Identifier of the finding requiring CVE enrichment"
    )
    sources: List[str] = Field(
        default_factory=lambda: list(DEFAULT_ENRICHMENT_SOURCES),
        description="Deterministic advisory feeds to consult",
    )

    @field_validator("sources", mode="before")
    @classmethod
    def _normalize_sources(cls, value: Any) -> List[str]:
        if value is None:
            return list(DEFAULT_ENRICHMENT_SOURCES)
        if isinstance(value, str):
            value = [value]
        normalized: List[str] = []
        for source in value:
            source_str = str(source).lower()
            if source_str not in SUPPORTED_ENRICHMENT_SOURCES:
                raise ValueError(f"Unsupported enrichment source: {source}")
            if source_str not in normalized:
                normalized.append(source_str)
        return normalized


class EnrichmentResponse(BaseModel):
    job_id: str
    finding_id: str
    queued_at: datetime
    sources: List[str] = Field(default_factory=list)


class FindingEnrichmentSummary(BaseModel):
    id: str
    job_id: str
    generated_at: datetime
    recorded_at: datetime
    advisories: List[Dict[str, Any]] = Field(default_factory=list)
    advisories_hash: str
    errors: Dict[str, str] = Field(default_factory=dict)
    errors_hash: str
    provenance: Dict[str, Any] = Field(default_factory=dict)
    provenance_hash: str
    payload_hash: str


class FindingTicketSummary(BaseModel):
    id: str
    integration: str
    reference: str
    status: str
    url: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class FindingCommentSummary(BaseModel):
    id: str
    author: str
    message: str
    created_at: datetime


class FindingResponse(BaseModel):
    id: str
    scan_id: str
    title: str
    severity: str
    cve_id: Optional[str]
    description: str
    detected_at: datetime
    updated_at: datetime
    status: str
    template_id: str
    evidence: Optional[str]
    remediation: Optional[str]
    enrichments: List[FindingEnrichmentSummary] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    scanner: str
    sample_id: Optional[str] = None
    tool: Optional[str] = None
    category: Literal["web", "binary_static", "binary_fuzzing"]
    assigned_to: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    comment_count: int = 0
    tickets: List[FindingTicketSummary] = Field(default_factory=list)


class FindingCollectionResponse(BaseModel):
    data: List[FindingResponse]


class FindingItemResponse(BaseModel):
    data: FindingResponse


class FindingCommentCollectionResponse(BaseModel):
    data: List[FindingCommentSummary]


class FindingTimelineEvent(BaseModel):
    kind: str
    actor: str
    created_at: datetime
    message: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class FindingTimelineResponse(BaseModel):
    data: List[FindingTimelineEvent]


class FindingTimelineBucket(BaseModel):
    date: datetime
    open: int
    acknowledged: int
    resolved: int
    total: int


class FindingTimelineCollectionResponse(BaseModel):
    data: List[FindingTimelineBucket]


class FindingAssignmentRequest(BaseModel):
    assignee: str = Field(..., min_length=1, max_length=128)


class FindingStatusUpdateRequest(BaseModel):
    status: Literal["open", "acknowledged", "resolved"]


class FindingTagsUpdateRequest(BaseModel):
    tags: List[str] = Field(default_factory=list)


class FindingCommentRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)


class ReportExportRequest(BaseModel):
    format: Literal["html", "pdf"] = "html"
    finding_ids: List[str] = Field(default_factory=list)
    scan_id: Optional[str] = None

    @field_validator("finding_ids", mode="before")
    @classmethod
    def _normalize_ids(cls, value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray)):
            normalized: List[str] = []
            for item in value:
                if not isinstance(item, str):
                    continue
                candidate = item.strip()
                if candidate:
                    normalized.append(candidate)
            return normalized
        return []

    @model_validator(mode="after")
    def _ensure_scope(self) -> "ReportExportRequest":
        if not self.finding_ids and not self.scan_id:
            raise ValueError("Provide at least one finding_id or scan_id for export")
        return self


class ReportExportResponse(BaseModel):
    report_id: str
    format: Literal["html", "pdf"]
    generated_at: datetime
    finding_count: int
    content: str = Field(description="Base64-encoded report content")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class JiraTicketRequest(BaseModel):
    finding_id: str = Field(..., min_length=1)
    project_key: str = Field(..., min_length=2, max_length=10)
    issue_type: str = Field(default="Bug", min_length=1, max_length=64)
    summary: str = Field(..., min_length=5, max_length=255)
    description: Optional[str] = None


class GitHubTicketRequest(BaseModel):
    finding_id: str = Field(..., min_length=1)
    repository: str = Field(..., min_length=2, max_length=200)
    title: str = Field(..., min_length=5, max_length=255)
    body: Optional[str] = None


class TicketResponse(BaseModel):
    id: str
    integration: str
    reference: str
    status: str
    url: Optional[str]
    created_at: datetime
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CallbackFinding(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)
    severity: str = Field(..., min_length=1, max_length=32)
    description: str = Field(..., min_length=1)
    cve_id: Optional[str] = Field(None, max_length=64)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    evidence: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        allowed = {"critical", "high", "medium", "low", "info"}
        lowered = value.lower()
        if lowered not in allowed:
            raise ValueError("Unsupported severity level")
        return lowered


class ScanCallbackRequest(BaseModel):
    scan_id: str
    status: str = Field(..., min_length=1, max_length=32)
    findings: List[CallbackFinding] = Field(default_factory=list)
    error: Optional[str] = Field(default=None)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str) -> str:
        allowed = {"completed", "failed"}
        lowered = value.lower()
        if lowered not in allowed:
            raise ValueError("Unsupported scan status")
        return lowered


NucleiCallbackRequest = ScanCallbackRequest


class Principal(BaseModel):
    subject: str
    auth_method: str
    roles: List[str] = Field(default_factory=list)

    def has_role(self, role: str) -> bool:
        return role in self.roles

    def has_any_role(self, roles: Iterable[str]) -> bool:
        role_set = set(self.roles)
        return any(role in role_set for role in roles)


class PrincipalCredentialCreateRequest(BaseModel):
    subject: str = Field(..., min_length=1, max_length=255)
    auth_method: Literal["api_key", "jwt"]
    roles: List[str] = Field(default_factory=list)
    description: Optional[str] = Field(default=None, max_length=255)
    secret: Optional[str] = Field(default=None, min_length=8, max_length=255)

    @field_validator("roles", mode="before")
    @classmethod
    def _normalize_roles(cls, value: Optional[List[str]]) -> List[str]:
        roles: List[str] = list(value or [])
        seen: set[str] = set()
        normalized: List[str] = []
        for role in roles:
            if role and role not in seen:
                seen.add(role)
                normalized.append(role)
        return normalized

    @field_validator("roles")
    @classmethod
    def _validate_roles(cls, value: List[str]) -> List[str]:
        invalid = [role for role in value if role not in ALLOWED_ROLES]
        if invalid:
            raise ValueError(
                f"Unsupported roles requested: {', '.join(sorted(invalid))}"
            )
        return value


class PrincipalCredentialResponse(BaseModel):
    id: int
    subject: str
    auth_method: str
    roles: List[str] = Field(default_factory=list)
    description: Optional[str]
    created_at: datetime
    revoked_at: Optional[datetime]
    key_fingerprint: Optional[str] = Field(
        default=None,
        description=(
            "Non-secret identifier derived from the credential hash to assist with"
            " rotation tracking."
        ),
    )

    @field_validator("roles", mode="before")
    @classmethod
    def _ensure_roles(cls, value: Optional[List[str]]) -> List[str]:
        return list(value or [])

    model_config = ConfigDict(from_attributes=True)


class PrincipalCredentialCollectionResponse(BaseModel):
    data: List[PrincipalCredentialResponse]


class PrincipalCredentialCreatedResponse(PrincipalCredentialResponse):
    secret: Optional[str] = None


def _serialize_principal_credential(
    credential: PrincipalCredential,
) -> PrincipalCredentialResponse:
    """Return a response model populated with safe credential metadata."""

    fingerprint = _fingerprint_from_hash(credential.key_hash)
    base_response = PrincipalCredentialResponse.model_validate(
        credential, from_attributes=True
    )
    return base_response.model_copy(update={"key_fingerprint": fingerprint})


class QueueClient:
    """Abstract queue client that can enqueue scan jobs."""

    def enqueue(
        self, channel: str, payload: Dict[str, Any]
    ) -> None:  # pragma: no cover - interface definition
        raise NotImplementedError


class RedisQueueClient(QueueClient):
    """Redis-backed queue client pushing serialized jobs into a list."""

    def __init__(self, redis_url: str) -> None:
        self._redis_url = redis_url
        self._client: Optional[Redis] = None

    @property
    def client(self) -> Redis:
        if self._client is None:
            self._client = Redis.from_url(
                self._redis_url, encoding="utf-8", decode_responses=True
            )
        return self._client

    def enqueue(self, channel: str, payload: Dict[str, Any]) -> None:
        serialized = json.dumps(payload, sort_keys=True)
        # rpush appends jobs to the right side of the list, providing FIFO ordering.
        self.client.rpush(channel, serialized)


def get_db_session() -> Iterator[Session]:
    """Yield a SQLAlchemy session bound to the configured engine."""

    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def get_queue_client(settings: Settings = Depends(get_settings)) -> QueueClient:
    return RedisQueueClient(settings.redis_url)


def _authenticate_callback_worker(
    request: Request,
    *,
    expected_token: str,
    subject: str,
    db: Session,
    resource_id: str,
) -> Principal:
    token = request.headers.get(CALLBACK_TOKEN_HEADER)
    if not token or not secrets.compare_digest(token, expected_token):
        worker_principal = Principal(subject=subject, auth_method="shared_secret")
        log_access_denied(
            db,
            principal=worker_principal,
            required_roles=[],
            resource_type="worker_callback",
            resource_id=resource_id,
            reason="invalid_callback_token",
            detail="Invalid callback token",
            status_code=status.HTTP_401_UNAUTHORIZED,
            extra_metadata={"token_provided": bool(token)},
        )
    return Principal(subject=subject, auth_method="shared_secret")


def _authenticate_api_key(
    candidate_api_key: str,
    *,
    db: Session,
    settings: Settings,
    source: str,
    silent: bool = False,
) -> Optional[Principal]:
    """Authenticate an API key against the credential store."""

    api_key_hash = _hash_secret(candidate_api_key)
    fingerprint = _fingerprint_from_hash(api_key_hash)

    if candidate_api_key in settings.api_keys:
        subject_hash = _hash_secret(candidate_api_key)
        return Principal(
            subject=f"apikey:{subject_hash}",
            auth_method="api_key",
            roles=list(DEFAULT_ADMIN_ROLES),
        )

    active_credential = (
        db.query(PrincipalCredential)
        .filter(
            PrincipalCredential.auth_method == "api_key",
            PrincipalCredential.key_hash == api_key_hash,
            PrincipalCredential.revoked_at.is_(None),
        )
        .first()
    )
    if active_credential:
        return Principal(
            subject=active_credential.subject,
            auth_method="api_key",
            roles=list(active_credential.roles or []),
        )

    revoked_credential = (
        db.query(PrincipalCredential)
        .filter(
            PrincipalCredential.auth_method == "api_key",
            PrincipalCredential.key_hash == api_key_hash,
            PrincipalCredential.revoked_at.isnot(None),
        )
        .first()
    )
    if revoked_credential:
        LOGGER.warning(
            "Rejected revoked API key",
            extra={"subject": revoked_credential.subject},
        )
        revoked_principal = Principal(
            subject=revoked_credential.subject,
            auth_method="api_key",
            roles=list(revoked_credential.roles or []),
        )
        log_access_denied(
            db,
            principal=revoked_principal,
            required_roles=[],
            resource_type="principal_credential",
            resource_id=str(revoked_credential.id),
            reason="credential_revoked",
            detail="API key revoked",
            status_code=status.HTTP_401_UNAUTHORIZED,
            extra_metadata={
                "credential_id": str(revoked_credential.id),
                "credential_status": "revoked",
                "key_fingerprint": _fingerprint_from_hash(revoked_credential.key_hash),
                "api_key_source": source,
            },
        )

    if silent:
        return None

    anonymous_principal = Principal(
        subject=f"apikey:{fingerprint}" if fingerprint else "apikey:unknown",
        auth_method="api_key",
        roles=[],
    )
    log_access_denied(
        db,
        principal=anonymous_principal,
        required_roles=[],
        resource_type="principal_credential",
        resource_id=None,
        reason="credential_not_found",
        detail="API key not recognized",
        status_code=status.HTTP_401_UNAUTHORIZED,
        extra_metadata={
            "credential_status": "unknown",
            "key_fingerprint": fingerprint,
            "api_key_source": source,
        },
    )


def _authenticate_jwt(
    token: str,
    *,
    settings: Settings,
    db: Session,
) -> Principal:
    """Authenticate a JWT bearer token and enforce credential state."""

    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
    except jwt.PyJWTError as exc:  # pragma: no cover - exercised indirectly
        LOGGER.warning("JWT validation failed", extra={"error": str(exc)})
        invalid_principal = Principal(
            subject="jwt:invalid",
            auth_method="jwt",
            roles=[],
        )
        log_access_denied(
            db,
            principal=invalid_principal,
            required_roles=[],
            resource_type="principal_credential",
            resource_id=None,
            reason="invalid_token",
            detail="Invalid token",
            status_code=status.HTTP_401_UNAUTHORIZED,
            extra_metadata={"error": str(exc)},
        )

    subject = payload.get("sub")
    if not subject:
        anonymous_principal = Principal(
            subject="jwt:anonymous",
            auth_method="jwt",
            roles=[],
        )
        log_access_denied(
            db,
            principal=anonymous_principal,
            required_roles=[],
            resource_type="principal_credential",
            resource_id=None,
            reason="invalid_token_payload",
            detail="Invalid token payload",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    record = (
        db.query(PrincipalCredential)
        .filter(
            PrincipalCredential.auth_method == "jwt",
            PrincipalCredential.subject == subject,
            PrincipalCredential.revoked_at.is_(None),
        )
        .first()
    )
    if record is None:
        unauthorized_principal = Principal(
            subject=subject,
            auth_method="jwt",
            roles=[],
        )
        log_access_denied(
            db,
            principal=unauthorized_principal,
            required_roles=[],
            resource_type="principal_credential",
            resource_id=None,
            reason="subject_not_authorized",
            detail="Subject not authorized",
            status_code=status.HTTP_403_FORBIDDEN,
        )

    roles = list(record.roles or [])
    return Principal(subject=record.subject, auth_method="jwt", roles=roles)


def authenticate(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    db: Session = Depends(get_db_session),
    settings: Settings = Depends(get_settings),
) -> Principal:
    """Authenticate API requests via API key header or bearer JWT."""

    api_key_header = request.headers.get("X-API-Key")
    bearer_token = credentials.credentials if credentials else None

    if api_key_header:
        principal = _authenticate_api_key(
            api_key_header,
            db=db,
            settings=settings,
            source="header",
        )
        if principal is not None:
            return principal

    if bearer_token:
        return _authenticate_jwt(bearer_token, settings=settings, db=db)

    anonymous = Principal(subject="anonymous", auth_method="unauthenticated", roles=[])
    log_access_denied(
        db,
        principal=anonymous,
        required_roles=[],
        resource_type="endpoint",
        resource_id=str(request.url.path),
        reason="missing_credentials",
        detail="Authentication required",
        status_code=status.HTTP_401_UNAUTHORIZED,
    )


def authenticate_nuclei_worker(
    request: Request,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db_session),
) -> Principal:
    """Authenticate nuclei worker callbacks using a shared secret header."""

    return _authenticate_callback_worker(
        request,
        expected_token=settings.nuclei_callback_token,
        subject="worker:nuclei",
        db=db,
        resource_id="nuclei",
    )


def authenticate_enrichment_worker(
    request: Request,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db_session),
) -> Principal:
    """Authenticate enrichment worker callbacks using a dedicated shared secret."""

    return _authenticate_callback_worker(
        request,
        expected_token=settings.enrichment_callback_token,
        subject="worker:enrichment",
        db=db,
        resource_id="enrichment",
    )


def authenticate_zap_worker(
    request: Request,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db_session),
) -> Principal:
    """Authenticate ZAP worker callbacks using a shared secret header."""

    return _authenticate_callback_worker(
        request,
        expected_token=settings.zap_callback_token,
        subject="worker:zap",
        db=db,
        resource_id="zap",
    )


def authenticate_sqlmap_worker(
    request: Request,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db_session),
) -> Principal:
    """Authenticate SQLMap worker callbacks using a shared secret header."""

    return _authenticate_callback_worker(
        request,
        expected_token=settings.sqlmap_callback_token,
        subject="worker:sqlmap",
        db=db,
        resource_id="sqlmap",
    )


def authenticate_binary_static_analysis_worker(
    request: Request,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db_session),
) -> Principal:
    """Authenticate binary static analysis worker callbacks."""

    return _authenticate_callback_worker(
        request,
        expected_token=settings.binary_static_analysis_callback_token,
        subject="worker:binary-static-analysis",
        db=db,
        resource_id="binary-static-analysis",
    )


def authenticate_binary_fuzzing_worker(
    request: Request,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db_session),
) -> Principal:
    """Authenticate binary fuzzing worker callbacks."""

    return _authenticate_callback_worker(
        request,
        expected_token=settings.binary_fuzzing_callback_token,
        subject="worker:binary-fuzzing",
        db=db,
        resource_id="binary-fuzzing",
    )


def log_access_denied(
    session: Session,
    *,
    principal: Principal,
    required_roles: Iterable[str],
    resource_type: str = "endpoint",
    resource_id: Optional[str] = None,
    reason: Optional[str] = None,
    detail: str = "Insufficient role for this operation",
    status_code: int = status.HTTP_403_FORBIDDEN,
    extra_metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """Record an audit trail for denied access before raising an error."""

    required_list = sorted({role for role in required_roles if role})
    granted_list = sorted({role for role in principal.roles})
    granted_set = set(granted_list)
    missing_roles = [role for role in required_list if role not in granted_set]

    metadata: Dict[str, Any] = {
        "required_roles": required_list,
        "granted_roles": granted_list,
        "auth_method": principal.auth_method,
    }
    if missing_roles:
        metadata["missing_roles"] = missing_roles
    if reason:
        metadata["reason"] = reason
    if extra_metadata:
        metadata.update(extra_metadata)

    record_audit_event(
        session,
        actor=principal,
        action="access_denied",
        resource_type=resource_type,
        resource_id=resource_id,
        metadata=metadata,
    )

    raise HTTPException(status_code=status_code, detail=detail)


def enforce_roles(
    principal: Principal,
    required_roles: Iterable[str],
    session: Session,
    *,
    resource_type: str = "endpoint",
    resource_id: Optional[str] = None,
) -> None:
    normalized_roles = list(dict.fromkeys(required_roles))
    if principal.has_role(ROLE_ADMIN):
        return
    if not principal.has_any_role(normalized_roles):
        log_access_denied(
            session,
            principal=principal,
            required_roles=normalized_roles,
            resource_type=resource_type,
            resource_id=resource_id,
            reason="missing_required_roles",
        )


def record_audit_event(
    session: Session,
    *,
    actor: Principal,
    action: str,
    resource_type: str,
    resource_id: Optional[str],
    metadata: Optional[Dict[str, Any]] = None,
    scan_id: Optional[str] = None,
    finding_id: Optional[str] = None,
    message: Optional[str] = None,
) -> AuditLog:
    """Persist and emit audit information about sensitive operations."""

    snapshot: Dict[str, Any] = metadata.copy() if metadata else {}
    snapshot.setdefault("resource_type", resource_type)
    if resource_id is not None:
        snapshot.setdefault("resource_id", resource_id)
    if scan_id is not None:
        snapshot.setdefault("scan_id", scan_id)
    if finding_id is not None:
        snapshot.setdefault("finding_id", finding_id)
    if message:
        snapshot.setdefault("message", message)

    entry = AuditLog(
        scan_id=scan_id,
        finding_id=finding_id,
        actor=actor.subject,
        action=action,
        message=message,
        evidence_snapshot=snapshot,
        evidence_hash="",
    )
    session.add(entry)
    try:
        session.commit()
        session.refresh(entry)
    except SQLAlchemyError:
        session.rollback()
        LOGGER.exception("Failed to persist audit event", extra={"action": action})
        raise

    AUDIT_LOGGER.info(
        "audit_event",
        extra={
            "actor": actor.subject,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "metadata": snapshot,
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        },
    )

    metrics.record_audit_event(action)

    return entry


app = FastAPI(title="Medusa Controller", version="0.1.0")


@app.middleware("http")
async def record_metrics_middleware(request: Request, call_next):
    """Capture request metrics for Prometheus."""

    start_time = time.perf_counter()
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    finally:
        duration = time.perf_counter() - start_time
        route = request.scope.get("route")
        endpoint = getattr(route, "path", request.url.path)
        metrics.observe_http_request(
            method=request.method,
            endpoint=endpoint,
            status_code=status_code,
            duration_seconds=duration,
        )


@app.get("/metrics", include_in_schema=False)
def metrics_endpoint() -> Response:
    """Expose controller metrics in Prometheus text format."""

    return Response(
        content=metrics.render_latest(), media_type=metrics.CONTENT_TYPE_LATEST
    )


@app.get("/principals", response_model=PrincipalCredentialCollectionResponse)
def list_principals(
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
) -> PrincipalCredentialCollectionResponse:
    enforce_roles(
        principal,
        [ROLE_ADMIN],
        db,
        resource_type="endpoint",
        resource_id="/principals",
    )
    records = (
        db.query(PrincipalCredential)
        .order_by(PrincipalCredential.created_at.desc())
        .all()
    )
    response_items = [_serialize_principal_credential(record) for record in records]

    record_audit_event(
        db,
        actor=principal,
        action="list_principals",
        resource_type="principal",
        resource_id=None,
        metadata={"count": len(response_items)},
    )

    return PrincipalCredentialCollectionResponse(data=response_items)


@app.get("/audit-log", response_model=AuditLogCollectionResponse)
def list_audit_log(
    actor: Optional[str] = None,
    action: Optional[str] = None,
    scan_id: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
) -> AuditLogCollectionResponse:
    """Return audit log entries for administrative review."""

    enforce_roles(
        principal,
        [ROLE_ADMIN],
        db,
        resource_type="endpoint",
        resource_id="/audit-log",
    )

    query = db.query(AuditLog)
    applied_filters: Dict[str, Any] = {}

    if actor:
        query = query.filter(AuditLog.actor == actor)
        applied_filters["actor"] = actor
    if action:
        query = query.filter(AuditLog.action == action)
        applied_filters["action"] = action
    if scan_id:
        query = query.filter(AuditLog.scan_id == scan_id)
        applied_filters["scan_id"] = scan_id

    total = query.count()
    records = (
        query.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit).all()
    )

    response_items = [
        AuditLogResponse.model_validate(record, from_attributes=True)
        for record in records
    ]

    metadata: Dict[str, Any] = {
        "limit": limit,
        "offset": offset,
        "returned": len(response_items),
    }
    if applied_filters:
        metadata["filters"] = applied_filters

    record_audit_event(
        db,
        actor=principal,
        action="list_audit_log",
        resource_type="audit_log",
        resource_id=None,
        metadata=metadata,
    )

    return AuditLogCollectionResponse(
        data=response_items,
        meta=PaginationMetadata(total=total, limit=limit, offset=offset),
    )


@app.post(
    "/principals",
    response_model=PrincipalCredentialCreatedResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_principal_credential(
    request: PrincipalCredentialCreateRequest,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
) -> PrincipalCredentialCreatedResponse:
    enforce_roles(
        principal,
        [ROLE_ADMIN],
        db,
        resource_type="endpoint",
        resource_id="/principals",
    )

    existing = (
        db.query(PrincipalCredential)
        .filter(PrincipalCredential.subject == request.subject)
        .filter(PrincipalCredential.revoked_at.is_(None))
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Principal subject already exists",
        )

    secret = request.secret
    key_hash: Optional[str] = None
    if request.auth_method == "api_key":
        if not secret:
            secret = secrets.token_urlsafe(32)
        key_hash = _hash_secret(secret)
    else:
        if secret:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="JWT principals do not accept shared secrets",
            )

    requested_roles = request.roles
    if ROLE_ADMIN in requested_roles:
        assigned_roles = list(dict.fromkeys(DEFAULT_ADMIN_ROLES))
    elif ROLE_ANALYST in requested_roles or not requested_roles:
        assigned_roles = list(dict.fromkeys(DEFAULT_ANALYST_ROLES))
    else:
        assigned_roles = requested_roles

    credential = PrincipalCredential(
        subject=request.subject,
        auth_method=request.auth_method,
        key_hash=key_hash,
        roles=assigned_roles,
        description=request.description,
    )
    db.add(credential)
    db.commit()
    db.refresh(credential)

    fingerprint = _fingerprint_from_hash(credential.key_hash)
    metadata: Dict[str, Any] = {
        "subject": credential.subject,
        "auth_method": credential.auth_method,
        "roles": credential.roles,
    }
    if fingerprint:
        metadata["rotation"] = {
            "key_fingerprint": fingerprint,
            "issued_at": credential.created_at.isoformat(),
        }

    record_audit_event(
        db,
        actor=principal,
        action="create_principal",
        resource_type="principal",
        resource_id=str(credential.id),
        metadata=metadata,
    )

    base_response = _serialize_principal_credential(credential)
    response_payload = PrincipalCredentialCreatedResponse.model_validate(
        base_response.model_dump()
    )
    if secret is not None:
        response_payload = response_payload.model_copy(update={"secret": secret})
    return response_payload


@app.post(
    "/principals/{credential_id}/revoke",
    response_model=PrincipalCredentialResponse,
)
def revoke_principal_credential(
    credential_id: int,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
) -> PrincipalCredentialResponse:
    enforce_roles(
        principal,
        [ROLE_ADMIN],
        db,
        resource_type="endpoint",
        resource_id=f"/principals/{credential_id}/revoke",
    )

    credential = db.get(PrincipalCredential, credential_id)
    if credential is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Principal not found"
        )

    if credential.revoked_at is None:
        credential.revoked_at = datetime.now(tz=timezone.utc)
        db.add(credential)
        db.commit()
        db.refresh(credential)
    else:
        db.refresh(credential)

    fingerprint = _fingerprint_from_hash(credential.key_hash)
    metadata = {
        "subject": credential.subject,
        "auth_method": credential.auth_method,
        "roles": credential.roles,
        "revoked_at": (
            credential.revoked_at.isoformat() if credential.revoked_at else None
        ),
    }
    if fingerprint:
        metadata["rotation"] = {
            "key_fingerprint": fingerprint,
            "revoked_at": (
                credential.revoked_at.isoformat() if credential.revoked_at else None
            ),
        }

    record_audit_event(
        db,
        actor=principal,
        action="revoke_principal",
        resource_type="principal",
        resource_id=str(credential.id),
        metadata=metadata,
    )

    return _serialize_principal_credential(credential)


@app.post(
    "/targets", response_model=TargetResponse, status_code=status.HTTP_201_CREATED
)
def create_target(
    request: TargetCreateRequest,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
) -> TargetResponse:
    enforce_roles(
        principal,
        [ROLE_TARGETS_WRITE],
        db,
        resource_type="endpoint",
        resource_id="/targets",
    )
    existing = db.query(Target).filter(Target.scope == request.scope).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Target scope already registered",
        )

    target = Target(
        name=request.name,
        scope=request.scope,
        is_authorized=request.is_authorized,
    )
    db.add(target)
    db.commit()
    db.refresh(target)

    record_audit_event(
        db,
        actor=principal,
        action="create_target",
        resource_type="target",
        resource_id=target.id,
        metadata={"scope": target.scope, "is_authorized": target.is_authorized},
    )

    return TargetResponse.model_validate(target, from_attributes=True)


@app.get("/targets", response_model=TargetCollectionResponse)
def list_targets(
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
) -> TargetCollectionResponse:
    enforce_roles(
        principal,
        [ROLE_TARGETS_READ],
        db,
        resource_type="endpoint",
        resource_id="/targets",
    )
    targets = db.query(Target).order_by(Target.created_at.desc()).all()

    record_audit_event(
        db,
        actor=principal,
        action="list_targets",
        resource_type="target",
        resource_id=None,
        metadata={"count": len(targets)},
    )

    return TargetCollectionResponse(
        data=[
            TargetResponse.model_validate(target, from_attributes=True)
            for target in targets
        ]
    )


@app.post("/scan", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
def enqueue_scan(
    scan_request: ScanRequest,
    http_request: Request,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
    queue: QueueClient = Depends(get_queue_client),
    settings: Settings = Depends(get_settings),
) -> ScanResponse:
    enforce_roles(
        principal,
        [ROLE_SCAN_ENQUEUE],
        db,
        resource_type="endpoint",
        resource_id="/scan",
    )

    target = db.get(Target, scan_request.target_id)
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Target not found"
        )

    if not target.is_authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Target is currently outside the authorized scope",
        )

    for host_key in ("requested_hosts", "allowed_hosts"):
        if host_key in scan_request.parameters:
            try:
                _coerce_requested_hosts(scan_request.parameters.get(host_key))
            except TypeError as exc:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"parameters.{host_key} must be an array of host strings",
                ) from exc

    scan = Scan(
        target_id=target.id,
        scanner=scan_request.scanner,
        parameters={},
        initiated_by=principal.subject,
    )
    db.add(scan)
    db.flush()

    submitted_at = datetime.now(tz=timezone.utc)
    job_id = str(uuid.uuid4())

    base_metadata: Dict[str, Any] = {
        "scan_id": str(scan.id),
        "target_id": str(target.id),
        "target_scope": target.scope,
        "target_name": target.name,
        "initiated_by": principal.subject,
        "submitted_at": submitted_at.isoformat(),
    }

    sanitized_parameters: Dict[str, Any] = {}
    extra_metadata: Dict[str, Any] = {}
    queue_channel: str
    job_payload: Dict[str, Any]
    audit_metadata: Dict[str, Any]
    rejected_hosts: List[str] = []

    if scan.scanner == SCAN_TYPE_NUCLEI:
        (
            profile,
            templates,
            tags,
            sanitized_parameters,
            extra_metadata,
        ) = resolve_nuclei_job_configuration(target.scope, scan_request.parameters)

        if (
            extra_metadata.get("rejected_hosts")
            and extra_metadata.get("requested_host_count")
            and not sanitized_parameters.get("requested_hosts")
        ):
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No requested hosts remain within the authorized target scope",
            )

        scan.parameters = sanitized_parameters
        callback_url = str(http_request.url_for("nuclei_callback"))
        metadata_payload = dict(base_metadata)
        metadata_payload.update(
            {
                "template_profile": profile,
                "controller_callback_url": callback_url,
                "parameters": sanitized_parameters,
            }
        )
        if extra_metadata:
            metadata_payload.update(extra_metadata)

        job_payload = {
            "job_id": job_id,
            "scan_id": str(scan.id),
            "target": target.scope,
            "target_id": str(target.id),
            "target_name": target.name,
            "scanner": scan.scanner,
            "templates": templates,
            "template_profile": profile,
            "parameters": sanitized_parameters,
            "callback_url": callback_url,
            "attempts": 0,
            "tags": tags,
            "initiated_by": principal.subject,
            "submitted_at": submitted_at.isoformat(),
            "metadata": metadata_payload,
        }

        queue_channel = settings.nuclei_queue_channel
        rejected_hosts = list(extra_metadata.get("rejected_hosts", []))
        audit_metadata = {
            "target_id": target.id,
            "scanner": scan.scanner,
            "job_id": job_id,
            "template_profile": profile,
            "requested_host_count": extra_metadata.get("requested_host_count", 0),
            "requested_hosts": sanitized_parameters.get("requested_hosts", []),
            "rejected_hosts": rejected_hosts,
        }
    elif scan.scanner == SCAN_TYPE_ZAP:
        if not _is_http_target(target.scope):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="ZAP scans require an HTTP or HTTPS scope",
            )
        sanitized_parameters, tags, extra_metadata = resolve_zap_job_configuration(
            target.scope, scan_request.parameters
        )
        scan.parameters = sanitized_parameters
        callback_url = str(http_request.url_for("zap_callback"))
        metadata_payload = dict(base_metadata)
        metadata_payload.update(
            {
                "controller_callback_url": callback_url,
                "parameters": sanitized_parameters,
            }
        )
        if extra_metadata:
            metadata_payload.update(extra_metadata)
        job_payload = {
            "job_id": job_id,
            "scan_id": str(scan.id),
            "target": target.scope,
            "target_id": str(target.id),
            "target_name": target.name,
            "scanner": scan.scanner,
            "parameters": sanitized_parameters,
            "callback_url": callback_url,
            "attempts": 0,
            "tags": tags,
            "initiated_by": principal.subject,
            "submitted_at": submitted_at.isoformat(),
            "metadata": metadata_payload,
        }
        queue_channel = settings.zap_queue_channel
        audit_metadata = {
            "target_id": target.id,
            "scanner": scan.scanner,
            "job_id": job_id,
            "policy": sanitized_parameters.get("policy"),
        }
    elif scan.scanner == SCAN_TYPE_SQLMAP:
        if not _is_http_target(target.scope):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="SQLMap scans require an HTTP or HTTPS scope",
            )
        sanitized_parameters, tags, extra_metadata = resolve_sqlmap_job_configuration(
            target.scope, scan_request.parameters
        )
        scan.parameters = sanitized_parameters
        callback_url = str(http_request.url_for("sqlmap_callback"))
        metadata_payload = dict(base_metadata)
        metadata_payload.update(
            {
                "controller_callback_url": callback_url,
                "parameters": sanitized_parameters,
            }
        )
        if extra_metadata:
            metadata_payload.update(extra_metadata)
        job_payload = {
            "job_id": job_id,
            "scan_id": str(scan.id),
            "target": target.scope,
            "target_id": str(target.id),
            "target_name": target.name,
            "scanner": scan.scanner,
            "parameters": sanitized_parameters,
            "callback_url": callback_url,
            "attempts": 0,
            "tags": tags,
            "initiated_by": principal.subject,
            "submitted_at": submitted_at.isoformat(),
            "metadata": metadata_payload,
        }
        queue_channel = settings.sqlmap_queue_channel
        audit_metadata = {
            "target_id": target.id,
            "scanner": scan.scanner,
            "job_id": job_id,
            "level": sanitized_parameters.get("level"),
            "risk": sanitized_parameters.get("risk"),
        }
    else:  # pragma: no cover - literal guard
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported scanner {scan.scanner}",
        )

    scan.parameters = dict(scan.parameters)
    db.commit()
    db.refresh(scan)

    queue.enqueue(queue_channel, job_payload)

    metrics.record_job_enqueued(scan.scanner)

    record_audit_event(
        db,
        actor=principal,
        action="enqueue_scan",
        resource_type="scan",
        resource_id=scan.id,
        scan_id=scan.id,
        metadata=audit_metadata,
    )

    return serialize_scan(scan)


@app.post(
    "/preprocess",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def enqueue_binary_preprocess(
    request: BinaryPreprocessRequest,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
    queue: QueueClient = Depends(get_queue_client),
    settings: Settings = Depends(get_settings),
) -> ScanResponse:
    """Queue a binary preprocessing task for an uploaded artifact."""

    enforce_roles(
        principal,
        [ROLE_BINARY_PREPROCESS_ENQUEUE],
        db,
        resource_type="endpoint",
        resource_id="/preprocess",
    )

    target = db.get(Target, request.target_id)
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Target not found"
        )

    if not target.is_authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Target is currently outside the authorized scope",
        )

    if request.expected_scope:
        provided = _normalize_hostname(request.expected_scope)
        expected = _normalize_hostname(target.scope)
        if provided != expected:
            record_audit_event(
                db,
                actor=principal,
                action="preprocess_scope_mismatch",
                resource_type="target",
                resource_id=target.id,
                metadata={
                    "provided_scope": request.expected_scope,
                    "normalized_provided": provided,
                    "expected_scope": expected,
                },
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Target scope assertion failed",
            )

    scan = Scan(
        target_id=target.id,
        scanner="binary_preprocess",
        parameters={
            "object_bucket": request.object_bucket,
            "object_key": request.object_key,
            "file_name": request.file_name,
            "metadata": request.metadata,
        },
        initiated_by=principal.subject,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    submitted_at = datetime.now(tz=timezone.utc)
    job_id = str(uuid.uuid4())

    job_metadata: Dict[str, Any] = {
        "scan_id": str(scan.id),
        "target_id": str(target.id),
        "target_scope": target.scope,
        "target_name": target.name,
        "object_bucket": request.object_bucket,
        "object_key": request.object_key,
        "file_name": request.file_name,
        "submitted_at": submitted_at.isoformat(),
        "initiated_by": principal.subject,
    }
    if request.metadata:
        job_metadata["analyst_metadata"] = request.metadata

    job_payload = {
        "job_id": job_id,
        "scan_id": str(scan.id),
        "target_id": str(target.id),
        "target_scope": target.scope,
        "object_bucket": request.object_bucket,
        "object_key": request.object_key,
        "file_name": request.file_name,
        "submitted_by": principal.subject,
        "submitted_at": submitted_at.isoformat(),
        "metadata": job_metadata,
    }

    queue.enqueue(settings.binary_preprocess_queue_channel, job_payload)

    metrics.record_job_enqueued("binary_preprocess")

    record_audit_event(
        db,
        actor=principal,
        action="enqueue_binary_preprocess",
        resource_type="scan",
        resource_id=scan.id,
        scan_id=scan.id,
        metadata={
            "target_id": target.id,
            "object_bucket": request.object_bucket,
            "object_key": request.object_key,
            "job_id": job_id,
        },
    )

    return serialize_scan(scan)


@app.post(
    "/binary/static-analysis",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def enqueue_binary_static_analysis(
    request: BinaryStaticAnalysisRequest,
    http_request: Request,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
    queue: QueueClient = Depends(get_queue_client),
    settings: Settings = Depends(get_settings),
) -> ScanResponse:
    """Queue a binary static analysis job for a previously normalized sample."""

    enforce_roles(
        principal,
        [ROLE_BINARY_STATIC_ANALYSIS_ENQUEUE],
        db,
        resource_type="endpoint",
        resource_id="/binary/static-analysis",
    )

    sample = db.get(BinarySample, request.sample_id)
    if sample is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Sample not found"
        )

    if request.target_id and request.target_id != sample.target_id:
        record_audit_event(
            db,
            actor=principal,
            action="static_analysis_target_mismatch",
            resource_type="binary_sample",
            resource_id=sample.id,
            scan_id=None,
            metadata={
                "provided_target_id": request.target_id,
                "expected_target_id": sample.target_id,
            },
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Sample does not belong to the asserted target",
        )

    target = db.get(Target, sample.target_id)
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Target not found"
        )

    scan = Scan(
        target_id=sample.target_id,
        scanner=SCAN_TYPE_BINARY_STATIC,
        parameters={
            "sample_id": sample.id,
            "storage_bucket": sample.storage_bucket,
            "storage_key": sample.storage_key,
            "file_name": sample.file_name,
            "metadata": request.metadata,
        },
        initiated_by=principal.subject,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    submitted_at = datetime.now(tz=timezone.utc)
    job_id = str(uuid.uuid4())
    callback_url = str(http_request.url_for("binary_static_analysis_callback"))

    job_metadata: Dict[str, Any] = {
        "scan_id": str(scan.id),
        "sample_id": sample.id,
        "target_id": sample.target_id,
        "target_scope": target.scope,
        "initiated_by": principal.subject,
        "submitted_at": submitted_at.isoformat(),
    }
    if request.metadata:
        job_metadata["analyst_metadata"] = request.metadata

    job_payload = {
        "job_id": job_id,
        "scan_id": str(scan.id),
        "sample_id": sample.id,
        "target_id": sample.target_id,
        "object_bucket": sample.storage_bucket,
        "object_key": sample.storage_key,
        "file_name": sample.file_name,
        "callback_url": callback_url,
        "attempts": 0,
        "submitted_at": submitted_at.isoformat(),
        "metadata": job_metadata,
    }

    queue.enqueue(settings.binary_static_analysis_queue_channel, job_payload)

    metrics.record_job_enqueued(SCAN_TYPE_BINARY_STATIC)

    record_audit_event(
        db,
        actor=principal,
        action="enqueue_binary_static_analysis",
        resource_type="scan",
        resource_id=scan.id,
        scan_id=scan.id,
        metadata={
            "sample_id": sample.id,
            "job_id": job_id,
            "object_bucket": sample.storage_bucket,
            "object_key": sample.storage_key,
        },
    )

    return serialize_scan(scan)


@app.post(
    "/binary/fuzzing",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def enqueue_binary_fuzzing(
    request: BinaryFuzzingRequest,
    http_request: Request,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
    queue: QueueClient = Depends(get_queue_client),
    settings: Settings = Depends(get_settings),
) -> ScanResponse:
    """Queue a binary fuzzing job for a previously normalized sample."""

    enforce_roles(
        principal,
        [ROLE_BINARY_FUZZING_ENQUEUE],
        db,
        resource_type="endpoint",
        resource_id="/binary/fuzzing",
    )

    sample = db.get(BinarySample, request.sample_id)
    if sample is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Sample not found"
        )

    if request.target_id and request.target_id != sample.target_id:
        record_audit_event(
            db,
            actor=principal,
            action="fuzzing_target_mismatch",
            resource_type="binary_sample",
            resource_id=sample.id,
            scan_id=None,
            metadata={
                "provided_target_id": request.target_id,
                "expected_target_id": sample.target_id,
            },
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Sample does not belong to the asserted target",
        )

    target = db.get(Target, sample.target_id)
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Target not found"
        )

    scan = Scan(
        target_id=sample.target_id,
        scanner=SCAN_TYPE_BINARY_FUZZING,
        parameters={
            "sample_id": sample.id,
            "storage_bucket": sample.storage_bucket,
            "storage_key": sample.storage_key,
            "file_name": sample.file_name,
            "metadata": request.metadata,
            "fuzz_duration_seconds": request.fuzz_duration_seconds,
        },
        initiated_by=principal.subject,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    submitted_at = datetime.now(tz=timezone.utc)
    job_id = str(uuid.uuid4())
    callback_url = str(http_request.url_for("binary_fuzzing_callback"))

    job_metadata: Dict[str, Any] = {
        "scan_id": str(scan.id),
        "sample_id": sample.id,
        "target_id": sample.target_id,
        "target_scope": target.scope,
        "initiated_by": principal.subject,
        "submitted_at": submitted_at.isoformat(),
    }
    if request.metadata:
        job_metadata["analyst_metadata"] = request.metadata
    if request.fuzz_duration_seconds:
        job_metadata["requested_duration_seconds"] = request.fuzz_duration_seconds

    job_payload = {
        "job_id": job_id,
        "scan_id": str(scan.id),
        "sample_id": sample.id,
        "target_id": sample.target_id,
        "object_bucket": sample.storage_bucket,
        "object_key": sample.storage_key,
        "file_name": sample.file_name,
        "callback_url": callback_url,
        "attempts": 0,
        "submitted_at": submitted_at.isoformat(),
        "metadata": job_metadata,
    }
    if request.fuzz_duration_seconds:
        job_payload["max_duration_seconds"] = request.fuzz_duration_seconds

    queue.enqueue(settings.binary_fuzzing_queue_channel, job_payload)

    metrics.record_job_enqueued(SCAN_TYPE_BINARY_FUZZING)

    record_audit_event(
        db,
        actor=principal,
        action="enqueue_binary_fuzzing",
        resource_type="scan",
        resource_id=scan.id,
        scan_id=scan.id,
        metadata={
            "sample_id": sample.id,
            "job_id": job_id,
            "object_bucket": sample.storage_bucket,
            "object_key": sample.storage_key,
            "requested_duration_seconds": request.fuzz_duration_seconds,
        },
    )

    return serialize_scan(scan)


@app.post(
    "/enrich", response_model=EnrichmentResponse, status_code=status.HTTP_202_ACCEPTED
)
def enqueue_enrichment(
    request: EnrichmentRequest,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
    queue: QueueClient = Depends(get_queue_client),
    settings: Settings = Depends(get_settings),
) -> EnrichmentResponse:
    """Queue a CVE enrichment job for the specified finding."""

    enforce_roles(
        principal,
        [ROLE_ENRICHMENT_ENQUEUE],
        db,
        resource_type="endpoint",
        resource_id="/enrich",
    )

    finding = db.get(Finding, request.finding_id)
    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )

    job_id = str(uuid.uuid4())
    queued_at = datetime.now(tz=timezone.utc)
    job_payload = {
        "job_id": job_id,
        "finding_id": finding.id,
        "scan_id": finding.scan_id,
        "cve_id": finding.cve_id,
        "title": finding.title,
        "severity": finding.severity,
        "metadata": finding.metadata_json,
        "sources": request.sources,
        "requested_by": principal.subject,
        "requested_at": queued_at.isoformat(),
    }
    queue.enqueue(settings.cve_enrichment_queue_channel, job_payload)

    metrics.record_job_enqueued("enrichment_cve")

    record_audit_event(
        db,
        actor=principal,
        action="enqueue_enrichment",
        resource_type="finding",
        resource_id=finding.id,
        scan_id=finding.scan_id,
        finding_id=finding.id,
        metadata={"job_id": job_id, "sources": request.sources},
    )

    return EnrichmentResponse(
        job_id=job_id,
        finding_id=finding.id,
        queued_at=queued_at,
        sources=list(request.sources),
    )


app.add_api_route(
    "/scans",
    enqueue_scan,
    methods=["POST"],
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
)


@app.get("/scans", response_model=ScanCollectionResponse)
def list_scans(
    target_id: Optional[str] = None,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
) -> ScanCollectionResponse:
    """Return the most recent scans for the authenticated principal."""

    enforce_roles(
        principal,
        [ROLE_SCANS_READ],
        db,
        resource_type="endpoint",
        resource_id="/scans",
    )
    query = db.query(Scan).options(
        selectinload(Scan.target), selectinload(Scan.findings)
    )
    if target_id is not None:
        query = query.filter(Scan.target_id == target_id)

    scans = query.order_by(Scan.created_at.desc()).all()

    record_audit_event(
        db,
        actor=principal,
        action="list_scans",
        resource_type="scan",
        resource_id=None,
        metadata={"target_id": target_id, "count": len(scans)},
    )
    return ScanCollectionResponse(data=[serialize_scan(scan) for scan in scans])


def _persist_scan_callback(
    *,
    db: Session,
    scan: Scan,
    payload: ScanCallbackRequest,
    principal: Principal,
    worker_name: str,
) -> int:
    if scan.scanner != worker_name:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan assigned to {scan.scanner} cannot accept {worker_name} callbacks",
        )
    if scan.status in {"completed", "failed"}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Scan already finalized"
        )
    if scan.findings:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Scan findings already recorded",
        )

    if payload.started_at and scan.started_at is None:
        scan.started_at = payload.started_at
    elif scan.started_at is None:
        scan.started_at = datetime.now(tz=timezone.utc)

    scan.status = payload.status
    if payload.status in {"completed", "failed"}:
        scan.completed_at = payload.completed_at or datetime.now(tz=timezone.utc)

    findings_persisted = 0
    for finding_payload in payload.findings:
        metadata_payload = deepcopy(_normalize_payload(finding_payload.metadata))
        if "scanner" not in metadata_payload:
            metadata_payload["scanner"] = scan.scanner
        evidence_payload = deepcopy(_normalize_payload(finding_payload.evidence))
        finding = Finding(
            scan_id=scan.id,
            severity=finding_payload.severity,
            title=finding_payload.title,
            description=finding_payload.description,
            cve_id=finding_payload.cve_id,
            metadata_json=metadata_payload,
            evidence=evidence_payload,
            evidence_hash="",
        )
        db.add(finding)
        findings_persisted += 1

    try:
        db.commit()
    except (
        SQLAlchemyError
    ) as exc:  # pragma: no cover - exercised in error handling tests
        db.rollback()
        LOGGER.exception(
            "Failed to persist %s callback payload",
            worker_name,
            extra={"scan_id": scan.id},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist callback",
        ) from exc

    return findings_persisted


def _handle_scan_callback(
    *,
    db: Session,
    payload: ScanCallbackRequest,
    principal: Principal,
    worker_name: str,
) -> Tuple[Scan, int]:
    scan = db.get(Scan, payload.scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found"
        )

    findings_persisted = _persist_scan_callback(
        db=db,
        scan=scan,
        payload=payload,
        principal=principal,
        worker_name=worker_name,
    )
    return scan, findings_persisted


def _persist_static_analysis_callback(
    *,
    db: Session,
    payload: StaticAnalysisCallbackRequest,
) -> Tuple[Scan, BinarySample, int]:
    scan = db.get(Scan, payload.scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found"
        )
    if scan.scanner != SCAN_TYPE_BINARY_STATIC:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Scan is not assigned to binary static analysis",
        )

    sample = db.get(BinarySample, payload.sample_id)
    if sample is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Sample not found"
        )
    if sample.target_id != scan.target_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Sample target does not match scan target",
        )

    existing = (
        db.query(BinaryStaticAnalysisFinding)
        .filter(
            BinaryStaticAnalysisFinding.scan_id == scan.id,
            BinaryStaticAnalysisFinding.job_id == payload.job_id,
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Static analysis findings already recorded for this job",
        )

    if scan.started_at is None:
        scan.started_at = payload.processed_at
    scan.status = payload.status
    if payload.status in {"completed", "failed"}:
        scan.completed_at = payload.processed_at

    findings_count = 0
    for finding_payload in payload.findings:
        metadata_payload = deepcopy(_normalize_payload(finding_payload.metadata))
        evidence_payload = deepcopy(_normalize_payload(finding_payload.evidence))
        record = BinaryStaticAnalysisFinding(
            sample_id=sample.id,
            scan_id=scan.id,
            job_id=payload.job_id,
            tool=finding_payload.tool,
            severity=finding_payload.severity,
            title=finding_payload.title,
            description=finding_payload.description,
            metadata_json=metadata_payload,
            evidence=evidence_payload,
            evidence_hash="",
            artifact_bucket=finding_payload.artifact_bucket,
            artifact_key=finding_payload.artifact_key,
            executed_at=finding_payload.executed_at,
        )
        db.add(record)
        findings_count += 1

    try:
        db.commit()
    except SQLAlchemyError as exc:  # pragma: no cover - defensive path
        db.rollback()
        LOGGER.exception(
            "Failed to persist binary static analysis callback",
            extra={"scan_id": scan.id},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist static analysis callback",
        ) from exc

    return scan, sample, findings_count


def _persist_binary_fuzzing_callback(
    *, db: Session, payload: FuzzingCallbackRequest
) -> Tuple[Scan, BinarySample, int]:
    scan = db.get(Scan, payload.scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found"
        )
    if scan.scanner != SCAN_TYPE_BINARY_FUZZING:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Scan is not assigned to binary fuzzing",
        )

    sample = db.get(BinarySample, payload.sample_id)
    if sample is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Sample not found"
        )
    if sample.target_id != scan.target_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Sample target does not match scan target",
        )

    existing = (
        db.query(BinaryFuzzingFinding)
        .filter(
            BinaryFuzzingFinding.scan_id == scan.id,
            BinaryFuzzingFinding.job_id == payload.job_id,
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Binary fuzzing findings already recorded for this job",
        )

    if scan.started_at is None:
        scan.started_at = payload.processed_at
    scan.status = payload.status
    if payload.status in {"completed", "failed"}:
        scan.completed_at = payload.processed_at

    findings_count = 0
    for finding_payload in payload.findings:
        metadata_payload = deepcopy(_normalize_payload(finding_payload.metadata))
        evidence_payload = deepcopy(_normalize_payload(finding_payload.evidence))
        if finding_payload.crash_type and "crash_type" not in metadata_payload:
            metadata_payload["crash_type"] = finding_payload.crash_type
        record = BinaryFuzzingFinding(
            sample_id=sample.id,
            scan_id=scan.id,
            job_id=payload.job_id,
            tool=finding_payload.tool,
            severity=finding_payload.severity,
            title=finding_payload.title,
            description=finding_payload.description,
            metadata_json=metadata_payload,
            evidence=evidence_payload,
            evidence_hash="",
            artifact_bucket=finding_payload.artifact_bucket,
            artifact_key=finding_payload.artifact_key,
            executed_at=finding_payload.executed_at,
        )
        db.add(record)
        findings_count += 1

    try:
        db.commit()
    except SQLAlchemyError as exc:  # pragma: no cover - defensive path
        db.rollback()
        LOGGER.exception(
            "Failed to persist binary fuzzing callback",
            extra={"scan_id": scan.id},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist binary fuzzing callback",
        ) from exc

    return scan, sample, findings_count


@app.post(
    "/internal/nuclei/callback",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
def nuclei_callback(
    payload: ScanCallbackRequest,
    principal: Principal = Depends(authenticate_nuclei_worker),
    db: Session = Depends(get_db_session),
) -> Response:
    """Persist nuclei worker results while enforcing evidence immutability."""

    scan, findings_persisted = _handle_scan_callback(
        db=db,
        payload=payload,
        principal=principal,
        worker_name=SCAN_TYPE_NUCLEI,
    )

    metrics.record_worker_callback(SCAN_TYPE_NUCLEI, findings_persisted)

    record_audit_event(
        db,
        actor=principal,
        action="nuclei_callback",
        resource_type="scan",
        resource_id=str(scan.id),
        scan_id=scan.id,
        metadata={
            "status": payload.status,
            "findings_count": findings_persisted,
        },
        message=payload.error,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.post(
    "/internal/zap/callback",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
def zap_callback(
    payload: ScanCallbackRequest,
    principal: Principal = Depends(authenticate_zap_worker),
    db: Session = Depends(get_db_session),
) -> Response:
    """Persist ZAP worker results."""

    scan, findings_persisted = _handle_scan_callback(
        db=db,
        payload=payload,
        principal=principal,
        worker_name=SCAN_TYPE_ZAP,
    )

    metrics.record_worker_callback(SCAN_TYPE_ZAP, findings_persisted)

    record_audit_event(
        db,
        actor=principal,
        action="zap_callback",
        resource_type="scan",
        resource_id=str(scan.id),
        scan_id=scan.id,
        metadata={
            "status": payload.status,
            "findings_count": findings_persisted,
        },
        message=payload.error,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.post(
    "/internal/sqlmap/callback",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
def sqlmap_callback(
    payload: ScanCallbackRequest,
    principal: Principal = Depends(authenticate_sqlmap_worker),
    db: Session = Depends(get_db_session),
) -> Response:
    """Persist SQLMap worker results."""

    scan, findings_persisted = _handle_scan_callback(
        db=db,
        payload=payload,
        principal=principal,
        worker_name=SCAN_TYPE_SQLMAP,
    )

    metrics.record_worker_callback(SCAN_TYPE_SQLMAP, findings_persisted)

    record_audit_event(
        db,
        actor=principal,
        action="sqlmap_callback",
        resource_type="scan",
        resource_id=str(scan.id),
        scan_id=scan.id,
        metadata={
            "status": payload.status,
            "findings_count": findings_persisted,
        },
        message=payload.error,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.post(
    "/internal/binary/static-analysis/callback",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
def binary_static_analysis_callback(
    payload: StaticAnalysisCallbackRequest,
    principal: Principal = Depends(authenticate_binary_static_analysis_worker),
    db: Session = Depends(get_db_session),
) -> Response:
    """Persist binary static analysis findings and emit audit metadata."""

    scan, sample, findings_persisted = _persist_static_analysis_callback(
        db=db,
        payload=payload,
    )

    metrics.record_worker_callback(SCAN_TYPE_BINARY_STATIC, findings_persisted)

    record_audit_event(
        db,
        actor=principal,
        action="binary_static_analysis_callback",
        resource_type="scan",
        resource_id=str(scan.id),
        scan_id=scan.id,
        metadata={
            "status": payload.status,
            "findings_count": findings_persisted,
            "job_id": payload.job_id,
            "sample_id": sample.id,
        },
        message=payload.error,
    )

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.post(
    "/internal/binary/fuzzing/callback",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
def binary_fuzzing_callback(
    payload: FuzzingCallbackRequest,
    principal: Principal = Depends(authenticate_binary_fuzzing_worker),
    db: Session = Depends(get_db_session),
) -> Response:
    """Persist binary fuzzing findings and emit audit metadata."""

    scan, sample, findings_persisted = _persist_binary_fuzzing_callback(
        db=db,
        payload=payload,
    )

    metrics.record_worker_callback(SCAN_TYPE_BINARY_FUZZING, findings_persisted)

    record_audit_event(
        db,
        actor=principal,
        action="binary_fuzzing_callback",
        resource_type="scan",
        resource_id=str(scan.id),
        scan_id=scan.id,
        metadata={
            "status": payload.status,
            "findings_count": findings_persisted,
            "job_id": payload.job_id,
            "sample_id": sample.id,
        },
        message=payload.error,
    )

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.post(
    "/internal/enrich/callback",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
def enrichment_callback(
    payload: CVEEnrichmentResult,
    principal: Principal = Depends(authenticate_enrichment_worker),
    db: Session = Depends(get_db_session),
) -> Response:
    """Persist deterministic enrichment payloads emitted by the CVE worker."""

    finding = (
        db.query(Finding)
        .options(selectinload(Finding.enrichments))
        .filter(Finding.id == payload.finding_id)
        .first()
    )
    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found"
        )

    existing = (
        db.query(FindingEnrichment)
        .filter(FindingEnrichment.job_id == payload.job_id)
        .first()
    )
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Enrichment already recorded",
        )

    advisories = [advisory.model_dump(mode="json") for advisory in payload.advisories]
    errors = {str(source): str(message) for source, message in payload.errors.items()}
    generated_at = payload.generated_at.astimezone(timezone.utc)
    received_at = datetime.now(tz=timezone.utc)
    provenance: Dict[str, Any] = {
        "job_id": payload.job_id,
        "worker_subject": principal.subject,
        "generated_at": generated_at.isoformat(),
        "received_at": received_at.isoformat(),
    }
    if advisories:
        provenance["sources"] = sorted(
            {
                entry.get("source")
                for entry in advisories
                if isinstance(entry, dict) and entry.get("source")
            }
        )
    if errors:
        provenance["error_sources"] = sorted(errors.keys())

    enrichment = FindingEnrichment(
        finding_id=finding.id,
        job_id=payload.job_id,
        generated_at=generated_at,
        advisories=advisories,
        advisories_hash="",
        errors=errors,
        errors_hash="",
        provenance=provenance,
        provenance_hash="",
        payload_hash="",
    )
    db.add(enrichment)

    try:
        db.commit()
        db.refresh(enrichment)
    except SQLAlchemyError as exc:
        db.rollback()
        LOGGER.exception(
            "Failed to persist enrichment callback",
            extra={"job_id": payload.job_id, "finding_id": payload.finding_id},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist enrichment",
        ) from exc

    metrics.record_worker_callback("enrichment", len(advisories))

    record_audit_event(
        db,
        actor=principal,
        action="enrichment_callback",
        resource_type="finding",
        resource_id=str(finding.id),
        scan_id=finding.scan_id,
        finding_id=finding.id,
        metadata={
            "job_id": payload.job_id,
            "advisory_count": len(advisories),
            "error_sources": sorted(errors.keys()),
        },
    )

    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _retrieve_finding_records(
    db: Session,
    *,
    target_id: Optional[str],
    scan_id: Optional[str],
) -> Tuple[
    List[Finding],
    List[BinaryStaticAnalysisFinding],
    List[BinaryFuzzingFinding],
]:
    query = db.query(Finding).options(
        selectinload(Finding.enrichments),
        selectinload(Finding.comments),
        selectinload(Finding.tickets),
    )
    if scan_id is not None:
        query = query.filter(Finding.scan_id == scan_id)
    elif target_id is not None:
        query = query.join(Finding.scan).filter(Scan.target_id == target_id)

    findings = query.order_by(Finding.created_at.desc()).all()

    static_query = db.query(BinaryStaticAnalysisFinding).options(
        selectinload(BinaryStaticAnalysisFinding.scan)
    )
    fuzzing_query = db.query(BinaryFuzzingFinding).options(
        selectinload(BinaryFuzzingFinding.scan)
    )

    if scan_id is not None:
        static_query = static_query.filter(
            BinaryStaticAnalysisFinding.scan_id == scan_id
        )
        fuzzing_query = fuzzing_query.filter(BinaryFuzzingFinding.scan_id == scan_id)
    elif target_id is not None:
        static_query = static_query.join(BinaryStaticAnalysisFinding.scan).filter(
            Scan.target_id == target_id
        )
        fuzzing_query = fuzzing_query.join(BinaryFuzzingFinding.scan).filter(
            Scan.target_id == target_id
        )

    static_findings = static_query.order_by(
        BinaryStaticAnalysisFinding.executed_at.desc()
    ).all()
    fuzzing_findings = fuzzing_query.order_by(
        BinaryFuzzingFinding.executed_at.desc()
    ).all()

    return findings, static_findings, fuzzing_findings


def _get_mutable_finding(db: Session, finding_id: str) -> Finding:
    finding = (
        db.query(Finding)
        .options(
            selectinload(Finding.enrichments),
            selectinload(Finding.comments),
            selectinload(Finding.tickets),
            selectinload(Finding.scan).selectinload(Scan.target),
        )
        .filter(Finding.id == finding_id)
        .one_or_none()
    )
    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found"
        )
    return finding


def _filter_finding_responses(
    responses: Iterable[FindingResponse],
    *,
    severity: Optional[str],
    status_filter: Optional[str],
    tag: Optional[str],
    assigned_to: Optional[str],
    since: Optional[datetime],
    until: Optional[datetime],
) -> Tuple[List[FindingResponse], Dict[str, Optional[str]]]:
    normalized_severity = severity.lower().strip() if severity else None
    normalized_status = status_filter.lower().strip() if status_filter else None
    normalized_tag = tag.lower().strip() if tag else None
    normalized_assignee = assigned_to.strip() if assigned_to else None

    def _matches(record: FindingResponse) -> bool:
        if normalized_severity and record.severity != normalized_severity:
            return False
        if normalized_status and record.status != normalized_status:
            return False
        if normalized_tag and normalized_tag not in record.tags:
            return False
        if normalized_assignee and record.assigned_to != normalized_assignee:
            return False
        if since and record.detected_at < since:
            return False
        if until and record.detected_at > until:
            return False
        return True

    filtered = [record for record in responses if _matches(record)]
    metadata = {
        "severity": normalized_severity,
        "status": normalized_status,
        "tag": normalized_tag,
        "assigned_to": normalized_assignee,
        "from": since.isoformat() if since else None,
        "to": until.isoformat() if until else None,
    }
    return filtered, metadata


def _build_timeline_buckets(
    responses: Iterable[FindingResponse],
) -> List[FindingTimelineBucket]:
    timeline: Dict[date, Dict[str, int]] = {}
    for record in responses:
        detected = record.detected_at.astimezone(timezone.utc)
        key = detected.date()
        bucket = timeline.setdefault(key, {"open": 0, "acknowledged": 0, "resolved": 0})
        bucket[record.status] = bucket.get(record.status, 0) + 1

    ordered: List[FindingTimelineBucket] = []
    for day in sorted(timeline.keys()):
        counts = timeline[day]
        timestamp = datetime.combine(day, datetime.min.time(), tzinfo=timezone.utc)
        total = counts.get("open", 0) + counts.get("acknowledged", 0) + counts.get("resolved", 0)
        ordered.append(
            FindingTimelineBucket(
                date=timestamp,
                open=counts.get("open", 0),
                acknowledged=counts.get("acknowledged", 0),
                resolved=counts.get("resolved", 0),
                total=total,
            )
        )
    return ordered


def _severity_to_cvss(severity: str) -> float:
    mapping = {
        "critical": 9.5,
        "high": 8.0,
        "medium": 6.0,
        "low": 3.0,
        "info": 0.0,
    }
    return mapping.get(severity.lower(), 0.0)


def _generate_ticket_reference(prefix: str, finding_id: str, summary: str) -> str:
    normalized_prefix = prefix.strip().upper()
    digest = hashlib.sha1(f"{finding_id}:{summary}".encode("utf-8")).hexdigest()
    return f"{normalized_prefix}-{digest[:8].upper()}"


def _render_report_html(findings: List[FindingResponse]) -> str:
    rows: List[str] = []
    for record in findings:
        evidence_text = record.evidence or "Evidence not provided."
        tags = ", ".join(record.tags) if record.tags else "none"
        cvss_score = _severity_to_cvss(record.severity)
        enrichments = len(record.enrichments)
        rows.append(
            """
            <section class="finding">
              <h2>{title}</h2>
              <p class="meta">Severity: {severity} • Status: {status} • CVSS: {cvss:.1f}</p>
              <p class="meta">Scan: {scan_id} • Detected: {detected} • Tags: {tags}</p>
              <p class="description">{description}</p>
              <pre class="evidence">{evidence}</pre>
              <p class="meta">Enrichments attached: {enrichments}</p>
            </section>
            """.format(
                title=html.escape(record.title),
                severity=html.escape(record.severity),
                status=html.escape(record.status),
                cvss=cvss_score,
                scan_id=html.escape(record.scan_id),
                detected=html.escape(record.detected_at.isoformat()),
                tags=html.escape(tags),
                description=html.escape(record.description),
                evidence=html.escape(evidence_text),
                enrichments=enrichments,
            )
        )

    body = "\n".join(rows)
    generated = datetime.now(tz=timezone.utc).isoformat()
    return f"""
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <title>Medusa Findings Report</title>
        <style>
          body {{ font-family: Arial, sans-serif; background-color: #0f172a; color: #e2e8f0; padding: 2rem; }}
          h1 {{ color: #38bdf8; }}
          .finding {{ border: 1px solid #1e293b; border-radius: 0.5rem; padding: 1.5rem; margin-bottom: 1.5rem; background: #1f2937; }}
          .meta {{ font-size: 0.85rem; color: #94a3b8; margin: 0.25rem 0; }}
          .description {{ margin: 1rem 0; line-height: 1.5; }}
          pre.evidence {{ background: #0f172a; padding: 1rem; overflow-x: auto; border-radius: 0.5rem; }}
        </style>
      </head>
      <body>
        <h1>Medusa Findings Report</h1>
        <p class="meta">Generated at {generated}</p>
        {body}
      </body>
    </html>
    """.strip()


def _render_report_pdf(findings: List[FindingResponse]) -> bytes:
    def _escape(content: str) -> str:
        return content.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    lines: List[str] = [
        f"Medusa Findings Report generated {datetime.now(tz=timezone.utc).isoformat()}"
    ]
    for record in findings:
        lines.append("")
        lines.append(f"Finding {record.id}: {record.title} [{record.severity.upper()}]")
        lines.append(f"Status: {record.status} | CVSS {_severity_to_cvss(record.severity):.1f}")
        lines.append(f"Detected: {record.detected_at.isoformat()} | Scan: {record.scan_id}")
        lines.append(
            f"Tags: {', '.join(record.tags) if record.tags else 'none'}"
        )
        description = textwrap.wrap(record.description, 90)
        lines.extend(description)
        evidence = record.evidence or "Evidence not provided."
        for segment in textwrap.wrap(f"Evidence: {evidence}", 90):
            lines.append(segment)

    content_segments = ["BT /F1 12 Tf 50 750 Td"]
    for index, line in enumerate(lines):
        if index == 0:
            content_segments.append(f"({_escape(line)}) Tj")
        else:
            content_segments.append(f"T* ({_escape(line)}) Tj")
    content_segments.append("ET")
    content_stream = "\n".join(content_segments)
    stream_bytes = content_stream.encode("utf-8")

    objects = [
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n",
        f"4 0 obj\n<< /Length {len(stream_bytes)} >>\nstream\n{content_stream}\nendstream\nendobj\n",
        "5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
    ]

    buffer = BytesIO()
    buffer.write(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(buffer.tell())
        buffer.write(obj.encode("utf-8"))
    xref_position = buffer.tell()
    buffer.write(f"xref\n0 {len(offsets)}\n".encode("utf-8"))
    buffer.write(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        buffer.write(f"{offset:010} 00000 n \n".encode("utf-8"))
    buffer.write(
        b"trailer\n<< /Size %d /Root 1 0 R >>\n" % len(offsets)
    )
    buffer.write(b"startxref\n")
    buffer.write(f"{xref_position}\n".encode("utf-8"))
    buffer.write(b"%%EOF")
    return buffer.getvalue()


@app.get("/findings", response_model=FindingCollectionResponse)
def list_findings(
    target_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status_filter: Optional[str] = Query(
        None, alias="status", description="Filter by workflow status"
    ),
    tag: Optional[str] = Query(None, description="Filter by tag"),
    assigned_to: Optional[str] = Query(None, description="Filter by assignee"),
    since: Optional[datetime] = Query(None, alias="from"),
    until: Optional[datetime] = Query(None, alias="to"),
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
) -> FindingCollectionResponse:
    """Return the latest findings for the requested scope."""

    enforce_roles(
        principal,
        [ROLE_FINDINGS_READ],
        db,
        resource_type="endpoint",
        resource_id="/findings",
    )

    findings, static_findings, fuzzing_findings = _retrieve_finding_records(
        db, target_id=target_id, scan_id=scan_id
    )

    aggregated: List[Tuple[datetime, FindingResponse]] = []
    for record in findings:
        aggregated.append((record.created_at, serialize_finding(record)))
    for record in static_findings:
        aggregated.append(
            (record.executed_at, serialize_binary_static_finding(record))
        )
    for record in fuzzing_findings:
        aggregated.append(
            (record.executed_at, serialize_binary_fuzzing_finding(record))
        )

    ordered = [
        response
        for _, response in sorted(aggregated, key=lambda item: item[0], reverse=True)
    ]

    filtered, metadata_filters = _filter_finding_responses(
        ordered,
        severity=severity,
        status_filter=status_filter,
        tag=tag,
        assigned_to=assigned_to,
        since=since,
        until=until,
    )

    web_count = sum(1 for record in filtered if record.category == "web")
    static_count = sum(1 for record in filtered if record.category == "binary_static")
    fuzzing_count = sum(1 for record in filtered if record.category == "binary_fuzzing")

    record_audit_event(
        db,
        actor=principal,
        action="list_findings",
        resource_type="finding",
        resource_id=None,
        scan_id=scan_id,
        metadata={
            "target_id": target_id,
            "count": len(filtered),
            "web_count": web_count,
            "binary_static_count": static_count,
            "binary_fuzzing_count": fuzzing_count,
            "filters": metadata_filters,
        },
    )

    return FindingCollectionResponse(data=filtered)


@app.get("/findings/timeline", response_model=FindingTimelineCollectionResponse)
def list_findings_timeline(
    target_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status_filter: Optional[str] = Query(
        None, alias="status", description="Filter by workflow status"
    ),
    tag: Optional[str] = Query(None, description="Filter by tag"),
    assigned_to: Optional[str] = Query(None, description="Filter by assignee"),
    since: Optional[datetime] = Query(None, alias="from"),
    until: Optional[datetime] = Query(None, alias="to"),
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
) -> FindingTimelineCollectionResponse:
    enforce_roles(
        principal,
        [ROLE_FINDINGS_READ],
        db,
        resource_type="endpoint",
        resource_id="/findings/timeline",
    )

    findings, static_findings, fuzzing_findings = _retrieve_finding_records(
        db, target_id=target_id, scan_id=scan_id
    )

    aggregated: List[Tuple[datetime, FindingResponse]] = []
    for record in findings:
        aggregated.append((record.created_at, serialize_finding(record)))
    for record in static_findings:
        aggregated.append(
            (record.executed_at, serialize_binary_static_finding(record))
        )
    for record in fuzzing_findings:
        aggregated.append(
            (record.executed_at, serialize_binary_fuzzing_finding(record))
        )

    ordered = [
        response
        for _, response in sorted(aggregated, key=lambda item: item[0], reverse=True)
    ]

    filtered, metadata_filters = _filter_finding_responses(
        ordered,
        severity=severity,
        status_filter=status_filter,
        tag=tag,
        assigned_to=assigned_to,
        since=since,
        until=until,
    )

    buckets = _build_timeline_buckets(filtered)

    record_audit_event(
        db,
        actor=principal,
        action="findings_timeline",
        resource_type="finding",
        resource_id=None,
        scan_id=scan_id,
        metadata={
            "target_id": target_id,
            "bucket_count": len(buckets),
            "filters": metadata_filters,
        },
    )

    return FindingTimelineCollectionResponse(data=buckets)


@app.get("/findings/{finding_id}", response_model=FindingItemResponse)
def get_finding(
    finding_id: str,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
) -> FindingItemResponse:
    """Fetch a single finding for detailed analysis views."""

    enforce_roles(
        principal,
        [ROLE_FINDINGS_READ],
        db,
        resource_type="endpoint",
        resource_id="/findings/{finding_id}",
    )
    finding = db.get(Finding, finding_id)
    if finding is not None:
        record_audit_event(
            db,
            actor=principal,
            action="get_finding",
            resource_type="finding",
            resource_id=finding_id,
            finding_id=finding_id,
            metadata={"scan_id": finding.scan_id},
        )
        return FindingItemResponse(data=serialize_finding(finding))

    static_record = db.get(BinaryStaticAnalysisFinding, finding_id)
    if static_record is not None:
        record_audit_event(
            db,
            actor=principal,
            action="get_binary_static_finding",
            resource_type="finding",
            resource_id=finding_id,
            finding_id=finding_id,
            metadata={
                "scan_id": static_record.scan_id,
                "category": "binary_static",
            },
        )
        return FindingItemResponse(
            data=serialize_binary_static_finding(static_record)
        )

    fuzz_record = db.get(BinaryFuzzingFinding, finding_id)
    if fuzz_record is not None:
        record_audit_event(
            db,
            actor=principal,
            action="get_binary_fuzzing_finding",
            resource_type="finding",
            resource_id=finding_id,
            finding_id=finding_id,
            metadata={
                "scan_id": fuzz_record.scan_id,
                "category": "binary_fuzzing",
            },
        )
        return FindingItemResponse(
            data=serialize_binary_fuzzing_finding(fuzz_record)
        )

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found"
    )


@app.get("/findings/{finding_id}/timeline", response_model=FindingTimelineResponse)
def get_finding_timeline(
    finding_id: str,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
) -> FindingTimelineResponse:
    enforce_roles(
        principal,
        [ROLE_FINDINGS_READ],
        db,
        resource_type="endpoint",
        resource_id=f"/findings/{finding_id}/timeline",
    )

    finding = _get_mutable_finding(db, finding_id)

    audit_entries = (
        db.query(AuditLog)
        .filter(AuditLog.finding_id == finding_id)
        .order_by(AuditLog.created_at.asc())
        .all()
    )

    events: List[FindingTimelineEvent] = []
    detection_actor = None
    if finding.scan and finding.scan.initiated_by:
        detection_actor = finding.scan.initiated_by
    elif finding.scan:
        detection_actor = finding.scan.scanner
    else:
        detection_actor = "system"
    events.append(
        FindingTimelineEvent(
            kind="finding.detected",
            actor=detection_actor,
            created_at=finding.created_at,
            metadata={
                "severity": finding.severity,
                "status": finding.status,
                "scanner": finding.scan.scanner if finding.scan else None,
            },
        )
    )

    for entry in audit_entries:
        snapshot = deepcopy(_normalize_payload(entry.evidence_snapshot))
        events.append(
            FindingTimelineEvent(
                kind=f"audit.{entry.action}",
                actor=entry.actor,
                created_at=entry.created_at,
                message=entry.message,
                metadata=snapshot,
            )
        )

    record_audit_event(
        db,
        actor=principal,
        action="get_finding_timeline",
        resource_type="finding",
        resource_id=finding_id,
        finding_id=finding_id,
        metadata={"event_count": len(events)},
    )

    return FindingTimelineResponse(data=events)


@app.get("/findings/{finding_id}/comments", response_model=FindingCommentCollectionResponse)
def list_finding_comments(
    finding_id: str,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
) -> FindingCommentCollectionResponse:
    enforce_roles(
        principal,
        [ROLE_FINDINGS_READ],
        db,
        resource_type="endpoint",
        resource_id=f"/findings/{finding_id}/comments",
    )

    _ = _get_mutable_finding(db, finding_id)
    comments = (
        db.query(FindingComment)
        .filter(FindingComment.finding_id == finding_id)
        .order_by(FindingComment.created_at.asc())
        .all()
    )
    payload = [serialize_comment(comment) for comment in comments]

    record_audit_event(
        db,
        actor=principal,
        action="list_finding_comments",
        resource_type="finding",
        resource_id=finding_id,
        finding_id=finding_id,
        metadata={"count": len(payload)},
    )

    return FindingCommentCollectionResponse(data=payload)


@app.post(
    "/findings/{finding_id}/comments",
    response_model=FindingCommentSummary,
    status_code=status.HTTP_201_CREATED,
)
def create_finding_comment(
    finding_id: str,
    request: FindingCommentRequest,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
) -> FindingCommentSummary:
    enforce_roles(
        principal,
        [ROLE_ANALYST],
        db,
        resource_type="endpoint",
        resource_id=f"/findings/{finding_id}/comments",
    )

    finding = _get_mutable_finding(db, finding_id)

    message = request.message.strip()
    if not message:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Comment body cannot be empty",
        )

    comment = FindingComment(
        finding_id=finding_id,
        author=principal.subject,
        message=message,
        metadata_json={"source": "analyst"},
        metadata_hash="",
    )
    db.add(comment)
    db.commit()
    db.refresh(comment)

    record_audit_event(
        db,
        actor=principal,
        action="comment_finding",
        resource_type="finding",
        resource_id=finding_id,
        finding_id=finding_id,
        metadata={"comment_id": comment.id, "message_preview": message[:120]},
    )

    # Refresh finding to update comment count for subsequent operations
    db.refresh(finding)

    return serialize_comment(comment)


@app.post(
    "/findings/{finding_id}/assign", response_model=FindingItemResponse
)
def assign_finding(
    finding_id: str,
    request: FindingAssignmentRequest,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
) -> FindingItemResponse:
    enforce_roles(
        principal,
        [ROLE_ANALYST],
        db,
        resource_type="endpoint",
        resource_id=f"/findings/{finding_id}/assign",
    )

    finding = _get_mutable_finding(db, finding_id)
    previous_status = finding.status
    sanitized_assignee = request.assignee.strip()
    if not sanitized_assignee:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Assignee cannot be blank",
        )
    finding.assigned_to = sanitized_assignee
    if finding.status == "open":
        finding.status = "acknowledged"
    db.add(finding)
    db.commit()
    db.refresh(finding)

    record_audit_event(
        db,
        actor=principal,
        action="assign_finding",
        resource_type="finding",
        resource_id=finding_id,
        finding_id=finding_id,
        metadata={
            "assigned_to": sanitized_assignee,
            "previous_status": previous_status,
        },
    )

    return FindingItemResponse(data=serialize_finding(finding))


@app.post(
    "/findings/{finding_id}/status", response_model=FindingItemResponse
)
def update_finding_status(
    finding_id: str,
    request: FindingStatusUpdateRequest,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
) -> FindingItemResponse:
    enforce_roles(
        principal,
        [ROLE_ANALYST],
        db,
        resource_type="endpoint",
        resource_id=f"/findings/{finding_id}/status",
    )

    finding = _get_mutable_finding(db, finding_id)
    previous_status = finding.status
    finding.status = request.status
    db.add(finding)
    db.commit()
    db.refresh(finding)

    record_audit_event(
        db,
        actor=principal,
        action="update_finding_status",
        resource_type="finding",
        resource_id=finding_id,
        finding_id=finding_id,
        metadata={
            "previous_status": previous_status,
            "new_status": request.status,
        },
    )

    return FindingItemResponse(data=serialize_finding(finding))


@app.post(
    "/findings/{finding_id}/tags", response_model=FindingItemResponse
)
def update_finding_tags(
    finding_id: str,
    request: FindingTagsUpdateRequest,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
) -> FindingItemResponse:
    enforce_roles(
        principal,
        [ROLE_ANALYST],
        db,
        resource_type="endpoint",
        resource_id=f"/findings/{finding_id}/tags",
    )

    finding = _get_mutable_finding(db, finding_id)
    normalized_tags = _sanitize_tags(request.tags)
    finding.tags = normalized_tags
    db.add(finding)
    db.commit()
    db.refresh(finding)

    record_audit_event(
        db,
        actor=principal,
        action="update_finding_tags",
        resource_type="finding",
        resource_id=finding_id,
        finding_id=finding_id,
        metadata={"tags": normalized_tags},
    )

    return FindingItemResponse(data=serialize_finding(finding))


@app.post("/reports/export", response_model=ReportExportResponse)
def export_findings_report(
    request: ReportExportRequest,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
) -> ReportExportResponse:
    enforce_roles(
        principal,
        [ROLE_REPORT_EXPORT],
        db,
        resource_type="endpoint",
        resource_id="/reports/export",
    )
    enforce_roles(
        principal,
        [ROLE_FINDINGS_READ],
        db,
        resource_type="endpoint",
        resource_id="/reports/export",
    )

    findings_map: Dict[str, FindingResponse] = {}

    if request.finding_ids:
        query = (
            db.query(Finding)
            .options(
                selectinload(Finding.enrichments),
                selectinload(Finding.comments),
                selectinload(Finding.tickets),
                selectinload(Finding.scan).selectinload(Scan.target),
            )
            .filter(Finding.id.in_(request.finding_ids))
        )
        for record in query.all():
            findings_map[str(record.id)] = serialize_finding(record)

    if request.scan_id:
        scan_findings, static_findings, fuzzing_findings = _retrieve_finding_records(
            db, target_id=None, scan_id=request.scan_id
        )
        for record in scan_findings:
            findings_map[str(record.id)] = serialize_finding(record)
        for record in static_findings:
            finding_response = serialize_binary_static_finding(record)
            findings_map[finding_response.id] = finding_response
        for record in fuzzing_findings:
            finding_response = serialize_binary_fuzzing_finding(record)
            findings_map[finding_response.id] = finding_response

    responses = list(findings_map.values())
    if not responses:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No findings available for export",
        )

    ordered = sorted(responses, key=lambda item: item.detected_at, reverse=True)

    if request.format == "html":
        report_bytes = _render_report_html(ordered).encode("utf-8")
    else:
        report_bytes = _render_report_pdf(ordered)

    encoded_content = base64.b64encode(report_bytes).decode("ascii")
    generated_at = datetime.now(tz=timezone.utc)
    report_id = str(uuid.uuid4())

    severity_counts: Dict[str, int] = {}
    status_counts: Dict[str, int] = {}
    for record in ordered:
        severity_counts[record.severity] = severity_counts.get(record.severity, 0) + 1
        status_counts[record.status] = status_counts.get(record.status, 0) + 1

    metadata = {
        "requested_findings": request.finding_ids,
        "scan_id": request.scan_id,
        "severity_counts": severity_counts,
        "status_counts": status_counts,
        "format": request.format,
    }

    record_audit_event(
        db,
        actor=principal,
        action="export_report",
        resource_type="finding",
        resource_id=None,
        metadata={
            "report_id": report_id,
            "format": request.format,
            "finding_count": len(ordered),
            "severity_counts": severity_counts,
        },
    )

    return ReportExportResponse(
        report_id=report_id,
        format=request.format,
        generated_at=generated_at,
        finding_count=len(ordered),
        content=encoded_content,
        metadata=metadata,
    )


@app.post("/tickets/jira", response_model=TicketResponse, status_code=status.HTTP_201_CREATED)
def create_jira_ticket(
    request: JiraTicketRequest,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
) -> TicketResponse:
    enforce_roles(
        principal,
        [ROLE_TICKETING_CREATE],
        db,
        resource_type="endpoint",
        resource_id="/tickets/jira",
    )
    enforce_roles(
        principal,
        [ROLE_FINDINGS_READ],
        db,
        resource_type="endpoint",
        resource_id="/tickets/jira",
    )

    finding = _get_mutable_finding(db, request.finding_id)
    if finding.scan and finding.scan.target and not finding.scan.target.is_authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Target scope is not authorized for ticketing",
        )

    reference = _generate_ticket_reference(
        request.project_key, finding.id, request.summary
    )
    payload = {
        "project_key": request.project_key.upper(),
        "issue_type": request.issue_type,
        "summary": request.summary,
        "description": request.description or finding.description,
        "severity": finding.severity,
        "cvss": _severity_to_cvss(finding.severity),
        "finding_id": finding.id,
    }

    ticket = FindingTicket(
        finding_id=finding.id,
        integration="jira",
        reference=reference,
        url=None,
        status="queued",
        payload=payload,
        payload_hash="",
        created_by=principal.subject,
    )
    db.add(ticket)
    db.commit()
    db.refresh(ticket)

    record_audit_event(
        db,
        actor=principal,
        action="create_jira_ticket",
        resource_type="finding",
        resource_id=finding.id,
        finding_id=finding.id,
        metadata={"reference": reference, "project_key": request.project_key.upper()},
    )

    return TicketResponse(
        id=ticket.id,
        integration="jira",
        reference=reference,
        status=ticket.status,
        url=ticket.url,
        created_at=ticket.created_at,
        metadata=payload,
    )


@app.post(
    "/tickets/github",
    response_model=TicketResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_github_ticket(
    request: GitHubTicketRequest,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
) -> TicketResponse:
    enforce_roles(
        principal,
        [ROLE_TICKETING_CREATE],
        db,
        resource_type="endpoint",
        resource_id="/tickets/github",
    )
    enforce_roles(
        principal,
        [ROLE_FINDINGS_READ],
        db,
        resource_type="endpoint",
        resource_id="/tickets/github",
    )

    finding = _get_mutable_finding(db, request.finding_id)
    if finding.scan and finding.scan.target and not finding.scan.target.is_authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Target scope is not authorized for ticketing",
        )

    repo_slug = request.repository.strip().replace("/", "-")
    reference = _generate_ticket_reference(f"GH-{repo_slug}", finding.id, request.title)
    payload = {
        "repository": request.repository,
        "title": request.title,
        "body": request.body or finding.description,
        "severity": finding.severity,
        "cvss": _severity_to_cvss(finding.severity),
        "finding_id": finding.id,
    }

    ticket = FindingTicket(
        finding_id=finding.id,
        integration="github",
        reference=reference,
        url=None,
        status="queued",
        payload=payload,
        payload_hash="",
        created_by=principal.subject,
    )
    db.add(ticket)
    db.commit()
    db.refresh(ticket)

    record_audit_event(
        db,
        actor=principal,
        action="create_github_ticket",
        resource_type="finding",
        resource_id=finding.id,
        finding_id=finding.id,
        metadata={"reference": reference, "repository": request.repository},
    )

    return TicketResponse(
        id=ticket.id,
        integration="github",
        reference=reference,
        status=ticket.status,
        url=ticket.url,
        created_at=ticket.created_at,
        metadata=payload,
    )


def serialize_scan(scan: Scan) -> ScanResponse:
    """Project a Scan ORM object into the API contract expected by the UI."""

    target_scope = scan.target.scope if scan.target else ""
    findings_count = (
        len(scan.findings)
        + len(scan.binary_analysis_findings)
        + len(scan.binary_fuzzing_findings)
    )

    return ScanResponse(
        id=str(scan.id),
        target_id=str(scan.target_id),
        target=target_scope,
        scanner=scan.scanner,
        status=scan.status,
        initiated_by=scan.initiated_by,
        created_at=scan.created_at,
        updated_at=scan.updated_at or scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        findings_count=findings_count,
    )


def serialize_ticket(ticket: FindingTicket) -> FindingTicketSummary:
    """Serialize ticket metadata for API consumers."""

    return FindingTicketSummary(
        id=str(ticket.id),
        integration=ticket.integration,
        reference=ticket.reference,
        status=ticket.status,
        url=ticket.url,
        created_at=ticket.created_at,
        updated_at=ticket.updated_at,
    )


def serialize_comment(comment: FindingComment) -> FindingCommentSummary:
    """Serialize immutable analyst commentary."""

    return FindingCommentSummary(
        id=str(comment.id),
        author=comment.author,
        message=comment.message,
        created_at=comment.created_at,
    )


def serialize_finding(finding: Finding) -> FindingResponse:
    """Project a Finding ORM object into the deterministic UI schema."""

    detected_at = finding.created_at
    metadata_payload = deepcopy(_normalize_payload(finding.metadata_json))
    evidence_payload = _normalize_payload(finding.evidence)
    evidence_text = (
        json.dumps(evidence_payload, sort_keys=True) if evidence_payload else None
    )

    template_id_source = (
        metadata_payload.get("template_id")
        or metadata_payload.get("rule_id")
        or metadata_payload.get("alert_id")
        or metadata_payload.get("signature_id")
        or metadata_payload.get("finding_id")
        or finding.cve_id
    )
    scanner_name = metadata_payload.get("scanner")
    if template_id_source:
        template_id = str(template_id_source)
    elif scanner_name:
        template_id = f"{scanner_name}:unspecified"
    else:
        template_id = "scanner:unspecified"

    scanner_value = (
        scanner_name
        or (finding.scan.scanner if finding.scan else "scanner:unknown")
    )
    tool_value = metadata_payload.get("tool")
    metadata_payload.setdefault("scanner", scanner_value)

    enrichments_payload: List[FindingEnrichmentSummary] = []
    if hasattr(finding, "enrichments") and finding.enrichments:
        ordered = sorted(
            finding.enrichments,
            key=lambda record: record.created_at,
            reverse=True,
        )
        for enrichment in ordered:
            advisories = deepcopy(enrichment.advisories or [])
            errors = deepcopy(enrichment.errors or {})
            provenance = deepcopy(enrichment.provenance or {})
            enrichments_payload.append(
                FindingEnrichmentSummary(
                    id=str(enrichment.id),
                    job_id=enrichment.job_id,
                    generated_at=enrichment.generated_at,
                    recorded_at=enrichment.created_at,
                    advisories=advisories,
                    advisories_hash=enrichment.advisories_hash,
                    errors=errors,
                    errors_hash=enrichment.errors_hash,
                    provenance=provenance,
                    provenance_hash=enrichment.provenance_hash,
                    payload_hash=enrichment.payload_hash,
                )
            )

    tickets_payload: List[FindingTicketSummary] = []
    if hasattr(finding, "tickets") and finding.tickets:
        ordered_tickets = sorted(
            finding.tickets,
            key=lambda record: record.created_at,
            reverse=True,
        )
        tickets_payload = [serialize_ticket(ticket) for ticket in ordered_tickets]

    return FindingResponse(
        id=str(finding.id),
        scan_id=str(finding.scan_id),
        title=finding.title,
        severity=finding.severity,
        cve_id=finding.cve_id,
        description=finding.description,
        detected_at=detected_at,
        updated_at=finding.updated_at or detected_at,
        status=finding.status or "open",
        template_id=template_id,
        evidence=evidence_text,
        remediation=None,
        enrichments=enrichments_payload,
        metadata=metadata_payload,
        scanner=scanner_value,
        sample_id=None,
        tool=str(tool_value) if tool_value else scanner_value,
        category="web",
        assigned_to=finding.assigned_to,
        tags=list(finding.tags or []),
        comment_count=len(getattr(finding, "comments", []) or []),
        tickets=tickets_payload,
    )


def serialize_binary_static_finding(
    record: BinaryStaticAnalysisFinding,
) -> FindingResponse:
    metadata_payload = deepcopy(_normalize_payload(record.metadata_json))
    metadata_payload.setdefault("scanner", SCAN_TYPE_BINARY_STATIC)
    metadata_payload.setdefault("tool", record.tool)
    evidence_payload = _normalize_payload(record.evidence)
    evidence_text = (
        json.dumps(evidence_payload, sort_keys=True) if evidence_payload else None
    )
    template_id_source = (
        metadata_payload.get("template_id")
        or metadata_payload.get("rule_id")
        or metadata_payload.get("alert_id")
        or metadata_payload.get("signature_id")
        or metadata_payload.get("finding_id")
    )
    template_id = (
        str(template_id_source)
        if template_id_source
        else f"{record.tool}:finding"
    )

    return FindingResponse(
        id=str(record.id),
        scan_id=str(record.scan_id),
        title=record.title,
        severity=record.severity,
        cve_id=metadata_payload.get("cve_id"),
        description=record.description,
        detected_at=record.executed_at,
        updated_at=record.updated_at or record.executed_at,
        status="open",
        template_id=template_id,
        evidence=evidence_text,
        remediation=None,
        enrichments=[],
        metadata=metadata_payload,
        scanner=SCAN_TYPE_BINARY_STATIC,
        sample_id=str(record.sample_id),
        tool=record.tool,
        category="binary_static",
        assigned_to=None,
        tags=[],
        comment_count=0,
        tickets=[],
    )


def serialize_binary_fuzzing_finding(
    record: BinaryFuzzingFinding,
) -> FindingResponse:
    metadata_payload = deepcopy(_normalize_payload(record.metadata_json))
    metadata_payload.setdefault("scanner", SCAN_TYPE_BINARY_FUZZING)
    metadata_payload.setdefault("tool", record.tool)
    evidence_payload = _normalize_payload(record.evidence)
    evidence_text = (
        json.dumps(evidence_payload, sort_keys=True) if evidence_payload else None
    )
    template_id_source = (
        metadata_payload.get("template_id")
        or metadata_payload.get("finding_id")
        or metadata_payload.get("crash_id")
        or metadata_payload.get("crash_type")
    )
    template_id = (
        str(template_id_source)
        if template_id_source
        else f"{record.tool}:crash"
    )

    return FindingResponse(
        id=str(record.id),
        scan_id=str(record.scan_id),
        title=record.title,
        severity=record.severity,
        cve_id=metadata_payload.get("cve_id"),
        description=record.description,
        detected_at=record.executed_at,
        updated_at=record.updated_at or record.executed_at,
        status="open",
        template_id=template_id,
        evidence=evidence_text,
        remediation=None,
        enrichments=[],
        metadata=metadata_payload,
        scanner=SCAN_TYPE_BINARY_FUZZING,
        sample_id=str(record.sample_id),
        tool=record.tool,
        category="binary_fuzzing",
        assigned_to=None,
        tags=[],
        comment_count=0,
        tickets=[],
    )


__all__ = [
    "app",
    "get_settings",
    "Settings",
    "Target",
    "Scan",
    "Finding",
    "FindingEnrichment",
    "AuditLog",
    "ScanResponse",
    "ScanCollectionResponse",
    "TargetCollectionResponse",
    "FindingResponse",
    "FindingEnrichmentSummary",
    "FindingCommentSummary",
    "FindingTicketSummary",
    "FindingCollectionResponse",
    "FindingItemResponse",
    "get_db_session",
    "get_queue_client",
    "RedisQueueClient",
    "QueueClient",
    "_hash_secret",
    "serialize_scan",
    "serialize_finding",
    "record_audit_event",
    "authenticate",
    "authenticate_nuclei_worker",
    "authenticate_enrichment_worker",
    "authenticate_zap_worker",
    "authenticate_sqlmap_worker",
    "ScanCallbackRequest",
]
