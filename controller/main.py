"""FastAPI controller for coordinating scan orchestration and persistence."""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Dict, Iterable, Iterator, List, Literal, Optional, Tuple, Union

import jwt
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, field_validator
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

from controller.db.models import (
    AuditLog,
    Finding,
    FindingEnrichment,
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
ROLE_TARGETS_READ = "targets:read"
ROLE_TARGETS_WRITE = "targets:write"
ROLE_ENRICHMENT_ENQUEUE = "enrich:enqueue"

ALLOWED_ROLES = {
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_FINDINGS_READ,
    ROLE_SCANS_READ,
    ROLE_SCAN_ENQUEUE,
    ROLE_TARGETS_READ,
    ROLE_TARGETS_WRITE,
    ROLE_ENRICHMENT_ENQUEUE,
}

DEFAULT_ANALYST_ROLES = [
    ROLE_ANALYST,
    ROLE_FINDINGS_READ,
    ROLE_SCANS_READ,
    ROLE_SCAN_ENQUEUE,
    ROLE_TARGETS_READ,
    ROLE_ENRICHMENT_ENQUEUE,
]

DEFAULT_ADMIN_ROLES = [
    ROLE_ADMIN,
    ROLE_FINDINGS_READ,
    ROLE_SCANS_READ,
    ROLE_SCAN_ENQUEUE,
    ROLE_TARGETS_READ,
    ROLE_TARGETS_WRITE,
    ROLE_ENRICHMENT_ENQUEUE,
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

NUCLEI_TEMPLATE_PROFILES: Dict[str, Tuple[str, ...]] = {
    "baseline": NUCLEI_BASELINE_TEMPLATES,
    "full": NUCLEI_BASELINE_TEMPLATES
    + (
        "http/cves/2023/CVE-2023-34362.yaml",
        "http/cves/2023/CVE-2023-50164.yaml",
        "network/exposed-services/ssh/weak-ciphers.yaml",
    ),
}

DEFAULT_NUCLEI_TEMPLATE_PROFILE = "baseline"

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
    if not any(lowered.startswith(prefix) for prefix in ALLOWED_NUCLEI_TEMPLATE_PREFIXES):
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
        raw_parameters.get("requested_hosts") or raw_parameters.get("allowed_hosts") or []
    )
    normalized_hosts = _coerce_requested_hosts(requested_hosts_value)
    allowed_hosts, rejected_hosts = _filter_hosts_for_scope(target_scope, normalized_hosts)

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
        include_paths = [segment.strip() for segment in include_value.split(",") if segment.strip()]
    elif isinstance(include_value, Iterable) and not isinstance(
        include_value, (bytes, bytearray, dict)
    ):
        include_paths = [str(item).strip() for item in include_value if str(item).strip()]

    exclude_paths: List[str] = []
    exclude_value = raw_parameters.get("exclude_paths")
    if isinstance(exclude_value, str):
        exclude_paths = [segment.strip() for segment in exclude_value.split(",") if segment.strip()]
    elif isinstance(exclude_value, Iterable) and not isinstance(
        exclude_value, (bytes, bytearray, dict)
    ):
        exclude_paths = [str(item).strip() for item in exclude_value if str(item).strip()]

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
        candidates = [segment.strip().lower() for segment in techniques_value.split(",")]
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

def _normalize_hostname(value: str) -> str:
    """Return a lowercase hostname without trailing dots or wildcard prefixes."""

    normalized = value.strip().lower().rstrip(".")
    if normalized.startswith("*."):
        normalized = normalized[2:]
    return normalized


Network = Union[IPv4Network, IPv6Network]

def _hash_secret(secret: str) -> str:
    """Return a SHA-256 hash of the provided secret."""

    return hashlib.sha256(secret.encode("utf-8")).hexdigest()

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


def _filter_hosts_for_scope(scope: str, requested_hosts: Iterable[str]) -> Tuple[List[str], List[str]]:
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
    scanner: Literal[
        SCAN_TYPE_NUCLEI, SCAN_TYPE_ZAP, SCAN_TYPE_SQLMAP
    ] = Field(description="Scanner identifier")
    parameters: Dict[str, Any] = Field(
        default_factory=dict, description="Scanner-specific configuration payload"
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


class FindingCollectionResponse(BaseModel):
    data: List[FindingResponse]


class FindingItemResponse(BaseModel):
    data: FindingResponse


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
            raise ValueError(f"Unsupported roles requested: {', '.join(sorted(invalid))}")
        return value


class PrincipalCredentialResponse(BaseModel):
    id: int
    subject: str
    auth_method: str
    roles: List[str] = Field(default_factory=list)
    description: Optional[str]
    created_at: datetime
    revoked_at: Optional[datetime]

    @field_validator("roles", mode="before")
    @classmethod
    def _ensure_roles(cls, value: Optional[List[str]]) -> List[str]:
        return list(value or [])

    model_config = ConfigDict(from_attributes=True)


class PrincipalCredentialCollectionResponse(BaseModel):
    data: List[PrincipalCredentialResponse]


class PrincipalCredentialCreatedResponse(PrincipalCredentialResponse):
    secret: Optional[str] = None


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
) -> Principal:
    token = request.headers.get(CALLBACK_TOKEN_HEADER)
    if not token or not secrets.compare_digest(token, expected_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid callback token",
        )
    return Principal(subject=subject, auth_method="shared_secret")


def authenticate(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db_session),
) -> Principal:
    """Authenticate caller via JWT bearer token or API key headers."""

    api_key_header = request.headers.get("X-API-Key")
    bearer_token = credentials.credentials if credentials else None

    candidate_api_key = api_key_header or bearer_token
    if candidate_api_key and candidate_api_key in settings.api_keys:
        subject_hash = _hash_secret(candidate_api_key)
        return Principal(
            subject=f"apikey:{subject_hash}",
            auth_method="api_key",
            roles=list(DEFAULT_ADMIN_ROLES),
        )

    if candidate_api_key:
        api_key_hash = _hash_secret(candidate_api_key)
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
            roles = list(active_credential.roles or [])
            return Principal(
                subject=active_credential.subject,
                auth_method="api_key",
                roles=roles,
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
                status_code=status.HTTP_403_FORBIDDEN,
                extra_metadata={
                    "credential_id": str(revoked_credential.id),
                    "credential_status": "revoked",
                },
            )

    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required"
        )

    token = credentials.credentials
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
    except jwt.PyJWTError as exc:  # pragma: no cover - exercised indirectly
        LOGGER.warning("JWT validation failed", extra={"error": str(exc)})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        ) from exc

    subject = payload.get("sub")
    if not subject:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload"
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
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Subject not authorized"
        )

    roles = list(record.roles or [])
    return Principal(subject=record.subject, auth_method="jwt", roles=roles)


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

    return entry


app = FastAPI(title="Medusa Controller", version="0.1.0")


@app.get("/principals", response_model=PrincipalCredentialCollectionResponse)
def list_principals(
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
) -> PrincipalCredentialCollectionResponse:
    enforce_roles(
        principal,
        ["admin"],
        db,
        resource_type="endpoint",
        resource_id="/principals",
    )
    records = (
        db.query(PrincipalCredential)
        .order_by(PrincipalCredential.created_at.desc())
        .all()
    )
    response_items = [
        PrincipalCredentialResponse.model_validate(record, from_attributes=True)
        for record in records
    ]

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
        query.order_by(AuditLog.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
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
        ["admin"],
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

    record_audit_event(
        db,
        actor=principal,
        action="create_principal",
        resource_type="principal",
        resource_id=str(credential.id),
        metadata={
            "subject": credential.subject,
            "auth_method": credential.auth_method,
            "roles": credential.roles,
        },
    )

    response_payload = PrincipalCredentialCreatedResponse.model_validate(
        credential, from_attributes=True
    )
    return response_payload.model_copy(update={"secret": secret})


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
        ["admin"],
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

    record_audit_event(
        db,
        actor=principal,
        action="revoke_principal",
        resource_type="principal",
        resource_id=str(credential.id),
        metadata={
            "subject": credential.subject,
            "auth_method": credential.auth_method,
            "roles": credential.roles,
        },
    )

    return PrincipalCredentialResponse.model_validate(credential, from_attributes=True)


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
        data=[TargetResponse.model_validate(target, from_attributes=True) for target in targets]
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

    tags: List[str] = []
    job_payload: Dict[str, Any]
    callback_url: str
    metadata_payload: Dict[str, Any] = {
        "scan_id": str(scan.id),
        "target_id": str(target.id),
        "target_scope": target.scope,
        "target_name": target.name,
        "initiated_by": principal.subject,
        "submitted_at": submitted_at.isoformat(),
    }

    if scan.scanner == SCAN_TYPE_NUCLEI:
        profile, templates, tags, sanitized_parameters, extra_metadata = (
            resolve_nuclei_job_configuration(target.scope, scan_request.parameters)
        )
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
        audit_metadata = {
            "target_id": target.id,
            "scanner": scan.scanner,
            "job_id": job_id,
            "template_profile": profile,
            "requested_host_count": extra_metadata.get("requested_host_count", 0),
            "requested_hosts": sanitized_parameters.get("requested_hosts", []),
        }
        if extra_metadata.get("rejected_hosts"):
            audit_metadata["rejected_hosts"] = extra_metadata["rejected_hosts"]
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

@app.post("/enrich", response_model=EnrichmentResponse, status_code=status.HTTP_202_ACCEPTED)
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
    except SQLAlchemyError as exc:  # pragma: no cover - exercised in error handling tests
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


@app.get("/findings", response_model=FindingCollectionResponse)
def list_findings(
    target_id: Optional[str] = None,
    scan_id: Optional[str] = None,
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
    query = db.query(Finding)
    if scan_id is not None:
        query = query.filter(Finding.scan_id == scan_id)
    elif target_id is not None:
        query = query.join(Finding.scan).filter(Scan.target_id == target_id)

    findings = query.order_by(Finding.created_at.desc()).all()

    record_audit_event(
        db,
        actor=principal,
        action="list_findings",
        resource_type="finding",
        resource_id=None,
        scan_id=scan_id,
        metadata={"target_id": target_id, "count": len(findings)},
    )

    return FindingCollectionResponse(
        data=[serialize_finding(finding) for finding in findings]
    )


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
        resource_id=f"/findings/{finding_id}",
    )
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found"
        )

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


def serialize_scan(scan: Scan) -> ScanResponse:
    """Project a Scan ORM object into the API contract expected by the UI."""

    target_scope = scan.target.scope if scan.target else ""
    findings_count = len(scan.findings)

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

    return FindingResponse(
        id=str(finding.id),
        scan_id=str(finding.scan_id),
        title=finding.title,
        severity=finding.severity,
        cve_id=finding.cve_id,
        description=finding.description,
        detected_at=detected_at,
        updated_at=finding.updated_at or detected_at,
        status="open",
        template_id=template_id,
        evidence=evidence_text,
        remediation=None,
        enrichments=enrichments_payload,
        metadata=metadata_payload,
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
