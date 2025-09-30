"""FastAPI controller for coordinating scan orchestration and persistence."""

from __future__ import annotations

import base64
import hashlib
import html
import json
import logging
import secrets
import smtplib
import textwrap
import time
import uuid
from collections import Counter
from copy import deepcopy
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from email.message import EmailMessage
from io import BytesIO
from functools import lru_cache
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from urllib.parse import urlparse
from typing import Any, Dict, Iterable, Iterator, List, Literal, Optional, Tuple, Union

import jwt
import requests
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
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
from sqlalchemy import func, literal, select, union_all
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, selectinload

from controller import metrics
from controller.db.models import (
    AuditLog,
    AnomalyEvent,
    BinaryFuzzingFinding,
    BinarySymbolicExecutionFinding,
    BinarySample,
    BinaryStaticAnalysisFinding,
    Finding,
    FindingEnrichment,
    FindingValidation,
    FindingComment,
    FindingTicket,
    ReportExport,
    PrincipalCredential,
    Scan,
    Target,
    ReconDiscovery,
    ReconObservation,
    ReconRun,
)
from controller.db.session import SessionLocal
from controller.notifications import (
    AnomalyNotification,
    CriticalFindingNotification,
    NotificationService,
    build_notification_service,
)
from controller.storage import (
    EphemeralReportStorage,
    ReportStorage,
    ReportStorageReference,
    ReportStorageError,
    S3ReportStorage,
)
from controller.severity import normalize_severity, severity_score
from controller.security.oidc import (
    OIDCNotApplicableError,
    OIDCSettings,
    OIDCValidationError,
    OIDCValidator,
    build_validator,
)
from controller.security.rate_limit import RateLimiter
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
ROLE_BINARY_SYMBOLIC_EXECUTION_ENQUEUE = "binary:symbolic-execution"
ROLE_TARGETS_READ = "targets:read"
ROLE_TARGETS_WRITE = "targets:write"
ROLE_ENRICHMENT_ENQUEUE = "enrich:enqueue"
ROLE_REPORT_EXPORT = "report:export"
ROLE_TICKETING_CREATE = "ticket:create"
ROLE_VALIDATION_ENQUEUE = "validation:enqueue"
ROLE_RECON_ENQUEUE = "recon:enqueue"

ALLOWED_ROLES = {
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_FINDINGS_READ,
    ROLE_SCANS_READ,
    ROLE_SCAN_ENQUEUE,
    ROLE_BINARY_PREPROCESS_ENQUEUE,
    ROLE_BINARY_STATIC_ANALYSIS_ENQUEUE,
    ROLE_BINARY_FUZZING_ENQUEUE,
    ROLE_BINARY_SYMBOLIC_EXECUTION_ENQUEUE,
    ROLE_TARGETS_READ,
    ROLE_TARGETS_WRITE,
    ROLE_ENRICHMENT_ENQUEUE,
    ROLE_VALIDATION_ENQUEUE,
    ROLE_REPORT_EXPORT,
    ROLE_TICKETING_CREATE,
    ROLE_RECON_ENQUEUE,
}

FINDING_STATUS_PENDING_VALIDATION = "pending_validation"
FINDING_STATUS_OPEN = "open"
FINDING_STATUS_INVALIDATED = "invalidated"
FINDING_STATUS_ACKNOWLEDGED = "acknowledged"
FINDING_STATUS_RESOLVED = "resolved"

FINDING_TIMELINE_STATUSES: Tuple[str, ...] = (
    FINDING_STATUS_PENDING_VALIDATION,
    FINDING_STATUS_OPEN,
    FINDING_STATUS_INVALIDATED,
    FINDING_STATUS_ACKNOWLEDGED,
    FINDING_STATUS_RESOLVED,
)

VALIDATION_STATUS_PENDING = "pending"
VALIDATION_STATUS_PASSED = "passed"
VALIDATION_STATUS_FAILED = "failed"

FINDING_SCOPE_STATUS_UNKNOWN = "unknown"
FINDING_SCOPE_STATUS_IN_SCOPE = "in_scope"
FINDING_SCOPE_STATUS_OUT_OF_SCOPE = "out_of_scope"
FINDING_SCOPE_STATUS_MIXED = "mixed"
RECON_STATUS_NEW = "new"
RECON_STATUS_APPROVED = "approved"
RECON_STATUS_REJECTED = "rejected"

DEFAULT_ANALYST_ROLES = [
    ROLE_ANALYST,
    ROLE_FINDINGS_READ,
    ROLE_SCANS_READ,
    ROLE_SCAN_ENQUEUE,
    ROLE_BINARY_PREPROCESS_ENQUEUE,
    ROLE_BINARY_STATIC_ANALYSIS_ENQUEUE,
    ROLE_BINARY_FUZZING_ENQUEUE,
    ROLE_BINARY_SYMBOLIC_EXECUTION_ENQUEUE,
    ROLE_TARGETS_READ,
    ROLE_ENRICHMENT_ENQUEUE,
    ROLE_VALIDATION_ENQUEUE,
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
    ROLE_BINARY_SYMBOLIC_EXECUTION_ENQUEUE,
    ROLE_TARGETS_READ,
    ROLE_TARGETS_WRITE,
    ROLE_ENRICHMENT_ENQUEUE,
    ROLE_VALIDATION_ENQUEUE,
    ROLE_REPORT_EXPORT,
    ROLE_TICKETING_CREATE,
    ROLE_RECON_ENQUEUE,
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
SCAN_TYPE_BINARY_SYMBOLIC = "binary_symbolic_execution"

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

ALLOWED_VALIDATION_STATUSES: Tuple[str, ...] = (
    "pending",
    "queued",
    "running",
    "passed",
    "failed",
)
FINAL_VALIDATION_STATUSES: Tuple[str, ...] = ("passed", "failed")


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
    validator_queue_channel: str = Field(
        "queues:validator:jobs",
        description="Redis list channel for validation agent jobs.",
    )
    recon_queue_channel: str = Field(
        "queues:recon:jobs",
        description="Redis list channel for authorized recon pull jobs.",
    )
    ticket_dispatch_queue_channel: str = Field(
        "queues:tickets:dispatch",
        description="Redis list channel for ticket dispatcher jobs.",
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
    binary_symbolic_execution_queue_channel: str = Field(
        "queues:binary:symbolic-execution",
        description="Redis list channel for angr symbolic execution jobs.",
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
    validator_callback_token: str = Field(
        ..., description="Shared secret required for validator worker callbacks."
    )
    enrichment_callback_token: str = Field(
        ..., description="Shared secret required for enrichment worker callbacks."
    )
    anomaly_callback_token: str = Field(
        ..., description="Shared secret required for anomaly worker callbacks."
    )
    validator_callback_token: str = Field(
        ..., description="Shared secret required for validator agent callbacks."
    )
    recon_callback_token: str = Field(
        ..., description="Shared secret required for recon worker callbacks."
    )
    binary_static_analysis_callback_token: str = Field(
        ...,
        description="Shared secret required for binary static analysis worker callbacks.",
    )
    binary_fuzzing_callback_token: str = Field(
        ..., description="Shared secret required for binary fuzzing worker callbacks."
    )
    binary_symbolic_execution_callback_token: str = Field(
        ...,
        description="Shared secret required for angr symbolic execution worker callbacks.",
    )
    slack_webhook_url: Optional[str] = Field(
        default=None,
        description="Incoming webhook URL for Slack critical finding notifications.",
    )
    email_smtp_host: Optional[str] = Field(
        default=None,
        description="SMTP host used to dispatch critical finding notifications.",
    )
    email_smtp_port: int = Field(
        default=587,
        description="SMTP port used when dispatching notification emails.",
    )
    email_username: Optional[str] = Field(
        default=None,
        description="Username for SMTP authentication if required.",
    )
    email_password: Optional[str] = Field(
        default=None,
        description="Password for SMTP authentication if required.",
    )
    email_from: Optional[str] = Field(
        default=None,
        description="Sender address used for notification emails.",
    )
    email_recipients: List[str] = Field(
        default_factory=list,
        description="Recipient addresses that receive critical finding notifications.",
    )
    email_use_tls: bool = Field(
        default=True,
        description="Enable STARTTLS when connecting to the SMTP server.",
    )

    notification_slack_webhook: Optional[str] = Field(
        default=None,
        description="Incoming webhook URL for Slack notifications.",
    )
    notification_email_sender: Optional[str] = Field(
        default=None,
        description="Email address used as the sender for notification emails.",
    )
    notification_email_recipients: List[str] = Field(
        default_factory=list,
        description="Email recipients for validated critical finding alerts.",
    )
    smtp_host: Optional[str] = Field(
        default=None,
        description="SMTP host used to dispatch notification emails.",
    )
    smtp_port: int = Field(
        default=587,
        description="SMTP port used for notification emails.",
    )
    smtp_username: Optional[str] = Field(
        default=None,
        description="SMTP username for authenticated email delivery.",
    )
    smtp_password: Optional[str] = Field(
        default=None,
        description="SMTP password for authenticated email delivery.",
    )
    smtp_use_tls: bool = Field(
        default=True,
        description="Whether to negotiate STARTTLS when delivering notification emails.",
    )
    s3_endpoint_url: Optional[str] = Field(
        default=None,
        description="Endpoint URL for the MinIO/S3-compatible object storage service.",
    )
    s3_region_name: Optional[str] = Field(
        default=None,
        description="Region identifier for the S3-compatible storage service.",
    )
    s3_access_key_id: Optional[str] = Field(
        default=None,
        description="Access key ID used for S3-compatible authentication.",
    )
    s3_secret_access_key: Optional[str] = Field(
        default=None,
        description="Secret access key used for S3-compatible authentication.",
    )
    s3_session_token: Optional[str] = Field(
        default=None,
        description="Optional session token for temporary MinIO/S3 credentials.",
    )
    s3_force_path_style: bool = Field(
        default=True,
        description="Force path-style bucket addressing for MinIO compatibility.",
    )
    report_export_bucket: str = Field(
        default="medusa-reports",
        description="Bucket used to persist rendered HTML/PDF report exports.",
    )
    report_export_prefix: str = Field(
        default="reports",
        description="Object prefix prepended to persisted report artifacts.",
    )
    oidc_issuer: Optional[str] = Field(
        default=None,
        description=("OIDC issuer expected in validated bearer tokens."),
    )
    oidc_audience: Optional[str] = Field(
        default=None,
        description="Audience/client ID expected in validated bearer tokens.",
    )
    oidc_jwks_url: Optional[str] = Field(
        default=None,
        description="JWKS endpoint used to resolve signing keys for OIDC tokens.",
    )
    oidc_roles_claim: str = Field(
        default="roles",
        description="Claim name containing RBAC roles within validated OIDC tokens.",
    )
    oidc_subject_claim: str = Field(
        default="sub",
        description="Claim name providing the stable subject identifier for OIDC tokens.",
    )
    oidc_allowed_algorithms: List[str] = Field(
        default_factory=lambda: ["RS256"],
        description="Algorithms permitted when validating OIDC bearer tokens.",
    )
    oidc_jwks_cache_ttl_seconds: int = Field(
        default=300,
        ge=30,
        description="Seconds JWKS responses are cached before revalidation.",
    )
    oidc_request_timeout_seconds: int = Field(
        default=5,
        ge=1,
        description="Timeout in seconds for JWKS retrieval requests.",
    )
    oidc_auto_provision: bool = Field(
        default=False,
        description=(
            "Automatically create or update OIDC principals using identity-provider"
            " group mappings when enabled."
        ),
    )
    oidc_auto_provision_allowed_issuers: List[str] = Field(
        default_factory=list,
        description=(
            "Allow-list of OIDC issuers permitted to auto-provision principals."
        ),
    )
    oidc_group_claim: str = Field(
        default="groups",
        min_length=1,
        description=(
            "Claim containing IdP groups used for automatic role assignments."
        ),
    )
    oidc_group_role_map: Dict[str, List[str]] = Field(
        default_factory=dict,
        description=(
            "Mapping of identity-provider groups to Medusa roles for auto-provisioning."
        ),
    )
    oidc_auto_provision_role_allow_list: List[str] = Field(
        default_factory=list,
        description=(
            "Subset of Medusa roles that may be granted during OIDC auto-provisioning."
        ),
    )
    oidc_auto_provision_expires_in_seconds: Optional[int] = Field(
        default=None,
        gt=0,
        description=(
            "Optional TTL applied to auto-provisioned principals (seconds from last login)."
        ),
    )
    rate_limit_max_requests: int = Field(
        default=300,
        ge=0,
        description="Maximum requests permitted per principal within the window.",
    )
    rate_limit_window_seconds: int = Field(
        default=60,
        ge=1,
        description="Sliding window interval for request rate limiting.",
    )
    rate_limit_exempt_subjects: List[str] = Field(
        default_factory=list,
        description="Subjects exempt from rate limiting (e.g., automation principals).",
    )

    @field_validator("oidc_auto_provision_allowed_issuers", mode="before")
    @classmethod
    def _normalize_oidc_allowed_issuers(
        cls, value: Optional[Iterable[str]]
    ) -> List[str]:
        issuers: List[str] = []
        for issuer in value or []:
            if isinstance(issuer, str):
                candidate = issuer.strip()
                if candidate:
                    issuers.append(candidate)
        return issuers

    @field_validator("oidc_auto_provision_role_allow_list", mode="before")
    @classmethod
    def _normalize_auto_provision_roles(
        cls, value: Optional[Iterable[str]]
    ) -> List[str]:
        roles: List[str] = []
        seen: set[str] = set()
        for role in value or []:
            if isinstance(role, str):
                candidate = role.strip()
            elif isinstance(role, int):
                candidate = str(role)
            else:
                candidate = ""
            if candidate and candidate not in seen:
                seen.add(candidate)
                roles.append(candidate)
        return roles

    @field_validator("oidc_auto_provision_role_allow_list")
    @classmethod
    def _validate_auto_provision_roles(cls, value: List[str]) -> List[str]:
        invalid = [role for role in value if role not in ALLOWED_ROLES]
        if invalid:
            raise ValueError(
                "Unsupported roles configured for OIDC auto-provisioning: "
                + ", ".join(sorted(invalid))
            )
        return value

    @field_validator("oidc_group_role_map", mode="before")
    @classmethod
    def _normalize_group_role_map(
        cls, value: Optional[Dict[str, Iterable[str]]]
    ) -> Dict[str, List[str]]:
        if not value:
            return {}
        normalized: Dict[str, List[str]] = {}
        for raw_group, raw_roles in value.items():
            group = str(raw_group).strip()
            if not group:
                continue
            roles: List[str] = []
            seen: set[str] = set()
            for role in raw_roles or []:
                if isinstance(role, str):
                    candidate = role.strip()
                elif isinstance(role, int):
                    candidate = str(role)
                else:
                    candidate = ""
                if candidate and candidate not in seen:
                    seen.add(candidate)
                    roles.append(candidate)
            if roles:
                normalized[group] = roles
        return normalized

    @field_validator("oidc_group_role_map")
    @classmethod
    def _validate_group_role_map(
        cls, value: Dict[str, List[str]]
    ) -> Dict[str, List[str]]:
        validated: Dict[str, List[str]] = {}
        for group, roles in value.items():
            invalid = [role for role in roles if role not in ALLOWED_ROLES]
            if invalid:
                raise ValueError(
                    f"Unsupported roles configured for group '{group}': "
                    + ", ".join(sorted(invalid))
                )
            validated[group] = roles
        return validated

    model_config = ConfigDict(env_prefix="MEDUSA_", case_sensitive=False)


@lru_cache()
def get_settings() -> Settings:
    """Return cached settings instance loaded from environment."""

    return Settings()


@lru_cache()
def get_oidc_validator(
    issuer: Optional[str],
    audience: Optional[str],
    jwks_url: Optional[str],
    roles_claim: str,
    subject_claim: str,
    allowed_algorithms: Tuple[str, ...],
    cache_ttl_seconds: int,
    request_timeout_seconds: int,
) -> Optional[OIDCValidator]:
    """Return an OIDC validator when configuration is provided."""

    if not issuer or not jwks_url:
        return None

    config = OIDCSettings(
        issuer=issuer,
        jwks_url=jwks_url,
        audience=audience,
        roles_claim=roles_claim,
        subject_claim=subject_claim,
        allowed_algorithms=allowed_algorithms,
        cache_ttl_seconds=cache_ttl_seconds,
        request_timeout_seconds=request_timeout_seconds,
    )
    return build_validator(config)


@lru_cache()
def get_rate_limiter(
    max_requests: int,
    window_seconds: int,
    exempt_subjects: Tuple[str, ...],
) -> Optional[RateLimiter]:
    """Return a shared rate limiter instance based on configuration."""

    if max_requests <= 0 or window_seconds <= 0:
        return None

    return RateLimiter.from_settings(
        max_requests=max_requests,
        window_seconds=window_seconds,
        exempt_subjects=exempt_subjects,
    )


security_scheme = HTTPBearer(auto_error=False)


def _normalize_payload(payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Ensure JSON payloads are deterministic dictionaries."""

    if payload is None:
        return {}
    return payload


ANOMALY_METADATA_MAX_DEPTH = 5
ANOMALY_METADATA_MAX_ITEMS = 50
ANOMALY_METADATA_MAX_STRING_LENGTH = 2048


def _sanitize_anomaly_metadata(value: Any, *, depth: int = 0) -> Any:
    """Return analyst-safe metadata derived from anomaly event payloads."""

    if depth >= ANOMALY_METADATA_MAX_DEPTH:
        return "[truncated]"

    if value is None or isinstance(value, (bool, int, float)):
        return value

    if isinstance(value, (datetime, date)):
        return value.isoformat()

    if isinstance(value, dict):
        sanitized: Dict[str, Any] = {}
        for key, nested in value.items():
            sanitized[str(key)] = _sanitize_anomaly_metadata(nested, depth=depth + 1)
        return sanitized

    if isinstance(value, (list, tuple, set, frozenset)):
        sanitized_items: List[Any] = []
        for index, item in enumerate(value):
            if index >= ANOMALY_METADATA_MAX_ITEMS:
                sanitized_items.append("[truncated]")
                break
            sanitized_items.append(_sanitize_anomaly_metadata(item, depth=depth + 1))
        return sanitized_items

    if isinstance(value, bytes):
        encoded = base64.b64encode(value).decode("ascii", errors="ignore")
        return html.escape(encoded, quote=True)

    normalized = str(value)
    if len(normalized) > ANOMALY_METADATA_MAX_STRING_LENGTH:
        normalized = f"{normalized[:ANOMALY_METADATA_MAX_STRING_LENGTH]}…"
    return html.escape(normalized, quote=True)


def _canonicalize_for_hash(value: Any) -> Any:
    """Return a canonical JSON-compatible structure for hashing."""

    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        canonical: Dict[str, Any] = {}
        for key in sorted(value.keys(), key=lambda item: str(item)):
            canonical[str(key)] = _canonicalize_for_hash(value[key])
        return canonical
    if isinstance(value, (list, tuple)):
        return [_canonicalize_for_hash(item) for item in value]
    if isinstance(value, (set, frozenset)):
        canonical_items = [_canonicalize_for_hash(item) for item in value]
        return sorted(
            canonical_items,
            key=lambda item: json.dumps(
                item, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ),
        )
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    return str(value)


def _hash_json_payload(payload: Any) -> str:
    """Canonicalize arbitrary payloads and return a SHA-256 hex digest."""

    canonical = _canonicalize_for_hash(payload)
    serialized = json.dumps(canonical, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


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


def _normalize_timestamp(value: Optional[datetime]) -> Optional[datetime]:
    """Coerce naive datetimes to UTC-aware timestamps."""

    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


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


class ReconFeedConfig(BaseModel):
    type: Literal["csv", "api"]
    url: str = Field(..., min_length=1, max_length=2048)
    delimiter: Optional[str] = Field(default=",", min_length=1, max_length=8)
    asset_column: Optional[str] = Field(default="asset", min_length=1, max_length=128)
    asset_type_column: Optional[str] = Field(default=None, min_length=1, max_length=128)
    encoding: str = Field(default="utf-8", min_length=1, max_length=64)
    method: Optional[str] = Field(default="GET", min_length=3, max_length=8)
    items_path: List[str] = Field(default_factory=list)
    asset_field: Optional[str] = Field(default="asset", min_length=1, max_length=128)
    type_field: Optional[str] = Field(default=None, min_length=1, max_length=128)

    @model_validator(mode="after")
    def _enforce_type_requirements(self) -> "ReconFeedConfig":
        if self.type == "csv":
            if not self.asset_column:
                raise ValueError("asset_column is required for CSV feeds")
            if self.method and self.method.upper() != "GET":
                raise ValueError("CSV feeds only support GET requests")
        elif self.type == "api":
            if not self.asset_field:
                raise ValueError("asset_field is required for API feeds")
        return self


class ReconToolingConfig(BaseModel):
    subfinder: bool = True
    amass: bool = True
    httpx: bool = True
    httpx_ports: List[int] = Field(default_factory=lambda: [80, 443, 8080])
    httpx_rate_limit: Optional[int] = Field(default=None, ge=1, le=10000)
    httpx_probe_tls: bool = True
    httpx_follow_redirects: bool = False

    @model_validator(mode="before")
    @classmethod
    def _coerce_httpx_payload(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        payload = dict(data)
        httpx_payload = payload.get("httpx")
        if isinstance(httpx_payload, dict):
            payload["httpx"] = bool(httpx_payload.get("enabled", True))

            def set_if_present(key: str, *aliases: str) -> None:
                for alias in (key, *aliases):
                    if alias in httpx_payload:
                        payload[key] = httpx_payload[alias]
                        return

            set_if_present("httpx_ports", "ports")
            set_if_present("httpx_rate_limit", "rate_limit")
            set_if_present("httpx_probe_tls", "probe_tls")
            set_if_present("httpx_follow_redirects", "follow_redirects")

        return payload

    @field_validator("httpx_ports", mode="before")
    @classmethod
    def _normalize_ports(cls, value: Optional[Iterable[Any]]) -> List[int]:
        ports: List[int] = []
        if not value:
            return [80, 443, 8080]
        for item in value:
            try:
                port = int(item)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                continue
            if 1 <= port <= 65535 and port not in ports:
                ports.append(port)
        return ports or [80, 443, 8080]


class ReconTargetConfig(BaseModel):
    target_id: str = Field(..., min_length=1, max_length=36)
    scope: str = Field(..., min_length=1, max_length=255)
    asset_type: Literal["domain", "ipv4", "ipv6"] = Field(default="domain")
    seed_assets: List[str] = Field(default_factory=list)

    @field_validator("seed_assets", mode="before")
    @classmethod
    def _normalize_seed_assets(cls, value: Optional[Iterable[str]]) -> List[str]:
        seeds: List[str] = []
        for item in value or []:
            if not isinstance(item, str):
                continue
            candidate = item.strip()
            if candidate and candidate not in seeds:
                seeds.append(candidate)
        return seeds


class ReconJobRequest(BaseModel):
    source: str = Field(..., min_length=1, max_length=128)
    mode: Literal["feed", "active"] = Field(default="feed")
    feed: Optional[ReconFeedConfig] = None
    targets: List[ReconTargetConfig] = Field(default_factory=list)
    tools: ReconToolingConfig = Field(default_factory=ReconToolingConfig)
    authorized_scopes: List[str] = Field(
        default_factory=list,
        description="List of domains or CIDR blocks that bound authorized assets",
    )
    labels: List[str] = Field(
        default_factory=list,
        description="Optional static labels recorded with each discovery",
    )

    @field_validator("authorized_scopes", mode="before")
    @classmethod
    def _normalize_scopes(cls, value: Optional[Iterable[str]]) -> List[str]:
        scopes: List[str] = []
        for item in value or []:
            if not isinstance(item, str):
                continue
            candidate = item.strip()
            if candidate:
                scopes.append(candidate)
        return scopes

    @field_validator("labels", mode="before")
    @classmethod
    def _normalize_labels(cls, value: Optional[Iterable[str]]) -> List[str]:
        normalized: List[str] = []
        for item in value or []:
            if not isinstance(item, str):
                continue
            candidate = item.strip().lower()
            if candidate and candidate not in normalized:
                normalized.append(candidate)
        return normalized

    @model_validator(mode="after")
    def _validate_mode_requirements(self) -> "ReconJobRequest":
        if self.mode == "feed":
            if self.feed is None:
                raise ValueError("feed configuration is required when mode is 'feed'")
            if not self.authorized_scopes:
                raise ValueError("authorized_scopes must contain at least one entry")
        else:
            if not self.targets:
                raise ValueError(
                    "At least one target must be supplied for active recon jobs"
                )
        return self


class ReconJobResponse(BaseModel):
    job_id: str
    queued_at: datetime
    source: str
    authorized_scopes: List[str]
    mode: Literal["feed", "active"]
    targets: List[ReconTargetConfig] = Field(default_factory=list)


class ReconAssetPayload(BaseModel):
    asset_type: Literal["domain", "ipv4", "ipv6", "url"]
    normalized_value: str = Field(..., min_length=1, max_length=1024)
    raw_value: Optional[str] = Field(default=None, max_length=1024)
    matched_scope: Optional[str] = Field(default=None, max_length=512)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    occurrences: int = Field(default=1, ge=1)


class ReconTargetExecutionPayload(BaseModel):
    target_id: Optional[str] = Field(default=None, max_length=36)
    name: Optional[str] = Field(default=None, max_length=255)
    scope: str = Field(..., min_length=1, max_length=255)
    asset_type: Literal["domain", "ipv4", "ipv6"] = Field(default="domain")
    seed_assets: List[str] = Field(default_factory=list)


class ReconExecutionPayload(BaseModel):
    mode: Literal["feed", "active"] = Field(default="feed")
    targets: List[ReconTargetExecutionPayload] = Field(default_factory=list)
    tools: Dict[str, Any] = Field(default_factory=dict)


class ReconCallbackRequest(BaseModel):
    job_id: str = Field(..., min_length=1, max_length=128)
    source: str = Field(..., min_length=1, max_length=128)
    retrieved_at: datetime
    authorized_scopes: List[str] = Field(default_factory=list)
    execution: Optional[ReconExecutionPayload] = None
    assets: List[ReconAssetPayload]

    @model_validator(mode="after")
    def _ensure_assets(self) -> "ReconCallbackRequest":
        if not self.assets:
            raise ValueError("At least one discovery must be submitted")
        return self


class ReconDiscoveryResponse(BaseModel):
    id: str
    source: str
    asset_type: str
    value: str
    raw_value: Optional[str]
    matched_scope: Optional[str]
    metadata: Dict[str, Any]
    status: str
    first_seen: datetime
    last_seen: datetime
    occurrences: int
    approved_target_id: Optional[str]
    diff_status: Literal["approved", "in_scope", "scope_extension", "unmatched"]

    model_config = ConfigDict(from_attributes=True)


class ReconDiscoveryCollectionResponse(BaseModel):
    data: List[ReconDiscoveryResponse]


class ReconRunResponse(BaseModel):
    id: str
    job_id: str
    source: str
    mode: str
    status: str
    retrieved_at: datetime
    authorized_scopes: List[str]
    tooling: Dict[str, Any]
    targets: List[Dict[str, Any]]
    observation_count: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ReconRunCollectionResponse(BaseModel):
    data: List[ReconRunResponse]


class ReconObservationResponse(BaseModel):
    id: str
    run_id: str
    target_id: Optional[str]
    asset_type: str
    normalized_value: str
    raw_value: Optional[str]
    matched_scope: Optional[str]
    port: Optional[int]
    occurrences: int
    metadata: Dict[str, Any]
    first_seen: datetime
    last_seen: datetime

    model_config = ConfigDict(from_attributes=True)


class ReconObservationCollectionResponse(BaseModel):
    data: List[ReconObservationResponse]


class ReconApproveRequest(BaseModel):
    target_name: str = Field(..., min_length=1, max_length=255)
    scope: Optional[str] = Field(default=None, min_length=1, max_length=255)


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


class BinarySymbolicExecutionRequest(BaseModel):
    sample_id: str = Field(
        ...,
        description="Identifier of the normalized binary sample to execute symbolically",
    )
    target_id: Optional[str] = Field(
        default=None,
        description="Optional assertion ensuring the sample belongs to the expected target",
    )
    analysis_depth: Optional[int] = Field(
        default=None,
        ge=1,
        le=1_000_000,
        description="Optional maximum number of basic blocks explored by angr",
    )
    timeout_seconds: Optional[int] = Field(
        default=None,
        ge=60,
        le=7200,
        description="Optional harness timeout override in seconds",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Operator-provided hints recorded with the symbolic execution job",
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
    meta: PaginationMetadata


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


class AnomalyEventResponse(BaseModel):
    id: str
    anomaly_type: str
    actor: str
    source: str
    detected_at: datetime
    first_seen: datetime
    last_seen: datetime
    count: int
    window_seconds: int
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


class AnomalyCollectionResponse(BaseModel):
    data: List[AnomalyEventResponse]
    meta: PaginationMetadata


class AnomalyItemResponse(BaseModel):
    data: AnomalyEventResponse


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

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        return normalize_severity(value)


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
        return normalize_severity(value)


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


class SymbolicExecutionArtifactPayload(BaseModel):
    tool: str
    bucket: str
    key: str


class SymbolicExecutionFindingPayload(BaseModel):
    tool: str
    severity: str
    title: str
    description: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    artifact_bucket: Optional[str] = None
    artifact_key: Optional[str] = None
    executed_at: datetime

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        return normalize_severity(value)


class SymbolicExecutionReportPayload(BaseModel):
    tool: str
    status: Literal["completed", "failed"]
    exit_code: int
    stdout: str
    stderr: str
    raw_output: Dict[str, Any] = Field(default_factory=dict)
    executed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None


class SymbolicExecutionCallbackRequest(BaseModel):
    job_id: str
    scan_id: str
    sample_id: str
    status: Literal["completed", "failed"]
    processed_at: datetime
    findings: List[SymbolicExecutionFindingPayload] = Field(default_factory=list)
    artifacts: List[SymbolicExecutionArtifactPayload] = Field(default_factory=list)
    reports: List[SymbolicExecutionReportPayload] = Field(default_factory=list)
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


class ValidationRequest(BaseModel):
    finding_id: str = Field(
        ..., min_length=1, description="Identifier of the finding to retest"
    )
    notes: Optional[str] = Field(
        default=None,
        max_length=2000,
        description="Optional analyst context for the validator agent.",
    )
    force: bool = Field(
        default=False,
        description="Allow revalidation even if a successful result already exists.",
    )


class ValidationResponse(BaseModel):
    job_id: str
    finding_id: str
    queued_at: datetime
    status: str

    @field_validator("status")
    @classmethod
    def _validate_status(cls, value: str) -> str:
        lowered = value.lower()
        if lowered not in ALLOWED_VALIDATION_STATUSES:
            raise ValueError("Unsupported validation status")
        return lowered


class LegacyValidationCallbackRequest(BaseModel):
    job_id: str = Field(..., min_length=1)
    finding_id: str = Field(..., min_length=1)
    status: str = Field(..., min_length=1, max_length=32)
    validator: str = Field(..., min_length=1, max_length=128)
    executed_at: datetime
    metadata: Dict[str, Any] = Field(default_factory=dict)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    notes: Optional[str] = Field(default=None, max_length=2000)
    requested_by: Optional[str] = Field(default=None, max_length=128)
    requested_at: Optional[datetime] = None

    @field_validator("status")
    @classmethod
    def _validate_status(cls, value: str) -> str:
        lowered = value.lower()
        allowed = {"passed", "failed"}
        if lowered not in allowed:
            raise ValueError("Unsupported validation status")
        return lowered


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
    synced_at: Optional[datetime] = None
    sync_error: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class FindingCommentSummary(BaseModel):
    id: str
    author: str
    message: str
    created_at: datetime


class FindingValidationSummary(BaseModel):
    id: str
    job_id: str
    status: str
    validator: str
    executed_at: datetime
    requested_by: Optional[str] = None
    requested_at: Optional[datetime] = None
    notes: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    evidence: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("status")
    @classmethod
    def _validate_status(cls, value: str) -> str:
        lowered = value.lower()
        if lowered not in ALLOWED_VALIDATION_STATUSES:
            raise ValueError("Unsupported validation status")
        return lowered


class FindingResponse(BaseModel):
    id: str
    scan_id: str
    title: str
    severity: str
    cve_id: Optional[str]
    description: str
    detected_at: datetime
    updated_at: datetime
    status: Literal[
        FINDING_STATUS_PENDING_VALIDATION,
        FINDING_STATUS_OPEN,
        FINDING_STATUS_INVALIDATED,
        FINDING_STATUS_ACKNOWLEDGED,
        FINDING_STATUS_RESOLVED,
    ]
    template_id: str
    evidence: Optional[str]
    remediation: Optional[str]
    enrichments: List[FindingEnrichmentSummary] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    scanner: str
    sample_id: Optional[str] = None
    tool: Optional[str] = None
    category: Literal["web", "binary_static", "binary_fuzzing", "binary_symbolic"]
    assigned_to: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    comment_count: int = 0
    tickets: List[FindingTicketSummary] = Field(default_factory=list)
    validation_status: str
    validated_at: Optional[datetime] = None
    validations: List[FindingValidationSummary] = Field(default_factory=list)
    cvss: float
    scope_status: Literal[
        FINDING_SCOPE_STATUS_UNKNOWN,
        FINDING_SCOPE_STATUS_IN_SCOPE,
        FINDING_SCOPE_STATUS_OUT_OF_SCOPE,
        FINDING_SCOPE_STATUS_MIXED,
    ]


class WorkflowCounts(BaseModel):
    """Aggregate counts for findings grouped by workflow status."""

    pending_validation: int = Field(0, ge=0)
    open: int = Field(0, ge=0)
    invalidated: int = Field(0, ge=0)
    acknowledged: int = Field(0, ge=0)
    resolved: int = Field(0, ge=0)


class FindingCollectionResponse(BaseModel):
    data: List[FindingResponse]
    meta: PaginationMetadata
    workflow_counts: WorkflowCounts


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
    pending_validation: int = 0
    open: int = 0
    invalidated: int = 0
    acknowledged: int = 0
    resolved: int = 0
    total: int = 0


class FindingTimelineCollectionResponse(BaseModel):
    data: List[FindingTimelineBucket]


class FindingAssignmentRequest(BaseModel):
    assignee: str = Field(..., min_length=1, max_length=128)


class FindingStatusUpdateRequest(BaseModel):
    status: Literal[
        FINDING_STATUS_OPEN,
        FINDING_STATUS_ACKNOWLEDGED,
        FINDING_STATUS_RESOLVED,
    ]


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


class ReportExportLocation(BaseModel):
    bucket: str
    key: str
    content_type: str


class ReportExportResponse(BaseModel):
    report_id: str
    format: Literal["html", "pdf"]
    generated_at: datetime
    finding_count: int
    checksum: str
    requested_by: str
    storage: ReportExportLocation
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ReportExportCollectionResponse(BaseModel):
    data: List[ReportExportResponse]
    meta: PaginationMetadata


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

    @field_validator("repository")
    @classmethod
    def validate_repository(cls, value: str) -> str:
        """Enforce canonical owner/repository slug formatting."""

        candidate = value.strip()
        segments = candidate.split("/")
        if len(segments) != 2 or not all(segments):
            raise ValueError("Repository must be in 'owner/repository' format")
        owner, repo = segments
        allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-_.")
        normalized = f"{owner.lower()}/{repo.lower()}"
        if any(ch not in allowed for ch in normalized.replace("/", "")):
            raise ValueError("Repository slug contains unsupported characters")
        return normalized


class TicketResponse(BaseModel):
    id: str
    integration: str
    reference: str
    status: str
    url: Optional[str]
    created_at: datetime
    updated_at: datetime
    synced_at: Optional[datetime] = None
    sync_error: Optional[str] = None
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
        return normalize_severity(value)


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


class ValidationFindingResult(BaseModel):
    finding_id: str = Field(..., min_length=1, max_length=36)
    status: Literal["passed", "failed"]
    observed_at: datetime
    evidence_hash: Optional[str] = None
    severity: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return normalize_severity(value)


class ValidatorCallbackRequest(BaseModel):
    job_id: str = Field(..., min_length=1, max_length=64)
    status: Literal["completed", "failed"]
    processed_at: datetime
    findings: List[ValidationFindingResult] = Field(default_factory=list)
    error: Optional[str] = None


class AnomalyObservation(BaseModel):
    anomaly_type: str = Field(..., min_length=1, max_length=128)
    actor: str = Field(..., min_length=1, max_length=128)
    first_seen: datetime
    last_seen: datetime
    count: int = Field(..., ge=1)
    window_seconds: int = Field(..., ge=1)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("anomaly_type", "actor", mode="before")
    @classmethod
    def _normalize_strings(cls, value: object) -> str:
        if isinstance(value, str):
            candidate = value.strip()
            if candidate:
                return candidate
        raise ValueError("value must be a non-empty string")

    @field_validator("first_seen", "last_seen")
    @classmethod
    def _ensure_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @field_validator("metadata", mode="before")
    @classmethod
    def _normalize_metadata(cls, value: object) -> Dict[str, Any]:
        if value is None:
            return {}
        if isinstance(value, dict):
            return value
        raise ValueError("metadata must be a JSON object")


class AnomalyCallbackRequest(BaseModel):
    source: str = Field(..., min_length=1, max_length=128)
    detected_at: datetime
    anomalies: List[AnomalyObservation] = Field(default_factory=list)

    @field_validator("source", mode="before")
    @classmethod
    def _normalize_source(cls, value: object) -> str:
        if isinstance(value, str):
            candidate = value.strip()
            if candidate:
                return candidate
        raise ValueError("source must be provided")

    @field_validator("detected_at")
    @classmethod
    def _normalize_detected_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def _require_anomalies(self) -> "AnomalyCallbackRequest":
        if not self.anomalies:
            raise ValueError("At least one anomaly must be provided")
        return self


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
    auth_method: Literal["api_key", "jwt", "oidc"]
    roles: List[str] = Field(default_factory=list)
    description: Optional[str] = Field(default=None, max_length=255)
    secret: Optional[str] = Field(default=None, min_length=8, max_length=255)
    expires_at: Optional[datetime] = Field(default=None)

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

    @field_validator("expires_at")
    @classmethod
    def _validate_expiration(cls, value: Optional[datetime]) -> Optional[datetime]:
        if value is not None and value.tzinfo is None:
            raise ValueError("expires_at must include timezone information")
        return value


class PrincipalCredentialResponse(BaseModel):
    id: int
    subject: str
    auth_method: str
    roles: List[str] = Field(default_factory=list)
    description: Optional[str]
    created_at: datetime
    expires_at: Optional[datetime]
    revoked_at: Optional[datetime]
    source: str
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
    ) -> int:  # pragma: no cover - interface definition
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

    def enqueue(self, channel: str, payload: Dict[str, Any]) -> int:
        serialized = json.dumps(payload, sort_keys=True)
        # rpush appends jobs to the right side of the list, providing FIFO ordering.
        self.client.rpush(channel, serialized)
        try:
            depth = int(self.client.llen(channel))
        except Exception:  # pragma: no cover - defensive path for Redis outages
            depth = -1
        return depth


def get_db_session() -> Iterator[Session]:
    """Yield a SQLAlchemy session bound to the configured engine."""

    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def get_queue_client(settings: Settings = Depends(get_settings)) -> QueueClient:
    return RedisQueueClient(settings.redis_url)


def get_notification_service(
    settings: Settings = Depends(get_settings),
) -> NotificationService:
    return build_notification_service(
        slack_webhook=settings.notification_slack_webhook,
        email_sender=settings.notification_email_sender,
        email_recipients=settings.notification_email_recipients,
        smtp_host=settings.smtp_host,
        smtp_port=settings.smtp_port,
        smtp_username=settings.smtp_username,
        smtp_password=settings.smtp_password,
        smtp_use_tls=settings.smtp_use_tls,
    )


@lru_cache()
def _build_report_storage(
    endpoint_url: Optional[str],
    region_name: Optional[str],
    access_key_id: Optional[str],
    secret_access_key: Optional[str],
    session_token: Optional[str],
    force_path_style: bool,
    bucket: str,
    prefix: str,
) -> ReportStorage:
    if not access_key_id or not secret_access_key:
        LOGGER.warning(
            "Report storage credentials missing; using ephemeral in-memory storage",
            extra={"bucket": bucket},
        )
        return EphemeralReportStorage()
    return S3ReportStorage(
        bucket=bucket,
        prefix=prefix,
        endpoint_url=endpoint_url,
        region_name=region_name,
        access_key_id=access_key_id,
        secret_access_key=secret_access_key,
        session_token=session_token,
        force_path_style=force_path_style,
    )


def get_report_storage(settings: Settings = Depends(get_settings)) -> ReportStorage:
    return _build_report_storage(
        settings.s3_endpoint_url,
        settings.s3_region_name,
        settings.s3_access_key_id,
        settings.s3_secret_access_key,
        settings.s3_session_token,
        settings.s3_force_path_style,
        settings.report_export_bucket,
        settings.report_export_prefix,
    )


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
    now = datetime.now(tz=timezone.utc)

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
        expires_at = _normalize_timestamp(active_credential.expires_at)
        if expires_at and expires_at <= now:
            expired_principal = Principal(
                subject=active_credential.subject,
                auth_method="api_key",
                roles=list(active_credential.roles or []),
            )
            log_access_denied(
                db,
                principal=expired_principal,
                required_roles=[],
                resource_type="principal_credential",
                resource_id=str(active_credential.id),
                reason="credential_expired",
                detail="API key expired",
                status_code=status.HTTP_401_UNAUTHORIZED,
                extra_metadata={
                    "credential_id": str(active_credential.id),
                    "credential_status": "expired",
                    "key_fingerprint": fingerprint,
                    "expires_at": expires_at.isoformat(),
                    "api_key_source": source,
                },
            )
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

    now = datetime.now(tz=timezone.utc)
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

    expires_at = _normalize_timestamp(record.expires_at)
    if expires_at and expires_at <= now:
        expired_principal = Principal(
            subject=record.subject,
            auth_method="jwt",
            roles=list(record.roles or []),
        )
        log_access_denied(
            db,
            principal=expired_principal,
            required_roles=[],
            resource_type="principal_credential",
            resource_id=str(record.id),
            reason="credential_expired",
            detail="JWT principal expired",
            status_code=status.HTTP_401_UNAUTHORIZED,
            extra_metadata={
                "credential_id": str(record.id),
                "credential_status": "expired",
                "expires_at": expires_at.isoformat(),
            },
        )

    roles = list(record.roles or [])
    return Principal(subject=record.subject, auth_method="jwt", roles=roles)


def _authenticate_oidc(
    token: str,
    *,
    validator: OIDCValidator,
    settings: Settings,
    db: Session,
) -> Principal:
    """Authenticate an OpenID Connect bearer token."""

    try:
        payload, header = validator.validate(token)
    except OIDCNotApplicableError:
        raise
    except OIDCValidationError as exc:
        invalid_principal = Principal(
            subject="oidc:invalid",
            auth_method="oidc",
            roles=[],
        )
        log_access_denied(
            db,
            principal=invalid_principal,
            required_roles=[],
            resource_type="principal_credential",
            resource_id=None,
            reason=exc.reason,
            detail="Invalid token",
            status_code=status.HTTP_401_UNAUTHORIZED,
            extra_metadata={"error": exc.message, "issuer": validator.issuer},
        )

    subject_claim = settings.oidc_subject_claim or validator.subject_claim
    subject_value = payload.get(subject_claim) or payload.get("sub")
    if not isinstance(subject_value, str) or not subject_value.strip():
        invalid_principal = Principal(
            subject="oidc:anonymous",
            auth_method="oidc",
            roles=[],
        )
        log_access_denied(
            db,
            principal=invalid_principal,
            required_roles=[],
            resource_type="principal_credential",
            resource_id=None,
            reason="invalid_token_payload",
            detail="Invalid token payload",
            status_code=status.HTTP_401_UNAUTHORIZED,
            extra_metadata={"claim": subject_claim},
        )

    now = datetime.now(tz=timezone.utc)
    token_roles_claim = settings.oidc_roles_claim or validator.roles_claim
    raw_roles = payload.get(token_roles_claim) or []
    normalized_roles = [
        str(role).strip() for role in raw_roles if isinstance(role, (str, int))
    ]
    filtered_roles = [role for role in normalized_roles if role in ALLOWED_ROLES]

    auto_allowed_roles = (
        set(settings.oidc_auto_provision_role_allow_list)
        if settings.oidc_auto_provision_role_allow_list
        else set(ALLOWED_ROLES)
    )
    auto_roles_from_token = [
        role for role in filtered_roles if role in auto_allowed_roles
    ]

    raw_groups: Any = None
    if settings.oidc_group_claim:
        raw_groups = payload.get(settings.oidc_group_claim)
    groups: List[str] = []
    if isinstance(raw_groups, str):
        raw_groups = [raw_groups]
    if isinstance(raw_groups, (list, tuple, set)):
        for item in raw_groups:
            if isinstance(item, (str, int)):
                candidate = str(item).strip()
                if candidate:
                    groups.append(candidate)

    mapped_roles: List[str] = []
    for group in groups:
        for medusa_role in settings.oidc_group_role_map.get(group, []):
            if medusa_role in auto_allowed_roles:
                mapped_roles.append(medusa_role)

    desired_roles = sorted(set(auto_roles_from_token + mapped_roles))
    issuer_value = str(payload.get("iss") or validator.issuer or "")
    allowed_issuers = set(settings.oidc_auto_provision_allowed_issuers)
    if settings.oidc_auto_provision and not allowed_issuers:
        LOGGER.warning(
            "OIDC auto-provision is enabled but no issuers are allow-listed",
            extra={"subject": subject_value, "issuer": issuer_value},
        )
    issuer_allowed = bool(allowed_issuers) and issuer_value in allowed_issuers
    auto_enabled = settings.oidc_auto_provision and issuer_allowed

    metadata_base: Dict[str, Any] = {
        "issuer": issuer_value,
        "token_roles": filtered_roles,
        "mapped_roles": sorted(set(mapped_roles)),
        "groups": groups,
        "kid": header.get("kid"),
    }

    record = (
        db.query(PrincipalCredential)
        .filter(
            PrincipalCredential.auth_method == "oidc",
            PrincipalCredential.subject == subject_value,
            PrincipalCredential.revoked_at.is_(None),
        )
        .first()
    )
    just_provisioned = False
    if record is None:
        revoked_record = (
            db.query(PrincipalCredential)
            .filter(
                PrincipalCredential.auth_method == "oidc",
                PrincipalCredential.subject == subject_value,
                PrincipalCredential.revoked_at.isnot(None),
            )
            .order_by(PrincipalCredential.revoked_at.desc())
            .first()
        )
        if revoked_record is not None:
            revoked_principal = Principal(
                subject=str(subject_value),
                auth_method="oidc",
                roles=list(revoked_record.roles or []),
            )
            revoked_metadata = dict(metadata_base)
            revoked_metadata.update(
                {
                    "credential_id": str(revoked_record.id),
                    "credential_status": "revoked",
                    "revoked_at": (
                        revoked_record.revoked_at.isoformat()
                        if revoked_record.revoked_at
                        else None
                    ),
                    "source": revoked_record.source,
                }
            )
            log_access_denied(
                db,
                principal=revoked_principal,
                required_roles=[],
                resource_type="principal_credential",
                resource_id=str(revoked_record.id),
                reason="credential_revoked",
                detail="OIDC credential revoked",
                status_code=status.HTTP_401_UNAUTHORIZED,
                extra_metadata=revoked_metadata,
            )

        if auto_enabled:
            if not desired_roles:
                unauthorized_principal = Principal(
                    subject=str(subject_value),
                    auth_method="oidc",
                    roles=[],
                )
                deny_metadata = dict(metadata_base)
                deny_metadata["issuer_allowed"] = issuer_allowed
                log_access_denied(
                    db,
                    principal=unauthorized_principal,
                    required_roles=[],
                    resource_type="principal_credential",
                    resource_id=None,
                    reason="oidc_provisioning_no_roles",
                    detail="OIDC token did not map to permitted roles",
                    status_code=status.HTTP_403_FORBIDDEN,
                    extra_metadata=deny_metadata,
                )

            ttl_seconds = settings.oidc_auto_provision_expires_in_seconds
            expiration_candidate = (
                now + timedelta(seconds=ttl_seconds) if ttl_seconds else None
            )
            transaction = db.begin_nested() if db.in_transaction() else db.begin()
            new_record = PrincipalCredential(
                subject=subject_value,
                auth_method="oidc",
                roles=desired_roles,
                description="Auto-provisioned via OIDC group mapping",
                expires_at=expiration_candidate,
                source="oidc_auto",
            )
            try:
                with transaction:
                    db.add(new_record)
            except SQLAlchemyError:
                if db.in_transaction():
                    db.rollback()
                LOGGER.exception(
                    "Failed to auto-provision OIDC principal",
                    extra={"subject": subject_value, "issuer": issuer_value},
                )
                failure_principal = Principal(
                    subject=str(subject_value),
                    auth_method="oidc",
                    roles=[],
                )
                failure_metadata = dict(metadata_base)
                failure_metadata["issuer_allowed"] = issuer_allowed
                log_access_denied(
                    db,
                    principal=failure_principal,
                    required_roles=[],
                    resource_type="principal_credential",
                    resource_id=None,
                    reason="oidc_provisioning_failed",
                    detail="OIDC provisioning failed",
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    extra_metadata=failure_metadata,
                )

            record = new_record
            db.refresh(record)
            just_provisioned = True
            provision_actor = Principal(
                subject=record.subject,
                auth_method="oidc",
                roles=list(record.roles or []),
            )
            normalized_expiry = _normalize_timestamp(record.expires_at)
            provision_metadata = dict(metadata_base)
            provision_metadata.update(
                {
                    "credential_id": str(record.id),
                    "assigned_roles": provision_actor.roles,
                    "expires_at": (
                        normalized_expiry.isoformat() if normalized_expiry else None
                    ),
                    "source": record.source,
                }
            )
            record_audit_event(
                db,
                actor=provision_actor,
                action="oidc_auto_provision",
                resource_type="principal_credential",
                resource_id=str(record.id),
                metadata=provision_metadata,
            )
        else:
            unauthorized_principal = Principal(
                subject=str(subject_value),
                auth_method="oidc",
                roles=desired_roles or filtered_roles,
            )
            deny_metadata = dict(metadata_base)
            deny_metadata["issuer_allowed"] = issuer_allowed
            log_access_denied(
                db,
                principal=unauthorized_principal,
                required_roles=[],
                resource_type="principal_credential",
                resource_id=None,
                reason="subject_not_authorized",
                detail="Subject not authorized",
                status_code=status.HTTP_403_FORBIDDEN,
                extra_metadata=deny_metadata,
            )

    stored_roles = list(record.roles or [])
    stored_role_set = set(stored_roles)
    desired_role_set = set(desired_roles)
    current_expiry = _normalize_timestamp(record.expires_at)

    if auto_enabled and record.source == "oidc_auto":
        ttl_seconds = settings.oidc_auto_provision_expires_in_seconds
        expiration_candidate: Optional[datetime] = None
        expiration_changed = False
        if ttl_seconds is not None and not just_provisioned:
            expiration_base = (
                current_expiry if current_expiry and current_expiry > now else now
            )
            expiration_candidate = expiration_base + timedelta(seconds=ttl_seconds)
            if current_expiry is None or expiration_candidate > current_expiry:
                expiration_changed = True
        needs_role_update = desired_role_set != stored_role_set
        needs_expiry_update = bool(expiration_candidate and expiration_changed)
        if needs_role_update or needs_expiry_update:
            previous_roles = list(stored_roles)
            transaction = db.begin_nested() if db.in_transaction() else db.begin()
            try:
                with transaction:
                    if needs_role_update:
                        record.roles = desired_roles
                    if expiration_candidate and expiration_changed:
                        record.expires_at = expiration_candidate
            except SQLAlchemyError:
                if db.in_transaction():
                    db.rollback()
                LOGGER.exception(
                    "Failed to synchronize OIDC roles",
                    extra={"subject": subject_value, "issuer": issuer_value},
                )
                failure_principal = Principal(
                    subject=record.subject,
                    auth_method="oidc",
                    roles=previous_roles,
                )
                failure_metadata = dict(metadata_base)
                failure_metadata.update(
                    {
                        "credential_id": str(record.id),
                        "previous_roles": previous_roles,
                        "desired_roles": desired_roles,
                    }
                )
                log_access_denied(
                    db,
                    principal=failure_principal,
                    required_roles=[],
                    resource_type="principal_credential",
                    resource_id=str(record.id),
                    reason="oidc_role_sync_failed",
                    detail="OIDC role synchronization failed",
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    extra_metadata=failure_metadata,
                )

            db.refresh(record)
            sync_actor = Principal(
                subject=record.subject,
                auth_method="oidc",
                roles=list(record.roles or []),
            )
            normalized_expiry = _normalize_timestamp(record.expires_at)
            sync_metadata = dict(metadata_base)
            sync_metadata.update(
                {
                    "credential_id": str(record.id),
                    "previous_roles": stored_roles,
                    "updated_roles": sync_actor.roles,
                    "expires_at": (
                        normalized_expiry.isoformat() if normalized_expiry else None
                    ),
                }
            )
            if needs_expiry_update:
                sync_metadata["previous_expires_at"] = (
                    current_expiry.isoformat() if current_expiry else None
                )
            record_audit_event(
                db,
                actor=sync_actor,
                action="oidc_role_sync",
                resource_type="principal_credential",
                resource_id=str(record.id),
                metadata=sync_metadata,
            )
            stored_roles = sync_actor.roles
            stored_role_set = set(stored_roles)
    else:
        token_union = set(filtered_roles) | set(mapped_roles)
        if token_union and not token_union.issubset(stored_role_set):
            drift_actor = Principal(
                subject=record.subject,
                auth_method="oidc",
                roles=stored_roles,
            )
            drift_metadata = dict(metadata_base)
            drift_metadata.update(
                {
                    "credential_id": str(record.id),
                    "stored_roles": stored_roles,
                    "token_roles": sorted(token_union),
                }
            )
            record_audit_event(
                db,
                actor=drift_actor,
                action="oidc_role_drift_detected",
                resource_type="principal_credential",
                resource_id=str(record.id),
                metadata=drift_metadata,
            )
            LOGGER.info(
                "OIDC token roles exceed stored principal permissions",
                extra={
                    "subject": subject_value,
                    "token_roles": sorted(token_union),
                    "stored_roles": stored_roles,
                },
            )

    expires_at = _normalize_timestamp(record.expires_at)
    if expires_at and expires_at <= now:
        expired_principal = Principal(
            subject=record.subject,
            auth_method="oidc",
            roles=stored_roles,
        )
        expired_metadata = dict(metadata_base)
        expired_metadata.update(
            {
                "credential_id": str(record.id),
                "credential_status": "expired",
                "expires_at": expires_at.isoformat(),
            }
        )
        log_access_denied(
            db,
            principal=expired_principal,
            required_roles=[],
            resource_type="principal_credential",
            resource_id=str(record.id),
            reason="credential_expired",
            detail="OIDC principal expired",
            status_code=status.HTTP_401_UNAUTHORIZED,
            extra_metadata=expired_metadata,
        )

    return Principal(subject=record.subject, auth_method="oidc", roles=stored_roles)


def enforce_request_rate_limit(
    request: Request,
    *,
    principal: Principal,
    db: Session,
    settings: Settings,
) -> None:
    """Apply per-subject request rate limits when configured."""

    limiter = get_rate_limiter(
        settings.rate_limit_max_requests,
        settings.rate_limit_window_seconds,
        tuple(settings.rate_limit_exempt_subjects),
    )
    if limiter is None or limiter.is_exempt(principal.subject):
        return

    client_host = request.client.host if request.client else "unknown"
    rate_key = principal.subject
    if principal.auth_method == "unauthenticated":
        rate_key = f"anonymous:{client_host}"

    result = limiter.allow(rate_key)
    if result.allowed:
        return

    metadata = dict(result.metadata)
    metadata.setdefault("subject", principal.subject)
    metadata.setdefault("client_host", client_host)
    retry_after = metadata.get("retry_after", settings.rate_limit_window_seconds)
    headers = {"Retry-After": str(retry_after)}

    log_access_denied(
        db,
        principal=principal,
        required_roles=[],
        resource_type="rate_limiter",
        resource_id=rate_key,
        reason="rate_limit_exceeded",
        detail="Too many requests",
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        extra_metadata=metadata,
        headers=headers,
    )


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
            enforce_request_rate_limit(
                request, principal=principal, db=db, settings=settings
            )
            return principal

    if bearer_token:
        validator = get_oidc_validator(
            settings.oidc_issuer,
            settings.oidc_audience,
            settings.oidc_jwks_url,
            settings.oidc_roles_claim,
            settings.oidc_subject_claim,
            tuple(settings.oidc_allowed_algorithms),
            settings.oidc_jwks_cache_ttl_seconds,
            settings.oidc_request_timeout_seconds,
        )
        if validator is not None:
            try:
                principal = _authenticate_oidc(
                    bearer_token, validator=validator, settings=settings, db=db
                )
            except OIDCNotApplicableError:
                principal = None
            else:
                enforce_request_rate_limit(
                    request, principal=principal, db=db, settings=settings
                )
                return principal

        principal = _authenticate_jwt(bearer_token, settings=settings, db=db)
        enforce_request_rate_limit(
            request, principal=principal, db=db, settings=settings
        )
        return principal

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


def authenticate_recon_worker(
    request: Request,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db_session),
) -> Principal:
    """Authenticate recon worker callbacks using a dedicated shared secret."""

    return _authenticate_callback_worker(
        request,
        expected_token=settings.recon_callback_token,
        subject="worker:recon",
        db=db,
        resource_id="recon",
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


def authenticate_validator_worker(
    request: Request,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db_session),
) -> Principal:
    """Authenticate validator worker callbacks using a shared secret header."""

    return _authenticate_callback_worker(
        request,
        expected_token=settings.validator_callback_token,
        subject="worker:validator",
        db=db,
        resource_id="validator",
    )


def authenticate_anomaly_worker(
    request: Request,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db_session),
) -> Principal:
    """Authenticate anomaly worker callbacks using a shared secret header."""

    return _authenticate_callback_worker(
        request,
        expected_token=settings.anomaly_callback_token,
        subject="worker:anomaly",
        db=db,
        resource_id="anomaly",
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


def authenticate_binary_symbolic_worker(
    request: Request,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db_session),
) -> Principal:
    """Authenticate binary symbolic execution worker callbacks."""

    return _authenticate_callback_worker(
        request,
        expected_token=settings.binary_symbolic_execution_callback_token,
        subject="worker:binary-symbolic-execution",
        db=db,
        resource_id="binary-symbolic-execution",
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
    headers: Optional[Dict[str, str]] = None,
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

    raise HTTPException(status_code=status_code, detail=detail, headers=headers)


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
    elif request.auth_method in {"jwt", "oidc"}:
        if secret:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="JWT and OIDC principals do not accept shared secrets",
            )
    else:  # pragma: no cover - guarded by request model validation
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported authentication method",
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
        expires_at=request.expires_at,
        source="manual",
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


def _coerce_recon_timestamp(value: Optional[datetime], fallback: datetime) -> datetime:
    candidate = value or fallback
    if candidate.tzinfo is None:
        candidate = candidate.replace(tzinfo=timezone.utc)
    return candidate


def _aggregate_recon_assets(
    payload: ReconCallbackRequest,
) -> List[Dict[str, Any]]:
    retrieved_at = _coerce_recon_timestamp(
        payload.retrieved_at, datetime.now(tz=timezone.utc)
    )
    aggregated: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for asset in payload.assets:
        normalized = asset.normalized_value.strip()
        if not normalized:
            continue
        key = (asset.asset_type, normalized)
        metadata_payload = asset.metadata if isinstance(asset.metadata, dict) else {}
        first_seen = _coerce_recon_timestamp(asset.first_seen, retrieved_at)
        last_seen = _coerce_recon_timestamp(asset.last_seen, retrieved_at)
        occurrences = max(1, asset.occurrences)
        existing = aggregated.get(key)
        if existing is None:
            aggregated[key] = {
                "asset_type": asset.asset_type,
                "value": normalized,
                "raw_value": asset.raw_value.strip() if asset.raw_value else None,
                "matched_scope": (
                    asset.matched_scope.strip() if asset.matched_scope else None
                ),
                "metadata": dict(metadata_payload),
                "first_seen": first_seen,
                "last_seen": last_seen,
                "occurrences": occurrences,
            }
            continue

        existing_first = _coerce_recon_timestamp(
            existing.get("first_seen"), retrieved_at
        )
        existing_last = _coerce_recon_timestamp(existing.get("last_seen"), retrieved_at)

        existing["occurrences"] += occurrences
        if asset.raw_value and not existing.get("raw_value"):
            existing["raw_value"] = asset.raw_value.strip()
        if asset.matched_scope and not existing.get("matched_scope"):
            existing["matched_scope"] = asset.matched_scope.strip()
        existing_metadata = existing.setdefault("metadata", {})
        existing_metadata.update(metadata_payload)
        if first_seen < existing_first:
            existing_first = first_seen
        if last_seen > existing_last:
            existing_last = last_seen
        existing["first_seen"] = existing_first
        existing["last_seen"] = existing_last

    return list(aggregated.values())


def _merge_recon_metadata(
    existing: Dict[str, Any],
    incoming: Dict[str, Any],
    *,
    source: str,
    existing_source: str,
) -> Dict[str, Any]:
    merged = dict(existing)
    if incoming:
        merged.update(incoming)
    if source and source != existing_source:
        sources = set()
        recorded = merged.get("sources")
        if isinstance(recorded, list):
            sources.update(str(value) for value in recorded)
        sources.add(existing_source)
        sources.add(source)
        merged["sources"] = sorted(sources)
    return merged


def _default_scope_for_discovery(discovery: ReconDiscovery) -> str:
    if discovery.asset_type == "url":
        parsed = urlparse(discovery.value)
        host = parsed.hostname
        if host:
            return host.lower()
    return discovery.value


def _asset_in_scope(asset_type: str, asset_value: str, scope: str) -> bool:
    candidate = scope.strip()
    if not candidate:
        return False
    if asset_type in {"ipv4", "ipv6"}:
        try:
            ip_value = ip_address(asset_value)
        except ValueError:
            return False
        try:
            network = ip_network(candidate, strict=False)
        except ValueError:
            try:
                ip_candidate = ip_address(candidate)
            except ValueError:
                return False
            return ip_value == ip_candidate
        return ip_value in network
    if asset_type == "url":
        parsed = urlparse(asset_value)
        host = parsed.hostname
        if host is None:
            return False
        try:
            ip_value = ip_address(host)
        except ValueError:
            return _asset_in_scope("domain", host.lower(), candidate)
        return _asset_in_scope(
            "ipv6" if ip_value.version == 6 else "ipv4", str(ip_value), candidate
        )
    normalized_asset = asset_value.lower().rstrip(".")
    normalized_scope = candidate.lower().rstrip(".")
    if normalized_scope == normalized_asset:
        return True
    return normalized_asset.endswith(f".{normalized_scope}")


def _classify_target_asset_type(scope: str) -> Literal["domain", "ipv4", "ipv6"]:
    try:
        network = ip_network(scope, strict=False)
    except ValueError:
        return "domain"
    return "ipv6" if network.version == 6 else "ipv4"


def _normalize_seed_for_scope(seed: str, asset_type: str, scope: str) -> Optional[str]:
    candidate = (seed or "").strip()
    if not candidate:
        return None
    if asset_type == "domain":
        normalized = candidate.lower().rstrip(".")
        if not normalized:
            return None
    else:
        try:
            normalized = str(ip_address(candidate))
        except ValueError:
            return None
    if not _asset_in_scope(asset_type, normalized, scope):
        return None
    return normalized


def _prepare_active_recon_targets(
    configs: List[ReconTargetConfig], db: Session
) -> Tuple[List[Dict[str, Any]], List[str]]:
    prepared: List[Dict[str, Any]] = []
    scopes: List[str] = []
    for config in configs:
        target = db.get(Target, config.target_id)
        if target is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Target {config.target_id} not found",
            )
        if not target.is_authorized:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Target is currently outside the authorized scope",
            )
        asset_type = _classify_target_asset_type(target.scope)
        sanitized_seeds: List[str] = []
        for seed in config.seed_assets:
            normalized = _normalize_seed_for_scope(seed, asset_type, target.scope)
            if normalized and normalized not in sanitized_seeds:
                sanitized_seeds.append(normalized)
        payload: Dict[str, Any] = {
            "target_id": target.id,
            "name": target.name,
            "scope": target.scope,
            "asset_type": asset_type,
        }
        if sanitized_seeds:
            payload["seed_assets"] = sanitized_seeds
        prepared.append(payload)
        if target.scope not in scopes:
            scopes.append(target.scope)
    return prepared, scopes


def _discovery_diff_status(
    discovery: ReconDiscovery,
) -> Literal["approved", "in_scope", "scope_extension", "unmatched"]:
    if discovery.status == RECON_STATUS_APPROVED:
        return "approved"
    if discovery.matched_scope:
        normalized_scope = discovery.matched_scope.strip().lower()
        normalized_value = discovery.value.strip().lower()
        if normalized_scope == normalized_value:
            return "in_scope"
        return "scope_extension"
    return "unmatched"


def _scope_within(candidate: str, reference: str) -> bool:
    candidate_value = candidate.strip()
    reference_value = reference.strip()
    if not candidate_value or not reference_value:
        return False

    try:
        reference_network = ip_network(reference_value, strict=False)
    except ValueError:
        try:
            reference_ip = ip_address(reference_value)
        except ValueError:
            candidate_domain = candidate_value.lower().rstrip(".")
            reference_domain = reference_value.lower().rstrip(".")
            if candidate_domain == reference_domain:
                return True
            return candidate_domain.endswith(f".{reference_domain}")
        else:
            try:
                candidate_ip = ip_address(candidate_value)
            except ValueError:
                try:
                    candidate_network = ip_network(candidate_value, strict=False)
                except ValueError:
                    return False
                single_reference = ip_network(
                    f"{reference_ip}/{reference_ip.max_prefixlen}", strict=False
                )
                return candidate_network == single_reference
            return candidate_ip == reference_ip

    try:
        candidate_network = ip_network(candidate_value, strict=False)
    except ValueError:
        try:
            candidate_ip = ip_address(candidate_value)
        except ValueError:
            return False
        return candidate_ip in reference_network
    return (
        candidate_network.subnet_of(reference_network)
        or candidate_network == reference_network
    )


def _upsert_recon_discovery(
    db: Session,
    *,
    source: str,
    asset_type: str,
    value: str,
    raw_value: Optional[str],
    matched_scope: Optional[str],
    metadata: Dict[str, Any],
    first_seen: datetime,
    last_seen: datetime,
    occurrences: int,
) -> Tuple[ReconDiscovery, bool, bool]:
    record = (
        db.query(ReconDiscovery)
        .filter(
            ReconDiscovery.asset_type == asset_type,
            ReconDiscovery.value == value,
        )
        .one_or_none()
    )
    if record is None:
        record = ReconDiscovery(
            source=source,
            asset_type=asset_type,
            value=value,
            raw_value=raw_value or value,
            matched_scope=matched_scope,
            metadata_json=dict(metadata),
            first_seen=first_seen,
            last_seen=last_seen,
            occurrences=max(1, occurrences),
        )
        db.add(record)
        return record, True, bool(matched_scope)

    existing_last_seen = _coerce_recon_timestamp(record.last_seen, last_seen)
    existing_first_seen = _coerce_recon_timestamp(record.first_seen, first_seen)
    incoming_last_seen = _coerce_recon_timestamp(last_seen, existing_last_seen)
    incoming_first_seen = _coerce_recon_timestamp(first_seen, existing_first_seen)

    scope_changed = False
    record.last_seen = max(existing_last_seen, incoming_last_seen)
    record.first_seen = min(existing_first_seen, incoming_first_seen)
    record.occurrences = max(1, record.occurrences + max(1, occurrences))
    if raw_value and not record.raw_value:
        record.raw_value = raw_value
    if matched_scope and matched_scope != (record.matched_scope or ""):
        if not record.matched_scope:
            record.matched_scope = matched_scope
        else:
            record.matched_scope = matched_scope
            scope_changed = True
    record.metadata_json = _merge_recon_metadata(
        record.metadata_json, metadata, source=source, existing_source=record.source
    )
    return record, False, scope_changed


@app.post(
    "/recon/jobs",
    response_model=ReconJobResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def schedule_recon_job(
    request: ReconJobRequest,
    http_request: Request,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
    queue: QueueClient = Depends(get_queue_client),
    settings: Settings = Depends(get_settings),
) -> ReconJobResponse:
    """Queue a recon worker job to pull authorized inventory feeds."""

    enforce_roles(
        principal,
        [ROLE_RECON_ENQUEUE],
        db,
        resource_type="endpoint",
        resource_id="/recon/jobs",
    )

    job_id = str(uuid.uuid4())
    queued_at = datetime.now(tz=timezone.utc)
    callback_url = str(http_request.url_for("recon_callback"))

    execution_payload: Dict[str, Any] = {"mode": request.mode}
    authorized_scopes: List[str]
    job_targets: List[Dict[str, Any]] = []

    if request.mode == "active":
        job_targets, active_scopes = _prepare_active_recon_targets(request.targets, db)
        execution_payload["targets"] = job_targets
        execution_payload["tools"] = request.tools.model_dump(exclude_none=True)
        authorized_scopes = active_scopes
    else:
        execution_payload["tools"] = {}
        authorized_scopes = list(request.authorized_scopes)

    job_payload: Dict[str, Any] = {
        "job_id": job_id,
        "source": request.source,
        "authorized_scopes": authorized_scopes,
        "labels": list(request.labels),
        "queued_at": queued_at.isoformat(),
        "requested_by": principal.subject,
        "callback_url": callback_url,
        "execution": execution_payload,
    }
    if request.mode == "feed" and request.feed is not None:
        job_payload["feed"] = request.feed.model_dump(exclude_none=True)

    queue_depth = queue.enqueue(settings.recon_queue_channel, job_payload)
    metrics.record_job_enqueued(
        "recon", queue_depth=queue_depth if queue_depth >= 0 else None
    )

    record_audit_event(
        db,
        actor=principal,
        action="enqueue_recon_job",
        resource_type="recon_job",
        resource_id=job_id,
        metadata={
            "source": request.source,
            "authorized_scopes": authorized_scopes,
            "labels": list(request.labels),
            "mode": request.mode,
            "target_count": len(job_targets),
        },
    )

    return ReconJobResponse(
        job_id=job_id,
        queued_at=queued_at,
        source=request.source,
        mode=request.mode,
        authorized_scopes=authorized_scopes,
        targets=(
            [ReconTargetConfig.model_validate(target) for target in job_targets]
            if job_targets
            else []
        ),
    )


@app.get(
    "/recon/discoveries",
    response_model=ReconDiscoveryCollectionResponse,
    status_code=status.HTTP_200_OK,
)
def list_recon_discoveries(
    status_filter: Optional[str] = Query(default=None, alias="status"),
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
) -> ReconDiscoveryCollectionResponse:
    enforce_roles(
        principal,
        [ROLE_TARGETS_READ],
        db,
        resource_type="endpoint",
        resource_id="/recon/discoveries",
    )

    query = db.query(ReconDiscovery)
    if status_filter:
        normalized_status = status_filter.strip().lower()
        query = query.filter(ReconDiscovery.status == normalized_status)

    discoveries = query.order_by(ReconDiscovery.last_seen.desc()).limit(200).all()
    data = [
        ReconDiscoveryResponse(
            id=discovery.id,
            source=discovery.source,
            asset_type=discovery.asset_type,
            value=discovery.value,
            raw_value=discovery.raw_value,
            matched_scope=discovery.matched_scope,
            metadata=dict(discovery.metadata_json),
            status=discovery.status,
            first_seen=_coerce_recon_timestamp(
                discovery.first_seen, discovery.first_seen
            ),
            last_seen=_coerce_recon_timestamp(discovery.last_seen, discovery.last_seen),
            occurrences=discovery.occurrences,
            approved_target_id=discovery.approved_target_id,
            diff_status=_discovery_diff_status(discovery),
        )
        for discovery in discoveries
    ]
    return ReconDiscoveryCollectionResponse(data=data)


@app.get(
    "/recon/runs",
    response_model=ReconRunCollectionResponse,
    status_code=status.HTTP_200_OK,
)
def list_recon_runs(
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
    limit: int = Query(default=25, ge=1, le=200),
) -> ReconRunCollectionResponse:
    enforce_roles(
        principal,
        [ROLE_TARGETS_READ],
        db,
        resource_type="endpoint",
        resource_id="/recon/runs",
    )

    runs = (
        db.query(ReconRun)
        .options(selectinload(ReconRun.observations))
        .order_by(ReconRun.retrieved_at.desc())
        .limit(limit)
        .all()
    )
    data = [
        ReconRunResponse(
            id=run.id,
            job_id=run.job_id,
            source=run.source,
            mode=run.mode,
            status=run.status,
            retrieved_at=_coerce_recon_timestamp(run.retrieved_at, run.retrieved_at),
            authorized_scopes=list(run.authorized_scopes or []),
            tooling=dict(run.tooling or {}),
            targets=list(run.targets or []),
            observation_count=len(run.observations or []),
            created_at=run.created_at,
            updated_at=run.updated_at,
        )
        for run in runs
    ]
    return ReconRunCollectionResponse(data=data)


@app.get(
    "/recon/runs/{run_id}/observations",
    response_model=ReconObservationCollectionResponse,
    status_code=status.HTTP_200_OK,
)
def list_recon_run_observations(
    run_id: str,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
) -> ReconObservationCollectionResponse:
    enforce_roles(
        principal,
        [ROLE_TARGETS_READ],
        db,
        resource_type="endpoint",
        resource_id=f"/recon/runs/{run_id}/observations",
    )

    run = (
        db.query(ReconRun)
        .options(selectinload(ReconRun.observations))
        .filter(ReconRun.id == run_id)
        .one_or_none()
    )
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recon run not found",
        )

    observations = sorted(
        run.observations,
        key=lambda item: _coerce_recon_timestamp(item.last_seen, item.last_seen),
        reverse=True,
    )
    data = [
        ReconObservationResponse(
            id=observation.id,
            run_id=observation.run_id,
            target_id=observation.target_id,
            asset_type=observation.asset_type,
            normalized_value=observation.normalized_value,
            raw_value=observation.raw_value,
            matched_scope=observation.matched_scope,
            port=observation.port,
            occurrences=observation.occurrences,
            metadata=dict(observation.metadata_json),
            first_seen=_coerce_recon_timestamp(
                observation.first_seen, observation.first_seen
            ),
            last_seen=_coerce_recon_timestamp(
                observation.last_seen, observation.last_seen
            ),
        )
        for observation in observations
    ]
    return ReconObservationCollectionResponse(data=data)


@app.post(
    "/recon/discoveries/{discovery_id}/approve",
    response_model=TargetResponse,
    status_code=status.HTTP_201_CREATED,
)
def approve_recon_discovery(
    discovery_id: str,
    request: ReconApproveRequest,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
) -> TargetResponse:
    """Approve a recon discovery and onboard it as an authorized target."""

    resource_id = f"/recon/discoveries/{discovery_id}/approve"
    enforce_roles(
        principal,
        [ROLE_TARGETS_WRITE],
        db,
        resource_type="endpoint",
        resource_id=resource_id,
    )

    discovery = db.get(ReconDiscovery, discovery_id)
    if discovery is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Discovery not found",
        )

    if discovery.status == RECON_STATUS_APPROVED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Discovery has already been approved",
        )

    if discovery.status == RECON_STATUS_REJECTED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Discovery has been rejected and cannot be approved",
        )

    default_scope = _default_scope_for_discovery(discovery).strip()
    requested_scope = (request.scope or default_scope).strip()
    if not requested_scope:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to derive a valid scope for the discovery",
        )

    if not _asset_in_scope(discovery.asset_type, discovery.value, requested_scope):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Discovery asset does not fall within the requested scope",
        )

    if discovery.matched_scope and not _scope_within(
        requested_scope, discovery.matched_scope
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Requested scope exceeds the authorized boundary",
        )

    existing_target = (
        db.query(Target).filter(Target.scope == requested_scope).one_or_none()
    )
    if existing_target is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A target with the requested scope already exists",
        )

    target = Target(
        name=request.target_name.strip(),
        scope=requested_scope,
        is_authorized=True,
    )
    discovery.status = RECON_STATUS_APPROVED
    discovery.approved_at = datetime.now(tz=timezone.utc)
    discovery.approved_by = principal.subject
    discovery.approved_target = target
    metadata = dict(discovery.metadata_json)
    metadata["approved_scope"] = requested_scope
    metadata["approved_by"] = principal.subject
    discovery.metadata_json = metadata

    db.add(target)
    db.add(discovery)

    try:
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()
        LOGGER.exception(
            "Failed to approve recon discovery",
            extra={"discovery_id": discovery_id},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to approve discovery",
        ) from exc

    db.refresh(target)

    record_audit_event(
        db,
        actor=principal,
        action="approve_recon_discovery",
        resource_type="recon_discovery",
        resource_id=discovery_id,
        metadata={
            "target_id": target.id,
            "target_scope": target.scope,
            "discovery_status": discovery.status,
        },
    )

    return TargetResponse.model_validate(target, from_attributes=True)


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

    queue_depth = queue.enqueue(queue_channel, job_payload)

    metrics.record_job_enqueued(
        scan.scanner, queue_depth=queue_depth if queue_depth >= 0 else None
    )

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

    queue_depth = queue.enqueue(settings.binary_preprocess_queue_channel, job_payload)

    metrics.record_job_enqueued(
        "binary_preprocess", queue_depth=queue_depth if queue_depth >= 0 else None
    )

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

    queue_depth = queue.enqueue(
        settings.binary_static_analysis_queue_channel, job_payload
    )

    metrics.record_job_enqueued(
        SCAN_TYPE_BINARY_STATIC,
        queue_depth=queue_depth if queue_depth >= 0 else None,
    )

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
    "/binary/symbolic-execution",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def enqueue_binary_symbolic_execution(
    request: BinarySymbolicExecutionRequest,
    http_request: Request,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
    queue: QueueClient = Depends(get_queue_client),
    settings: Settings = Depends(get_settings),
) -> ScanResponse:
    """Queue an angr symbolic execution job for a normalized sample."""

    enforce_roles(
        principal,
        [ROLE_BINARY_SYMBOLIC_EXECUTION_ENQUEUE],
        db,
        resource_type="endpoint",
        resource_id="/binary/symbolic-execution",
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
            action="symbolic_execution_target_mismatch",
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

    scan_parameters: Dict[str, Any] = {
        "sample_id": sample.id,
        "storage_bucket": sample.storage_bucket,
        "storage_key": sample.storage_key,
        "file_name": sample.file_name,
    }
    if request.analysis_depth is not None:
        scan_parameters["analysis_depth"] = request.analysis_depth
    if request.timeout_seconds is not None:
        scan_parameters["timeout_seconds"] = request.timeout_seconds
    if request.metadata:
        scan_parameters["metadata"] = request.metadata

    scan = Scan(
        target_id=sample.target_id,
        scanner=SCAN_TYPE_BINARY_SYMBOLIC,
        parameters=scan_parameters,
        initiated_by=principal.subject,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    submitted_at = datetime.now(tz=timezone.utc)
    job_id = str(uuid.uuid4())
    callback_url = str(http_request.url_for("binary_symbolic_execution_callback"))

    job_metadata: Dict[str, Any] = {
        "scan_id": str(scan.id),
        "sample_id": sample.id,
        "target_id": sample.target_id,
        "target_scope": target.scope,
        "initiated_by": principal.subject,
        "submitted_at": submitted_at.isoformat(),
    }
    if request.analysis_depth is not None:
        job_metadata["analysis_depth"] = request.analysis_depth
    if request.timeout_seconds is not None:
        job_metadata["timeout_seconds"] = request.timeout_seconds
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

    queue_depth = queue.enqueue(
        settings.binary_symbolic_execution_queue_channel, job_payload
    )

    metrics.record_job_enqueued(
        SCAN_TYPE_BINARY_SYMBOLIC,
        queue_depth=queue_depth if queue_depth >= 0 else None,
    )

    record_audit_event(
        db,
        actor=principal,
        action="enqueue_binary_symbolic_execution",
        resource_type="scan",
        resource_id=scan.id,
        scan_id=scan.id,
        metadata={
            "sample_id": sample.id,
            "job_id": job_id,
            "object_bucket": sample.storage_bucket,
            "object_key": sample.storage_key,
            "analysis_depth": request.analysis_depth,
            "timeout_seconds": request.timeout_seconds,
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

    queue_depth = queue.enqueue(settings.binary_fuzzing_queue_channel, job_payload)

    metrics.record_job_enqueued(
        SCAN_TYPE_BINARY_FUZZING,
        queue_depth=queue_depth if queue_depth >= 0 else None,
    )

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
    queue_depth = queue.enqueue(settings.cve_enrichment_queue_channel, job_payload)

    metrics.record_job_enqueued(
        "enrichment_cve", queue_depth=queue_depth if queue_depth >= 0 else None
    )

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


@app.post(
    "/validate",
    response_model=ValidationResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def enqueue_validation(
    request: ValidationRequest,
    http_request: Request,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
    queue: QueueClient = Depends(get_queue_client),
    settings: Settings = Depends(get_settings),
) -> ValidationResponse:
    """Queue a validator job to retest a high-value finding."""

    enforce_roles(
        principal,
        [ROLE_VALIDATION_ENQUEUE],
        db,
        resource_type="endpoint",
        resource_id="/validate",
    )

    finding = (
        db.query(Finding)
        .options(selectinload(Finding.scan).selectinload(Scan.target))
        .filter(Finding.id == request.finding_id)
        .one_or_none()
    )
    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )

    if not request.force and finding.validation_status in FINAL_VALIDATION_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Finding already validated",
        )

    queued_at = datetime.now(tz=timezone.utc)
    job_id = str(uuid.uuid4())
    callback_url = str(http_request.url_for("validator_callback"))

    metadata: Dict[str, Any] = {
        "finding_id": finding.id,
        "scan_id": finding.scan_id,
        "severity": finding.severity,
        "requested_by": principal.subject,
        "requested_at": queued_at.isoformat(),
        "finding_metadata": deepcopy(finding.metadata_json or {}),
    }
    if finding.scan and finding.scan.target:
        metadata["target_id"] = finding.scan.target.id
        metadata["target_scope"] = finding.scan.target.scope
        metadata["target_name"] = finding.scan.target.name
    if finding.scan:
        metadata["scanner"] = finding.scan.scanner
    if request.notes:
        metadata["analyst_notes"] = request.notes

    job_payload = {
        "job_id": job_id,
        "finding_id": finding.id,
        "scan_id": finding.scan_id,
        "severity": finding.severity,
        "callback_url": callback_url,
        "metadata": metadata,
        "evidence": deepcopy(finding.evidence or {}),
        "attempts": 0,
        "submitted_at": queued_at.isoformat(),
    }

    queue_depth = queue.enqueue(settings.validator_queue_channel, job_payload)
    metrics.record_job_enqueued(
        "validation", queue_depth=queue_depth if queue_depth >= 0 else None
    )

    finding.validation_status = "queued"
    finding.validated_at = None
    db.commit()
    db.refresh(finding)

    record_audit_event(
        db,
        actor=principal,
        action="enqueue_validation",
        resource_type="finding",
        resource_id=finding.id,
        finding_id=finding.id,
        metadata={
            "job_id": job_id,
            "force": request.force,
            "notes_provided": bool(request.notes),
        },
    )

    return ValidationResponse(
        job_id=job_id,
        finding_id=finding.id,
        queued_at=queued_at,
        status=finding.validation_status,
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
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
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

    total = query.count()
    scans = query.order_by(Scan.created_at.desc()).offset(offset).limit(limit).all()

    serialized_scans = [serialize_scan(scan) for scan in scans]

    metadata: Dict[str, Any] = {
        "limit": limit,
        "offset": offset,
        "returned": len(serialized_scans),
    }
    if target_id is not None:
        metadata["target_id"] = target_id

    record_audit_event(
        db,
        actor=principal,
        action="list_scans",
        resource_type="scan",
        resource_id=None,
        metadata=metadata,
    )
    return ScanCollectionResponse(
        data=serialized_scans,
        meta=PaginationMetadata(total=total, limit=limit, offset=offset),
    )


@app.get("/anomalies", response_model=AnomalyCollectionResponse)
def list_anomalies(
    anomaly_type: Optional[str] = Query(
        None, alias="type", description="Filter by anomaly type"
    ),
    actor: Optional[str] = Query(None, description="Filter by actor identifier"),
    source: Optional[str] = Query(None, description="Filter by anomaly source"),
    since: Optional[datetime] = Query(None, alias="from"),
    until: Optional[datetime] = Query(None, alias="to"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
) -> AnomalyCollectionResponse:
    """Return sanitized anomaly events with RBAC and pagination."""

    enforce_roles(
        principal,
        [ROLE_ANALYST, ROLE_FINDINGS_READ],
        db,
        resource_type="endpoint",
        resource_id="/anomalies",
    )

    query = db.query(AnomalyEvent)
    applied_filters: Dict[str, Any] = {}

    if anomaly_type:
        sanitized_type = anomaly_type.strip()
        if sanitized_type:
            query = query.filter(AnomalyEvent.anomaly_type == sanitized_type)
            applied_filters["anomaly_type"] = sanitized_type
    if actor:
        sanitized_actor = actor.strip()
        if sanitized_actor:
            query = query.filter(AnomalyEvent.actor == sanitized_actor)
            applied_filters["actor"] = sanitized_actor
    if source:
        sanitized_source = source.strip()
        if sanitized_source:
            query = query.filter(AnomalyEvent.source == sanitized_source)
            applied_filters["source"] = sanitized_source
    if since:
        query = query.filter(AnomalyEvent.detected_at >= since)
        applied_filters["from"] = since.isoformat()
    if until:
        query = query.filter(AnomalyEvent.detected_at <= until)
        applied_filters["to"] = until.isoformat()

    total = query.count()
    records = (
        query.order_by(AnomalyEvent.detected_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    serialized = [serialize_anomaly_event(record) for record in records]

    metadata: Dict[str, Any] = {
        "limit": limit,
        "offset": offset,
        "returned": len(serialized),
    }
    if applied_filters:
        metadata["filters"] = applied_filters

    record_audit_event(
        db,
        actor=principal,
        action="list_anomalies",
        resource_type="anomaly_event",
        resource_id=None,
        metadata=metadata,
    )

    return AnomalyCollectionResponse(
        data=serialized,
        meta=PaginationMetadata(total=total, limit=limit, offset=offset),
    )


@app.get("/anomalies/{anomaly_id}", response_model=AnomalyItemResponse)
def get_anomaly(
    anomaly_id: str,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
) -> AnomalyItemResponse:
    """Return a single anomaly event after RBAC enforcement."""

    enforce_roles(
        principal,
        [ROLE_ANALYST, ROLE_FINDINGS_READ],
        db,
        resource_type="endpoint",
        resource_id=f"/anomalies/{anomaly_id}",
    )

    record = db.query(AnomalyEvent).filter(AnomalyEvent.id == anomaly_id).one_or_none()
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Anomaly not found"
        )

    response_payload = serialize_anomaly_event(record)

    record_audit_event(
        db,
        actor=principal,
        action="view_anomaly",
        resource_type="anomaly_event",
        resource_id=anomaly_id,
        metadata={
            "anomaly_type": record.anomaly_type,
            "actor": record.actor,
            "source": record.source,
        },
    )

    return AnomalyItemResponse(data=response_payload)


def _persist_scan_callback(
    *,
    db: Session,
    scan: Scan,
    payload: ScanCallbackRequest,
    principal: Principal,
    worker_name: str,
    queue: QueueClient,
    settings: Settings,
    validator_callback_url: str,
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

    pending_validation_jobs: List[Dict[str, Any]] = []
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
        submitted_at = datetime.now(tz=timezone.utc)
        job_id = str(uuid.uuid4())
        finding.status = FINDING_STATUS_PENDING_VALIDATION
        finding.validation_status = VALIDATION_STATUS_PENDING
        finding.validation_metadata = {
            "job_id": job_id,
            "status": VALIDATION_STATUS_PENDING,
            "scheduled_at": submitted_at.isoformat(),
            "source_worker": worker_name,
        }
        db.add(finding)
        pending_validation_jobs.append(
            {
                "finding": finding,
                "job_id": job_id,
                "submitted_at": submitted_at,
                "metadata": metadata_payload,
                "evidence": evidence_payload,
            }
        )
        findings_persisted += 1

    if pending_validation_jobs:
        db.flush()

    validation_jobs: List[Dict[str, Any]] = []
    for job_data in pending_validation_jobs:
        finding_record: Finding = job_data["finding"]
        job_payload = _build_validation_job(
            finding=finding_record,
            scan=scan,
            job_id=job_data["job_id"],
            submitted_at=job_data["submitted_at"],
            worker_name=worker_name,
            metadata=job_data["metadata"],
            evidence=job_data["evidence"],
            validator_callback_url=validator_callback_url,
        )
        if job_payload:
            validation_jobs.append(
                {
                    "payload": job_payload,
                    "finding": finding_record,
                }
            )

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

    if settings.validator_queue_channel and validation_jobs:
        for job in validation_jobs:
            depth = queue.enqueue(settings.validator_queue_channel, job["payload"])
            metrics.record_job_enqueued(
                "validation", queue_depth=depth if depth >= 0 else None
            )
            record_audit_event(
                db,
                actor=principal,
                action="enqueue_validation",
                resource_type="finding",
                resource_id=str(job["finding"].id),
                finding_id=str(job["finding"].id),
                scan_id=str(scan.id),
                metadata={
                    "job_id": job["payload"]["job_id"],
                    "validator_queue": settings.validator_queue_channel,
                    "severity": job["finding"].severity,
                },
            )

    return findings_persisted


def _build_validation_job(
    *,
    finding: Finding,
    scan: Scan,
    job_id: str,
    submitted_at: datetime,
    worker_name: str,
    metadata: Dict[str, Any],
    evidence: Dict[str, Any],
    validator_callback_url: str,
) -> Optional[Dict[str, Any]]:
    if not validator_callback_url:
        return None

    target_scope = scan.target.scope if scan.target else None

    job_payload: Dict[str, Any] = {
        "job_id": job_id,
        "finding_id": str(finding.id),
        "scan_id": str(scan.id),
        "target_id": str(scan.target_id),
        "target_scope": target_scope,
        "scanner": scan.scanner,
        "severity": finding.severity,
        "evidence_hash": finding.evidence_hash,
        "callback_url": validator_callback_url,
        "submitted_at": submitted_at.isoformat(),
        "metadata": {
            "source_worker": worker_name,
            "source_scan_created_at": (
                scan.created_at.isoformat() if scan.created_at else None
            ),
        },
    }

    http_steps: List[Dict[str, Any]] = []
    uri = evidence.get("uri") or metadata.get("uri")
    if isinstance(uri, str) and uri.strip().lower().startswith(("http://", "https://")):
        method = evidence.get("method") or metadata.get("method") or "GET"
        expected_status = (
            evidence.get("status") or metadata.get("expected_status") or 200
        )
        http_steps.append(
            {
                "method": str(method).upper(),
                "url": uri.strip(),
                "expected_status": expected_status,
            }
        )

    if http_steps:
        job_payload["verification"] = {"http": http_steps}

    job_payload["metadata"] = {
        key: value
        for key, value in job_payload["metadata"].items()
        if value is not None
    }

    return job_payload


def _handle_scan_callback(
    *,
    db: Session,
    payload: ScanCallbackRequest,
    principal: Principal,
    worker_name: str,
    queue: QueueClient,
    settings: Settings,
    validator_callback_url: str,
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
        queue=queue,
        settings=settings,
        validator_callback_url=validator_callback_url,
    )
    return scan, findings_persisted


def _compute_scan_job_latencies(scan: Scan) -> Tuple[Optional[float], Optional[float]]:
    """Derive queue wait and execution runtimes for a scan job."""

    queue_latency: Optional[float] = None
    runtime: Optional[float] = None

    created_at = _ensure_utc(scan.created_at)
    started_at = _ensure_utc(scan.started_at)
    completed_at = _ensure_utc(scan.completed_at)

    if created_at and started_at:
        queue_latency = max(0.0, (started_at - created_at).total_seconds())

    if started_at and completed_at:
        runtime = max(0.0, (completed_at - started_at).total_seconds())

    return queue_latency, runtime


def _ensure_utc(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _parse_iso_datetime(value: object) -> Optional[datetime]:
    """Parse ISO-8601 timestamps from payload metadata into UTC datetimes."""

    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            return None
        try:
            parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    return None


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


def _persist_binary_symbolic_callback(
    *, db: Session, payload: SymbolicExecutionCallbackRequest
) -> Tuple[Scan, BinarySample, int]:
    scan = db.get(Scan, payload.scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found"
        )
    if scan.scanner != SCAN_TYPE_BINARY_SYMBOLIC:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Scan is not assigned to binary symbolic execution",
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
        db.query(BinarySymbolicExecutionFinding)
        .filter(
            BinarySymbolicExecutionFinding.scan_id == scan.id,
            BinarySymbolicExecutionFinding.job_id == payload.job_id,
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Symbolic execution findings already recorded for this job",
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
        record = BinarySymbolicExecutionFinding(
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
            "Failed to persist binary symbolic execution callback",
            extra={"scan_id": scan.id},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist binary symbolic execution callback",
        ) from exc

    return scan, sample, findings_count


@app.post(
    "/internal/recon",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
def recon_callback(
    payload: ReconCallbackRequest,
    principal: Principal = Depends(authenticate_recon_worker),
    db: Session = Depends(get_db_session),
) -> Response:
    """Persist recon discoveries emitted by the recon worker."""

    aggregated = _aggregate_recon_assets(payload)
    if not aggregated:
        LOGGER.info(
            "Recon callback received without assets",
            extra={"job_id": payload.job_id, "source": payload.source},
        )
        metrics.record_worker_callback("recon", 0)
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    processed = 0
    created_count = 0
    scope_changes = 0
    execution_mode = payload.execution.mode if payload.execution else "feed"
    execution_context = (
        payload.execution.model_dump(exclude_none=True)
        if payload.execution
        else {"mode": execution_mode, "targets": [], "tools": {}}
    )
    run = db.query(ReconRun).filter(ReconRun.job_id == payload.job_id).one_or_none()
    if run is None:
        run = ReconRun(
            job_id=payload.job_id,
            source=payload.source,
            mode=execution_mode,
            status="completed",
            retrieved_at=_coerce_recon_timestamp(
                payload.retrieved_at, payload.retrieved_at
            ),
            authorized_scopes=list(dict.fromkeys(payload.authorized_scopes or [])),
            tooling=execution_context.get("tools", {}),
            targets=execution_context.get("targets", []),
            metadata_json={},
        )
    else:
        run.source = payload.source
        run.mode = execution_mode
        run.status = "completed"
        run.retrieved_at = _coerce_recon_timestamp(
            payload.retrieved_at, run.retrieved_at
        )
        run.authorized_scopes = list(dict.fromkeys(payload.authorized_scopes or []))
        run.tooling = execution_context.get("tools", {})
        run.targets = execution_context.get("targets", [])

    run.metadata_json = {
        "asset_count": len(aggregated),
        "authorized_scopes": list(run.authorized_scopes),
    }
    run.observations.clear()
    db.add(run)

    scope_cache: Dict[str, Optional[str]] = {}
    try:
        for asset in aggregated:
            metadata = dict(asset.get("metadata", {}))
            target_id: Optional[str] = None
            if isinstance(metadata.get("target_id"), str):
                target_id = metadata.get("target_id")
            matched_scope = asset.get("matched_scope")
            if target_id is None and isinstance(matched_scope, str) and matched_scope:
                if matched_scope not in scope_cache:
                    target_obj = (
                        db.query(Target)
                        .filter(Target.scope == matched_scope)
                        .one_or_none()
                    )
                    scope_cache[matched_scope] = target_obj.id if target_obj else None
                cached_id = scope_cache.get(matched_scope)
                if cached_id:
                    target_id = cached_id

            port_value = metadata.get("port")
            try:
                port = int(port_value) if port_value is not None else None
            except (TypeError, ValueError):
                port = None

            observation = ReconObservation(
                run=run,
                target_id=target_id,
                asset_type=asset["asset_type"],
                normalized_value=asset["value"],
                raw_value=asset.get("raw_value"),
                matched_scope=matched_scope,
                port=port,
                occurrences=asset["occurrences"],
                metadata_json=metadata,
                first_seen=asset["first_seen"],
                last_seen=asset["last_seen"],
            )
            run.observations.append(observation)

            _, created, scope_changed = _upsert_recon_discovery(
                db,
                source=payload.source,
                asset_type=asset["asset_type"],
                value=asset["value"],
                raw_value=asset.get("raw_value"),
                matched_scope=asset.get("matched_scope"),
                metadata=metadata,
                first_seen=asset["first_seen"],
                last_seen=asset["last_seen"],
                occurrences=asset["occurrences"],
            )
            processed += 1
            if created:
                created_count += 1
            if scope_changed:
                scope_changes += 1
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()
        LOGGER.exception(
            "Failed to persist recon discoveries",
            extra={"job_id": payload.job_id, "source": payload.source},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist recon discoveries",
        ) from exc

    metrics.record_worker_callback("recon", processed)

    record_audit_event(
        db,
        actor=principal,
        action="recon_callback",
        resource_type="recon_discovery",
        resource_id=None,
        metadata={
            "job_id": payload.job_id,
            "source": payload.source,
            "assets_received": len(payload.assets),
            "assets_persisted": processed,
            "assets_created": created_count,
            "scope_changes": scope_changes,
            "run_id": run.id,
            "mode": execution_mode,
        },
    )

    LOGGER.info(
        "Persisted recon discoveries",
        extra={
            "job_id": payload.job_id,
            "source": payload.source,
            "processed": processed,
            "created": created_count,
            "scope_changes": scope_changes,
            "run_id": run.id,
            "worker_subject": principal.subject,
        },
    )

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.post(
    "/internal/nuclei/callback",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
def nuclei_callback(
    payload: ScanCallbackRequest,
    http_request: Request,
    principal: Principal = Depends(authenticate_nuclei_worker),
    db: Session = Depends(get_db_session),
    queue: QueueClient = Depends(get_queue_client),
    settings: Settings = Depends(get_settings),
) -> Response:
    """Persist nuclei worker results while enforcing evidence immutability."""

    scan, findings_persisted = _handle_scan_callback(
        db=db,
        payload=payload,
        principal=principal,
        worker_name=SCAN_TYPE_NUCLEI,
        queue=queue,
        settings=settings,
        validator_callback_url=str(http_request.url_for("validator_callback")),
    )

    queue_latency, runtime = _compute_scan_job_latencies(scan)
    metrics.record_worker_callback(
        SCAN_TYPE_NUCLEI,
        findings_persisted,
        queue_latency_seconds=queue_latency,
        runtime_seconds=runtime,
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
    http_request: Request,
    principal: Principal = Depends(authenticate_zap_worker),
    db: Session = Depends(get_db_session),
    queue: QueueClient = Depends(get_queue_client),
    settings: Settings = Depends(get_settings),
) -> Response:
    """Persist ZAP worker results."""

    scan, findings_persisted = _handle_scan_callback(
        db=db,
        payload=payload,
        principal=principal,
        worker_name=SCAN_TYPE_ZAP,
        queue=queue,
        settings=settings,
        validator_callback_url=str(http_request.url_for("validator_callback")),
    )

    queue_latency, runtime = _compute_scan_job_latencies(scan)
    metrics.record_worker_callback(
        SCAN_TYPE_ZAP,
        findings_persisted,
        queue_latency_seconds=queue_latency,
        runtime_seconds=runtime,
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
    http_request: Request,
    principal: Principal = Depends(authenticate_sqlmap_worker),
    db: Session = Depends(get_db_session),
    queue: QueueClient = Depends(get_queue_client),
    settings: Settings = Depends(get_settings),
) -> Response:
    """Persist SQLMap worker results."""

    scan, findings_persisted = _handle_scan_callback(
        db=db,
        payload=payload,
        principal=principal,
        worker_name=SCAN_TYPE_SQLMAP,
        queue=queue,
        settings=settings,
        validator_callback_url=str(http_request.url_for("validator_callback")),
    )

    queue_latency, runtime = _compute_scan_job_latencies(scan)
    metrics.record_worker_callback(
        SCAN_TYPE_SQLMAP,
        findings_persisted,
        queue_latency_seconds=queue_latency,
        runtime_seconds=runtime,
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


@app.post("/internal/validator/callback")
def validator_callback(
    payload: ValidatorCallbackRequest | LegacyValidationCallbackRequest,
    principal: Principal = Depends(authenticate_validator_worker),
    db: Session = Depends(get_db_session),
    settings: Settings = Depends(get_settings),
    notification_service: NotificationService = Depends(get_notification_service),
) -> Response:
    """Promote or reject findings based on validator retests."""

    if isinstance(payload, LegacyValidationCallbackRequest):
        return _handle_legacy_validator_callback(
            payload,
            principal=principal,
            db=db,
            settings=settings,
        )

    validation_results: List[Dict[str, Any]] = []
    queue_latency_samples: List[float] = []

    for result in payload.findings:
        finding = db.get(Finding, result.finding_id)
        if finding is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Finding {result.finding_id} not found",
            )
        if (
            result.evidence_hash
            and finding.evidence_hash
            and result.evidence_hash != finding.evidence_hash
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Evidence hash mismatch during validation",
            )
        if finding.status not in {
            FINDING_STATUS_PENDING_VALIDATION,
            FINDING_STATUS_INVALIDATED,
        }:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Finding already validated",
            )

        normalized_status = (
            VALIDATION_STATUS_PASSED
            if result.status == "passed"
            else VALIDATION_STATUS_FAILED
        )

        if result.severity:
            finding.severity = result.severity

        finding.validation_status = normalized_status
        finding.validated_at = result.observed_at
        finding.status = (
            FINDING_STATUS_OPEN
            if normalized_status == VALIDATION_STATUS_PASSED
            else FINDING_STATUS_INVALIDATED
        )

        validation_metadata = deepcopy(_normalize_payload(finding.validation_metadata))
        scheduled_at = _parse_iso_datetime(validation_metadata.get("scheduled_at"))
        if scheduled_at is not None:
            queue_latency_samples.append(
                max(0.0, (result.observed_at - scheduled_at).total_seconds())
            )
        history = validation_metadata.setdefault("history", [])
        history.append(
            {
                "job_id": payload.job_id,
                "status": normalized_status,
                "observed_at": result.observed_at.isoformat(),
                "details": deepcopy(result.details),
            }
        )
        validation_metadata["job_id"] = payload.job_id
        validation_metadata["status"] = normalized_status
        validation_metadata["validator_subject"] = principal.subject
        if payload.error:
            errors = validation_metadata.setdefault("errors", [])
            if payload.error not in errors:
                errors.append(payload.error)
        finding.validation_metadata = validation_metadata

        validation_results.append(
            {
                "finding": finding,
                "status": normalized_status,
                "details": deepcopy(result.details),
            }
        )

    try:
        db.commit()
    except SQLAlchemyError as exc:  # pragma: no cover - defensive path
        db.rollback()
        LOGGER.exception(
            "Failed to persist validator callback",
            extra={"job_id": payload.job_id},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist validator callback",
        ) from exc

    average_queue_latency = (
        sum(queue_latency_samples) / len(queue_latency_samples)
        if queue_latency_samples
        else None
    )
    metrics.record_worker_callback(
        "validator",
        len(validation_results),
        queue_latency_seconds=average_queue_latency,
    )

    notifications: List[CriticalFindingNotification] = []
    for item in validation_results:
        finding: Finding = item["finding"]
        record_audit_event(
            db,
            actor=principal,
            action="validator_callback",
            resource_type="finding",
            resource_id=str(finding.id),
            finding_id=str(finding.id),
            scan_id=str(finding.scan_id),
            metadata={
                "job_id": payload.job_id,
                "validation_status": item["status"],
                "details": item["details"],
            },
            message=payload.error if payload.error else None,
        )

        if (
            finding.severity == "critical"
            and item["status"] == VALIDATION_STATUS_PASSED
        ):
            target_scope = (
                finding.scan.target.scope
                if finding.scan and finding.scan.target
                else None
            )
            notifications.append(
                CriticalFindingNotification(
                    finding_id=str(finding.id),
                    title=finding.title,
                    severity=finding.severity,
                    target=target_scope,
                    scanner=finding.scan.scanner if finding.scan else None,
                    validation_status=item["status"],
                    validated_at=(
                        finding.validated_at.isoformat()
                        if finding.validated_at
                        else None
                    ),
                    evidence_hash=finding.evidence_hash,
                    metadata={
                        "scan_id": str(finding.scan_id),
                        "job_id": payload.job_id,
                    },
                )
            )

    for notification in notifications:
        notification_service.notify_critical_finding(notification)

    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _handle_legacy_validator_callback(
    payload: LegacyValidationCallbackRequest,
    *,
    principal: Principal,
    db: Session,
    settings: Settings,
) -> Response:
    finding = (
        db.query(Finding)
        .options(
            selectinload(Finding.validations),
            selectinload(Finding.scan).selectinload(Scan.target),
        )
        .filter(Finding.id == payload.finding_id)
        .one_or_none()
    )
    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )

    existing = (
        db.query(FindingValidation)
        .filter(FindingValidation.job_id == payload.job_id)
        .one_or_none()
    )
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Validation already recorded",
        )

    executed_at = payload.executed_at.astimezone(timezone.utc)
    normalized_status = payload.status.lower()
    metadata_payload = deepcopy(_normalize_payload(payload.metadata))
    evidence_payload = deepcopy(_normalize_payload(payload.evidence))
    validation = FindingValidation(
        finding_id=finding.id,
        job_id=payload.job_id,
        status=normalized_status,
        validator=payload.validator,
        executed_at=executed_at,
        requested_by=payload.requested_by,
        requested_at=payload.requested_at,
        notes=payload.notes,
        metadata_json=metadata_payload,
        evidence=evidence_payload,
        evidence_hash=_hash_json_payload(evidence_payload),
        metadata_hash=_hash_json_payload(metadata_payload),
    )
    db.add(validation)

    finding.validation_status = normalized_status
    if normalized_status == "passed":
        finding.status = FINDING_STATUS_OPEN
        finding.validated_at = executed_at
    else:
        finding.status = FINDING_STATUS_INVALIDATED
        finding.validated_at = None

    try:
        db.commit()
    except SQLAlchemyError as exc:  # pragma: no cover - defensive path
        db.rollback()
        LOGGER.exception(
            "Failed to persist legacy validator callback",
            extra={"job_id": payload.job_id, "finding_id": payload.finding_id},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist validator callback",
        ) from exc

    db.refresh(finding)
    db.refresh(validation)

    queue_latency: Optional[float] = None
    if payload.requested_at is not None:
        requested_at = payload.requested_at.astimezone(timezone.utc)
        queue_latency = max(0.0, (executed_at - requested_at).total_seconds())

    metrics.record_worker_callback("validator", 1, queue_latency_seconds=queue_latency)

    record_audit_event(
        db,
        actor=principal,
        action="validator_callback",
        resource_type="finding",
        resource_id=str(finding.id),
        finding_id=str(finding.id),
        scan_id=str(finding.scan_id),
        metadata={
            "job_id": payload.job_id,
            "status": normalized_status,
            "validator": payload.validator,
        },
    )

    if normalized_status == "passed":
        _dispatch_validation_notifications(finding, validation, settings)

    response = FindingItemResponse(data=serialize_finding(finding))
    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content=response.model_dump(mode="json"),
    )


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

    queue_latency, runtime = _compute_scan_job_latencies(scan)
    metrics.record_worker_callback(
        SCAN_TYPE_BINARY_STATIC,
        findings_persisted,
        queue_latency_seconds=queue_latency,
        runtime_seconds=runtime,
    )

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

    queue_latency, runtime = _compute_scan_job_latencies(scan)
    metrics.record_worker_callback(
        SCAN_TYPE_BINARY_FUZZING,
        findings_persisted,
        queue_latency_seconds=queue_latency,
        runtime_seconds=runtime,
    )

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
    "/internal/binary/symbolic-execution/callback",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
def binary_symbolic_execution_callback(
    payload: SymbolicExecutionCallbackRequest,
    principal: Principal = Depends(authenticate_binary_symbolic_worker),
    db: Session = Depends(get_db_session),
) -> Response:
    """Persist angr symbolic execution findings and emit audit metadata."""

    scan, sample, findings_persisted = _persist_binary_symbolic_callback(
        db=db,
        payload=payload,
    )

    queue_latency, runtime = _compute_scan_job_latencies(scan)
    metrics.record_worker_callback(
        SCAN_TYPE_BINARY_SYMBOLIC,
        findings_persisted,
        queue_latency_seconds=queue_latency,
        runtime_seconds=runtime,
    )

    record_audit_event(
        db,
        actor=principal,
        action="binary_symbolic_execution_callback",
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
        metrics.record_worker_callback("enrichment", 0, result="error")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found"
        )

    existing = (
        db.query(FindingEnrichment)
        .filter(FindingEnrichment.job_id == payload.job_id)
        .first()
    )
    if existing is not None:
        metrics.record_worker_callback("enrichment", 0, result="error")
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

    payload_material = payload.model_dump(mode="json")
    enrichment = FindingEnrichment(
        finding_id=finding.id,
        job_id=payload.job_id,
        generated_at=generated_at,
        advisories=advisories,
        advisories_hash=_hash_json_payload(advisories),
        errors=errors,
        errors_hash=_hash_json_payload(errors),
        provenance=provenance,
        provenance_hash=_hash_json_payload(provenance),
        payload_hash=_hash_json_payload(payload_material),
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
        metrics.record_worker_callback("enrichment", 0, result="error")
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


@app.post(
    "/internal/anomalies",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
def anomaly_callback(
    payload: AnomalyCallbackRequest,
    principal: Principal = Depends(authenticate_anomaly_worker),
    db: Session = Depends(get_db_session),
    notification_service: NotificationService = Depends(get_notification_service),
) -> Response:
    """Persist anomaly callback payloads and dispatch notifications."""

    for anomaly in payload.anomalies:
        event = AnomalyEvent(
            anomaly_type=anomaly.anomaly_type,
            actor=anomaly.actor,
            source=payload.source,
            detected_at=payload.detected_at,
            first_seen=anomaly.first_seen,
            last_seen=anomaly.last_seen,
            count=anomaly.count,
            window_seconds=anomaly.window_seconds,
            metadata_json=anomaly.metadata,
        )
        db.add(event)

    try:
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()
        LOGGER.exception(
            "Failed to persist anomaly callback",
            extra={"source": payload.source, "count": len(payload.anomalies)},
        )
        metrics.record_worker_callback("anomaly", 0, result="error")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist anomaly events",
        ) from exc

    for anomaly in payload.anomalies:
        notification_service.notify_anomaly(
            AnomalyNotification(
                anomaly_type=anomaly.anomaly_type,
                actor=anomaly.actor,
                source=payload.source,
                count=anomaly.count,
                window_seconds=anomaly.window_seconds,
                first_seen=anomaly.first_seen.isoformat(),
                last_seen=anomaly.last_seen.isoformat(),
                metadata=anomaly.metadata,
            )
        )

    LOGGER.info(
        "Persisted anomaly events",
        extra={
            "source": payload.source,
            "count": len(payload.anomalies),
            "actors": sorted({anomaly.actor for anomaly in payload.anomalies}),
            "worker_subject": principal.subject,
        },
    )

    metrics.record_worker_callback("anomaly", len(payload.anomalies))

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@dataclass(frozen=True)
class FindingQueryFilters:
    """Normalized filters applied when fetching findings from the database."""

    severity: Optional[str]
    status: Optional[str]
    tag: Optional[str]
    assigned_to: Optional[str]
    since: Optional[datetime]
    until: Optional[datetime]
    scope_status: Optional[str]


@dataclass(frozen=True)
class RetrievedFindingRecord:
    """Container linking a category to the ORM record used for serialization."""

    category: str
    detected_at: datetime
    record: Union[
        Finding,
        BinaryStaticAnalysisFinding,
        BinarySymbolicExecutionFinding,
        BinaryFuzzingFinding,
    ]


@dataclass(frozen=True)
class FindingRetrievalResult:
    """Structured result for paginated or full finding lookups."""

    records: List[RetrievedFindingRecord]
    total: int


def _normalize_finding_filters(
    *,
    severity: Optional[str],
    status_filter: Optional[str],
    tag: Optional[str],
    assigned_to: Optional[str],
    since: Optional[datetime],
    until: Optional[datetime],
    scope_status: Optional[str],
) -> Tuple[FindingQueryFilters, Dict[str, Optional[str]]]:
    """Normalize API filter inputs so SQL comparisons remain deterministic."""

    normalized_severity = severity.lower().strip() if severity else None
    normalized_status = status_filter.lower().strip() if status_filter else None
    normalized_tag = tag.lower().strip() if tag else None
    normalized_assignee = assigned_to.strip() if assigned_to else None
    normalized_scope = scope_status.lower().strip() if scope_status else None

    filters = FindingQueryFilters(
        severity=normalized_severity,
        status=normalized_status,
        tag=normalized_tag,
        assigned_to=normalized_assignee,
        since=since,
        until=until,
        scope_status=normalized_scope,
    )

    metadata = {
        "severity": normalized_severity,
        "status": normalized_status,
        "tag": normalized_tag,
        "assigned_to": normalized_assignee,
        "scope": normalized_scope,
        "from": since.isoformat() if since else None,
        "to": until.isoformat() if until else None,
    }

    return filters, metadata


def _binary_categories_allowed(filters: FindingQueryFilters) -> bool:
    """Return ``True`` if binary categories can satisfy the requested filters."""

    if filters.status and filters.status != FINDING_STATUS_OPEN:
        return False
    if filters.tag:
        return False
    if filters.assigned_to:
        return False
    if filters.scope_status and filters.scope_status != FINDING_SCOPE_STATUS_UNKNOWN:
        return False
    return True


def _apply_finding_filters_to_query(
    query,
    *,
    filters: FindingQueryFilters,
    target_id: Optional[str],
    scan_id: Optional[str],
):
    """Apply normalized filters to a ``Finding`` ORM query."""

    if scan_id is not None:
        query = query.filter(Finding.scan_id == scan_id)
    elif target_id is not None:
        query = query.join(Finding.scan).filter(Scan.target_id == target_id)

    if filters.severity:
        query = query.filter(func.lower(Finding.severity) == filters.severity)
    if filters.status:
        query = query.filter(func.lower(Finding.status) == filters.status)
    if filters.tag:
        query = query.filter(Finding.tags.contains([filters.tag]))
    if filters.assigned_to:
        query = query.filter(Finding.assigned_to == filters.assigned_to)
    if filters.scope_status:
        query = query.filter(func.lower(Finding.scope_status) == filters.scope_status)
    if filters.since:
        query = query.filter(Finding.created_at >= filters.since)
    if filters.until:
        query = query.filter(Finding.created_at <= filters.until)
    return query


def _apply_binary_filters_to_query(
    query,
    model,
    *,
    filters: FindingQueryFilters,
    target_id: Optional[str],
    scan_id: Optional[str],
):
    """Apply scan/target/time filters to binary finding ORM queries."""

    if scan_id is not None:
        query = query.filter(model.scan_id == scan_id)
    elif target_id is not None:
        query = query.join(model.scan).filter(Scan.target_id == target_id)

    if filters.severity:
        query = query.filter(func.lower(model.severity) == filters.severity)
    if filters.since:
        query = query.filter(model.executed_at >= filters.since)
    if filters.until:
        query = query.filter(model.executed_at <= filters.until)
    return query


def _empty_workflow_counts() -> Dict[str, int]:
    """Return a zeroed mapping for all supported workflow states."""

    return {
        FINDING_STATUS_PENDING_VALIDATION: 0,
        FINDING_STATUS_OPEN: 0,
        FINDING_STATUS_INVALIDATED: 0,
        FINDING_STATUS_ACKNOWLEDGED: 0,
        FINDING_STATUS_RESOLVED: 0,
    }


def _count_findings_by_workflow_state(
    db: Session,
    *,
    target_id: Optional[str],
    scan_id: Optional[str],
    filters: FindingQueryFilters,
) -> Dict[str, int]:
    """Aggregate filtered findings grouped by workflow status."""

    counts = _empty_workflow_counts()

    status_column = func.lower(Finding.status)
    status_query = db.query(
        status_column.label("status"), func.count(Finding.id).label("count")
    )
    status_query = _apply_finding_filters_to_query(
        status_query,
        filters=filters,
        target_id=target_id,
        scan_id=scan_id,
    )

    for row in status_query.group_by(status_column).all():
        normalized = (row.status or FINDING_STATUS_OPEN).strip().lower()
        if normalized not in counts:
            # Ignore legacy states so the API contract remains stable.
            continue
        counts[normalized] = int(row.count)

    if _binary_categories_allowed(filters):
        binary_models = (
            BinaryStaticAnalysisFinding,
            BinarySymbolicExecutionFinding,
            BinaryFuzzingFinding,
        )
        open_total = counts[FINDING_STATUS_OPEN]
        for model in binary_models:
            binary_query = _apply_binary_filters_to_query(
                db.query(func.count(model.id)),
                model,
                filters=filters,
                target_id=target_id,
                scan_id=scan_id,
            )
            result = binary_query.scalar()
            open_total += int(result or 0)
        counts[FINDING_STATUS_OPEN] = open_total

    return counts


def _hydrate_paginated_records(
    db: Session,
    rows: List[Tuple[str, str, datetime]],
) -> List[RetrievedFindingRecord]:
    """Fetch ORM objects for paginated rows without disturbing ordering."""

    id_buckets: Dict[str, List[str]] = {}
    for category, record_id, _detected_at in rows:
        bucket = id_buckets.setdefault(category, [])
        bucket.append(record_id)

    results: Dict[str, Dict[str, RetrievedFindingRecord]] = {}

    if ids := id_buckets.get("web"):
        records = (
            db.query(Finding)
            .options(
                selectinload(Finding.enrichments),
                selectinload(Finding.comments),
                selectinload(Finding.tickets),
                selectinload(Finding.validations),
            )
            .filter(Finding.id.in_(ids))
            .all()
        )
        results["web"] = {
            str(record.id): RetrievedFindingRecord(
                category="web", detected_at=record.created_at, record=record
            )
            for record in records
        }

    if ids := id_buckets.get("binary_static"):
        records = (
            db.query(BinaryStaticAnalysisFinding)
            .options(selectinload(BinaryStaticAnalysisFinding.scan))
            .filter(BinaryStaticAnalysisFinding.id.in_(ids))
            .all()
        )
        results["binary_static"] = {
            str(record.id): RetrievedFindingRecord(
                category="binary_static",
                detected_at=record.executed_at,
                record=record,
            )
            for record in records
        }

    if ids := id_buckets.get("binary_symbolic"):
        records = (
            db.query(BinarySymbolicExecutionFinding)
            .options(selectinload(BinarySymbolicExecutionFinding.scan))
            .filter(BinarySymbolicExecutionFinding.id.in_(ids))
            .all()
        )
        results["binary_symbolic"] = {
            str(record.id): RetrievedFindingRecord(
                category="binary_symbolic",
                detected_at=record.executed_at,
                record=record,
            )
            for record in records
        }

    if ids := id_buckets.get("binary_fuzzing"):
        records = (
            db.query(BinaryFuzzingFinding)
            .options(selectinload(BinaryFuzzingFinding.scan))
            .filter(BinaryFuzzingFinding.id.in_(ids))
            .all()
        )
        results["binary_fuzzing"] = {
            str(record.id): RetrievedFindingRecord(
                category="binary_fuzzing",
                detected_at=record.executed_at,
                record=record,
            )
            for record in records
        }

    ordered: List[RetrievedFindingRecord] = []
    for category, record_id, detected_at in rows:
        category_records = results.get(category, {})
        record = category_records.get(record_id)
        if record is None:
            continue
        # ``detected_at`` may be truncated when read from SQLite so we reapply it.
        ordered.append(
            RetrievedFindingRecord(
                category=record.category, detected_at=detected_at, record=record.record
            )
        )

    return ordered


def _retrieve_finding_records(
    db: Session,
    *,
    target_id: Optional[str],
    scan_id: Optional[str],
    filters: FindingQueryFilters,
    paginate: bool,
    limit: Optional[int] = None,
    offset: Optional[int] = None,
) -> FindingRetrievalResult:
    """Apply filters and pagination directly in SQL before serialization."""

    include_binary = _binary_categories_allowed(filters)

    base_finding_query = _apply_finding_filters_to_query(
        db.query(Finding),
        filters=filters,
        target_id=target_id,
        scan_id=scan_id,
    )
    web_select = base_finding_query.with_entities(
        literal("web").label("category"),
        Finding.id.label("record_id"),
        Finding.created_at.label("detected_at"),
    ).statement

    select_statements = [web_select]

    if include_binary:
        static_select = (
            _apply_binary_filters_to_query(
                db.query(BinaryStaticAnalysisFinding),
                BinaryStaticAnalysisFinding,
                filters=filters,
                target_id=target_id,
                scan_id=scan_id,
            )
            .with_entities(
                literal("binary_static").label("category"),
                BinaryStaticAnalysisFinding.id.label("record_id"),
                BinaryStaticAnalysisFinding.executed_at.label("detected_at"),
            )
            .statement
        )

        symbolic_select = (
            _apply_binary_filters_to_query(
                db.query(BinarySymbolicExecutionFinding),
                BinarySymbolicExecutionFinding,
                filters=filters,
                target_id=target_id,
                scan_id=scan_id,
            )
            .with_entities(
                literal("binary_symbolic").label("category"),
                BinarySymbolicExecutionFinding.id.label("record_id"),
                BinarySymbolicExecutionFinding.executed_at.label("detected_at"),
            )
            .statement
        )

        fuzzing_select = (
            _apply_binary_filters_to_query(
                db.query(BinaryFuzzingFinding),
                BinaryFuzzingFinding,
                filters=filters,
                target_id=target_id,
                scan_id=scan_id,
            )
            .with_entities(
                literal("binary_fuzzing").label("category"),
                BinaryFuzzingFinding.id.label("record_id"),
                BinaryFuzzingFinding.executed_at.label("detected_at"),
            )
            .statement
        )

        select_statements.extend([static_select, symbolic_select, fuzzing_select])

    if paginate:
        if limit is None or offset is None:
            raise ValueError("Pagination requires explicit limit and offset")

        combined = (
            select_statements[0].subquery()
            if len(select_statements) == 1
            else union_all(*select_statements).subquery()
        )

        total = db.execute(select(func.count()).select_from(combined)).scalar_one()
        if total == 0:
            return FindingRetrievalResult(records=[], total=0)

        windowed = select(
            combined.c.category,
            combined.c.record_id,
            combined.c.detected_at,
            func.row_number()
            .over(order_by=combined.c.detected_at.desc())
            .label("row_number"),
        ).subquery()

        page_stmt = (
            select(
                windowed.c.category,
                windowed.c.record_id,
                windowed.c.detected_at,
            )
            .where(windowed.c.row_number > offset)
            .where(windowed.c.row_number <= offset + limit)
            .order_by(windowed.c.row_number)
        )

        rows = [
            (row.category, str(row.record_id), row.detected_at)
            for row in db.execute(page_stmt).all()
        ]

        records = _hydrate_paginated_records(db, rows)
        return FindingRetrievalResult(records=records, total=total)

    # ``paginate`` disabled for timeline generation; fetch all filtered records.
    web_records = (
        _apply_finding_filters_to_query(
            db.query(Finding).options(
                selectinload(Finding.enrichments),
                selectinload(Finding.comments),
                selectinload(Finding.tickets),
                selectinload(Finding.validations),
            ),
            filters=filters,
            target_id=target_id,
            scan_id=scan_id,
        )
        .order_by(Finding.created_at.desc())
        .all()
    )

    records: List[RetrievedFindingRecord] = [
        RetrievedFindingRecord(
            category="web", detected_at=record.created_at, record=record
        )
        for record in web_records
    ]

    if include_binary:
        static_records = (
            _apply_binary_filters_to_query(
                db.query(BinaryStaticAnalysisFinding).options(
                    selectinload(BinaryStaticAnalysisFinding.scan)
                ),
                BinaryStaticAnalysisFinding,
                filters=filters,
                target_id=target_id,
                scan_id=scan_id,
            )
            .order_by(BinaryStaticAnalysisFinding.executed_at.desc())
            .all()
        )
        records.extend(
            RetrievedFindingRecord(
                category="binary_static",
                detected_at=record.executed_at,
                record=record,
            )
            for record in static_records
        )

        symbolic_records = (
            _apply_binary_filters_to_query(
                db.query(BinarySymbolicExecutionFinding).options(
                    selectinload(BinarySymbolicExecutionFinding.scan)
                ),
                BinarySymbolicExecutionFinding,
                filters=filters,
                target_id=target_id,
                scan_id=scan_id,
            )
            .order_by(BinarySymbolicExecutionFinding.executed_at.desc())
            .all()
        )
        records.extend(
            RetrievedFindingRecord(
                category="binary_symbolic",
                detected_at=record.executed_at,
                record=record,
            )
            for record in symbolic_records
        )

        fuzzing_records = (
            _apply_binary_filters_to_query(
                db.query(BinaryFuzzingFinding).options(
                    selectinload(BinaryFuzzingFinding.scan)
                ),
                BinaryFuzzingFinding,
                filters=filters,
                target_id=target_id,
                scan_id=scan_id,
            )
            .order_by(BinaryFuzzingFinding.executed_at.desc())
            .all()
        )
        records.extend(
            RetrievedFindingRecord(
                category="binary_fuzzing",
                detected_at=record.executed_at,
                record=record,
            )
            for record in fuzzing_records
        )

    records.sort(key=lambda item: item.detected_at, reverse=True)
    return FindingRetrievalResult(records=records, total=len(records))


def _get_mutable_finding(db: Session, finding_id: str) -> Finding:
    finding = (
        db.query(Finding)
        .options(
            selectinload(Finding.enrichments),
            selectinload(Finding.comments),
            selectinload(Finding.tickets),
            selectinload(Finding.validations),
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


def _build_timeline_buckets(
    rows: Iterable[Tuple[datetime, str, int]],
) -> List[FindingTimelineBucket]:
    """Translate aggregated SQL rows into timeline response buckets."""

    timeline: Dict[datetime, Dict[str, int]] = {}
    for bucket_time, status, count in rows:
        if status not in FINDING_TIMELINE_STATUSES:
            # Ignore legacy workflow states that the UI no longer displays.
            continue

        normalized = bucket_time
        if normalized.tzinfo is None:
            normalized = normalized.replace(tzinfo=timezone.utc)
        normalized = normalized.astimezone(timezone.utc)
        normalized = normalized.replace(hour=0, minute=0, second=0, microsecond=0)

        bucket = timeline.setdefault(
            normalized, {state: 0 for state in FINDING_TIMELINE_STATUSES}
        )
        bucket[status] += int(count)

    ordered: List[FindingTimelineBucket] = []
    for timestamp in sorted(timeline.keys()):
        counts = timeline[timestamp]
        total = sum(counts[state] for state in FINDING_TIMELINE_STATUSES)
        ordered.append(
            FindingTimelineBucket(
                date=timestamp,
                pending_validation=counts[FINDING_STATUS_PENDING_VALIDATION],
                open=counts[FINDING_STATUS_OPEN],
                invalidated=counts[FINDING_STATUS_INVALIDATED],
                acknowledged=counts[FINDING_STATUS_ACKNOWLEDGED],
                resolved=counts[FINDING_STATUS_RESOLVED],
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
        lines.append(
            f"Status: {record.status} | CVSS {_severity_to_cvss(record.severity):.1f}"
        )
        lines.append(
            f"Detected: {record.detected_at.isoformat()} | Scan: {record.scan_id}"
        )
        lines.append(f"Tags: {', '.join(record.tags) if record.tags else 'none'}")
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
    buffer.write(b"trailer\n<< /Size %d /Root 1 0 R >>\n" % len(offsets))
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
    scope: Optional[str] = Query(
        None,
        description=(
            "Filter by scope compliance status (unknown, in_scope, out_of_scope, mixed)"
        ),
    ),
    since: Optional[datetime] = Query(None, alias="from"),
    until: Optional[datetime] = Query(None, alias="to"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
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

    filters, metadata_filters = _normalize_finding_filters(
        severity=severity,
        status_filter=status_filter,
        tag=tag,
        assigned_to=assigned_to,
        since=since,
        until=until,
        scope_status=scope,
    )

    result = _retrieve_finding_records(
        db,
        target_id=target_id,
        scan_id=scan_id,
        filters=filters,
        paginate=True,
        limit=limit,
        offset=offset,
    )

    workflow_counts = _count_findings_by_workflow_state(
        db,
        target_id=target_id,
        scan_id=scan_id,
        filters=filters,
    )

    serialized: List[FindingResponse] = []
    for record in result.records:
        if record.category == "web":
            serialized.append(serialize_finding(record.record))
        elif record.category == "binary_static":
            serialized.append(serialize_binary_static_finding(record.record))
        elif record.category == "binary_symbolic":
            serialized.append(serialize_binary_symbolic_finding(record.record))
        elif record.category == "binary_fuzzing":
            serialized.append(serialize_binary_fuzzing_finding(record.record))

    category_counts = Counter(record.category for record in result.records)
    total_records = result.total

    # Track category totals for the returned window to monitor data disclosure.
    web_count = category_counts.get("web", 0)
    static_count = category_counts.get("binary_static", 0)
    symbolic_count = category_counts.get("binary_symbolic", 0)
    fuzzing_count = category_counts.get("binary_fuzzing", 0)

    record_audit_event(
        db,
        actor=principal,
        action="list_findings",
        resource_type="finding",
        resource_id=None,
        scan_id=scan_id,
        metadata={
            "target_id": target_id,
            "limit": limit,
            "offset": offset,
            "returned": len(serialized),
            "total_available": total_records,
            "web_count": web_count,
            "binary_static_count": static_count,
            "binary_symbolic_count": symbolic_count,
            "binary_fuzzing_count": fuzzing_count,
            "filters": metadata_filters,
        },
    )

    return FindingCollectionResponse(
        data=serialized,
        meta=PaginationMetadata(total=total_records, limit=limit, offset=offset),
        workflow_counts=WorkflowCounts(**workflow_counts),
    )


@app.get("/findings/timeline", response_model=FindingTimelineCollectionResponse)
def list_findings_timeline(
    target_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status_filter: Optional[str] = Query(
        None, alias="status", description="Filter by workflow status"
    ),
    tag: Optional[str] = Query(None, description="Filter by tag"),
    scope: Optional[str] = Query(
        None,
        description=(
            "Filter by scope compliance status (unknown, in_scope, out_of_scope, mixed)"
        ),
    ),
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

    filters, metadata_filters = _normalize_finding_filters(
        severity=severity,
        status_filter=status_filter,
        tag=tag,
        assigned_to=assigned_to,
        since=since,
        until=until,
        scope_status=scope,
    )

    bind = db.get_bind()
    dialect_name = bind.dialect.name if bind is not None else ""

    def _bucket_expression(column):
        if dialect_name == "sqlite":
            return func.date(column)
        return func.date_trunc("day", column)

    bucket_column = _bucket_expression(Finding.created_at)
    status_column = func.lower(Finding.status)
    count_column = func.count(Finding.id)

    query = db.query(
        bucket_column.label("bucket"),
        status_column.label("status"),
        count_column.label("count"),
    )
    query = _apply_finding_filters_to_query(
        query,
        filters=filters,
        target_id=target_id,
        scan_id=scan_id,
    )

    aggregated_rows: List[Tuple[object, str, int]] = [
        (row.bucket, row.status, row.count)
        for row in query.group_by(bucket_column, status_column)
        .order_by(bucket_column.asc())
        .all()
    ]

    if _binary_categories_allowed(filters):
        binary_models = (
            BinaryStaticAnalysisFinding,
            BinarySymbolicExecutionFinding,
            BinaryFuzzingFinding,
        )
        for model in binary_models:
            executed_bucket = _bucket_expression(model.executed_at)
            binary_query = _apply_binary_filters_to_query(
                db.query(
                    executed_bucket.label("bucket"),
                    literal(FINDING_STATUS_OPEN).label("status"),
                    func.count(model.id).label("count"),
                ),
                model,
                filters=filters,
                target_id=target_id,
                scan_id=scan_id,
            )
            aggregated_rows.extend(
                (row.bucket, row.status, row.count)
                for row in binary_query.group_by(executed_bucket)
                .order_by(executed_bucket.asc())
                .all()
            )

    def _normalize_bucket(value: object) -> datetime:
        if isinstance(value, datetime):
            normalized = value
        elif isinstance(value, date):
            normalized = datetime.combine(
                value, datetime.min.time(), tzinfo=timezone.utc
            )
        elif isinstance(value, str):
            # SQLite ``date`` emits ISO-8601 strings without timezone data.
            normalized = datetime.fromisoformat(value.replace(" ", "T"))
        else:
            raise TypeError(f"Unsupported timeline bucket type: {type(value)!r}")

        if normalized.tzinfo is None:
            normalized = normalized.replace(tzinfo=timezone.utc)
        return normalized

    normalized_rows: List[Tuple[datetime, str, int]] = [
        (_normalize_bucket(bucket), status, int(count))
        for bucket, status, count in aggregated_rows
    ]

    buckets = _build_timeline_buckets(normalized_rows)

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


@app.get("/findings/scope", response_model=FindingCollectionResponse)
def list_findings_by_scope(
    scope: str = Query(
        ...,
        description=("Return findings matching the provided scope compliance status"),
    ),
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
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
) -> FindingCollectionResponse:
    return list_findings(
        target_id=target_id,
        scan_id=scan_id,
        severity=severity,
        status_filter=status_filter,
        tag=tag,
        assigned_to=assigned_to,
        scope=scope,
        since=since,
        until=until,
        limit=limit,
        offset=offset,
        principal=principal,
        db=db,
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
        return FindingItemResponse(data=serialize_binary_static_finding(static_record))

    symbolic_record = db.get(BinarySymbolicExecutionFinding, finding_id)
    if symbolic_record is not None:
        record_audit_event(
            db,
            actor=principal,
            action="get_binary_symbolic_finding",
            resource_type="finding",
            resource_id=finding_id,
            finding_id=finding_id,
            metadata={
                "scan_id": symbolic_record.scan_id,
                "category": "binary_symbolic",
            },
        )
        return FindingItemResponse(
            data=serialize_binary_symbolic_finding(symbolic_record)
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
        return FindingItemResponse(data=serialize_binary_fuzzing_finding(fuzz_record))

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


@app.get(
    "/findings/{finding_id}/comments", response_model=FindingCommentCollectionResponse
)
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

    metadata_payload = {"source": "analyst"}
    comment = FindingComment(
        finding_id=finding_id,
        author=principal.subject,
        message=message,
        metadata_json=metadata_payload,
        metadata_hash=_hash_json_payload(metadata_payload),
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


@app.post("/findings/{finding_id}/assign", response_model=FindingItemResponse)
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
    if finding.status in {FINDING_STATUS_OPEN, FINDING_STATUS_PENDING_VALIDATION}:
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


@app.post("/findings/{finding_id}/status", response_model=FindingItemResponse)
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


@app.post("/findings/{finding_id}/tags", response_model=FindingItemResponse)
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
    storage: ReportStorage = Depends(get_report_storage),
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
                selectinload(Finding.validations),
                selectinload(Finding.scan).selectinload(Scan.target),
            )
            .filter(Finding.id.in_(request.finding_ids))
        )
        for record in query.all():
            findings_map[str(record.id)] = serialize_finding(record)

    if request.scan_id:
        (
            scan_findings,
            static_findings,
            symbolic_findings,
            fuzzing_findings,
        ) = _retrieve_finding_records(db, target_id=None, scan_id=request.scan_id)
        for record in scan_findings:
            findings_map[str(record.id)] = serialize_finding(record)
        for record in static_findings:
            finding_response = serialize_binary_static_finding(record)
            findings_map[finding_response.id] = finding_response
        for record in symbolic_findings:
            finding_response = serialize_binary_symbolic_finding(record)
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
        content_type = "text/html; charset=utf-8"
        extension = "html"
    else:
        report_bytes = _render_report_pdf(ordered)
        content_type = "application/pdf"
        extension = "pdf"

    generated_at = datetime.now(tz=timezone.utc)
    report_id = str(uuid.uuid4())
    checksum = hashlib.sha256(report_bytes).hexdigest()

    try:
        storage_reference = storage.store(
            report_id=report_id,
            data=report_bytes,
            content_type=content_type,
            extension=extension,
        )
    except ReportStorageError as exc:
        LOGGER.exception(
            "Failed to persist report export", extra={"report_id": report_id}
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to persist report export",
        ) from exc

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

    export_record = ReportExport(
        id=report_id,
        format=request.format,
        content_type=content_type,
        content_length=len(report_bytes),
        content_sha256=checksum,
        storage_bucket=storage_reference.bucket,
        storage_key=storage_reference.key,
        requested_by=principal.subject,
        generated_at=generated_at,
        finding_count=len(ordered),
        scan_id=request.scan_id,
        finding_ids=[record.id for record in ordered],
        metadata_json=metadata,
    )

    db.add(export_record)
    db.commit()
    db.refresh(export_record)

    record_audit_event(
        db,
        actor=principal,
        action="export_report",
        resource_type="report_export",
        resource_id=report_id,
        metadata={
            "report_id": report_id,
            "format": request.format,
            "finding_count": len(ordered),
            "severity_counts": severity_counts,
            "storage_bucket": storage_reference.bucket,
            "storage_key": storage_reference.key,
            "checksum": checksum,
        },
    )

    return ReportExportResponse(
        report_id=report_id,
        format=request.format,
        generated_at=generated_at,
        finding_count=len(ordered),
        checksum=checksum,
        requested_by=principal.subject,
        storage=ReportExportLocation(
            bucket=storage_reference.bucket,
            key=storage_reference.key,
            content_type=content_type,
        ),
        metadata=metadata,
    )


@app.get("/reports/export", response_model=ReportExportCollectionResponse)
def list_report_exports(
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
    scan_id: Optional[str] = Query(None),
    finding_id: Optional[str] = Query(None, alias="findingId"),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> ReportExportCollectionResponse:
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

    query = db.query(ReportExport)
    if scan_id:
        query = query.filter(ReportExport.scan_id == scan_id)
    if finding_id:
        bind = db.get_bind()
        if bind is not None and bind.dialect.name == "sqlite":
            query = query.filter(ReportExport.finding_ids.like(f'%"{finding_id}"%'))
        else:
            query = query.filter(ReportExport.finding_ids.contains([finding_id]))

    total = query.count()

    records = (
        query.order_by(ReportExport.generated_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    payload = [serialize_report_export(record) for record in records]
    return ReportExportCollectionResponse(
        data=payload,
        meta=PaginationMetadata(total=total, limit=limit, offset=offset),
    )


@app.get("/reports/{report_id}")
def download_report_export(
    report_id: str,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
    storage: ReportStorage = Depends(get_report_storage),
) -> Response:
    enforce_roles(
        principal,
        [ROLE_REPORT_EXPORT],
        db,
        resource_type="endpoint",
        resource_id=f"/reports/{report_id}",
    )
    enforce_roles(
        principal,
        [ROLE_FINDINGS_READ],
        db,
        resource_type="endpoint",
        resource_id=f"/reports/{report_id}",
    )

    record = db.get(ReportExport, report_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report export not found",
        )

    reference = ReportStorageReference(
        bucket=record.storage_bucket,
        key=record.storage_key,
        content_type=record.content_type,
    )
    try:
        data = storage.fetch(reference)
    except ReportStorageError as exc:
        LOGGER.exception(
            "Failed to download report export", extra={"report_id": report_id}
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to download report export",
        ) from exc

    checksum = hashlib.sha256(data).hexdigest()
    if checksum != record.content_sha256:
        LOGGER.error(
            "Report export checksum mismatch",
            extra={
                "report_id": report_id,
                "expected": record.content_sha256,
                "observed": checksum,
            },
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Stored report failed integrity verification",
        )

    filename = f"medusa-report-{record.id}.{record.format}"

    record_audit_event(
        db,
        actor=principal,
        action="download_report",
        resource_type="report_export",
        resource_id=str(record.id),
        metadata={
            "report_id": str(record.id),
            "format": record.format,
            "storage_bucket": record.storage_bucket,
            "storage_key": record.storage_key,
        },
    )

    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Report-Checksum": checksum,
        "X-Report-Storage-Bucket": record.storage_bucket,
        "X-Report-Storage-Key": record.storage_key,
    }
    return Response(content=data, media_type=record.content_type, headers=headers)


@app.post(
    "/tickets/jira", response_model=TicketResponse, status_code=status.HTTP_201_CREATED
)
def create_jira_ticket(
    request: JiraTicketRequest,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
    queue: QueueClient = Depends(get_queue_client),
    settings: Settings = Depends(get_settings),
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

    payload_hash = _hash_json_payload(payload)
    ticket = FindingTicket(
        finding_id=finding.id,
        integration="jira",
        reference=reference,
        url=None,
        status="queued",
        payload=payload,
        payload_hash=payload_hash,
        created_by=principal.subject,
    )
    db.add(ticket)
    db.commit()
    db.refresh(ticket)

    job_payload = {"ticket_id": ticket.id, "integration": "jira"}
    try:
        queue_depth = queue.enqueue(
            settings.ticket_dispatch_queue_channel,
            job_payload,
        )
    except Exception as exc:
        LOGGER.exception(
            "Failed to enqueue Jira ticket for dispatch",
            extra={"ticket_id": ticket.id},
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to enqueue Jira ticket for dispatch",
        ) from exc

    metrics.record_job_enqueued(
        "ticket_dispatch",
        queue_depth=queue_depth if queue_depth >= 0 else None,
    )

    record_audit_event(
        db,
        actor=principal,
        action="create_jira_ticket",
        resource_type="finding",
        resource_id=finding.id,
        finding_id=finding.id,
        metadata={
            "reference": reference,
            "project_key": request.project_key.upper(),
            "queue_channel": settings.ticket_dispatch_queue_channel,
        },
    )

    return TicketResponse(
        id=ticket.id,
        integration="jira",
        reference=reference,
        status=ticket.status,
        url=ticket.url,
        created_at=ticket.created_at,
        updated_at=ticket.updated_at,
        synced_at=ticket.synced_at,
        sync_error=ticket.sync_error,
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
    queue: QueueClient = Depends(get_queue_client),
    settings: Settings = Depends(get_settings),
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

    repository = request.repository
    repo_slug = repository.replace("/", "-")
    reference = _generate_ticket_reference(f"GH-{repo_slug}", finding.id, request.title)
    payload = {
        "repository": repository,
        "title": request.title,
        "body": request.body or finding.description,
        "severity": finding.severity,
        "cvss": _severity_to_cvss(finding.severity),
        "finding_id": finding.id,
    }

    payload_hash = _hash_json_payload(payload)
    ticket = FindingTicket(
        finding_id=finding.id,
        integration="github",
        reference=reference,
        url=None,
        status="queued",
        payload=payload,
        payload_hash=payload_hash,
        created_by=principal.subject,
    )
    db.add(ticket)
    db.commit()
    db.refresh(ticket)

    job_payload = {"ticket_id": ticket.id, "integration": "github"}
    try:
        queue_depth = queue.enqueue(
            settings.ticket_dispatch_queue_channel,
            job_payload,
        )
    except Exception as exc:
        LOGGER.exception(
            "Failed to enqueue GitHub ticket for dispatch",
            extra={"ticket_id": ticket.id},
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to enqueue GitHub ticket for dispatch",
        ) from exc

    metrics.record_job_enqueued(
        "ticket_dispatch",
        queue_depth=queue_depth if queue_depth >= 0 else None,
    )

    record_audit_event(
        db,
        actor=principal,
        action="create_github_ticket",
        resource_type="finding",
        resource_id=finding.id,
        finding_id=finding.id,
        metadata={
            "reference": reference,
            "repository": repository,
            "queue_channel": settings.ticket_dispatch_queue_channel,
        },
    )

    return TicketResponse(
        id=ticket.id,
        integration="github",
        reference=reference,
        status=ticket.status,
        url=ticket.url,
        created_at=ticket.created_at,
        updated_at=ticket.updated_at,
        synced_at=ticket.synced_at,
        sync_error=ticket.sync_error,
        metadata=payload,
    )


def serialize_scan(scan: Scan) -> ScanResponse:
    """Project a Scan ORM object into the API contract expected by the UI."""

    target_scope = scan.target.scope if scan.target else ""
    findings_count = (
        len(scan.findings)
        + len(scan.binary_analysis_findings)
        + len(scan.binary_symbolic_execution_findings)
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
        synced_at=ticket.synced_at,
        sync_error=ticket.sync_error,
        metadata=ticket.remote_metadata if ticket.remote_metadata else {},
    )


def serialize_report_export(record: ReportExport) -> ReportExportResponse:
    """Project a persisted report export into the API schema."""

    metadata = deepcopy(record.metadata_json or {})
    return ReportExportResponse(
        report_id=str(record.id),
        format=record.format,
        generated_at=record.generated_at,
        finding_count=record.finding_count,
        checksum=record.content_sha256,
        requested_by=record.requested_by,
        storage=ReportExportLocation(
            bucket=record.storage_bucket,
            key=record.storage_key,
            content_type=record.content_type,
        ),
        metadata=metadata,
    )


def serialize_comment(comment: FindingComment) -> FindingCommentSummary:
    """Serialize immutable analyst commentary."""

    return FindingCommentSummary(
        id=str(comment.id),
        author=comment.author,
        message=comment.message,
        created_at=comment.created_at,
    )


def _post_slack_notification(webhook_url: str, payload: Dict[str, Any]) -> None:
    try:
        response = requests.post(webhook_url, json=payload, timeout=5)
        response.raise_for_status()
    except requests.RequestException as exc:  # pragma: no cover - network errors
        LOGGER.warning(
            "Failed to dispatch Slack notification",
            extra={"error": str(exc)},
        )


def _send_email_notification(settings: Settings, subject: str, body: str) -> None:
    if (
        not settings.email_smtp_host
        or not settings.email_from
        or not settings.email_recipients
    ):
        return

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.email_from
    message["To"] = ", ".join(settings.email_recipients)
    message.set_content(body)

    try:
        with smtplib.SMTP(
            settings.email_smtp_host,
            settings.email_smtp_port,
            timeout=10,
        ) as client:
            if settings.email_use_tls:
                client.starttls()
            if settings.email_username and settings.email_password:
                client.login(settings.email_username, settings.email_password)
            client.send_message(message)
    except Exception as exc:  # pragma: no cover - depends on external SMTP
        LOGGER.warning(
            "Failed to dispatch email notification",
            extra={
                "error": str(exc),
                "recipients": len(settings.email_recipients),
            },
        )


def _dispatch_validation_notifications(
    finding: Finding, validation: FindingValidation, settings: Settings
) -> None:
    if finding.severity.lower() != "critical":
        return

    target_scope = None
    target_name = None
    scanner_name = None
    if finding.scan:
        scanner_name = finding.scan.scanner
        if finding.scan.target:
            target_scope = finding.scan.target.scope
            target_name = finding.scan.target.name

    summary_lines = [
        f"Finding: {finding.title}",
        f"Severity: {finding.severity.upper()}",
        f"Validator: {validation.validator}",
        f"Validated At: {validation.executed_at.isoformat()}",
    ]
    if target_scope:
        summary_lines.append(f"Scope: {target_scope}")
    elif target_name:
        summary_lines.append(f"Target: {target_name}")
    if scanner_name:
        summary_lines.append(f"Scanner: {scanner_name}")
    if validation.notes:
        summary_lines.append(f"Notes: {validation.notes}")

    body = "\n".join(summary_lines)
    subject = f"Medusa critical finding validated: {finding.title}"

    if settings.slack_webhook_url:
        slack_payload = {
            "text": f":rotating_light: {subject}\n{body}",
        }
        _post_slack_notification(settings.slack_webhook_url, slack_payload)

    _send_email_notification(settings, subject, body)


def serialize_anomaly_event(event: AnomalyEvent) -> AnomalyEventResponse:
    """Project an anomaly ORM record into an analyst-safe schema."""

    metadata_payload = deepcopy(_normalize_payload(event.metadata_json))
    sanitized_metadata = _sanitize_anomaly_metadata(metadata_payload)

    return AnomalyEventResponse(
        id=str(event.id),
        anomaly_type=event.anomaly_type,
        actor=event.actor,
        source=event.source,
        detected_at=event.detected_at,
        first_seen=event.first_seen,
        last_seen=event.last_seen,
        count=event.count,
        window_seconds=event.window_seconds,
        metadata=sanitized_metadata,
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

    scanner_value = scanner_name or (
        finding.scan.scanner if finding.scan else "scanner:unknown"
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

    status_value = finding.status or FINDING_STATUS_OPEN
    validation_status = finding.validation_status or (
        VALIDATION_STATUS_PASSED
        if status_value == FINDING_STATUS_OPEN
        else VALIDATION_STATUS_PENDING
    )

    scope_status_value = (
        (finding.scope_status or FINDING_SCOPE_STATUS_UNKNOWN).strip().lower()
    )
    if scope_status_value not in {
        FINDING_SCOPE_STATUS_UNKNOWN,
        FINDING_SCOPE_STATUS_IN_SCOPE,
        FINDING_SCOPE_STATUS_OUT_OF_SCOPE,
        FINDING_SCOPE_STATUS_MIXED,
    }:
        scope_status_value = FINDING_SCOPE_STATUS_UNKNOWN

    metadata_payload.setdefault("severity_score", severity_score(finding.severity))
    metadata_payload.setdefault("validation_status", validation_status)
    validation_payload = deepcopy(_normalize_payload(finding.validation_metadata))
    validation_payload.setdefault("status", validation_status)
    if finding.validated_at:
        validation_payload.setdefault("validated_at", finding.validated_at.isoformat())
    if "validation" not in metadata_payload:
        metadata_payload["validation"] = validation_payload
    tickets_payload: List[FindingTicketSummary] = []
    if hasattr(finding, "tickets") and finding.tickets:
        ordered_tickets = sorted(
            finding.tickets,
            key=lambda record: record.created_at,
            reverse=True,
        )
        tickets_payload = [serialize_ticket(ticket) for ticket in ordered_tickets]

    validations_payload: List[FindingValidationSummary] = []
    if hasattr(finding, "validations") and finding.validations:
        ordered_validations = sorted(
            finding.validations,
            key=lambda record: record.executed_at,
            reverse=True,
        )
        for validation in ordered_validations:
            validations_payload.append(
                FindingValidationSummary(
                    id=str(validation.id),
                    job_id=validation.job_id,
                    status=validation.status,
                    validator=validation.validator,
                    executed_at=validation.executed_at,
                    requested_by=validation.requested_by,
                    requested_at=validation.requested_at,
                    notes=validation.notes,
                    metadata=deepcopy(validation.metadata_json or {}),
                    evidence=deepcopy(validation.evidence or {}),
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
        status=status_value,
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
        validation_status=finding.validation_status or "pending",
        validated_at=finding.validated_at,
        validations=validations_payload,
        cvss=_severity_to_cvss(finding.severity),
        scope_status=scope_status_value,
    )


def serialize_binary_static_finding(
    record: BinaryStaticAnalysisFinding,
) -> FindingResponse:
    metadata_payload = deepcopy(_normalize_payload(record.metadata_json))
    metadata_payload.setdefault("scanner", SCAN_TYPE_BINARY_STATIC)
    metadata_payload.setdefault("tool", record.tool)
    metadata_payload.setdefault("severity_score", severity_score(record.severity))
    metadata_payload.setdefault("validation_status", VALIDATION_STATUS_PASSED)
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
        str(template_id_source) if template_id_source else f"{record.tool}:finding"
    )

    if "validation" not in metadata_payload:
        metadata_payload["validation"] = {
            "status": VALIDATION_STATUS_PASSED,
            "validated_at": record.executed_at.isoformat(),
        }

    return FindingResponse(
        id=str(record.id),
        scan_id=str(record.scan_id),
        title=record.title,
        severity=record.severity,
        cve_id=metadata_payload.get("cve_id"),
        description=record.description,
        detected_at=record.executed_at,
        updated_at=record.updated_at or record.executed_at,
        status=FINDING_STATUS_OPEN,
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
        validation_status="pending",
        validated_at=None,
        validations=[],
        cvss=_severity_to_cvss(record.severity),
        scope_status=FINDING_SCOPE_STATUS_UNKNOWN,
    )


def serialize_binary_symbolic_finding(
    record: BinarySymbolicExecutionFinding,
) -> FindingResponse:
    metadata_payload = deepcopy(_normalize_payload(record.metadata_json))
    metadata_payload.setdefault("scanner", SCAN_TYPE_BINARY_SYMBOLIC)
    metadata_payload.setdefault("tool", record.tool)
    metadata_payload.setdefault("severity_score", severity_score(record.severity))
    metadata_payload.setdefault("validation_status", VALIDATION_STATUS_PASSED)
    evidence_payload = _normalize_payload(record.evidence)
    evidence_text = (
        json.dumps(evidence_payload, sort_keys=True) if evidence_payload else None
    )
    template_id_source = (
        metadata_payload.get("path_id")
        or metadata_payload.get("trace_id")
        or metadata_payload.get("finding_id")
    )
    template_id = (
        str(template_id_source) if template_id_source else f"{record.tool}:finding"
    )

    if "validation" not in metadata_payload:
        metadata_payload["validation"] = {
            "status": VALIDATION_STATUS_PASSED,
            "validated_at": record.executed_at.isoformat(),
        }

    return FindingResponse(
        id=str(record.id),
        scan_id=str(record.scan_id),
        title=record.title,
        severity=record.severity,
        cve_id=metadata_payload.get("cve_id"),
        description=record.description,
        detected_at=record.executed_at,
        updated_at=record.updated_at or record.executed_at,
        status=FINDING_STATUS_OPEN,
        template_id=template_id,
        evidence=evidence_text,
        remediation=None,
        enrichments=[],
        metadata=metadata_payload,
        scanner=SCAN_TYPE_BINARY_SYMBOLIC,
        sample_id=str(record.sample_id),
        tool=record.tool,
        category="binary_symbolic",
        assigned_to=None,
        tags=[],
        comment_count=0,
        tickets=[],
        validation_status="pending",
        validated_at=None,
        validations=[],
        cvss=_severity_to_cvss(record.severity),
        scope_status=FINDING_SCOPE_STATUS_UNKNOWN,
    )


def serialize_binary_fuzzing_finding(
    record: BinaryFuzzingFinding,
) -> FindingResponse:
    metadata_payload = deepcopy(_normalize_payload(record.metadata_json))
    metadata_payload.setdefault("scanner", SCAN_TYPE_BINARY_FUZZING)
    metadata_payload.setdefault("tool", record.tool)
    metadata_payload.setdefault("severity_score", severity_score(record.severity))
    metadata_payload.setdefault("validation_status", VALIDATION_STATUS_PASSED)
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
        str(template_id_source) if template_id_source else f"{record.tool}:crash"
    )

    if "validation" not in metadata_payload:
        metadata_payload["validation"] = {
            "status": VALIDATION_STATUS_PASSED,
            "validated_at": record.executed_at.isoformat(),
        }

    return FindingResponse(
        id=str(record.id),
        scan_id=str(record.scan_id),
        title=record.title,
        severity=record.severity,
        cve_id=metadata_payload.get("cve_id"),
        description=record.description,
        detected_at=record.executed_at,
        updated_at=record.updated_at or record.executed_at,
        status=FINDING_STATUS_OPEN,
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
        validation_status="pending",
        validated_at=None,
        validations=[],
        cvss=_severity_to_cvss(record.severity),
        scope_status=FINDING_SCOPE_STATUS_UNKNOWN,
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
    "authenticate_anomaly_worker",
    "ScanCallbackRequest",
    "AnomalyCallbackRequest",
]
