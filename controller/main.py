"""FastAPI controller for coordinating scan workflows.

This module exposes routes for managing scan targets, enqueueing nuclei scan
jobs, ingesting worker callbacks, and retrieving findings. It couples HTTP
requests to a queue backend (Redis) and an SQLAlchemy/Postgres persistence
layer, while emitting structured audit events for each call.
"""
from __future__ import annotations
import hashlib
import json
import logging
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Dict, Iterable, Iterator, List, Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, field_validator
try:  # pragma: no cover - compatibility shim for environments without pydantic-settings
    from pydantic_settings import BaseSettings
except ModuleNotFoundError:  # pragma: no cover
    class BaseSettings(BaseModel):  # type: ignore[override]
        """Minimal stand-in used when pydantic-settings is unavailable."""

        class Config:
            arbitrary_types_allowed = True
from redis import Redis
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, selectinload

from controller.db.models import AuditLog, Finding, Scan, Target
from controller.db.session import SessionLocal


LOGGER = logging.getLogger("medusa.controller")
AUDIT_LOGGER = logging.getLogger("medusa.audit")


class Settings(BaseSettings):
    """Runtime configuration for the controller service."""

    database_url: str = Field(
        "postgresql+psycopg2://medusa:medusa@localhost:5432/medusa",
        description="SQLAlchemy URL for the Postgres database.",
    )
    redis_url: str = Field(
        "redis://localhost:6379/0", description="Connection string for Redis queue backend."
    )
    nuclei_queue_channel: str = Field(
        "queues:nuclei:jobs", description="Redis list channel for nuclei scan jobs."
    )
    jwt_secret: str = Field(..., description="JWT secret used to validate bearer tokens.")
    api_keys: List[str] = Field(default_factory=list, description="Static API keys for service accounts.")
    nuclei_callback_token: str = Field(
        ..., description="Shared secret token required for nuclei worker callbacks."
    )

    class Config:
        env_prefix = "MEDUSA_"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """Return cached settings instance."""

    return Settings()
def _normalize_payload(payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Ensure payloads used for hashing are deterministic dictionaries."""

    if payload is None:
        return {}
    return payload


class TargetCreateRequest(BaseModel):
    """Request body for registering a new authorized target."""

    name: str = Field(..., min_length=1, max_length=255, description="Friendly target name")
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
    """Serialized target representation."""

    id: str
    name: str
    scope: str
    is_authorized: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanRequest(BaseModel):
    """Request body for scheduling a scan job."""

    target_id: str
    scanner: str = Field(..., min_length=1, max_length=64, description="Scanner identifier")
    parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Scanner-specific configuration payload",
    )


class ScanResponse(BaseModel):
    """Serialized scan representation returned to clients."""

    id: str
    target_id: str
    target: str
    scanner: str
    status: str
    initiated_by: Optional[str]
    created_at: datetime
    updated_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    findings_count: int

    model_config = ConfigDict(from_attributes=True)


class ScanCollectionResponse(BaseModel):
    data: List[ScanResponse]


class FindingResponse(BaseModel):
    """Serialized finding representation returned to clients."""

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

    model_config = ConfigDict(from_attributes=True)


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


class NucleiCallbackRequest(BaseModel):
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


class Principal(BaseModel):
    subject: str
    auth_method: str
    roles: List[str] = Field(default_factory=list)

    def has_role(self, role: str) -> bool:
        return role in self.roles

    def has_any_role(self, roles: Iterable[str]) -> bool:
        role_set = set(self.roles)
        return any(role in role_set for role in roles)


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def enforce_roles(principal: Principal, required_roles: Iterable[str]) -> None:
    if principal.has_role("admin"):
        return
    if not principal.has_any_role(required_roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient role for this operation",
        )


class QueueClient:
    """Abstract queue client that can enqueue scan jobs."""

    def enqueue(self, channel: str, payload: Dict[str, Any]) -> None:  # pragma: no cover - interface definition
        raise NotImplementedError


class RedisQueueClient(QueueClient):
    """Redis-backed queue client pushing serialized jobs into a list."""

    def __init__(self, redis_url: str) -> None:
        self._redis_url = redis_url
        self._client: Optional[Redis] = None

    @property
    def client(self) -> Redis:
        if self._client is None:
            self._client = Redis.from_url(self._redis_url, encoding="utf-8", decode_responses=True)
        return self._client

    def enqueue(self, channel: str, payload: Dict[str, Any]) -> None:
        serialized = json.dumps(payload, sort_keys=True)
        # rpush is used to append jobs to the right side of the list, providing FIFO ordering.
        self.client.rpush(channel, serialized)
security_scheme = HTTPBearer(auto_error=False)


def authenticate(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    settings: Settings = Depends(get_settings),
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
            roles=["admin", "scan:enqueue", "targets:write", "findings:read"],
        )

    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

    token = credentials.credentials
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
    except jwt.PyJWTError as exc:  # pragma: no cover - exercised indirectly
        LOGGER.warning("JWT validation failed", extra={"error": str(exc)})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc

    subject = payload.get("sub")
    if not subject:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    roles_payload = payload.get("roles", [])
    if isinstance(roles_payload, str):
        roles = [roles_payload]
    elif isinstance(roles_payload, Iterable):
        roles = [str(role) for role in roles_payload]
    else:
        roles = [str(roles_payload)] if roles_payload else []

    return Principal(subject=str(subject), auth_method="jwt", roles=roles)


def authenticate_worker(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> Principal:
    """Authenticate nuclei worker callbacks using a shared secret header."""

    token = request.headers.get("X-Callback-Token")
    if not token or token != settings.nuclei_callback_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid callback token")

    return Principal(subject="worker:nuclei", auth_method="shared_secret")


def get_db_session() -> Iterator[Session]:
    """Yield a SQLAlchemy session bound to the configured engine."""

    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def get_queue_client(settings: Settings = Depends(get_settings)) -> QueueClient:
    return RedisQueueClient(settings.redis_url)


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

    snapshot: Dict[str, Any] = {
        "resource_type": resource_type,
        "resource_id": resource_id,
        "metadata": metadata or {},
    }

    event = AuditLog(
        scan_id=scan_id,
        finding_id=finding_id,
        actor=actor.subject,
        action=action,
        message=message or f"{resource_type}.{action}",
        evidence_snapshot=snapshot,
    )
    session.add(event)
    try:
        session.commit()
        session.refresh(event)
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
            "metadata": metadata or {},
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        },
    )

    return event


app = FastAPI(title="Medusa Controller", version="0.1.0")


@app.post("/targets", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
def create_target(
    request: TargetCreateRequest,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
) -> TargetResponse:
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

    return TargetResponse.model_validate(target)


@app.post("/scan", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
def enqueue_scan(
    request: ScanRequest,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
    queue: QueueClient = Depends(get_queue_client),
    settings: Settings = Depends(get_settings),
) -> ScanResponse:
    enforce_roles(principal, ["scan:enqueue"])
    target = db.get(Target, request.target_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")

    if not target.is_authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Target is currently outside the authorized scope",
        )

    scan = Scan(
        target_id=target.id,
        scanner=request.scanner,
        parameters=request.parameters,
        initiated_by=principal.subject,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    job_payload = {
        "scan_id": scan.id,
        "target_id": target.id,
        "scanner": scan.scanner,
        "parameters": scan.parameters,
        "initiated_by": principal.subject,
        "submitted_at": datetime.now(tz=timezone.utc).isoformat(),
    }
    queue.enqueue(settings.nuclei_queue_channel, job_payload)

    record_audit_event(
        db,
        actor=principal,
        action="enqueue_scan",
        resource_type="scan",
        resource_id=scan.id,
        scan_id=scan.id,
        metadata={"target_id": target.id, "scanner": scan.scanner},
    )

    return serialize_scan(scan)


@app.get("/scans", response_model=ScanCollectionResponse)
def list_scans(
    target_id: Optional[str] = None,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
) -> ScanCollectionResponse:
    """Return the most recent scans for the authenticated principal."""

    query = db.query(Scan).options(selectinload(Scan.target), selectinload(Scan.findings))
    if target_id is not None:
        query = query.filter(Scan.target_id == target_id)

    scans = query.order_by(Scan.created_at.desc()).all()
    return ScanCollectionResponse(data=[serialize_scan(scan) for scan in scans])


@app.post(
    "/internal/nuclei/callback",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
def nuclei_callback(
    payload: NucleiCallbackRequest,
    principal: Principal = Depends(authenticate_worker),
    db: Session = Depends(get_db_session),
) -> Response:
    """Persist nuclei worker results while enforcing evidence immutability."""

    scan = db.get(Scan, payload.scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    if scan.status in {"completed", "failed"}:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Scan already finalized")

    if scan.findings:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Scan findings already recorded")

    if payload.started_at and scan.started_at is None:
        scan.started_at = payload.started_at
    elif scan.started_at is None:
        scan.started_at = datetime.now(tz=timezone.utc)

    scan.status = payload.status
    if payload.status in {"completed", "failed"}:
        scan.completed_at = payload.completed_at or datetime.now(tz=timezone.utc)

    findings_persisted = 0
    for finding_payload in payload.findings:
        finding = Finding(
            scan_id=scan.id,
            title=finding_payload.title,
            severity=finding_payload.severity,
            cve_id=finding_payload.cve_id,
            description=finding_payload.description,
            evidence=_normalize_payload(finding_payload.evidence),
            evidence_hash="",
        )
        db.add(finding)
        findings_persisted += 1

    try:
        db.commit()
    except SQLAlchemyError as exc:  # pragma: no cover - exercised in error handling tests
        db.rollback()
        LOGGER.exception(
            "Failed to persist nuclei callback payload", extra={"scan_id": payload.scan_id}
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist callback",
        ) from exc

    record_audit_event(
        db,
        actor=principal,
        action="nuclei_callback",
        resource_type="scan",
        resource_id=str(scan.id),
        metadata={
            "status": payload.status,
            "findings_count": findings_persisted,
            "error": payload.error,
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
        metadata={"target_id": target_id, "scan_id": scan_id},
    )

    return FindingCollectionResponse(data=[serialize_finding(finding) for finding in findings])


@app.get("/findings/{finding_id}", response_model=FindingItemResponse)
def get_finding(
    finding_id: str,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
) -> FindingItemResponse:
    """Fetch a single finding for detailed analysis views."""

    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

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
    evidence_payload = _normalize_payload(finding.evidence)
    evidence_text = json.dumps(evidence_payload, sort_keys=True) if evidence_payload else None

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
        template_id=finding.cve_id or "nuclei:unspecified",
        evidence=evidence_text,
        remediation=None,
    )


__all__ = [
    "app",
    "get_settings",
    "Settings",
    "Target",
    "Scan",
    "Finding",
    "AuditLog",
    "ScanResponse",
    "ScanCollectionResponse",
    "FindingResponse",
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
]
