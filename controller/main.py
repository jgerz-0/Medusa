"""FastAPI controller for coordinating scan workflows.

This module exposes routes for managing scan targets, enqueueing nuclei scan
jobs, and retrieving findings. It couples HTTP requests to a queue backend
(Redis) and an SQLAlchemy/Postgres persistence layer, while emitting structured
audit events for each call.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Dict, List, Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, BaseSettings, ConfigDict, Field
from redis import Redis
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from controller.db.models import AuditLog, Base, Finding, Scan, Target


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

    class Config:
        env_prefix = "MEDUSA_"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """Return cached settings instance."""

    return Settings()


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
    scanner: str
    status: str
    parameters: Dict[str, Any]
    initiated_by: Optional[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FindingResponse(BaseModel):
    """Serialized finding representation."""

    id: str
    scan_id: str
    severity: str
    title: str
    description: str
    cve_id: Optional[str]
    evidence: Dict[str, Any]
    evidence_hash: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class Principal(BaseModel):
    subject: str
    auth_method: str


@lru_cache()
def _engine_from_url(url: str) -> Engine:
    """Cache database engines per URL."""

    return create_engine(url, future=True, pool_pre_ping=True)


@lru_cache()
def _session_factory_from_url(url: str) -> sessionmaker:
    """Cache session factories bound to the cached engines."""

    engine = _engine_from_url(url)
    return sessionmaker(bind=engine, expire_on_commit=False, class_=Session)


def get_engine(settings: Settings) -> Engine:
    return _engine_from_url(settings.database_url)


def get_session_factory(settings: Settings) -> sessionmaker:
    return _session_factory_from_url(settings.database_url)


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

    api_key = request.headers.get("X-API-Key")
    if api_key and api_key in settings.api_keys:
        return Principal(subject=f"apikey:{api_key}", auth_method="api_key")

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

    return Principal(subject=subject, auth_method="jwt")


def get_db_session(settings: Settings = Depends(get_settings)):
    """Yield a SQLAlchemy session bound to the configured engine."""

    session_factory = get_session_factory(settings)
    session = session_factory()
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
) -> None:
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

    return ScanResponse.model_validate(scan)


@app.get("/findings", response_model=List[FindingResponse])
def list_findings(
    target_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
) -> List[FindingResponse]:
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

    return [FindingResponse.model_validate(finding) for finding in findings]


__all__ = [
    "app",
    "get_settings",
    "Settings",
    "Base",
    "Target",
    "Scan",
    "Finding",
    "AuditLog",
    "get_db_session",
    "get_queue_client",
    "RedisQueueClient",
    "QueueClient",
]
