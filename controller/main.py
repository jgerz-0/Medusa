"""FastAPI controller for coordinating scan workflows.

This module exposes routes for managing scan targets, enqueueing nuclei scan
jobs, and retrieving findings. It couples HTTP requests to a queue backend
(Redis) and an SQLAlchemy/Postgres persistence layer, while emitting structured
audit events for each call.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Dict, Iterable, List, Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import AnyHttpUrl, BaseModel, BaseSettings, Field, root_validator
from redis import Redis
from sqlalchemy import JSON, Column, DateTime, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker


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


Base = declarative_base()


class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    url = Column(String(1024), nullable=False, unique=True)
    scope = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(tz=timezone.utc))

    scans = relationship("Scan", back_populates="target", cascade="all,delete")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target_id = Column(Integer, ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    profile = Column(String(128), nullable=False)
    status = Column(String(32), nullable=False, default="queued")
    requested_hosts = Column(JSON, nullable=False)
    initiated_by = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(tz=timezone.utc))

    target = relationship("Target", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all,delete")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    severity = Column(String(32), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(tz=timezone.utc))

    scan = relationship("Scan", back_populates="findings")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    actor = Column(String(255), nullable=False)
    action = Column(String(128), nullable=False)
    resource_type = Column(String(64), nullable=False)
    resource_id = Column(String(64), nullable=True)
    metadata_json = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(tz=timezone.utc))


class ScopeDefinition(BaseModel):
    """Approved scope for a target or scan request."""

    allowed_hosts: List[str] = Field(..., description="List of fully qualified hostnames allowed for scanning.")

    @root_validator
    def validate_hosts(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        hosts = values.get("allowed_hosts", [])
        if not hosts:
            raise ValueError("At least one allowed host must be provided.")
        for host in hosts:
            if not host or " " in host:
                raise ValueError("Invalid host entry in allowed_hosts.")
        return values


class TargetCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    url: AnyHttpUrl
    scope: ScopeDefinition

    @root_validator
    def ensure_url_in_scope(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        url = values.get("url")
        scope = values.get("scope")
        if url and scope:
            hostname = url.host
            if hostname not in scope.allowed_hosts:
                raise ValueError("Target URL hostname is not in the approved scope.")
        return values


class TargetResponse(BaseModel):
    id: int
    name: str
    url: AnyHttpUrl
    scope: ScopeDefinition

    class Config:
        orm_mode = True


class ScanRequest(BaseModel):
    target_id: int
    profile: str = Field(..., min_length=1, max_length=128)
    requested_hosts: List[str] = Field(..., description="Hosts that should be scanned for this run.")

    @root_validator
    def ensure_requested_hosts(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        hosts = values.get("requested_hosts", [])
        if not hosts:
            raise ValueError("At least one host must be requested for scanning.")
        for host in hosts:
            if not host or " " in host:
                raise ValueError("Invalid host entry in requested_hosts.")
        return values


class ScanResponse(BaseModel):
    id: int
    target_id: int
    profile: str
    status: str
    requested_hosts: List[str]

    class Config:
        orm_mode = True


class FindingResponse(BaseModel):
    id: int
    scan_id: int
    severity: str
    title: str
    description: str
    created_at: datetime

    class Config:
        orm_mode = True


class Principal(BaseModel):
    subject: str
    auth_method: str
    roles: List[str] = Field(default_factory=list)

    def has_role(self, role: str) -> bool:
        return role in self.roles

    def has_any_role(self, roles: Iterable[str]) -> bool:
        role_set = set(self.roles)
        return any(role in role_set for role in roles)


class PrincipalCredential(Base):
    __tablename__ = "principal_credentials"

    id = Column(Integer, primary_key=True, autoincrement=True)
    subject = Column(String(255), nullable=False, unique=True)
    auth_method = Column(String(32), nullable=False)
    key_hash = Column(String(128), nullable=True)
    roles = Column(JSON, nullable=False, default=list)
    description = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(tz=timezone.utc))
    revoked_at = Column(DateTime(timezone=True), nullable=True)


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


def get_db_session(settings: Settings = Depends(get_settings)):
    """Yield a SQLAlchemy session bound to the configured engine."""

    session_factory = get_session_factory(settings)
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


security_scheme = HTTPBearer(auto_error=False)


def authenticate(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db_session),
) -> Principal:
    """Authenticate caller via JWT bearer token or API key headers."""

    api_key = request.headers.get("X-API-Key")
    if api_key:
        key_hash = _hash_secret(api_key)
        record = (
            db.query(PrincipalCredential)
            .filter(
                PrincipalCredential.auth_method == "api_key",
                PrincipalCredential.key_hash == key_hash,
                PrincipalCredential.revoked_at.is_(None),
            )
            .first()
        )
        if record:
            return Principal(
                subject=record.subject,
                auth_method="api_key",
                roles=list(record.roles or []),
            )
        if api_key in settings.api_keys:
            LOGGER.warning("Using legacy static API key configuration", extra={"subject": api_key})
            return Principal(
                subject=f"apikey:{api_key}",
                auth_method="api_key",
                roles=["legacy"],
            )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

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
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Subject not authorized")

    roles = list(record.roles or [])
    if not roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Subject not authorized")

    return Principal(subject=subject, auth_method="jwt", roles=roles)


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
) -> None:
    """Persist and emit audit information about sensitive operations."""

    event = AuditEvent(
        actor=actor.subject,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        metadata_json=metadata or {},
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
    existing = db.query(Target).filter(Target.url == str(request.url)).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Target already exists")

    target = Target(name=request.name, url=str(request.url), scope=request.scope.dict())
    db.add(target)
    db.commit()
    db.refresh(target)

    record_audit_event(
        db,
        actor=principal,
        action="create_target",
        resource_type="target",
        resource_id=str(target.id),
        metadata={"url": target.url},
    )

    return TargetResponse.from_orm(target)


@app.post("/scan", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
def enqueue_scan(
    request: ScanRequest,
    principal: Principal = Depends(authenticate),
    db: Session = Depends(get_db_session),
    queue: QueueClient = Depends(get_queue_client),
    settings: Settings = Depends(get_settings),
) -> ScanResponse:
    enforce_roles(principal, ["scan:enqueue"])
    target = db.query(Target).get(request.target_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")

    allowed_hosts: Iterable[str] = target.scope.get("allowed_hosts", [])
    if not set(request.requested_hosts).issubset(set(allowed_hosts)):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Requested hosts outside scope")

    scan = Scan(
        target_id=target.id,
        profile=request.profile,
        requested_hosts=request.requested_hosts,
        initiated_by=principal.subject,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    job_payload = {
        "scan_id": scan.id,
        "target_id": target.id,
        "profile": scan.profile,
        "requested_hosts": scan.requested_hosts,
        "initiated_by": principal.subject,
        "submitted_at": datetime.now(tz=timezone.utc).isoformat(),
    }
    queue.enqueue(settings.nuclei_queue_channel, job_payload)

    record_audit_event(
        db,
        actor=principal,
        action="enqueue_scan",
        resource_type="scan",
        resource_id=str(scan.id),
        metadata={"target_id": target.id, "profile": scan.profile},
    )

    return ScanResponse.from_orm(scan)


@app.get("/findings", response_model=List[FindingResponse])
def list_findings(
    target_id: Optional[int] = None,
    scan_id: Optional[int] = None,
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
        metadata={"target_id": target_id, "scan_id": scan_id},
    )

    return [FindingResponse.from_orm(finding) for finding in findings]


__all__ = [
    "app",
    "get_settings",
    "Settings",
    "Target",
    "Scan",
    "Finding",
    "AuditEvent",
    "PrincipalCredential",
    "get_db_session",
    "get_queue_client",
    "RedisQueueClient",
    "QueueClient",
    "_hash_secret",
]
