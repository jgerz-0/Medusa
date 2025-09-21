import base64
import types
from datetime import datetime, timedelta, timezone
from typing import Generator, Tuple

import jwt
import pytest
from fastapi import HTTPException, status
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from controller.db.models import AuditLog, PrincipalCredential
from controller.main import (
    ROLE_ADMIN,
    ROLE_TARGETS_READ,
    Settings,
    Principal,
    _authenticate_oidc,
    enforce_request_rate_limit,
    get_oidc_validator,
    get_rate_limiter,
)
from controller.security.oidc import OIDCSettings, OIDCValidator
from controller.tests.conftest import api_client  # noqa: F401  # re-export fixture


@pytest.fixture()
def controller_api_client(
    api_client: Generator[
        Tuple[TestClient, object, sessionmaker, Settings], None, None
    ],
) -> Tuple[TestClient, object, sessionmaker, Settings]:
    return api_client


def _oct_secret(secret: str) -> str:
    raw = base64.urlsafe_b64encode(secret.encode("utf-8")).decode("ascii")
    return raw.rstrip("=")


@pytest.mark.parametrize("extra_role", [["untracked"], []])
def test_oidc_bearer_token_authenticates(
    controller_api_client: Tuple[TestClient, object, sessionmaker, Settings],
    extra_role: list[str],
) -> None:
    _client, _queue, session_factory, settings = controller_api_client
    get_oidc_validator.cache_clear()  # type: ignore[attr-defined]

    _configure_oidc(settings)
    validator = _build_validator(settings)

    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": "oidc-analyst",
        "iss": settings.oidc_issuer,
        "aud": settings.oidc_audience,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "roles": [ROLE_TARGETS_READ, *extra_role],
    }
    token = jwt.encode(
        payload,
        TEST_SHARED_SECRET,
        algorithm="HS256",
        headers={"kid": TEST_KID},
    )

    with session_factory() as session:
        session.add(
            PrincipalCredential(
                subject="oidc-analyst",
                auth_method="oidc",
                roles=[ROLE_TARGETS_READ],
            )
        )
        session.commit()

        principal = _authenticate_oidc(
            token,
            validator=validator,
            settings=settings,
            db=session,
        )

    assert principal.subject == "oidc-analyst"
    assert ROLE_TARGETS_READ in principal.roles

    get_oidc_validator.cache_clear()  # type: ignore[attr-defined]


def test_oidc_auto_provision_creates_principal_and_audit_log(
    controller_api_client: Tuple[TestClient, object, sessionmaker, Settings],
) -> None:
    _client, _queue, session_factory, settings = controller_api_client
    get_oidc_validator.cache_clear()  # type: ignore[attr-defined]

    _configure_oidc(settings)
    settings.oidc_auto_provision = True
    settings.oidc_auto_provision_allowed_issuers = [settings.oidc_issuer]
    settings.oidc_group_role_map = {
        "medusa-analysts": [ROLE_TARGETS_READ],
    }
    settings.oidc_auto_provision_role_allow_list = [ROLE_TARGETS_READ]
    settings.oidc_auto_provision_expires_in_seconds = 600

    validator = _build_validator(settings)
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": "oidc-auto",
        "iss": settings.oidc_issuer,
        "aud": settings.oidc_audience,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "groups": ["medusa-analysts"],
    }
    token = jwt.encode(
        payload,
        TEST_SHARED_SECRET,
        algorithm="HS256",
        headers={"kid": TEST_KID},
    )

    with session_factory() as session:
        principal = _authenticate_oidc(
            token,
            validator=validator,
            settings=settings,
            db=session,
        )

        assert principal.subject == "oidc-auto"
        assert principal.roles == [ROLE_TARGETS_READ]

        credential = (
            session.query(PrincipalCredential)
            .filter(PrincipalCredential.subject == "oidc-auto")
            .one()
        )
        assert credential.source == "oidc_auto"
        assert credential.roles == [ROLE_TARGETS_READ]
        assert credential.expires_at is not None
        assert _as_utc(credential.expires_at) > now

        audit_entry = (
            session.query(AuditLog)
            .filter(AuditLog.action == "oidc_auto_provision")
            .one()
        )
        metadata = audit_entry.evidence_snapshot
        assert metadata["assigned_roles"] == [ROLE_TARGETS_READ]
        assert metadata["source"] == "oidc_auto"

    get_oidc_validator.cache_clear()  # type: ignore[attr-defined]


def test_oidc_auto_provision_syncs_roles_and_extends_expiry(
    controller_api_client: Tuple[TestClient, object, sessionmaker, Settings],
) -> None:
    _client, _queue, session_factory, settings = controller_api_client
    get_oidc_validator.cache_clear()  # type: ignore[attr-defined]

    _configure_oidc(settings)
    settings.oidc_auto_provision = True
    settings.oidc_auto_provision_allowed_issuers = [settings.oidc_issuer]
    settings.oidc_group_role_map = {
        "medusa-admins": [ROLE_ADMIN],
    }
    settings.oidc_auto_provision_role_allow_list = [ROLE_ADMIN]
    settings.oidc_auto_provision_expires_in_seconds = 600

    validator = _build_validator(settings)
    now = datetime.now(tz=timezone.utc)

    with session_factory() as session:
        session.add(
            PrincipalCredential(
                subject="oidc-auto",
                auth_method="oidc",
                roles=[ROLE_TARGETS_READ],
                source="oidc_auto",
                expires_at=now - timedelta(minutes=5),
            )
        )
        session.commit()

        payload = {
            "sub": "oidc-auto",
            "iss": settings.oidc_issuer,
            "aud": settings.oidc_audience,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
            "groups": ["medusa-admins"],
        }
        token = jwt.encode(
            payload,
            TEST_SHARED_SECRET,
            algorithm="HS256",
            headers={"kid": TEST_KID},
        )

        principal = _authenticate_oidc(
            token,
            validator=validator,
            settings=settings,
            db=session,
        )

        assert principal.roles == [ROLE_ADMIN]

        credential = (
            session.query(PrincipalCredential)
            .filter(PrincipalCredential.subject == "oidc-auto")
            .one()
        )
        assert credential.roles == [ROLE_ADMIN]
        assert credential.expires_at is not None
        assert _as_utc(credential.expires_at) > now

        audit_entry = (
            session.query(AuditLog).filter(AuditLog.action == "oidc_role_sync").one()
        )
        metadata = audit_entry.evidence_snapshot
        assert metadata["previous_roles"] == [ROLE_TARGETS_READ]
        assert metadata["updated_roles"] == [ROLE_ADMIN]

    get_oidc_validator.cache_clear()  # type: ignore[attr-defined]


def test_oidc_revoked_principal_is_denied(
    controller_api_client: Tuple[TestClient, object, sessionmaker, Settings],
) -> None:
    _client, _queue, session_factory, settings = controller_api_client
    get_oidc_validator.cache_clear()  # type: ignore[attr-defined]

    _configure_oidc(settings)
    settings.oidc_auto_provision = True
    settings.oidc_auto_provision_allowed_issuers = [settings.oidc_issuer]
    settings.oidc_group_role_map = {"medusa-analysts": [ROLE_TARGETS_READ]}
    settings.oidc_auto_provision_role_allow_list = [ROLE_TARGETS_READ]
    settings.oidc_auto_provision_expires_in_seconds = 600

    validator = _build_validator(settings)
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": "oidc-auto",
        "iss": settings.oidc_issuer,
        "aud": settings.oidc_audience,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "groups": ["medusa-analysts"],
    }
    token = jwt.encode(
        payload,
        TEST_SHARED_SECRET,
        algorithm="HS256",
        headers={"kid": TEST_KID},
    )

    with session_factory() as session:
        session.add(
            PrincipalCredential(
                subject="oidc-auto",
                auth_method="oidc",
                roles=[ROLE_TARGETS_READ],
                revoked_at=now,
                source="oidc_auto",
            )
        )
        session.commit()

        with pytest.raises(HTTPException) as exc_info:
            _authenticate_oidc(
                token,
                validator=validator,
                settings=settings,
                db=session,
            )

        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED

        audit_entry = (
            session.query(AuditLog)
            .filter(AuditLog.action == "access_denied")
            .order_by(AuditLog.created_at.desc())
            .first()
        )
        assert audit_entry is not None
        metadata = audit_entry.evidence_snapshot
        assert metadata["reason"] == "credential_revoked"
        assert metadata["credential_status"] == "revoked"

    get_oidc_validator.cache_clear()  # type: ignore[attr-defined]


def test_rate_limiting_enforced(
    controller_api_client: Tuple[TestClient, object, sessionmaker, Settings],
) -> None:
    _client, _queue, session_factory, settings = controller_api_client
    get_rate_limiter.cache_clear()  # type: ignore[attr-defined]

    settings.rate_limit_max_requests = 2
    settings.rate_limit_window_seconds = 60
    settings.rate_limit_exempt_subjects = []

    principal = Principal(subject="limit-tester", auth_method="api_key", roles=[])
    request = types.SimpleNamespace(client=types.SimpleNamespace(host="127.0.0.1"))

    with session_factory() as session:
        enforce_request_rate_limit(
            request, principal=principal, db=session, settings=settings
        )
        enforce_request_rate_limit(
            request, principal=principal, db=session, settings=settings
        )
        with pytest.raises(HTTPException) as exc_info:
            enforce_request_rate_limit(
                request, principal=principal, db=session, settings=settings
            )

    assert exc_info.value.status_code == 429
    get_rate_limiter.cache_clear()  # type: ignore[attr-defined]


TEST_KID = "unit-test"
TEST_SHARED_SECRET = "oidc-secret"


def _configure_oidc(settings: Settings) -> None:
    settings.oidc_issuer = "https://issuer.test"
    settings.oidc_audience = "medusa-api"
    settings.oidc_jwks_url = "https://issuer.test/jwks"
    settings.oidc_allowed_algorithms = ["HS256"]
    settings.oidc_roles_claim = "roles"
    settings.oidc_subject_claim = "sub"
    settings.oidc_jwks_cache_ttl_seconds = 60
    settings.oidc_request_timeout_seconds = 5


def _build_validator(settings: Settings) -> OIDCValidator:
    jwks_document = {
        "keys": [
            {
                "kty": "oct",
                "kid": TEST_KID,
                "k": _oct_secret(TEST_SHARED_SECRET),
            }
        ]
    }

    return OIDCValidator(
        OIDCSettings(
            issuer=settings.oidc_issuer,
            jwks_url=settings.oidc_jwks_url,
            audience=settings.oidc_audience,
            roles_claim=settings.oidc_roles_claim,
            subject_claim=settings.oidc_subject_claim,
            allowed_algorithms=("HS256",),
            cache_ttl_seconds=settings.oidc_jwks_cache_ttl_seconds,
            request_timeout_seconds=settings.oidc_request_timeout_seconds,
        ),
        jwks_loader=lambda _url, _timeout: jwks_document,
    )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
