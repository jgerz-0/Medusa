import base64
import types
from datetime import datetime, timedelta, timezone
from typing import Generator, Tuple

import jwt
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from controller.db.models import AuditLog, PrincipalCredential
from controller.main import (
    CREDENTIAL_SOURCE_MANUAL,
    CREDENTIAL_SOURCE_OIDC_AUTO,
    ROLE_FINDINGS_READ,
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
    api_client: Generator[Tuple[TestClient, object, sessionmaker, Settings], None, None]
) -> Tuple[TestClient, object, sessionmaker, Settings]:
    return api_client


def _oct_secret(secret: str) -> str:
    raw = base64.urlsafe_b64encode(secret.encode("utf-8")).decode("ascii")
    return raw.rstrip("=")


def _configure_validator(
    settings: Settings, *, shared_secret: str = "oidc-secret"
) -> Tuple[OIDCValidator, str]:
    settings.oidc_issuer = "https://issuer.test"
    settings.oidc_audience = "medusa-api"
    settings.oidc_jwks_url = "https://issuer.test/jwks"
    settings.oidc_allowed_algorithms = ["HS256"]
    settings.oidc_roles_claim = "roles"
    settings.oidc_subject_claim = "sub"
    settings.oidc_jwks_cache_ttl_seconds = 60
    settings.oidc_request_timeout_seconds = 5

    jwks_document = {
        "keys": [
            {
                "kty": "oct",
                "kid": "unit-test",
                "k": _oct_secret(shared_secret),
            }
        ]
    }

    validator = OIDCValidator(
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
    return validator, shared_secret


@pytest.mark.parametrize("extra_role", [["untracked"], []])
def test_oidc_bearer_token_authenticates(
    controller_api_client: Tuple[TestClient, object, sessionmaker, Settings],
    extra_role: list[str],
) -> None:
    _client, _queue, session_factory, settings = controller_api_client
    get_oidc_validator.cache_clear()  # type: ignore[attr-defined]

    validator, shared_secret = _configure_validator(settings)

    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": "oidc-analyst",
        "iss": settings.oidc_issuer,
        "aud": settings.oidc_audience,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "roles": [ROLE_TARGETS_READ, *extra_role],
    }
    token = jwt.encode(payload, shared_secret, algorithm="HS256", headers={"kid": "unit-test"})

    with session_factory() as session:
        session.add(
            PrincipalCredential(
                subject="oidc-analyst",
                auth_method="oidc",
                roles=[ROLE_TARGETS_READ],
                source=CREDENTIAL_SOURCE_MANUAL,
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


def test_oidc_auto_provision_creates_principal(
    controller_api_client: Tuple[TestClient, object, sessionmaker, Settings]
) -> None:
    _client, _queue, session_factory, settings = controller_api_client
    get_oidc_validator.cache_clear()  # type: ignore[attr-defined]

    validator, shared_secret = _configure_validator(settings)
    settings.oidc_auto_provision_enabled = True
    settings.oidc_auto_provision_allowed_issuers = [settings.oidc_issuer]
    settings.oidc_auto_provision_allowed_roles = [
        ROLE_TARGETS_READ,
        ROLE_FINDINGS_READ,
    ]
    settings.oidc_auto_provision_role_map = {
        "medusa-analyst": [ROLE_TARGETS_READ, ROLE_FINDINGS_READ]
    }
    settings.oidc_auto_provision_claim = "groups"
    settings.oidc_auto_provision_ttl_seconds = 3600

    issued_at = datetime.now(tz=timezone.utc)
    payload = {
        "sub": "oidc-provision",
        "iss": settings.oidc_issuer,
        "aud": settings.oidc_audience,
        "iat": int(issued_at.timestamp()),
        "exp": int((issued_at + timedelta(minutes=5)).timestamp()),
        "groups": ["medusa-analyst"],
        "roles": [],
    }
    token = jwt.encode(payload, shared_secret, algorithm="HS256", headers={"kid": "unit-test"})

    with session_factory() as session:
        principal = _authenticate_oidc(
            token,
            validator=validator,
            settings=settings,
            db=session,
        )

        assert principal.subject == "oidc-provision"
        assert sorted(principal.roles) == sorted(
            [ROLE_TARGETS_READ, ROLE_FINDINGS_READ]
        )

        credential = (
            session.query(PrincipalCredential)
            .filter(PrincipalCredential.subject == "oidc-provision")
            .one()
        )
        assert credential.source == CREDENTIAL_SOURCE_OIDC_AUTO
        assert sorted(credential.roles) == sorted(
            [ROLE_TARGETS_READ, ROLE_FINDINGS_READ]
        )
        expires_at = credential.expires_at
        assert expires_at is not None
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        delta = (expires_at - datetime.now(tz=timezone.utc)).total_seconds()
        assert delta == pytest.approx(3600, abs=5)

        provision_event = (
            session.query(AuditLog)
            .filter(AuditLog.action == "provision_oidc_principal")
            .order_by(AuditLog.created_at.desc())
            .first()
        )
        assert provision_event is not None
        assert provision_event.actor == "oidc-provision"
        snapshot = provision_event.evidence_snapshot
        assert sorted(snapshot["roles"]) == sorted(
            [ROLE_TARGETS_READ, ROLE_FINDINGS_READ]
        )

    get_oidc_validator.cache_clear()  # type: ignore[attr-defined]


def test_oidc_auto_provision_syncs_roles_and_refreshes_expiry(
    controller_api_client: Tuple[TestClient, object, sessionmaker, Settings]
) -> None:
    _client, _queue, session_factory, settings = controller_api_client
    get_oidc_validator.cache_clear()  # type: ignore[attr-defined]

    validator, shared_secret = _configure_validator(settings)
    settings.oidc_auto_provision_enabled = True
    settings.oidc_auto_provision_allowed_issuers = [settings.oidc_issuer]
    settings.oidc_auto_provision_allowed_roles = [
        ROLE_TARGETS_READ,
        ROLE_FINDINGS_READ,
    ]
    settings.oidc_auto_provision_role_map = {
        "blue-team": [ROLE_TARGETS_READ, ROLE_FINDINGS_READ]
    }
    settings.oidc_auto_provision_claim = "groups"
    settings.oidc_auto_provision_ttl_seconds = 1800

    expired_time = datetime.now(tz=timezone.utc) - timedelta(seconds=30)
    with session_factory() as setup_session:
        setup_session.add(
            PrincipalCredential(
                subject="oidc-sync",
                auth_method="oidc",
                roles=[ROLE_TARGETS_READ],
                expires_at=expired_time,
                source=CREDENTIAL_SOURCE_OIDC_AUTO,
            )
        )
        setup_session.commit()

    payload = {
        "sub": "oidc-sync",
        "iss": settings.oidc_issuer,
        "aud": settings.oidc_audience,
        "iat": int(datetime.now(tz=timezone.utc).timestamp()),
        "exp": int((datetime.now(tz=timezone.utc) + timedelta(minutes=5)).timestamp()),
        "groups": ["blue-team"],
        "roles": [],
    }
    token = jwt.encode(payload, shared_secret, algorithm="HS256", headers={"kid": "unit-test"})

    with session_factory() as session:
        principal = _authenticate_oidc(
            token,
            validator=validator,
            settings=settings,
            db=session,
        )

        assert principal.subject == "oidc-sync"
        assert sorted(principal.roles) == sorted(
            [ROLE_TARGETS_READ, ROLE_FINDINGS_READ]
        )

        credential = (
            session.query(PrincipalCredential)
            .filter(PrincipalCredential.subject == "oidc-sync")
            .one()
        )
        assert credential.source == CREDENTIAL_SOURCE_OIDC_AUTO
        assert sorted(credential.roles) == sorted(
            [ROLE_TARGETS_READ, ROLE_FINDINGS_READ]
        )
        expires_at = credential.expires_at
        assert expires_at is not None
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        expiry_delta = (
            expires_at - datetime.now(tz=timezone.utc)
        ).total_seconds()
        assert expiry_delta == pytest.approx(1800, abs=5)

        sync_event = (
            session.query(AuditLog)
            .filter(AuditLog.action == "sync_oidc_principal")
            .order_by(AuditLog.created_at.desc())
            .first()
        )
        assert sync_event is not None
        snapshot = sync_event.evidence_snapshot
        assert snapshot["previous_roles"] == [ROLE_TARGETS_READ]
        assert sorted(snapshot["updated_roles"]) == sorted(
            [ROLE_TARGETS_READ, ROLE_FINDINGS_READ]
        )

    get_oidc_validator.cache_clear()  # type: ignore[attr-defined]


def test_oidc_auto_provision_rejected_for_revoked_subject(
    controller_api_client: Tuple[TestClient, object, sessionmaker, Settings]
) -> None:
    _client, _queue, session_factory, settings = controller_api_client
    get_oidc_validator.cache_clear()  # type: ignore[attr-defined]

    validator, shared_secret = _configure_validator(settings)
    settings.oidc_auto_provision_enabled = True
    settings.oidc_auto_provision_allowed_issuers = [settings.oidc_issuer]
    settings.oidc_auto_provision_allowed_roles = [ROLE_TARGETS_READ]
    settings.oidc_auto_provision_role_map = {"revoked-group": [ROLE_TARGETS_READ]}
    settings.oidc_auto_provision_claim = "groups"
    settings.oidc_auto_provision_ttl_seconds = 900

    with session_factory() as setup_session:
        setup_session.add(
            PrincipalCredential(
                subject="oidc-revoked",
                auth_method="oidc",
                roles=[ROLE_TARGETS_READ],
                revoked_at=datetime.now(tz=timezone.utc),
                source=CREDENTIAL_SOURCE_OIDC_AUTO,
            )
        )
        setup_session.commit()

    payload = {
        "sub": "oidc-revoked",
        "iss": settings.oidc_issuer,
        "aud": settings.oidc_audience,
        "iat": int(datetime.now(tz=timezone.utc).timestamp()),
        "exp": int((datetime.now(tz=timezone.utc) + timedelta(minutes=5)).timestamp()),
        "groups": ["revoked-group"],
        "roles": [],
    }
    token = jwt.encode(payload, shared_secret, algorithm="HS256", headers={"kid": "unit-test"})

    with session_factory() as session:
        with pytest.raises(HTTPException) as exc_info:
            _authenticate_oidc(
                token,
                validator=validator,
                settings=settings,
                db=session,
            )

        assert exc_info.value.status_code == 403

        active_records = (
            session.query(PrincipalCredential)
            .filter(
                PrincipalCredential.subject == "oidc-revoked",
                PrincipalCredential.revoked_at.is_(None),
            )
            .count()
        )
        assert active_records == 0

    get_oidc_validator.cache_clear()  # type: ignore[attr-defined]


def test_rate_limiting_enforced(
    controller_api_client: Tuple[TestClient, object, sessionmaker, Settings]
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
