import base64
import types
from datetime import datetime, timedelta, timezone
from typing import Generator, Tuple

import jwt
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from controller.db.models import PrincipalCredential
from controller.main import (
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


@pytest.mark.parametrize("extra_role", [["untracked"], []])
def test_oidc_bearer_token_authenticates(
    controller_api_client: Tuple[TestClient, object, sessionmaker, Settings],
    extra_role: list[str],
) -> None:
    _client, _queue, session_factory, settings = controller_api_client
    get_oidc_validator.cache_clear()  # type: ignore[attr-defined]

    settings.oidc_issuer = "https://issuer.test"
    settings.oidc_audience = "medusa-api"
    settings.oidc_jwks_url = "https://issuer.test/jwks"
    settings.oidc_allowed_algorithms = ["HS256"]
    settings.oidc_roles_claim = "roles"
    settings.oidc_subject_claim = "sub"
    settings.oidc_jwks_cache_ttl_seconds = 60
    settings.oidc_request_timeout_seconds = 5

    shared_secret = "oidc-secret"
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
