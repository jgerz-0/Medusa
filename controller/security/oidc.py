"""Utilities for validating OpenID Connect bearer tokens."""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import jwt
from jwt import InvalidTokenError
from jwt.algorithms import get_default_algorithms


class OIDCNotApplicableError(Exception):
    """Raised when an OIDC validator cannot process the presented token."""


class OIDCValidationError(Exception):
    """Raised when an OpenID Connect token fails validation."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


@dataclass(frozen=True)
class OIDCSettings:
    """Configuration required to validate OpenID Connect tokens."""

    issuer: str
    jwks_url: str
    audience: Optional[str]
    roles_claim: str
    subject_claim: str
    allowed_algorithms: Tuple[str, ...]
    cache_ttl_seconds: int
    request_timeout_seconds: int

    def normalized_algorithms(self) -> Tuple[str, ...]:
        return tuple(sorted({alg for alg in self.allowed_algorithms if alg}))


def fetch_jwks_document(url: str, timeout: int) -> Dict[str, Any]:
    """Retrieve a JWKS document from the configured identity provider."""

    request = Request(url, headers={"Accept": "application/json"})
    try:
        with urlopen(request, timeout=timeout) as response:  # nosec: B310 - controlled URL
            payload = response.read()
    except (HTTPError, URLError) as exc:  # pragma: no cover - network error path
        raise OIDCValidationError("jwks_fetch_failed", str(exc)) from exc

    try:
        document: Dict[str, Any] = json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError as exc:  # pragma: no cover - malformed JWKS path
        raise OIDCValidationError("jwks_parse_error", "Invalid JWKS response") from exc

    return document


class OIDCValidator:
    """Validate OpenID Connect bearer tokens against a JWKS cache."""

    def __init__(
        self,
        config: OIDCSettings,
        *,
        jwks_loader: Optional[Callable[[str, int], Dict[str, Any]]] = None,
    ) -> None:
        self._config = config
        self._jwks_loader = jwks_loader or fetch_jwks_document
        self._lock = threading.Lock()
        self._cached_keys: Dict[str, Dict[str, Any]] = {}
        self._expires_at = 0.0

    @property
    def issuer(self) -> str:
        return self._config.issuer

    @property
    def roles_claim(self) -> str:
        return self._config.roles_claim

    @property
    def subject_claim(self) -> str:
        return self._config.subject_claim

    def validate(self, token: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Return the decoded payload and header for a valid OIDC token."""

        try:
            header = jwt.get_unverified_header(token)
        except InvalidTokenError as exc:
            raise OIDCValidationError("invalid_header", str(exc)) from exc

        algorithm = header.get("alg")
        if not algorithm:
            raise OIDCNotApplicableError("missing_alg")

        allowed_algorithms = self._config.normalized_algorithms()
        if allowed_algorithms and algorithm not in allowed_algorithms:
            raise OIDCNotApplicableError("unsupported_algorithm")

        key_id = header.get("kid")
        if not key_id:
            raise OIDCNotApplicableError("missing_kid")

        signing_key = self._get_signing_key(str(key_id))
        algorithm_impl = get_default_algorithms().get(algorithm)
        if algorithm_impl is None:
            raise OIDCValidationError("unsupported_algorithm", f"Unsupported alg {algorithm}")

        public_key = algorithm_impl.from_jwk(json.dumps(signing_key))

        options = {
            "require": ["exp", "iat", "sub"],
            "verify_aud": bool(self._config.audience),
        }

        try:
            payload = jwt.decode(
                token,
                key=public_key,
                algorithms=[algorithm],
                audience=self._config.audience,
                issuer=self._config.issuer,
                options=options,
            )
        except InvalidTokenError as exc:
            raise OIDCValidationError("invalid_signature", str(exc)) from exc

        return payload, header

    def _get_signing_key(self, kid: str) -> Dict[str, Any]:
        now = time.monotonic()
        with self._lock:
            if not self._cached_keys or now >= self._expires_at:
                self._refresh_cache(now)
            key = self._cached_keys.get(kid)
        if key is None:
            raise OIDCValidationError("unknown_kid", f"Unknown signing key: {kid}")
        return key

    def _refresh_cache(self, now: float) -> None:
        document = self._jwks_loader(
            self._config.jwks_url, self._config.request_timeout_seconds
        )
        keys = document.get("keys")
        if not isinstance(keys, list):
            raise OIDCValidationError("jwks_parse_error", "JWKS payload missing keys")

        key_map: Dict[str, Dict[str, Any]] = {}
        for key in keys:
            if isinstance(key, dict) and key.get("kid"):
                key_map[str(key["kid"])] = key

        if not key_map:
            raise OIDCValidationError("jwks_empty", "JWKS response did not include keys")

        self._cached_keys = key_map
        self._expires_at = now + max(self._config.cache_ttl_seconds, 30)


def build_validator(config: OIDCSettings) -> OIDCValidator:
    """Factory helper that returns an OIDC validator for the provided config."""

    return OIDCValidator(config)
