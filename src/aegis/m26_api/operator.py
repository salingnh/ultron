"""Operator identity (OI-4/X-8, owner decision OD-5): per-operator bearer token, server-verified.

The owner decided (OD-5) that an operator presents a per-operator bearer token; the server
verifies it and works with an **opaque principal id** from then on - no contract, database row or
log carries the token itself, and `requested_by.id` is that opaque id.

G1.1a only fixes the seam: the `OperatorAuthenticator` protocol, the fail-closed default and the
FastAPI dependency that every write route will use. G1.1b implements the token store and the
routes that stamp `requested_by`. Until then `RejectingAuthenticator` refuses every call, so a
route added without wiring an authenticator cannot accidentally accept anonymous operators.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

from fastapi import HTTPException, Request, status

__all__ = [
    "OperatorAuthenticationError",
    "OperatorAuthenticator",
    "Principal",
    "RejectingAuthenticator",
    "bearer_token",
    "require_principal",
]

BEARER_PREFIX = "bearer "


@dataclass(frozen=True, slots=True)
class Principal:
    """Server-assigned operator identity; `id` is opaque and never the raw token."""

    id: str
    kind: Literal["operator"] = "operator"


class OperatorAuthenticationError(Exception):
    """The bearer token is missing, malformed, unknown or revoked (HTTP 401)."""


@runtime_checkable
class OperatorAuthenticator(Protocol):
    """Verifies `Authorization: Bearer <token>` server-side and returns the principal."""

    def authenticate(self, authorization: str | None) -> Principal: ...


def bearer_token(authorization: str | None) -> str:
    """Extract the token from an `Authorization` header, or fail closed."""
    if not authorization:
        raise OperatorAuthenticationError("missing Authorization header")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() + " " != BEARER_PREFIX or not token.strip():
        raise OperatorAuthenticationError("Authorization must be 'Bearer <token>'")
    return token.strip()


class RejectingAuthenticator:
    """Default authenticator: refuses every request (G1.1b replaces it)."""

    def authenticate(self, authorization: str | None) -> Principal:
        bearer_token(authorization)
        raise OperatorAuthenticationError(
            "operator token verification is not configured yet (G1.1b)"
        )


def require_principal(request: Request) -> Principal:
    """FastAPI dependency returning the server-verified operator principal.

    The authenticator is resolved per app (`app.state.operator_authenticator`) so tests and
    deployments can replace it without touching routes; when it is absent every call is refused.
    """
    authenticator = getattr(request.app.state, "operator_authenticator", None) or (
        RejectingAuthenticator()
    )
    try:
        return authenticator.authenticate(request.headers.get("authorization"))
    except OperatorAuthenticationError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(error),
            headers={"WWW-Authenticate": "Bearer"},
        ) from error
