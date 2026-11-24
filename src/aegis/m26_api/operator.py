"""Operator identity (OI-4/X-8, owner decision OD-5): per-operator bearer token, server-verified.

The owner decided (OD-5) that an operator presents a per-operator bearer token; the server
verifies it and works with an **opaque principal id** from then on - no contract, database row or
log carries the token itself, and `requested_by.id` is that opaque id.

G1.1b implements the verifier:

* `OperatorTokens` is the token store. It maps an opaque principal id to the **sha256 digest** of
  that operator's token, so the deployment never holds a usable token (the operator presents it,
  the server hashes it and compares). The store is loaded from a JSON file named by
  `AEGIS_OPERATOR_TOKENS_FILE`:

      {"operators": [{"principal_id": "op-<opaque>", "token_sha256": "<64 lowercase hex>"}]}

  Parsing is strict and fail-closed: unknown keys, a malformed digest, a duplicate principal, a
  shared digest between two principals, or an empty entry list is an error at start-up, never a
  silently ignored operator. Revoking an operator = removing its entry and restarting; the token
  is never logged, stored in the database or copied into a response.
* `TokenAuthenticator` compares the presented token's digest with every entry using
  `hmac.compare_digest` and returns `Principal(id=<principal_id>)`, an opaque id the rest of the
  server uses as the `operator` actor (C05). A token is never an identity: the principal id is.

The `OperatorAuthenticator` protocol, the fail-closed `RejectingAuthenticator` default and the
FastAPI dependency stay as G1.1a defined them, so an app built without an authenticator cannot
accidentally accept anonymous operators.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol, cast, runtime_checkable

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

__all__ = [
    "OPERATOR_TOKENS_FILE",
    "OperatorAuthenticationError",
    "OperatorAuthenticator",
    "OperatorTokenError",
    "OperatorTokens",
    "Principal",
    "RejectingAuthenticator",
    "TokenAuthenticator",
    "bearer_token",
    "require_principal",
    "token_digest",
]

BEARER_PREFIX = "bearer "
OPERATOR_TOKENS_FILE = "AEGIS_OPERATOR_TOKENS_FILE"
#: Documented as `operatorToken` (the contract's securityScheme name) in the served OpenAPI.
BEARER_SCHEME_NAME = "operatorToken"
BEARER = HTTPBearer(auto_error=False, scheme_name=BEARER_SCHEME_NAME)
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
#: An opaque principal id: no spaces, no `@`, no punctuation that suggests a login name.
_PRINCIPAL_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_TOKEN_STORE_KEYS = frozenset({"operators"})
_OPERATOR_KEYS = frozenset({"principal_id", "token_sha256"})


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
    """Default authenticator: refuses every request when no token store is configured."""

    def authenticate(self, authorization: str | None) -> Principal:
        bearer_token(authorization)
        raise OperatorAuthenticationError("operator token verification is not configured")


class OperatorTokenError(RuntimeError):
    """The token store is missing, unreadable or not a valid store (start-up failure)."""


def token_digest(token: str) -> str:
    """The stored form of an operator token: sha256 of its UTF-8 bytes, lowercase hex."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class OperatorTokens:
    """Opaque principal id -> sha256 digest of that principal's operator token."""

    entries: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        if not self.entries:
            raise OperatorTokenError("the operator token store is empty")
        principals = [principal for principal, _ in self.entries]
        digests = [digest for _, digest in self.entries]
        if len(set(principals)) != len(principals):
            raise OperatorTokenError("the operator token store declares a principal twice")
        if len(set(digests)) != len(digests):
            raise OperatorTokenError(
                "two operators share a token digest; a token must identify exactly one principal"
            )

    @classmethod
    def from_documents(cls, operators: object) -> OperatorTokens:
        """Build the store from the parsed `operators` array of the token file."""
        if not isinstance(operators, list):
            raise OperatorTokenError("the token store needs an `operators` array")
        entries: list[tuple[str, str]] = []
        for index, item in enumerate(operators):
            if not isinstance(item, Mapping):
                raise OperatorTokenError(f"operators[{index}] must be a JSON object")
            entry = cast(Mapping[str, Any], item)
            if set(entry) != _OPERATOR_KEYS:
                raise OperatorTokenError(
                    f"operators[{index}] must have exactly {sorted(_OPERATOR_KEYS)}"
                )
            principal = entry["principal_id"]
            digest = entry["token_sha256"]
            if not isinstance(principal, str) or not _PRINCIPAL_ID.fullmatch(principal):
                raise OperatorTokenError(
                    f"operators[{index}].principal_id must be an opaque id {_PRINCIPAL_ID.pattern}"
                )
            if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
                raise OperatorTokenError(
                    f"operators[{index}].token_sha256 must be 64 lowercase hex characters"
                )
            entries.append((principal, digest))
        return cls(tuple(entries))

    @classmethod
    def from_document(cls, document: object) -> OperatorTokens:
        """Build the store from the whole token-file document."""
        if not isinstance(document, Mapping):
            raise OperatorTokenError("the operator token file must contain a JSON object")
        mapping = cast(Mapping[str, Any], document)
        if set(mapping) != _TOKEN_STORE_KEYS:
            raise OperatorTokenError(
                f"the operator token file must have exactly {sorted(_TOKEN_STORE_KEYS)}"
            )
        return cls.from_documents(mapping["operators"])

    @classmethod
    def from_file(cls, path: str | Path) -> OperatorTokens:
        """Load the store from a JSON file; every failure is a typed start-up error."""
        source = Path(path)
        try:
            document = json.loads(source.read_text(encoding="utf-8"))
        except OSError as error:
            raise OperatorTokenError(
                f"cannot read the operator token file {source}: {error}"
            ) from error
        except json.JSONDecodeError as error:
            raise OperatorTokenError(
                f"the operator token file {source} is not JSON: {error}"
            ) from error
        return cls.from_document(document)

    def principal_for(self, token: str) -> str | None:
        """The opaque principal id of `token`, or None. Compares every entry, in constant time."""
        presented = token_digest(token)
        matched: str | None = None
        for principal, digest in self.entries:
            if hmac.compare_digest(presented, digest):
                matched = principal
        return matched


class TokenAuthenticator:
    """Verifies an operator bearer token against `OperatorTokens` (OD-5)."""

    def __init__(self, tokens: OperatorTokens) -> None:
        self._tokens = tokens

    @property
    def tokens(self) -> OperatorTokens:
        return self._tokens

    def authenticate(self, authorization: str | None) -> Principal:
        token = bearer_token(authorization)
        principal = self._tokens.principal_for(token)
        if principal is None:
            raise OperatorAuthenticationError("unknown or revoked operator token")
        return Principal(id=principal)


def require_principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(BEARER)],
) -> Principal:
    """FastAPI dependency returning the server-verified operator principal.

    The authenticator is resolved per app (`app.state.operator_authenticator`) so tests and
    deployments can replace it without touching routes; when it is absent every call is refused.
    `HTTPBearer(auto_error=False)` only documents the `operatorToken` scheme in the served
    OpenAPI; the header itself is still parsed and refused by `bearer_token()` below, so a
    malformed Authorization header is a 401 `error.v2`, not FastAPI's 403.
    """
    del credentials  # parsed for the OpenAPI security requirement; the raw header is the input
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
