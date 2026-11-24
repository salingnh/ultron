"""The operator token verifier (OD-5): start-up validation and server-side verification."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from aegis.m26_api.operator import (
    OperatorAuthenticationError,
    OperatorAuthenticator,
    OperatorTokenError,
    OperatorTokens,
    Principal,
    RejectingAuthenticator,
    TokenAuthenticator,
    bearer_token,
    token_digest,
)

TOKEN = "operator-token-0123456789"
OTHER = "operator-token-9876543210"
PRINCIPAL = "op-soc-1"


def store(*pairs: tuple[str, str]) -> OperatorTokens:
    return OperatorTokens.from_document(
        {"operators": [{"principal_id": p, "token_sha256": token_digest(t)} for p, t in pairs]}
    )


def test_token_digest_is_sha256_of_the_token_bytes() -> None:
    assert token_digest(TOKEN) == hashlib.sha256(TOKEN.encode("utf-8")).hexdigest()
    assert len(token_digest(TOKEN)) == 64


def test_a_valid_token_maps_to_the_opaque_principal() -> None:
    tokens = store((PRINCIPAL, TOKEN), ("op-soc-2", OTHER))
    authenticator = TokenAuthenticator(tokens)
    principal = authenticator.authenticate(f"Bearer {TOKEN}")

    assert principal == Principal(id=PRINCIPAL, kind="operator")
    # The identity is the principal id, never the secret that was presented.
    assert TOKEN not in principal.id
    assert len(tokens.entries) == 2


def test_unknown_token_and_missing_header_fail_closed() -> None:
    authenticator = TokenAuthenticator(store((PRINCIPAL, TOKEN)))
    with pytest.raises(OperatorAuthenticationError, match="unknown or revoked"):
        authenticator.authenticate("Bearer not-a-configured-token")
    for header in (None, "", "Basic abc", "Bearer "):
        with pytest.raises(OperatorAuthenticationError):
            authenticator.authenticate(header)


def test_revoked_operator_is_refused_without_changing_the_others() -> None:
    authenticator = TokenAuthenticator(store(("op-a", TOKEN)))
    assert authenticator.authenticate(f"Bearer {TOKEN}").id == "op-a"
    rotated = TokenAuthenticator(store(("op-b", OTHER)))
    with pytest.raises(OperatorAuthenticationError):
        rotated.authenticate(f"Bearer {TOKEN}")
    assert rotated.authenticate(f"Bearer {OTHER}").id == "op-b"


def test_token_store_file_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "operators.json"
    path.write_text(
        json.dumps(
            {"operators": [{"principal_id": PRINCIPAL, "token_sha256": token_digest(TOKEN)}]}
        ),
        encoding="utf-8",
    )
    tokens = OperatorTokens.from_file(path)
    assert tokens.principal_for(TOKEN) == PRINCIPAL
    assert tokens.principal_for(OTHER) is None


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ({}, "exactly"),
        ({"operators": [], "extra": 1}, "exactly"),
        ({"operators": []}, "empty"),
        ({"operators": "nope"}, "array"),
        ({"operators": [42]}, "JSON object"),
        ({"operators": [{"principal_id": "op-1"}]}, "exactly"),
        (
            {"operators": [{"principal_id": "op-1", "token_sha256": "A" * 64}]},
            "64 lowercase hex",
        ),
        (
            {"operators": [{"principal_id": "op-1", "token_sha256": "a" * 63}]},
            "64 lowercase hex",
        ),
        ({"operators": [{"principal_id": "Op 1", "token_sha256": "a" * 64}]}, "opaque id"),
        (
            {
                "operators": [
                    {"principal_id": "op-1", "token_sha256": "a" * 64},
                    {"principal_id": "op-1", "token_sha256": "b" * 64},
                ]
            },
            "twice",
        ),
        (
            {
                "operators": [
                    {"principal_id": "op-1", "token_sha256": "a" * 64},
                    {"principal_id": "op-2", "token_sha256": "a" * 64},
                ]
            },
            "share a token digest",
        ),
    ],
)
def test_invalid_stores_are_start_up_errors(document: object, message: str) -> None:
    with pytest.raises(OperatorTokenError, match=message):
        OperatorTokens.from_document(document)


def test_missing_and_malformed_files_are_start_up_errors(tmp_path: Path) -> None:
    with pytest.raises(OperatorTokenError, match="cannot read"):
        OperatorTokens.from_file(tmp_path / "absent.json")
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    with pytest.raises(OperatorTokenError, match="not JSON"):
        OperatorTokens.from_file(broken)


def test_default_authenticator_refuses_every_call() -> None:
    with pytest.raises(OperatorAuthenticationError, match="not configured"):
        RejectingAuthenticator().authenticate(f"Bearer {TOKEN}")


def test_authenticators_are_structural() -> None:
    assert isinstance(TokenAuthenticator(store((PRINCIPAL, TOKEN))), OperatorAuthenticator)
    assert bearer_token(f"Bearer {TOKEN}") == TOKEN
