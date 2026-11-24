"""`Idempotency-Key` handling on `idempotency_record` (contract: POST create/update rules).

Same key + same body returns the stored response with `Idempotent-Replayed: true`;
same key + a different body is 409 `IDEMPOTENCY_CONFLICT` and writes nothing. The
projection that is hashed is the *contract-validated* request body, canonicalised
with sorted keys and no whitespace; it is a comparison fingerprint for this table,
not a published content hash (`aegis-c14n/1` is for envelopes and job fingerprints).
A key that differs only in key order, so two clients that send the same JSON in a
different order replay each other's result instead of conflicting.

Concurrency: the caller takes the transaction-level advisory lock of
`(scope, key)` before reading the record, so two simultaneous requests with one key
serialise and the second one sees the first one's committed response. Without the
lock both could miss the row and create two campaigns.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Final

import psycopg
from psycopg.types.json import Jsonb

__all__ = [
    "IdempotencyConflict",
    "lock_key",
    "replay",
    "request_hash",
    "store",
]

#: Upper bound from the contract's Idempotency-Key parameter.
KEY_MIN_LENGTH: Final = 8
KEY_MAX_LENGTH: Final = 256


class IdempotencyConflict(RuntimeError):
    """The key was used before with different content (HTTP 409)."""

    def __init__(self, scope: str, key: str) -> None:
        self.scope = scope
        self.key = key
        super().__init__(f"Idempotency-Key {key!r} was already used with a different body")


def request_hash(body: Any) -> str:
    """sha256 of the canonical text of a contract-validated request body."""
    canonical = json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def lock_key(connection: psycopg.Connection[Any], *, scope: str, key: str) -> None:
    """Serialise concurrent requests that share `(scope, key)` for this transaction."""
    connection.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
        (f"{scope}|{key}",),
    )


def replay(
    connection: psycopg.Connection[Any],
    *,
    scope: str,
    key: str,
    digest: str,
) -> dict[str, Any] | None:
    """The stored response of a previous call with the same content, or None."""
    row = connection.execute(
        """
        SELECT request_hash, response
          FROM aegis.idempotency_record
         WHERE scope = %s AND key = %s
        """,
        (scope, key),
    ).fetchone()
    if row is None:
        return None
    if row["request_hash"] != digest:
        raise IdempotencyConflict(scope, key)
    response = row["response"]
    if not isinstance(response, dict):  # pragma: no cover - the column is jsonb of an object
        raise RuntimeError(f"idempotency_record {scope}/{key} holds a non-object response")
    return response


def store(
    connection: psycopg.Connection[Any],
    *,
    scope: str,
    key: str,
    digest: str,
    status_code: int,
    response: dict[str, Any],
) -> None:
    """Record the response of this call in the same transaction as the effect."""
    connection.execute(
        """
        INSERT INTO aegis.idempotency_record (scope, key, request_hash, status_code, response)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (scope, key, digest, status_code, Jsonb(response)),
    )
