"""`params._meta` of `tools/list` and `tools/call` (contracts/mcp/README.md).

The contract table defines four `aegis.io/*` keys. This module reads them, checks their formats
against `common/ids.v2`, and reports every problem at once as an RFC 6901 JSON Pointer into the
request, so the server can answer one `-32602` with the full list instead of one per call.

The values are **not** authority: `aegis.io/campaign_id`/`session_id` are only compared with the
context the server bound for this transport session (see `session`). G0.3a verified on the wire
that the keys arrive intact in `params.meta`; the wire names are fixed by the contract and are not
changed here.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

__all__ = [
    "CAMPAIGN_ID",
    "IDEMPOTENCY_KEY",
    "NAMESPACE",
    "REQUIRED_KEYS",
    "SESSION_ID",
    "TRACE_ID",
    "Meta",
    "MetaError",
    "json_pointer",
    "parse_meta",
]

TRACE_ID = "aegis.io/trace_id"
CAMPAIGN_ID = "aegis.io/campaign_id"
SESSION_ID = "aegis.io/session_id"
IDEMPOTENCY_KEY = "aegis.io/idempotency_key"

REQUIRED_KEYS: tuple[str, ...] = (TRACE_ID, CAMPAIGN_ID, SESSION_ID, IDEMPOTENCY_KEY)
NAMESPACE = "aegis.io/"

# contracts/common/ids.v2.schema.json#/$defs/Id (UUIDv7, lowercase).
_UUID7 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
# W3C trace id, as `traceparent` carries it.
_TRACE = re.compile(r"^[0-9a-f]{32}$")
# Opaque client key. The README documents the client convention `<session_id>:step:<n>`; the server
# must not depend on that structure (a key is opaque), so only length and charset are checked.
_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")


def json_pointer(key: str) -> str:
    """JSON Pointer to a wire key (RFC 6901 escaping: `~` -> `~0`, `/` -> `~1`)."""
    return "/_meta/" + key.replace("~", "~0").replace("/", "~1")


@dataclass(frozen=True, slots=True)
class Meta:
    trace_id: str
    campaign_id: str
    session_id: str
    idempotency_key: str


@dataclass(frozen=True, slots=True)
class MetaError:
    field: str
    message: str

    @property
    def pointer(self) -> str:
        return json_pointer(self.field)


def _present(value: Any) -> bool:
    return value is not None


def parse_meta(meta: Mapping[str, Any] | None) -> tuple[Meta | None, list[MetaError]]:
    """Read the four required keys; return every problem at once (none = a valid `Meta`)."""
    if not _present(meta):
        return None, [
            MetaError(key, "required params._meta key is missing") for key in REQUIRED_KEYS
        ]
    assert meta is not None

    errors: list[MetaError] = []
    for key in REQUIRED_KEYS:
        if key not in meta:
            errors.append(MetaError(key, "required params._meta key is missing"))

    # The `aegis.io/` namespace belongs to the contract: an unknown key there is a client bug, not
    # a hint. Keys outside the namespace (e.g. `progressToken`) are the SDK's and are ignored.
    for key in meta:
        if isinstance(key, str) and key.startswith(NAMESPACE) and key not in REQUIRED_KEYS:
            errors.append(MetaError(key, "unknown key in the reserved aegis.io/ namespace"))
    if errors:
        return None, errors

    values: dict[str, str] = {}
    for key in REQUIRED_KEYS:
        value = meta[key]
        if not isinstance(value, str):
            errors.append(MetaError(key, "value must be a string"))
        else:
            values[key] = value

    checks = {
        TRACE_ID: (_TRACE, "must be 32 lowercase hex characters (W3C trace id)"),
        CAMPAIGN_ID: (_UUID7, "must be a lowercase UUIDv7"),
        SESSION_ID: (_UUID7, "must be a lowercase UUIDv7"),
        IDEMPOTENCY_KEY: (_IDEMPOTENCY, "must be 8..128 of [A-Za-z0-9._:-]"),
    }
    for key, (pattern, message) in checks.items():
        value = values.get(key)
        if value is not None and not pattern.fullmatch(value):
            errors.append(MetaError(key, message))

    if errors:
        return None, errors
    return (
        Meta(
            trace_id=values[TRACE_ID],
            campaign_id=values[CAMPAIGN_ID],
            session_id=values[SESSION_ID],
            idempotency_key=values[IDEMPOTENCY_KEY],
        ),
        [],
    )
