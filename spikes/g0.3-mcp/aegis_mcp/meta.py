"""`params._meta` contract for tools/call (contracts/mcp/README.md).

The table in the contract README defines four keys.  The spike decides how the
server reads them, what a wrong value returns, and how the values are bound to a
server-side session; the decisions are written up in the report and rolled into
contracts/mcp/README.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

TRACE_ID = "aegis.io/trace_id"
CAMPAIGN_ID = "aegis.io/campaign_id"
SESSION_ID = "aegis.io/session_id"
IDEMPOTENCY_KEY = "aegis.io/idempotency_key"

REQUIRED_KEYS = (TRACE_ID, CAMPAIGN_ID, SESSION_ID, IDEMPOTENCY_KEY)
NAMESPACE = "aegis.io/"

# contracts/common/ids.v2.schema.json#/$defs/Id (UUIDv7, lowercase)
_UUID7 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_TRACE = re.compile(r"^[0-9a-f]{32}$")
# Opaque client key.  The README documents the client convention
# "<session_id>:step:<n>"; the server must not depend on that structure, so the
# key is only length/charset checked here.
_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")


@dataclass(frozen=True)
class Meta:
    trace_id: str
    campaign_id: str
    session_id: str
    idempotency_key: str


def json_pointer(key: str) -> str:
    """JSON pointer to a wire key (RFC 6901 escaping)."""
    return "/_meta/" + key.replace("~", "~0").replace("/", "~1")


@dataclass(frozen=True)
class MetaError:
    field: str
    message: str

    @property
    def pointer(self) -> str:
        return json_pointer(self.field)


def parse_meta(meta: Mapping[str, Any] | None) -> tuple[Meta | None, list[MetaError]]:
    """Read the four required keys; return every problem at once."""
    if meta is None:
        return None, [MetaError(key, "required params._meta key is missing") for key in REQUIRED_KEYS]

    errors: list[MetaError] = []
    for key in REQUIRED_KEYS:
        if key not in meta:
            errors.append(MetaError(key, "required params._meta key is missing"))

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
