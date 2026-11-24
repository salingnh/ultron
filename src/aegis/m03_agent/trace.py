"""Trace ids for a session's model and MCP calls (W3C trace-id: 32 lowercase hex, non-zero).

The id is generated once per planning round and carried in the `_meta` of every MCP call of that
round and in the `trace_id` of the model request, so a refusal, a usage row and a policy decision
can be joined without storing the conversation. It is not the campaign's trace id and never
contains a credential.
"""

from __future__ import annotations

import uuid

__all__ = ["new_trace_id"]


def new_trace_id() -> str:
    value = uuid.uuid4().hex
    while value == "0" * 32:  # pragma: no cover - 2**-128
        value = uuid.uuid4().hex
    return value
