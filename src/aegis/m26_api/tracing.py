"""W3C trace context for M26 (contract: "accept `traceparent`, echo it, generate when absent").

`audit_log.trace_id` is a required 32-hex column, so every request needs a trace id
before any row is written. The id is taken from an incoming `traceparent` when that
header is valid (version 00, non-zero trace and span ids) and generated otherwise;
either way it is echoed in the response's `traceparent` header, so a caller can line
its own trace up with the audit rows.
"""

from __future__ import annotations

import re
import uuid
from typing import Final

from fastapi import Request

__all__ = ["TRACEPARENT_HEADER", "current_trace_id", "traceparent", "trace_id_of"]

TRACEPARENT_HEADER: Final = "traceparent"
_TRACEPARENT = re.compile(
    r"^(?P<version>[0-9a-f]{2})-(?P<trace>[0-9a-f]{32})-(?P<span>[0-9a-f]{16})-(?P<flags>[0-9a-f]{2})$"
)
_ZERO_TRACE: Final = "0" * 32
_ZERO_SPAN: Final = "0" * 16


def trace_id_of(header: str | None) -> str | None:
    """The trace id of a valid `traceparent` header, or None when it must be generated."""
    if not header:
        return None
    match = _TRACEPARENT.fullmatch(header.strip())
    if match is None or match["version"] == "ff":
        return None
    if match["trace"] == _ZERO_TRACE or match["span"] == _ZERO_SPAN:
        return None
    return match["trace"]


def current_trace_id(request: Request) -> str:
    """The request's trace id: the caller's valid one, otherwise a fresh one."""
    return trace_id_of(request.headers.get(TRACEPARENT_HEADER)) or uuid.uuid4().hex


def traceparent(trace_id: str) -> str:
    """A `traceparent` header value carrying `trace_id` (sampled, fresh span id)."""
    if not re.fullmatch(r"[0-9a-f]{32}", trace_id) or trace_id == _ZERO_TRACE:
        raise ValueError(f"not a W3C trace id: {trace_id!r}")
    return f"00-{trace_id}-{uuid.uuid4().hex[:16]}-01"
