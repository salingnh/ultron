"""`error.v2` responses for M26: one exception type and one set of handlers.

The contract answers an operation-level failure with `error.v2`
(`code`, `next_action`, optional `field`/`trace_id`), not with FastAPI's
`{"detail": ...}`. Routes raise `ApiError`; a body that fails FastAPI's own
validation is mapped to the same 400 `INPUT_INVALID`; an `HTTPException` raised by
a dependency (401 from the operator dependency) keeps its status and headers but
gets the contract body. Every response carries the request's `traceparent` back.
"""

from __future__ import annotations

from typing import Any, Final

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .tracing import TRACEPARENT_HEADER, current_trace_id, traceparent

__all__ = ["INPUT_INVALID", "ApiError", "error_payload", "install_error_handlers"]

#: Codes published by `common/error.v2`; a route may only raise one of these.
ERROR_CODES: Final = frozenset(
    {
        "INPUT_INVALID",
        "OUT_OF_SCOPE",
        "POLICY_DENIED",
        "RATE_LIMITED",
        "TOOL_UNAVAILABLE",
        "DEPENDENCY_MISSING",
        "NETWORK_TIMEOUT",
        "EXECUTION_TIMEOUT",
        "RESOURCE_LIMIT",
        "OUTPUT_INVALID",
        "EVIDENCE_INCOMPLETE",
        "CANCELLED",
        "IDEMPOTENCY_CONFLICT",
        "INTERNAL_ERROR",
    }
)
NEXT_ACTIONS: Final = frozenset(
    {
        "RETRY",
        "RETRY_LATER",
        "FIX_INPUT",
        "WAIT_WINDOW",
        "CHECK_PROVIDER",
        "REVIEW_QUARANTINE",
        "ESCALATE",
        "NONE",
    }
)
INPUT_INVALID: Final = "INPUT_INVALID"


class ApiError(Exception):
    """An operation-level failure rendered as `error.v2`."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        *,
        next_action: str = "NONE",
        field: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        if code not in ERROR_CODES:
            raise ValueError(f"error code {code!r} is not published by common/error.v2")
        if next_action not in NEXT_ACTIONS:
            raise ValueError(f"next_action {next_action!r} is not published by common/error.v2")
        self.status_code = status_code
        self.code = code
        self.message = message
        self.next_action = next_action
        self.field = field
        self.headers = dict(headers or {})
        super().__init__(message)


def error_payload(
    *,
    code: str,
    message: str,
    next_action: str,
    trace_id: str,
    field: str | None = None,
) -> dict[str, Any]:
    """The `error.v2` body (keys with a null value are omitted, never sent as null)."""
    payload: dict[str, Any] = {
        "code": code,
        "message": message[:2000],
        "next_action": next_action,
        "trace_id": trace_id,
    }
    if field:
        payload["field"] = field
    return payload


def _json(
    payload: dict[str, Any],
    *,
    status_code: int,
    trace_id: str,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    merged = dict(headers or {})
    merged[TRACEPARENT_HEADER] = traceparent(trace_id)
    return JSONResponse(content=payload, status_code=status_code, headers=merged)


def _field_of(errors: list[dict[str, Any]]) -> str | None:
    """The first JSON pointer of a FastAPI validation error list (`/policy/max_parallel_jobs`)."""
    for error in errors:
        location = [
            part for part in error.get("loc", ()) if part not in {"body", "query", "header", "path"}
        ]
        if not location:
            continue
        return "/" + "/".join(str(part) for part in location)
    return None


def install_error_handlers(app: FastAPI) -> None:
    """Register the contract-shaped handlers on `app` (idempotent, called by create_app)."""

    @app.exception_handler(ApiError)
    def _api_error(request: Request, error: ApiError) -> JSONResponse:
        trace_id = current_trace_id(request)
        return _json(
            error_payload(
                code=error.code,
                message=error.message,
                next_action=error.next_action,
                field=error.field,
                trace_id=trace_id,
            ),
            status_code=error.status_code,
            trace_id=trace_id,
            headers=error.headers,
        )

    @app.exception_handler(RequestValidationError)
    def _validation_error(request: Request, error: RequestValidationError) -> JSONResponse:
        trace_id = current_trace_id(request)
        errors = [dict(item) for item in error.errors()]
        detail = "; ".join(
            f"{_field_of([item]) or '/'}: {item.get('msg', 'invalid value')}" for item in errors[:5]
        )
        return _json(
            error_payload(
                code=INPUT_INVALID,
                message=f"request does not satisfy the contract: {detail}"[:2000],
                next_action="FIX_INPUT",
                field=_field_of(errors),
                trace_id=trace_id,
            ),
            status_code=400,
            trace_id=trace_id,
        )

    @app.exception_handler(StarletteHTTPException)
    def _http_error(request: Request, error: StarletteHTTPException) -> JSONResponse:
        trace_id = current_trace_id(request)
        message = error.detail if isinstance(error.detail, str) else "request failed"
        return _json(
            error_payload(
                code=INPUT_INVALID,
                message=message,
                next_action="FIX_INPUT",
                trace_id=trace_id,
            ),
            status_code=error.status_code,
            trace_id=trace_id,
            headers={key: value for key, value in (error.headers or {}).items()},
        )
