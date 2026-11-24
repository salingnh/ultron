"""`/api/v2/jobs` — M05 submission, read model and cancel (G1.1c).

The routes are thin on purpose: authenticate the operator (bearer token -> opaque principal, OD-5),
hand the DTO to `JobService`, and translate a `Refusal` into the contract `Error` with its HTTP
status
and `next_action`. No policy rule lives here.

Contract points that are visible in this file:

* `POST /jobs` needs `Idempotency-Key`; a replay of the accepted request answers `200` with
  `Idempotent-Replayed: true`, a new job `202`; the same key with a different body is `409`
  `IDEMPOTENCY_CONFLICT` (the service compares `request_hash`);
* a policy refusal (`403`/`429`) is a recorded decision and publishes `policy.denied.v2`;
* `traceparent` is accepted and the trace id is echoed; when it is absent or malformed the server
  generates one (`common/ids.v2` TraceContext);
* errors are always the contract `Error` (code + next_action + trace_id), never a free-text string.
"""

from __future__ import annotations

import re
from typing import Annotated, Any

from fastapi import (
    APIRouter,
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from aegis.contracts_gen.capability.job_submit_v2_schema import JobSubmit
from aegis.m05_registry.errors import M05Error
from aegis.m05_registry.ids import trace_id as new_trace_id
from aegis.m05_registry.service import JobService
from aegis.m26_api.operator import Principal, require_principal

__all__ = ["router", "install_job_service", "get_job_service"]

router = APIRouter(tags=["jobs"])

TRACEPARENT = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")
IDEMPOTENCY_HEADER = Header(
    alias="Idempotency-Key",
    min_length=8,
    max_length=256,
    description="8–256 characters; the same key with the same body replays the accepted job.",
)


def install_job_service(app: FastAPI, service: JobService) -> None:
    """Wire the M05 service on the app (tests do this; the deployment wires the real one)."""
    app.state.job_service = service


def get_job_service(request: Request) -> JobService:
    service: JobService | None = getattr(request.app.state, "job_service", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="M05 job service is not configured",
        )
    return service


def _trace_id(request: Request) -> str:
    header = request.headers.get("traceparent") or ""
    match = TRACEPARENT.fullmatch(header.strip().lower())
    return match.group(1) if match and match.group(1) != "0" * 32 else new_trace_id()


def _traceparent(trace_id: str) -> str:
    """Echo the W3C header; the span id of this hop is not the caller's concern in G1."""
    return f"00-{trace_id}-{'0' * 16}-01"


def _refuse(error: Any, request: Request) -> JSONResponse:
    """Render a `M05Error` as the contract `Error` body with its status and Retry-After."""
    refusal = error.refusal
    body = refusal.body(_trace_id(request))
    headers = {"traceparent": _traceparent(body["trace_id"])}
    if refusal.retry_after_seconds is not None:
        headers["Retry-After"] = str(refusal.retry_after_seconds)
    return JSONResponse(status_code=refusal.status_code, content=body, headers=headers)


def _handle(error: Any, request: Request) -> Any:
    from aegis.m05_registry.errors import M05Error

    if isinstance(error, M05Error):
        return _refuse(error, request)
    raise error


def _parse_submit(payload: Any) -> JobSubmit:
    """Validate the body as the contract DTO; a failure is a contract 400, not FastAPI's 422."""
    if not isinstance(payload, dict):
        raise M05Error.input_invalid("request body must be a JSON object", field="")
    try:
        return JobSubmit.model_validate(payload)
    except ValidationError as error:
        first = error.errors()[0]
        location = "/".join(str(part) for part in first["loc"])
        raise M05Error.input_invalid(
            f"request body does not satisfy job-submit.v2: {first['msg']}", field=f"/{location}"
        ) from error


def _idempotency_key(value: str | None) -> str:
    key = (value or "").strip()
    if len(key) < 8 or len(key) > 256:
        raise M05Error.input_invalid(
            "Idempotency-Key header is required (8–256 characters)", field="/Idempotency-Key"
        )
    return key


@router.post("/jobs", status_code=status.HTTP_202_ACCEPTED)
def submit_job(
    request: Request,
    payload: dict[str, Any],
    principal: Annotated[Principal, Depends(require_principal)],
    service: Annotated[JobService, Depends(get_job_service)],
    response: Response,
    idempotency_key: Annotated[str | None, IDEMPOTENCY_HEADER] = None,
) -> Any:
    """Accept a job (202) or replay the one this key/fingerprint already accepted (200)."""
    trace = _trace_id(request)
    try:
        body = _parse_submit(payload)
        outcome = service.submit(
            body,
            requested_by={"kind": "operator", "id": principal.id},
            idempotency_key=_idempotency_key(idempotency_key),
            trace_id=trace,
        )
    except Exception as error:  # noqa: BLE001 - M05 refusals carry their own status
        return _handle(error, request)
    response.status_code = status.HTTP_200_OK if outcome.replayed else status.HTTP_202_ACCEPTED
    response.headers["traceparent"] = _traceparent(trace)
    if outcome.replayed:
        response.headers["Idempotent-Replayed"] = "true"
    return outcome.job


@router.get("/jobs")
def list_jobs(
    request: Request,
    principal: Annotated[Principal, Depends(require_principal)],
    service: Annotated[JobService, Depends(get_job_service)],
    campaign_id: Annotated[str, Query(min_length=1)],
    job_status: Annotated[str | None, Query(alias="status")] = None,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> Any:
    """Job list for one campaign (keyset cursor, `next_cursor` absent = last page)."""
    try:
        page = service.list_jobs(
            campaign_id=campaign_id, status=job_status, cursor=cursor, limit=limit
        )
    except Exception as error:  # noqa: BLE001
        return _handle(error, request)
    payload: dict[str, Any] = {"items": list(page.items)}
    if page.next_cursor is not None:
        payload["next_cursor"] = page.next_cursor
    return payload


@router.get("/jobs/{job_id}")
def get_job(
    request: Request,
    job_id: str,
    principal: Annotated[Principal, Depends(require_principal)],
    service: Annotated[JobService, Depends(get_job_service)],
) -> Any:
    """One job with its wait/dispatch reasons, cancel intent and dependency list."""
    try:
        return service.get_job(job_id)
    except Exception as error:  # noqa: BLE001
        return _handle(error, request)


@router.post("/jobs/{job_id}/cancel")
def cancel_job(
    request: Request,
    job_id: str,
    principal: Annotated[Principal, Depends(require_principal)],
    service: Annotated[JobService, Depends(get_job_service)],
    body: dict[str, Any] | None = None,
) -> Any:
    """Record a cancel intent (idempotent); a QUEUED job is terminalised immediately."""
    reason = None
    if isinstance(body, dict):
        candidate = body.get("reason")
        reason = str(candidate)[:2000] if candidate is not None else None
    try:
        return service.cancel(
            job_id, requested_by={"kind": "operator", "id": principal.id}, reason=reason
        )
    except Exception as error:  # noqa: BLE001
        return _handle(error, request)
