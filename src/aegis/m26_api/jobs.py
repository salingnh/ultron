"""`/api/v2/jobs` — M05 submission, read model and cancel (G1.1c).

The routes are thin: authenticate the operator (bearer token -> opaque principal, OD-5), hand
the request to `JobService`, and translate an `M05Error` into the app's `ApiError` - the one error
layer of `m26_api.errors` (contract `error.v2` body, `traceparent` echo, no FastAPI `detail`
shape). No policy rule lives here.

Contract points that are visible in this file:

* `POST /jobs` needs `Idempotency-Key`; a replay of the accepted request answers `200` with
  `Idempotent-Replayed: true`, a new job `202`; the same key with a different body is `409`
  `IDEMPOTENCY_CONFLICT` (the service compares `request_hash`);
* a policy refusal (`403`/`429`) is a recorded decision and publishes `policy.denied.v2`;
* every response carries the request's `traceparent` (the shared tracing helper).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated, Any

import psycopg
from fastapi import APIRouter, Depends, FastAPI, Header, Query, Request, Response, status
from pydantic import ValidationError

from aegis.contracts_gen.capability.job_submit_v2_schema import JobSubmit
from aegis.m05_registry.errors import M05Error
from aegis.m05_registry.registry import PostgresManifestRegistry
from aegis.m05_registry.service import JobService, PostgresJobService
from aegis.m05_registry.signing import KeyRing
from aegis.m26_api.errors import ApiError
from aegis.m26_api.manifests import adapter_manifests
from aegis.m26_api.operator import Principal, require_principal
from aegis.m26_api.tracing import TRACEPARENT_HEADER, current_trace_id, traceparent

__all__ = ["build_job_service", "install_job_service", "register", "router"]

router = APIRouter(tags=["jobs"])

IDEMPOTENCY_HEADER = Header(
    alias="Idempotency-Key",
    min_length=8,
    max_length=256,
    description="8–256 characters; the same key with the same body replays the accepted job.",
)


def register(registry: Any, *, prefix: str = "") -> Any:
    """Mount the jobs router on the app registry (called by `main.build_registry`)."""
    from aegis.m26_api.app import API_PREFIX

    return registry.register("jobs", router, prefix=prefix or API_PREFIX)


def install_job_service(app: FastAPI, service: JobService) -> None:
    """Wire the M05 service on the app (`build_job_service` in production, a fake in tests)."""
    app.state.job_service = service


def build_job_service(
    dsn: str,
    *,
    connect: Callable[[], Any] | None = None,
    manifests: Callable[[], list[bytes]] | None = None,
    key_ring: KeyRing | None = None,
) -> PostgresJobService:
    """The production M05: registry seeded from `adapters/**/manifest.yaml`, keys from env.

    A manifest that cannot be admitted aborts start-up: a registry that silently drops a provider
    would make every job of that capability look "unknown" instead of "the deployment is broken".
    """
    opener = connect or (lambda: psycopg.connect(dsn))
    registry = PostgresManifestRegistry(opener)
    for raw in (manifests or adapter_manifests)():
        registry.register(raw, registered_by={"kind": "module", "id": "M05"})
    return PostgresJobService(
        opener,
        registry=registry,
        key_ring=key_ring or KeyRing.from_env(),
    )


def get_job_service(request: Request) -> JobService:
    service: JobService | None = getattr(request.app.state, "job_service", None)
    if service is None:
        raise ApiError(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "DEPENDENCY_MISSING",
            "M05 job service is not configured on this app",
            next_action="ESCALATE",
        )
    return service


def _api_error(error: M05Error) -> ApiError:
    """One translation: the refusal already decided code, status, next_action and retry hint."""
    refusal = error.refusal
    headers: dict[str, str] = {}
    if refusal.retry_after_seconds is not None:
        headers["Retry-After"] = str(refusal.retry_after_seconds)
    return ApiError(
        refusal.status_code,
        str(refusal.code),
        refusal.message,
        next_action=str(refusal.next_action),
        field=refusal.field,
        headers=headers,
        retry_after_seconds=refusal.retry_after_seconds,
    )


def _parse_submit(payload: Any) -> JobSubmit:
    """Validate the body as the contract DTO; a failure is a contract 400, not FastAPI's 422."""
    if not isinstance(payload, dict):
        raise ApiError(
            status.HTTP_400_BAD_REQUEST,
            "INPUT_INVALID",
            "request body must be a JSON object",
            next_action="FIX_INPUT",
            field="",
        )
    try:
        return JobSubmit.model_validate(payload)
    except ValidationError as error:
        first = error.errors()[0]
        location = "/".join(str(part) for part in first["loc"])
        raise ApiError(
            status.HTTP_400_BAD_REQUEST,
            "INPUT_INVALID",
            f"request body does not satisfy job-submit.v2: {first['msg']}",
            next_action="FIX_INPUT",
            field=f"/{location}",
        ) from error


def _idempotency_key(value: str | None) -> str:
    key = (value or "").strip()
    if len(key) < 8 or len(key) > 256:
        raise ApiError(
            status.HTTP_400_BAD_REQUEST,
            "INPUT_INVALID",
            "Idempotency-Key header is required (8–256 characters)",
            next_action="FIX_INPUT",
            field="/Idempotency-Key",
        )
    return key


def _trace(request: Request, response: Response) -> str:
    trace = current_trace_id(request)
    response.headers[TRACEPARENT_HEADER] = traceparent(trace)
    return trace


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
    trace = _trace(request, response)
    try:
        outcome = service.submit(
            _parse_submit(payload),
            requested_by={"kind": "operator", "id": principal.id},
            idempotency_key=_idempotency_key(idempotency_key),
            trace_id=trace,
        )
    except M05Error as error:
        raise _api_error(error) from error
    response.status_code = status.HTTP_200_OK if outcome.replayed else status.HTTP_202_ACCEPTED
    if outcome.replayed:
        response.headers["Idempotent-Replayed"] = "true"
    return outcome.job


@router.get("/jobs")
def list_jobs(
    request: Request,
    response: Response,
    principal: Annotated[Principal, Depends(require_principal)],
    service: Annotated[JobService, Depends(get_job_service)],
    campaign_id: Annotated[str, Query(min_length=1)],
    job_status: Annotated[str | None, Query(alias="status")] = None,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> Any:
    """Job list for one campaign (keyset cursor, `next_cursor` absent = last page)."""
    _trace(request, response)
    try:
        page = service.list_jobs(
            campaign_id=campaign_id, status=job_status, cursor=cursor, limit=limit
        )
    except M05Error as error:
        raise _api_error(error) from error
    payload: dict[str, Any] = {"items": list(page.items)}
    if page.next_cursor is not None:
        payload["next_cursor"] = page.next_cursor
    return payload


@router.get("/jobs/{job_id}")
def get_job(
    request: Request,
    response: Response,
    job_id: str,
    principal: Annotated[Principal, Depends(require_principal)],
    service: Annotated[JobService, Depends(get_job_service)],
) -> Any:
    """One job with its wait/dispatch reasons, cancel intent and dependency list."""
    _trace(request, response)
    try:
        return service.get_job(job_id)
    except M05Error as error:
        raise _api_error(error) from error


@router.post("/jobs/{job_id}/cancel")
def cancel_job(
    request: Request,
    response: Response,
    job_id: str,
    principal: Annotated[Principal, Depends(require_principal)],
    service: Annotated[JobService, Depends(get_job_service)],
    body: dict[str, Any] | None = None,
) -> Any:
    """Record a cancel intent (idempotent); a QUEUED job is terminalised immediately."""
    _trace(request, response)
    reason = None
    if isinstance(body, dict) and body.get("reason") is not None:
        reason = str(body["reason"])[:2000]
    try:
        return service.cancel(
            job_id, requested_by={"kind": "operator", "id": principal.id}, reason=reason
        )
    except M05Error as error:
        raise _api_error(error) from error
