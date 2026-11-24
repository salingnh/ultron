"""M26 campaign REST (card G1.1b): create, read, list, policy adopt, pause/resume/cancel.

Contract: `contracts/api/openapi.v2.yaml` (operations `createCampaign`, `listCampaigns`,
`getCampaign`, `updateCampaignPolicy`, `pauseCampaign`, `resumeCampaign`,
`cancelCampaign`) plus `campaign/campaign-create.v2`, `campaign/campaign.v2` and
`common/error.v2`. The contract bundle is authoritative for the wire shape; this
module adds HTTP, the verified operator principal and idempotency on top of the M01
repository.

Deliberate choices:

* The request body is validated with `aegis.validation` against the contract schema
  *before* it is used. The generated DTOs are not the request gate: Pydantic's lax
  mode coerces values the contract rejects (a JSON string `"10"` for an integer) and
  cannot enforce the `aegis-*` formats; the codegen models are exercised in the tests
  instead.
* Every mutation stamps the actor from the verified principal (`require_principal`),
  never from the body (C05/X-8). The body has no actor field by contract.
* Write endpoints require `Idempotency-Key`; a replay returns the previously stored
  response with `Idempotent-Replayed: true`, a changed body is 409.
* A campaign id that is not UUIDv7-shaped is answered 404, not 500: it cannot exist
  and PostgreSQL would refuse the comparison.
"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime
from typing import Annotated, Any

import psycopg
from fastapi import APIRouter, Body, Depends, Header, Query, Request, Response
from fastapi import status as http_status

from aegis import validation
from aegis.contracts_gen.campaign import campaign_v2_schema
from aegis.m01_campaign import (
    CampaignNotFound,
    CampaignStateConflict,
    adopt_policy,
    change_status,
    create_campaign,
    get_campaign,
    list_campaigns,
)
from aegis.m01_campaign.campaigns import timestamp
from aegis.m26_api.db import connection as db_connection
from aegis.m26_api.errors import INPUT_INVALID, ApiError
from aegis.m26_api.idempotency import IdempotencyConflict, lock_key, replay, request_hash, store
from aegis.m26_api.operator import Principal, require_principal
from aegis.m26_api.registry import RouterEntry, RouterRegistry
from aegis.m26_api.tracing import TRACEPARENT_HEADER, current_trace_id, traceparent

__all__ = [
    "CAMPAIGN_CREATE",
    "CAMPAIGN_OPERATIONS",
    "CAMPAIGN_READ",
    "ROE_POLICY",
    "decode_cursor",
    "encode_cursor",
    "register",
    "router",
]

CAMPAIGN_CREATE = "campaign/campaign-create.v2.schema.json"
CAMPAIGN_READ = "campaign/campaign.v2.schema.json"
ROE_POLICY = "campaign/roe-policy.v2.schema.json"
ID_REFERENCE = "common/ids.v2.schema.json#/$defs/Id"

CREATE_SCOPE = "POST /campaigns"
POLICY_SCOPE = "POST /campaigns/{campaign_id}/policy"
IDEMPOTENT_REPLAYED = "Idempotent-Replayed"
API_PREFIX = "/api/v2"

#: Operations this router implements; the conformance test compares it with the contract.
CAMPAIGN_OPERATIONS = (
    "createCampaign",
    "listCampaigns",
    "getCampaign",
    "updateCampaignPolicy",
    "pauseCampaign",
    "resumeCampaign",
    "cancelCampaign",
)

_ERROR_400 = {"description": "Lỗi chuẩn (error.v2): body/header sai"}
_ERROR_401 = {"description": "Lỗi chuẩn (error.v2): thiếu hoặc sai operator token"}
_ERROR_404 = {"description": "Lỗi chuẩn (error.v2): campaign không tồn tại"}
_ERROR_409 = {"description": "Lỗi chuẩn (error.v2): xung đột trạng thái/khóa"}

IDEMPOTENCY_HEADER = Header(
    ...,
    alias="Idempotency-Key",
    min_length=8,
    max_length=256,
    description="Idempotency-Key của contract: cùng khóa cùng body trả lại kết quả cũ.",
)

router = APIRouter(tags=["campaigns"])


# --------------------------------------------------------------------------- helpers


def _is_id(value: str) -> bool:
    return not validation.errors(ID_REFERENCE, value)


def _actor(principal: Principal) -> dict[str, str]:
    return {"kind": principal.kind, "id": principal.id}


def _trace(request: Request, response: Response) -> str:
    trace_id = current_trace_id(request)
    response.headers[TRACEPARENT_HEADER] = traceparent(trace_id)
    return trace_id


def _contract_body(reference: str, body: Any) -> None:
    """Validate a request body; a violation is a 400 INPUT_INVALID with its pointer."""
    try:
        validation.validate(reference, body)
    except validation.ContractViolation as error:
        first = error.errors[0] if error.errors else ""
        pointer, _, message = first.partition(": ")
        raise ApiError(
            http_status.HTTP_400_BAD_REQUEST,
            INPUT_INVALID,
            f"request body does not satisfy {reference}: {len(error.errors)} violation(s); "
            f"first: {message or first}",
            next_action="FIX_INPUT",
            field=pointer or None,
        ) from error


def _contract_response(campaign: dict[str, Any]) -> dict[str, Any]:
    """The read model must satisfy campaign.v2; a violation is a server bug."""
    try:
        validation.validate(CAMPAIGN_READ, campaign)
    except validation.ContractViolation as error:
        raise ApiError(
            http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            f"campaign read model violates {CAMPAIGN_READ}: {error}",
        ) from error
    return campaign


def _not_found(campaign_id: str) -> ApiError:
    return ApiError(
        http_status.HTTP_404_NOT_FOUND,
        INPUT_INVALID,
        f"campaign {campaign_id} does not exist",
        next_action="FIX_INPUT",
    )


def _state_conflict(error: CampaignStateConflict) -> ApiError:
    return ApiError(http_status.HTTP_409_CONFLICT, INPUT_INVALID, str(error), next_action="NONE")


def _idempotency_conflict(error: IdempotencyConflict) -> ApiError:
    return ApiError(
        http_status.HTTP_409_CONFLICT,
        "IDEMPOTENCY_CONFLICT",
        f"Idempotency-Key was already used with a different body ({error.scope})",
        next_action="NONE",
    )


def encode_cursor(created_at: datetime, campaign_id: str) -> str:
    """Opaque keyset cursor of (created_at, campaign_id)."""
    raw = f"{timestamp(created_at)}|{campaign_id}"
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, str]:
    """Parse a cursor this endpoint issued; anything else is 400 INPUT_INVALID."""
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        created_at_text, separator, campaign_id = raw.partition("|")
        if not separator:
            raise ValueError("cursor has no separator")
        created_at = datetime.fromisoformat(created_at_text)
        if created_at.tzinfo is None:
            raise ValueError("cursor timestamp has no timezone")
    except (ValueError, UnicodeError, binascii.Error) as error:
        raise ApiError(
            http_status.HTTP_400_BAD_REQUEST,
            INPUT_INVALID,
            "cursor is not one this endpoint issued",
            next_action="FIX_INPUT",
            field="/cursor",
        ) from error
    if not _is_id(campaign_id):
        raise ApiError(
            http_status.HTTP_400_BAD_REQUEST,
            INPUT_INVALID,
            "cursor does not carry a campaign id",
            next_action="FIX_INPUT",
            field="/cursor",
        )
    return created_at, campaign_id


# --------------------------------------------------------------------------- routes


@router.post(
    "/campaigns",
    status_code=http_status.HTTP_202_ACCEPTED,
    operation_id="createCampaign",
    summary="Tạo chiến dịch kèm ảnh chụp RoE",
    responses={400: _ERROR_400, 401: _ERROR_401, 409: _ERROR_409},
)
def create_campaign_route(
    request: Request,
    response: Response,
    body: Annotated[dict[str, Any], Body(...)],
    idempotency_key: Annotated[str, IDEMPOTENCY_HEADER],
    principal: Annotated[Principal, Depends(require_principal)],
    db: Annotated[psycopg.Connection[Any], Depends(db_connection)],
) -> dict[str, Any]:
    trace_id = _trace(request, response)
    _contract_body(CAMPAIGN_CREATE, body)
    digest = request_hash(body)

    lock_key(db, scope=CREATE_SCOPE, key=idempotency_key)
    try:
        previous = replay(db, scope=CREATE_SCOPE, key=idempotency_key, digest=digest)
    except IdempotencyConflict as error:
        raise _idempotency_conflict(error) from error
    if previous is not None:
        response.headers[IDEMPOTENT_REPLAYED] = "true"
        return previous

    created = create_campaign(db, body=body, actor=_actor(principal), trace_id=trace_id)
    payload = created.as_response()
    store(
        db,
        scope=CREATE_SCOPE,
        key=idempotency_key,
        digest=digest,
        status_code=http_status.HTTP_202_ACCEPTED,
        response=payload,
    )
    return payload


@router.get(
    "/campaigns",
    operation_id="listCampaigns",
    summary="Danh sách chiến dịch (keyset cursor)",
    responses={400: _ERROR_400, 401: _ERROR_401},
)
def list_campaigns_route(
    request: Request,
    response: Response,
    principal: Annotated[Principal, Depends(require_principal)],
    db: Annotated[psycopg.Connection[Any], Depends(db_connection)],
    status_filter: Annotated[
        campaign_v2_schema.CampaignStatus | None, Query(alias="status")
    ] = None,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> dict[str, Any]:
    _trace(request, response)
    after = decode_cursor(cursor) if cursor else None
    items, next_after = list_campaigns(
        db,
        status=status_filter.value if status_filter is not None else None,
        limit=limit,
        after=after,
    )
    page: dict[str, Any] = {"items": [_contract_response(item) for item in items]}
    if next_after is not None:
        page["next_cursor"] = encode_cursor(*next_after)
    return page


@router.get(
    "/campaigns/{campaign_id}",
    operation_id="getCampaign",
    summary="Trạng thái chiến dịch",
    responses={401: _ERROR_401, 404: _ERROR_404},
)
def get_campaign_route(
    request: Request,
    response: Response,
    campaign_id: str,
    principal: Annotated[Principal, Depends(require_principal)],
    db: Annotated[psycopg.Connection[Any], Depends(db_connection)],
) -> dict[str, Any]:
    _trace(request, response)
    campaign = get_campaign(db, campaign_id) if _is_id(campaign_id) else None
    if campaign is None:
        raise _not_found(campaign_id)
    return _contract_response(campaign)


@router.post(
    "/campaigns/{campaign_id}/policy",
    operation_id="updateCampaignPolicy",
    summary="Đổi RoE, sinh policy_version mới (bản cũ không bị sửa)",
    responses={400: _ERROR_400, 401: _ERROR_401, 404: _ERROR_404, 409: _ERROR_409},
)
def update_campaign_policy_route(
    request: Request,
    response: Response,
    campaign_id: str,
    body: Annotated[dict[str, Any], Body(...)],
    idempotency_key: Annotated[str, IDEMPOTENCY_HEADER],
    principal: Annotated[Principal, Depends(require_principal)],
    db: Annotated[psycopg.Connection[Any], Depends(db_connection)],
) -> dict[str, Any]:
    trace_id = _trace(request, response)
    if not _is_id(campaign_id):
        raise _not_found(campaign_id)
    policy, reason = _policy_request(body)
    digest = request_hash(body)

    lock_key(db, scope=POLICY_SCOPE, key=idempotency_key)
    try:
        previous = replay(db, scope=POLICY_SCOPE, key=idempotency_key, digest=digest)
    except IdempotencyConflict as error:
        raise _idempotency_conflict(error) from error
    if previous is not None:
        response.headers[IDEMPOTENT_REPLAYED] = "true"
        return previous

    try:
        version = adopt_policy(
            db,
            campaign_id=campaign_id,
            policy=policy,
            reason=reason,
            actor=_actor(principal),
            trace_id=trace_id,
        )
    except CampaignNotFound as error:
        raise _not_found(campaign_id) from error
    except CampaignStateConflict as error:
        raise _state_conflict(error) from error

    payload = {"policy_version": version}
    store(
        db,
        scope=POLICY_SCOPE,
        key=idempotency_key,
        digest=digest,
        status_code=http_status.HTTP_200_OK,
        response=payload,
    )
    return payload


@router.post(
    "/campaigns/{campaign_id}/pause",
    operation_id="pauseCampaign",
    summary="Tạm dừng",
    responses={400: _ERROR_400, 401: _ERROR_401, 404: _ERROR_404, 409: _ERROR_409},
)
def pause_campaign_route(
    request: Request,
    response: Response,
    campaign_id: str,
    body: Annotated[dict[str, Any], Body(...)],
    principal: Annotated[Principal, Depends(require_principal)],
    db: Annotated[psycopg.Connection[Any], Depends(db_connection)],
) -> dict[str, Any]:
    return _action("pause", request, response, campaign_id, body, principal, db)


@router.post(
    "/campaigns/{campaign_id}/resume",
    operation_id="resumeCampaign",
    summary="Tiếp tục",
    responses={400: _ERROR_400, 401: _ERROR_401, 404: _ERROR_404, 409: _ERROR_409},
)
def resume_campaign_route(
    request: Request,
    response: Response,
    campaign_id: str,
    body: Annotated[dict[str, Any], Body(...)],
    principal: Annotated[Principal, Depends(require_principal)],
    db: Annotated[psycopg.Connection[Any], Depends(db_connection)],
) -> dict[str, Any]:
    return _action("resume", request, response, campaign_id, body, principal, db)


@router.post(
    "/campaigns/{campaign_id}/cancel",
    operation_id="cancelCampaign",
    summary="Hủy chiến dịch",
    responses={400: _ERROR_400, 401: _ERROR_401, 404: _ERROR_404, 409: _ERROR_409},
)
def cancel_campaign_route(
    request: Request,
    response: Response,
    campaign_id: str,
    body: Annotated[dict[str, Any], Body(...)],
    principal: Annotated[Principal, Depends(require_principal)],
    db: Annotated[psycopg.Connection[Any], Depends(db_connection)],
) -> dict[str, Any]:
    return _action("cancel", request, response, campaign_id, body, principal, db)


# --------------------------------------------------------------------------- request parsing


def _policy_request(body: dict[str, Any]) -> tuple[dict[str, Any], str]:
    policy = body.get("policy")
    reason = body.get("reason")
    if policy is None:
        raise ApiError(
            http_status.HTTP_400_BAD_REQUEST,
            INPUT_INVALID,
            "body.policy is required",
            next_action="FIX_INPUT",
            field="/policy",
        )
    _contract_body(ROE_POLICY, policy)
    if not isinstance(reason, str) or len(reason) < 3:
        raise ApiError(
            http_status.HTTP_400_BAD_REQUEST,
            INPUT_INVALID,
            "body.reason is required and at least 3 characters",
            next_action="FIX_INPUT",
            field="/reason",
        )
    return policy, reason


def _action(
    action: str,
    request: Request,
    response: Response,
    campaign_id: str,
    body: dict[str, Any],
    principal: Principal,
    db: psycopg.Connection[Any],
) -> dict[str, Any]:
    trace_id = _trace(request, response)
    if not _is_id(campaign_id):
        raise _not_found(campaign_id)
    reason = body.get("reason")
    if not isinstance(reason, str) or len(reason) > 2000:
        raise ApiError(
            http_status.HTTP_400_BAD_REQUEST,
            INPUT_INVALID,
            "body.reason must be a string of at most 2000 characters",
            next_action="FIX_INPUT",
            field="/reason",
        )
    try:
        campaign = change_status(
            db,
            campaign_id=campaign_id,
            action=action,
            reason=reason,
            actor=_actor(principal),
            trace_id=trace_id,
        )
    except CampaignNotFound as error:
        raise _not_found(campaign_id) from error
    except CampaignStateConflict as error:
        raise _state_conflict(error) from error
    return _contract_response(campaign)


# --------------------------------------------------------------------------- registration


def register(registry: RouterRegistry, *, prefix: str = API_PREFIX) -> RouterEntry:
    """Mount the campaign router on an app registry (called by the app entrypoint)."""
    return registry.register("campaigns", router, prefix=prefix)
