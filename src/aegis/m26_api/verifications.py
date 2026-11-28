"""M26 verification routes (G2-B): list the checks, request one, read the runs.

Contract: `contracts/api/openapi.v2.yaml` operations `listVerificationChecks`,
`requestVerification` and `listVerifications`; the request body is
`verification/verification-request.v2`, the page items are `verification/verification-run.v2`.

The operator's freedom ends at the check id and the finding: the request body carries no target,
URL, payload or template, and this module builds the whole job input server-side from the finding,
the reviewed registry and the deployment's control map (`aegis.m05_registry.verification`). M05 then
rebuilds the same input and refuses any difference, so the route is a convenience, not the boundary.

A request is a normal `verify.check` job submitted through M05 (decision, task, idempotency): the
job is the request's state, and a replay of the same `Idempotency-Key` returns the original job.
The run rows appear once the job completed and M21 decided it (`aegis.m21_verify`); a failed or
cancelled job has no run row and is read as the job.

Two refusals are decided here because they are request-level, before any job:

* `expected_seq` must be the finding's current `transition_seq` (409, field=/expected_seq) - the
  optimistic lock the transition route uses; a verification must not be queued against a finding
  the operator has not seen;
* the finding's campaign must be active (not COMPLETED/FAILED/CANCELLED): a terminal campaign has
  no workflow to dispatch the job, so accepting it would leave a `QUEUED` job nobody runs. That is
  a policy refusal with its own code, not a silent queue.
"""

from __future__ import annotations

from typing import Annotated, Any

import psycopg
from fastapi import APIRouter, Body, Depends, Header, Query, Request, Response
from fastapi import status as http_status

from aegis import validation
from aegis.common import verification_controls as control_map
from aegis.common.verification import VerificationCheck, load_checks
from aegis.contracts_gen.capability.job_submit_v2_schema import JobSubmit
from aegis.m05_registry.caps import CampaignPolicy, network_profile
from aegis.m05_registry.errors import M05Error
from aegis.m05_registry.service import JobService
from aegis.m05_registry.verification import approved_checks, build_request_input
from aegis.m26_api.app import API_PREFIX
from aegis.m26_api.db import ConnectionDep
from aegis.m26_api.errors import ApiError
from aegis.m26_api.jobs import _api_error, get_job_service
from aegis.m26_api.operator import Principal, require_principal
from aegis.m26_api.registry import RouterEntry, RouterRegistry
from aegis.m26_api.tracing import TRACEPARENT_HEADER, current_trace_id, traceparent

__all__ = [
    "CHECKS_PATH",
    "LIST_PATH",
    "REQUEST_PATH",
    "register",
    "router",
]

router = APIRouter(tags=["findings"])

CHECKS_PATH = "/findings/{finding_id}/verification-checks"
REQUEST_PATH = "/findings/{finding_id}/verifications"
LIST_PATH = "/findings/{finding_id}/verifications"
RUN_SCHEMA = "verification/verification-run.v2.schema.json"
REQUEST_SCHEMA = "verification/verification-request.v2.schema.json"
OPERATIONS = ("listVerificationChecks", "requestVerification", "listVerifications")
#: Statuses whose campaign still has a workflow to dispatch the job the request queues.
ACTIVE = ("CREATED", "RUNNING", "WAITING", "PAUSED")
IDEMPOTENCY_HEADER = Header(
    alias="Idempotency-Key",
    min_length=8,
    max_length=256,
    description="8-256 characters; the same key with the same body replays the accepted job.",
)
ERROR_400 = {"description": "Lỗi chuẩn (error.v2): body sai hoặc check_id ngoài enum"}
ERROR_401 = {"description": "Lỗi chuẩn (error.v2): thiếu hoặc sai operator token"}
ERROR_403 = {
    "description": (
        "Lỗi chuẩn (error.v2): check chưa duyệt, lab-only trên internet, hoặc target ngoài scope"
    )
}
ERROR_404 = {"description": "Lỗi chuẩn (error.v2): finding không tồn tại"}
ERROR_409 = {
    "description": "Lỗi chuẩn (error.v2): expected_seq lệch hoặc Idempotency-Key trùng body khác"
}


def register(registry: RouterRegistry, *, prefix: str = "") -> RouterEntry:
    return registry.register("verifications", router, prefix=prefix or API_PREFIX)


def _trace(request: Request, response: Response) -> str:
    trace = current_trace_id(request)
    response.headers[TRACEPARENT_HEADER] = traceparent(trace)
    return trace


def _is_id(value: str) -> bool:
    return not validation.errors("common/ids.v2.schema.json#/$defs/Id", value)


def _not_found(finding_id: str) -> ApiError:
    return ApiError(
        http_status.HTTP_404_NOT_FOUND,
        "INPUT_INVALID",
        f"finding {finding_id} does not exist",
        next_action="FIX_INPUT",
        field="/finding_id",
    )


def _finding(db: psycopg.Connection[Any], finding_id: str) -> dict[str, Any] | None:
    row = db.execute("SELECT * FROM finding WHERE finding_id = %s", (finding_id,)).fetchone()
    return None if row is None else dict(row)


def _campaign_policy(db: psycopg.Connection[Any], campaign_id: str) -> CampaignPolicy:
    row = db.execute(
        "SELECT c.campaign_id, c.current_policy_version, c.scope_id, p.policy"
        "  FROM campaign c JOIN policy_snapshot p"
        "    ON p.policy_version = c.current_policy_version"
        " WHERE c.campaign_id = %s",
        (campaign_id,),
    ).fetchone()
    if row is None:
        raise ApiError(
            http_status.HTTP_404_NOT_FOUND,
            "INPUT_INVALID",
            f"campaign {campaign_id} of the finding does not exist",
            next_action="FIX_INPUT",
            field="/finding_id",
        )
    campaign = CampaignPolicy(
        campaign_id=str(row["campaign_id"]),
        policy_version=str(row["current_policy_version"]),
        scope_id=str(row["scope_id"]),
        policy=dict(row["policy"]),
    )
    return campaign


def _status_of(db: psycopg.Connection[Any], campaign_id: str) -> str:
    row = db.execute(
        "SELECT status FROM campaign WHERE campaign_id = %s", (campaign_id,)
    ).fetchone()
    return "" if row is None else str(row["status"])


def _timestamp(value: Any) -> str:
    return str(value.isoformat()).replace("+00:00", "Z")


def _reason(check: VerificationCheck, *, profile: str, allowed: frozenset[str]) -> str | None:
    if check.check_id not in allowed:
        return f"not approved for the {profile} profile of this deployment"
    if check.lab_only and profile != "lab":
        return f"lab-only ({check.check_class}); the campaign's profile is {profile}"
    return None


@router.get(
    CHECKS_PATH,
    operation_id="listVerificationChecks",
    summary="Các check xác minh động áp dụng cho finding và profile của campaign",
    responses={401: ERROR_401, 404: ERROR_404},
)
def list_verification_checks(
    request: Request,
    response: Response,
    finding_id: str,
    principal: Annotated[Principal, Depends(require_principal)],
    db: ConnectionDep,
) -> dict[str, Any]:
    _trace(request, response)
    del principal
    if not _is_id(finding_id):
        raise _not_found(finding_id)
    finding = _finding(db, finding_id)
    if finding is None:
        raise _not_found(finding_id)
    campaign = _campaign_policy(db, str(finding["first_campaign_id"]))
    profile = network_profile(campaign.policy)
    allowed = approved_checks().allowed(profile)
    mapping = control_map.cached_controls()
    items = []
    for check in load_checks().checks:
        if check.finding_rule != str(finding["rule_id"]):
            continue
        reason = _reason(check, profile=profile, allowed=allowed)
        if reason is None and control_map.controls_for(mapping, check.check_id) is None:
            reason = "the deployment has no control map for this check"
        items.append(
            {
                "check_id": check.check_id,
                "title": check.title,
                "class": check.check_class,
                "lab_only": check.lab_only,
                "available": reason is None,
                **({"unavailable_reason": reason} if reason is not None else {}),
            }
        )
    return {"items": items}


@router.post(
    REQUEST_PATH,
    status_code=http_status.HTTP_202_ACCEPTED,
    operation_id="requestVerification",
    summary="Yêu cầu một lần xác minh động cho finding (job verify.check)",
    responses={400: ERROR_400, 401: ERROR_401, 403: ERROR_403, 404: ERROR_404, 409: ERROR_409},
)
def request_verification(
    request: Request,
    response: Response,
    finding_id: str,
    principal: Annotated[Principal, Depends(require_principal)],
    db: ConnectionDep,
    service: Annotated[JobService, Depends(get_job_service)],
    body: Annotated[dict[str, Any], Body(...)],
    idempotency_key: Annotated[str, IDEMPOTENCY_HEADER],
) -> Any:
    trace = _trace(request, response)
    if not _is_id(finding_id):
        raise _not_found(finding_id)
    if not isinstance(body, dict):
        raise ApiError(
            http_status.HTTP_400_BAD_REQUEST,
            "INPUT_INVALID",
            "body must be a verification-request object",
            next_action="FIX_INPUT",
            field="/",
        )
    problems = validation.problems(REQUEST_SCHEMA, body)
    if problems:
        pointer, message = problems[0]
        raise ApiError(
            http_status.HTTP_400_BAD_REQUEST,
            "INPUT_INVALID",
            f"{pointer or '/'}: {message}",
            next_action="FIX_INPUT",
            field=pointer or "/",
        )
    finding = _finding(db, finding_id)
    if finding is None:
        raise _not_found(finding_id)
    expected = int(body["expected_seq"])
    current = int(finding["transition_seq"])
    if expected != current:
        raise ApiError(
            http_status.HTTP_409_CONFLICT,
            "INPUT_INVALID",
            f"expected_seq {expected} is not the finding's current transition_seq {current}",
            next_action="FIX_INPUT",
            field="/expected_seq",
        )
    campaign = _campaign_policy(db, str(finding["first_campaign_id"]))
    profile = network_profile(campaign.policy)
    check_id = str(body["check_id"])
    check = load_checks().by_id(check_id)
    if check is None:  # pragma: no cover - the request schema enum is the registry
        raise ApiError(
            http_status.HTTP_400_BAD_REQUEST,
            "INPUT_INVALID",
            f"check {check_id!r} is not in the reviewed registry",
            next_action="FIX_INPUT",
            field="/check_id",
        )
    reason = _reason(check, profile=profile, allowed=approved_checks().allowed(profile))
    if reason is not None:
        raise ApiError(
            http_status.HTTP_403_FORBIDDEN,
            "POLICY_DENIED",
            f"check {check_id!r} is unavailable: {reason}",
            next_action="FIX_INPUT",
            field="/check_id",
        )
    if check.finding_rule != str(finding["rule_id"]):
        raise ApiError(
            http_status.HTTP_403_FORBIDDEN,
            "POLICY_DENIED",
            f"check {check_id!r} verifies {check.finding_rule}, the finding is "
            f"{finding['rule_id']}",
            next_action="FIX_INPUT",
            field="/check_id",
        )
    status = _status_of(db, campaign.campaign_id)
    if status not in ACTIVE:
        raise ApiError(
            http_status.HTTP_403_FORBIDDEN,
            "POLICY_DENIED",
            f"the finding's campaign is {status}; a verification job needs an active campaign to "
            "dispatch it",
            next_action="FIX_INPUT",
            field="/finding_id",
        )
    try:
        values = build_request_input(
            db,
            campaign=campaign,
            check=check,
            finding_id=finding_id,
        )
        outcome = service.submit(
            JobSubmit.model_validate(
                {
                    "campaign_id": campaign.campaign_id,
                    "capability": "verify.check",
                    "provider": check.provider,
                    "input": values,
                    "scan_cycle": None,
                    "rationale": f"verification {check.check_id} of finding {finding_id}",
                    "priority": 60,
                }
            ),
            requested_by={"kind": "operator", "id": principal.id},
            idempotency_key=idempotency_key.strip(),
            trace_id=trace,
        )
    except M05Error as error:
        raise _api_error(error) from error
    response.status_code = (
        http_status.HTTP_200_OK if outcome.replayed else http_status.HTTP_202_ACCEPTED
    )
    if outcome.replayed:
        response.headers["Idempotent-Replayed"] = "true"
    return outcome.job


def _run_document(row: dict[str, Any]) -> dict[str, Any]:
    document: dict[str, Any] = {
        "verification_id": str(row["verification_id"]),
        "finding_id": str(row["finding_id"]),
        "campaign_id": str(row["campaign_id"]),
        "job_id": str(row["job_id"]),
        "check_id": str(row["check_id"]),
        "check_class": str(row["check_class"]),
        "network_profile": str(row["network_profile"]),
        "check_pack_sha256": str(row["check_pack_sha256"]),
        "target": row["target_ref"],
        "controls": row["controls"],
        "outcome": str(row["outcome"]),
        "matched": row["matched"],
        "requests_sent": int(row["requests_sent"]),
        "request_cap": int(row["request_cap"]),
        "evidence": {
            "positive": str(row["positive_evidence_id"]),
            "control_a": None
            if row["control_a_evidence_id"] is None
            else str(row["control_a_evidence_id"]),
            "control_b": None
            if row["control_b_evidence_id"] is None
            else str(row["control_b_evidence_id"]),
        },
        "transition_seq": None if row["transition_seq"] is None else int(row["transition_seq"]),
        "requested_by": row["requested_by"],
        "decided_by": row["decided_by"],
        "started_at": _timestamp(row["started_at"]),
        "finished_at": _timestamp(row["finished_at"]),
    }
    if row["canary_sha256"] is not None or row["canary_name_sha256"] is not None:
        canary: dict[str, Any] = {}
        if row["canary_sha256"] is not None:
            canary["sha256"] = str(row["canary_sha256"])
        if row["canary_name_sha256"] is not None:
            canary["name_sha256"] = str(row["canary_name_sha256"])
        document["canary"] = canary
    problems = validation.problems(RUN_SCHEMA, document)
    if problems:
        pointer, message = problems[0]
        raise ApiError(
            http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            f"a verification run violates its contract at {pointer or '/'}: {message[:300]}",
        )
    return document


def _encode_cursor(created_at: Any, verification_id: str) -> str:
    import base64

    raw = f"{_timestamp(created_at)}|{verification_id}".encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_cursor(cursor: str) -> tuple[Any, str]:
    import base64
    import binascii
    from datetime import datetime

    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(padded.encode()).decode()
        at, _, verification_id = raw.partition("|")
        return datetime.fromisoformat(at.replace("Z", "+00:00")), verification_id
    except (ValueError, UnicodeDecodeError, binascii.Error) as error:
        raise ApiError(
            http_status.HTTP_400_BAD_REQUEST,
            "INPUT_INVALID",
            f"cursor is not a verification-run cursor: {error}",
            next_action="FIX_INPUT",
            field="/cursor",
        ) from error


@router.get(
    LIST_PATH,
    operation_id="listVerifications",
    summary="Các lần xác minh đã quyết định của finding, mới nhất trước",
    responses={400: ERROR_400, 401: ERROR_401, 404: ERROR_404},
)
def list_verifications(
    request: Request,
    response: Response,
    finding_id: str,
    principal: Annotated[Principal, Depends(require_principal)],
    db: ConnectionDep,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> dict[str, Any]:
    _trace(request, response)
    del principal
    if not _is_id(finding_id):
        raise _not_found(finding_id)
    if _finding(db, finding_id) is None:
        raise _not_found(finding_id)
    after_at, after_id = (None, None) if not cursor else _decode_cursor(cursor)
    rows = db.execute(
        "SELECT * FROM verification_run WHERE finding_id = %s"
        " AND (%s::timestamptz IS NULL OR (created_at, verification_id) < (%s, %s))"
        " ORDER BY created_at DESC, verification_id DESC LIMIT %s",
        (finding_id, after_at, after_at, after_id, limit + 1),
    ).fetchall()
    page = [dict(row) for row in rows[:limit]]
    document: dict[str, Any] = {"items": [_run_document(row) for row in page]}
    if len(rows) > limit and page:
        document["next_cursor"] = _encode_cursor(
            page[-1]["created_at"], str(page[-1]["verification_id"])
        )
    return document
