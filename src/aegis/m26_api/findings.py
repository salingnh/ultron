"""M26 findings API (G2 slice A): the operator view and lifecycle of M20's findings.

Contract: `contracts/api/openapi.v2.yaml` operations `listFindings`, `getFinding`,
`transitionFinding`, `getFindingHistory` and `assessFinding`; the item shape is
`contracts/finding/finding.v2.schema.json`, the history shape is inline in the OpenAPI.

Every operation is behind the operator bearer (`require_principal`): a finding carries evidence
references and severity, so it is not anonymous data. The response of every operation is validated
against the contract before it leaves the app - a producer bug is a 500, never a 200 with a shape
the UI would render as truth.

`listFindings` is a keyset page over `(last_seen, finding_id)` descending. `campaign_id` narrows to
the campaigns that hold the finding's asset (`asset_campaign`), never to `first_campaign_id`: an
asset found by one campaign is the same finding for every campaign that acquired it (the
candidate rule of migration 0004/0008). `changed_since` filters on `last_seen`, the public "when
was this finding last observed" instant.

`transitionFinding` is the operator's lifecycle action. The table `finding/transitions.v2.yaml` is
the rule (`aegis.common.finding_transitions`), the actor is the server-verified principal (the body
`transition-request.v2` carries no actor at all, C05), and `expected_seq` is an optimistic
lock: a stale value answers 409 with `field=/expected_seq`, never overwrites a concurrent change.
The write is idempotent on the contract's `Idempotency-Key` (the same `idempotency_record` table the
campaign routes use, scoped by the operation and the finding): the same key with the same body
replays the stored response (header `Idempotent-Replayed: true`) and writes nothing, while the same
key with a different body is `IDEMPOTENCY_CONFLICT`. The transition row, the `finding.changed.v2`
event and the idempotency record are written in one transaction.

`assessFinding` runs the C07 severity assessment (M20's runtime) on demand. It is idempotent per
input revision: a retry of the same finding at the same knowledge revision returns the stored
record and calls no model. A missing model or an exhausted campaign budget stores an UNRATED record
with the failure, which is a 200 - the finding's severity is data, not a request error.
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
from aegis.common.finding_transitions import rule_for
from aegis.common.finding_write import TransitionRefused, write_transition
from aegis.m20_vuln import severity
from aegis.m26_api.app import API_PREFIX
from aegis.m26_api.db import ConnectionDep
from aegis.m26_api.errors import INPUT_INVALID, ApiError
from aegis.m26_api.idempotency import (
    IdempotencyConflict,
    lock_key,
    replay,
    request_hash,
    store,
)
from aegis.m26_api.operator import Principal, require_principal
from aegis.m26_api.registry import RouterEntry, RouterRegistry
from aegis.m26_api.tracing import TRACEPARENT_HEADER, current_trace_id, traceparent

__all__ = [
    "FINDING_OPERATIONS",
    "decode_cursor",
    "encode_cursor",
    "register",
    "router",
]

LIST_PATH = "/findings"
ITEM_PATH = "/findings/{finding_id}"
TRANSITION_PATH = "/findings/{finding_id}/transitions"
HISTORY_PATH = "/findings/{finding_id}/history"
ASSESSMENT_PATH = "/findings/{finding_id}/assessment"
FINDING_SCHEMA = "finding/finding.v2.schema.json"
TRANSITION_SCHEMA = "finding/transition-request.v2.schema.json"
SEVERITY_SCHEMA = severity.SEVERITY_SCHEMA
STATUS_SCHEMA = "finding/finding-status.v2.schema.json"
#: Operations this router implements; the conformance test compares it with the contract.
FINDING_OPERATIONS = (
    "listFindings",
    "getFinding",
    "transitionFinding",
    "getFindingHistory",
    "assessFinding",
)
#: The operator's side of the transition table (the server-verified principal acts).
OPERATOR = "operator"
#: The outbox `producer` of an operator transition (the API wrote it, the operator acted).
PRODUCER = "M26"
#: Header of a replayed write (contract convention; same value as the campaign routes).
IDEMPOTENT_REPLAYED = "Idempotent-Replayed"
#: `idempotency_record.scope` of a transition; the finding is part of the scope because the same
#: key on two findings is two different writes (the body alone cannot tell them apart).
TRANSITION_SCOPE = "POST /findings/{finding_id}/transitions"
IDEMPOTENCY_HEADER = Header(
    ...,
    alias="Idempotency-Key",
    min_length=8,
    max_length=256,
    description="Idempotency-Key của contract: cùng khóa cùng body trả lại kết quả cũ.",
)

_ERROR_400 = {"description": "Lỗi chuẩn (error.v2): tham số/body sai"}
_ERROR_401 = {"description": "Lỗi chuẩn (error.v2): thiếu hoặc sai operator token"}
_ERROR_404 = {"description": "Lỗi chuẩn (error.v2): finding không tồn tại"}
_ERROR_409 = {"description": "Chuyển trạng thái không hợp lệ hoặc expected_seq lệch"}

router = APIRouter(tags=["findings"])

LIST_QUERY = (
    "SELECT f.finding_id, f.fingerprint, f.asset_id, a.canonical_key AS asset_key,"
    "       f.rule_id, f.category, f.title, f.vulnerability_ids, f.location, f.match_method,"
    "       f.confidence, f.status, f.severity, f.current_assessment, f.transition_seq,"
    "       f.first_seen, f.last_seen,"
    "       (SELECT array_agg(DISTINCT fs.provider) FROM finding_source fs"
    "         WHERE fs.finding_id = f.finding_id) AS providers"
    "  FROM finding f JOIN asset a ON a.asset_id = f.asset_id"
    " WHERE (%s::uuid IS NULL OR EXISTS ("
    "         SELECT 1 FROM asset_campaign ac"
    "          WHERE ac.asset_id = f.asset_id AND ac.campaign_id = %s::uuid))"
    "   AND (%s::uuid IS NULL OR f.asset_id = %s::uuid)"
    "   AND (%s::text[] IS NULL OR f.status = ANY(%s::text[]))"
    "   AND (%s::text[] IS NULL OR f.severity = ANY(%s::text[]))"
    "   AND (%s::text IS NULL OR f.category = %s::text)"
    "   AND (%s::text IS NULL OR %s::text = ANY(f.vulnerability_ids))"
    "   AND (%s::boolean = FALSE OR EXISTS ("
    "         SELECT 1 FROM vulnerability_current vc"
    "          WHERE vc.source = 'kev' AND NOT vc.withdrawn"
    "            AND vc.vulnerability_id = ANY(f.vulnerability_ids)))"
    "   AND (%s::timestamptz IS NULL OR f.last_seen >= %s::timestamptz)"
    "   AND (%s::timestamptz IS NULL"
    "        OR (f.last_seen, f.finding_id) < (%s::timestamptz, %s::uuid))"
    " ORDER BY f.last_seen DESC, f.finding_id DESC"
    " LIMIT %s"
)

#: The single-finding read is its own statement: the page query's first filter is a campaign.
FINDING_QUERY = (
    "SELECT f.finding_id, f.fingerprint, f.asset_id, a.canonical_key AS asset_key,"
    "       f.rule_id, f.category, f.title, f.vulnerability_ids, f.location, f.match_method,"
    "       f.confidence, f.status, f.severity, f.current_assessment, f.transition_seq,"
    "       f.first_seen, f.last_seen,"
    "       (SELECT array_agg(DISTINCT fs.provider) FROM finding_source fs"
    "         WHERE fs.finding_id = f.finding_id) AS providers"
    "  FROM finding f JOIN asset a ON a.asset_id = f.asset_id"
    " WHERE f.finding_id = %s"
)

EVIDENCE_QUERY = (
    "SELECT DISTINCT ON (fr.finding_id, e.evidence_id)"
    "       fr.finding_id, e.evidence_id, e.sha256, e.source_tool, e.media_type, fr.observed_at"
    "  FROM finding_run fr JOIN evidence e ON e.evidence_id = fr.evidence_id"
    " WHERE fr.finding_id = ANY(%s::uuid[]) AND fr.evidence_id IS NOT NULL"
    " ORDER BY fr.finding_id, e.evidence_id, fr.observed_at DESC"
)


def _is_id(value: str) -> bool:
    return not validation.errors("common/ids.v2.schema.json#/$defs/Id", value)


def _trace(request: Request, response: Response) -> None:
    response.headers[TRACEPARENT_HEADER] = traceparent(current_trace_id(request))


def _bad_request(message: str, field: str) -> ApiError:
    return ApiError(
        http_status.HTTP_400_BAD_REQUEST,
        INPUT_INVALID,
        message,
        next_action="FIX_INPUT",
        field=field,
    )


def _not_found(finding_id: str) -> ApiError:
    return ApiError(
        http_status.HTTP_404_NOT_FOUND,
        INPUT_INVALID,
        f"finding {finding_id} does not exist",
        next_action="FIX_INPUT",
    )


def _stale_seq(expected: int, current: int) -> ApiError:
    """A stale `expected_seq`: a 409 whose stable discriminator is the field, not a generic code.

    `error.v2` has no conflict code of its own; the repository's state-conflict convention
    (`campaigns._state_conflict`) is `INPUT_INVALID` with 409. `field` points at the input that
    lost the race, so an API client can tell it apart from a reused `Idempotency-Key`
    (`IDEMPOTENCY_CONFLICT`, no field) without parsing the message.
    """
    return ApiError(
        http_status.HTTP_409_CONFLICT,
        INPUT_INVALID,
        f"expected_seq {expected} does not match the current transition_seq {current}",
        next_action="RETRY",
        field="/expected_seq",
        headers={"Retry-After": "0"},
    )


def _not_allowed(from_status: str, to_status: str) -> ApiError:
    return ApiError(
        http_status.HTTP_409_CONFLICT,
        INPUT_INVALID,
        f"transitions.v2.yaml does not allow {from_status} -> {to_status} by the operator",
        next_action="FIX_INPUT",
        field="/to",
    )


def _idempotency_conflict(error: IdempotencyConflict) -> ApiError:
    return ApiError(
        http_status.HTTP_409_CONFLICT,
        "IDEMPOTENCY_CONFLICT",
        f"Idempotency-Key was already used with a different body ({error.scope})",
        next_action="NONE",
    )


def encode_cursor(last_seen: datetime, finding_id: str) -> str:
    stamp = last_seen.isoformat().replace("+00:00", "Z")
    raw = f"finding|{stamp}|{finding_id}"
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, str]:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        marker, _, rest = raw.partition("|")
        stamp, _, finding_id = rest.partition("|")
        if marker != "finding" or not stamp or not _is_id(finding_id):
            raise ValueError("not a finding cursor")
        parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except (ValueError, UnicodeError, binascii.Error) as error:
        raise _bad_request("cursor is not one this endpoint issued", "/cursor") from error
    return parsed, finding_id


def _timestamp(value: object) -> str:
    render = getattr(value, "isoformat", None)
    if callable(render):
        return str(render()).replace("+00:00", "Z")
    return str(value)


def _split(values: list[str] | None) -> list[str] | None:
    """`?status=a,b` (OpenAPI form/explode=false) and `?status=a&status=b` both work."""
    if values is None:
        return None
    flattened: list[str] = []
    for value in values:
        flattened.extend(part.strip() for part in value.split(",") if part.strip())
    return flattened or None


def _evidence(
    db: psycopg.Connection[Any], finding_ids: list[str]
) -> dict[str, list[dict[str, Any]]]:
    if not finding_ids:
        return {}
    rows = db.execute(EVIDENCE_QUERY, (finding_ids,)).fetchall()
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        item = {
            "evidence_id": str(row["evidence_id"]),
            "sha256": str(row["sha256"]),
            "source_tool": str(row["source_tool"]),
            "media_type": str(row["media_type"]),
        }
        grouped.setdefault(str(row["finding_id"]), []).append(item)
    return grouped


def _assessment_record(db: psycopg.Connection[Any], assessment_id: object) -> dict[str, Any] | None:
    if assessment_id is None:
        return None
    row = db.execute(
        "SELECT assessment FROM severity_assessment WHERE assessment_id = %s", (assessment_id,)
    ).fetchone()
    return None if row is None else dict(row["assessment"])


def _item(
    db: psycopg.Connection[Any],
    row: dict[str, Any],
    evidence: list[dict[str, Any]],
    *,
    detail: bool,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "finding_id": str(row["finding_id"]),
        "fingerprint": str(row["fingerprint"]),
        "asset_id": str(row["asset_id"]),
        "asset_key": str(row["asset_key"]),
        "rule_id": str(row["rule_id"]),
        "category": str(row["category"]),
        "title": str(row["title"]),
        "vulnerability_ids": [str(value) for value in row["vulnerability_ids"] or ()],
        "location": dict(row["location"] or {}),
        "status": str(row["status"]),
        "severity": str(row["severity"]),
        "first_seen": _timestamp(row["first_seen"]),
        "last_seen": _timestamp(row["last_seen"]),
        "evidence": evidence,
    }
    if row["match_method"] is not None:
        item["match_method"] = str(row["match_method"])
    if row["confidence"] is not None:
        item["confidence"] = float(row["confidence"])
    providers = [str(value) for value in row["providers"] or ()]
    if providers:
        item["providers"] = providers
    if detail:
        assessment = _assessment_record(db, row["current_assessment"])
        if assessment is not None:
            item["severity_assessment"] = assessment
    return item


def _validated(schema: str, document: dict[str, Any], label: str) -> dict[str, Any]:
    problems = validation.problems(schema, document)
    if problems:
        pointer, message = problems[0]
        raise ApiError(
            http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            f"{label} violates {schema} at {pointer or '/'}: {message[:300]}",
        )
    return document


def _finding_row(db: psycopg.Connection[Any], finding_id: str) -> dict[str, Any] | None:
    row = db.execute(FINDING_QUERY, (finding_id,)).fetchone()
    return None if row is None else dict(row)


def _document(db: psycopg.Connection[Any], row: dict[str, Any]) -> dict[str, Any]:
    evidence = _evidence(db, [str(row["finding_id"])]).get(str(row["finding_id"]), [])
    return _item(db, row, evidence, detail=True)


@router.get(
    LIST_PATH,
    operation_id="listFindings",
    summary="Lọc và xuất findings",
    responses={400: _ERROR_400, 401: _ERROR_401},
)
def list_findings(
    request: Request,
    response: Response,
    principal: Annotated[Principal, Depends(require_principal)],
    db: ConnectionDep,
    campaign_id: Annotated[str | None, Query()] = None,
    asset_id: Annotated[str | None, Query()] = None,
    status: Annotated[list[str] | None, Query()] = None,
    severity_: Annotated[list[str] | None, Query(alias="severity")] = None,
    category: Annotated[str | None, Query()] = None,
    vulnerability_id: Annotated[str | None, Query()] = None,
    kev: Annotated[bool, Query()] = False,
    changed_since: Annotated[datetime | None, Query()] = None,
    format: Annotated[str, Query()] = "json",
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> dict[str, Any]:
    _trace(request, response)
    del principal  # the dependency is the check; the read needs no actor
    if format != "json":
        raise _bad_request("only format=json is published at G2", "/format")
    for name, value in (("campaign_id", campaign_id), ("asset_id", asset_id)):
        if value is not None and not _is_id(value):
            raise _bad_request(f"{name} is not a valid id", f"/{name}")
    statuses = _split(status)
    severities = _split(severity_)
    if statuses is not None:
        allowed = set(validation.document(STATUS_SCHEMA).get("enum") or ())
        unknown = [value for value in statuses if value not in allowed]
        if unknown:
            raise _bad_request(f"unknown finding status {unknown[0]}", "/status")
    if severities is not None:
        allowed = set(
            (validation.document(SEVERITY_SCHEMA).get("$defs") or {})
            .get("Severity", {})
            .get("enum")
            or ()
        )
        unknown = [value for value in severities if value not in allowed]
        if unknown:
            raise _bad_request(f"unknown severity {unknown[0]}", "/severity")
    after_seen: datetime | None = None
    after_id: str | None = None
    if cursor:
        after_seen, after_id = decode_cursor(cursor)
    rows = db.execute(
        LIST_QUERY,
        (
            campaign_id,
            campaign_id,
            asset_id,
            asset_id,
            statuses,
            statuses,
            severities,
            severities,
            category,
            category,
            vulnerability_id,
            vulnerability_id,
            kev,
            changed_since,
            changed_since,
            after_seen,
            after_seen,
            after_id,
            limit + 1,
        ),
    ).fetchall()
    page = [dict(row) for row in rows[:limit]]
    evidence = _evidence(db, [str(row["finding_id"]) for row in page])
    body: dict[str, Any] = {
        "items": [
            _validated(
                FINDING_SCHEMA,
                _item(
                    db,
                    row,
                    evidence.get(str(row["finding_id"]), []),
                    detail=False,
                ),
                "a finding list item",
            )
            for row in page
        ]
    }
    if len(rows) > limit and page:
        body["next_cursor"] = encode_cursor(page[-1]["last_seen"], str(page[-1]["finding_id"]))
    return body


@router.get(
    ITEM_PATH,
    operation_id="getFinding",
    summary="Chi tiết finding kèm bằng chứng (signed URL)",
    responses={401: _ERROR_401, 404: _ERROR_404},
)
def get_finding(
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
    row = _finding_row(db, finding_id)
    if row is None:
        raise _not_found(finding_id)
    return _validated(FINDING_SCHEMA, _document(db, row), "a finding")


@router.get(
    HISTORY_PATH,
    operation_id="getFindingHistory",
    summary=(
        "Trạng thái và mức nghiêm trọng theo từng lần chạy (FindingRun) cùng các lần chuyển "
        "trạng thái"
    ),
    responses={401: _ERROR_401, 404: _ERROR_404},
)
def get_finding_history(
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
    if _finding_row(db, finding_id) is None:
        raise _not_found(finding_id)
    runs = db.execute(
        "SELECT scan_id, seen, status, severity, severity_reason, evidence_id, observed_at"
        "  FROM finding_run WHERE finding_id = %s ORDER BY observed_at DESC, scan_id DESC",
        (finding_id,),
    ).fetchall()
    transitions = db.execute(
        "SELECT seq, from_status, to_status, reason, evidence_id, actor, cause, created_at"
        "  FROM finding_transition WHERE finding_id = %s ORDER BY seq",
        (finding_id,),
    ).fetchall()
    assessments = db.execute(
        "SELECT assessment FROM severity_assessment WHERE finding_id = %s"
        " ORDER BY created_at DESC, assessment_id DESC",
        (finding_id,),
    ).fetchall()
    body: dict[str, Any] = {
        "runs": [_run_item(dict(row)) for row in runs],
        "transitions": [_transition_item(dict(row)) for row in transitions],
        "assessments": [dict(row["assessment"]) for row in assessments],
    }
    return _validated_history(body)


def _run_item(row: dict[str, Any]) -> dict[str, Any]:
    item: dict[str, Any] = {
        "scan_id": str(row["scan_id"]),
        "seen": bool(row["seen"]),
        "status": str(row["status"]),
        "severity": str(row["severity"]),
        "observed_at": _timestamp(row["observed_at"]),
    }
    if row["severity_reason"] is not None:
        item["severity_reason"] = str(row["severity_reason"])
    if row["evidence_id"] is not None:
        item["evidence_id"] = str(row["evidence_id"])
    return item


def _transition_item(row: dict[str, Any]) -> dict[str, Any]:
    item: dict[str, Any] = {
        "seq": int(row["seq"]),
        "from_status": None if row["from_status"] is None else str(row["from_status"]),
        "to_status": str(row["to_status"]),
        "reason": str(row["reason"]),
        "actor": dict(row["actor"]),
        "cause": str(row["cause"]),
        "created_at": _timestamp(row["created_at"]),
    }
    if row["evidence_id"] is not None:
        item["evidence_id"] = str(row["evidence_id"])
    return item


def _validated_history(document: dict[str, Any]) -> dict[str, Any]:
    problems = validation.openapi_response_validator(HISTORY_PATH).iter_errors(document)
    first = next(problems, None)
    if first is not None:
        raise ApiError(
            http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "finding history violates its contract at "
            f"/{'/'.join(str(part) for part in first.absolute_path)}: {first.message[:300]}",
        )
    return document


@router.post(
    TRANSITION_PATH,
    operation_id="transitionFinding",
    summary="Đổi trạng thái finding kèm lý do (kiểm theo finding/transitions.v2.yaml)",
    responses={400: _ERROR_400, 401: _ERROR_401, 404: _ERROR_404, 409: _ERROR_409},
)
def transition_finding(
    request: Request,
    response: Response,
    finding_id: str,
    principal: Annotated[Principal, Depends(require_principal)],
    db: ConnectionDep,
    body: Annotated[dict[str, Any], Body(...)],
    idempotency_key: Annotated[str, IDEMPOTENCY_HEADER],
) -> dict[str, Any]:
    _trace(request, response)
    if not _is_id(finding_id):
        raise _not_found(finding_id)
    if not isinstance(body, dict):
        raise _bad_request("body must be a transition-request object", "/")
    problems = validation.problems(TRANSITION_SCHEMA, body)
    if problems:
        pointer, message = problems[0]
        raise _bad_request(f"{pointer or '/'}: {message}", pointer or "/")
    # The body carries no actor (transition-request.v2): the server assigns the verified
    # principal, so a client cannot name another operator in the history.
    scope = TRANSITION_SCOPE.format(finding_id=finding_id)
    digest = request_hash(body)
    lock_key(db, scope=scope, key=idempotency_key)
    try:
        previous = replay(db, scope=scope, key=idempotency_key, digest=digest)
    except IdempotencyConflict as error:
        raise _idempotency_conflict(error) from error
    if previous is not None:
        # The response of the first call, even if the finding has changed since: that is what
        # "same key + same body returns the original response" means, and it writes nothing.
        response.headers[IDEMPOTENT_REPLAYED] = "true"
        return previous
    row = db.execute(
        "SELECT * FROM finding WHERE finding_id = %s FOR UPDATE", (finding_id,)
    ).fetchone()
    if row is None:
        raise _not_found(finding_id)
    finding = dict(row)
    expected = int(body["expected_seq"])
    current = int(finding["transition_seq"])
    if expected != current:
        raise _stale_seq(expected, current)
    to_status = str(body["to"])
    reason = str(body["reason"])
    rule = rule_for(str(finding["status"]), to_status, OPERATOR)
    if rule is None:
        raise _not_allowed(str(finding["status"]), to_status)
    evidence_id = body.get("evidence_id")
    if "reason" in rule.requires and not reason:
        raise _bad_request("this transition requires a reason", "/reason")
    if "evidence" in rule.requires and not evidence_id:
        raise _bad_request("this transition requires evidence_id", "/evidence_id")
    if evidence_id is not None and not _is_id(str(evidence_id)):
        raise _bad_request("evidence_id is not a valid id", "/evidence_id")
    if (
        evidence_id is not None
        and db.execute("SELECT 1 FROM evidence WHERE evidence_id = %s", (evidence_id,)).fetchone()
        is None
    ):
        raise _bad_request(f"evidence {evidence_id} does not exist", "/evidence_id")
    seq = current + 1
    try:
        write_transition(
            db,
            finding_id=finding_id,
            from_status=str(finding["status"]),
            to_status=to_status,
            reason=reason,
            evidence_id=None if evidence_id is None else str(evidence_id),
            actor={"kind": "operator", "id": principal.id},
            cause="operator",
            old_severity=str(finding["severity"]),
            new_severity=str(finding["severity"]),
            campaign_id=str(finding["first_campaign_id"]),
            seq=seq,
            producer=PRODUCER,
            trace={"trace_id": current_trace_id(request)},
        )
    except TransitionRefused as error:
        raise _stale_seq(current, current + 1) from error
    fresh = _finding_row(db, finding_id)
    if fresh is None:  # pragma: no cover - the row was locked and updated in this transaction
        raise _not_found(finding_id)
    document = _validated(FINDING_SCHEMA, _document(db, fresh), "a finding")
    store(
        db,
        scope=scope,
        key=idempotency_key,
        digest=digest,
        status_code=http_status.HTTP_200_OK,
        response=document,
    )
    return document


@router.post(
    ASSESSMENT_PATH,
    operation_id="assessFinding",
    summary="Đánh giá mức nghiêm trọng do agent (C07) cho một finding",
    responses={400: _ERROR_400, 401: _ERROR_401, 404: _ERROR_404},
)
async def assess_finding(
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
    if _finding_row(db, finding_id) is None:
        raise _not_found(finding_id)
    client = getattr(request.app.state, "severity_client", None)
    model, provider, model_name = (None, None, None) if client is None else client
    assessor = severity.SeverityAssessor(db, model=model, provider=provider, model_name=model_name)
    outcome = await assessor.assess(finding_id, trigger="operator_request")
    return _validated(SEVERITY_SCHEMA, outcome.record, "a severity assessment")


def register(registry: RouterRegistry, *, prefix: str = API_PREFIX) -> RouterEntry:
    """Mount the findings router on an app registry."""
    return registry.register("findings", router, prefix=prefix)
