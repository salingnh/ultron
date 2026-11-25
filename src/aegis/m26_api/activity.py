"""`/api/v2/campaigns/{campaign_id}/activity` - what the agent did, without reading logs.

The screen this serves answers one question (DESIGN.md, "Nguyên tắc trình bày"): which sessions
ran, what each one proposed, what policy decided and why, what it was blocked on, and what it
spent. The endpoint is a **read model**, not a second state machine and not a log tail: every entry
is projected from the current row of the table that owns the fact, and nothing is written.

Sources (the four tables the agent's work already lives in):

* `agent_session` - one `session_started` and, once it is finished, one `session_finished` with
  the row's status, decision and `stop_reason`. The ledger's `cycle_started`/`cycle_finished`
  describe the same two events and add nothing to them, so they are not repeated here;
* `policy_decision` (+ `scan_job.decision_id`, unique since 0001) - one `decision` per tool call,
  with the resolved TargetRefs, approved/denied, the reason code (error.v2 `code` + the rule that
  refused) and the job it produced;
* `campaign_ledger` kinds `idle_cycle`, `blocker`, `budget` - the three entries M03 appends that no
  other table carries. `cursor` (a context-read marker) and `stop_condition` (already covered by
  `session_finished.stop_reason`) are not published.

Privacy is a property of the projection, not a filter: no query below selects `policy_decision.
rationale` or `.input`, no ledger payload is copied wholesale (only named numeric/enum fields), and
tool output never reaches this document. A field is published because it is a structured column
with a contract type - not because it happened to be short.

Order: newest first by the source timestamp, with `(kind, entry_id)` as a deterministic tiebreak,
so a keyset cursor is exact across pages even when two entries share an instant. The cursor carries
the campaign it was issued for; a cursor from another campaign is `400 INPUT_INVALID` instead of a
silently wrong page.

Contract: `contracts/api/openapi.v2.yaml` -> `getCampaignActivity`
(`x-aegis-status: locked`, `x-aegis-locked-by: G1.6-activity`), body
`contracts/agent/activity.v2.schema.json`. The route validates what it built against that schema and
answers 500 rather than an invalid 200 (`_validated`, the same rule as `getCampaignFlow`).
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime
from http import HTTPStatus
from typing import Annotated, Any

import psycopg
from fastapi import APIRouter, Depends, Query, Request, Response

from aegis import validation
from aegis.m01_campaign.campaigns import timestamp
from aegis.m26_api.db import ConnectionDep
from aegis.m26_api.errors import INPUT_INVALID, ApiError
from aegis.m26_api.operator import Principal, require_principal
from aegis.m26_api.registry import RouterRegistry
from aegis.m26_api.tracing import TRACEPARENT_HEADER, current_trace_id, traceparent

__all__ = [
    "ACTIVITY_OPERATIONS",
    "activity_timeline",
    "decode_cursor",
    "encode_cursor",
    "register",
    "router",
]

#: Operations this router implements; the conformance test compares it with the contract.
ACTIVITY_OPERATIONS = ("getCampaignActivity",)

ID_REFERENCE = "common/ids.v2.schema.json#/$defs/Id"
ERROR_401 = {"description": "Lỗi chuẩn (error.v2): thiếu hoặc sai operator token"}
API_PREFIX = "/api/v2"
PATH = "/campaigns/{campaign_id}/activity"

#: Ledger kinds this feed publishes; M03 owns them (`aegis.m03_agent.ledger.KINDS`).
LEDGER_KINDS = ("idle_cycle", "blocker", "budget")

#: Entry kinds, one per source row; the contract's `$defs/Entry` oneOf is the same closed set.
ENTRY_KINDS = ("session_started", "session_finished", "decision", "idle_cycle", "blocker", "budget")

router = APIRouter(tags=["campaigns"])


# --------------------------------------------------------------------------- helpers


def _is_id(value: str) -> bool:
    return not validation.errors(ID_REFERENCE, value)


def _trace(request: Request, response: Response) -> str:
    trace_id = current_trace_id(request)
    response.headers[TRACEPARENT_HEADER] = traceparent(trace_id)
    return trace_id


def _not_found(campaign_id: str) -> ApiError:
    return ApiError(
        HTTPStatus.NOT_FOUND,
        INPUT_INVALID,
        f"campaign {campaign_id} does not exist",
        next_action="FIX_INPUT",
    )


def _invalid_cursor(message: str) -> ApiError:
    return ApiError(
        HTTPStatus.BAD_REQUEST,
        INPUT_INVALID,
        message,
        next_action="FIX_INPUT",
        field="/cursor",
    )


def encode_cursor(at: str, kind: str, entry_id: str, campaign_id: str) -> str:
    """Opaque keyset cursor of `(at, kind, entry_id)` scoped to the campaign that issued it."""
    raw = f"{at}|{kind}|{entry_id}|{campaign_id}"
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")


def decode_cursor(cursor: str, campaign_id: str) -> tuple[str, str, str]:
    """Parse a cursor this endpoint issued for `campaign_id`; anything else is 400."""
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        at, kind, entry_id, issued_for = raw.split("|", 3)
        datetime.fromisoformat(at)
        if kind not in ENTRY_KINDS or not entry_id:
            raise ValueError("cursor does not name an entry of this feed")
    except (ValueError, UnicodeError, binascii.Error) as error:
        raise _invalid_cursor("cursor is not one this endpoint issued") from error
    if issued_for != campaign_id:
        raise _invalid_cursor("cursor was issued for another campaign")
    return at, kind, entry_id


def _validated(document: dict[str, Any]) -> dict[str, Any]:
    """A document that does not satisfy the locked response is a producer bug, not a 200."""
    validator = validation.openapi_response_validator(PATH)
    problems = sorted(validator.iter_errors(document), key=str)
    if problems:
        first = problems[0]
        pointer = "/" + "/".join(str(part) for part in first.absolute_path)
        raise ApiError(
            HTTPStatus.INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            f"activity read model violates getCampaignActivity at {pointer or '/'}: "
            f"{first.message[:300]}",
        )
    return document


def _maybe(values: dict[str, Any]) -> dict[str, Any]:
    """Drop the `None` values: the contract says "absent", never `null`, for optional fields."""
    return {key: value for key, value in values.items() if value is not None}


# --------------------------------------------------------------------------- queries

CAMPAIGN_ROW = "SELECT 1 FROM aegis.campaign WHERE campaign_id = %s"

#: The page's keys, newest first. One row per published source row: `(at, kind, entry_id)` is the
#: keyset key, `source_id` is what the second step re-reads the row by. `LIMIT limit + 1` is how the
#: route knows whether older entries exist without a second count.
PAGE_KEYS = """
    SELECT kind, entry_id, at, source_id FROM (
        SELECT 'session_started'::text AS kind,
               'session:' || s.session_id::text || ':start' AS entry_id,
               s.started_at AS at,
               s.session_id::text AS source_id
          FROM aegis.agent_session s
         WHERE s.campaign_id = %(campaign_id)s
        UNION ALL
        SELECT 'session_finished',
               'session:' || s.session_id::text || ':finish',
               s.finished_at,
               s.session_id::text
          FROM aegis.agent_session s
         WHERE s.campaign_id = %(campaign_id)s AND s.finished_at IS NOT NULL
        UNION ALL
        SELECT 'decision',
               'decision:' || d.decision_id::text,
               d.created_at,
               d.decision_id::text
          FROM aegis.policy_decision d
         WHERE d.campaign_id = %(campaign_id)s
        UNION ALL
        SELECT l.kind,
               'ledger:' || l.seq::text,
               l.created_at,
               l.seq::text
          FROM aegis.campaign_ledger l
         WHERE l.campaign_id = %(campaign_id)s AND l.kind = ANY(%(ledger_kinds)s)
    ) AS keys
     WHERE %(after_at)s::timestamptz IS NULL
        OR (at, kind, entry_id)
           < (%(after_at)s::timestamptz, %(after_kind)s::text, %(after_id)s::text)
     ORDER BY at DESC, kind DESC, entry_id DESC
     LIMIT %(limit)s
"""

SESSION_ROWS = """
    SELECT session_id, objective_id, policy_version, revision_from, status, decision,
           stop_reason, steps_used, started_at, finished_at
      FROM aegis.agent_session
     WHERE session_id = ANY(%s)
"""

DECISION_ROWS = """
    SELECT d.decision_id, d.session_id, d.capability, d.provider, d.decision, d.rule, d.error,
           d.target_refs, d.requested_by, d.proposed_by, d.policy_version, d.created_at,
           j.job_id
      FROM aegis.policy_decision d
      LEFT JOIN aegis.scan_job j ON j.decision_id = d.decision_id
     WHERE d.decision_id = ANY(%s)
"""

LEDGER_ROWS = """
    SELECT seq, kind, payload, created_at
      FROM aegis.campaign_ledger
     WHERE campaign_id = %s AND seq = ANY(%s)
"""


# --------------------------------------------------------------------------- entry builders


@dataclass(frozen=True, slots=True)
class Key:
    """One page slot: the ordering key plus the source row it points at."""

    kind: str
    entry_id: str
    at: datetime
    source_id: str


def _session_entries(kind: str, row: dict[str, Any]) -> dict[str, Any]:
    """`session_started` reads `started_at`; `session_finished` reads the terminal columns."""
    session_id = str(row["session_id"])
    if kind == "session_started":
        return _maybe(
            {
                "kind": kind,
                "entry_id": f"session:{session_id}:start",
                "at": timestamp(row["started_at"]),
                "session_id": session_id,
                "objective_id": None if row["objective_id"] is None else str(row["objective_id"]),
                "policy_version": row["policy_version"],
                "revision_from": int(row["revision_from"]),
            }
        )
    finished_at = row["finished_at"]
    if finished_at is None:  # pragma: no cover - the keys query filters these out
        raise ApiError(
            HTTPStatus.INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            f"agent_session {session_id} has a finish key but no finished_at",
        )
    return _maybe(
        {
            "kind": kind,
            "entry_id": f"session:{session_id}:finish",
            "at": timestamp(finished_at),
            "session_id": session_id,
            "status": row["status"],
            "decision": row["decision"],
            "stop_reason": row["stop_reason"],
            "steps_used": int(row["steps_used"]),
        }
    )


def _decision_entry(row: dict[str, Any]) -> dict[str, Any]:
    """One policy decision; the reason carries error.v2 `code` and the rule that refused."""
    decision = str(row["decision"])
    entry: dict[str, Any] = {
        "kind": "decision",
        "entry_id": f"decision:{row['decision_id']}",
        "at": timestamp(row["created_at"]),
        "decision_id": str(row["decision_id"]),
        "capability": row["capability"],
        "decision": decision,
        "targets": list(row["target_refs"] or ()),
        "requested_by": dict(row["requested_by"]),
        "policy_version": row["policy_version"],
    }
    optional = _maybe(
        {
            "provider": row["provider"],
            "job_id": None if row["job_id"] is None else str(row["job_id"]),
            "proposed_by": None if row["proposed_by"] is None else dict(row["proposed_by"]),
        }
    )
    entry.update(optional)
    if decision == "denied":
        # The 0001 CHECK refuses a denied decision without an error object, and error.v2 requires
        # `code`; a row that broke that is a producer bug and fails the contract below.
        error = row["error"] if isinstance(row["error"], dict) else {}
        entry["reason"] = _maybe({"code": error.get("code"), "rule": row["rule"]})
    return entry


def _ledger_entry(row: dict[str, Any]) -> dict[str, Any]:
    """`idle_cycle`/`blocker`/`budget` from the named payload fields; never the free-text ones."""
    kind = str(row["kind"])
    payload = row["payload"] if isinstance(row["payload"], dict) else {}
    session_id = payload.get("session_id")
    entry: dict[str, Any] = {
        "kind": kind,
        "entry_id": f"ledger:{row['seq']}",
        "at": timestamp(row["created_at"]),
        "session_id": None if session_id is None else str(session_id),
    }
    if kind == "idle_cycle":
        cycle = payload.get("cycle")
        entry["cycle"] = None if cycle is None else int(cycle)
    elif kind == "blocker":
        # `detail` is deliberately not published: it is free text built from a dependency's answer.
        entry["code"] = payload.get("code")
        entry["context"] = None if payload.get("context") is None else str(payload["context"])[:200]
    elif kind == "budget":
        entry["sent_tokens"] = int(payload.get("sent_tokens") or 0)
        entry["sent_cost_usd"] = float(payload.get("sent_cost_usd") or 0.0)
        for key in ("remaining_tokens", "remaining_cost_usd"):
            value = payload.get(key)
            if value is None:
                entry[key] = None
            elif key.endswith("tokens"):
                entry[key] = int(value)
            else:
                entry[key] = float(value)
        models = payload.get("models")
        if isinstance(models, list) and models:
            entry["models"] = [str(model)[:200] for model in models]
    return _maybe(entry)


def _entries_by_key(
    connection: psycopg.Connection[Any], campaign_id: str, keys: list[Key]
) -> dict[str, dict[str, Any]]:
    """Re-read only the rows behind this page's keys, then turn each into its entry."""
    entry_ids = [key.entry_id for key in keys]
    sessions = {
        str(row["session_id"]): row
        for row in connection.execute(
            SESSION_ROWS,
            ([key.source_id for key in keys if key.kind.startswith("session")],),
        ).fetchall()
    }
    decisions = {
        str(row["decision_id"]): row
        for row in connection.execute(
            DECISION_ROWS, ([key.source_id for key in keys if key.kind == "decision"],)
        ).fetchall()
    }
    ledger = {
        str(row["seq"]): row
        for row in connection.execute(
            LEDGER_ROWS,
            (campaign_id, [int(key.source_id) for key in keys if key.kind in LEDGER_KINDS]),
        ).fetchall()
    }
    entries: dict[str, dict[str, Any]] = {}
    for key in keys:
        if key.kind.startswith("session"):
            row = sessions.get(key.source_id)
            if row is not None:
                entries[key.entry_id] = _session_entries(key.kind, row)
        elif key.kind == "decision":
            row = decisions.get(key.source_id)
            if row is not None:
                entries[key.entry_id] = _decision_entry(row)
        else:
            row = ledger.get(key.source_id)
            if row is not None:
                entries[key.entry_id] = _ledger_entry(row)
    missing = [entry_id for entry_id in entry_ids if entry_id not in entries]
    if missing:  # pragma: no cover - the keys and the rows come from one database
        raise ApiError(
            HTTPStatus.INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            f"activity read model lost {len(missing)} source row(s): {missing[:3]}",
        )
    return entries


# --------------------------------------------------------------------------- read model


def activity_timeline(
    connection: psycopg.Connection[Any],
    campaign_id: str,
    *,
    after: tuple[str, str, str] | None = None,
    limit: int = 50,
) -> dict[str, Any] | None:
    """One page of the campaign's activity timeline, or None when the campaign does not exist."""
    if connection.execute(CAMPAIGN_ROW, (campaign_id,)).fetchone() is None:
        return None
    after_at, after_kind, after_id = (None, None, None) if after is None else after
    rows = connection.execute(
        PAGE_KEYS,
        {
            "campaign_id": campaign_id,
            "ledger_kinds": list(LEDGER_KINDS),
            "after_at": after_at,
            "after_kind": after_kind,
            "after_id": after_id,
            "limit": limit + 1,
        },
    ).fetchall()
    keys = [
        Key(
            kind=str(row["kind"]),
            entry_id=str(row["entry_id"]),
            at=row["at"],
            source_id=str(row["source_id"]),
        )
        for row in rows
    ]
    more = len(keys) > limit
    page = keys[:limit]
    entries = _entries_by_key(connection, campaign_id, page) if page else {}
    document: dict[str, Any] = {
        "items": [entries[key.entry_id] for key in page],
        "truncated": more,
    }
    if more and page:
        last = page[-1]
        document["next_cursor"] = encode_cursor(
            timestamp(last.at), last.kind, last.entry_id, campaign_id
        )
    return document


# --------------------------------------------------------------------------- routes


@router.get(
    PATH,
    operation_id="getCampaignActivity",
    summary=(
        "Dòng thời gian hoạt động của agent trong chiến dịch (phiên, quyết định tool, "
        "idle/blocker, ngân sách)"
    ),
    responses={
        HTTPStatus.BAD_REQUEST: {"description": "Lỗi chuẩn (error.v2): cursor/limit sai"},
        HTTPStatus.UNAUTHORIZED: ERROR_401,
        HTTPStatus.NOT_FOUND: {"description": "Lỗi chuẩn (error.v2): campaign không tồn tại"},
    },
)
def get_campaign_activity(
    request: Request,
    response: Response,
    campaign_id: str,
    principal: Annotated[Principal, Depends(require_principal)],
    db: ConnectionDep,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> dict[str, Any]:
    """Keyset page (newest first) of what the agent did in one campaign."""
    _trace(request, response)
    if not _is_id(campaign_id):
        raise _not_found(campaign_id)
    after = decode_cursor(cursor, campaign_id) if cursor else None
    document = activity_timeline(db, campaign_id, after=after, limit=limit)
    if document is None:
        raise _not_found(campaign_id)
    return _validated(document)


def register(registry: RouterRegistry, *, prefix: str = "") -> Any:
    """Mount the activity router on the app registry (called by `main.build_registry`)."""
    return registry.register("activity", router, prefix=prefix or API_PREFIX)
