"""`/api/v2/campaigns/{campaign_id}/flow` - the React Flow read model of one campaign (G1.5a).

The endpoint answers one question for the scan-flow screen: what happened in this campaign, in
which order, and why is a job still waiting? It is a **read model**, not a second state machine:
every node is projected from the current row of its own module (`campaign`, `agent_session`,
`policy_decision`, `scan_job`) and every edge from a relationship that module already stores
(`job_dependency`, `policy_decision.session_id`, `scan_job.decision_id`). Nothing is inferred,
nothing is written.

Contract: `contracts/api/openapi.v2.yaml` -> `getCampaignFlow` (`x-aegis-status: locked`,
`x-aegis-locked-by: G1.5a`). The node shape is conditional, and this module feeds it exactly:

* a `job` node carries the full `job.v2` triple the screen needs - `status` (JobStatus),
  `attempt`/`generation` (0007 fencing) and, while the job waits, `wait_reason`, plus the
  `cancel` intent of `job.v2#/$defs/CancelIntent`;
* every other node type carries a status of its own module and **no** `attempt`/`generation`
  (the contract's `allOf` refuses them).

`finding_batch` is part of the published node enum but no producer exists in G1 (findings are G2);
this read model never invents one. Asset/provenance endpoints are G1.4b and are not served here.

Authorisation: the operation reads the same campaign data the seven G1.1b campaign operations do,
so it requires the same verified operator bearer token (OD-5): `security: operatorToken` and `401`
are published for `getCampaignFlow` and the route depends on `require_principal`. The actor of a
read is not written anywhere; authentication only decides who may look.
"""

from __future__ import annotations

from typing import Annotated, Any

import psycopg
from fastapi import APIRouter, Depends, Request, Response

from aegis import validation
from aegis.m01_campaign.campaigns import timestamp
from aegis.m26_api.db import connection as db_connection
from aegis.m26_api.errors import INPUT_INVALID, ApiError
from aegis.m26_api.operator import Principal, require_principal
from aegis.m26_api.registry import RouterRegistry
from aegis.m26_api.tracing import TRACEPARENT_HEADER, current_trace_id, traceparent

__all__ = ["FLOW_OPERATIONS", "campaign_flow", "register", "router"]

#: Operations this router implements; the conformance test compares it with the contract.
FLOW_OPERATIONS = ("getCampaignFlow",)

ID_REFERENCE = "common/ids.v2.schema.json#/$defs/Id"
ERROR_401 = {"description": "Lỗi chuẩn (error.v2): thiếu hoặc sai operator token"}
API_PREFIX = "/api/v2"
LABEL_MAX = 200
MORE_TARGETS_MAX = 20

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
        404,
        INPUT_INVALID,
        f"campaign {campaign_id} does not exist",
        next_action="FIX_INPUT",
    )


def _validated(flow: dict[str, Any]) -> dict[str, Any]:
    """A document that does not satisfy the locked response is a server/producer bug, not a 200."""
    validator = validation.openapi_response_validator("/campaigns/{campaign_id}/flow")
    problems = sorted(validator.iter_errors(flow), key=str)
    if problems:
        first = problems[0]
        pointer = "/" + "/".join(str(part) for part in first.absolute_path)
        raise ApiError(
            500,
            "INTERNAL_ERROR",
            f"flow read model violates getCampaignFlow at {pointer or '/'}: {first.message[:300]}",
        )
    return flow


def _label(value: str) -> str:
    return value if len(value) <= LABEL_MAX else value[: LABEL_MAX - 1] + "\u2026"


def _maybe_time(value: Any) -> str | None:
    return None if value is None else timestamp(value)


def _requested_targets(row: dict[str, Any]) -> list[str]:
    """The targets the job was asked for, in the request's own order.

    `scan_job.targets` is the legacy canonical-key projection and may be empty (a seed-only
    TargetRef has no canonical key), so the merged input is the first source: those are the values
    the operator/MCP call named. Only strings are used; a capability that takes structured targets
    is labelled by the capability alone.
    """
    payload = row.get("input")
    requested = payload.get("targets") if isinstance(payload, dict) else None
    if isinstance(requested, list):
        names = [item for item in requested if isinstance(item, str)]
        if names:
            return names
    projected = row.get("targets")
    return [] if not projected else [str(item) for item in projected]


def _target_label(targets: list[str]) -> str:
    """`first_target` plus a `+N` hint: the screen names the tool, not every target."""
    if not targets:
        return ""
    first = targets[0]
    if len(targets) == 1:
        return first
    more = len(targets) - 1
    return f"{first} +{more}" if more <= MORE_TARGETS_MAX else f"{first} +{more}"


def _cancel_intent(row: dict[str, Any]) -> dict[str, Any] | None:
    """job.v2#/$defs/CancelIntent from the 0007 columns (absent until a cancel is requested)."""
    requested_at = row.get("cancel_requested_at")
    if requested_at is None:
        return None
    intent: dict[str, Any] = {
        "requested_at": timestamp(requested_at),
        "requested_by": row["cancel_requested_by"],
    }
    if row.get("cancel_reason") is not None:
        intent["reason"] = row["cancel_reason"]
    return intent


# --------------------------------------------------------------------------- queries

CAMPAIGN_ROW = """
    SELECT campaign_id, name, status, started_at, ended_at
      FROM aegis.campaign
     WHERE campaign_id = %s
"""

SESSION_ROWS = """
    SELECT s.session_id, s.status, s.started_at, s.finished_at, o.text AS objective
      FROM aegis.agent_session s
      LEFT JOIN aegis.objective o ON o.objective_id = s.objective_id
     WHERE s.campaign_id = %s
     ORDER BY s.started_at, s.session_id
"""

DECISION_ROWS = """
    SELECT decision_id, session_id, capability, decision, error, created_at
      FROM aegis.policy_decision
     WHERE campaign_id = %s
     ORDER BY created_at, decision_id
"""

JOB_ROWS = """
    SELECT job_id, decision_id, capability, targets, input, status, attempt, generation,
           wait_reason, cancel_requested_at, cancel_requested_by, cancel_reason,
           error, started_at, finished_at, created_at
      FROM aegis.scan_job
     WHERE campaign_id = %s
     ORDER BY created_at, job_id
"""

DEPENDENCY_ROWS = """
    SELECT job_id, depends_on_job_id
      FROM aegis.job_dependency
     WHERE campaign_id = %s
     ORDER BY job_id, depends_on_job_id
"""

#: A monotonic change token, not a graph revision. Every append that can change a node, a status or
#: an edge of this campaign raises it, so a client can poll it cheaply and re-read only when it
#: moved (job status changes append `job_status_change` rows, M02 dispatch included).
REVISION_ROW = """
    SELECT (SELECT count(*) FROM aegis.campaign_status_change WHERE campaign_id = %(c)s)
         + (SELECT count(*) FROM aegis.scan_job WHERE campaign_id = %(c)s)
         + (SELECT count(*) FROM aegis.policy_decision WHERE campaign_id = %(c)s)
         + (SELECT count(*) FROM aegis.agent_session WHERE campaign_id = %(c)s)
         + (SELECT count(*) FROM aegis.job_dependency WHERE campaign_id = %(c)s)
         + (SELECT count(*) FROM aegis.job_status_change s
              JOIN aegis.scan_job j ON j.job_id = s.job_id
             WHERE j.campaign_id = %(c)s) AS revision
"""


# --------------------------------------------------------------------------- read model


def campaign_flow(connection: psycopg.Connection[Any], campaign_id: str) -> dict[str, Any] | None:
    """The flow document of one campaign, or None when the campaign does not exist."""
    campaign = connection.execute(CAMPAIGN_ROW, (campaign_id,)).fetchone()
    if campaign is None:
        return None

    sessions = connection.execute(SESSION_ROWS, (campaign_id,)).fetchall()
    decisions = connection.execute(DECISION_ROWS, (campaign_id,)).fetchall()
    jobs = connection.execute(JOB_ROWS, (campaign_id,)).fetchall()
    dependencies = connection.execute(DEPENDENCY_ROWS, (campaign_id,)).fetchall()
    revision = connection.execute(REVISION_ROW, {"c": campaign_id}).fetchone()

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    def edge(source: str, target: str, kind: str) -> None:
        edges.append({"from": source, "to": target, "kind": kind})

    campaign_node: dict[str, Any] = {
        "id": str(campaign["campaign_id"]),
        "type": "campaign",
        "status": campaign["status"],
        "label": _label(campaign["name"]),
    }
    started_at = _maybe_time(campaign["started_at"])
    if started_at is not None:
        campaign_node["started_at"] = started_at
    finished_at = _maybe_time(campaign["ended_at"])
    if finished_at is not None:
        campaign_node["finished_at"] = finished_at
    nodes.append(campaign_node)

    session_ids = {str(row["session_id"]) for row in sessions}
    for row in sessions:
        session_id = str(row["session_id"])
        node: dict[str, Any] = {
            "id": session_id,
            "type": "session",
            "status": row["status"],
            "label": _label(f"M03 session: {row['objective']}" if row["objective"] else session_id),
        }
        session_started = _maybe_time(row["started_at"])
        if session_started is not None:
            node["started_at"] = session_started
        session_finished = _maybe_time(row["finished_at"])
        if session_finished is not None:
            node["finished_at"] = session_finished
        nodes.append(node)
        edge(str(campaign["campaign_id"]), session_id, "initiates")

    for row in decisions:
        decision_id = str(row["decision_id"])
        node = {
            "id": decision_id,
            "type": "decision",
            "status": row["decision"],
            "label": _label(f"{row['capability']}: {row['decision']}"),
            "started_at": timestamp(row["created_at"]),
        }
        if row["error"] is not None:
            node["error"] = row["error"]
        nodes.append(node)
        decision_session = None if row["session_id"] is None else str(row["session_id"])
        if decision_session is not None and decision_session in session_ids:
            edge(decision_session, decision_id, "evaluates")
        else:
            # A REST submission has no agent session (job-submit.v2 has no session); the campaign
            # decides on its own. The edge keeps every decision reachable from the root.
            edge(str(campaign["campaign_id"]), decision_id, "initiates")

    job_ids = {str(row["job_id"]) for row in jobs}
    decision_ids = {str(row["decision_id"]) for row in decisions}
    for row in jobs:
        job_id = str(row["job_id"])
        node = {
            "id": job_id,
            "type": "job",
            "status": row["status"],
            "label": _label(
                f"{row['capability']}: {_target_label(_requested_targets(row))}".rstrip(": ")
            ),
            "attempt": row["attempt"],
            "generation": row["generation"],
        }
        if row["wait_reason"] is not None:
            node["wait_reason"] = row["wait_reason"]
        cancel = _cancel_intent(row)
        if cancel is not None:
            node["cancel"] = cancel
        if row["error"] is not None:
            node["error"] = row["error"]
        job_started = _maybe_time(row["started_at"])
        if job_started is not None:
            node["started_at"] = job_started
        job_finished = _maybe_time(row["finished_at"])
        if job_finished is not None:
            node["finished_at"] = job_finished
        nodes.append(node)
        decision_id = str(row["decision_id"])
        if decision_id in decision_ids:
            edge(decision_id, job_id, "dispatches")

    for row in dependencies:
        source, target = str(row["depends_on_job_id"]), str(row["job_id"])
        if source in job_ids and target in job_ids:
            # Direction: predecessor -> successor, the same arrow the screen draws.
            edge(source, target, "depends_on")

    return {
        "revision": int(revision["revision"]) if revision is not None else 0,
        "nodes": nodes,
        "edges": edges,
    }


# --------------------------------------------------------------------------- routes


@router.get(
    "/campaigns/{campaign_id}/flow",
    operation_id="getCampaignFlow",
    summary=(
        "Dữ liệu màn hình luồng quét (React Flow) - phiên agent, quyết định policy, "
        "job và quan hệ cha con"
    ),
    responses={401: ERROR_401},
)
def get_campaign_flow(
    request: Request,
    response: Response,
    campaign_id: str,
    principal: Annotated[Principal, Depends(require_principal)],
    db: Annotated[psycopg.Connection[Any], Depends(db_connection)],
) -> dict[str, Any]:
    """Nodes and edges of one campaign (campaign, session, decision, job) plus a change token."""
    _trace(request, response)
    flow = campaign_flow(db, campaign_id) if _is_id(campaign_id) else None
    if flow is None:
        raise _not_found(campaign_id)
    return _validated(flow)


def register(registry: RouterRegistry, *, prefix: str = "") -> Any:
    """Mount the flow router on the app registry (called by `main.build_registry`)."""
    return registry.register("flow", router, prefix=prefix or API_PREFIX)
