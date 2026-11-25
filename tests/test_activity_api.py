"""`GET /campaigns/{id}/activity`: the agent's timeline over the rows M01/M03/M05 really write.

What this proves, and on which path:

* the campaign is created and started through M01's write path (`create_campaign` +
  `apply_workflow_action`, the two calls the campaign API makes);
* the sessions run the production loop (`aegis.m03_agent.session.run_session` with `build_deps`:
  the PostgreSQL store, ledger and context source) against the real MCP boundary
  (`McpToolService`) on top of the real M05 acceptance path (`PostgresJobService`,
  `PostgresSessionDirectory`, `PostgresCampaignPolicies`, the pinned manifests), one M02 cycle
  label each - the same rows the demo campaign of `make demo-g16c` leaves behind;
* the timeline is compared entry by entry with those rows, rebuilt here from SQL: a field the route
  invents or drops has to disagree.

The denial is a real one: M05 resolves `ip:127.0.0.1`, its deny set refuses the loopback target
(`OUT_OF_SCOPE` / `target_denied`), and M03 keeps the refusal and goes on with the next call. A
target outside the campaign scope never gets that far - it is `INPUT_INVALID` before a decision row
exists (0012), which is why the refusal is a deny-set one.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from collections.abc import Iterator
from contextlib import asynccontextmanager, contextmanager
from typing import Any

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg.rows import dict_row

from aegis import validation
from aegis.contracts_gen.agent.activity_v2_schema import (
    Activity,
    Blocker,
    Budget,
    Decision,
    IdleCycle,
    SessionFinished,
    SessionStarted,
)
from aegis.m01_campaign.campaigns import create_campaign, timestamp
from aegis.m01_campaign.status import apply_workflow_action
from aegis.m03_agent.config import SessionConfig
from aegis.m03_agent.session import build_deps, run_session
from aegis.m04_model.fake import FakeModelClient
from aegis.m05_registry.ids import uuid7
from aegis.m05_registry.mcp.campaign import PostgresCampaignPolicies
from aegis.m05_registry.mcp.graph import UnavailableGraphQueries
from aegis.m05_registry.mcp.service import McpToolService
from aegis.m05_registry.mcp.session import PostgresSessionDirectory
from aegis.m05_registry.registry import PostgresManifestRegistry
from aegis.m05_registry.service import PostgresJobService
from aegis.m05_registry.signing import KeyRing
from aegis.m26_api import activity as activity_module
from aegis.m26_api.app import API_PREFIX, create_app
from aegis.m26_api.operator import TokenAuthenticator
from aegis.m26_api.registry import RouterRegistry
from tests import campaign_support as support
from tests.db_support import (
    OPERATOR,
    SeededCampaign,
    connect,
    migrated_database,
    requires_postgres,
)
from tests.m02_support import complete_job, run_job
from tests.m03_support import (
    ENUMERATE,
    InProcessToolClient,
    decision_response,
    session_request,
    tool_call_response,
)
from tests.m03_support import run as drive
from tests.mcp_support import manifest_bytes
from tests.support import REPO_ROOT
from tests.test_m05_service import service as m05_service

pytestmark = requires_postgres
MODULE_ACTOR = {"kind": "module", "id": "M02"}
#: A loopback address in the campaign's own scope: M05 resolves it and *then* its deny set refuses
#: it (OI-5), which is the only way a refusal reaches `policy_decision` (0012 needs resolved refs).
LOOPBACK = "127.0.0.1"

ACTIVITY_PATH = "/campaigns/{campaign_id}/activity"
SCHEMA = "agent/activity.v2.schema.json"
CONFIG = SessionConfig(model="scripted-test", max_steps=6, in_session_idle_rounds=2)
DISCOVER = "network.discover_services"

#: Text that must never reach the timeline: a rationale (request text the operator/agent wrote) and
#: the model's plan summary. Both are stored in the rows this feed reads alongside.
RATIONALE = "SENTINEL-RATIONALE-do-not-publish-this-request-text"
SUMMARY = "SENTINEL-SUMMARY-do-not-publish-this-model-text"


@pytest.fixture()
def dsn() -> Iterator[str]:
    with migrated_database() as value:
        yield value


def _client(dsn: str) -> TestClient:
    registry = RouterRegistry()
    activity_module.register(registry)
    app = create_app(
        registry,
        operator_authenticator=TokenAuthenticator(support.operator_tokens()),
        database_dsn=dsn,
    )
    return TestClient(app)


def _get(client: TestClient, campaign_id: str, **params: Any) -> Any:
    return client.get(
        f"{API_PREFIX}/campaigns/{campaign_id}/activity", headers=support.auth(), params=params
    )


class FixedBinder:
    """Deterministic resolver: the `ip:` target of the refused call binds its own address."""

    def addresses(self, value: str) -> tuple[str, ...]:
        del value
        return ("198.51.100.10",)


@contextmanager
def boundary(dsn: str) -> Iterator[McpToolService]:
    """The real MCP service over the real M05 acceptance path (the wiring `main.py` builds)."""
    opener = lambda: connect(dsn)  # noqa: E731 - a lambda keeps the opener type simple
    registry = PostgresManifestRegistry(opener)
    for raw in manifest_bytes():
        registry.register(raw, registered_by={"kind": "module", "id": "M05"})
    ring = KeyRing.dev()
    yield McpToolService(
        registry=registry,
        jobs=PostgresJobService(opener, registry=registry, key_ring=ring, binder=FixedBinder()),
        sessions=PostgresSessionDirectory(opener),
        policies=PostgresCampaignPolicies(opener),
        graph=UnavailableGraphQueries(),
    )


def cycle(
    dsn: str,
    tool_service: McpToolService,
    campaign: SeededCampaign,
    responses: list[Any],
    *,
    number: int,
    cursor: int = 0,
) -> Any:
    """One production `run_agent_session` for M02's cycle label `<campaign>:cycle-<n>`."""
    client = InProcessToolClient(tool_service)

    @asynccontextmanager
    async def tools() -> Any:
        try:
            yield client
        finally:
            await client.aclose()

    deps = build_deps(
        config=CONFIG,
        dsn=dsn,
        tools=tools,
        model=FakeModelClient(responses=list(responses)),
    )
    label = f"{campaign.campaign_id}:cycle-{number}"
    return drive(
        run_session(
            session_request(
                campaign_id=campaign.campaign_id, session_id=label, cycle=number, cursor=cursor
            ),
            deps,
        )
    )


def arguments(targets: list[str], rationale: str = "enumerate for the objective") -> dict[str, Any]:
    return {"input": {"targets": targets}, "rationale": rationale}


def submitted_by_operator(dsn: str, campaign: SeededCampaign) -> str:
    """One REST-style submission: M05 with the operator principal and no agent session."""
    from aegis.contracts_gen.capability.job_submit_v2_schema import JobSubmit

    body = JobSubmit.model_validate(
        {
            "campaign_id": campaign.campaign_id,
            "capability": "dns.resolve",
            "input": {"targets": [campaign.seed_domain]},
            "rationale": RATIONALE,
        }
    )
    with m05_service(dsn) as jobs:
        outcome = jobs.submit(body, requested_by=OPERATOR, idempotency_key="activity-rest-submit-1")
    return str(outcome.job["job_id"])


# --------------------------------------------------------------------------- the real campaign


def started_campaign(dsn: str, *, name: str) -> SeededCampaign:
    """M01 create + M02 start through the real write path, with a loopback IP in the scope."""
    body = support.campaign_body(
        name=name,
        targets={
            "domains": ["internal.example"],
            "ips": ["10.20.0.0/24", LOOPBACK],
            "keywords": ["acme corp"],
        },
    )
    with psycopg.connect(dsn, row_factory=dict_row) as conn, conn.transaction():
        created = create_campaign(
            conn, body=body, actor=OPERATOR, trace_id=uuid7().replace("-", "")[:32]
        ).as_response()
        apply_workflow_action(
            conn,
            campaign_id=created["campaign_id"],
            action="start",
            reason="activity read model test campaign",
            actor=MODULE_ACTOR,
            trace_id=uuid7().replace("-", "")[:32],
        )
    return SeededCampaign(
        campaign_id=created["campaign_id"],
        policy_version=created["policy_version"],
        scope_id=created["scope_id"],
        seed_domain="internal.example",
        seed_ip=LOOPBACK,
        known_asset="",
    )


def agent_activity(dsn: str) -> tuple[SeededCampaign, dict[str, str]]:
    """A campaign whose sessions, decisions, jobs and ledger come from the production path.

    Three M02 cycles, the order the workflow runs them in:

    0. one call M05 refuses on the deny set (loopback), one it accepts (the job), then the loop
       hands back to the workflow because a job is in flight;
    1. after the job succeeded, the planner reports the objective met -> `stop`/`objective_met`;
    2. nothing new to look at -> `wait` with no job, the idle cycle M02 pauses on.
    """
    campaign = started_campaign(dsn, name="activity read model")
    sessions: dict[str, str] = {"rest_job": submitted_by_operator(dsn, campaign)}
    with boundary(dsn) as tool_service:
        first = cycle(
            dsn,
            tool_service,
            campaign,
            [
                tool_call_response(
                    DISCOVER,
                    {
                        "input": {"targets": [f"ip:{LOOPBACK}"], "ports": [443]},
                        "rationale": RATIONALE,
                    },
                ),
                tool_call_response(ENUMERATE, arguments([campaign.seed_domain])),
            ],
            number=0,
        )
        sessions["proposed"] = str(first.ref.session_id)
        assert len(first.outcome.job_ids) == 1, "the accepted call produced the job"
        job_id = first.outcome.job_ids[0]
        run_job(dsn, job_id)
        assert complete_job(dsn, job_id, "SUCCEEDED") == "terminalized"
        sessions["job"] = job_id

        stopped = cycle(
            dsn,
            tool_service,
            campaign,
            [decision_response("stop", SUMMARY)],
            number=1,
            cursor=first.outcome.cursor,
        )
        sessions["stopped"] = str(stopped.ref.session_id)
        assert stopped.outcome.stop_reason == "objective_met"

        idle = cycle(
            dsn,
            tool_service,
            campaign,
            [decision_response("wait", SUMMARY)],
            number=2,
            cursor=stopped.outcome.cursor,
        )
        sessions["idle"] = str(idle.ref.session_id)
        assert idle.outcome.idle is True
    return campaign, sessions


# --------------------------------------------------------------------------- the DB rows


def _rows(dsn: str, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        conn.execute("SET search_path = aegis, public")
        return [dict(row) for row in conn.execute(sql, params).fetchall()]


def expected_timeline(dsn: str, campaign_id: str) -> list[dict[str, Any]]:
    """The same page rebuilt from SQL, in the contract's shape and order (newest first).

    Written out per source instead of reusing the route's builders: a field the route invents or
    drops has to disagree here. The sort key is the row's own timestamp, not its text form.
    """
    keyed: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    for row in _rows(
        dsn,
        "SELECT session_id, objective_id, policy_version, revision_from, status, decision,"
        " stop_reason, steps_used, started_at, finished_at FROM agent_session"
        " WHERE campaign_id = %s",
        (campaign_id,),
    ):
        session_id = str(row["session_id"])
        started: dict[str, Any] = {
            "kind": "session_started",
            "entry_id": f"session:{session_id}:start",
            "at": timestamp(row["started_at"]),
            "session_id": session_id,
            "policy_version": row["policy_version"],
            "revision_from": int(row["revision_from"]),
        }
        if row["objective_id"] is not None:
            started["objective_id"] = str(row["objective_id"])
        keyed.append(((row["started_at"], "session_started", started["entry_id"]), started))
        if row["finished_at"] is not None:
            finished: dict[str, Any] = {
                "kind": "session_finished",
                "entry_id": f"session:{session_id}:finish",
                "at": timestamp(row["finished_at"]),
                "session_id": session_id,
                "status": row["status"],
                "decision": row["decision"],
                "steps_used": int(row["steps_used"]),
            }
            if row["stop_reason"] is not None:
                finished["stop_reason"] = row["stop_reason"]
            keyed.append(((row["finished_at"], "session_finished", finished["entry_id"]), finished))
    for row in _rows(
        dsn,
        "SELECT d.decision_id, d.capability, d.provider, d.decision, d.rule, d.error,"
        " d.target_refs, d.requested_by, d.proposed_by, d.policy_version, d.created_at, j.job_id"
        " FROM policy_decision d LEFT JOIN scan_job j ON j.decision_id = d.decision_id"
        " WHERE d.campaign_id = %s",
        (campaign_id,),
    ):
        decision: dict[str, Any] = {
            "kind": "decision",
            "entry_id": f"decision:{row['decision_id']}",
            "at": timestamp(row["created_at"]),
            "decision_id": str(row["decision_id"]),
            "capability": row["capability"],
            "decision": row["decision"],
            "targets": list(row["target_refs"]),
            "requested_by": dict(row["requested_by"]),
            "policy_version": row["policy_version"],
        }
        if row["provider"] is not None:
            decision["provider"] = row["provider"]
        if row["job_id"] is not None:
            decision["job_id"] = str(row["job_id"])
        if row["proposed_by"] is not None:
            decision["proposed_by"] = dict(row["proposed_by"])
        if row["decision"] == "denied":
            reason: dict[str, Any] = {"code": row["error"]["code"]}
            if row["rule"] is not None:
                reason["rule"] = row["rule"]
            decision["reason"] = reason
        keyed.append(((row["created_at"], "decision", decision["entry_id"]), decision))
    for row in _rows(
        dsn,
        "SELECT seq, kind, payload, created_at FROM campaign_ledger"
        " WHERE campaign_id = %s AND kind IN ('idle_cycle', 'blocker', 'budget')",
        (campaign_id,),
    ):
        payload = row["payload"]
        entry: dict[str, Any] = {
            "kind": row["kind"],
            "entry_id": f"ledger:{row['seq']}",
            "at": timestamp(row["created_at"]),
        }
        if payload.get("session_id") is not None:
            entry["session_id"] = str(payload["session_id"])
        if row["kind"] == "idle_cycle":
            if payload.get("cycle") is not None:
                entry["cycle"] = int(payload["cycle"])
        elif row["kind"] == "blocker":
            entry["code"] = payload["code"]
            if payload.get("context") is not None:
                entry["context"] = payload["context"]
        else:
            entry["sent_tokens"] = int(payload["sent_tokens"])
            entry["sent_cost_usd"] = float(payload["sent_cost_usd"])
            if payload.get("remaining_tokens") is not None:
                entry["remaining_tokens"] = int(payload["remaining_tokens"])
            if payload.get("remaining_cost_usd") is not None:
                entry["remaining_cost_usd"] = float(payload["remaining_cost_usd"])
            if payload.get("models"):
                entry["models"] = list(payload["models"])
        keyed.append(((row["created_at"], row["kind"], entry["entry_id"]), entry))
    keyed.sort(key=lambda item: item[0], reverse=True)
    return [entry for _key, entry in keyed]


def seed_target_id(dsn: str, campaign: SeededCampaign, raw_value: str | None = None) -> str:
    """The `campaign_target` row M01 wrote for one seed; a raw value is what TargetRef names."""
    rows = _rows(
        dsn,
        "SELECT target_id::text FROM campaign_target WHERE scope_id = %s AND raw_value = %s",
        (campaign.scope_id, raw_value if raw_value is not None else campaign.seed_domain),
    )
    assert len(rows) == 1
    return str(rows[0]["target_id"])


# --------------------------------------------------------------------------- the timeline


def test_the_timeline_is_the_rows_the_agent_and_policy_wrote(dsn: str) -> None:
    campaign, sessions = agent_activity(dsn)
    response = _get(_client(dsn), campaign.campaign_id)
    assert response.status_code == 200, response.text
    document = response.json()

    # Every entry equals its row, in the row's own order: nothing is invented and nothing is lost.
    assert document["items"] == expected_timeline(dsn, campaign.campaign_id)
    # The page is the whole history of this campaign, so the client must not think it was cut.
    assert document["truncated"] is False and "next_cursor" not in document
    validation.validate(SCHEMA, document)

    by_kind: dict[str, list[dict[str, Any]]] = {}
    for entry in document["items"]:
        by_kind.setdefault(entry["kind"], []).append(entry)

    # A tool call M05 refused: the reason is the decision's own error code and rule, with no job.
    denied = [entry for entry in by_kind["decision"] if entry["decision"] == "denied"]
    assert len(denied) == 1
    refusal = denied[0]
    assert refusal["capability"] == DISCOVER
    assert refusal["reason"] == {"code": "OUT_OF_SCOPE", "rule": "target_denied"}
    assert "job_id" not in refusal
    assert refusal["proposed_by"] == {"kind": "agent", "id": sessions["proposed"]}
    assert refusal["requested_by"] == {"kind": "module", "id": "M02"}
    assert refusal["targets"] == [{"seed_id": seed_target_id(dsn, campaign, LOOPBACK)}]

    # A tool call M05 approved: the job it produced is linked, and the proposer is the session.
    approved = [entry for entry in by_kind["decision"] if entry["decision"] == "approved"]
    assert len(approved) == 2, "one proposed by the agent session, one submitted by the operator"
    agent_job = next(entry for entry in approved if "proposed_by" in entry)
    assert agent_job["provider"] == "subfinder"
    assert agent_job["job_id"] == sessions["job"]
    assert agent_job["targets"] == [{"seed_id": seed_target_id(dsn, campaign)}]
    assert all("reason" not in entry for entry in approved)
    # ... and one submitted directly by the operator, which has no proposer to invent.
    operator_job = next(entry for entry in approved if "proposed_by" not in entry)
    assert operator_job["requested_by"] == OPERATOR
    assert operator_job["job_id"] == sessions["rest_job"]
    assert operator_job["capability"] == "dns.resolve"

    # Sessions: the start/stop pair, with the stop reason M03 recorded.
    finished = {entry["session_id"]: entry for entry in by_kind["session_finished"]}
    assert set(finished) == {sessions["proposed"], sessions["stopped"], sessions["idle"]}
    assert finished[sessions["proposed"]]["decision"] == "wait"
    assert "stop_reason" not in finished[sessions["proposed"]]
    assert finished[sessions["stopped"]]["status"] == "SUCCEEDED"
    assert finished[sessions["stopped"]]["decision"] == "stop"
    assert finished[sessions["stopped"]]["stop_reason"] == "objective_met"
    assert finished[sessions["idle"]]["decision"] == "wait"
    assert "stop_reason" not in finished[sessions["idle"]]
    assert {entry["session_id"] for entry in by_kind["session_started"]} == set(finished)

    # The idle cycle M02 pauses on, the blocker every session recorded, and the budget snapshot.
    assert {entry["session_id"] for entry in by_kind["idle_cycle"]} == {sessions["idle"]}
    assert {entry["code"] for entry in by_kind["blocker"]} == {"DEPENDENCY_MISSING"}
    assert {entry["context"] for entry in by_kind["blocker"]} == {"context graph"}
    budgets = {entry["session_id"]: entry for entry in by_kind["budget"]}
    assert set(budgets) == set(finished)
    assert budgets[sessions["stopped"]]["sent_tokens"] > 0
    assert budgets[sessions["stopped"]]["models"] == ["scripted-test"]
    assert budgets[sessions["stopped"]]["sent_cost_usd"] > 0
    # The RoE's cost ceiling is set and the token ceiling is not: one is present, one is absent -
    # never a 0 that would claim an exhausted budget.
    assert "remaining_cost_usd" in budgets[sessions["stopped"]]
    assert "remaining_tokens" not in budgets[sessions["stopped"]]


def test_the_feed_publishes_only_the_ledger_kinds_it_owns(dsn: str) -> None:
    """`cursor` and `stop_condition` are M03's bookkeeping, not two more timeline entries."""
    campaign, sessions = agent_activity(dsn)
    with connect(dsn) as conn:
        rows = conn.execute(
            "SELECT seq, kind FROM campaign_ledger WHERE campaign_id = %s ORDER BY seq",
            (campaign.campaign_id,),
        ).fetchall()
    written = {str(row[1]) for row in rows}
    assert {"cursor", "stop_condition", "cycle_started", "cycle_finished"} <= written
    hidden = {f"ledger:{row[0]}" for row in rows if str(row[1]) in {"cursor", "stop_condition"}}
    assert hidden, "the real path writes these kinds"

    document = _get(_client(dsn), campaign.campaign_id).json()
    published = {entry["entry_id"] for entry in document["items"]}
    assert published.isdisjoint(hidden)
    assert {entry["kind"] for entry in document["items"]} == {
        "session_started",
        "session_finished",
        "decision",
        "idle_cycle",
        "blocker",
        "budget",
    }
    # The stop reason is on the session, which is where the contract puts it.
    stopped = next(
        entry
        for entry in document["items"]
        if entry["kind"] == "session_finished" and entry["session_id"] == sessions["stopped"]
    )
    assert stopped["stop_reason"] == "objective_met"


# --------------------------------------------------------------------------- pagination


def test_pagination_walks_the_same_timeline_one_page_at_a_time(dsn: str) -> None:
    campaign, _sessions = agent_activity(dsn)
    client = _client(dsn)
    whole = _get(client, campaign.campaign_id).json()
    assert len(whole["items"]) >= 8, "the fixture campaign has several entries per source"

    collected: list[dict[str, Any]] = []
    cursor: str | None = None
    pages = 0
    while True:
        params: dict[str, Any] = {"limit": 3}
        if cursor is not None:
            params["cursor"] = cursor
        page = _get(client, campaign.campaign_id, **params)
        assert page.status_code == 200, page.text
        body = page.json()
        assert len(body["items"]) <= 3
        pages += 1
        collected.extend(body["items"])
        if "next_cursor" in body:
            # An explicit flag for a screen that must not believe it saw everything.
            assert body["truncated"] is True
            assert body["next_cursor"] != cursor
            cursor = body["next_cursor"]
            continue
        assert body["truncated"] is False
        break

    assert pages >= 3
    assert collected == whole["items"]
    assert len({entry["entry_id"] for entry in collected}) == len(collected)


def test_a_cursor_from_another_campaign_is_refused(dsn: str) -> None:
    first, _sessions = agent_activity(dsn)
    second = started_campaign(dsn, name="activity cursor scope")
    page = _get(_client(dsn), first.campaign_id, limit=1).json()
    cursor = page["next_cursor"]

    refused = _get(_client(dsn), second.campaign_id, cursor=cursor)
    assert refused.status_code == 400, refused.text
    assert refused.json()["code"] == "INPUT_INVALID"
    assert refused.json()["field"] == "/cursor"


def test_a_malformed_cursor_is_an_error_v2_400(dsn: str) -> None:
    campaign = started_campaign(dsn, name="activity bad cursor")
    response = _get(_client(dsn), campaign.campaign_id, cursor="not-a-cursor")
    assert response.status_code == 400, response.text
    body = response.json()
    assert body["code"] == "INPUT_INVALID" and body["field"] == "/cursor"
    assert body["next_action"] == "FIX_INPUT" and body["trace_id"]


# --------------------------------------------------------------------------- errors


def test_the_read_needs_the_operator_token(dsn: str) -> None:
    campaign = started_campaign(dsn, name="activity auth")
    client = _client(dsn)
    path = f"{API_PREFIX}/campaigns/{campaign.campaign_id}/activity"
    anonymous = client.get(path)
    assert anonymous.status_code == 401, anonymous.text
    assert anonymous.json()["code"] == "INPUT_INVALID"
    wrong = client.get(path, headers={"authorization": "Bearer not-an-operator-token"})
    assert wrong.status_code == 401, wrong.text
    assert wrong.json()["trace_id"]


def test_an_unknown_or_malformed_campaign_is_a_404(dsn: str) -> None:
    client = _client(dsn)
    missing = _get(client, "01900000-0000-7000-8000-00000000dead")
    assert missing.status_code == 404, missing.text
    assert missing.json()["code"] == "INPUT_INVALID"
    malformed = _get(client, "not-an-id")
    assert malformed.status_code == 404, malformed.text
    assert malformed.json()["trace_id"]


def test_a_limit_outside_the_contract_is_an_error_v2_400(dsn: str) -> None:
    campaign = started_campaign(dsn, name="activity limit")
    response = _get(_client(dsn), campaign.campaign_id, limit=0)
    assert response.status_code == 400, response.text
    assert response.json()["code"] == "INPUT_INVALID"
    assert _get(_client(dsn), campaign.campaign_id, limit=201).status_code == 400


def test_a_producer_row_the_contract_refuses_is_a_500_not_an_invalid_200(dsn: str) -> None:
    campaign, _sessions = agent_activity(dsn)
    # The ledger is append-only, so the producer bug is an append: a blocker the schema requires a
    # `code` for, written without one.
    with connect(dsn) as conn, conn.transaction():
        inserted = conn.execute(
            "INSERT INTO campaign_ledger (campaign_id, seq, kind, payload)"
            " SELECT %s, coalesce(max(seq), 0) + 1, 'blocker', '{}'::jsonb"
            "   FROM campaign_ledger WHERE campaign_id = %s RETURNING seq",
            (campaign.campaign_id, campaign.campaign_id),
        ).fetchone()
    assert inserted is not None
    seq = int(inserted[0])
    response = _get(_client(dsn), campaign.campaign_id)
    assert response.status_code == 500, response.text
    body = response.json()
    assert body["code"] == "INTERNAL_ERROR"
    # The message names the contract rule, the pointer and the offending entry: a producer bug a
    # reader can find, instead of an invalid 200 the screen would render as data.
    assert "getCampaignActivity" in body["message"]
    assert "/items/0" in body["message"] and f"ledger:{seq}" in body["message"]


# --------------------------------------------------------------------------- privacy


PUBLISHED_FIELDS = {
    "kind",
    "entry_id",
    "at",
    "session_id",
    "objective_id",
    "policy_version",
    "revision_from",
    "status",
    "decision",
    "stop_reason",
    "steps_used",
    "decision_id",
    "capability",
    "provider",
    "reason",
    "targets",
    "job_id",
    "requested_by",
    "proposed_by",
    "cycle",
    "code",
    "context",
    "sent_tokens",
    "sent_cost_usd",
    "remaining_tokens",
    "remaining_cost_usd",
    "models",
}


def test_no_prompt_model_text_or_secret_reaches_the_timeline(dsn: str) -> None:
    campaign, _sessions = agent_activity(dsn)
    client = _client(dsn)
    collected: list[dict[str, Any]] = []
    cursor: str | None = None
    while True:
        params: dict[str, Any] = {"limit": 3}
        if cursor is not None:
            params["cursor"] = cursor
        body = _get(client, campaign.campaign_id, **params).json()
        collected.extend(body["items"])
        if "next_cursor" not in body:
            break
        cursor = body["next_cursor"]

    with connect(dsn) as conn:
        stored = [
            str(row[0])
            for row in conn.execute(
                "SELECT rationale FROM policy_decision WHERE campaign_id = %s",
                (campaign.campaign_id,),
            ).fetchall()
        ]
        summaries = conn.execute(
            "SELECT count(*) FROM campaign_ledger WHERE campaign_id = %s AND payload::text LIKE %s",
            (campaign.campaign_id, f"%{SUMMARY}%"),
        ).fetchone()
    assert RATIONALE in stored, "the sensitive text really is in the rows this feed reads"
    assert summaries is not None and int(summaries[0]) >= 1, "the model summary is stored too"

    text = json.dumps(collected, ensure_ascii=False)
    for sentinel in (RATIONALE, SUMMARY, "SENTINEL"):
        assert sentinel not in text
    for token in support.OPERATORS.values():
        assert token not in text
    # No free-text field survives at all: only the names the contract publishes.
    for entry in collected:
        assert set(entry) <= PUBLISHED_FIELDS, entry["entry_id"]
        assert {"rationale", "input", "detail", "summary"}.isdisjoint(entry)


# --------------------------------------------------------------------------- generated DTO


def test_the_generated_dto_parses_every_kind_of_the_timeline(dsn: str) -> None:
    """The codegen tree is load-bearing: the published body is what `make codegen` typed."""
    campaign, _sessions = agent_activity(dsn)
    document = _get(_client(dsn), campaign.campaign_id).json()
    timeline = Activity.model_validate(document)
    kinds = {type(item.root) for item in timeline.items}
    assert {
        SessionStarted,
        SessionFinished,
        Decision,
        IdleCycle,
        Blocker,
        Budget,
    } <= kinds
    assert timeline.truncated is False and timeline.next_cursor is None


# --------------------------------------------------------------------------- the demo gate


def _demo_module() -> Any:
    """`scripts/demo/demo-g16c.py` as a module: its activity check is the operator's gate."""
    demo = REPO_ROOT / "scripts/demo/demo-g16c.py"
    if str(demo.parent) not in sys.path:
        sys.path.insert(0, str(demo.parent))
    spec = importlib.util.spec_from_file_location("demo_g16c_activity", demo)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_demo_gate_compares_the_feed_with_the_rows(
    dsn: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`make demo-g16c` step 2b: the check the operator runs must work before it is run there.

    The stack is the only thing left out: the demo's HTTP call goes through the app under test and
    everything else (SQL, pagination walk, assertions) is the code the gate runs.
    """
    campaign, sessions = agent_activity(dsn)
    module = _demo_module()
    client = _client(dsn)
    token = support.OPERATORS["op-soc-1"]

    def fake_api(method: str, path: str, **kwargs: Any) -> Any:
        assert kwargs.get("token") == token
        response = client.request(method, path, headers={"authorization": f"Bearer {token}"})
        assert response.status_code < 400, response.text
        return response.json()

    monkeypatch.setattr(module.support, "api", fake_api)
    monkeypatch.setattr(module.support, "operator_token", lambda: token)
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as conn:
        conn.execute("SET search_path = aegis, public")
        result = module._activity(conn, campaign.campaign_id)

    assert result["entries"] == len(_get(client, campaign.campaign_id).json()["items"])
    assert result["pages"] >= 1
    assert result["kinds"]["decision"] == 3
    assert result["kinds"]["session_started"] == 3
    assert result["kinds"]["idle_cycle"] == 1
    assert result["approved_jobs"] == 2
    approved_jobs = {
        entry["job_id"]
        for entry in _get(client, campaign.campaign_id).json()["items"]
        if entry["kind"] == "decision" and "job_id" in entry
    }
    assert sessions["job"] in approved_jobs and sessions["rest_job"] in approved_jobs
