"""M03 on PostgreSQL and on the wire: the agent_session authority, the checkpoint and recovery.

The loop's own acceptance is in `test_m03_loop.py` (in-memory ports); this module proves the parts
that only a database and a real HTTP server can show:

* the `agent_session` row M03 creates is what makes a `tools/call` legal for the MCP server
  (`PostgresSessionDirectory` refuses anything else);
* the LangGraph checkpoint lives in the `langgraph` schema keyed by that session id, so a retried
  activity call resumes instead of replaying;
* a lost MCP answer still yields exactly one job (the idempotency key), and a crash after the last
  node records the result without replaying the session;
* the finished row holds the contract `session-result.v2` and only MCP job ids;
* the SDK client reaches the real Streamable HTTP server from inside a session;
* `budget.max_agent_sessions` refuses another cycle.

They need `AEGIS_TEST_PG_DSN` (the gate provides a throwaway PostgreSQL 16); without it they skip,
and `AEGIS_NO_SKIPS=1` fails the gate if one is skipped.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import asynccontextmanager, contextmanager
from typing import Any

import pytest
from mcp.shared.exceptions import MCPError

from aegis import validation
from aegis.m03_agent import fake_policy  # noqa: F401 - the module must import without a DB
from aegis.m03_agent.config import SessionConfig
from aegis.m03_agent.mcp import McpToolClient
from aegis.m03_agent.session import SessionDeps, build_deps, run_session
from aegis.m03_agent.store import SessionRefused
from aegis.m04_model.fake import FakeModelClient
from aegis.m05_registry.mcp.service import McpToolService
from aegis.m05_registry.mcp.session import PostgresSessionDirectory
from aegis.m05_registry.service import TERMINAL_STATUSES
from tests.db_support import (
    SeededCampaign,
    connect,
    migrated_database,
    policy_document,
    requires_postgres,
    seed_campaign,
)
from tests.m03_support import (
    ENUMERATE,
    InProcessToolClient,
    decision_response,
    job_store,
    run,
    service,
    session_request,
    tool_call_response,
)
from tests.mcp_support import serve

pytestmark = requires_postgres

CONFIG = SessionConfig(model="scripted-test", max_steps=6, in_session_idle_rounds=2)
SESSION_SCHEMA = "agent/session-result.v2.schema.json"


def arguments(targets: list[str] | None = None) -> dict[str, Any]:
    return {
        "input": {"targets": targets or ["internal.example"]},
        "rationale": "Enumerate the lab domain's subdomains for the campaign objective",
    }


@contextmanager
def campaign_context(policy: dict[str, Any] | None = None) -> Iterator[tuple[str, SeededCampaign]]:
    with migrated_database() as dsn:
        seeded = seed_campaign(dsn, policy=policy)
        yield dsn, seeded


def m05_connect(dsn: str) -> Any:
    """M05 reads rows by position; M03's own connections use `dict_row` (never shared)."""
    import psycopg

    conn = psycopg.connect(dsn, autocommit=True)
    conn.execute("SET search_path = aegis, public")
    return conn


def pg_service(dsn: str) -> McpToolService:
    """The real MCP boundary with the PostgreSQL session authority and an in-memory job store."""
    return service(sessions=PostgresSessionDirectory(lambda: m05_connect(dsn)))


def deps_with(
    dsn: str,
    service_: McpToolService,
    *,
    responses: list[Any],
    client: InProcessToolClient | None = None,
) -> tuple[SessionDeps, InProcessToolClient]:
    tool_client = client or InProcessToolClient(service_)

    @asynccontextmanager
    async def _open() -> Any:
        try:
            yield tool_client
        finally:
            await tool_client.aclose()

    deps = build_deps(
        config=CONFIG,
        dsn=dsn,
        tools=_open,
        model=FakeModelClient(responses=list(responses)),
    )
    return deps, tool_client


def scalar(dsn: str, query: str, params: tuple[Any, ...] = ()) -> Any:
    with connect(dsn) as conn:
        row = conn.execute(query, params).fetchone()
    return None if row is None else row[0]


def test_the_agent_session_row_authorises_the_mcp_call() -> None:
    with campaign_context() as (dsn, seeded):
        service_ = pg_service(dsn)
        deps, client = deps_with(
            dsn,
            service_,
            responses=[tool_call_response(ENUMERATE, arguments())],
        )

        session = run(run_session(session_request(campaign_id=seeded.campaign_id), deps))

        assert len(client.calls) == 1
        assert len(session.outcome.job_ids) == 1
        job = next(iter(job_store(service_).jobs.values()))
        assert job["proposed_by"] == {"kind": "agent", "id": session.ref.session_id}
        # the server refuses a session id that has no RUNNING agent_session row
        with pytest.raises(MCPError) as caught:
            service_.call(
                tool_name=ENUMERATE,
                arguments=arguments(),
                request_meta={
                    "aegis.io/trace_id": "0123456789abcdef0123456789abcdef",
                    "aegis.io/campaign_id": seeded.campaign_id,
                    "aegis.io/session_id": "01934f6a-0000-7000-8000-0000000000ff",
                    "aegis.io/idempotency_key": "unknown-session:step:1",
                },
                mcp_session_id=None,
            )
        assert caught.value.data["code"] == "INPUT_INVALID"
        assert len(job_store(service_).jobs) == 1


def test_the_session_row_holds_the_contract_result_and_only_mcp_job_ids() -> None:
    with campaign_context() as (dsn, seeded):
        service_ = pg_service(dsn)
        deps, _client = deps_with(
            dsn,
            service_,
            responses=[tool_call_response(ENUMERATE, arguments())],
        )

        session = run(run_session(session_request(campaign_id=seeded.campaign_id), deps))

        with connect(dsn) as conn:
            row = conn.execute(
                "SELECT status, decision, stop_reason, steps_used, result, objective_id, "
                "revision_from, finished_at FROM agent_session WHERE session_id = %s",
                (session.ref.session_id,),
            ).fetchone()
        assert row is not None
        status, decision, stop_reason, steps_used, result, objective_id, revision_from, finished = (
            row
        )
        assert status == "SUCCEEDED"
        assert decision == "wait"
        assert stop_reason is None
        assert steps_used == 1
        assert finished is not None
        assert revision_from == 0
        validation.validate(SESSION_SCHEMA, result)
        assert result["requested_jobs"] == list(session.outcome.job_ids)
        assert all(job_id in job_store(service_).jobs for job_id in result["requested_jobs"])
        # the objective row M03 created is the session's objective (the MCP server checks it)
        with connect(dsn) as conn:
            objective = conn.execute(
                "SELECT campaign_id, text, created_by FROM objective WHERE objective_id = %s",
                (objective_id,),
            ).fetchone()
        assert objective is not None
        assert str(objective[0]) == seeded.campaign_id
        assert objective[2] == {"kind": "module", "id": "M03"}
        # the ledger keeps the session link and its budget/provenance entries
        kinds = [
            row[0]
            for row in _rows(
                dsn,
                "SELECT kind FROM campaign_ledger WHERE campaign_id = %s ORDER BY seq",
                (seeded.campaign_id,),
            )
        ]
        assert kinds.count("cycle_started") == 1
        assert kinds.count("cycle_finished") == 1
        assert "cursor" in kinds
        assert "budget" in kinds


def test_the_checkpoint_lives_in_the_langgraph_schema_keyed_by_session_id() -> None:
    with campaign_context() as (dsn, seeded):
        service_ = pg_service(dsn)
        deps, _client = deps_with(
            dsn,
            service_,
            responses=[tool_call_response(ENUMERATE, arguments())],
        )

        session = run(run_session(session_request(campaign_id=seeded.campaign_id), deps))

        tables = [
            row[0]
            for row in _rows(
                dsn,
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'langgraph'",
            )
        ]
        assert "checkpoints" in tables
        with connect(dsn) as conn:
            row = conn.execute(
                "SELECT count(*) FROM langgraph.checkpoints WHERE thread_id = %s",
                (session.ref.session_id,),
            ).fetchone()
        assert row is not None and int(row[0]) >= 1  # one checkpoint per completed node


def test_a_lost_mcp_answer_does_not_create_a_second_job() -> None:
    with campaign_context() as (dsn, seeded):
        service_ = pg_service(dsn)
        crashing = InProcessToolClient(service_, fail_after_call=1)
        deps, client = deps_with(
            dsn,
            service_,
            responses=[tool_call_response(ENUMERATE, arguments())],
            client=crashing,
        )

        with pytest.raises(RuntimeError):
            run(run_session(session_request(campaign_id=seeded.campaign_id), deps))
        # the server accepted the job before the answer was lost
        assert len(job_store(service_).jobs) == 1
        assert scalar(dsn, "SELECT count(*) FROM agent_session") == 1

        # the activity retry resumes at the dispatch node and replays the same idempotency key
        resumed_deps, resumed_client = deps_with(
            dsn,
            service_,
            responses=[tool_call_response(ENUMERATE, arguments())],
            client=InProcessToolClient(service_),
        )
        session = run(run_session(session_request(campaign_id=seeded.campaign_id), resumed_deps))

        assert session.resumed is True
        assert len(resumed_client.calls) == 1  # one replay call, and M05 answered `duplicate`
        assert len(job_store(service_).jobs) == 1  # still one job
        assert session.result is not None
        assert session.result["requested_jobs"] == [next(iter(job_store(service_).jobs))]


def test_a_crash_after_the_last_node_records_the_result_without_replaying() -> None:
    with campaign_context() as (dsn, seeded):
        service_ = pg_service(dsn)
        crashing = InProcessToolClient(service_, fail_on_close=True)
        deps, _client = deps_with(
            dsn,
            service_,
            responses=[tool_call_response(ENUMERATE, arguments())],
            client=crashing,
        )

        with pytest.raises(RuntimeError):
            run(run_session(session_request(campaign_id=seeded.campaign_id), deps))
        # the graph reached its last node; only the result write was lost
        assert len(job_store(service_).jobs) == 1

        resumed_deps, resumed_client = deps_with(
            dsn,
            service_,
            responses=[tool_call_response(ENUMERATE, arguments())],
            client=InProcessToolClient(service_),
        )
        session = run(run_session(session_request(campaign_id=seeded.campaign_id), resumed_deps))

        assert session.resumed is True
        assert resumed_client.calls == []  # no node was replayed, so nothing was dispatched
        assert len(job_store(service_).jobs) == 1
        assert scalar(dsn, "SELECT count(*) FROM agent_session") == 1
        assert scalar(dsn, "SELECT count(*) FROM agent_session WHERE status = 'SUCCEEDED'") == 1


def test_a_retried_activity_call_returns_the_recorded_outcome() -> None:
    with campaign_context() as (dsn, seeded):
        service_ = pg_service(dsn)
        deps, client = deps_with(
            dsn,
            service_,
            responses=[tool_call_response(ENUMERATE, arguments())],
        )
        first = run(run_session(session_request(campaign_id=seeded.campaign_id), deps))

        second_deps, second_client = deps_with(
            dsn,
            service_,
            responses=[tool_call_response(ENUMERATE, arguments())],
            client=InProcessToolClient(service_),
        )
        second = run(run_session(session_request(campaign_id=seeded.campaign_id), second_deps))

        assert len(client.calls) == 1
        assert second_client.calls == []
        assert second.resumed is True
        assert second.outcome.job_ids == first.outcome.job_ids
        assert scalar(dsn, "SELECT count(*) FROM agent_session") == 1  # one row per cycle label
        assert scalar(dsn, "SELECT count(*) FROM objective") == 1  # one objective for the campaign


def test_the_max_agent_sessions_budget_refuses_another_cycle() -> None:
    policy = policy_document(
        budget={
            "max_jobs": 50,
            "max_llm_tokens": 100000,
            "max_llm_cost_usd": 5,
            "max_agent_sessions": 1,
        }
    )
    with campaign_context(policy=policy) as (dsn, seeded):
        service_ = pg_service(dsn)
        deps, _client = deps_with(
            dsn,
            service_,
            responses=[tool_call_response(ENUMERATE, arguments())],
        )
        run(run_session(session_request(campaign_id=seeded.campaign_id), deps))

        second_deps, _second_client = deps_with(
            dsn,
            service_,
            responses=[decision_response("wait", "second cycle")],
            client=InProcessToolClient(service_),
        )
        with pytest.raises(SessionRefused) as caught:
            run(
                run_session(
                    session_request(
                        campaign_id=seeded.campaign_id,
                        cycle=1,
                        session_id=(f"{seeded.campaign_id}:cycle-1"),
                    ),
                    second_deps,
                )
            )

    assert "max_agent_sessions" in str(caught.value)
    # M02 terminalises the campaign from this code (D4, item 61 trial); the message is for people.
    assert caught.value.code == SessionRefused.BUDGET_EXHAUSTED


def test_the_sdk_client_reaches_the_real_mcp_server_from_inside_a_session() -> None:

    with campaign_context() as (dsn, seeded):
        service_ = pg_service(dsn)
        held: dict[str, McpToolClient] = {}

        def factory() -> Any:
            @asynccontextmanager
            async def _open() -> Any:
                async with serve(service_) as url:
                    client = McpToolClient(url)
                    await client.connect()
                    held["url"] = client  # keep a handle for the assertion below
                    try:
                        yield client
                    finally:
                        await client.aclose()

            return _open()

        deps = build_deps(
            config=CONFIG,
            dsn=dsn,
            tools=factory,
            model=FakeModelClient(responses=[tool_call_response(ENUMERATE, arguments())]),
        )

        session = run(run_session(session_request(campaign_id=seeded.campaign_id), deps))

        assert len(session.outcome.job_ids) == 1
        assert len(job_store(service_).jobs) == 1
        job = next(iter(job_store(service_).jobs.values()))
        assert job["proposed_by"] == {"kind": "agent", "id": session.ref.session_id}
        assert held  # the client was connected across the whole session


def test_the_catalogue_is_the_session_filtered_one() -> None:
    """The policy denylist of the campaign hides a capability from this session's tools/list."""
    with campaign_context() as (dsn, seeded):
        service_ = service(
            sessions=PostgresSessionDirectory(lambda: m05_connect(dsn)),
            denylists={seeded.campaign_id: frozenset({ENUMERATE})},
        )
        deps, client = deps_with(
            dsn,
            service_,
            responses=[
                # the model asks for the denied capability: not published, so M03 refuses it
                tool_call_response(ENUMERATE, arguments()),
                decision_response("wait", "the denylist hides the enumeration capability"),
            ],
        )

        session = run(run_session(session_request(campaign_id=seeded.campaign_id), deps))

    assert client.calls == []
    assert session.result is not None
    assert session.result["denied"][0]["capability"] == ENUMERATE
    assert session.outcome.idle is True


def test_the_agent_session_is_running_before_the_first_tool_call() -> None:
    """The store commits RUNNING first: a call from inside the graph always finds the row."""
    with campaign_context() as (dsn, seeded):
        service_ = pg_service(dsn)
        seen: list[str] = []

        class CheckingClient(InProcessToolClient):
            async def call_capability(self, tool: str, arguments_: Any, *, meta: Any) -> Any:
                seen.append(
                    str(
                        scalar(
                            dsn,
                            "SELECT status FROM agent_session WHERE session_id = %s",
                            (meta.session_id,),
                        )
                    )
                )
                return await super().call_capability(tool, arguments_, meta=meta)

        deps, _client = deps_with(
            dsn,
            service_,
            responses=[tool_call_response(ENUMERATE, arguments())],
            client=CheckingClient(service_),
        )
        run(run_session(session_request(campaign_id=seeded.campaign_id), deps))

    assert seen == ["RUNNING"]


def test_the_terminal_status_constant_covers_the_row() -> None:
    """Guards the store's invariant against a contract change (job.v2 vs agent_session)."""
    assert "SUCCEEDED" in TERMINAL_STATUSES  # the M05 job statuses would also move


def _rows(dsn: str, query: str, params: tuple[Any, ...] = ()) -> list[Any]:
    with connect(dsn) as conn:
        return list(conn.execute(query, params).fetchall())


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True)
