"""Temporal activities for the G0.1 spike.

`run_agent_session` is the interesting one: it hosts the LangGraph graph with a
Postgres checkpointer keyed by `session_id`, so a worker kill inside the activity
resumes at the last completed node instead of replaying the session.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict
from typing import Any

from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from temporalio import activity

from . import config, ledger
from .agent_graph import run_session_graph
from .fakes import FakeMcpRegistry
from .runtime import current_attempt
from .spike_types import ContextBundle, FetchDeltaInput, NodeInput, RunRecord, SessionInput, SessionResult


@activity.defn
async def record_workflow_run(rec: RunRecord) -> None:
    async with ledger.connect() as conn:
        await ledger.record_workflow_run(
            conn,
            workflow_id=rec.workflow_id,
            run_id=rec.run_id,
            first_run_id=rec.first_run_id,
            continued_from_run_id=rec.continued_from_run_id,
            cursor_in=rec.cursor_in,
            cycle_in=rec.cycle_in,
        )


@activity.defn
async def fetch_delta(inp: FetchDeltaInput) -> ContextBundle:
    """Read-only: hand the session a bounded context delta and the next cursor."""
    async with ledger.connect() as conn:
        cur = await conn.execute(
            "SELECT count(*) FROM spike.mcp_job WHERE campaign_id = %s",
            (inp.campaign_id,),
        )
        row = await cur.fetchone()
        known_jobs = int(row[0]) if row else 0
        await ledger.record_event(
            conn, "fetch_delta", {"campaign_id": inp.campaign_id, "cursor_in": inp.cursor, "known_jobs": known_jobs}
        )
    return ContextBundle(
        campaign_id=inp.campaign_id,
        cursor_in=inp.cursor,
        cursor_out=inp.cursor + 1,
        objective="spike objective: discover subdomains of the authorized lab seed",
        observations=[f"known_jobs={known_jobs}"],
    )


@activity.defn
async def run_agent_session(inp: SessionInput) -> SessionResult:
    attempt = current_attempt()
    async with ledger.connect() as conn:
        await ledger.record_event(
            conn, "session_attempt_started", {"session_id": inp.session_id, "attempt": attempt}
        )
        try:
            async with AsyncPostgresSaver.from_conn_string(config.checkpoint_dsn()) as checkpointer:
                await checkpointer.setup()
                state, resumed = await run_session_graph(conn, inp, attempt, checkpointer)
        except asyncio.CancelledError:
            # Cancellation was requested (signal -> workflow -> activity). The graph
            # checkpoint keeps whatever completed; record why the session stopped.
            payload = {"session_id": inp.session_id, "attempt": attempt, "reason": "cancel signal"}
            await ledger.record_event(conn, "session_canceled", payload)
            await ledger.save_session_state(
                conn,
                session_id=inp.session_id,
                campaign_id=inp.campaign_id,
                status="canceled",
                stop_reason="cancel signal",
                steps=-1,  # unknown: the graph was interrupted mid-node
                cursor=inp.cursor_in,
                attempt=attempt,
                result=payload,
            )
            raise

        status = "completed" if state.get("decision") == "stop" else "incomplete"
        result = SessionResult(
            session_id=inp.session_id,
            status=status,
            stop_reason=state.get("stop_reason"),
            steps=int(state.get("step", 0)),
            cursor=int(state.get("cursor_out", inp.cursor_out)),
            job_id=state.get("job_id"),
            resumed=resumed,
            attempt=attempt,
        )
        await ledger.save_session_state(
            conn,
            session_id=inp.session_id,
            campaign_id=inp.campaign_id,
            status=status,
            stop_reason=result.stop_reason,
            steps=result.steps,
            cursor=result.cursor,
            attempt=attempt,
            result=asdict(result),
        )
        await ledger.record_event(conn, "session_attempt_finished", asdict(result))
        return result


@activity.defn
async def cancel_jobs(campaign_id: str) -> dict[str, Any]:
    """Cancel in-flight MCP jobs of a campaign (called after the session activity stops)."""
    async with ledger.connect() as conn:
        canceled = await FakeMcpRegistry(conn).cancel_campaign(campaign_id)
        payload = {"campaign_id": campaign_id, "canceled_job_ids": canceled}
        await ledger.record_event(conn, "cancel_jobs", payload)
    return payload


@activity.defn
async def publish_snapshot(campaign_id: str) -> dict[str, Any]:
    async with ledger.connect() as conn:
        cur = await conn.execute(
            """
            SELECT count(*)::int,
                   count(*) FILTER (WHERE status = 'SUCCEEDED')::int,
                   count(*) FILTER (WHERE status = 'CANCELLED')::int,
                   count(*) FILTER (WHERE status = 'FAILED')::int
            FROM spike.mcp_job WHERE campaign_id = %s
            """,
            (campaign_id,),
        )
        row = await cur.fetchone()
        snapshot = {
            "campaign_id": campaign_id,
            "jobs_total": int(row[0]),
            "jobs_succeeded": int(row[1]),
            "jobs_canceled": int(row[2]),
            "jobs_failed": int(row[3]),
        }
        await ledger.record_event(conn, "snapshot", snapshot)
    return snapshot



@activity.defn
async def run_graph_node(inp: NodeInput) -> dict[str, Any]:
    from .agent_graph import SessionNodes

    attempt = current_attempt()
    session = SessionInput(
        campaign_id=inp.campaign_id,
        session_id=inp.session_id,
        cursor_in=int(inp.state.get("cursor_in", 0)),
        cursor_out=int(inp.state.get("cursor_out", 1)),
        objective=inp.objective,
        fake_job_delay_seconds=inp.fake_job_delay_seconds,
    )
    async with ledger.connect() as conn:
        nodes = SessionNodes(conn, session, attempt)
        update = await getattr(nodes, inp.node)(dict(inp.state))
        await ledger.record_event(
            conn,
            "session_workflow_node",
            {"session_id": inp.session_id, "node": inp.node, "attempt": attempt},
        )
    return update


ALL_ACTIVITIES = [
    record_workflow_run,
    fetch_delta,
    run_agent_session,
    run_graph_node,
    cancel_jobs,
    publish_snapshot,
]
ORCHESTRATOR_ACTIVITIES = [record_workflow_run, fetch_delta, cancel_jobs, publish_snapshot]
AGENT_ACTIVITIES = [run_agent_session, run_graph_node]
