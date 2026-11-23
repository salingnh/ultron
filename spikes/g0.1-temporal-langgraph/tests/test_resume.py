"""Acceptance: kill the worker mid-activity -> resume from the LangGraph checkpoint,
no duplicate MCP job; and the idempotency key still holds when the checkpoint is lost.
"""

from __future__ import annotations

import asyncio
import uuid

from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

from aegis_spike import config
from aegis_spike.agent_graph import run_session_graph
from aegis_spike.spike_types import SessionInput

from .conftest import start_campaign, wait_until


async def _node_log(db, session_id: str) -> list[tuple[int, str]]:
    cur = await db.execute(
        "SELECT activity_attempt, node FROM spike.node_log WHERE session_id = %s ORDER BY id", (session_id,)
    )
    return [(int(a), n) for a, n in await cur.fetchall()]


async def test_worker_kill_resumes_from_checkpoint_without_duplicate_job(
    temporal, db, worker_factory, campaign_id: str
):
    session_id = f"{campaign_id}:cycle-0"
    worker = worker_factory()
    handle, _ = await start_campaign(temporal, campaign_id, max_cycles=1, fake_job_delay_seconds=20)

    async def dispatched() -> bool:
        cur = await db.execute(
            "SELECT count(*) FROM spike.mcp_job WHERE campaign_id = %s", (campaign_id,)
        )
        if (await cur.fetchone())[0] < 1:
            return False
        return ["await_result"] == [n for _, n in await _node_log(db, session_id)][-1:]

    await wait_until(dispatched, timeout=60, what="session activity to reach await_result with a dispatched job")

    before_kill = await _node_log(db, session_id)
    assert [n for _, n in before_kill] == ["plan", "select_tool", "dispatch", "await_result"]
    assert worker.proc is not None
    worker.kill()  # SIGKILL, no graceful shutdown

    # While the worker is dead nothing may advance the session.
    await asyncio.sleep(3)
    assert await _node_log(db, session_id) == before_kill

    worker2 = worker_factory()  # a fresh worker process, same task queues
    result = await asyncio.wait_for(handle.result(), timeout=120)
    assert result.status == "COMPLETED"
    assert result.stop_reason == "objective_done"

    after = await _node_log(db, session_id)
    attempts: dict[int, list[str]] = {}
    for attempt, node in after:
        attempts.setdefault(attempt, []).append(node)
    assert max(attempts) >= 2, f"activity was not retried: {attempts}"
    first = attempts[1]
    second = attempts[max(attempts)]
    assert first == ["plan", "select_tool", "dispatch", "await_result"]
    assert second[0] == "await_result", f"retry re-ran the graph from the start: {second}"
    assert "dispatch" not in second and "plan" not in second

    cur = await db.execute(
        "SELECT count(*), sum(dispatch_calls) FROM spike.mcp_job WHERE campaign_id = %s", (campaign_id,)
    )
    jobs, dispatch_calls = await cur.fetchone()
    assert jobs == 1, "the crash produced a second MCP job"
    assert dispatch_calls == 1, "dispatch node ran twice; checkpoint resume failed"

    # Completed model calls are not repeated either.
    cur = await db.execute(
        "SELECT node, count(*) FROM spike.model_call WHERE session_id = %s GROUP BY node ORDER BY node",
        (session_id,),
    )
    assert await cur.fetchall() == [("analyze", 1), ("plan", 1)]

    cur = await db.execute(
        "SELECT status, attempts FROM spike.session_state WHERE session_id = %s", (session_id,)
    )
    status, attempts_recorded = await cur.fetchone()
    assert status == "completed"
    assert attempts_recorded >= 2

    cur = await db.execute(
        "SELECT count(*) FROM spike.event WHERE kind = 'session_attempt_started' AND payload->>'session_id' = %s",
        (session_id,),
    )
    assert (await cur.fetchone())[0] >= 2
    assert worker2.proc is not None


async def test_idempotency_key_prevents_duplicate_job_when_checkpoint_is_lost(db, campaign_id: str):
    """Second line of defence: even a from-scratch retry reuses the same MCP job."""
    session_id = f"{campaign_id}:cycle-0"
    inp = SessionInput(
        campaign_id=campaign_id,
        session_id=session_id,
        cursor_in=0,
        cursor_out=1,
        objective="spike objective: lose the checkpoint",
        fake_job_delay_seconds=0.2,
    )
    dsn = config.checkpoint_dsn()
    async with AsyncPostgresSaver.from_conn_string(dsn) as checkpointer:
        await checkpointer.setup()
        first_state, first_resumed = await run_session_graph(db, inp, 1, checkpointer)
        assert first_resumed is False

        # Simulate losing every checkpoint for this session (new container, wiped volume).
        async with db.transaction():
            for table in ("checkpoint_writes", "checkpoint_blobs", "checkpoints"):
                await db.execute(f"DELETE FROM {config.CHECKPOINT_SCHEMA}.{table} WHERE thread_id = %s", (session_id,))

        second_state, second_resumed = await run_session_graph(db, inp, 2, checkpointer)
        assert second_resumed is False, "graph did not start over after the checkpoint wipe"

    assert second_state["job_id"] == first_state["job_id"]
    cur = await db.execute(
        "SELECT count(*), sum(dispatch_calls) FROM spike.mcp_job WHERE campaign_id = %s", (campaign_id,)
    )
    jobs, dispatch_calls = await cur.fetchone()
    assert jobs == 1
    assert dispatch_calls == 2, "the retry did not reuse the stored idempotency key"

    cur = await db.execute(
        "SELECT node, activity_attempt FROM spike.node_log WHERE session_id = %s ORDER BY id", (session_id,)
    )
    rows = [(n, a) for n, a in await cur.fetchall()]
    assert [n for n, _ in rows[:6]] == ["plan", "select_tool", "dispatch", "await_result", "analyze", "decide_next"]
    assert [n for n, _ in rows[6:]] == ["plan", "select_tool", "dispatch", "await_result", "analyze", "decide_next"]
    assert uuid.UUID(second_state["job_id"])  # a real job id, not a fresh one
