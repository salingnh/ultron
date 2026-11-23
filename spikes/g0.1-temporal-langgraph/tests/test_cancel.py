"""Acceptance: the cancel signal stops the session and its in-flight MCP job."""

from __future__ import annotations

import time

from aegis_spike.workflows import CampaignWorkflow

from .conftest import start_campaign, wait_until


async def test_cancel_signal_stops_session_and_inflight_job(temporal, db, worker_factory, campaign_id: str):
    session_id = f"{campaign_id}:cycle-0"
    worker_factory()
    handle, _ = await start_campaign(temporal, campaign_id, max_cycles=2, fake_job_delay_seconds=120)

    async def in_flight() -> bool:
        cur = await db.execute(
            "SELECT count(*) FROM spike.node_log WHERE session_id = %s AND node = 'await_result'", (session_id,)
        )
        return (await cur.fetchone())[0] == 1

    await wait_until(in_flight, timeout=60, what="session activity to be waiting on its MCP job")
    status_before = await handle.query(CampaignWorkflow.status)
    assert status_before.state == "RUNNING"

    started = time.monotonic()
    await handle.signal(CampaignWorkflow.cancel, "g0.1 test: operator cancel")
    result = await handle.result()
    elapsed = time.monotonic() - started

    assert result.status == "CANCELED"
    assert result.stop_reason == "g0.1 test: operator cancel"
    assert elapsed < 20, f"cancel took {elapsed:.1f}s: the in-flight activity was not stopped"
    assert result.canceled_job_ids, "cancel_jobs did not see the in-flight job"

    cur = await db.execute(
        "SELECT status FROM spike.mcp_job WHERE campaign_id = %s", (campaign_id,)
    )
    assert [row[0] for row in await cur.fetchall()] == ["CANCELLED"]

    cur = await db.execute(
        "SELECT status, stop_reason FROM spike.session_state WHERE session_id = %s", (session_id,)
    )
    assert await cur.fetchone() == ("canceled", "cancel signal")

    cur = await db.execute(
        "SELECT node FROM spike.node_log WHERE session_id = %s ORDER BY id", (session_id,)
    )
    assert [row[0] for row in await cur.fetchall()] == ["plan", "select_tool", "dispatch", "await_result"]

    status_after = await handle.query(CampaignWorkflow.status)
    assert status_after.state == "CANCELED"
    assert status_after.cancel_requested is True

    cur = await db.execute(
        "SELECT count(*) FROM spike.event WHERE kind = 'cancel_jobs' AND payload->>'campaign_id' = %s",
        (campaign_id,),
    )
    assert (await cur.fetchone())[0] == 1
