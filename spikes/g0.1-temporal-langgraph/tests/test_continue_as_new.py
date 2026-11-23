"""Acceptance: Continue-As-New carries the cursor (and the cycle counter) into the new run."""

from __future__ import annotations


from .conftest import start_campaign


async def test_continue_as_new_carries_cursor(temporal, db, worker_factory, campaign_id: str):
    worker_factory()
    handle, _ = await start_campaign(
        temporal,
        campaign_id,
        max_cycles=4,
        continue_as_new_after_cycles=2,
        fake_job_delay_seconds=0.2,
    )
    result = await handle.result()
    assert result.status == "COMPLETED"
    assert result.cycle == 4
    assert result.cursor == 4

    cur = await db.execute(
        """
        SELECT run_id, first_run_id, continued_from_run_id, cursor_in, cycle_in
        FROM spike.workflow_run WHERE workflow_id = %s ORDER BY id
        """,
        (f"campaign-{campaign_id}",),
    )
    runs = await cur.fetchall()
    assert len(runs) == 2, f"expected one Continue-As-New, got {runs}"
    first, second = runs
    assert first[3] == 0 and first[4] == 0
    assert first[2] is None
    assert second[2] == first[0], "the new run is not reported as continued from the first one"
    assert second[3] == 2, "cursor was not carried into the continued run"
    assert second[4] == 2, "cycle counter was not carried into the continued run"
    assert second[1] == first[1], "first_execution_run_id changed across Continue-As-New"

    # Temporal itself must show exactly two runs for the same workflow id.
    count = 0
    async for _ in temporal.list_workflows(f'WorkflowId = "campaign-{campaign_id}"'):
        count += 1
    assert count == 2

    # Every cycle produced exactly one job, none lost across the run boundary.
    cur = await db.execute(
        "SELECT count(*), count(DISTINCT job_id) FROM spike.mcp_job WHERE campaign_id = %s", (campaign_id,)
    )
    assert await cur.fetchone() == (4, 4)

    cur = await db.execute(
        "SELECT count(*) FROM spike.session_state WHERE campaign_id = %s AND status = 'completed'", (campaign_id,)
    )
    assert (await cur.fetchone())[0] == 4
