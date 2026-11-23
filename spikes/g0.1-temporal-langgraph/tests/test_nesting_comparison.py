"""Variant B (workflow per session) measured against variant A (activity-hosted).

Used only by the G0.1 decision memo: same fake model/registry, same one-round session,
so the Temporal history cost of each nesting model is comparable.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from aegis_spike import config
from aegis_spike.session_workflow import SessionWorkflow
from aegis_spike.spike_types import SessionInput

from .conftest import start_campaign, wait_until

EVIDENCE = Path(__file__).resolve().parents[1] / "evidence"


def history_metrics(history) -> dict[str, object]:
    raw = history.to_json()
    payload_sizes = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            if "data" in node and isinstance(node["data"], str):
                payload_sizes.append(len(node["data"]))
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(json.loads(raw))
    return {
        "events": len(history.events),
        "bytes": len(raw.encode()),
        "max_payload_bytes": max(payload_sizes) if payload_sizes else 0,
        "payload_count": len(payload_sizes),
    }


def _session_input(campaign_id: str, delay: float = 0.2) -> SessionInput:
    return SessionInput(
        campaign_id=campaign_id,
        session_id=f"{campaign_id}:cycle-0",
        cursor_in=0,
        cursor_out=1,
        objective="spike objective: discover subdomains of the authorized lab seed",
        fake_job_delay_seconds=delay,
    )


async def test_variant_b_session_workflow_completes(temporal, db, worker_factory, campaign_id: str):
    worker_factory()
    inp = _session_input(campaign_id)
    handle = await temporal.start_workflow(
        SessionWorkflow.run, inp, id=f"session-{inp.session_id}", task_queue=config.AGENT_QUEUE
    )
    result = await asyncio.wait_for(handle.result(), timeout=120)
    assert result["status"] == "completed"

    cur = await db.execute("SELECT count(*), sum(dispatch_calls) FROM spike.mcp_job WHERE campaign_id = %s", (campaign_id,))
    assert await cur.fetchone() == (1, 1)

    variant_b = history_metrics(await handle.fetch_history())

    # Variant A, same session, one campaign cycle (for the side-by-side number).
    campaign_b = await start_campaign(temporal, campaign_id + "-a", max_cycles=1, fake_job_delay_seconds=0.2)
    await campaign_b[0].result()
    variant_a = history_metrics(await campaign_b[0].fetch_history())

    EVIDENCE.mkdir(exist_ok=True)
    (EVIDENCE / "nesting-comparison.json").write_text(
        json.dumps(
            {
                "variant_a_activity_hosted_campaign_cycle": variant_a,
                "variant_b_workflow_per_session": variant_b,
                "note": (
                    "Variant A's history covers one CampaignWorkflow cycle (record_workflow_run, "
                    "fetch_delta, the whole session activity, publish_snapshot); variant B's history "
                    "is the session workflow alone (6 node activities) and still needs a campaign parent."
                ),
            },
            indent=2,
        )
    )


async def test_variant_b_restart_mid_session(temporal, db, worker_factory, campaign_id: str):
    """Kill the worker inside await_result: variant B resumes from history, no duplicate job."""
    session_id = f"{campaign_id}:cycle-0"
    worker = worker_factory()
    inp = _session_input(campaign_id, delay=20)
    handle = await temporal.start_workflow(
        SessionWorkflow.run, inp, id=f"session-{session_id}", task_queue=config.AGENT_QUEUE
    )

    async def in_flight() -> bool:
        cur = await db.execute(
            "SELECT count(*) FROM spike.node_log WHERE session_id = %s AND node = 'await_result'", (session_id,)
        )
        return (await cur.fetchone())[0] == 1

    await wait_until(in_flight, timeout=60, what="variant B session to wait on its MCP job")
    worker.kill()
    worker_factory()
    result = await asyncio.wait_for(handle.result(), timeout=120)
    assert result["status"] == "completed"

    cur = await db.execute(
        "SELECT count(*), sum(dispatch_calls) FROM spike.mcp_job WHERE campaign_id = %s", (campaign_id,)
    )
    assert await cur.fetchone() == (1, 1)

    cur = await db.execute(
        "SELECT node, activity_attempt FROM spike.node_log WHERE session_id = %s ORDER BY id", (session_id,)
    )
    rows = await cur.fetchall()
    assert [n for n, _ in rows] == ["plan", "select_tool", "dispatch", "await_result", "await_result", "analyze", "decide_next"]
    assert rows[3][1] == 1 and rows[4][1] == 2, rows
