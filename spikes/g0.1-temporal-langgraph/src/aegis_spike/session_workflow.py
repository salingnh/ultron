"""Variant B for the G0.1 decision memo: one Temporal workflow per agent session.

The graph topology (node order) lives in workflow code and every node is its own
activity, so the session state lands in Temporal history instead of a LangGraph
checkpoint. Same fake model/registry as variant A, so the comparison is apples to apples:
  * history events/bytes for one identical session
  * restart behaviour when the worker dies inside a node

This variant is only a comparison artefact; it is not the chosen design.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from .activities import run_graph_node
    from .spike_types import NodeInput, SessionInput

NODE_ORDER = ("plan", "select_tool", "dispatch", "await_result", "analyze", "decide_next")
NODE_TIMEOUT = timedelta(seconds=300)
NODE_RETRY = RetryPolicy(maximum_attempts=5)


@workflow.defn(name="SessionWorkflow")
class SessionWorkflow:
    @workflow.run
    async def run(self, inp: SessionInput) -> dict[str, Any]:
        state: dict[str, Any] = {
            "campaign_id": inp.campaign_id,
            "session_id": inp.session_id,
            "objective": inp.objective,
            "cursor_in": inp.cursor_in,
            "cursor_out": inp.cursor_out,
            "step": 0,
        }
        for node in NODE_ORDER:
            # The branch is deterministic because the condition comes from recorded
            # activity results; the node order itself is workflow code.
            if state.get("stop_reason") or state.get("decision") == "stop":
                break
            update = await workflow.execute_activity(
                run_graph_node,
                NodeInput(
                    campaign_id=inp.campaign_id,
                    session_id=inp.session_id,
                    node=node,
                    state=dict(state),
                    objective=inp.objective,
                    fake_job_delay_seconds=inp.fake_job_delay_seconds,
                ),
                start_to_close_timeout=NODE_TIMEOUT,
                heartbeat_timeout=timedelta(seconds=3),
                retry_policy=NODE_RETRY,
            )
            state.update(update)
        return {
            "session_id": inp.session_id,
            "status": "completed" if state.get("decision") == "stop" else "incomplete",
            "stop_reason": state.get("stop_reason"),
            "steps": state.get("step"),
            "cursor": state.get("cursor_out"),
            "job_id": state.get("job_id"),
        }
