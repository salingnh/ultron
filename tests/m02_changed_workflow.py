"""Negative control for the replay gate: same workflow type, different command sequence.

The replayer must reject a history produced by `CampaignWorkflow` when the code that claims the same
workflow type issues a different first command. If this class ever replays the committed history
without an error, the gate is not a gate.
"""

from __future__ import annotations

from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from aegis.m02_orchestrator.activities import dispatch_ready
    from aegis.m02_orchestrator.types import CampaignOutcome, CampaignRunInput

__all__ = ["ChangedCampaignWorkflow"]


@workflow.defn(name="CampaignWorkflow")
class ChangedCampaignWorkflow:
    """Different first command (`dispatch_ready` instead of `load_campaign`)."""

    @workflow.run
    async def run(self, inp: CampaignRunInput) -> CampaignOutcome:
        await workflow.execute_activity(
            dispatch_ready,
            inp.campaign_id,
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=RetryPolicy(maximum_attempts=5),
        )
        return CampaignOutcome(
            campaign_id=inp.campaign_id,
            status="COMPLETED",
            stop_reason="negative control",
        )
