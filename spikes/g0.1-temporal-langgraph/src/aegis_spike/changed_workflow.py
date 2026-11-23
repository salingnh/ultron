"""Replay negative control: an incompatible workflow code change must be rejected.

The Temporal sandbox blocks `random`/`uuid4`/`time` inside workflow code, so the honest
regression control is "same workflow type, different command sequence" — exactly the
case a CI replay gate must catch before a deploy.
"""

from __future__ import annotations

from datetime import timedelta

from temporalio import workflow

from .spike_types import CampaignInput


@workflow.defn(name="CampaignWorkflow")
class ChangedCampaignWorkflow:
    """Same workflow type as CampaignWorkflow but a different first command."""

    @workflow.run
    async def run(self, inp: CampaignInput) -> str:
        # History for the real workflow starts with ScheduleActivityTask; this starts
        # with StartTimer, so replay must report a nondeterministic command sequence.
        await workflow.sleep(timedelta(seconds=1))
        return "changed"
