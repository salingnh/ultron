"""The workflow-signal port of M02's dispatchers, and its Temporal implementation.

The schedulers never talk to Temporal directly: the outbox dispatcher (job.completed.v2) and the
campaign watcher (status changes from M01) call this small port, so both can be tested against a
recording fake without a server, and a Temporal outage stays an infrastructure failure instead of
a database one.
"""

from __future__ import annotations

from typing import Protocol

from temporalio.client import Client
from temporalio.common import WorkflowIDConflictPolicy
from temporalio.service import RPCError, RPCStatusCode

from .types import ORCHESTRATOR_QUEUE, CampaignRunInput, workflow_id

__all__ = ["TemporalSignals", "WorkflowSignals"]


class WorkflowSignals(Protocol):
    """What the dispatchers need from the workflow runtime."""

    async def ensure_started(self, campaign_id: str) -> bool: ...

    async def signal_status(
        self, campaign_id: str, status: str, reason: str | None = None
    ) -> bool: ...

    async def job_completed(self, campaign_id: str, job_id: str, status: str) -> bool: ...


def _is_not_found(error: BaseException) -> bool:
    return isinstance(error, RPCError) and error.status == RPCStatusCode.NOT_FOUND


class TemporalSignals:
    """`WorkflowSignals` on a Temporal client; every call is idempotent and best-effort."""

    def __init__(self, client: Client, *, task_queue: str = ORCHESTRATOR_QUEUE) -> None:
        self._client = client
        self._task_queue = task_queue

    async def ensure_started(self, campaign_id: str) -> bool:
        """Ensure `campaign-<id>` has an open run (idempotent) and report that it does."""
        from aegis.m02_orchestrator.workflow import CampaignWorkflow

        await self._client.start_workflow(
            CampaignWorkflow.run,
            CampaignRunInput(campaign_id=campaign_id),
            id=workflow_id(campaign_id),
            task_queue=self._task_queue,
            id_conflict_policy=WorkflowIDConflictPolicy.USE_EXISTING,
        )
        return True

    async def signal_status(self, campaign_id: str, status: str, reason: str | None = None) -> bool:
        """Deliver the signal matching a campaign status; False when no workflow accepted it."""
        handle = self._client.get_workflow_handle(workflow_id(campaign_id))
        try:
            if status == "PAUSED":
                await handle.signal("pause", args=[reason])
            elif status in ("RUNNING", "WAITING"):
                await handle.signal("resume")
            elif status == "CANCELLED":
                await handle.signal("cancel", args=[reason])
            else:
                # CREATED has no signal: the workflow's own `start` transition covers it.
                return True
        except RPCError as error:
            if _is_not_found(error):
                return False
            raise
        return True

    async def job_completed(self, campaign_id: str, job_id: str, status: str) -> bool:
        """Deliver `job_completed`; False when the campaign has no open workflow (yet)."""
        handle = self._client.get_workflow_handle(workflow_id(campaign_id))
        try:
            await handle.signal("job_completed", args=[job_id, status])
        except RPCError as error:
            if _is_not_found(error):
                return False
            raise
        return True
