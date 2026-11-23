"""CampaignWorkflow: the G0.1 prototype of M02 orchestration.

Shape decided by this spike (see DECISION.md):
  * LangGraph sessions run inside the `run_agent_session` activity, not as workflows.
  * `cancel` is a signal; the handler cancels the in-flight activity task and the
    workflow then runs `cancel_jobs`, so both the session and its MCP job stop.
  * Continue-As-New carries the cursor, cycle counter and execution settings.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import is_cancelled_exception

with workflow.unsafe.imports_passed_through():
    from . import config
    from .activities import cancel_jobs, fetch_delta, publish_snapshot, record_workflow_run, run_agent_session
    from .spike_types import (
        CampaignInput,
        CampaignOutcome,
        CampaignStatusView,
        FetchDeltaInput,
        RunRecord,
        SessionInput,
        SessionResult,
    )

ACTIVITY_TIMEOUT = timedelta(seconds=30)
SESSION_TIMEOUT = timedelta(seconds=300)
HEARTBEAT_TIMEOUT = timedelta(seconds=3)
RETRY = RetryPolicy(maximum_attempts=5)


@workflow.defn(name="CampaignWorkflow")
class CampaignWorkflow:
    def __init__(self) -> None:
        self._paused = False
        self._cancel_requested = False
        self._cancel_reason: str | None = None
        self._state = "RUNNING"
        self._pending: set[str] = set()
        self._last_revision = 0
        self._idle_cycles = 0
        self._cycle = 0
        self._cursor = 0
        self._session_task: asyncio.Task[SessionResult] | None = None

    # ---- signals -------------------------------------------------------------
    @workflow.signal
    async def pause(self, reason: str | None = None) -> None:
        self._paused = True
        self._state = "PAUSED"

    @workflow.signal
    async def resume(self) -> None:
        self._paused = False
        self._state = "RUNNING"

    @workflow.signal
    async def cancel(self, reason: str | None = None) -> None:
        self._cancel_requested = True
        self._cancel_reason = reason
        self._state = "CANCELING"
        # Cancel propagation: the in-flight session activity is cancelled here; the
        # activity cleans up and the workflow waits for that (WAIT_CANCELLATION_COMPLETED).
        if self._session_task is not None:
            self._session_task.cancel()

    @workflow.signal
    async def job_completed(self, job_id: str, status: str) -> None:
        self._pending.discard(job_id)

    @workflow.signal
    async def knowledge_delta(self, revision: int) -> None:
        if revision > self._last_revision:
            self._last_revision = revision

    # ---- query ---------------------------------------------------------------
    @workflow.query
    def status(self) -> CampaignStatusView:
        return CampaignStatusView(
            state=self._state,
            cycle=self._cycle,
            cursor=self._cursor,
            pending_jobs=sorted(self._pending),
            last_revision=self._last_revision,
            idle_cycles=self._idle_cycles,
            paused=self._paused,
            cancel_requested=self._cancel_requested,
        )

    # ---- run -----------------------------------------------------------------
    @workflow.run
    async def run(self, inp: CampaignInput) -> CampaignOutcome:
        self._cycle = inp.cycle
        self._cursor = inp.cursor
        info = workflow.info()
        await workflow.execute_activity(
            record_workflow_run,
            RunRecord(
                workflow_id=info.workflow_id,
                run_id=info.run_id,
                first_run_id=info.first_execution_run_id,
                continued_from_run_id=info.continued_run_id,
                cursor_in=inp.cursor,
                cycle_in=inp.cycle,
            ),
            start_to_close_timeout=ACTIVITY_TIMEOUT,
            retry_policy=RETRY,
        )

        outcome = CampaignOutcome(status="COMPLETED", stop_reason="max_cycles", cursor=self._cursor, cycle=self._cycle)

        while self._cycle < inp.max_cycles:
            await workflow.wait_condition(lambda: not self._paused or self._cancel_requested)
            if self._cancel_requested:
                break
            if self._pending:  # wake on job_completed signal, never busy-poll
                await workflow.wait_condition(
                    lambda: not self._pending or self._cancel_requested or self._paused
                )
                continue

            bundle = await workflow.execute_activity(
                fetch_delta,
                FetchDeltaInput(campaign_id=inp.campaign_id, cursor=self._cursor),
                start_to_close_timeout=ACTIVITY_TIMEOUT,
                retry_policy=RETRY,
            )
            session = SessionInput(
                campaign_id=inp.campaign_id,
                session_id=f"{inp.campaign_id}:cycle-{self._cycle}",
                cursor_in=bundle.cursor_in,
                cursor_out=bundle.cursor_out,
                objective=bundle.objective,
                fake_job_delay_seconds=inp.fake_job_delay_seconds,
            )
            self._session_task = asyncio.create_task(
                workflow.execute_activity(
                    run_agent_session,
                    session,
                    task_queue=config.AGENT_QUEUE,
                    start_to_close_timeout=SESSION_TIMEOUT,
                    heartbeat_timeout=HEARTBEAT_TIMEOUT,
                    retry_policy=RETRY,
                    cancellation_type=workflow.ActivityCancellationType.WAIT_CANCELLATION_COMPLETED,
                )
            )
            try:
                result = await self._session_task
            except asyncio.CancelledError:  # the workflow run itself was cancelled
                raise
            except Exception as exc:
                # A cancelled activity surfaces as ActivityError whose cause is a
                # cancelled failure; anything else is a real failure and must propagate.
                if not (self._cancel_requested and is_cancelled_exception(exc)):
                    raise
                result = None
            finally:
                self._session_task = None

            if result is None:
                self._state = "CANCELING"
                canceled = await workflow.execute_activity(
                    cancel_jobs,
                    inp.campaign_id,
                    start_to_close_timeout=ACTIVITY_TIMEOUT,
                    retry_policy=RETRY,
                )
                outcome = CampaignOutcome(
                    status="CANCELED",
                    stop_reason=self._cancel_reason or "cancel signal",
                    cursor=self._cursor,
                    cycle=self._cycle,
                    canceled_job_ids=list(canceled["canceled_job_ids"]),
                )
                self._state = "CANCELED"
                break

            self._cycle += 1
            self._cursor = result.cursor
            if result.stop_reason not in (None, "objective_done"):
                self._idle_cycles += 1
            else:
                self._idle_cycles = 0
            outcome = CampaignOutcome(
                status="COMPLETED",
                stop_reason=result.stop_reason,
                cursor=self._cursor,
                cycle=self._cycle,
                jobs=[result.job_id] if result.job_id else [],
            )
            if (
                inp.continue_as_new_after_cycles
                and self._cycle < inp.max_cycles
                and self._cycle % inp.continue_as_new_after_cycles == 0
            ):
                # History stays small; the cursor and cycle travel with the new run.
                workflow.continue_as_new(
                    CampaignInput(
                        campaign_id=inp.campaign_id,
                        cursor=self._cursor,
                        cycle=self._cycle,
                        max_cycles=inp.max_cycles,
                        continue_as_new_after_cycles=inp.continue_as_new_after_cycles,
                        fake_job_delay_seconds=inp.fake_job_delay_seconds,
                    )
                )

        snapshot = await workflow.execute_activity(
            publish_snapshot,
            inp.campaign_id,
            start_to_close_timeout=ACTIVITY_TIMEOUT,
            retry_policy=RETRY,
        )
        outcome.snapshot = dict(snapshot)
        outcome.cursor = self._cursor
        outcome.cycle = self._cycle
        return outcome
