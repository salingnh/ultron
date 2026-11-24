"""CampaignWorkflow — the durable M02 orchestration loop (interfaces/README.md §7).

Shape locked by the G0.1 decision (02-nen-tang §Phiên agent):

* the agent session runs **inside** the `run_agent_session` activity (M03, G1.2c), not as a child
  workflow: Temporal history keeps ids and cursor, not graph state;
* the activity is scheduled with a finite `heartbeat_timeout` and
  `WAIT_CANCELLATION_COMPLETED`, and a `cancel` signal cancels the in-flight task, so the session's
  checkpoint cleanup and stop reason actually run;
* the campaign loop waits on signals or a timer, never busy-polls;
* Continue-As-New carries the cursor, cycle counter and revision across runs.

The loop never starts a container itself: every tick asks the `dispatch_ready` activity, which
commits the dispatch decision (QUEUED -> VALIDATING) and the wait reasons. Job completion comes
back as the `job_completed` signal, sent by the outbox dispatcher when it sees `job.completed.v2`.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import timedelta
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import is_cancelled_exception

with workflow.unsafe.imports_passed_through():
    from aegis.m02_orchestrator.activities import (
        cancel_jobs,
        dispatch_ready,
        finish_campaign,
        load_campaign,
    )
    from aegis.m02_orchestrator.types import (
        AGENT_QUEUE,
        CampaignOutcome,
        CampaignRunInput,
        CampaignSnapshot,
        CampaignStatusView,
        CancelOutcome,
        DispatchPlan,
        SessionOutcome,
        SessionRequest,
    )

__all__ = ["CampaignWorkflow"]

ACTIVITY_TIMEOUT = timedelta(seconds=30)
SESSION_TIMEOUT = timedelta(minutes=30)
HEARTBEAT_TIMEOUT = timedelta(seconds=3)
RETRY = RetryPolicy(maximum_attempts=5)
TERMINAL_STATUSES = frozenset({"COMPLETED", "FAILED", "CANCELLED"})
SESSION_ACTIVITY = "run_agent_session"


@workflow.defn(name="CampaignWorkflow")
class CampaignWorkflow:
    """One campaign, one workflow (`campaign-<campaign_id>`), signals per the interface."""

    def __init__(self) -> None:
        self._paused = False
        self._cancel_requested = False
        self._cancel_reason: str | None = None
        self._state = "RUNNING"
        self._cycle = 0
        #: Cycle the current run started from (a Continue-As-New run must not continue again
        #: before it has done any work, or `cycle % N == 0` would loop forever).
        self._start_cycle = 0
        self._cursor = 0
        self._idle_cycles = 0
        self._last_revision = 0
        self._objective = ""
        self._queued = 0
        self._in_flight = 0
        self._pending: set[str] = set()
        #: Bumped by every signal that should wake the loop (job_completed, knowledge_delta).
        self._wake = 0
        self._session_task: asyncio.Task[Any] | None = None
        self._stop_reason: str | None = None

    # --- signals -------------------------------------------------------------------------
    @workflow.signal
    def pause(self, reason: str | None = None) -> None:
        self._paused = True
        self._state = "PAUSED"
        del reason  # the history row keeps the operator's reason (M01); the workflow only stops

    @workflow.signal
    def resume(self) -> None:
        self._paused = False
        self._state = "RUNNING"
        self._wake += 1

    @workflow.signal
    def cancel(self, reason: str | None = None) -> None:
        self._cancel_requested = True
        self._cancel_reason = reason
        self._state = "CANCELING"
        if self._session_task is not None:
            # Cancel propagation: the activity cleans up its checkpoint and records the stop
            # reason before returning; the workflow waits for that (WAIT_CANCELLATION_COMPLETED).
            self._session_task.cancel()

    @workflow.signal
    def job_completed(self, job_id: str, status: str) -> None:
        # The dispatcher delivers job.completed.v2 as a signal; a duplicate is harmless.
        del status
        self._pending.discard(job_id)
        self._wake += 1

    @workflow.signal
    def knowledge_delta(self, revision: int) -> None:
        if revision > self._last_revision:
            self._last_revision = revision
        self._wake += 1

    # --- query ---------------------------------------------------------------------------
    @workflow.query
    def status(self) -> CampaignStatusView:
        return CampaignStatusView(
            state=self._state,
            cycle=self._cycle,
            cursor=self._cursor,
            pending_jobs=tuple(sorted(self._pending)),
            queued_jobs=self._queued,
            in_flight_jobs=self._in_flight,
            last_revision=self._last_revision,
            idle_cycles=self._idle_cycles,
            paused=self._paused,
            cancel_requested=self._cancel_requested,
            stop_reason=self._stop_reason,
        )

    # --- run -----------------------------------------------------------------------------
    @workflow.run
    async def run(self, inp: CampaignRunInput) -> CampaignOutcome:
        self._cycle = inp.cycle
        self._start_cycle = inp.cycle
        self._cursor = inp.cursor
        self._idle_cycles = inp.idle_cycles
        self._last_revision = inp.last_revision

        snapshot: CampaignSnapshot = await workflow.execute_activity(
            load_campaign,
            inp.campaign_id,
            start_to_close_timeout=ACTIVITY_TIMEOUT,
            retry_policy=RETRY,
        )
        self._objective = snapshot.objective
        self._pending = set(snapshot.pending_job_ids)
        if snapshot.status in TERMINAL_STATUSES:
            self._state = snapshot.status
            self._stop_reason = f"campaign_{snapshot.status.lower()}"
            return self._outcome(
                inp.campaign_id, snapshot.status, self._stop_reason or "campaign_terminal"
            )
        if snapshot.status == "PAUSED":
            self._paused = True
            self._state = "PAUSED"
        if snapshot.status == "CREATED":
            await self._finish(inp.campaign_id, "start", "campaign workflow started")

        while True:
            if self._cancel_requested:
                return await self._cancel(inp)
            if self._paused:
                await workflow.wait_condition(lambda: not self._paused or self._cancel_requested)
                continue

            self._continue_as_new_if_needed(inp)

            plan: DispatchPlan = await workflow.execute_activity(
                dispatch_ready,
                inp.campaign_id,
                start_to_close_timeout=ACTIVITY_TIMEOUT,
                retry_policy=RETRY,
            )
            self._queued = plan.queued
            self._in_flight = plan.in_flight
            # The committed rows are the truth about what is still running: a `job_completed`
            # signal that arrived between two ticks cannot leave the loop waiting for it.
            self._pending = set(plan.pending)
            if plan.stop is not None:
                return await self._stop(inp, plan)

            if plan.claimed:
                await self._wait_for_change(inp.tick_seconds)
                continue
            if self._pending or plan.queued:
                # Jobs are running, or blocked by a gate the timer re-evaluates (window, rate).
                await self._wait_for_change(inp.tick_seconds)
                continue

            outcome = await self._run_session(inp)
            if outcome is None:  # cancelled mid-session; the loop top handles the cancel
                continue
            self._cursor = outcome.cursor
            self._cycle += 1
            self._idle_cycles = self._idle_cycles + 1 if outcome.idle else 0
            if outcome.stop_reason is not None:
                self._stop_reason = outcome.stop_reason
                await self._finish(inp.campaign_id, "complete", outcome.stop_reason)
                self._state = "COMPLETED"
                return self._outcome(inp.campaign_id, "COMPLETED", outcome.stop_reason)
            threshold = snapshot.idle_cycles_before_pause
            if self._idle_cycles >= threshold:
                reason = f"no progress for {self._idle_cycles} session(s)"
                await self._finish(inp.campaign_id, "pause", reason)
                self._paused = True
                self._state = "PAUSED"
                continue
            if self._cycle >= inp.max_cycles:
                await self._finish(inp.campaign_id, "complete", "max_cycles")
                self._state = "COMPLETED"
                return self._outcome(inp.campaign_id, "COMPLETED", "max_cycles")

    # --- steps ---------------------------------------------------------------------------
    async def _run_session(self, inp: CampaignRunInput) -> SessionOutcome | None:
        request = SessionRequest(
            campaign_id=inp.campaign_id,
            session_id=f"{inp.campaign_id}:cycle-{self._cycle}",
            cycle=self._cycle,
            cursor=self._cursor,
            objective=self._objective,
        )
        self._session_task = asyncio.create_task(
            workflow.execute_activity(
                SESSION_ACTIVITY,
                request,
                result_type=SessionOutcome,
                task_queue=AGENT_QUEUE,
                start_to_close_timeout=SESSION_TIMEOUT,
                heartbeat_timeout=HEARTBEAT_TIMEOUT,
                retry_policy=RETRY,
                cancellation_type=workflow.ActivityCancellationType.WAIT_CANCELLATION_COMPLETED,
            )
        )
        try:
            result: SessionOutcome = await self._session_task
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # A cancelled activity surfaces as ActivityError whose cause is a cancelled failure,
            # not as asyncio.CancelledError (G0.1 memo). Only the campaign cancel may swallow it.
            if not (self._cancel_requested and is_cancelled_exception(exc)):
                raise
            return None
        finally:
            self._session_task = None
        return result

    async def _cancel(self, inp: CampaignRunInput) -> CampaignOutcome:
        outcome: CancelOutcome = await workflow.execute_activity(
            cancel_jobs,
            args=[inp.campaign_id, self._cancel_reason],
            start_to_close_timeout=ACTIVITY_TIMEOUT,
            retry_policy=RETRY,
        )
        reason = self._cancel_reason or "cancel signal"
        await self._finish(inp.campaign_id, "cancel", reason)
        self._state = "CANCELLED"
        self._stop_reason = reason
        return CampaignOutcome(
            campaign_id=inp.campaign_id,
            status="CANCELLED",
            stop_reason=reason,
            cycle=self._cycle,
            cursor=self._cursor,
            canceled_job_ids=outcome.canceled_job_ids,
        )

    async def _stop(self, inp: CampaignRunInput, plan: DispatchPlan) -> CampaignOutcome:
        if plan.stop == "duration_budget_exhausted":
            await self._finish(inp.campaign_id, "fail", plan.stop)
            self._state = "FAILED"
            self._stop_reason = plan.stop
            return self._outcome(inp.campaign_id, "FAILED", plan.stop)
        # campaign_completed / campaign_failed / campaign_cancelled: already terminal in the DB.
        self._state = plan.status
        self._stop_reason = plan.stop or f"campaign_{plan.status.lower()}"
        return self._outcome(inp.campaign_id, plan.status, self._stop_reason)

    async def _finish(self, campaign_id: str, action: str, reason: str) -> None:
        await workflow.execute_activity(
            finish_campaign,
            args=[campaign_id, action, reason],
            start_to_close_timeout=ACTIVITY_TIMEOUT,
            retry_policy=RETRY,
        )

    async def _wait_for_change(self, seconds: float) -> None:
        before = self._wake
        await workflow.wait_condition(
            lambda: self._wake != before or self._cancel_requested or self._paused,
            timeout=timedelta(seconds=max(0.01, seconds)),
        )

    def _continue_as_new_if_needed(self, inp: CampaignRunInput) -> None:
        advanced = self._cycle > self._start_cycle
        cycles_due = bool(
            advanced and inp.continue_after_cycles and self._cycle % inp.continue_after_cycles == 0
        )
        history_due = (
            inp.continue_after_history_events > 0
            and workflow.info().get_current_history_length() >= inp.continue_after_history_events
        )
        if not (cycles_due or history_due):
            return
        workflow.continue_as_new(
            replace(
                inp,
                cycle=self._cycle,
                cursor=self._cursor,
                idle_cycles=self._idle_cycles,
                last_revision=self._last_revision,
            )
        )

    def _outcome(self, campaign_id: str, status: str, stop_reason: str) -> CampaignOutcome:
        return CampaignOutcome(
            campaign_id=campaign_id,
            status=status,
            stop_reason=stop_reason,
            cycle=self._cycle,
            cursor=self._cursor,
        )
