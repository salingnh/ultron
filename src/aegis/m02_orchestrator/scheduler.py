"""M02 ready-job dispatcher: the one place that decides which QUEUED job may start.

The contract fixes the order and the gates (02-nen-tang §Scheduling, interfaces/README.md
§Scheduling, job.v2 WaitReason):

* only a `SUCCEEDED` predecessor releases a dependent job; a failed or cancelled predecessor
  leaves it waiting with a reason (never drops the dependency);
* a dispatch is a state change the scheduler commits: `QUEUED -> VALIDATING` plus one
  `job_status_change` row. M06 (G1.3a) picks up `VALIDATING` jobs, starts the sandbox and moves
  them on; the scheduler never runs a container;
* jobs held by the contract (`dispatch_block_reasons IS NOT NULL`, 0011/0014) are not part of the
  dispatchable queue at all: they are filtered out, not given a wait reason (contract text);
* every other blocked job gets exactly one `wait_reason` (the job.v2 shape, X-4), and a job that
  stays blocked for the same reason keeps its original `since`;
* `priority DESC, created_at ASC, job_id ASC` decides which ready jobs fill the free slots.

Gates and their precedence (`DEPENDENCY_*` first because they are per job, then campaign-wide,
then the slot limits applied in priority order):

1. dependency: `DEPENDENCY_FAILED` (a predecessor FAILED/CANCELLED) or `DEPENDENCY_PENDING`
2. `CAMPAIGN_PAUSED`
3. `BUDGET_EXHAUSTED`: the campaign wall-clock budget `max_duration_hours` is used up; the token
   and cost budget is M04's pre-check and the job-count budget is M05's acceptance check
   (G1.1c decision), so they are not repeated here
4. `WINDOW_CLOSED`: outside every `allowed_windows` entry or inside a `blackout_windows` entry
5. `CONCURRENCY_LIMIT`: `max_parallel_jobs` jobs are already VALIDATING..COLLECTING
6. `RATE_LIMITED`: `rate_limits.jobs_per_minute` dispatches already happened in the last minute

The campaign row is locked for the duration of the tick, so the workflow and an operator action
cannot interleave a pause with a dispatch; job claims are conditional on `status = ''QUEUED''`
anyway.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from aegis.m01_campaign import status as campaign_status

from .types import BlockedJob, CampaignSnapshot, CancelOutcome, DispatchPlan
from .windows import utcnow, windows_open

__all__ = [
    "IN_FLIGHT_STATUSES",
    "PostgresScheduler",
    "SchedulerError",
    "TERMINAL_STATUSES",
]

TERMINAL_STATUSES = frozenset({"COMPLETED", "FAILED", "CANCELLED"})
IN_FLIGHT_STATUSES = ("VALIDATING", "DISPATCHED", "RUNNING", "COLLECTING")

MODULE_ACTOR = {"kind": "module", "id": "M02"}

_CAMPAIGN_SQL = """
SELECT c.campaign_id, c.status, c.objective, c.started_at, c.created_at,
       c.current_policy_version, p.policy
  FROM campaign c
  JOIN policy_snapshot p ON p.policy_version = c.current_policy_version
 WHERE c.campaign_id = %s
   FOR UPDATE OF c
"""

_QUEUE_SQL = """
SELECT job_id, priority, created_at, attempt, wait_reason
  FROM scan_job
 WHERE campaign_id = %s
   AND status = 'QUEUED'
   AND dispatch_block_reasons IS NULL
   AND cancel_requested_at IS NULL
 ORDER BY priority DESC, created_at ASC, job_id ASC
"""

_DEPS_SQL = """
SELECT d.job_id, d.depends_on_job_id, p.status
  FROM job_dependency d
  JOIN scan_job p ON p.job_id = d.depends_on_job_id
 WHERE d.campaign_id = %s
   AND d.job_id = ANY(%s)
"""

_IN_FLIGHT_SQL = """
SELECT count(*) AS count FROM scan_job
 WHERE campaign_id = %s AND status = ANY(%s)
"""

_DISPATCHED_LAST_MINUTE_SQL = """
SELECT count(*) AS count
  FROM job_status_change s
  JOIN scan_job j ON j.job_id = s.job_id
 WHERE j.campaign_id = %s
   AND s.to_status = 'VALIDATING'
   AND s.created_at > %s
"""


class SchedulerError(RuntimeError):
    """The campaign does not exist or its row cannot be scheduled."""


def _isoformat(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _rows(
    conn: psycopg.Connection[Any], query: str, params: tuple[Any, ...] = ()
) -> list[dict[str, Any]]:
    """Rows as mappings regardless of the connection's own `row_factory`."""
    with conn.cursor(row_factory=dict_row) as cursor:
        cursor.execute(query, params)
        return list(cursor.fetchall())


def _row(
    conn: psycopg.Connection[Any], query: str, params: tuple[Any, ...] = ()
) -> dict[str, Any] | None:
    rows = _rows(conn, query, params)
    return rows[0] if rows else None


class PostgresScheduler:
    """Dispatch decisions on the contract schema; one transaction per tick."""

    def __init__(
        self,
        connect: Callable[[], psycopg.Connection[Any]],
        *,
        now: Callable[[], datetime] = utcnow,
    ) -> None:
        self._connect = connect
        self._now = now

    # --- read side -----------------------------------------------------------------------
    def snapshot(self, campaign_id: str) -> CampaignSnapshot:
        """The campaign row the workflow needs to start (status, objective, policy limits)."""
        with self._connect() as conn:
            row = _row(
                conn,
                """
                SELECT c.campaign_id, c.status, c.objective, p.policy
                  FROM campaign c
                  JOIN policy_snapshot p ON p.policy_version = c.current_policy_version
                 WHERE c.campaign_id = %s
                """,
                (campaign_id,),
            )
            if row is None:
                raise SchedulerError(f"campaign {campaign_id} does not exist")
            policy = row["policy"] or {}
            pending = _row(
                conn,
                """
                SELECT array_agg(job_id ORDER BY created_at, job_id) AS ids
                  FROM scan_job
                 WHERE campaign_id = %s AND status = ANY(%s)
                """,
                (campaign_id, list(IN_FLIGHT_STATUSES)),
            )
        budget = policy.get("budget") or {}
        idle = int(budget.get("idle_cycles_before_pause") or 3)
        return CampaignSnapshot(
            campaign_id=str(row["campaign_id"]),
            status=str(row["status"]),
            objective=str(row["objective"]),
            max_parallel_jobs=int(policy.get("max_parallel_jobs") or 1),
            idle_cycles_before_pause=idle,
            pending_job_ids=tuple(str(item) for item in ((pending or {}).get("ids") or ())),
        )

    # --- scheduling ----------------------------------------------------------------------
    def dispatch(self, campaign_id: str) -> DispatchPlan:
        """Evaluate every gate, write the wait reasons and claim the dispatchable jobs."""
        moment = self._now()
        with self._connect() as conn, conn.transaction():
            campaign = _row(conn, _CAMPAIGN_SQL, (campaign_id,))
            if campaign is None:
                raise SchedulerError(f"campaign {campaign_id} does not exist")
            status = str(campaign["status"])
            policy: Mapping[str, Any] = campaign["policy"] or {}

            queue = _rows(conn, _QUEUE_SQL, (campaign_id,))
            in_flight = self._in_flight(conn, campaign_id)

            if status in TERMINAL_STATUSES:
                return DispatchPlan(
                    campaign_id=campaign_id,
                    status=status,
                    queued=len(queue),
                    in_flight=in_flight,
                    stop=f"campaign_{status.lower()}",
                )

            dependency = self._dependency_reasons(conn, campaign_id, queue)
            waiting: list[BlockedJob] = []
            ready: list[Mapping[str, Any]] = []
            for job in queue:
                reason = dependency.get(str(job["job_id"]))
                if reason is None:
                    ready.append(job)
                else:
                    waiting.append(
                        self._write_reason(
                            conn, job, reason.code, reason.detail, reason.blocking_job_ids, moment
                        )
                    )

            if status == "PAUSED":
                blocked = self._block_all(
                    conn, ready, "CAMPAIGN_PAUSED", f"campaign {campaign_id} is paused", moment
                )
                return DispatchPlan(
                    campaign_id=campaign_id,
                    status=status,
                    paused=True,
                    waiting=tuple(waiting + blocked),
                    queued=len(queue),
                    in_flight=in_flight,
                )

            budget = self._duration_budget_exhausted(campaign, policy, moment)
            if budget is not None:
                blocked = self._block_all(conn, ready, "BUDGET_EXHAUSTED", budget, moment)
                return DispatchPlan(
                    campaign_id=campaign_id,
                    status=status,
                    waiting=tuple(waiting + blocked),
                    queued=len(queue),
                    in_flight=in_flight,
                    stop="duration_budget_exhausted",
                )

            if not windows_open(policy, moment):
                blocked = self._block_all(
                    conn,
                    ready,
                    "WINDOW_CLOSED",
                    "outside the campaign allowed windows or inside a blackout window",
                    moment,
                )
                return DispatchPlan(
                    campaign_id=campaign_id,
                    status=status,
                    waiting=tuple(waiting + blocked),
                    queued=len(queue),
                    in_flight=in_flight,
                )

            max_parallel = int(policy.get("max_parallel_jobs") or 1)
            slots = max(0, max_parallel - in_flight)
            rate_limits = policy.get("rate_limits") or {}
            per_minute = rate_limits.get("jobs_per_minute")
            rate_left: int | None = None
            if isinstance(per_minute, int):
                already = self._dispatched_last_minute(conn, campaign_id, moment)
                rate_left = max(0, per_minute - already)

            claimed: list[str] = []
            for candidate in ready:
                job_id = str(candidate["job_id"])
                if slots <= 0:
                    waiting.append(
                        self._write_reason(
                            conn,
                            candidate,
                            "CONCURRENCY_LIMIT",
                            f"{in_flight + len(claimed)} of {max_parallel} parallel jobs "
                            "are in flight",
                            (),
                            moment,
                        )
                    )
                    continue
                if rate_left is not None and rate_left <= 0:
                    waiting.append(
                        self._write_reason(
                            conn,
                            candidate,
                            "RATE_LIMITED",
                            f"{per_minute} dispatch(es) already started in the last minute",
                            (),
                            moment,
                        )
                    )
                    continue
                if self._claim(conn, job_id):
                    claimed.append(job_id)
                    slots -= 1
                    if rate_left is not None:
                        rate_left -= 1

            return DispatchPlan(
                campaign_id=campaign_id,
                status=status,
                claimed=tuple(claimed),
                waiting=tuple(waiting),
                queued=len(queue),
                in_flight=in_flight + len(claimed),
            )

    # --- cancellation and terminal state -------------------------------------------------
    def cancel_jobs(self, campaign_id: str, reason: str | None = None) -> CancelOutcome:
        """Record the cancel intent and terminalise QUEUED jobs (C06: intent first)."""
        canceled: list[str] = []
        requested: list[str] = []
        with self._connect() as conn, conn.transaction():
            rows = _rows(
                conn,
                """
                SELECT job_id, status, generation, attempt
                  FROM scan_job
                 WHERE campaign_id = %s AND status <> ALL(%s)
                 ORDER BY created_at, job_id
                   FOR UPDATE
                """,
                (campaign_id, list(TERMINAL_STATUSES)),
            )
            for row in rows:
                job_id = str(row["job_id"])
                outcome = conn.execute(
                    "SELECT aegis.request_job_cancel(%s, %s, %s)",
                    (job_id, Jsonb(dict(MODULE_ACTOR)), reason),
                ).fetchone()
                if str(row["status"]) == "QUEUED":
                    # There is no runner to stop: record the intent, then the one terminal CAS.
                    # A terminal job cannot carry a wait reason (0014 constraint), and the
                    # scheduler may have written one before the cancel arrived.
                    conn.execute(
                        "UPDATE scan_job SET wait_reason = NULL WHERE job_id = %s", (job_id,)
                    )
                    conn.execute(
                        "SELECT aegis.record_job_callback(%s, %s, %s, 'CANCELLED')",
                        (job_id, row["generation"], row["attempt"]),
                    )
                    canceled.append(job_id)
                elif outcome is not None and str(outcome[0]) == "requested":
                    requested.append(job_id)
        return CancelOutcome(
            canceled_job_ids=tuple(canceled), cancel_requested_job_ids=tuple(requested)
        )

    def finish(
        self, campaign_id: str, action: str, reason: str, *, trace_id: str | None = None
    ) -> bool:
        """Move the campaign to a workflow-owned state (`start`, `complete`, `fail`, `cancel`)."""
        with self._connect() as conn, conn.transaction():
            changed = campaign_status.apply_workflow_action(
                conn,
                campaign_id=campaign_id,
                action=action,
                reason=reason,
                actor=MODULE_ACTOR,
                trace_id=trace_id or uuid.uuid4().hex,
            )
        return bool(changed)

    # --- internals -----------------------------------------------------------------------
    def _in_flight(self, conn: psycopg.Connection[Any], campaign_id: str) -> int:
        row = _row(conn, _IN_FLIGHT_SQL, (campaign_id, list(IN_FLIGHT_STATUSES)))
        return int(row["count"]) if row is not None else 0

    def _dispatched_last_minute(
        self, conn: psycopg.Connection[Any], campaign_id: str, moment: datetime
    ) -> int:
        row = _row(conn, _DISPATCHED_LAST_MINUTE_SQL, (campaign_id, moment - timedelta(minutes=1)))
        return int(row["count"]) if row is not None else 0

    @staticmethod
    def _duration_budget_exhausted(
        campaign: Mapping[str, Any], policy: Mapping[str, Any], moment: datetime
    ) -> str | None:
        hours = policy.get("max_duration_hours")
        if not isinstance(hours, int):
            return None
        started = campaign["started_at"] or campaign["created_at"]
        if not isinstance(started, datetime):  # pragma: no cover - column is timestamptz
            return None
        if moment - started >= timedelta(hours=hours):
            return (
                f"campaign duration budget max_duration_hours={hours} is used up "
                f"(started {_isoformat(started)})"
            )
        return None

    def _dependency_reasons(
        self,
        conn: psycopg.Connection[Any],
        campaign_id: str,
        queue: Sequence[Mapping[str, Any]],
    ) -> dict[str, BlockedJob]:
        if not queue:
            return {}
        ids = [str(job["job_id"]) for job in queue]
        rows = _rows(conn, _DEPS_SQL, (campaign_id, ids))
        dependencies: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for row in rows:
            dependencies[str(row["job_id"])].append(
                (str(row["depends_on_job_id"]), str(row["status"]))
            )
        reasons: dict[str, BlockedJob] = {}
        for job_id, predecessors in dependencies.items():
            failed = [pid for pid, state in predecessors if state in ("FAILED", "CANCELLED")]
            if failed:
                states = ", ".join(
                    f"{pid} {dict(predecessors)[pid]}".strip() for pid in sorted(failed)
                )
                reasons[job_id] = BlockedJob(
                    job_id=job_id,
                    code="DEPENDENCY_FAILED",
                    detail=f"predecessor did not succeed: {states}",
                    blocking_job_ids=tuple(sorted(failed)),
                )
                continue
            pending = [pid for pid, state in predecessors if state != "SUCCEEDED"]
            if pending:
                reasons[job_id] = BlockedJob(
                    job_id=job_id,
                    code="DEPENDENCY_PENDING",
                    detail=f"waiting for {len(pending)} predecessor(s) to succeed",
                    blocking_job_ids=tuple(sorted(pending)),
                )
        return reasons

    def _block_all(
        self,
        conn: psycopg.Connection[Any],
        jobs: Sequence[Mapping[str, Any]],
        code: str,
        detail: str,
        moment: datetime,
    ) -> list[BlockedJob]:
        return [self._write_reason(conn, job, code, detail, (), moment) for job in jobs]

    def _write_reason(
        self,
        conn: psycopg.Connection[Any],
        job: Mapping[str, Any],
        code: str,
        detail: str,
        blocking: tuple[str, ...],
        moment: datetime,
    ) -> BlockedJob:
        """Persist one wait reason; an unchanged reason keeps its original `since`."""
        job_id = str(job["job_id"])
        reason: dict[str, Any] = {"code": code, "detail": detail}
        if blocking:
            reason["blocking_job_ids"] = list(blocking)
        existing = job.get("wait_reason")
        if isinstance(existing, Mapping) and (
            existing.get("code") == code
            and existing.get("detail") == detail
            and tuple(existing.get("blocking_job_ids") or ()) == blocking
            and isinstance(existing.get("since"), str)
        ):
            reason["since"] = existing["since"]
        else:
            reason["since"] = _isoformat(moment)
        conn.execute(
            """
            UPDATE scan_job
               SET wait_reason = %s
             WHERE job_id = %s AND status = 'QUEUED' AND wait_reason IS DISTINCT FROM %s
            """,
            (Jsonb(reason), job_id, Jsonb(reason)),
        )
        return BlockedJob(job_id=job_id, code=code, detail=detail, blocking_job_ids=blocking)

    @staticmethod
    def _claim(conn: psycopg.Connection[Any], job_id: str) -> bool:
        row = conn.execute(
            """
            UPDATE scan_job
               SET status = 'VALIDATING', wait_reason = NULL
             WHERE job_id = %s
               AND status = 'QUEUED'
               AND dispatch_block_reasons IS NULL
               AND cancel_requested_at IS NULL
             RETURNING job_id
            """,
            (job_id,),
        ).fetchone()
        if row is None:
            return False
        conn.execute(
            """
            INSERT INTO job_status_change (job_id, seq, from_status, to_status)
            SELECT %s, coalesce(max(seq), 0) + 1, 'QUEUED', 'VALIDATING'
              FROM job_status_change WHERE job_id = %s
            """,
            (job_id, job_id),
        )
        return True
