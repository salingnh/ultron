"""M02 scheduler acceptance: priority, dependency, budget/rate/concurrency, wait reasons."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from psycopg.rows import dict_row

from tests.db_support import (
    connect,
    migrated_database,
    policy_document,
    requires_postgres,
    seed_campaign,
)
from tests.m02_support import (
    FixedClock,
    accept_job,
    adopt_policy,
    complete_job,
    run_job,
    scheduler_for,
    service,
    set_campaign_status,
    wait_reason,
)

pytestmark = requires_postgres


def _queued(dsn: str, campaign_id: str) -> list[str]:
    with connect(dsn) as conn:
        rows = conn.execute(
            "SELECT job_id FROM scan_job WHERE campaign_id = %s AND status = 'QUEUED' "
            "ORDER BY priority DESC, created_at, job_id",
            (campaign_id,),
        ).fetchall()
    return [str(row[0]) for row in rows]


def _status(dsn: str, job_id: str) -> str:
    with connect(dsn) as conn:
        row = conn.execute("SELECT status FROM scan_job WHERE job_id = %s", (job_id,)).fetchone()
    assert row is not None
    return str(row[0])


def _history(dsn: str, job_id: str) -> list[tuple[str, str]]:
    with connect(dsn) as conn:
        rows = conn.execute(
            "SELECT from_status, to_status FROM job_status_change WHERE job_id = %s ORDER BY seq",
            (job_id,),
        ).fetchall()
    return [(str(row[0]), str(row[1])) for row in rows]


def test_priority_order_claims_and_a_dependency_is_never_overtaken() -> None:
    """A higher-priority dependent job waits for its predecessor before any lower-priority job."""
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn, policy=policy_document(max_parallel_jobs=10))
        with service(dsn) as jobs:
            parent = accept_job(jobs, campaign, priority=10)
            dependent = accept_job(jobs, campaign, priority=99, depends_on=[parent])
            independent = accept_job(jobs, campaign, priority=90)
        clock = FixedClock()
        with scheduler_for(dsn, clock) as scheduler:
            first = scheduler.dispatch(campaign.campaign_id)
            # priority DESC: 90 independent, 10 parent; the 99 dependent waits for its predecessor.
            assert first.claimed == (independent, parent)
            assert [(blocked.job_id, blocked.code) for blocked in first.waiting] == [
                (dependent, "DEPENDENCY_PENDING")
            ]
            assert first.waiting[0].blocking_job_ids == (parent,)
            reason = wait_reason(dsn, dependent)
            assert reason is not None and reason["code"] == "DEPENDENCY_PENDING"
            assert _status(dsn, parent) == "VALIDATING"

            # The predecessor is not SUCCEEDED yet: another tick still refuses to overtake.
            again = scheduler.dispatch(campaign.campaign_id)
            assert again.claimed == ()

            run_job(dsn, parent)
            assert complete_job(dsn, parent) == "terminalized"
            three = scheduler.dispatch(campaign.campaign_id)
            assert three.claimed == (dependent,)
            assert wait_reason(dsn, dependent) is None
            assert _history(dsn, dependent) == [("QUEUED", "VALIDATING")]


def test_failed_predecessor_leaves_the_dependent_waiting_with_a_reason() -> None:
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn)
        with service(dsn) as jobs:
            parent = accept_job(jobs, campaign)
            dependent = accept_job(jobs, campaign, priority=100, depends_on=[parent])
        with scheduler_for(dsn) as scheduler:
            assert scheduler.dispatch(campaign.campaign_id).claimed == (parent,)
            run_job(dsn, parent)
            assert complete_job(dsn, parent, "FAILED") == "terminalized"
            plan = scheduler.dispatch(campaign.campaign_id)
        assert plan.claimed == ()
        blocked = {item.job_id: item for item in plan.waiting}
        assert blocked[dependent].code == "DEPENDENCY_FAILED"
        assert blocked[dependent].blocking_job_ids == (parent,)
        reason = wait_reason(dsn, dependent)
        assert reason is not None and reason["code"] == "DEPENDENCY_FAILED"
        assert _status(dsn, dependent) == "QUEUED"


def test_paused_campaign_claims_nothing_and_reports_the_reason() -> None:
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn)
        with service(dsn) as jobs:
            job = accept_job(jobs, campaign)
        set_campaign_status(dsn, campaign.campaign_id, "PAUSED", "operator pause")
        with scheduler_for(dsn) as scheduler:
            plan = scheduler.dispatch(campaign.campaign_id)
        assert plan.paused is True and plan.claimed == ()
        assert [(item.job_id, item.code) for item in plan.waiting] == [(job, "CAMPAIGN_PAUSED")]
        assert wait_reason(dsn, job) is not None


def test_duration_budget_blocks_dispatch_and_stops_the_workflow() -> None:
    # The campaign started nine hours before the instant the scheduler decides at: both times come
    # from the same injected clock (`FixedClock`), so the test does not depend on the wall clock it
    # runs at (the database's `now()` is a second clock and must not be mixed in).
    clock = FixedClock(datetime(2026, 11, 24, 3, 0, tzinfo=UTC))
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn, policy=policy_document(max_duration_hours=8))
        with service(dsn) as jobs:
            job = accept_job(jobs, campaign)
        with connect(dsn) as conn, conn.transaction():
            conn.execute(
                "UPDATE campaign SET started_at = %s WHERE campaign_id = %s",
                (clock() - timedelta(hours=9), campaign.campaign_id),
            )
        with scheduler_for(dsn, clock) as scheduler:
            plan = scheduler.dispatch(campaign.campaign_id)
        assert plan.stop == "duration_budget_exhausted"
        assert plan.claimed == ()
        assert [(item.job_id, item.code) for item in plan.waiting] == [(job, "BUDGET_EXHAUSTED")]


def test_concurrency_limit_releases_the_next_job_when_one_finishes() -> None:
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn, policy=policy_document(max_parallel_jobs=1))
        with service(dsn) as jobs:
            first = accept_job(jobs, campaign, priority=80)
            second = accept_job(jobs, campaign, priority=20)
        with scheduler_for(dsn) as scheduler:
            plan = scheduler.dispatch(campaign.campaign_id)
            assert plan.claimed == (first,)
            assert plan.in_flight == 1
            assert [(item.job_id, item.code) for item in plan.waiting] == [
                (second, "CONCURRENCY_LIMIT")
            ]
            assert wait_reason(dsn, second) is not None
            run_job(dsn, first)
            assert complete_job(dsn, first) == "terminalized"
            after = scheduler.dispatch(campaign.campaign_id)
        assert after.claimed == (second,)
        assert wait_reason(dsn, second) is None


def test_rate_limit_blocks_after_the_per_minute_allowance() -> None:
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn, policy=policy_document(max_parallel_jobs=10))
        with service(dsn) as jobs:
            first = accept_job(jobs, campaign, priority=90)
            second = accept_job(jobs, campaign, priority=10)
        # M05 already enforces the acceptance rate; the dispatch rate is a separate gate, so the
        # policy is adopted after both jobs were accepted.
        adopt_policy(
            dsn, campaign.campaign_id, max_parallel_jobs=10, rate_limits={"jobs_per_minute": 1}
        )
        with scheduler_for(dsn) as scheduler:
            plan = scheduler.dispatch(campaign.campaign_id)
            assert plan.claimed == (first,)
            blocked = {item.job_id: item for item in plan.waiting}
            assert blocked[second].code == "RATE_LIMITED"


def test_held_jobs_are_not_in_the_dispatchable_queue_and_get_no_wait_reason() -> None:
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn)
        with service(dsn) as jobs:
            healthy = accept_job(jobs, campaign, priority=10)
            held = accept_job(jobs, campaign, priority=90)
        # The hold is immutable through `cols_only` (0014) and in production only the migration
        # backfill writes it, so the test briefly disables that one guard on its own throwaway
        # database to reproduce the legacy row shape the scheduler must exclude.
        with connect(dsn) as conn, conn.transaction():
            conn.execute("ALTER TABLE scan_job DISABLE TRIGGER cols_only")
            conn.execute(
                "UPDATE scan_job SET dispatch_block_reasons = ARRAY['LEGACY_ACTOR'] "
                "WHERE job_id = %s",
                (held,),
            )
            conn.execute("ALTER TABLE scan_job ENABLE TRIGGER cols_only")
        with scheduler_for(dsn) as scheduler:
            plan = scheduler.dispatch(campaign.campaign_id)
        assert plan.claimed == (healthy,)
        assert [item.job_id for item in plan.waiting] == []
        assert wait_reason(dsn, held) is None
        assert _status(dsn, held) == "QUEUED"


def test_an_unchanged_wait_reason_keeps_its_first_since_timestamp() -> None:
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn)
        with service(dsn) as jobs:
            job = accept_job(jobs, campaign)
        set_campaign_status(dsn, campaign.campaign_id, "PAUSED", "pause")
        clock = FixedClock(datetime(2026, 11, 24, 3, 0, tzinfo=UTC))
        with scheduler_for(dsn, clock) as scheduler:
            scheduler.dispatch(campaign.campaign_id)
            first = wait_reason(dsn, job)
            clock.moment = clock.moment + timedelta(seconds=30)
            scheduler.dispatch(campaign.campaign_id)
            second = wait_reason(dsn, job)
        assert first is not None and second is not None
        assert first["since"] == second["since"]
        assert second["since"] == "2026-11-24T03:00:00Z"


def test_cancel_intent_terminalises_queued_jobs_and_marks_running_ones() -> None:
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn, policy=policy_document(max_parallel_jobs=1))
        with service(dsn) as jobs:
            queued = accept_job(jobs, campaign, priority=10)
            running = accept_job(jobs, campaign, priority=90)
        with scheduler_for(dsn) as scheduler:
            # max_parallel_jobs=1: only the higher-priority job is claimed; the other stays QUEUED.
            assert scheduler.dispatch(campaign.campaign_id).claimed == (running,)
            run_job(dsn, running)
            outcome = scheduler.cancel_jobs(campaign.campaign_id, "operator cancel")
        assert running in outcome.cancel_requested_job_ids
        assert _status(dsn, running) == "RUNNING"
        assert queued in outcome.canceled_job_ids
        assert _status(dsn, queued) == "CANCELLED"


def test_workflow_actions_write_campaign_history_and_stop_at_terminal() -> None:
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn, status="CREATED")
        with scheduler_for(dsn) as scheduler:
            snapshot = scheduler.snapshot(campaign.campaign_id)
            assert snapshot.status == "CREATED"
            assert scheduler.finish(campaign.campaign_id, "start", "workflow started") is True
            assert scheduler.finish(campaign.campaign_id, "complete", "objective_done") is True
            assert scheduler.finish(campaign.campaign_id, "complete", "objective_done") is False
        with connect(dsn) as conn, conn.cursor(row_factory=dict_row) as cursor:
            row = cursor.execute(
                "SELECT status, status_reason, started_at, ended_at FROM campaign "
                "WHERE campaign_id = %s",
                (campaign.campaign_id,),
            ).fetchone()
            history = cursor.execute(
                "SELECT from_status, to_status, actor->>'id' AS actor_id "
                "FROM campaign_status_change WHERE campaign_id = %s ORDER BY seq",
                (campaign.campaign_id,),
            ).fetchall()
            audits = cursor.execute(
                "SELECT action FROM audit_log WHERE campaign_id = %s ORDER BY occurred_at",
                (campaign.campaign_id,),
            ).fetchall()
        assert row is not None
        assert row["status"] == "COMPLETED" and row["status_reason"] == "objective_done"
        assert row["started_at"] is not None and row["ended_at"] is not None
        assert [(item["from_status"], item["to_status"], item["actor_id"]) for item in history] == [
            ("CREATED", "RUNNING", "M02"),
            ("RUNNING", "COMPLETED", "M02"),
        ]
        assert [item["action"] for item in audits] == ["campaign.start", "campaign.complete"]


def test_unknown_campaign_is_an_error() -> None:
    from aegis.m02_orchestrator.scheduler import SchedulerError

    with migrated_database() as dsn:
        with scheduler_for(dsn) as scheduler:
            with pytest.raises(SchedulerError):
                scheduler.dispatch(str(uuid.uuid4()))


def test_m05_cancel_of_a_queued_job_with_a_wait_reason_clears_it_first() -> None:
    """G1.1d interaction: a QUEUED job may carry a wait reason, which 0014 forbids after cancel."""
    campaign = None
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn, policy=policy_document(max_parallel_jobs=1))
        with service(dsn) as jobs:
            busy = accept_job(jobs, campaign, priority=90)
            waiting = accept_job(jobs, campaign, priority=10)
            with scheduler_for(dsn) as scheduler:
                assert scheduler.dispatch(campaign.campaign_id).claimed == (busy,)
            assert wait_reason(dsn, waiting) is not None
            canceled = jobs.cancel(
                waiting, requested_by={"kind": "operator", "id": "op-m02"}, reason="test"
            )
        assert canceled["status"] == "CANCELLED"
        assert wait_reason(dsn, waiting) is None


def test_dispatch_reports_every_pending_job_of_the_campaign() -> None:
    """`DispatchPlan.pending` is what keeps the workflow from starting a session while a job runs.

    It must come from the committed rows (a job claimed in this tick, a job still QUEUED, a job in
    flight) and must drop a job as soon as it is terminal: a signal that arrives while the campaign
    is between ticks would otherwise leave the loop waiting for an event that already happened.
    """
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn, policy=policy_document(max_parallel_jobs=1))
        with service(dsn) as jobs:
            first = accept_job(jobs, campaign)
            second = accept_job(jobs, campaign, priority=10)
        with scheduler_for(dsn) as scheduler:
            plan = scheduler.dispatch(campaign.campaign_id)
            assert set(plan.pending) == {first, second}
            assert set(plan.claimed) == {first}, "one slot: only the higher priority job runs"

            run_job(dsn, first)
            complete_job(dsn, first)
            plan = scheduler.dispatch(campaign.campaign_id)
            assert first not in plan.pending, "a terminal job is not pending"
            assert plan.claimed == (second,)
