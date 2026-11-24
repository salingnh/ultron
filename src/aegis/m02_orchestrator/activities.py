"""Temporal activities of M02 (interfaces/README.md §7) — thin wrappers over the scheduler.

Every activity is idempotent and does its own short database transaction; Temporal may retry it
after a worker crash and the result must be the same. The DSN is configured once by the worker
entry point (`python -m aegis.m02_orchestrator.worker`), or read from `AEGIS_PG_DSN`.

`run_agent_session` is deliberately **not** here: it belongs to M03 (G1.2c) and is registered on the
`aegis-agent` queue. This module only defines the seam (`SessionRequest`/`SessionOutcome`).
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

import psycopg
from temporalio import activity

from . import db
from .scheduler import PostgresScheduler
from .types import CampaignSnapshot, CancelOutcome, DispatchPlan

__all__ = [
    "ACTIVITIES",
    "cancel_jobs",
    "configure",
    "dispatch_ready",
    "finish_campaign",
    "load_campaign",
]

#: Set by the worker entry point; tests set it to the throwaway database before starting a worker.
_dsn: str | None = None
_connect: Callable[[], psycopg.Connection[Any]] | None = None
_scheduler_factory: Callable[[], PostgresScheduler] | None = None


def configure(
    *,
    dsn: str | None = None,
    connect: Callable[[], psycopg.Connection[Any]] | None = None,
    scheduler: Callable[[], PostgresScheduler] | None = None,
) -> None:
    """Point the activities at a database (DSN, a connect factory, or a scheduler factory)."""
    global _dsn, _connect, _scheduler_factory
    _dsn = dsn
    _connect = connect
    _scheduler_factory = scheduler


def _scheduler() -> PostgresScheduler:
    if _scheduler_factory is not None:
        return _scheduler_factory()
    if _connect is not None:
        return PostgresScheduler(_connect)
    return PostgresScheduler(lambda: db.connect(_dsn))


@activity.defn(name="load_campaign")
async def load_campaign(campaign_id: str) -> CampaignSnapshot:
    """Read the campaign row a workflow needs at start-up (status, objective, policy limits)."""
    return _scheduler().snapshot(campaign_id)


@activity.defn(name="dispatch_ready")
async def dispatch_ready(campaign_id: str) -> DispatchPlan:
    """One scheduler tick: write wait reasons and claim the jobs that may start now."""
    return _scheduler().dispatch(campaign_id)


@activity.defn(name="cancel_jobs")
async def cancel_jobs(campaign_id: str, reason: str | None = None) -> CancelOutcome:
    """Record the cancel intent and terminalise QUEUED jobs (C06 intent-first cancellation)."""
    return _scheduler().cancel_jobs(campaign_id, reason)


@activity.defn(name="finish_campaign")
async def finish_campaign(campaign_id: str, action: str, reason: str) -> bool:
    """Apply a workflow-owned campaign transition (start/complete/fail/cancel)."""
    trace_id = uuid.uuid4().hex
    return _scheduler().finish(campaign_id, action, reason, trace_id=trace_id)


#: The activities the orchestrator worker registers (G1.2c adds the session activity to the
#: `aegis-agent` queue, not to this list).
ACTIVITIES: list[Callable[..., Any]] = [
    load_campaign,
    dispatch_ready,
    cancel_jobs,
    finish_campaign,
]
