"""Temporal activities of M02 (interfaces/README.md §7) — thin wrappers over the scheduler.

Every activity is idempotent and does its own short database transaction; Temporal may retry it
after a worker crash and the result must be the same. The DSN is configured once by the worker
entry point (`python -m aegis.m02_orchestrator.worker`), or read from `AEGIS_PG_DSN`.

`run_agent_session` is deliberately **not** here: it belongs to M03 (G1.2c) and is registered on the
`aegis-agent` queue. This module only defines the seam (`SessionRequest`/`SessionOutcome`).
"""

from __future__ import annotations

import logging
import os
import uuid
from collections.abc import Callable
from typing import Any

import psycopg
from temporalio import activity

from . import db
from .finalize import finalize
from .scheduler import PostgresScheduler
from .types import CampaignSnapshot, CancelOutcome, DispatchPlan, FinalCampaign

__all__ = [
    "ACTIVITIES",
    "cancel_jobs",
    "configure",
    "dispatch_ready",
    "finalize_campaign",
    "finish_campaign",
    "load_campaign",
]

#: Set by the worker entry point; tests set it to the throwaway database before starting a worker.
_dsn: str | None = None
_connect: Callable[[], psycopg.Connection[Any]] | None = None
_scheduler_factory: Callable[[], PostgresScheduler] | None = None
_evidence_reader: Callable[[], Any] | None = None
logger = logging.getLogger("aegis.m02.activities")


def configure(
    *,
    dsn: str | None = None,
    connect: Callable[[], psycopg.Connection[Any]] | None = None,
    scheduler: Callable[[], PostgresScheduler] | None = None,
    evidence: Callable[[], Any] | None = None,
) -> None:
    """Point the activities at a database (DSN, a connect factory, or a scheduler factory).

    `evidence` builds the M21 evidence reader (the object store); tests and the demo inject an
    in-memory reader, production reads `AEGIS_S3_ENDPOINT`/`AEGIS_S3_BUCKET`.
    """
    global _dsn, _connect, _scheduler_factory, _evidence_reader
    _dsn = dsn
    _connect = connect
    _scheduler_factory = scheduler
    _evidence_reader = evidence


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
    """One scheduler tick: write wait reasons, claim what may start, and decide verify runs.

    The verification pass is part of this tick because a completed `verify.check` job is a
    *decision* the campaign state depends on (a VERIFIED finding changes the plan the next session
    reads). It is idempotent by job id and a no-op when there is nothing to decide; a decision
    error is logged and left for the next tick, because a broken evidence object must not stop the
    campaign's scheduling loop.
    """
    plan = _scheduler().dispatch(campaign_id)
    decide_verifications(campaign_id)
    return plan


@activity.defn(name="cancel_jobs")
async def cancel_jobs(campaign_id: str, reason: str | None = None) -> CancelOutcome:
    """Record the cancel intent and terminalise QUEUED jobs (C06 intent-first cancellation)."""
    return _scheduler().cancel_jobs(campaign_id, reason)


@activity.defn(name="finish_campaign")
async def finish_campaign(campaign_id: str, action: str, reason: str) -> bool:
    """Apply a workflow-owned campaign transition (start/complete/fail/cancel)."""
    trace_id = uuid.uuid4().hex
    return _scheduler().finish(campaign_id, action, reason, trace_id=trace_id)


@activity.defn(name="finalize_campaign")
async def finalize_campaign(campaign_id: str, proposed: str) -> FinalCampaign:
    """The chain's last step: match the campaign's products, then verify its coverage.

    Runs on one M20 connection (`dict_row`, autocommit, `search_path`), which is what the matcher
    needs; a matching failure is returned, not raised, so the campaign still finishes - with
    `matching_failed` instead of a false `objective_met`.
    """
    from aegis.m20_vuln.matching import connect as matcher_connect

    # A verify job that finished just before the campaign ends is decided first, so the final
    # verdict sees the VERIFIED transition it wrote (and a stale request is still INCONCLUSIVE).
    decide_verifications(campaign_id)
    connection = matcher_connect(_dsn_or_env())
    try:
        return finalize(connection, campaign_id, proposed)
    finally:
        connection.close()


def decide_verifications(campaign_id: str) -> list[dict[str, Any]]:
    """Decide the campaign's completed-but-undecided `verify.check` jobs (M21).

    Returns the written run records (empty on a replay or when there is nothing to decide). Any
    failure is logged and swallowed: the campaign keeps scheduling, the run stays undecided, and
    the operator CLI (`python -m aegis.m21_verify decide --job`) reports the same error loudly.
    """
    from aegis.m20_vuln.matching import connect as matcher_connect
    from aegis.m21_verify import writer as verification

    connection = matcher_connect(_dsn_or_env())
    try:
        if not verification.open_runs(connection, campaign_id):
            return []
        reader = _evidence_reader() if _evidence_reader is not None else None
        if reader is None:
            from aegis.m21_verify.evidence import reader_from_env

            reader = reader_from_env()
        records = verification.decide_campaign(connection, campaign_id, reader=reader)
        return [record.as_dict() for record in records]
    except Exception as error:  # noqa: BLE001 - never take the campaign down for a verify run
        logger.warning(
            "verification decision left for the next tick",
            extra={"campaign_id": campaign_id, "error": f"{type(error).__name__}: {error}"},
        )
        return []
    finally:
        connection.close()


def _dsn_or_env() -> str:
    """The DSN this worker was configured with, else `AEGIS_PG_DSN` (the worker's own rule)."""
    if _dsn:
        return _dsn
    value = os.environ.get("AEGIS_PG_DSN", "")
    if not value:
        raise RuntimeError(
            "the finalize activity needs AEGIS_PG_DSN (or configure(dsn=...)) to run the matcher"
        )
    return value


#: The activities the orchestrator worker registers (G1.2c adds the session activity to the
#: `aegis-agent` queue, not to this list).
ACTIVITIES: list[Callable[..., Any]] = [
    load_campaign,
    dispatch_ready,
    cancel_jobs,
    finalize_campaign,
    finish_campaign,
]
