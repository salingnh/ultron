"""Shared helpers for the M02 (G1.1d) tests: accepted jobs, a controlled clock, fake signals.

Jobs are created through the real M05 acceptance path (`tests.test_m05_service.service`), so the
scheduler is tested against rows the contract actually produces (decision, signed task, pins,
target refs) instead of hand-inserted fixtures. Every test owns a throwaway database.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from psycopg.types.json import Jsonb

from aegis.m02_orchestrator.scheduler import PostgresScheduler
from aegis.m02_orchestrator.signals import WorkflowSignals
from tests.db_support import OPERATOR, SeededCampaign, connect, policy_document
from tests.test_m05_service import body, service

__all__ = [
    "FixedClock",
    "RecordingSignals",
    "accept_job",
    "adopt_policy",
    "complete_job",
    "open_policy",
    "run_job",
    "scheduler_for",
    "service",
    "set_campaign_status",
    "wait_reason",
]


def open_policy(**overrides: Any) -> dict[str, Any]:
    """A valid roe-policy.v2 document with the sample windows removed (tests opt in per case)."""
    document = policy_document()
    document.pop("allowed_windows", None)
    document.pop("blackout_windows", None)
    document.update(overrides)
    return document


@dataclass
class FixedClock:
    moment: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __call__(self) -> datetime:
        return self.moment


@contextmanager
def scheduler_for(dsn: str, clock: Any = None) -> Iterator[PostgresScheduler]:
    yield PostgresScheduler(lambda: connect(dsn), now=clock or FixedClock())


def accept_job(jobs: Any, campaign: SeededCampaign, **overrides: Any) -> str:
    """Create one job through M05 and return its id."""
    outcome = jobs.submit(
        body(campaign, **overrides),
        requested_by=OPERATOR,
        idempotency_key=f"m02-{uuid.uuid4()}",
    )
    return str(outcome.job["job_id"])


def run_job(dsn: str, job_id: str) -> None:
    """Move a claimed job to RUNNING the way M06 would (attempt unchanged on first dispatch)."""
    with connect(dsn) as conn, conn.transaction():
        conn.execute(
            "UPDATE scan_job SET status = 'RUNNING', started_at = now() WHERE job_id = %s",
            (job_id,),
        )
        conn.execute(
            """
            INSERT INTO job_status_change (job_id, seq, from_status, to_status)
            SELECT %s, coalesce(max(seq), 0) + 1, 'VALIDATING', 'RUNNING'
              FROM job_status_change WHERE job_id = %s
            """,
            (job_id, job_id),
        )


def complete_job(
    dsn: str,
    job_id: str,
    status: str = "SUCCEEDED",
    attempt: int = 1,
    generation: int = 1,
    error: dict[str, Any] | None = None,
) -> str:
    """Terminalise a job through the contract CAS; FAILED needs an error object (0001 CHECK)."""
    if status == "FAILED" and error is None:
        error = {
            "code": "TOOL_ERROR",
            "message": "job failed in the M02 scheduler test",
            "trace_id": uuid.uuid4().hex,
        }
    with connect(dsn) as conn, conn.transaction():
        row = conn.execute(
            "SELECT aegis.record_job_callback(%s, %s, %s, %s, NULL, %s)",
            (job_id, generation, attempt, status, Jsonb(error) if error is not None else None),
        ).fetchone()
    assert row is not None
    return str(row[0])


def adopt_policy(dsn: str, campaign_id: str, **overrides: Any) -> str:
    """Append a v2 policy snapshot and make it current (the M01 adopt operation, test form)."""
    document = open_policy(**overrides)
    with connect(dsn) as conn, conn.transaction():
        row = conn.execute("SELECT aegis.next_policy_version()").fetchone()
        assert row is not None
        version = str(row[0])
        conn.execute(
            "INSERT INTO policy_snapshot "
            "(policy_version, campaign_id, policy, policy_hash, created_by) "
            "VALUES (%s, %s, %s, aegis.policy_hash(%s), %s)",
            (version, campaign_id, Jsonb(document), Jsonb(document), Jsonb(OPERATOR)),
        )
        conn.execute(
            "UPDATE campaign SET current_policy_version = %s WHERE campaign_id = %s",
            (version, campaign_id),
        )
    return version


def set_campaign_status(dsn: str, campaign_id: str, status: str, reason: str | None = None) -> None:
    with connect(dsn) as conn, conn.transaction():
        conn.execute(
            "UPDATE campaign SET status = %s, status_reason = %s WHERE campaign_id = %s",
            (status, reason, campaign_id),
        )


def wait_reason(dsn: str, job_id: str) -> dict[str, Any] | None:
    with connect(dsn) as conn:
        row = conn.execute(
            "SELECT wait_reason FROM scan_job WHERE job_id = %s", (job_id,)
        ).fetchone()
    assert row is not None
    return dict(row[0]) if row[0] is not None else None


def start_campaign_row(dsn: str, campaign_id: str, status: str = "RUNNING") -> None:
    with connect(dsn) as conn, conn.transaction():
        conn.execute(
            "UPDATE campaign SET status = %s, started_at = now() WHERE campaign_id = %s",
            (status, campaign_id),
        )


class RecordingSignals(WorkflowSignals):
    """A `WorkflowSignals` that records calls; `fail_on` makes the next call raise."""

    def __init__(self) -> None:
        self.started: list[str] = []
        self.statuses: list[tuple[str, str, str | None]] = []
        self.completed: list[tuple[str, str, str]] = []
        self.present: set[str] = set()
        self.fail_with: Exception | None = None

    async def ensure_started(self, campaign_id: str) -> bool:
        self.started.append(campaign_id)
        self.present.add(campaign_id)
        return True

    async def signal_status(self, campaign_id: str, status: str, reason: str | None = None) -> bool:
        if self.fail_with is not None:
            raise self.fail_with
        self.statuses.append((campaign_id, status, reason))
        return campaign_id in self.present

    async def job_completed(self, campaign_id: str, job_id: str, status: str) -> bool:
        if self.fail_with is not None:
            raise self.fail_with
        self.completed.append((campaign_id, job_id, status))
        return campaign_id in self.present


def insert_outbox_event(
    dsn: str,
    *,
    event_type: str,
    campaign_id: str,
    payload: Mapping[str, Any],
    dedup_key: str | None = None,
) -> int:
    """Append an event the way M06 does (the allocator assigns the publication sequence)."""
    with connect(dsn) as conn, conn.transaction():
        row = conn.execute(
            """
            INSERT INTO outbox_event
                (event_id, type, producer, dedup_key, campaign_id, payload, trace)
            VALUES (%s, %s, 'M06', %s, %s, %s, %s)
            RETURNING seq
            """,
            (
                uuid.uuid4(),
                event_type,
                dedup_key or str(uuid.uuid4()),
                campaign_id,
                Jsonb(dict(payload)),
                Jsonb({"trace_id": uuid.uuid4().hex, "campaign_id": campaign_id}),
            ),
        ).fetchone()
    assert row is not None
    return int(row[0])
