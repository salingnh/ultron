"""M06 job lifecycle in PostgreSQL: the M02 → M06 seam and the one terminal callback (C06).

The scheduler leaves a dispatched job in `VALIDATING` (interfaces/README.md §Scheduling, G1.1d).
M06 is the component that runs it and the only one that terminalizes:

    VALIDATING --claim--> DISPATCHED --running--> RUNNING --collecting--> COLLECTING
        |                    |                       |
        +--------------------+-----------------------+--> SUCCEEDED | FAILED | CANCELLED
                                                          (aegis.record_job_callback)

Every transition writes its `job_status_change` row in the same transaction. The terminal step is
the contract's compare-and-set on `(generation, attempt)`: `record_job_callback` returns
`terminalized`, `duplicate` (the exact result is already recorded) or `quarantined` (a stale or
conflicting callback), and the envelope's `event_id` is passed on so the job row references the
accepted ingestion receipt (`scan_job.envelope_event_id` → `ingestion_inbox`).

The claim is conditional on `status = 'VALIDATING'` and on `cancel_requested_at IS NULL`, so a
cancel intent recorded before the container starts wins: M06 never runs a job whose cancellation
was already asked for, it terminalizes it as CANCELLED.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

TERMINAL_DB_STATUSES = frozenset({"SUCCEEDED", "FAILED", "CANCELLED"})
CALLBACK_RESULTS = frozenset({"terminalized", "duplicate", "quarantined"})
DSN_ENV = "AEGIS_PG_DSN"
SEARCH_PATH = "SET search_path = aegis, public"
STATEMENT_TIMEOUT_ENV = "AEGIS_M06_STATEMENT_TIMEOUT_MS"
DEFAULT_STATEMENT_TIMEOUT_MS = 15_000


class LifecycleError(RuntimeError):
    """The lifecycle could not be recorded; the job row is left as it was."""


@dataclass(frozen=True)
class JobClaim:
    """The `(generation, attempt)` fence M06 holds for one run."""

    job_id: str
    generation: int
    attempt: int


def dsn_from_env() -> str:
    dsn = os.environ.get(DSN_ENV)
    if not dsn:
        raise LifecycleError(f"{DSN_ENV} is not set: M06 needs the control-plane PostgreSQL DSN")
    return dsn


def connect(dsn: str | None = None) -> psycopg.Connection[Any]:
    """An autocommit session pinned to the schema, with a bounded statement timeout."""
    conn = psycopg.connect(dsn or dsn_from_env(), autocommit=True)
    try:
        conn.execute(SEARCH_PATH)
        timeout = int(os.environ.get(STATEMENT_TIMEOUT_ENV, DEFAULT_STATEMENT_TIMEOUT_MS))
        conn.execute(f"SET statement_timeout = {max(1, timeout)}")
    except BaseException:  # pragma: no cover - a failed connect must not leak a session
        conn.close()
        raise
    return conn


class JobLifecycle:
    """The job-row transitions M06 owns, one short transaction each."""

    def __init__(self, connect: Callable[[], psycopg.Connection[Any]]) -> None:
        self._connect = connect

    @classmethod
    def from_dsn(cls, dsn: str | None = None) -> JobLifecycle:
        target = dsn or dsn_from_env()
        return cls(lambda: connect(target))

    # -- transitions ------------------------------------------------------------------------

    def claim(self, job_id: str) -> JobClaim | None:
        """Take a `VALIDATING` job, or return None when it is no longer M06's to run."""
        with self._connect() as conn, conn.transaction():
            row = conn.execute(
                """
                UPDATE scan_job
                   SET status = 'DISPATCHED', started_at = coalesce(started_at, now())
                 WHERE job_id = %s
                   AND status = 'VALIDATING'
                   AND cancel_requested_at IS NULL
                 RETURNING generation, attempt
                """,
                (job_id,),
            ).fetchone()
            if row is None:
                return None
            _record_status(conn, job_id, "VALIDATING", "DISPATCHED")
            return JobClaim(job_id=job_id, generation=int(row[0]), attempt=int(row[1]))

    def running(self, claim: JobClaim) -> bool:
        """`DISPATCHED → RUNNING` once the container of this attempt is up."""
        return self._move(claim, "DISPATCHED", "RUNNING")

    def collecting(self, claim: JobClaim) -> bool:
        """`RUNNING → COLLECTING` before the collector reads the output."""
        return self._move(claim, "RUNNING", "COLLECTING")

    def _move(self, claim: JobClaim, source: str, target: str) -> bool:
        with self._connect() as conn, conn.transaction():
            row = conn.execute(
                """
                UPDATE scan_job
                   SET status = %s
                 WHERE job_id = %s AND status = %s AND generation = %s AND attempt = %s
                 RETURNING job_id
                """,
                (target, claim.job_id, source, claim.generation, claim.attempt),
            ).fetchone()
            if row is None:
                return False
            _record_status(conn, claim.job_id, source, target)
            return True

    def finish(
        self,
        claim: JobClaim,
        status: str,
        *,
        envelope_event_id: str | None = None,
        error: Mapping[str, Any] | None = None,
        evidence_refs: Iterable[Mapping[str, Any]] = (),
    ) -> str:
        """Terminalize through `aegis.record_job_callback`; returns its verdict."""
        if status not in TERMINAL_DB_STATUSES:
            raise LifecycleError(f"{status!r} is not a terminal status")
        if status == "FAILED" and error is None:
            raise LifecycleError("a FAILED job needs the contract error object")
        with self._connect() as conn, conn.transaction():
            row = conn.execute(
                "SELECT aegis.record_job_callback(%s, %s, %s, %s, %s, %s, NULL, %s, %s)",
                (
                    claim.job_id,
                    claim.generation,
                    claim.attempt,
                    status,
                    envelope_event_id,
                    Jsonb(dict(error)) if error is not None else None,
                    Jsonb({"job_id": claim.job_id, "attempt": claim.attempt}),
                    Jsonb([dict(reference) for reference in evidence_refs]),
                ),
            ).fetchone()
            if row is None:
                raise LifecycleError("record_job_callback returned no verdict")
            verdict = str(row[0])
            if verdict not in CALLBACK_RESULTS:
                raise LifecycleError(f"unexpected record_job_callback verdict {verdict!r}")
            if verdict == "terminalized":
                self._publish_completed(
                    conn,
                    claim,
                    status,
                    envelope_event_id=envelope_event_id,
                    error=error,
                    evidence_refs=evidence_refs,
                )
        return verdict

    @staticmethod
    def _publish_completed(
        conn: psycopg.Connection[Any],
        claim: JobClaim,
        status: str,
        *,
        envelope_event_id: str | None,
        error: Mapping[str, Any] | None,
        evidence_refs: Iterable[Mapping[str, Any]],
    ) -> None:
        """Write `job.completed.v2` in the same transaction as the terminal row.

        M02's dispatcher turns this event into the workflow's `job_completed` signal
        (`m02_orchestrator/outbox.py`), and the contract names M06 the producer of the event
        (`contracts/events/job.completed.v2.schema.json`). Nothing wrote it before the G1.5c demo
        joined the modules, so the signal never arrived; the workflow now also re-reads the
        committed rows every tick, but the event is what the contract and the graph history expect.
        Only the accepted terminal result publishes: a `duplicate` or `quarantined` callback is not
        a new completion, and `ON CONFLICT` keeps a replay idempotent.
        """
        row = conn.execute(
            "SELECT campaign_id FROM scan_job WHERE job_id = %s", (claim.job_id,)
        ).fetchone()
        if row is None:  # pragma: no cover - the callback just updated this row
            raise LifecycleError(f"job {claim.job_id} vanished after its terminal callback")
        payload: dict[str, Any] = {
            "job_id": claim.job_id,
            "campaign_id": str(row[0]),
            "status": status,
            "attempt": claim.attempt,
            "generation": claim.generation,
            "evidence_refs": [
                str(reference.get("evidence_id"))
                for reference in evidence_refs
                if reference.get("evidence_id") is not None
            ],
            "finished_at": _now(),
        }
        if envelope_event_id is not None:
            payload["envelope_event_id"] = envelope_event_id
        if error is not None and status == "FAILED":
            payload["error"] = dict(error)
        conn.execute(
            "INSERT INTO outbox_event (event_id, type, producer, dedup_key, campaign_id, payload,"
            " trace) VALUES (%s, 'job.completed.v2', 'M06', %s, %s, %s, %s)"
            " ON CONFLICT (type, dedup_key) DO NOTHING",
            (
                new_id(),
                f"{claim.job_id}:{claim.generation}:{claim.attempt}",
                str(row[0]),
                Jsonb(payload),
                Jsonb({"job_id": claim.job_id, "attempt": claim.attempt}),
            ),
        )

    # -- reads ------------------------------------------------------------------------------

    def cancel_requested(self, job_id: str) -> bool:
        """True while a non-terminal job carries a cancel intent (M06 then stops the container)."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT cancel_requested_at IS NOT NULL, status FROM scan_job WHERE job_id = %s",
                (job_id,),
            ).fetchone()
        if row is None:
            raise LifecycleError(f"job {job_id} does not exist")
        requested, status = bool(row[0]), str(row[1])
        return requested and status not in TERMINAL_DB_STATUSES

    def status(self, job_id: str) -> str:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT status FROM scan_job WHERE job_id = %s", (job_id,)
            ).fetchone()
        if row is None:
            raise LifecycleError(f"job {job_id} does not exist")
        return str(row[0])


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def new_id() -> str:
    """A UUIDv7: the contract's `Id` shape, minted here so M06 needs no other module for one."""
    millis = int(time.time() * 1000) & ((1 << 48) - 1)
    random_bits = int.from_bytes(os.urandom(10), "big")
    rand_a = random_bits >> 68
    rand_b = random_bits & ((1 << 62) - 1)
    value = (millis << 80) | (0x7 << 76) | (rand_a << 64) | (0b10 << 62) | rand_b
    digits = f"{value:032x}"
    return f"{digits[0:8]}-{digits[8:12]}-{digits[12:16]}-{digits[16:20]}-{digits[20:32]}"


def _record_status(
    conn: psycopg.Connection[Any], job_id: str, from_status: str, to_status: str
) -> None:
    conn.execute(
        """
        INSERT INTO job_status_change (job_id, seq, from_status, to_status)
        SELECT %s, coalesce(max(seq), 0) + 1, %s, %s
          FROM job_status_change WHERE job_id = %s
        """,
        (job_id, from_status, to_status, job_id),
    )


__all__ = [
    "CALLBACK_RESULTS",
    "DEFAULT_STATEMENT_TIMEOUT_MS",
    "DSN_ENV",
    "JobClaim",
    "JobLifecycle",
    "LifecycleError",
    "TERMINAL_DB_STATUSES",
    "connect",
    "dsn_from_env",
]
