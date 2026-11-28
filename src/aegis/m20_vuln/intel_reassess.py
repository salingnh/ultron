"""M20 intel-driven re-assessment (G2 slice C, V4/V5 without alert delivery).

A feed revision can change what a finding means without changing anything the scanner saw: KEV
adds a CVE, EPSS moves, NVD withdraws an advisory, distro fix data retracts a candidate. Slice A's
`graph_revision` never moves for those, so an assessment deduplicated on it would stay stale
forever. This consumer closes that gap the C04 way:

1. it is its own outbox consumer (`m20-severity#g1`) and dispatcher (`m20-severity`), so it can
   checkpoint without sharing M23's or M02's cursor; it takes the dispatcher lease first and a
   second live instance gets `leased = False` instead of processing the same events;
2. it refreshes the publication watermark in its own short transaction and reads
   `aegis.outbox_batch` - published events only, never past the watermark, gaps legal;
3. for every `intel.revision.v2` event it takes the payload's `impacted_ids` and asks the severity
   queue for the open findings whose CVEs intersect them. `input_revision` is content-addressed
   (finding row, evidence runs, intel revisions, match decision), so exactly those findings get a
   new revision; findings of other CVEs keep the stored record and cost nothing;
4. it checkpoints with `aegis.consumer_advance(consumer, seq, dispatcher, fence)` only after the
   batch applied. A crash before the checkpoint replays the batch; the unique
   `(finding_id, input_revision)` of 0012 returns the stored rows, so a replay adds no row and
   calls no model. That is the at-least-once contract, made harmless by the dedup.

**No scan job is created.** The consumer reads the outbox and `finding`/`vulnerability_current`
rows and writes only `severity_assessment`, `agent_session` (the provenance of a model call) and
`finding.severity/current_assessment`; a test asserts `scan_job` is untouched.

The model is the deployment's: `None` means a scripted deployment (every assessment is UNRATED with
the reason), a configured client makes one call per finding whose revision changed. Nothing here
talks to Telegram - delivery is V5's `M24`, not this slice.
"""

from __future__ import annotations

import os
import socket
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import psycopg

from aegis.common.ports import ModelClient
from aegis.m20_vuln import severity

__all__ = [
    "CONSUMER",
    "DISPATCHER",
    "ReassessReport",
    "IntelReassessor",
    "run_once",
]

CONSUMER = "m20-severity#g1"
DISPATCHER = "m20-severity"
EVENT_TYPE = "intel.revision.v2"
DEFAULT_BATCH = 200
LEASE_TTL_SECONDS = 60


@dataclass(frozen=True, slots=True)
class ReassessReport:
    """One consumer pass: what it read, what it assessed and where it checkpointed."""

    leased: bool = False
    fence: int | None = None
    watermark: int = 0
    events: int = 0
    intel_events: int = 0
    impacted_cves: int = 0
    candidates: int = 0
    assessed: int = 0
    created: int = 0
    unrated: int = 0
    model_calls: int = 0
    checkpoint: int | None = None
    error: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {field: getattr(self, field) for field in self.__slots__}


class IntelReassessor:
    """One outbox consumer that re-assesses the findings a feed revision names."""

    def __init__(
        self,
        connection: psycopg.Connection[Any],
        *,
        consumer: str = CONSUMER,
        dispatcher: str = DISPATCHER,
        holder: str | None = None,
        batch: int = DEFAULT_BATCH,
        lease_ttl_seconds: int = LEASE_TTL_SECONDS,
        model: ModelClient | None = None,
        provider: str | None = None,
        model_name: str | None = None,
        prompt_version: str = severity.PROMPT_VERSION,
    ) -> None:
        self._conn = connection
        self._consumer = consumer
        self._dispatcher = dispatcher
        self._holder = holder or f"{socket.gethostname()}:{os.getpid()}"
        self._batch = batch
        self._lease_ttl = lease_ttl_seconds
        self._model = model
        self._provider = provider
        self._model_name = model_name
        self._prompt_version = prompt_version

    def run_once(self) -> ReassessReport:
        """Lease, read one published batch, apply it, checkpoint. Never raises for a busy lease."""
        fence = self._take_lease()
        if fence is None:
            return ReassessReport(leased=False)
        try:
            return self._consume(fence)
        finally:
            # A one-shot CLI must not leave a live lease that blocks the next pass for a minute;
            # the fence makes this a no-op if another holder superseded us meanwhile.
            self._release_lease(fence)

    def _consume(self, fence: int) -> ReassessReport:
        with self._conn.transaction():
            watermark = self._refresh_watermark(fence)
        events = self._read_batch()
        checkpoint: int | None = None
        intel_events = 0
        unseen: set[str] = set()
        candidates = assessed = created = unrated = model_calls = 0
        for event in events:
            if str(event["type"]) == EVENT_TYPE:
                intel_events += 1
                # One event names exactly the revisions it wrote: assess its CVEs, not every CVE
                # of the batch, so a big sync does not re-open unrelated findings.
                impacted = _impacted_ids(event["payload"])
                unseen.update(impacted)
                outcome = severity.assess_pending(
                    self._conn,
                    only_vulnerabilities=impacted,
                    trigger="intel_revision",
                    model=self._model,
                    provider=self._provider,
                    model_name=self._model_name,
                    prompt_version=self._prompt_version,
                )
                candidates += outcome.candidates
                assessed += outcome.assessed
                created += outcome.created
                unrated += outcome.unrated
                model_calls += outcome.model_calls
            checkpoint = int(event["seq"])
        if checkpoint is not None:
            with self._conn.transaction():
                self._conn.execute(
                    "SELECT aegis.consumer_advance(%s, %s, %s, %s)",
                    (self._consumer, checkpoint, self._dispatcher, fence),
                )
        return ReassessReport(
            leased=True,
            fence=fence,
            watermark=watermark,
            events=len(events),
            intel_events=intel_events,
            impacted_cves=len(unseen),
            candidates=candidates,
            assessed=assessed,
            created=created,
            unrated=unrated,
            model_calls=model_calls,
            checkpoint=checkpoint,
        )

    # --- outbox plumbing (C04/D25, the same calls M02's dispatcher makes) ---------------------

    def _take_lease(self) -> int | None:
        with self._conn.transaction():
            row = self._conn.execute(
                "SELECT aegis.outbox_dispatch_lease(%s, %s, %s) AS fence",
                (self._dispatcher, self._holder, self._lease_ttl),
            ).fetchone()
        assert row is not None
        return None if row["fence"] is None else int(row["fence"])

    def _release_lease(self, fence: int) -> None:
        with self._conn.transaction():
            self._conn.execute(
                "UPDATE aegis.outbox_dispatcher SET holder = NULL, leased_until = NULL,"
                " updated_at = now() WHERE name = %s AND holder = %s AND fence = %s",
                (self._dispatcher, self._holder, fence),
            )

    def _refresh_watermark(self, fence: int) -> int:
        row = self._conn.execute(
            "SELECT aegis.outbox_watermark_refresh(%s, %s) AS watermark",
            (self._dispatcher, fence),
        ).fetchone()
        if row is None:  # pragma: no cover - the function always returns a row
            raise RuntimeError("aegis.outbox_watermark_refresh returned no row")
        return int(row["watermark"])

    def _read_batch(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT seq, event_id, type, payload FROM aegis.outbox_batch(%s, %s)",
            (self._consumer, self._batch),
        ).fetchall()
        return [dict(row) for row in rows]


def _impacted_ids(payload: object) -> set[str]:
    """The `impacted_ids` of an `intel.revision.v2` payload (empty when malformed)."""
    if not isinstance(payload, Mapping):
        return set()
    ids = payload.get("impacted_ids")
    if not isinstance(ids, Sequence) or isinstance(ids, (str, bytes)):
        return set()
    return {str(value) for value in ids if isinstance(value, str)}


def run_once(
    connection: psycopg.Connection[Any],
    *,
    model: ModelClient | None = None,
    provider: str | None = None,
    model_name: str | None = None,
    consumer: str = CONSUMER,
    batch: int = DEFAULT_BATCH,
) -> ReassessReport:
    """The CLI entry point: one pass, default consumer generation."""
    return IntelReassessor(
        connection,
        consumer=consumer,
        batch=batch,
        model=model,
        provider=provider,
        model_name=model_name,
    ).run_once()
