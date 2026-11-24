"""Outbox dispatcher of M02: `job.completed.v2` becomes the workflow's `job_completed` signal.

Uses the S1.3 algorithm and nothing else (0008, superseded refresh by 0013):

1. take or renew the dispatcher lease (fencing token) — a superseded holder can neither publish
   nor checkpoint;
2. refresh the publication watermark in **its own short transaction**, so the exclusive publication
   lock is released before any event is read or any signal is sent (R-6; the session timeouts in
   `db.py` keep an abandoned one from holding writer locks);
3. read the next batch with `aegis.outbox_batch` (never past the watermark, gaps are legal);
4. deliver each event, then checkpoint with `aegis.consumer_advance` at the last sequence the batch
   actually applied. A failed signal stops the batch: the event is retried on the next tick.
   `job_completed` is idempotent (the workflow discards the job id from its pending set), so
   at-least-once delivery needs no inbox row for this consumer.

Only `job.completed.v2` is delivered; every other published event is checkpointed and left to its
own consumer (SSE, ingestion, projector).
"""

from __future__ import annotations

import asyncio
import os
import socket
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

import psycopg

from .db import connect as connect_dispatcher
from .signals import WorkflowSignals

__all__ = ["CONSUMER", "DISPATCHER_NAME", "DispatchOutcome", "OutboxDispatcher"]

CONSUMER = "m02-campaign-signals"
DISPATCHER_NAME = "m02-outbox"
LEASE_TTL_SECONDS = 15


@dataclass(frozen=True, slots=True)
class DispatchOutcome:
    """What one dispatcher tick did; every field is cheap to log or assert on."""

    leased: bool = False
    fence: int | None = None
    watermark: int = 0
    scanned: int = 0
    delivered: int = 0
    checkpoint: int | None = None
    error: str | None = None


class OutboxDispatcher:
    """One consumer (`job.completed.v2` -> signal) with the shared dispatcher lease."""

    def __init__(
        self,
        connect: Callable[[], psycopg.Connection[Any]],
        signals: WorkflowSignals,
        *,
        consumer: str = CONSUMER,
        dispatcher: str = DISPATCHER_NAME,
        holder: str | None = None,
        lease_ttl_seconds: int = LEASE_TTL_SECONDS,
        batch_size: int = 100,
    ) -> None:
        self._connect = connect
        self._signals = signals
        self._consumer = consumer
        self._dispatcher = dispatcher
        self._holder = holder or f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
        self._lease_ttl = lease_ttl_seconds
        self._batch_size = batch_size

    async def run_once(self) -> DispatchOutcome:
        with self._connect() as conn:
            fence: int | None = None
            with conn.transaction():
                row = conn.execute(
                    "SELECT aegis.outbox_dispatch_lease(%s, %s, %s) AS fence",
                    (self._dispatcher, self._holder, self._lease_ttl),
                ).fetchone()
                fence = int(row["fence"]) if row is not None and row["fence"] is not None else None
            if fence is None:
                return DispatchOutcome(leased=False)

            # R-6: the watermark refresh is its own short transaction; its exclusive publication
            # lock is released at commit, before the batch read and before any network signal.
            with conn.transaction():
                row = conn.execute(
                    "SELECT aegis.outbox_watermark_refresh(%s, %s) AS watermark",
                    (self._dispatcher, fence),
                ).fetchone()
                watermark = int(row["watermark"]) if row is not None else 0

            batch = conn.execute(
                "SELECT seq, event_id, type, campaign_id, payload FROM aegis.outbox_batch(%s, %s)",
                (self._consumer, self._batch_size),
            ).fetchall()

            delivered = 0
            checkpoint: int | None = None
            error: str | None = None
            for event in batch:
                if event["type"] == "job.completed.v2":
                    try:
                        await self._deliver(event)
                    except Exception as exc:  # noqa: BLE001 - stop and retry from this seq
                        error = f"{type(exc).__name__}: {exc}"
                        break
                    delivered += 1
                checkpoint = int(event["seq"])

            if checkpoint is not None:
                with conn.transaction():
                    conn.execute(
                        "SELECT aegis.consumer_advance(%s, %s, %s, %s)",
                        (self._consumer, checkpoint, self._dispatcher, fence),
                    )
        return DispatchOutcome(
            leased=True,
            fence=fence,
            watermark=watermark,
            scanned=len(batch),
            delivered=delivered,
            checkpoint=checkpoint,
            error=error,
        )

    async def _deliver(self, event: Mapping[str, Any]) -> None:
        payload = event["payload"] or {}
        campaign_id = event["campaign_id"] or payload.get("campaign_id")
        if campaign_id is None or not payload.get("job_id") or not payload.get("status"):
            # A malformed event must not stall the consumer forever; it is checkpointed and the
            # contract producer (M06) is at fault. Raise instead of silently dropping? The event
            # cannot be delivered, so it is recorded as an error and the batch stops.
            raise ValueError(f"job.completed.v2 event {event['event_id']} is missing keys")
        await self._signals.job_completed(
            str(campaign_id), str(payload["job_id"]), str(payload["status"])
        )


async def dispatch_forever(
    dispatcher: OutboxDispatcher, *, interval_seconds: float = 1.0, once: bool = False
) -> None:
    while True:
        await dispatcher.run_once()
        if once:
            return
        await asyncio.sleep(interval_seconds)


def default_connect() -> psycopg.Connection[Any]:
    return connect_dispatcher()
