"""Campaign state watcher: M01's committed transitions become workflow start/signals.

M01 (`aegis.m01_campaign.status`) stays the single writer of `campaign.status`; this watcher is the
hook that turns a committed row into the M02 signal, without putting a Temporal client in the API
process:

* a campaign that is not terminal must have an open workflow — `ensure_started` is idempotent;
* a status change is signalled once: `PAUSED -> pause`, `RUNNING/WAITING -> resume`,
  `CANCELLED -> cancel`. The current status is remembered per campaign in this process, and a
  restart re-reads the row and signals the current state once, so a signal lost while the
  dispatcher was down is re-sent from the database instead of from a lost in-memory event;
* a workflow that is gone (`NOT_FOUND`) is started again on the next tick if the campaign is still
  active, so a crash of Temporal does not silently stop a campaign.

The workflow itself also reads `campaign.status` in every `dispatch_ready` tick, so a pause is
enforced even before its signal arrives; the signal exists to stop an in-flight session promptly.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

import psycopg

from .signals import WorkflowSignals

__all__ = ["CampaignStateWatcher", "WatchOutcome"]

#: A campaign in one of these states needs no workflow and no signal.
_QUIET = ("COMPLETED", "FAILED")

_ACTIVE_SQL = """
SELECT campaign_id, status, status_reason
  FROM campaign
 WHERE status <> ALL(%s)
"""


@dataclass(frozen=True, slots=True)
class WatchOutcome:
    """What one watcher tick did."""

    watched: int = 0
    started: int = 0
    signalled: int = 0
    undelivered: int = 0


class CampaignStateWatcher:
    """Starts missing workflows and signals committed campaign status changes once."""

    def __init__(self, connect: Callable[[], psycopg.Connection[Any]], signals: WorkflowSignals):
        self._connect = connect
        self._signals = signals
        self._last_status: dict[str, str] = {}

    async def run_once(self) -> WatchOutcome:
        with self._connect() as conn:
            rows = conn.execute(_ACTIVE_SQL, (list(_QUIET),)).fetchall()
        started = signalled = undelivered = 0
        seen: set[str] = set()
        for row in rows:
            campaign_id = str(row["campaign_id"])
            status = str(row["status"])
            seen.add(campaign_id)
            if status != "CANCELLED":
                await self._signals.ensure_started(campaign_id)
                started += 1
            if self._last_status.get(campaign_id) == status:
                continue
            delivered = await self._signal(campaign_id, status, _reason(row))
            self._last_status[campaign_id] = status
            if delivered:
                signalled += 1
            else:
                undelivered += 1
        for campaign_id in set(self._last_status) - seen:
            del self._last_status[campaign_id]
        return WatchOutcome(
            watched=len(rows), started=started, signalled=signalled, undelivered=undelivered
        )

    async def _signal(self, campaign_id: str, status: str, reason: str | None) -> bool:
        return await self._signals.signal_status(campaign_id, status, reason)


def _reason(row: Mapping[str, Any]) -> str | None:
    reason = row.get("status_reason")
    return str(reason) if reason is not None else None
