"""The intel refresh ledger and feed staleness (item 80): "did the daily sync work?".

`intel_snapshot` answers "what intel is loaded" and nothing else. A refresh whose NVD leg fails
writes no snapshot, so without a second record the operator cannot tell a feed that is quiet from a
schedule that has been broken since Tuesday. This module owns that second record and the one
staleness definition every reader uses:

* **the run**: one `intel_sync_run` row (migration 0009) inserted as `RUNNING` before the first
  network call and finished as `SUCCEEDED` or `FAILED` with the same `legs` document the CLI
  prints. A `RUNNING` row that never finished is the visible sign of a worker that died mid-sync.
* **the status**: for every feed this deployment syncs, the newest snapshot (`fetched_at`, the
  moment *this deployment* stored it - `snapshot_at` is the feed's own publication date and can lag
  legitimately), its age in seconds, and whether it is older than `STALE_AFTER_SECONDS`. A feed
  with no snapshot is stale and says `snapshot: null`; a stale feed is never silently omitted.

The thresholds are deliberately larger than the daily schedule: one missed run should be visible as
"the last run failed", while two missed runs (or a broken schedule with no run rows at all) make the
feed stale. KEV is updated a few times a week by CISA, so its bound is 72 h rather than 48 h.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from aegis.m18_intel import feeds
from aegis.m18_intel.refresh import RefreshOptions, refresh
from aegis.m18_intel.sync import FeedSyncError, connect_from_env
from aegis.m27_ingestion.ids import uuid7

__all__ = [
    "FEEDS",
    "STALE_AFTER_SECONDS",
    "TRIGGERS",
    "feed_status",
    "latest_run",
    "record_finish",
    "record_start",
    "recorded_refresh",
]

#: The feeds `sync-intel` refreshes and the status endpoint reports, in report order.
FEEDS = (feeds.NVD, feeds.DISTRO, feeds.EPSS, feeds.KEV)
#: How old the newest *fetched* snapshot may be before the feed is stale (daily schedule).
STALE_AFTER_SECONDS: Mapping[str, int] = {
    feeds.NVD: 48 * 3600,
    feeds.DISTRO: 48 * 3600,
    feeds.EPSS: 48 * 3600,
    feeds.KEV: 72 * 3600,
}
TRIGGERS = ("schedule", "manual")


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def record_start(connection: Any, trigger: str, *, started_at: datetime | None = None) -> str:
    """Open one attempt; the row exists before the first feed call so a crash leaves a trace."""
    if trigger not in TRIGGERS:
        raise ValueError(f"unknown intel sync trigger {trigger!r}; expected one of {TRIGGERS}")
    run_id = str(uuid7())
    connection.execute(
        "INSERT INTO intel_sync_run (run_id, trigger, status, started_at)"
        " VALUES (%s, %s, 'RUNNING', %s)",
        (run_id, trigger, started_at or datetime.now(UTC)),
    )
    return run_id


def record_finish(
    connection: Any,
    run_id: str,
    *,
    ok: bool,
    legs: Mapping[str, Any],
    error: str | None = None,
    finished_at: datetime | None = None,
) -> None:
    """Finish one attempt with the per-feed legs and a status that matches the outcome."""
    from psycopg.types.json import Jsonb

    connection.execute(
        "UPDATE intel_sync_run"
        "   SET status = %s, finished_at = %s, legs = %s, error = %s"
        " WHERE run_id = %s AND status = 'RUNNING'",
        (
            "SUCCEEDED" if ok else "FAILED",
            finished_at or datetime.now(UTC),
            Jsonb(dict(legs)),
            error,
            run_id,
        ),
    )


def latest_run(connection: Any) -> dict[str, Any] | None:
    """The newest attempt (running or finished), or None when the refresh never ran."""
    row = connection.execute(
        "SELECT run_id, trigger, status, started_at, finished_at, legs, error"
        "  FROM intel_sync_run ORDER BY started_at DESC, run_id DESC LIMIT 1"
    ).fetchone()
    return None if row is None else _run_document(row)


def _run_document(row: Mapping[str, Any]) -> dict[str, Any]:
    finished = row["finished_at"]
    return {
        "run_id": str(row["run_id"]),
        "trigger": str(row["trigger"]),
        "status": str(row["status"]),
        "started_at": _iso(row["started_at"]),
        "finished_at": None if finished is None else _iso(finished),
        "legs": row["legs"] if isinstance(row["legs"], dict) else {},
        "error": row["error"],
    }


def feed_status(connection: Any, *, now: datetime | None = None) -> dict[str, Any]:
    """The staleness document the API serves: newest snapshot per feed, age, and last run."""
    moment = now or datetime.now(UTC)
    rows = connection.execute(
        "SELECT DISTINCT ON (feed) feed, version, snapshot_at, fetched_at, record_count"
        "  FROM intel_snapshot"
        " WHERE feed = ANY(%s)"
        " ORDER BY feed, fetched_at DESC, snapshot_id DESC",
        (list(FEEDS),),
    ).fetchall()
    newest = {str(row["feed"]): row for row in rows}
    items: list[dict[str, Any]] = []
    stale: list[str] = []
    for feed in FEEDS:
        row = newest.get(feed)
        if row is None:
            age_seconds = None
            is_stale = True
            snapshot = None
        else:
            age_seconds = max(0, int((moment - row["fetched_at"]).total_seconds()))
            is_stale = age_seconds > STALE_AFTER_SECONDS[feed]
            snapshot = {
                "version": str(row["version"]),
                "snapshot_at": _iso(row["snapshot_at"]),
                "fetched_at": _iso(row["fetched_at"]),
                "record_count": int(row["record_count"]),
            }
        if is_stale:
            stale.append(feed)
        items.append(
            {
                "feed": feed,
                "stale": is_stale,
                "age_seconds": age_seconds,
                "snapshot": snapshot,
            }
        )
    return {
        "generated_at": _iso(moment),
        "stale_feeds": stale,
        "feeds": items,
        "last_run": latest_run(connection),
    }


def _failure_summary(legs: Mapping[str, Any]) -> str | None:
    parts = [
        f"{feed}: {leg['error']}"
        for feed, leg in legs.items()
        if isinstance(leg, dict) and isinstance(leg.get("error"), str)
    ]
    return "; ".join(parts) if parts else None


def recorded_refresh(
    trigger: str,
    options: RefreshOptions,
    *,
    require_database: bool = True,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Run the refresh and persist the attempt; the CLI and the activity share this call.

    `require_database=False` is the CLI's offline path (all legs skipped in a test): the refresh
    still runs and says `recorded: false`, which the CLI prints as a warning instead of pretending
    a run was recorded. The scheduled activity passes `True`: a schedule whose runs leave no record
    is not a schedule anyone can audit.
    """
    source = os.environ if env is None else env
    connection = connect_from_env(source) if source.get("AEGIS_PG_DSN") else None
    if connection is None and require_database:
        raise FeedSyncError("AEGIS_PG_DSN is required to record a scheduled intel sync run")
    if connection is None:
        print("intel sync run not recorded: AEGIS_PG_DSN is not set", file=sys.stderr)
    run_id = record_start(connection, trigger) if connection is not None else None
    try:
        document = refresh(options)
        if connection is not None and run_id is not None:
            raw_legs = document.get("legs")
            legs: Mapping[str, Any] = raw_legs if isinstance(raw_legs, dict) else {}
            record_finish(
                connection,
                run_id,
                ok=bool(document.get("ok")),
                legs=legs,
                error=None if document.get("ok") else _failure_summary(legs),
            )
        return {**document, "run_id": run_id, "recorded": connection is not None}
    except BaseException as error:
        if connection is not None and run_id is not None:
            record_finish(connection, run_id, ok=False, legs={}, error=str(error))
        raise
    finally:
        if connection is not None:
            connection.close()
