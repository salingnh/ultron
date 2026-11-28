"""The intel run ledger and the one staleness definition (item 80, migration 0009).

`intel_snapshot` says what is loaded; these tests pin the second question the schedule needs: did
the attempt work, and is the loaded data still fresh? The database half runs against the real
contract chain, a fixed clock and real rows; the refresh itself is substituted because M18's sync
is covered by its own suites.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
import pytest
from psycopg.rows import dict_row

from aegis.m18_intel import runs
from aegis.m18_intel.refresh import RefreshOptions
from tests.db_support import migrated_database, requires_postgres

pytestmark = requires_postgres

NOW = datetime(2026, 12, 1, 12, 0, tzinfo=UTC)


@pytest.fixture()
def dsn() -> Iterator[str]:
    with migrated_database() as value:
        yield value


@pytest.fixture()
def connection(dsn: str) -> Iterator[psycopg.Connection[Any]]:
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as conn:
        conn.execute("SET search_path = aegis, public")
        yield conn


def _snapshot(
    connection: psycopg.Connection[Any],
    feed: str,
    version: str,
    fetched_at: datetime,
    *,
    snapshot_at: datetime | None = None,
) -> None:
    connection.execute(
        "INSERT INTO intel_snapshot (snapshot_id, feed, version, snapshot_at, fetched_at,"
        " record_count, source_uri)"
        " VALUES (gen_random_uuid(), %s, %s, %s, %s, 1, 'fixture')",
        (feed, version, snapshot_at or fetched_at, fetched_at),
    )


def _feed(document: dict[str, Any], name: str) -> dict[str, Any]:
    return next(item for item in document["feeds"] if item["feed"] == name)


def test_a_run_is_running_until_it_finishes_with_its_legs(
    connection: psycopg.Connection[Any],
) -> None:
    run_id = runs.record_start(connection, "schedule", started_at=NOW)
    open_run = runs.latest_run(connection)
    assert open_run is not None
    assert open_run["run_id"] == run_id
    assert open_run["status"] == "RUNNING" and open_run["finished_at"] is None
    assert open_run["trigger"] == "schedule"

    runs.record_finish(
        connection,
        run_id,
        ok=False,
        legs={"kev": {"error": "HTTP 503"}},
        error="kev: HTTP 503",
        finished_at=NOW + timedelta(minutes=5),
    )
    finished = runs.latest_run(connection)
    assert finished is not None
    assert finished["status"] == "FAILED"
    assert finished["finished_at"] == "2026-12-01T12:05:00Z"
    assert finished["error"] == "kev: HTTP 503"
    assert finished["legs"] == {"kev": {"error": "HTTP 503"}}


def test_an_unknown_trigger_is_refused(connection: psycopg.Connection[Any]) -> None:
    with pytest.raises(ValueError, match="trigger"):
        runs.record_start(connection, "timer")


def test_staleness_uses_the_newest_fetched_snapshot_and_reports_missing_feeds(
    connection: psycopg.Connection[Any],
) -> None:
    _snapshot(connection, "nvd", "2026-12-01", NOW - timedelta(hours=1))
    _snapshot(connection, "epss", "2026-11-28", NOW - timedelta(hours=80))
    # KEV has two snapshots; the newest fetched one decides, even though its version is older.
    _snapshot(connection, "kev", "2026.11.30", NOW - timedelta(hours=4))
    _snapshot(connection, "kev", "2026.11.01", NOW - timedelta(hours=2))

    document = runs.feed_status(connection, now=NOW)

    assert document["generated_at"] == "2026-12-01T12:00:00Z"
    assert document["stale_feeds"] == ["epss"]
    nvd = _feed(document, "nvd")
    assert nvd["stale"] is False and nvd["age_seconds"] == 3600
    assert nvd["snapshot"]["version"] == "2026-12-01"
    epss = _feed(document, "epss")
    assert epss["stale"] is True and epss["age_seconds"] == 80 * 3600
    kev = _feed(document, "kev")
    assert kev["stale"] is False and kev["age_seconds"] == 2 * 3600
    assert kev["snapshot"]["version"] == "2026.11.01"


def test_a_feed_with_no_snapshot_is_stale_and_not_omitted(
    connection: psycopg.Connection[Any],
) -> None:
    document = runs.feed_status(connection, now=NOW)
    assert [item["feed"] for item in document["feeds"]] == ["nvd", "epss", "kev"]
    assert document["stale_feeds"] == ["nvd", "epss", "kev"]
    assert all(
        item["snapshot"] is None and item["age_seconds"] is None for item in document["feeds"]
    )
    assert document["last_run"] is None


def test_recorded_refresh_persists_success_and_failure(
    dsn: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    outcomes: list[dict[str, Any]] = [
        {"ok": True, "legs": {"nvd": {"records": 4}, "kev": {"status": "skipped"}}},
        {"ok": False, "legs": {"kev": {"error": "HTTP 503"}}},
    ]

    def fake_refresh(options: RefreshOptions) -> dict[str, Any]:
        del options
        return outcomes.pop(0)

    monkeypatch.setattr(runs, "refresh", fake_refresh)
    monkeypatch.setenv("AEGIS_PG_DSN", dsn)

    success = runs.recorded_refresh("manual", RefreshOptions())
    assert success["recorded"] is True and success["run_id"]
    assert success["ok"] is True

    failed = runs.recorded_refresh("schedule", RefreshOptions())
    assert failed["ok"] is False

    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        conn.execute("SET search_path = aegis, public")
        rows = conn.execute(
            "SELECT status, legs, error FROM intel_sync_run ORDER BY started_at"
        ).fetchall()
        status = runs.feed_status(conn, now=NOW)["last_run"]
    assert [row["status"] for row in rows] == ["SUCCEEDED", "FAILED"]
    assert rows[1]["error"] == "kev: HTTP 503"
    assert status is not None and status["status"] == "FAILED"


def test_a_scheduled_run_without_a_database_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AEGIS_PG_DSN", raising=False)
    with pytest.raises(Exception, match="AEGIS_PG_DSN"):
        runs.recorded_refresh("schedule", RefreshOptions(), require_database=True)
