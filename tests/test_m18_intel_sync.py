"""M18 feed sync against PostgreSQL 16 (G1.6 slice C): immutable snapshots, revisions, events.

The S3 half is an in-memory stand-in with the same `put`/`head` contract (the real client is
exercised by the demo and by M28's own tests); everything below it is the real schema, the real
transaction and the real outbox. What these tests pin:

* a snapshot is stored once, content addressed, and the same bytes loaded twice write nothing;
* the same `(feed, version)` with other bytes is refused, never overwritten;
* a changed record is a new revision of that `(vulnerability_id, source)` and only then is
  `intel.revision.v2` published, with the impacted ids and the change kind.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import psycopg
import pytest
from psycopg.rows import dict_row

from aegis.m18_intel.sync import FeedSync, SnapshotConflict
from aegis.migrations import apply_contract_migrations
from tests import g16c_support as fixtures
from tests.db_support import requires_postgres
from tests.pg import throwaway_database

pytestmark = requires_postgres


@pytest.fixture()
def dsn() -> Iterator[str]:
    """A throwaway database with the contract chain applied.

    The migration runner reads the bookkeeping table by position, so it runs on its own tuple-row
    connection first; the sync then opens its own `dict_row` connection, as it does in production.
    """
    with throwaway_database() as value:
        with psycopg.connect(value, autocommit=True) as setup:
            apply_contract_migrations(setup)
        yield value


@pytest.fixture()
def connection(dsn: str) -> Iterator[psycopg.Connection[Any]]:
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as conn:
        conn.execute("SET search_path = aegis, public")
        yield conn


def _snapshots(connection: psycopg.Connection[Any]) -> list[dict[str, Any]]:
    rows = connection.execute(
        "SELECT feed, version, snapshot_at, record_count, source_uri, content_sha256"
        "  FROM intel_snapshot ORDER BY feed"
    ).fetchall()
    return [dict(row) for row in rows]


def test_a_sync_stores_the_bytes_once_and_writes_nothing_on_the_second_run(
    connection: psycopg.Connection[Any], dsn: str
) -> None:
    reports, store = fixtures.seed_intel(dsn)
    assert reports["nvd"].records == 3
    assert reports["nvd"].written == 3
    assert reports["kev"].written == 2
    assert reports["epss"].written == 3
    assert all(report.event_published for report in reports.values())
    # Content-addressed key, the exact bytes, and the sha256 the row records.
    keys = sorted(store.objects)
    assert keys[0] == f"feeds/epss/{fixtures.VERSION}/{reports['epss'].content_sha256}.csv"
    assert store.objects[keys[0]] == fixtures.EPSS.read_bytes()
    assert _snapshots(connection)[0]["source_uri"] == "epss-slice.csv"

    again, _ = fixtures.seed_intel(dsn, store=store)
    assert [report.written for report in again.values()] == [0, 0, 0]
    assert [report.unchanged for report in again.values()] == [3, 2, 3]
    assert not any(report.event_published for report in again.values())
    assert [row["feed"] for row in _snapshots(connection)] == ["epss", "kev", "nvd"]
    assert len(store.objects) == len(keys)


def test_an_event_carries_the_impacted_ids_and_the_change_kind(
    connection: psycopg.Connection[Any], dsn: str
) -> None:
    fixtures.seed_intel(dsn)
    events = fixtures.events(connection, "intel.revision.v2")
    assert [event["dedup_key"] for event in events] == [
        f"nvd:{fixtures.VERSION}",
        f"kev:{fixtures.VERSION}",
        f"epss:{fixtures.VERSION}",
    ]
    assert {event["producer"] for event in events} == {"M18"}
    nvd_payload = events[0]["payload"]
    assert sorted(nvd_payload["impacted_ids"]) == [
        "CVE-2021-23017",
        "CVE-2021-41773",
        "CVE-2022-22965",
    ]
    assert nvd_payload["change_kinds"] == ["new_vuln"]
    assert nvd_payload["snapshot_at"] == "2026-11-24T06:00:00Z"


def test_the_same_version_with_other_bytes_is_refused(
    connection: psycopg.Connection[Any], dsn: str
) -> None:
    sync = FeedSync(fixtures.connector(dsn), fixtures.MemoryStore())
    first = sync.sync(
        "nvd",
        fixtures.VERSION,
        fixtures.NVD.read_bytes(),
        source_uri="nvd-slice.json",
        snapshot_at=fixtures.SNAPSHOT_AT,
    )
    with pytest.raises(SnapshotConflict):
        sync.sync(
            "nvd",
            fixtures.VERSION,
            fixtures.nvd_with_extra_revision(),
            source_uri="nvd-slice.json",
            snapshot_at=fixtures.SNAPSHOT_AT,
        )
    assert first.created_snapshot is True


def test_a_changed_record_is_a_new_revision_and_a_new_delta(
    connection: psycopg.Connection[Any], dsn: str
) -> None:
    fixtures.seed_intel(dsn)
    sync = FeedSync(fixtures.connector(dsn), fixtures.MemoryStore())
    report = sync.sync(
        "nvd",
        "2026-11-25",
        fixtures.nvd_with_extra_revision(),
        source_uri="nvd-slice.json",
        snapshot_at=fixtures.SNAPSHOT_AT,
    )
    assert report.created_snapshot is True
    assert report.written == 1
    assert report.unchanged == 2
    assert report.change_kinds == ("affected_range_changed",)
    event = fixtures.events(connection, "intel.revision.v2")[-1]
    assert event["payload"]["impacted_ids"] == ["CVE-2021-23017"]
    rows = connection.execute(
        "SELECT count(*) AS revisions FROM vulnerability_revision"
        " WHERE vulnerability_id = 'CVE-2021-23017' AND source = 'nvd'"
    ).fetchone()
    assert rows is not None and rows["revisions"] == 2
    # The current revision is the new one; the old one stays as history.
    current = connection.execute(
        "SELECT affected->'cpe_match'->0->>'version_end_excluding' AS end_excluding"
        "  FROM vulnerability_current"
        " WHERE vulnerability_id = 'CVE-2021-23017' AND source = 'nvd'"
    ).fetchone()
    assert current is not None and current["end_excluding"] == "1.21.0"
