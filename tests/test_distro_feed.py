"""The distro fix feed (item 80): parsers, config, snapshot sync, and the version order.

No test reaches the network: the OVAL/JSON documents are committed slices of the real shapes and
the sync's download is a function the test passes in. The sync half runs against the real contract
chain and the in-memory object store, so the snapshot/immutability rules are the production ones.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from aegis.m18_intel import distro as distro_feed
from aegis.m18_intel.sync import FeedSync
from aegis.m20_vuln.distro import compare_dpkg_versions, distro_from_value
from tests import g16c_support as fixtures
from tests.db_support import migrated_database, requires_postgres

DISTRO_FIXTURES = Path(__file__).resolve().parent / "fixtures/intel/distro"
SOURCES = DISTRO_FIXTURES / "sources.json"
JAMMY = DISTRO_FIXTURES / "ubuntu-jammy-slice.oval.xml"
BOOKWORM = DISTRO_FIXTURES / "debian-bookworm-slice.json"
FETCHED_AT = datetime(2026, 11, 24, 6, 0, tzinfo=UTC)


def _fetch(data: Path) -> Any:
    def fetch(url: str) -> distro_feed.FetchResult:
        del url
        return distro_feed.FetchResult(data.read_bytes(), FETCHED_AT)

    return fetch


def test_the_config_refuses_a_duplicate_or_unknown_source(tmp_path: Path) -> None:
    document = json.loads(SOURCES.read_text(encoding="utf-8"))
    document["sources"].append(dict(document["sources"][0]))
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(distro_feed.DistroSourceError, match="duplicate"):
        distro_feed.load_distro_sources(duplicate)

    document = json.loads(SOURCES.read_text(encoding="utf-8"))
    document["sources"][0]["kind"] = "rhsa"
    unknown = tmp_path / "unknown.json"
    unknown.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(distro_feed.DistroSourceError, match="kind"):
        distro_feed.load_distro_sources(unknown)


def test_the_oval_parser_reads_the_fixed_version_and_strips_the_oval_epoch() -> None:
    config = distro_feed.load_distro_sources(SOURCES)
    records = distro_feed.parse_ubuntu_oval(JAMMY.read_bytes(), config.sources[0])
    by_id = {record.vulnerability_id: record for record in records}
    assert set(by_id) == {"CVE-2024-6387", "CVE-2016-20012"}
    affected = by_id["CVE-2024-6387"].affected
    assert affected is not None
    assert affected["distro"] == {"id": "ubuntu", "release": "jammy", "codename": "22.04"}
    assert affected["packages"]["openssh"]["fixed"] == "1:8.9p1-3ubuntu0.10"


def test_the_oval_parser_refuses_an_export_with_no_fix() -> None:
    config = distro_feed.load_distro_sources(SOURCES)
    empty = b'<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"/>'
    with pytest.raises(distro_feed.DistroSourceError, match="no CVE"):
        distro_feed.parse_ubuntu_oval(empty, config.sources[0])
    with pytest.raises(distro_feed.DistroSourceError, match="malformed"):
        distro_feed.parse_ubuntu_oval(b"<not-xml", config.sources[0])


def test_the_debian_parser_keeps_open_and_resolved_entries() -> None:
    config = distro_feed.load_distro_sources(SOURCES)
    records = distro_feed.parse_debian_tracker(BOOKWORM.read_bytes(), config.sources[1])
    by_id = {record.vulnerability_id: record for record in records}
    assert by_id["CVE-2024-6387"].affected is not None
    assert by_id["CVE-2024-6387"].affected["packages"]["openssh"] == {
        "fixed": "1:9.2p1-2+deb12u3",
        "status": "resolved",
    }
    assert by_id["CVE-2016-20012"].affected is not None
    assert by_id["CVE-2016-20012"].affected["packages"]["openssh"] == {
        "fixed": None,
        "status": "open",
    }


def test_the_version_order_is_dpkgs() -> None:
    for left, right, expected in (
        ("1.0", "1.1", -1),
        ("1.0~rc1", "1.0", -1),
        ("1:1.0", "2.0", 1),
        ("1.0-1", "1.0-2", -1),
        ("1.0-1ubuntu1", "1.0-1", 1),
        ("1:8.9p1-3ubuntu0.18", "1:8.9p1-3ubuntu0.10", 1),
        ("1:8.9p1-3ubuntu0.3", "1:8.9p1-3ubuntu0.10", -1),
        ("1.0", "1.0", 0),
    ):
        assert compare_dpkg_versions(left, right) == expected, (left, right)


def test_a_recorded_distro_value_is_read_and_a_partial_one_is_ignored() -> None:
    value = {
        "product": "openssh",
        "version": "8.9p1",
        "distro": {
            "id": "ubuntu",
            "release": None,
            "package": "openssh",
            "version": "8.9p1-3ubuntu0.18",
        },
    }
    ref = distro_from_value(value)
    assert ref is not None and ref.version == "8.9p1-3ubuntu0.18"
    assert distro_from_value({"product": "openssh", "distro": {"id": "ubuntu"}}) is None
    assert (
        distro_from_value({"distro": {"id": "ubuntu", "package": "openssh", "version": ""}}) is None
    )


@requires_postgres
def test_sync_stores_one_snapshot_per_release_and_is_idempotent() -> None:
    with migrated_database() as dsn:
        store = fixtures.MemoryStore()
        sync = FeedSync(fixtures.connector(dsn), store)
        first = distro_feed.sync_distro(
            source_file=SOURCES,
            sync=sync,
            fetch=lambda url: distro_feed.FetchResult(
                (JAMMY if "ubuntu" in url else BOOKWORM).read_bytes(), FETCHED_AT
            ),
            now=FETCHED_AT,
        )
        assert first["ok"] is True, first
        assert set(first["sources"]) == {"ubuntu-jammy", "debian-bookworm"}
        assert first["sources"]["ubuntu-jammy"]["written"] == 2
        assert first["sources"]["debian-bookworm"]["written"] == 3

        second = distro_feed.sync_distro(
            source_file=SOURCES,
            sync=sync,
            fetch=lambda url: distro_feed.FetchResult(
                (JAMMY if "ubuntu" in url else BOOKWORM).read_bytes(), FETCHED_AT
            ),
            now=FETCHED_AT,
        )
        assert second["ok"] is True
        assert second["sources"]["ubuntu-jammy"]["written"] == 0
        assert second["sources"]["debian-bookworm"]["written"] == 0

        connection = fixtures.connector(dsn)()
        try:
            rows = connection.execute(
                "SELECT feed, version, record_count FROM intel_snapshot"
                " WHERE feed = 'distro' ORDER BY version"
            ).fetchall()
            revisions = connection.execute(
                "SELECT count(*) AS n FROM vulnerability_revision WHERE source = 'distro'"
            ).fetchone()
        finally:
            connection.close()
        assert [row["feed"] for row in rows] == ["distro", "distro"]
        assert revisions is not None and revisions["n"] == 5
        assert all("jammy" in row["version"] or "bookworm" in row["version"] for row in rows)


@requires_postgres
def test_one_failed_source_does_not_hide_the_other() -> None:
    with migrated_database() as dsn:
        sync = FeedSync(fixtures.connector(dsn), fixtures.MemoryStore())

        def fetch(url: str) -> distro_feed.FetchResult:
            if "ubuntu" in url:
                raise distro_feed.DistroSourceError("HTTP 503")
            return distro_feed.FetchResult(BOOKWORM.read_bytes(), FETCHED_AT)

        report = distro_feed.sync_distro(
            source_file=SOURCES, sync=sync, fetch=fetch, now=FETCHED_AT
        )
        assert report["ok"] is False
        assert report["sources"]["ubuntu-jammy"]["error"] == "HTTP 503"
        assert report["sources"]["debian-bookworm"]["written"] == 3
        assert report["errors"] == [{"source": "ubuntu-jammy", "error": "HTTP 503"}]


@requires_postgres
def test_a_size_outside_the_configured_bounds_is_refused(tmp_path: Path) -> None:
    document = json.loads(SOURCES.read_text(encoding="utf-8"))
    document["sources"][0]["size_min_bytes"] = 10_000_000
    document["sources"][0]["size_max_bytes"] = 20_000_000
    small = tmp_path / "sources.json"
    small.write_text(json.dumps(document), encoding="utf-8")
    with migrated_database() as dsn:
        report = distro_feed.sync_distro(
            source_file=small,
            sync=FeedSync(fixtures.connector(dsn), fixtures.MemoryStore()),
            fetch=lambda url: distro_feed.FetchResult(
                (JAMMY if "ubuntu" in url else BOOKWORM).read_bytes(), FETCHED_AT
            ),
            now=FETCHED_AT,
        )
    assert report["ok"] is False
    assert "outside the configured" in report["sources"]["ubuntu-jammy"]["error"]
