"""Distro-aware matching (item 80): a patched distro build is not a live candidate.

NVD matches the upstream version; the distro feed says whether the package the banner names already
carries the backport. The rows and snapshots here are the real M18 sync and the real matcher against
a throwaway database; only the downloads are fixture bytes.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psycopg
import pytest

from aegis.m18_intel.distro import FetchResult, sync_distro
from aegis.m18_intel.sync import FeedSync
from aegis.m20_vuln import visibility
from aegis.m20_vuln.matching import FIXED_BY_DISTRO_CODE, Matcher
from tests import g16c_support as fixtures
from tests.db_support import requires_postgres
from tests.m23_support import connect, ingest
from tests.support_ingestion import asset, observation

pytestmark = requires_postgres

DISTRO_FIXTURES = Path(__file__).resolve().parent / "fixtures/intel/distro"
SOURCES = DISTRO_FIXTURES / "sources.json"
JAMMY = DISTRO_FIXTURES / "ubuntu-jammy-slice.oval.xml"
BOOKWORM = DISTRO_FIXTURES / "debian-bookworm-slice.json"
NVD_OPENSSH = fixtures.FIXTURES / "nvd-openssh-slice.json"

PATCHED = "service:203.0.113.10:22/tcp"
UNPATCHED = "service:203.0.113.11:22/tcp"
DEBIAN_PATCHED = "service:203.0.113.12:22/tcp"
UNKNOWN_PACKAGE = "service:203.0.113.13:80/tcp"
APACHE = "service:203.0.113.14:80/tcp"
TOMCAT = "service:203.0.113.15:8080/tcp"


def _openssh(version: str, distro: dict[str, Any]) -> dict[str, Any]:
    return {
        "product": "openssh",
        "version": version,
        "cpe": f"cpe:2.3:a:openbsd:openssh:{version}:*:*:*:*:*:*:*",
        "distro": distro,
    }


def _services() -> list[dict[str, Any]]:
    return [
        asset(PATCHED, "service"),
        asset(UNPATCHED, "service"),
        asset(DEBIAN_PATCHED, "service"),
        asset(UNKNOWN_PACKAGE, "service"),
        asset(APACHE, "service"),
        asset(TOMCAT, "service"),
    ]


def _observations() -> list[dict[str, Any]]:
    return [
        observation(
            PATCHED,
            "service.product",
            _openssh(
                "8.9p1",
                {
                    "id": "ubuntu",
                    "release": None,
                    "package": "openssh",
                    "version": "8.9p1-3ubuntu0.18",
                },
            ),
        ),
        observation(
            UNPATCHED,
            "service.product",
            _openssh(
                "8.9p1",
                {
                    "id": "ubuntu",
                    "release": None,
                    "package": "openssh",
                    "version": "8.9p1-3ubuntu0.3",
                },
            ),
        ),
        observation(
            DEBIAN_PATCHED,
            "service.product",
            _openssh(
                "9.2p1",
                {
                    "id": "debian",
                    "release": "12",
                    "package": "openssh",
                    "version": "9.2p1-2+deb12u4",
                },
            ),
        ),
        observation(
            APACHE,
            "service.product",
            {
                "product": "http_server",
                "version": "2.4.49",
                "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
            },
        ),
        observation(
            TOMCAT,
            "service.product",
            {
                "product": "tomcat",
                "version": "9.0.30",
                "cpe": "cpe:2.3:a:apache:tomcat:9.0.30:*:*:*:*:*:*:*",
            },
        ),
        observation(
            UNKNOWN_PACKAGE,
            "service.product",
            {
                "product": "nginx",
                "version": "1.18.0",
                "cpe": "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*",
                "distro": {
                    "id": "ubuntu",
                    "release": None,
                    "package": "nginx",
                    "version": "1.18.0-1ubuntu1",
                },
            },
        ),
    ]


def _fetch(url: str) -> FetchResult:
    files = {
        "fixture://ubuntu-jammy": JAMMY,
        "fixture://debian-bookworm": BOOKWORM,
    }
    return FetchResult(files[url].read_bytes(), datetime(2026, 11, 24, 6, 0, tzinfo=UTC))


def _seed_nvd(dsn: str) -> None:
    sync = FeedSync(fixtures.connector(dsn), fixtures.MemoryStore())
    for version, path in (("2026-11-24", fixtures.NVD), ("2026-11-25", NVD_OPENSSH)):
        sync.sync(
            "nvd",
            version,
            path.read_bytes(),
            source_uri=path.name,
            snapshot_at=fixtures.SNAPSHOT_AT,
        )


def _seed_distro(dsn: str) -> dict[str, Any]:
    return sync_distro(
        source_file=SOURCES,
        sync=FeedSync(fixtures.connector(dsn), fixtures.MemoryStore()),
        fetch=_fetch,
        now=datetime(2026, 11, 24, 6, 0, tzinfo=UTC),
    )


@contextmanager
def _dataset(*, with_distro: bool = True, jobs: int = 2) -> Iterator[tuple[str, list[str]]]:
    from tests.m23_support import pipeline_database

    with pipeline_database(jobs=jobs) as value:
        dsn, job_ids = value
        _seed_nvd(dsn)
        if with_distro:
            report = _seed_distro(dsn)
            assert report["ok"] is True, report
        ingest(
            dsn,
            job_ids[0],
            assets=_services(),
            observations=_observations(),
            coverage=[PATCHED, UNPATCHED, DEBIAN_PATCHED, UNKNOWN_PACKAGE, APACHE, TOMCAT],
        )
        yield dsn, job_ids


@pytest.fixture()
def dataset() -> Iterator[tuple[str, list[str]]]:
    with _dataset() as value:
        yield value


def _asset_ids(connection: psycopg.Connection[Any]) -> dict[str, str]:
    rows = connection.execute(
        "SELECT canonical_key, asset_id FROM asset WHERE canonical_key = ANY(%s)",
        ([PATCHED, UNPATCHED, DEBIAN_PATCHED, UNKNOWN_PACKAGE, APACHE, TOMCAT],),
    ).fetchall()
    return {str(row["canonical_key"]): str(row["asset_id"]) for row in rows}


def test_a_patched_distro_build_is_not_a_candidate(dataset: tuple[str, list[str]]) -> None:
    dsn, _jobs = dataset
    with connect(dsn) as connection:
        report = Matcher(connection).run()
        ids = _asset_ids(connection)
        listed = visibility.candidate_rows(connection, list(ids.values()))

    assert report.distro_fixed == 2
    assert report.distro_vulnerable == 1
    assert report.distro_unresolved == 1
    assert report.new_matches == 4
    assert {(row["canonical_key"], row["vulnerability_id"]) for row in listed} == {
        (UNPATCHED, "CVE-2024-6387"),
        (UNKNOWN_PACKAGE, "CVE-2021-23017"),
        # The vulnlab expectations (Apache 2.4.49 -> CVE-2021-41773, Tomcat 9.0.30 ->
        # CVE-2020-1938) are untouched: they carry no distro marker, so the distro feed never gets
        # to suppress them.
        (APACHE, "CVE-2021-41773"),
        (TOMCAT, "CVE-2020-1938"),
    }
    assert report.coverage["distro"]["fixed"] == ["CVE-2024-6387"]


def test_an_existing_candidate_is_retracted_when_the_distro_fix_arrives() -> None:
    with _dataset(with_distro=False) as (dsn, _jobs):
        with connect(dsn) as connection:
            # First run without the distro feed: the upstream range reports every build.
            first = Matcher(connection).run()
            assert first.new_matches == 6
            _seed_distro(dsn)
            second = Matcher(connection).run()
            rows = connection.execute(
                "SELECT DISTINCT ON (package_asset_id, vulnerability_id)"
                "       a.canonical_key, m.matched, m.match_method, m.retraction_reason,"
                "       m.affected_range"
                "  FROM package_vuln_match m JOIN asset a ON a.asset_id = m.package_asset_id"
                " WHERE m.vulnerability_id = 'CVE-2024-6387'"
                " ORDER BY package_asset_id, vulnerability_id, m.created_at DESC, m.match_id DESC"
            ).fetchall()
    by_key = {str(row["canonical_key"]): row for row in rows}
    assert second.distro_retracted == 2
    for key in (PATCHED, DEBIAN_PATCHED):
        assert by_key[key]["matched"] is False
        assert by_key[key]["retraction_reason"] == FIXED_BY_DISTRO_CODE
        assert by_key[key]["match_method"] == "distro_fixed"
        assert by_key[key]["affected_range"].endswith("fixed 1:8.9p1-3ubuntu0.10") or by_key[key][
            "affected_range"
        ].endswith("fixed 1:9.2p1-2+deb12u3")
    assert by_key[UNPATCHED]["matched"] is True


def test_an_unknown_distro_package_keeps_the_upstream_candidate(
    dataset: tuple[str, list[str]],
) -> None:
    dsn, _jobs = dataset
    with connect(dsn) as connection:
        # The distro feed has no nginx rows for this CVE, so nothing can be said about the package:
        # the NVD candidate stands and the run counts it instead of silently dropping it.
        report = Matcher(connection).run()
    assert report.distro_unresolved == 1
    assert report.distro_fixed == 2
