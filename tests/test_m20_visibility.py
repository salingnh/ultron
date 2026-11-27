"""P8: one definition of "a candidate" — the newest decision + matched — for M23/M26/the demo.

`package_vuln_match` is append-only and migration 0008 lets a newer intel revision retract a
candidate. A pair is a candidate only when its **newest** row says `matched`; the projector (M23),
the read API (M26) and the G1.6c demo must therefore read exactly the same set. The demo used to
select every row, so on any stack where a retraction existed it reported "the graph edges and the
candidates disagree" while the graph was right (item 61 trial, P8).

These tests seed real positives, then a real retraction through the M20 matcher, and require the
four readers to agree — including the demo's own `_candidates`.
"""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Iterator
from typing import Any

import pytest

from aegis.m18_intel.sync import FeedSync
from aegis.m20_vuln import visibility
from aegis.m20_vuln.matching import Matcher
from aegis.m23_graph import pg as m23_pg
from aegis.m26_api import vulnerabilities as m26
from tests import g16c_support as fixtures
from tests.db_support import requires_postgres
from tests.m23_support import connect, ingest, pipeline_database
from tests.support import REPO_ROOT

pytestmark = requires_postgres


@pytest.fixture()
def database() -> Iterator[tuple[str, list[str]]]:
    with pipeline_database(jobs=1) as value:
        yield value


def _ingest_services(dsn: str, job_id: str) -> None:
    receipt = ingest(
        dsn,
        job_id,
        assets=fixtures.service_assets(),
        observations=list(fixtures.service_observations()),
        coverage=fixtures.coverage(),
    )
    assert receipt.accepted and not receipt.quarantined, receipt


def _demo_candidates(connection: Any, assets: dict[str, str]) -> list[dict[str, Any]]:
    """The G1.6c demo's own reader, loaded the way the demo script is loaded."""
    path = REPO_ROOT / "scripts/demo/demo-g16c.py"
    spec = importlib.util.spec_from_file_location("aegis_demo_g16c_p8", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    candidates: list[dict[str, Any]] = module._candidates(connection, assets)
    return candidates


def _service_assets(connection: Any) -> dict[str, str]:
    """The assets the fixture observations fingerprinted (two services and one application)."""
    keys = [
        str(item["canonical_key"]) for item in fixtures.service_assets() if item["kind"] != "domain"
    ]
    rows = connection.execute(
        "SELECT asset_id, canonical_key FROM asset"
        " WHERE canonical_key = ANY(%s) ORDER BY canonical_key",
        (keys,),
    ).fetchall()
    return {str(row["canonical_key"]): str(row["asset_id"]) for row in rows}


def _m26_ids(connection: Any, asset_id: str) -> set[str]:
    rows = connection.execute(
        m26.QUERY, ([asset_id], [asset_id], asset_id, None, None, None, None, False, 100)
    ).fetchall()
    return {str(row["vulnerability_id"]) for row in rows}


def _every_reader(connection: Any) -> dict[str, set[str]]:
    assets = _service_assets(connection)
    ids = list(assets.values())
    demo = _demo_candidates(connection, assets)
    return {
        "visibility.candidate_rows": {
            str(row["vulnerability_id"]) for row in visibility.candidate_rows(connection, ids)
        },
        "demo._candidates": {str(row["vulnerability_id"]) for row in demo},
        "m23.current_matched_pairs": {
            vulnerability for _, vulnerability in m23_pg.current_matched_pairs(connection, ids)
        },
        "m26.query": set().union(*(_m26_ids(connection, asset_id) for asset_id in ids)),
    }


def test_the_four_readers_agree_before_and_after_a_retraction(
    database: tuple[str, list[str]],
) -> None:
    dsn, jobs = database
    _ingest_services(dsn, jobs[0])
    connection = connect(dsn)
    try:
        fixtures.seed_intel(dsn)
        first = Matcher(connection).run()
        assert first.new_matches == 3 and first.retracted == 0

        readers = _every_reader(connection)
        expected = {"CVE-2021-41773", "CVE-2021-23017", "CVE-2022-22965"}
        for name, found in readers.items():
            assert found == expected, f"{name} disagrees before the retraction: {sorted(found)}"

        # A newer revision of CVE-2021-41773 stops matching httpd 2.4.49: M20 retracts the pair.
        FeedSync(fixtures.connector(dsn), fixtures.MemoryStore()).sync(
            "nvd",
            "2026-11-27-retraction",
            fixtures.nvd_with_retracted_match(),
            source_uri="nvd-slice-retraction.json",
        )
        second = Matcher(connection).run()
        assert second.retracted == 1 and second.retractions_blocked == 0

        expected = {"CVE-2021-23017", "CVE-2022-22965"}
        for name, found in _every_reader(connection).items():
            assert found == expected, f"{name} disagrees after the retraction: {sorted(found)}"

        # The retraction is history, not a deleted row: the old positive is still there, and the
        # newest decision of the pair is the negative one.
        service_ids = list(_service_assets(connection).values())
        assert visibility.current_matched_pairs(connection, service_ids)
        rows = connection.execute(
            "SELECT matched FROM package_vuln_match WHERE vulnerability_id = 'CVE-2021-41773'"
            " ORDER BY created_at"
        ).fetchall()
        assert [bool(row["matched"]) for row in rows] == [True, False]
    finally:
        connection.close()
