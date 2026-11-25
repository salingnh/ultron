"""M20 matcher against PostgreSQL 16 (G1.6 slice C): candidates, idempotency, the intel delta.

The observations are ingested by M27 from an envelope whose values carry CPEs (the shape G1.6
slice A's fingerprinters will send); the intel is the committed fixture slices loaded by the real
M18 sync. What these tests pin:

* an exact-version criterion and a version range both become candidates, with the confidence the
  matcher documents, and each candidate publishes one `vulnerability.matched.v2` in the same
  transaction;
* re-running is `ON CONFLICT DO NOTHING`: no second row, no second event;
* a new intel snapshot is a new revision of the CVE, hence a new candidate and a new event, while
  the old decision stays as history;
* a value without a CPE is not guessed at.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from typing import Any

import pytest

from aegis import validation
from aegis.m18_intel.sync import FeedSync
from aegis.m20_vuln.matching import Matcher, changed_vulnerabilities
from aegis.m23_graph.models import VULNERABILITY_EVENT
from tests import g16c_support as fixtures
from tests.db_support import requires_postgres
from tests.m23_support import connect, ingest, pipeline_database
from tests.support_ingestion import observation

pytestmark = requires_postgres

EVENT_SCHEMA = "events/vulnerability.matched.v2.schema.json"


@pytest.fixture()
def database() -> Iterator[tuple[str, list[str]]]:
    with pipeline_database(jobs=2) as value:
        yield value


def ingest_services(
    dsn: str, job_id: str, observations: Sequence[dict[str, Any]] | None = None
) -> Any:
    values = fixtures.service_observations() if observations is None else observations
    return ingest(
        dsn,
        job_id,
        assets=fixtures.service_assets(),
        observations=list(values),
        coverage=fixtures.coverage(),
    )


def test_the_matcher_records_one_candidate_per_service_and_cve(
    database: tuple[str, list[str]],
) -> None:
    dsn, jobs = database
    ingest_services(dsn, jobs[0])
    with connect(dsn) as connection:
        fixtures.seed_intel(dsn)
        report = Matcher(connection).run()
        found = fixtures.matches(connection)

    assert report.new_matches == 3 and report.existing_matches == 0
    assert report.events == 3
    by_vulnerability = {row["vulnerability_id"]: row for row in found}
    assert set(by_vulnerability) == {
        "CVE-2021-41773",  # Apache 2.4.49, an exact criterion
        "CVE-2021-23017",  # nginx 1.18.0, inside 0.6.18 .. 1.20.1
        "CVE-2022-22965",  # Spring Framework 5.3.17, inside 5.3.0 .. 5.3.18
    }
    assert by_vulnerability["CVE-2021-41773"]["canonical_key"] == fixtures.SERVICE_KEY
    assert by_vulnerability["CVE-2021-41773"]["match_method"] == "cpe_range"
    assert float(by_vulnerability["CVE-2021-41773"]["confidence"]) == 0.7
    assert by_vulnerability["CVE-2021-41773"]["affected_range"] is None
    assert float(by_vulnerability["CVE-2021-23017"]["confidence"]) == 0.6
    assert by_vulnerability["CVE-2021-23017"]["affected_range"] == ">= 0.6.18, < 1.20.1"
    assert by_vulnerability["CVE-2022-22965"]["canonical_key"] == fixtures.APP_KEY
    assert all(row["snapshot_id"] is not None for row in found)


def test_each_new_candidate_publishes_one_valid_event(database: tuple[str, list[str]]) -> None:
    dsn, jobs = database
    ingest_services(dsn, jobs[0])
    with connect(dsn) as connection:
        fixtures.seed_intel(dsn)
        Matcher(connection).run()
        events = fixtures.events(connection, VULNERABILITY_EVENT)
        match_ids = {
            str(row["match_id"])
            for row in connection.execute("SELECT match_id FROM package_vuln_match").fetchall()
        }

    assert len(events) == 3
    assert {event["dedup_key"] for event in events} == match_ids
    assert {event["producer"] for event in events} == {"M20"}
    for event in events:
        validation.validate(EVENT_SCHEMA, event["payload"])
        assert event["payload"]["vulnerability_id"].startswith("CVE-")
        assert event["payload"]["canonical_key"] in fixtures.coverage()


def test_a_second_run_writes_nothing(database: tuple[str, list[str]]) -> None:
    dsn, jobs = database
    ingest_services(dsn, jobs[0])
    with connect(dsn) as connection:
        fixtures.seed_intel(dsn)
        Matcher(connection).run()
        before = fixtures.matches(connection)
        report = Matcher(connection).run()
        after = fixtures.matches(connection)

    assert report.new_matches == 0 and report.existing_matches == 3
    assert report.events == 0
    assert after == before


def test_a_new_intel_revision_is_a_new_candidate_and_the_old_one_stays(
    database: tuple[str, list[str]],
) -> None:
    dsn, jobs = database
    ingest_services(dsn, jobs[0])
    with connect(dsn) as connection:
        fixtures.seed_intel(dsn)
        Matcher(connection).run()
        delta, cursor = changed_vulnerabilities(connection, 0)
        assert "CVE-2021-23017" in delta and cursor > 0
        report = Matcher(connection).run(only_vulnerabilities={"CVE-2021-23017"}, cursor=cursor)
        history = connection.execute(
            "SELECT count(*) AS rows FROM package_vuln_match"
            " WHERE vulnerability_id = 'CVE-2021-23017'"
        ).fetchone()

    # Same revision, same decision: the delta re-run confirms the existing candidate.
    assert report.new_matches == 0
    assert history is not None and history["rows"] == 1

    with connect(dsn) as connection:
        FeedSync(fixtures.connector(dsn), fixtures.MemoryStore()).sync(
            "nvd",
            "2026-11-25",
            fixtures.nvd_with_extra_revision(),
            source_uri="nvd-slice.json",
            snapshot_at=fixtures.SNAPSHOT_AT,
        )
        delta, cursor = changed_vulnerabilities(connection, cursor)
        assert delta == {"CVE-2021-23017"}
        report = Matcher(connection).run(only_vulnerabilities=delta)
        rows = connection.execute(
            "SELECT snapshot_id, created_at FROM package_vuln_match"
            " WHERE vulnerability_id = 'CVE-2021-23017' ORDER BY created_at"
        ).fetchall()

    # A new intel revision is a new decision even when the version still matches: the old row
    # stays as history and the newest row is what the API and the graph read.
    assert report.new_matches == 1
    assert len(rows) == 2
    assert rows[0]["snapshot_id"] != rows[1]["snapshot_id"]


def test_a_value_without_a_cpe_is_not_guessed_at(database: tuple[str, list[str]]) -> None:
    dsn, jobs = database
    ingest_services(
        dsn,
        jobs[0],
        observations=[
            observation(
                fixtures.NGINX_SERVICE_KEY,
                "service.product",
                {"product": "nginx", "version": "1.18.0"},
            )
        ],
    )
    with connect(dsn) as connection:
        fixtures.seed_intel(dsn)
        report = Matcher(connection).run()
        found = fixtures.matches(connection)

    assert found == []
    assert report.skipped_values >= 1
    assert report.new_matches == 0


def test_a_campaign_without_targets_matches_nothing(database: tuple[str, list[str]]) -> None:
    dsn, jobs = database
    ingest_services(dsn, jobs[0])
    with connect(dsn) as connection:
        fixtures.seed_intel(dsn)
        report = Matcher(connection).run(campaign_id="01900000-0000-7000-8000-0000000c00ff")

    assert report.targets == 0
    assert report.new_matches == 0


def test_a_dry_run_reports_without_writing(database: tuple[str, list[str]]) -> None:
    dsn, jobs = database
    ingest_services(dsn, jobs[0])
    with connect(dsn) as connection:
        fixtures.seed_intel(dsn)
        report = Matcher(connection).run(dry_run=True)
        found = fixtures.matches(connection)
        events = fixtures.events(connection, VULNERABILITY_EVENT)

    assert report.new_matches == 3
    assert found == [] and events == []


def test_a_withdrawn_cve_is_not_a_candidate(database: tuple[str, list[str]]) -> None:
    dsn, jobs = database
    ingest_services(dsn, jobs[0])
    with connect(dsn) as connection:
        fixtures.seed_intel(dsn)
        FeedSync(fixtures.connector(dsn), fixtures.MemoryStore()).sync(
            "nvd",
            "2026-11-26",
            fixtures.nvd_with_rejected_cve(),
            source_uri="nvd-slice.json",
            snapshot_at=fixtures.SNAPSHOT_AT,
        )
        report = Matcher(connection).run()
        found = {row["vulnerability_id"] for row in fixtures.matches(connection)}

    assert report.new_matches == 2
    assert found == {"CVE-2021-23017", "CVE-2022-22965"}
