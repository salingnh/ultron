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
from aegis.m20_vuln.configurations import (
    PLATFORM_UNCONFIRMED_CODE,
    VERSION_UNSPECIFIED_CODE,
)
from aegis.m20_vuln.matching import (
    NO_LONGER_MATCHES_CODE,
    VERSION_UNKNOWN_CODE,
    VERSION_UNKNOWN_MESSAGE,
    WITHDRAWN_CODE,
    Matcher,
    changed_vulnerabilities,
)
from aegis.m23_graph.models import VULNERABILITY_EVENT
from tests import db_support as support
from tests import g16c_support as fixtures
from tests.db_support import requires_postgres
from tests.m23_support import CAMPAIGN_ID, connect, ingest, pipeline_database
from tests.support_ingestion import asset, observation

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


def test_a_configuration_that_needs_an_unobserved_platform_is_not_a_candidate(
    database: tuple[str, list[str]],
) -> None:
    """Item 61: the trial's httpd 2.4.49 service was a candidate for "httpd on Windows".

    The fixture adds CVE-2024-40898 (httpd < 2.4.62 **and** microsoft:windows), CVE-1999-0289
    (`http_server:-`, no version) and CVE-2021-42013 (a real bounded range). Only the range may
    become a candidate, and the two rejected decisions must be visible in the report's coverage.
    """
    dsn, jobs = database
    ingest_services(dsn, jobs[0])
    with connect(dsn) as connection:
        fixtures.seed_intel(dsn)
        FeedSync(fixtures.connector(dsn), fixtures.MemoryStore()).sync(
            "nvd",
            "2026-11-26-configurations",
            fixtures.nvd_with_configuration_cases(),
            source_uri="nvd-configurations.json",
            snapshot_at=fixtures.SNAPSHOT_AT,
        )
        report = Matcher(connection).run()
        found = fixtures.matches(connection)

    candidates = {row["vulnerability_id"] for row in found}
    assert candidates == {"CVE-2021-41773", "CVE-2021-23017", "CVE-2022-22965", "CVE-2021-42013"}
    assert "CVE-2024-40898" not in candidates
    assert "CVE-1999-0289" not in candidates
    assert report.new_matches == 4
    assert report.platform_unconfirmed == 1
    assert report.version_unspecified == 1

    limitations = {item["code"]: item for item in report.coverage["limitations"]}
    platform = limitations[PLATFORM_UNCONFIRMED_CODE]
    assert platform["vulnerability_ids"] == ["CVE-2024-40898"]
    assert platform["subjects"] == [fixtures.SERVICE_KEY]
    assert platform["decisions"] == 1
    assert limitations[VERSION_UNSPECIFIED_CODE]["vulnerability_ids"] == ["CVE-1999-0289"]
    # The range candidate keeps its bounds, so an operator can audit what matched.
    range_row = next(row for row in found if row["vulnerability_id"] == "CVE-2021-42013")
    assert range_row["affected_range"] == ">= 2.4.49, <= 2.4.50"


def _current_candidates(connection: Any) -> set[str]:
    """CVE ids whose newest decision per (asset, vulnerability) is a match (the read-model rule)."""
    rows = connection.execute(
        "WITH latest AS ("
        "  SELECT DISTINCT ON (package_asset_id, vulnerability_id)"
        "         vulnerability_id, matched"
        "    FROM package_vuln_match"
        "   ORDER BY package_asset_id, vulnerability_id, created_at DESC, match_id DESC"
        ")"
        " SELECT vulnerability_id FROM latest WHERE matched"
    ).fetchall()
    return {str(row["vulnerability_id"]) for row in rows}


def _decisions(connection: Any, vulnerability_id: str) -> list[dict[str, Any]]:
    rows = connection.execute(
        "SELECT match_id, matched, retraction_reason, vuln_rev_id, campaign_id, confidence"
        "  FROM package_vuln_match WHERE vulnerability_id = %s"
        " ORDER BY created_at, match_id",
        (vulnerability_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def test_a_new_revision_that_stops_matching_retracts_the_candidate(
    database: tuple[str, list[str]],
) -> None:
    """Item 61 retraction: a match at revision N, a non-match at N+1 -> the candidate is gone.

    History stays (the positive decision at N is still a row), the retraction is a decision of its
    own at N+1 with the reason, and it publishes the event M23 removes the edge from. A second run
    at the same revision writes neither a row nor an event.
    """
    dsn, jobs = database
    ingest_services(dsn, jobs[0])
    with connect(dsn) as connection:
        fixtures.seed_intel(dsn)
        first = Matcher(connection).run()
        assert first.new_matches == 3
        events_before = len(fixtures.events(connection, VULNERABILITY_EVENT))

        based = FeedSync(fixtures.connector(dsn), fixtures.MemoryStore()).sync(
            "nvd",
            "2026-11-27",
            fixtures.nvd_with_retracted_match(),
            source_uri="nvd-retraction.json",
            snapshot_at=fixtures.SNAPSHOT_AT,
        )
        report = Matcher(connection).run()
        decisions = _decisions(connection, "CVE-2021-41773")
        events = fixtures.events(connection, VULNERABILITY_EVENT)
        found = _current_candidates(connection)

    assert based.written == 1  # one revision: the re-analysed CVE
    assert report.retracted == 1
    assert report.new_matches == 0
    assert report.retractions_blocked == 0
    assert len(report.retractions) == 1
    retraction = report.retractions[0]
    assert retraction["asset"] == fixtures.SERVICE_KEY
    assert retraction["vulnerability_id"] == "CVE-2021-41773"
    assert retraction["reason"] == NO_LONGER_MATCHES_CODE
    assert retraction["snapshot_id"] == based.snapshot_id
    assert retraction["campaign_id"] == str(decisions[0]["campaign_id"])

    # History: the match at the old revision and the retraction at the new one.
    assert [row["matched"] for row in decisions] == [True, False]
    assert decisions[1]["retraction_reason"] == NO_LONGER_MATCHES_CODE
    assert decisions[1]["vuln_rev_id"] != decisions[0]["vuln_rev_id"]
    assert decisions[1]["confidence"] is None
    assert decisions[1]["campaign_id"] == decisions[0]["campaign_id"]

    # The read model's newest row of the pair is the retraction, so the candidate is gone while
    # both rows stay in the append-only history.
    assert {"CVE-2021-23017", "CVE-2022-22965"} == found

    # One event for the retraction, carrying the retraction's own match_id.
    assert len(events) == events_before + 1
    assert events[-1]["dedup_key"] == str(decisions[1]["match_id"])
    assert events[-1]["payload"]["vulnerability_id"] == "CVE-2021-41773"
    assert events[-1]["payload"]["campaign_id"] == str(decisions[1]["campaign_id"])

    # Idempotent: the newest decision is already a retraction, so nothing is written again.
    with connect(dsn) as connection:
        again = Matcher(connection).run()
        assert _decisions(connection, "CVE-2021-41773") == decisions
        assert len(fixtures.events(connection, VULNERABILITY_EVENT)) == events_before + 1
    assert again.retracted == 0 and again.retractions_blocked == 0


def test_a_rejected_revision_retracts_the_candidate_it_withdraws(
    database: tuple[str, list[str]],
) -> None:
    """A CVE NVD rejects after it matched is never a candidate again: reason WITHDRAWN."""
    dsn, jobs = database
    ingest_services(dsn, jobs[0])
    with connect(dsn) as connection:
        fixtures.seed_intel(dsn)
        Matcher(connection).run()
        FeedSync(fixtures.connector(dsn), fixtures.MemoryStore()).sync(
            "nvd",
            "2026-11-27",
            fixtures.nvd_with_rejected_cve(),
            source_uri="nvd-rejected.json",
            snapshot_at=fixtures.SNAPSHOT_AT,
        )
        report = Matcher(connection).run()
        decisions = _decisions(connection, "CVE-2021-41773")
        current = _current_candidates(connection)

    assert report.retracted == 1
    assert decisions[-1]["matched"] is False
    assert decisions[-1]["retraction_reason"] == WITHDRAWN_CODE
    assert "CVE-2021-41773" not in current


def test_a_retraction_that_cannot_be_written_is_counted_for_the_next_sync(
    database: tuple[str, list[str]],
) -> None:
    """A code change without a new intel revision cannot retract: the append-only key refuses it.

    M20 counts that case instead of writing a row the unique index would drop, so an operator sees
    that the candidate is stale only until the next sync instead of never.
    """
    dsn, jobs = database
    ingest_services(dsn, jobs[0])
    with connect(dsn) as connection:
        fixtures.seed_intel(dsn)
        Matcher(connection).run()
        FeedSync(fixtures.connector(dsn), fixtures.MemoryStore()).sync(
            "nvd",
            "2026-11-27",
            fixtures.nvd_with_retracted_match(),
            source_uri="nvd-retraction.json",
            snapshot_at=fixtures.SNAPSHOT_AT,
        )
        # A match already recorded *at the current revision* (the state a previous run of another
        # build left behind): the retraction would be the same (asset, vuln, rev, method) key.
        current = connection.execute(
            "SELECT vulnerability_id, vuln_rev_id, snapshot_id FROM vulnerability_current"
            " WHERE source = 'nvd' AND vulnerability_id = 'CVE-2021-41773'"
        ).fetchone()
        owner = connection.execute(
            "SELECT asset_id FROM asset WHERE canonical_key = %s", (fixtures.SERVICE_KEY,)
        ).fetchone()
        assert current is not None and owner is not None
        asset_id = owner["asset_id"]
        connection.execute(
            "INSERT INTO package_vuln_match (match_id, package_asset_id, vulnerability_id,"
            " vuln_rev_id, match_method, matched, confidence, snapshot_id, campaign_id)"
            " VALUES (%s, %s, 'CVE-2021-41773', %s, 'cpe_range', TRUE, 0.7, %s, %s)",
            (
                "01900000-0000-7000-8000-0000000c0a99",
                asset_id,
                current["vuln_rev_id"],
                current["snapshot_id"],
                CAMPAIGN_ID,
            ),
        )
        report = Matcher(connection).run()
        rows = _decisions(connection, "CVE-2021-41773")

    assert report.retractions_blocked == 1
    assert report.retracted == 0
    assert [row["matched"] for row in rows][-1] is True  # the stale decision stays the newest


def test_a_revision_that_stops_naming_the_product_still_retracts(
    database: tuple[str, list[str]],
) -> None:
    """The narrowed catalogue never shows this CVE to the run: the retraction decides it here."""
    dsn, jobs = database
    ingest_services(dsn, jobs[0])
    with connect(dsn) as connection:
        fixtures.seed_intel(dsn)
        Matcher(connection).run()
        FeedSync(fixtures.connector(dsn), fixtures.MemoryStore()).sync(
            "nvd",
            "2026-11-27",
            fixtures.nvd_without_the_product(),
            source_uri="nvd-no-product.json",
            snapshot_at=fixtures.SNAPSHOT_AT,
        )
        report = Matcher(connection).run()
        decisions = _decisions(connection, "CVE-2021-41773")
        current = _current_candidates(connection)

    assert report.retracted == 1
    assert [row["matched"] for row in decisions] == [True, False]
    assert decisions[-1]["retraction_reason"] == NO_LONGER_MATCHES_CODE
    assert "CVE-2021-41773" not in current

    # A delta run scoped to another CVE leaves the tail alone: it did not look at it.
    with connect(dsn) as connection:
        assert _decisions(connection, "CVE-2021-41773")[-1]["matched"] is False
        scoped = Matcher(connection).run(only_vulnerabilities={"CVE-2021-23017"})
    assert scoped.retracted == 0


def _ensure_0007(dsn: str) -> None:
    import psycopg

    migration = (support.REPO / "contracts/db/postgres/0007_intel_indexes.sql").read_text(
        encoding="utf-8"
    )
    with psycopg.connect(dsn, autocommit=True) as conn:
        row = conn.execute(
            "SELECT to_regprocedure('aegis.nvd_cpe_products(jsonb)') IS NOT NULL"
        ).fetchone()
        if row and row[0]:
            return
        conn.execute(migration)


def test_versionless_products_yield_no_candidates_and_report_coverage(
    database: tuple[str, list[str]],
) -> None:
    dsn, jobs = database
    ssh_key = "service:10.114.53.20:22/tcp"
    nginx_key = "service:10.114.53.20:80/tcp"
    app_key = "app:http://10.114.53.20:80"
    ingest(
        dsn,
        jobs[0],
        assets=[
            asset("dns:edge.internal.example", "domain"),
            asset(ssh_key, "service", discovered_from=("dns:edge.internal.example",)),
            asset(nginx_key, "service", discovered_from=("dns:edge.internal.example",)),
            asset(app_key, "application", discovered_from=(nginx_key,)),
        ],
        observations=[
            observation(
                ssh_key,
                "service.product",
                {
                    "product": "OpenSSH",
                    "version": "8.9p1",
                    "cpe": "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*",
                },
            ),
            observation(
                nginx_key,
                "service.product",
                {"vendor": "f5", "product": "nginx", "cpe": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"},
            ),
            observation(app_key, "http.technology", ["openresty", "nginx"]),
        ],
        coverage=[ssh_key, nginx_key, app_key],
    )
    import json as _json

    openssh_nvd = _json.dumps(
        {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-38408",
                        "vulnStatus": "Analyzed",
                        "lastModified": "2026-11-24T06:00:00.000",
                        "descriptions": [{"lang": "en", "value": "OpenSSH PKCS11"}],
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {
                                                "vulnerable": True,
                                                "criteria": (
                                                    "cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*"
                                                ),
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                }
            ]
        }
    ).encode("utf-8")
    _ensure_0007(dsn)
    FeedSync(fixtures.connector(dsn), fixtures.MemoryStore()).sync(
        "nvd",
        "2026-11-24-ssh",
        openssh_nvd,
        source_uri="openssh.json",
        snapshot_at=fixtures.SNAPSHOT_AT,
    )
    with connect(dsn) as connection:
        report = Matcher(connection).run()
        found = fixtures.matches(connection)

    assert [row["vulnerability_id"] for row in found] == ["CVE-2023-38408"]
    assert found[0]["canonical_key"] == ssh_key
    assert report.unmatchable_targets == 2
    assert report.coverage["subjects"] == 3
    assert report.coverage["matchable_subjects"] == 1
    assert report.coverage["unmatchable_subjects"] == 2
    limitation = report.coverage["limitations"][0]
    assert limitation["code"] == VERSION_UNKNOWN_CODE
    assert limitation["message"] == VERSION_UNKNOWN_MESSAGE
    assert set(limitation["products"]) == {"nginx", "openresty"}
    assert report.coverage["by_subject"][app_key]["matchable"] is False


def test_gin_indexed_catalogue_narrows_100_services(database: tuple[str, list[str]]) -> None:
    dsn, jobs = database
    _ensure_0007(dsn)
    service_assets = [asset("dns:scale.internal.example", "domain")]
    service_obs = []
    service_cov = []
    for port in range(1000, 1100):
        key = f"service:10.114.53.99:{port}/tcp"
        service_assets.append(
            asset(key, "service", discovered_from=("dns:scale.internal.example",))
        )
        service_obs.append(
            observation(
                key,
                "service.product",
                {
                    "product": "OpenSSH",
                    "version": "8.9p1",
                    "cpe": "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*",
                },
            )
        )
        service_cov.append(key)
    ingest(dsn, jobs[0], assets=service_assets, observations=service_obs, coverage=service_cov)
    import json as _json

    entries = [
        {
            "cve": {
                "id": f"CVE-2024-{10000 + idx}",
                "vulnStatus": "Analyzed",
                "lastModified": "2026-11-24T06:00:00.000",
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": (
                                            "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"
                                            if idx < 3
                                            else f"cpe:2.3:a:unrelated{idx}:app:*:*:*:*:*:*:*:*"
                                        ),
                                        "versionStartIncluding": "8.0",
                                        "versionEndExcluding": "9.3",
                                    }
                                ]
                            }
                        ]
                    }
                ],
            }
        }
        for idx in range(50)
    ]
    FeedSync(fixtures.connector(dsn), fixtures.MemoryStore()).sync(
        "nvd",
        "2026-11-24-scale",
        _json.dumps({"vulnerabilities": entries}).encode("utf-8"),
        source_uri="scale.json",
        snapshot_at=fixtures.SNAPSHOT_AT,
    )
    with connect(dsn) as connection:
        report = Matcher(connection).run()

    assert report.targets == 100
    assert report.catalogue_revisions == 3
    assert report.new_matches == 300
