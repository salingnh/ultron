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
from aegis.m20_vuln.matching import (
    VERSION_UNKNOWN_CODE,
    VERSION_UNKNOWN_MESSAGE,
    Matcher,
    changed_vulnerabilities,
)
from aegis.m23_graph.models import VULNERABILITY_EVENT
from tests import db_support as support
from tests import g16c_support as fixtures
from tests.db_support import requires_postgres
from tests.m23_support import connect, ingest, pipeline_database
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
