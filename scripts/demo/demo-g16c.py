#!/usr/bin/env python3
"""`make demo-g16c` - the G1.6 slice C gate: service fingerprint -> CVE candidate with KEV/EPSS.

What it does, in the order an operator would:

1. `POST /campaigns` - a campaign seeded on the lab zone (the same body `demo-g1` uses).
2. A fingerprinted service is ingested by M27. Slice A's adapters are a separate task, so
   `slice_a.py` submits the envelope they will produce (Apache 2.4.49 on :80, nginx 1.18.0 on
   :8080, and the Spring application nginx serves) through the real ingestion port.
3. `python -m aegis.m18_intel sync` for the three pinned feed slices (NVD CVE JSON 2.0, CISA KEV,
   FIRST EPSS): the bytes go to S3 content addressed, `intel_snapshot` +
   `vulnerability_revision` are written, `intel.revision.v2` is published.
4. The M20 matcher turns the observations' CPEs into candidate `package_vuln_match` rows and
   `vulnerability.matched.v2` events - candidates, never findings.
5. The running projector (M23) draws `(service)-[:AFFECTED_BY]->(:Vulnerability)` with the CVSS,
   KEV and EPSS values of the pinned intel; the demo waits for the edge instead of writing it.
6. `GET /assets/{asset_id}/vulnerabilities` returns the same candidates to the operator, validated
   against the contract.
7. Every claim is checked against PostgreSQL and Neo4j and written to `.local/demo/`.

Exit codes: 0 = every check passed, 1 = a check failed (the failing line is printed), 2 = the stack
is not ready (the message says which setting or container is missing).
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import slice_a  # noqa: E402 - the slice A stand-in, a sibling module
import support  # noqa: E402 - the demo scripts' shared helpers, a sibling module

INTEL_FIXTURES = support.REPO / "tests/fixtures/intel"
INTEL_VERSION = "2026-11-24"
PROJECTION_TIMEOUT_ENV = "G16C_PROJECTION_TIMEOUT"
DEFAULT_PROJECTION_TIMEOUT = 120.0


def main(argv: list[str] | None = None) -> int:
    del argv
    support.load_demo_env()
    _require_environment()
    support.section("0. stack")
    support.line("postgres", _masked(os.environ["AEGIS_PG_DSN"]))
    support.line("neo4j", os.environ["AEGIS_NEO4J_URI"])
    support.line("api", os.environ["AEGIS_API_URL"])
    support.line("s3", os.environ.get("AEGIS_S3_ENDPOINT", "-"))

    support.section("1. campaign (POST /campaigns, lab seed)")
    campaign_id = support.create_campaign("G1.6c CVE/CTI demo")
    support.line("campaign_id", campaign_id)

    connection = support.pg()
    try:
        support.section("2. slice A stand-in: a fingerprinted service, ingested by M27")
        ingested = slice_a.ingest_services(connection, campaign_id)
        support.line("job_id", ingested["job_id"])
        support.line("receipt", json.dumps(ingested["receipt"], sort_keys=True))
        for key, asset_id in ingested["assets"].items():
            support.line("asset", key, "->", asset_id)

        support.section("3. intel: pinned NVD/KEV/EPSS slices -> S3 + PostgreSQL")
        reports = _sync_intel(connection)

        support.section("4. matching: CPE + version -> candidate CVEs")
        from aegis.m20_vuln.matching import Matcher

        report = Matcher(connection).run(campaign_id=campaign_id)
        support.line("counters", json.dumps(report.as_dict(), sort_keys=True))
        candidates = _candidates(connection, ingested["assets"])
        support.require(
            candidates, "the matcher produced no candidate for the fingerprinted services"
        )
        for item in candidates:
            support.line(
                "candidate",
                item["canonical_key"],
                item["vulnerability_id"],
                f"cvss={item['cvss_base']}",
                f"kev={item['kev']}",
                f"epss={item['epss']}",
                f"confidence={item['confidence']}",
            )

        support.section("5. graph: :Vulnerability + AFFECTED_BY (M23 projector)")
        projected = _wait_for_projection(ingested["assets"])
        for item in projected:
            support.line(
                "edge",
                f"{item['canonical_key']} -[:AFFECTED_BY]-> {item['vulnerability_id']}",
                f"cvss={item['cvss_base']}",
                f"kev={item['kev']}",
                f"epss={item['epss']}",
                f"confidence={item['confidence']}",
            )

        support.section("6. API: GET /assets/{asset_id}/vulnerabilities")
        api_items = _api_items(ingested["assets"])

        support.section("7. evidence")
        evidence = {
            "campaign_id": campaign_id,
            "intel": reports,
            "matching": report.as_dict(),
            "candidates": candidates,
            "graph": projected,
            "api": api_items,
        }
        _check(evidence, ingested)
    finally:
        connection.close()

    support.section("evidence file")
    support.line(str(support.write_artifact(f"g16c-{_stamp()}.json", evidence)))
    support.section("result")
    support.line("PASS - service -> CVE candidate with KEV/EPSS, in PostgreSQL and Neo4j")
    return 0


def _require_environment() -> None:
    for name in ("AEGIS_PG_DSN", "AEGIS_NEO4J_URI", "AEGIS_NEO4J_PASSWORD", "AEGIS_API_URL"):
        support.require(os.environ.get(name), f"{name} is not set: run `make run-local` first")
    support.require(
        os.environ.get("AEGIS_S3_ENDPOINT") and os.environ.get("AEGIS_S3_BUCKET"),
        "AEGIS_S3_ENDPOINT/AEGIS_S3_BUCKET are not set: run `make run-local` first",
    )


def _masked(dsn: str) -> str:
    """The DSN without its password, for the log line."""
    head, _, tail = dsn.partition(" password=")
    if not tail:
        return dsn
    rest = tail.split(" ", 1)
    return f"{head} password=***' {rest[1] if len(rest) > 1 else ''}".strip()


def _sync_intel(connection: Any) -> dict[str, Any]:
    """Load the three committed slices through the real M18 sync, one snapshot per feed."""
    from aegis.m18_intel.sync import FeedSync

    sync = FeedSync.from_env()
    reports: dict[str, Any] = {}
    for feed, path in (
        ("nvd", INTEL_FIXTURES / "nvd-slice.json"),
        ("kev", INTEL_FIXTURES / "kev-slice.json"),
        ("epss", INTEL_FIXTURES / "epss-slice.csv"),
    ):
        report = sync.sync(
            feed,
            INTEL_VERSION,
            path.read_bytes(),
            source_uri=path.name,
            snapshot_at=datetime(2026, 11, 24, 6, 0, tzinfo=UTC),
        )
        reports[feed] = report.as_dict()
        support.line(
            "sync",
            feed,
            f"records={report.records}",
            f"written={report.written}",
            f"unchanged={report.unchanged}",
            f"sha256={report.content_sha256[:12]}",
            f"event={report.event_published}",
        )
    stored = support.rows(
        connection,
        "SELECT feed, version, content_sha256, record_count, source_uri FROM intel_snapshot"
        " ORDER BY feed",
    )
    support.line("intel_snapshot", len(stored), "rows")
    return reports


def _candidates(connection: Any, assets: dict[str, str]) -> list[dict[str, Any]]:
    return support.rows(
        connection,
        """
        SELECT a.canonical_key, m.vulnerability_id, m.match_method, m.confidence,
               m.affected_range, m.snapshot_id,
               nvd.cvss->>'base_score' AS cvss_base,
               nvd.cvss->>'base_severity' AS cvss_severity,
               (k.kev IS NOT NULL) AS kev,
               e.epss->>'score' AS epss
          FROM package_vuln_match m
          JOIN asset a ON a.asset_id = m.package_asset_id
          LEFT JOIN vulnerability_current nvd
            ON nvd.vulnerability_id = m.vulnerability_id AND nvd.source = 'nvd'
          LEFT JOIN vulnerability_current k
            ON k.vulnerability_id = m.vulnerability_id AND k.source = 'kev'
          LEFT JOIN vulnerability_current e
            ON e.vulnerability_id = m.vulnerability_id AND e.source = 'epss'
         WHERE m.package_asset_id = ANY(%s::uuid[])
         ORDER BY a.canonical_key, m.vulnerability_id
        """,
        (list(assets.values()),),
    )


def _neo4j_driver() -> Any:
    from neo4j import GraphDatabase

    return GraphDatabase.driver(
        os.environ["AEGIS_NEO4J_URI"],
        auth=(os.environ.get("AEGIS_NEO4J_USER", "neo4j"), os.environ["AEGIS_NEO4J_PASSWORD"]),
    )


def _wait_for_projection(assets: dict[str, str]) -> list[dict[str, Any]]:
    """Poll the graph the running projector writes; never write it from the demo."""
    timeout = float(os.environ.get(PROJECTION_TIMEOUT_ENV) or DEFAULT_PROJECTION_TIMEOUT)
    driver = _neo4j_driver()
    deadline = time.monotonic() + timeout
    try:
        while True:
            records, _, _ = driver.execute_query(
                "MATCH (a:Asset)-[r:AFFECTED_BY]->(v:Vulnerability)"
                " WHERE a.asset_id IN $ids"
                " RETURN a.canonical_key AS canonical_key, v.vulnerability_id AS vulnerability_id,"
                "        v.cvss_base AS cvss_base, v.kev AS kev, v.epss AS epss,"
                "        r.confidence AS confidence, r.affected_range AS affected_range"
                " ORDER BY a.canonical_key, v.vulnerability_id",
                ids=list(assets.values()),
            )
            projected = [dict(record) for record in records]
            if projected:
                return projected
            if time.monotonic() >= deadline:
                support.fail(
                    "no AFFECTED_BY edge appeared in the graph within "
                    f"{timeout:.0f}s: the projector (`make run-local` starts it) must be running "
                    "and its cursor behind the outbox; after a graph wipe, rebuild the projection "
                    "with `python -m aegis.m23_graph rebuild`"
                )
            time.sleep(0.5)
    finally:
        driver.close()


def _api_items(assets: dict[str, str]) -> list[dict[str, Any]]:
    token = support.operator_token()
    items: list[dict[str, Any]] = []
    for key, asset_id in assets.items():
        body = support.api("GET", f"/api/v2/assets/{asset_id}/vulnerabilities", token=token)
        for item in body.get("items", []):
            items.append({"canonical_key": key, **item})
        support.line("api", key, json.dumps(body.get("items", []), sort_keys=True))
    return items


def _check(evidence: dict[str, Any], ingested: dict[str, Any]) -> None:
    support.require(
        all(report["records"] > 0 for report in evidence["intel"].values()),
        "an intel snapshot loaded no record",
    )
    candidates = evidence["candidates"]
    service_candidates = {
        item["vulnerability_id"]
        for item in candidates
        if item["canonical_key"].startswith("service:")
    }
    support.require(
        "CVE-2021-41773" in service_candidates,
        "the Apache 2.4.49 service has no CVE-2021-41773 candidate",
    )
    support.require(
        any(item["vulnerability_id"] == "CVE-2022-22965" for item in candidates),
        "the Spring application has no CVE-2022-22965 candidate",
    )
    kev = [item for item in candidates if item["kev"]]
    support.require(kev, "no candidate carries a KEV flag")
    support.require(
        all(item["epss"] is not None for item in candidates), "a candidate has no EPSS score"
    )
    support.require(
        all(item["cvss_base"] is not None for item in candidates), "a candidate has no CVSS score"
    )
    graph = evidence["graph"]
    support.require(
        {item["vulnerability_id"] for item in graph}
        == {item["vulnerability_id"] for item in candidates},
        "the graph edges and the candidates disagree",
    )
    support.require(
        all(item["kev"] is not None for item in graph), "a graph edge lost its KEV flag"
    )
    api = evidence["api"]
    support.require(
        {item["vulnerability_id"] for item in api}
        == {item["vulnerability_id"] for item in candidates},
        "the API and the candidates disagree",
    )
    support.require(
        all(item["confidence"] is not None for item in api), "an API candidate has no confidence"
    )
    connection = support.pg()
    try:
        events = support.count(
            connection,
            "SELECT count(*) FROM outbox_event WHERE type = 'vulnerability.matched.v2'",
        )
        support.line("events", events, "vulnerability.matched.v2")
        support.require(events >= len(candidates), "fewer events than candidates")
        support.require(
            support.count(connection, "SELECT count(*) FROM vulnerability_revision") > 0,
            "no vulnerability_revision rows",
        )
    finally:
        connection.close()
    support.line(
        "M27 receipt",
        f"accepted={ingested['receipt'].get('accepted')}",
        f"duplicate={ingested['receipt'].get('duplicate')}",
        f"revision={ingested['receipt'].get('revision')}",
    )


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


if __name__ == "__main__":
    sys.exit(main())
