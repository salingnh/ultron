#!/usr/bin/env python3
"""`make demo-g16c` - the G1.6 slice C gate: real discovery -> CVE candidate with KEV/EPSS.

What it does, in the order an operator would:

1. `POST /campaigns` - a campaign on the lab zone whose objective asks for the services on the
   resolved addresses (the same body `demo-discovery` uses). The real chain runs: Subfinder ->
   DNSx -> naabu, and M27 records the Service assets and their port observations.
2. `python -m aegis.m18_intel sync` for the three pinned feed slices (NVD CVE JSON 2.0, CISA KEV,
   FIRST EPSS): the bytes go to S3 content addressed, `intel_snapshot` +
   `vulnerability_revision` are written, `intel.revision.v2` is published.
3. The M20 matcher turns the *product/version/CPE observations* of those services into candidate
   `package_vuln_match` rows and `vulnerability.matched.v2` events - candidates, never findings.
4. The running projector (M23) draws `(service)-[:AFFECTED_BY]->(:Vulnerability)` with the CVSS,
   KEV and EPSS values of the pinned intel; the demo waits for the edge instead of writing it.
5. `GET /assets/{asset_id}/vulnerabilities` returns the same candidates to the operator, validated
   against the contract. The service table carries CVE-2021-41773 (httpd 2.4.49) and CVE-2020-1938
   (Tomcat 9.0.30, read from its error page body); the AJP port 8009 stays product-less.
6. Every claim is checked against PostgreSQL and Neo4j and written to `.local/demo/`.

The product/version/CPE row is the dedicated fingerprinter's (slice B): the port scan reports a
service by address and transport and deliberately does not guess what runs behind it (see the
naabu manifest's licenseNotes). Until that adapter is on the branch the demo runs the real chain,
reports which services it found and exits **2 (BLOCKED)**: the chain reached the service level, the
CVE stage has nothing to match yet. It never writes a stand-in row.

Exit codes: 0 = every check passed, 1 = a check failed (the failing line is printed), 2 = the chain
ran but the CVE stage has no product observation to match (BLOCKED), or the stack is not ready.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.parse
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import support  # noqa: E402 - the demo scripts' shared helpers, a sibling module

INTEL_FIXTURES = support.REPO / "tests/fixtures/intel"
INTEL_VERSION = "2026-11-24"
PROJECTION_TIMEOUT_ENV = "G16C_PROJECTION_TIMEOUT"
DEFAULT_PROJECTION_TIMEOUT = 120.0
CAMPAIGN_TIMEOUT_ENV = "G16C_CAMPAIGN_TIMEOUT"
DEFAULT_CAMPAIGN_TIMEOUT = 420.0
#: The objective the scripted policy reads: it runs the DNS chain and then the port/service step.
OBJECTIVE = (
    "Enumerate the subdomains of the authorized lab zone, resolve the names the enumeration "
    "found, then discover which ports and services those addresses expose so every address is "
    "linked to the services behind it"
)


def main(argv: list[str] | None = None) -> int:
    del argv
    support.load_demo_env()
    _require_environment()
    support.section("0. stack")
    support.line("postgres", _masked(os.environ["AEGIS_PG_DSN"]))
    support.line("neo4j", os.environ["AEGIS_NEO4J_URI"])
    support.line("api", os.environ["AEGIS_API_URL"])
    support.line("s3", os.environ.get("AEGIS_S3_ENDPOINT", "-"))

    support.section("1. campaign (POST /campaigns, real discovery chain)")
    campaign_id = support.create_campaign("G1.6c CVE/CTI demo", OBJECTIVE)
    support.line("campaign_id", campaign_id)
    campaign_timeout = float(os.environ.get(CAMPAIGN_TIMEOUT_ENV) or DEFAULT_CAMPAIGN_TIMEOUT)
    finished = support.wait_campaign(campaign_id, timeout_seconds=campaign_timeout)
    status = str(finished.get("status"))
    support.line("status", status, "|", finished.get("status_reason") or "-")
    support.require(status == "COMPLETED", f"the campaign ended {status}, not COMPLETED")

    connection = support.pg()
    try:
        support.section("2. the services the real adapters reported")
        services, jobs = _services(connection, campaign_id)
        for job in jobs:
            support.line("job", job["capability"], job["provider"], job["status"])
        support.require(
            all(job["status"] == "SUCCEEDED" for job in jobs), "a discovery job did not succeed"
        )
        support.require(services, "the chain recorded no service asset")
        for item in services:
            support.line(
                "service",
                item["canonical_key"],
                "| product",
                json.dumps(item["product"], sort_keys=True) if item["product"] else "none",
            )
        targetable = {item["canonical_key"]: item["asset_id"] for item in services}
        products = [item for item in services if item["product"]]

        support.section("2b. activity: GET /campaigns/{id}/activity against the rows")
        activity = _activity(connection, campaign_id)

        support.section("3. intel: pinned NVD/KEV/EPSS slices -> S3 + PostgreSQL")
        reports = _sync_intel(connection)

        if not products:
            support.section("4. CVE stage: BLOCKED, no product/version/CPE observation")
            support.line(
                "reason",
                "the port scan reports a service by address and transport and does not guess the",
            )
            support.line(
                "        product behind it (naabu's own -sV misattributes a host's probe answer to",
            )
            support.line(
                "        every host on the same port, so it is not enabled); the fingerprinter",
            )
            support.line(
                "        (slice B) is what writes service.product {product, version, cpe}."
            )
            support.line("services found", len(services))
            support.line("result", "BLOCKED - the chain ran on real adapters; nothing to match yet")
            evidence = {
                "campaign_id": campaign_id,
                "jobs": jobs,
                "services": services,
                "intel": reports,
                "activity": activity,
                "verdict": "BLOCKED",
                "blocked_on": "no service.product observation (fingerprinter, slice B)",
            }
            support.section("evidence file")
            support.line(str(support.write_artifact(f"g16c-{_stamp()}.json", evidence)))
            return 2

        support.section("4. matching: CPE + version -> candidate CVEs")
        from aegis.m20_vuln.matching import Matcher

        report = Matcher(connection).run(campaign_id=campaign_id)
        support.line("counters", json.dumps(report.as_dict(), sort_keys=True))
        candidates = _candidates(connection, targetable)
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
        projected = _wait_for_projection(targetable)
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
        api_items = _api_items(targetable)

        support.section("7. evidence")
        evidence = {
            "campaign_id": campaign_id,
            "jobs": jobs,
            "services": services,
            "intel": reports,
            "matching": report.as_dict(),
            "candidates": candidates,
            "graph": projected,
            "api": api_items,
            "activity": activity,
            "verdict": "PASS",
        }
        _check(evidence, targetable)
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


def _services(
    connection: Any, campaign_id: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The campaign's service assets with their newest product observation, and its jobs."""
    jobs = support.rows(
        connection,
        "SELECT job_id, capability, provider, status FROM scan_job"
        " WHERE campaign_id = %s ORDER BY created_at",
        (campaign_id,),
    )
    services = support.rows(
        connection,
        """
        SELECT a.asset_id::text AS asset_id, a.canonical_key,
               (SELECT o.value FROM observation o
                 WHERE o.subject_asset_id = a.asset_id
                   AND o.predicate = 'service.product' AND o.polarity = 'present'
                 ORDER BY o.revision DESC LIMIT 1) AS product
          FROM asset a
          JOIN asset_campaign ac ON ac.asset_id = a.asset_id AND ac.campaign_id = %s
         WHERE a.kind = 'service'
         ORDER BY a.canonical_key
        """,
        (campaign_id,),
    )
    return services, jobs


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
    # The candidate set is the graph's rule, not a copy of it: the newest decision of a pair
    # (`aegis.m20_vuln.visibility`), which is what M23 projects and M26 lists. Reading every
    # `package_vuln_match` row here made the demo disagree with the graph on any stack where a
    # newer intel revision retracted an old candidate (P8, item 61 trial).
    from aegis.m20_vuln.visibility import candidate_rows

    return candidate_rows(connection, list(assets.values()))


def _activity(connection: Any, campaign_id: str) -> dict[str, Any]:
    """Every page of the activity feed, checked against the rows it projects (item 63).

    The feed is the operator's answer to "what did the agent do"; this gate proves it is the rows
    and not a story: same entries as `agent_session`/`policy_decision`/`campaign_ledger`, same
    timestamps, every approved decision linked to its job, and the pagination flags honest.
    """
    import urllib.parse

    from aegis.m01_campaign.campaigns import timestamp

    token = support.operator_token()
    items: list[dict[str, Any]] = []
    cursor: str | None = None
    pages = 0
    while True:
        path = f"/api/v2/campaigns/{campaign_id}/activity?limit=100"
        if cursor is not None:
            path += "&cursor=" + urllib.parse.quote(cursor)
        body = support.api("GET", path, token=token)
        pages += 1
        items.extend(body["items"])
        if "next_cursor" not in body:
            support.require(body["truncated"] is False, "the last activity page says truncated")
            break
        support.require(
            body["truncated"] is True, "an activity page with next_cursor is not marked truncated"
        )
        cursor = str(body["next_cursor"])
        support.require(pages < 100, "the activity feed did not terminate")
    support.line("pages", pages, "| entries", len(items))

    expected: dict[str, str] = {}
    for row in support.rows(
        connection,
        "SELECT session_id::text AS session_id, started_at, finished_at FROM agent_session"
        " WHERE campaign_id = %s",
        (campaign_id,),
    ):
        expected[f"session:{row['session_id']}:start"] = timestamp(row["started_at"])
        if row["finished_at"] is not None:
            expected[f"session:{row['session_id']}:finish"] = timestamp(row["finished_at"])
    approved: dict[str, str] = {}
    for row in support.rows(
        connection,
        "SELECT d.decision_id::text AS decision_id, d.decision, d.created_at, j.job_id::text"
        "        AS job_id"
        "   FROM policy_decision d LEFT JOIN scan_job j ON j.decision_id = d.decision_id"
        "  WHERE d.campaign_id = %s",
        (campaign_id,),
    ):
        entry_id = f"decision:{row['decision_id']}"
        expected[entry_id] = timestamp(row["created_at"])
        if row["decision"] == "approved":
            support.require(row["job_id"] is not None, f"{entry_id} is approved without a job")
            approved[entry_id] = row["job_id"]
    for row in support.rows(
        connection,
        "SELECT seq, created_at FROM campaign_ledger"
        "  WHERE campaign_id = %s AND kind IN ('idle_cycle', 'blocker', 'budget')",
        (campaign_id,),
    ):
        expected[f"ledger:{row['seq']}"] = timestamp(row["created_at"])

    support.require(expected, "the campaign wrote no agent session at all")
    published = {item["entry_id"]: item["at"] for item in items}
    support.require(
        len(published) == len(items), "the activity feed repeated an entry across pages"
    )
    support.require(
        set(published) == set(expected),
        "the activity feed and the rows disagree: "
        f"missing {sorted(set(expected) - set(published))[:5]}, "
        f"extra {sorted(set(published) - set(expected))[:5]}",
    )
    support.require(
        all(published[entry_id] == at for entry_id, at in expected.items()),
        "an activity entry carries a timestamp its row does not have",
    )
    kinds = support.rows(
        connection,
        "SELECT kind, count(*) AS n FROM (SELECT 'decision' AS kind FROM policy_decision"
        "   WHERE campaign_id = %s UNION ALL SELECT 'session_started' FROM agent_session"
        "   WHERE campaign_id = %s UNION ALL SELECT 'session_finished' FROM agent_session"
        "   WHERE campaign_id = %s AND finished_at IS NOT NULL"
        "   UNION ALL SELECT kind FROM campaign_ledger WHERE campaign_id = %s"
        "   AND kind IN ('idle_cycle', 'blocker', 'budget')) AS written GROUP BY kind",
        (campaign_id, campaign_id, campaign_id, campaign_id),
    )
    counted: dict[str, int] = {}
    for item in items:
        counted[item["kind"]] = counted.get(item["kind"], 0) + 1
    support.require(
        counted == {row["kind"]: int(row["n"]) for row in kinds},
        f"the feed's kinds {counted} are not the rows' {kinds}",
    )
    for item in items:
        if item["kind"] == "decision" and item["decision"] == "approved":
            support.require(
                item.get("job_id") == approved[item["entry_id"]],
                f"{item['entry_id']} does not link the job its decision produced",
            )
        if item["kind"] == "decision" and item["decision"] == "denied":
            support.require(
                item.get("reason", {}).get("code"),
                f"{item['entry_id']} is denied without a reason code",
            )
        support.require(
            {"rationale", "input", "detail", "summary"}.isdisjoint(item),
            f"{item['entry_id']} publishes a free-text field",
        )
    for item in items[:8]:
        support.line(
            "entry",
            item["kind"],
            item["at"],
            item.get("capability") or item.get("stop_reason") or item.get("code") or "",
            item.get("job_id", ""),
        )
    return {
        "pages": pages,
        "entries": len(items),
        "kinds": counted,
        "approved_jobs": len(approved),
    }


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
    """Every candidate page of every asset: the endpoint pages at 50 by default.

    Reading only the first page made the demo compare a 50-row subset with the full candidate list
    on any asset that has more than 50 candidates (a full NVD catalogue gives httpd/tomcat far
    more), which the API is not wrong about: `next_cursor` says there is another page.
    """
    token = support.operator_token()
    items: list[dict[str, Any]] = []
    for key, asset_id in assets.items():
        cursor: str | None = None
        pages = 0
        while True:
            path = f"/api/v2/assets/{asset_id}/vulnerabilities"
            if cursor is not None:
                path += "?limit=200&cursor=" + urllib.parse.quote(cursor)
            body = support.api("GET", path, token=token)
            page = list(body.get("items", []))
            items.extend({"canonical_key": key, **item} for item in page)
            pages += 1
            if "next_cursor" not in body:
                break
            cursor = str(body["next_cursor"])
            support.require(pages < 100, f"the candidate list of {key} did not terminate")
        found = sum(1 for item in items if item["canonical_key"] == key)
        support.line("api", key, f"{found} candidates, {pages} page(s)")
    return items


def _check(evidence: dict[str, Any], assets: dict[str, str]) -> None:
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
        "the Apache httpd 2.4.49 service (httpd.lab.aegis.test) has no CVE-2021-41773 candidate",
    )
    # Tomcat 9.0.30 prints `Apache Tomcat/9.0.30` in its 404 page body; web.probe_http reads that
    # body and matches the versioned CPE against NVD's 9.0.0-<9.0.31 Ghostcat range. The AJP port
    # 8009 has no product: no provider in the chain identifies AJP, so the candidate attaches to the
    # HTTP service, not to the port (see the G1.6b report).
    tomcat = {
        item["vulnerability_id"]
        for item in candidates
        if item["canonical_key"] == "service:10.114.53.212:8080/tcp"
    }
    support.require(
        "CVE-2020-1938" in tomcat,
        "the Tomcat 9.0.30 HTTP service has no CVE-2020-1938 (Ghostcat) candidate; "
        f"candidates for that service: {sorted(tomcat)}",
    )
    support.require(
        any(item["kev"] for item in candidates if item["vulnerability_id"] == "CVE-2020-1938"),
        "the CVE-2020-1938 candidate does not carry the KEV flag",
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
    support.line("services matched", len({item["canonical_key"] for item in candidates}))


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


if __name__ == "__main__":
    sys.exit(main())
