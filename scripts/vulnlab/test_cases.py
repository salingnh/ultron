#!/usr/bin/env python3
"""`make vulnlab-test PROFILE=lab|internet` - assert the chain against the CVE lab catalog.

For every case in `tests/vulnlab/cases.yaml` this creates one campaign against the case's target
(the origin address on the lab network for `lab`, the public tunnel hostname for `internet`), waits
for it to finish, loads the committed feed slices through M18 when the store is empty,
runs the M20 matcher for the campaign, then reads what the campaign recorded (PostgreSQL
observations and assets, the Neo4j `AFFECTED_BY` candidates) and prints a verdict per case:

    PASS     every catalog assertion held
    FAIL     the chain ran and produced the wrong or missing detection
    BLOCKED  the chain never left DNS (or proposed no job): the port/fingerprint/CVE capabilities
             of slices A/B/C are not on this branch yet, so there is nothing to assert against

Exit codes: 0 every case passed, 1 at least one failed, 2 nothing failed but at least one was
blocked (a runnable integration signal, not a red detector).

It talks to the local stack `make run-local` wrote (`.local/run-local.env`), or to the file named by
`AEGIS_VULNLAB_RUN_ENV` - never to a shared environment. `--plan` prints the campaigns it would
create and touches nothing.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
# The G1.5c demos' thin helpers (POST /campaigns, poll, PostgreSQL, Neo4j) are reused rather than
# re-implemented: this runner must read the running stack, not a second copy of it.
sys.path.insert(0, str(REPO / "scripts" / "demo"))

import support  # noqa: E402 - sibling module, loaded by path like scripts/demo/*.py

from tests.vulnlab.catalog import (  # noqa: E402 - after sys.path setup
    CATALOG_PATH,
    CampaignSnapshot,
    Case,
    Catalog,
    CveFinding,
    ServiceFinding,
    WebFinding,
    campaign_target,
    compare,
    load_catalog,
)

ARTIFACT_DIR = REPO / "deploy" / "vulnlab" / ".run" / "tests"
VULNLAB_ENV = REPO / "deploy" / "vulnlab" / ".env"
TERMINAL = {"COMPLETED", "FAILED", "CANCELLED"}
OBSERVATIONS = (
    "net.port_state",
    "service.product",
    "http.status",
    "http.title",
    "http.technology",
)
VERDICT_EXIT = {"pass": 0, "fail": 1, "blocked": 2}


class RunnerError(RuntimeError):
    """The runner cannot continue; the message says what is missing and how to fix it."""


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def load_vulnlab_env() -> None:
    """Export `deploy/vulnlab/.env` (names, hostnames, TTL); an explicit environment wins."""
    if not VULNLAB_ENV.is_file():
        raise RunnerError(f"{VULNLAB_ENV} is missing: run make vulnlab-up first")
    for raw in VULNLAB_ENV.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name, separator, value = line.partition("=")
        if not separator:
            raise RunnerError(f"{VULNLAB_ENV}: unsupported line {line!r}")
        os.environ.setdefault(name.strip(), value.strip())


def campaign_body(case: Case, profile: str, catalog: Catalog) -> dict[str, Any]:
    targets = campaign_target(case, profile, os.environ)
    return {
        "name": f"vulnlab-{profile}-{case.id}-{_stamp()}"[:200],
        "objective": (
            f"Vulnlab case {case.id}: discover the open service and its product/version/CPE on the "
            f"{profile} target, then match public CVE candidates. Detection only - no payloads."
        ),
        "targets": dict(targets),
        "policy": dict(catalog.policy),
        "labels": {
            "authorization": "owner, item 61, 2026-11-25",
            "vulnlab_case": case.id,
            "vulnlab_profile": profile,
        },
    }


def create_campaign(case: Case, profile: str, catalog: Catalog) -> str:
    created = support.api(
        "POST",
        "/api/v2/campaigns",
        payload=campaign_body(case, profile, catalog),
        token=support.operator_token(),
        headers={"Idempotency-Key": f"vulnlab-{uuid.uuid4()}"},
    )
    if not isinstance(created, dict) or "campaign_id" not in created:
        raise RunnerError(f"POST /campaigns answered {created!r}")
    return str(created["campaign_id"])


def _open_services(connection: Any, campaign_id: str) -> dict[str, ServiceFinding]:
    rows = support.rows(
        connection,
        """
        SELECT a.canonical_key, host(s.ip) AS ip, s.port, s.transport
          FROM aegis.asset a
          JOIN aegis.asset_campaign ac ON ac.asset_id = a.asset_id
          JOIN aegis.asset_service s ON s.asset_id = a.asset_id
         WHERE ac.campaign_id = %s
        """,
        [campaign_id],
    )
    services = {
        str(row["canonical_key"]): ServiceFinding(
            ip=str(row["ip"]),
            port=int(row["port"]),
            transport=str(row["transport"]),
        )
        for row in rows
    }
    # `net.port_state` is the contract's statement about the port; when slice A does not publish it
    # yet the service asset itself is still evidence that the port answered.
    open_keys = {
        str(row["canonical_key"])
        for row in support.rows(
            connection,
            """
            SELECT a.canonical_key
              FROM aegis.observation o
              JOIN aegis.asset a ON a.asset_id = o.subject_asset_id
              JOIN aegis.asset_campaign ac ON ac.asset_id = a.asset_id
             WHERE ac.campaign_id = %s AND o.predicate = 'net.port_state'
               AND o.value #>> '{}' = 'open'
            """,
            [campaign_id],
        )
    }
    if open_keys:
        services = {key: value for key, value in services.items() if key in open_keys}
    return services


def _observations(connection: Any, campaign_id: str) -> list[dict[str, Any]]:
    return support.rows(
        connection,
        """
        SELECT a.canonical_key, a.kind, o.predicate, o.value
          FROM aegis.observation o
          JOIN aegis.asset a ON a.asset_id = o.subject_asset_id
          JOIN aegis.asset_campaign ac ON ac.asset_id = a.asset_id
         WHERE ac.campaign_id = %s AND o.predicate = ANY(%s)
        """,
        [campaign_id, list(OBSERVATIONS)],
    )


def _cves(campaign_id: str) -> tuple[CveFinding, ...]:
    """The campaign's candidate edges, read from Neo4j.

    `support.neo4j_query` reads `cypher-shell --format plain`, which joins columns with `|`, so each
    attribute is its own single-column query and the three lists are zipped in the same order.
    """
    scope = (
        "MATCH (n:Asset) WHERE $cid IN n.campaign_ids"
        " MATCH (n)-[:AFFECTED_BY]->(v:Vulnerability)"
        " RETURN {field} AS entry"
        " ORDER BY n.canonical_key, v.vulnerability_id"
    )

    def column(field: str) -> list[str]:
        return [
            str(row["entry"])
            for row in support.neo4j_query(scope.format(field=field), cid=campaign_id)
        ]

    assets = column("coalesce(n.canonical_key, '')")
    cves = column("coalesce(v.vulnerability_id, '')")
    flags = column("toString(coalesce(v.kev, false))")
    found: list[CveFinding] = []
    for asset, cve_id, flag in zip(assets, cves, flags, strict=True):
        if not cve_id.startswith("CVE-"):
            continue
        found.append(CveFinding(asset=asset, cve_id=cve_id, kev=flag.strip().lower() == "true"))
    return tuple(found)


def snapshot(connection: Any, campaign_id: str, status: str) -> CampaignSnapshot:
    services = _open_services(connection, campaign_id)
    observations = _observations(connection, campaign_id)
    web: dict[str, dict[str, Any]] = {}
    for row in observations:
        key = str(row["canonical_key"])
        if row["predicate"] == "service.product":
            value = row["value"] or {}
            service = services.get(key)
            if service is None:
                continue
            services[key] = ServiceFinding(
                ip=service.ip,
                port=service.port,
                transport=service.transport,
                product=str(value.get("product") or ""),
                version=str(value.get("version") or ""),
                cpe=_cpe_values(value.get("cpe")),
            )
        elif row["predicate"].startswith("http."):
            entry = web.setdefault(key, {"status": None, "title": None, "technology": []})
            if row["predicate"] == "http.status":
                entry["status"] = _int(row["value"])
            elif row["predicate"] == "http.title":
                entry["title"] = _text(row["value"])
            elif row["predicate"] == "http.technology":
                entry["technology"] = _list(row["value"])
    web_findings = tuple(
        WebFinding(
            url=key,
            status=entry["status"],
            title=entry["title"],
            technology=tuple(entry["technology"]),
        )
        for key, entry in sorted(web.items())
    )
    jobs = tuple(
        str(row["capability"])
        for row in support.rows(
            connection,
            "SELECT capability FROM aegis.scan_job WHERE campaign_id = %s",
            [campaign_id],
        )
    )
    errors = ()
    if status not in TERMINAL:
        errors = (f"campaign {campaign_id} ended {status}, not COMPLETED",)
    elif status == "FAILED":
        errors = (f"campaign {campaign_id} FAILED (see .local/m02-worker.log / m06.log)",)
    known = tuple(
        str(row["vulnerability_id"])
        for row in support.rows(
            connection,
            # Only the NVD catalogue can produce a candidate (the KEV/EPSS rows are scores for a
            # CVE, not a CPE range). Counting them as "known" made the catalog assert a candidate
            # the loaded NVD snapshot cannot match, so the configured KEV source turned into false
            # failures on a store that holds only the fixture NVD slice (D8, item 61 trial).
            "SELECT vulnerability_id FROM aegis.vulnerability_current"
            " WHERE source = 'nvd' AND NOT withdrawn ORDER BY vulnerability_id",
        )
    )
    return CampaignSnapshot(
        campaign_id=campaign_id,
        status=status,
        jobs=jobs,
        services=tuple(services.values()),
        web=web_findings,
        cves=_cves(campaign_id),
        known_vulnerabilities=known,
        errors=errors,
    )


def _cpe_values(raw: Any) -> tuple[str, ...]:
    if isinstance(raw, str) and raw.strip():
        return (raw.strip(),)
    if isinstance(raw, list):
        return tuple(str(item).strip() for item in raw if str(item).strip())
    return ()


def _int(raw: Any) -> int | None:
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str) and raw.strip().isdigit():
        return int(raw.strip())
    return None


def _text(raw: Any) -> str | None:
    if isinstance(raw, str):
        return raw
    if raw is None:
        return None
    return str(raw)


def _list(raw: Any) -> list[str]:
    if isinstance(raw, list):
        return [str(item) for item in raw]
    if isinstance(raw, str) and raw:
        return [raw]
    return []


INTEL_FIXTURES = REPO / "tests/fixtures/intel"
INTEL_VERSION = "2026-11-24"


def _ensure_intel(connection: Any) -> None:
    """Load the committed feed slices when the intel store is empty (idempotent when it is not).

    The harness is a test: it seeds the pinned fixtures, never the network. A deployment loads the
    live catalogues with the scheduled refresh (`make intel-sync`: NVD auto, EPSS when configured,
    KEV default-branch HEAD) and this function then leaves that data alone (`present > 0`).
    """
    from aegis.m18_intel.sync import FeedSync

    present = support.count(connection, "SELECT count(*) FROM intel_snapshot")
    if present:
        return
    sync = FeedSync.from_env()
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
        print(
            f"  intel {feed}: records={report.records} written={report.written}"
            f" sha256={report.content_sha256[:12]}"
        )


def _wait_for_candidates(campaign_id: str, expected: int, timeout_seconds: float = 90.0) -> None:
    """Wait until the projector published the matcher's candidates as AFFECTED_BY edges."""
    if expected <= 0:
        return
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        rows = support.neo4j_query(
            "MATCH (n:Asset) WHERE $cid IN n.campaign_ids"
            " MATCH (n)-[:AFFECTED_BY]->(:Vulnerability)"
            " RETURN count(*) AS edges",
            cid=campaign_id,
        )
        edges = int(rows[0]["edges"]) if rows else 0
        if edges >= expected:
            return
        time.sleep(1)
    print(
        f"  projection: only {edges} AFFECTED_BY edge(s) after {timeout_seconds:.0f}s "
        f"(matcher wrote {expected}); reading what the graph has"
    )


def run_case(
    case: Case, profile: str, catalog: Catalog, timeout_seconds: float, verbose: bool
) -> tuple[dict[str, Any], int]:
    print(f"\n== {case.id} [{profile}] " + "=" * max(0, 60 - len(case.id) - len(profile)))
    campaign_id = create_campaign(case, profile, catalog)
    print(f"  campaign {campaign_id}")

    def progress(body: dict[str, Any]) -> None:
        print(f"  .. {body.get('status')} {body.get('status_reason') or ''}".rstrip())

    finished = support.wait_campaign(campaign_id, timeout_seconds=timeout_seconds, on_tick=progress)
    status = str(finished.get("status"))
    connection = support.pg()
    try:
        # The campaign records product/version/CPE; the CVE candidates need the intel store and the
        # matcher. Loading the three committed slices is idempotent (M18 skips unchanged bytes), and
        # the matcher is per campaign, so this is the smallest step that makes a case assertable -
        # the harness used to assume a demo had left both behind.
        _ensure_intel(connection)
        from aegis.m20_vuln.matching import Matcher

        report = Matcher(connection).run(campaign_id=campaign_id)
        print(f"  matcher: {json.dumps(report.as_dict(), sort_keys=True)[:200]}")
        # The candidates live in Neo4j, which the projector fills asynchronously: wait for the
        # campaign's AFFECTED_BY edges before reading them, or a fast run asserts on an empty graph.
        _wait_for_candidates(campaign_id, report.new_matches)
        recorded = snapshot(connection, campaign_id, status)
    finally:
        connection.close()

    verdict = compare(case, profile, recorded)
    print(f"  {verdict.status.upper()}: {verdict.reason or 'all assertions held'}")
    if verbose:
        for check in verdict.checks:
            print(f"    {'ok  ' if check.ok else 'FAIL'} {check.name}: {check.detail}")
        print(
            f"    observed: services={list(recorded.services)} web={[w.url for w in recorded.web]}"
        )
        print(f"    candidates: {list(recorded.cve_ids())}")
    report = {
        "case": case.id,
        "profile": profile,
        "campaign_id": campaign_id,
        "campaign_status": status,
        "verdict": verdict.status,
        "reason": verdict.reason,
        "checks": [
            {"name": check.name, "ok": check.ok, "detail": check.detail} for check in verdict.checks
        ],
        "jobs": list(recorded.capabilities),
        "services": [dataclasses.asdict(service) for service in recorded.services],
        "web": [dataclasses.asdict(web) for web in recorded.web],
        "candidates": list(recorded.cve_ids()),
    }
    return report, VERDICT_EXIT[verdict.status]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile", choices=("lab", "internet"), default=os.environ.get("PROFILE", "lab")
    )
    parser.add_argument("--case", action="append", default=[], help="only these case ids")
    parser.add_argument("--timeout", type=float, default=None, help="per-campaign timeout seconds")
    parser.add_argument("--plan", action="store_true", help="print campaigns, create nothing")
    parser.add_argument("--verbose", action="store_true", help="print every check")
    parser.add_argument(
        "--allow-placeholder-hostnames",
        action="store_true",
        help="accept the .env.example example.com hostnames (the tunnel run will fail, by design)",
    )
    arguments = parser.parse_args(argv)

    catalog = load_catalog(CATALOG_PATH)
    cases = list(catalog.cases)
    if arguments.case:
        wanted = set(arguments.case)
        unknown = wanted - {case.id for case in cases}
        if unknown:
            print(f"[vulnlab] unknown case(s): {sorted(unknown)}", file=sys.stderr)
            return 2
        cases = [case for case in cases if case.id in wanted]
    timeout_seconds = arguments.timeout or float(catalog.timeout_seconds)

    try:
        load_vulnlab_env()
    except RunnerError as error:
        print(f"[vulnlab] {error}", file=sys.stderr)
        return 2

    if arguments.profile == "internet":
        if not os.environ.get("AEGIS_VULNLAB_TUNNEL_TOKEN", "").strip():
            print(
                "[vulnlab] PROFILE=internet needs a running tunnel: AEGIS_VULNLAB_TUNNEL_TOKEN is "
                "empty (see deploy/vulnlab/.env)",
                file=sys.stderr,
            )
            return 2
        placeholder = [
            case.id
            for case in cases
            if ".example." in (os.environ.get(case.host_env or "", "") if case.host_env else "")
        ]
        if placeholder and not arguments.allow_placeholder_hostnames:
            print(
                f"[vulnlab] placeholder hostnames for {placeholder}: set the real public names "
                "in deploy/vulnlab/.env first (or pass --allow-placeholder-hostnames to see the "
                "failure)",
                file=sys.stderr,
            )
            return 2

    if arguments.plan:
        for case in cases:
            body = campaign_body(case, arguments.profile, catalog)
            print(f"{case.id}: targets={body['targets']} labels={body['labels']}")
        return 0

    run_env = os.environ.get("AEGIS_VULNLAB_RUN_ENV", "").strip()
    if run_env:
        support.RUN_ENV = Path(run_env)
    try:
        support.load_demo_env()
    except support.DemoError as error:
        print(f"[vulnlab] {error}", file=sys.stderr)
        return 2

    reports: list[dict[str, Any]] = []
    for case in cases:
        try:
            report, _code = run_case(
                case, arguments.profile, catalog, timeout_seconds, arguments.verbose
            )
        except (RunnerError, support.DemoError) as error:
            print(f"  FAIL {case.id}: {error}", file=sys.stderr)
            report = {
                "case": case.id,
                "profile": arguments.profile,
                "verdict": "fail",
                "reason": str(error),
            }
        reports.append(report)

    stamp = _stamp()
    directory = ARTIFACT_DIR / f"{arguments.profile}-{stamp}"
    directory.mkdir(parents=True, exist_ok=True)
    document = {
        "profile": arguments.profile,
        "started_at": stamp,
        "catalog_version": catalog.version,
        "feed": dict(catalog.feed),
        "cases": reports,
    }
    (directory / "report.json").write_text(
        json.dumps(document, indent=1, sort_keys=True, default=str) + "\n", encoding="utf-8"
    )
    lines = [f"profile {arguments.profile}"]
    for report in reports:
        lines.append(f"{report['verdict'].upper():8} {report['case']}: {report.get('reason', '')}")
    (directory / "report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    passed = sum(1 for report in reports if report["verdict"] == "pass")
    failed_count = sum(1 for report in reports if report["verdict"] == "fail")
    blocked_count = sum(1 for report in reports if report["verdict"] == "blocked")
    print("\n== result " + "=" * 60)
    print(f"  {passed} passed, {failed_count} failed, {blocked_count} blocked")
    print(f"  report {directory / 'report.txt'}")
    if failed_count:
        return 1
    return 2 if blocked_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
