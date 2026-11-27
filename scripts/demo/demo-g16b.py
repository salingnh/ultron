#!/usr/bin/env python3
"""`make demo-g16b` — the G1.6b gate: port -> service/product/version/CPE -> application.

Runs one campaign on the authorized lab and prints the evidence this slice asks for (item 61):

1. `POST /campaigns` on the lab zone, whose objective asks for the services on the resolved
   addresses and for the product behind them (the scripted policy reads the objective and the
   bundle's observations), with the lab-only policy. The chain is the real one: Subfinder reads
   the lab's passive stub, DNSx resolves what it found, Naabu scans those addresses.
2. The campaign continues: `service.fingerprint` (fingerprintx) reads
   protocol/banner/product/version/CPE on every open service, `web.probe_http` (httpx) turns
   each http(s) service into an Application with its technologies and TLS certificate.
3. Evidence: the job chain and its dependency edge, the service observations in PostgreSQL, the
   applications and `SERVES` edges, the same nodes and `:Observation` values in Neo4j, the campaign
   flow read model, and the no-duplicate queries.

Exit codes: 0 = every check passed, 1 = a check failed (the failing line is printed),
2 = the chain cannot run in this build (the message says what is missing, e.g. no port-discovery
provider), 3 = the stack is not ready (the message says which command starts it).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import support  # noqa: E402 - the demo scripts' shared helpers, a sibling module

FINGERPRINT = "service.fingerprint"
PROBE_HTTP = "web.probe_http"
DISCOVER = "network.discover_services"
#: Products the lab's pinned service images must show up with (fingerprintx + CPE 2.3).
EXPECTED_PRODUCTS = {("nginx", "1.18.0"), ("http_server", "2.4.49")}
#: The lab origin that answers HTTPS with a certificate from the throwaway lab CA.
EXPECTED_TLS_ORIGIN = "app:https://10.114.53.211:443"
DEMO_TIMEOUT_ENV = "DEMO_TIMEOUT_SECONDS"
DEFAULT_TIMEOUT = 600.0


def main(argv: list[str] | None = None) -> int:
    support.load_demo_env()
    timeout = float(os.environ.get(DEMO_TIMEOUT_ENV) or DEFAULT_TIMEOUT)
    support.section("0. stack and capabilities")
    _stack_check()
    try:
        capabilities = _capabilities()
    except support.DemoError as error:
        support.section("result")
        support.line(f"NOT READY: {error}")
        return 3
    support.line("capabilities", ", ".join(sorted(capabilities)))
    for capability in (DISCOVER, FINGERPRINT, PROBE_HTTP):
        support.require(
            capability in capabilities,
            f"the API does not publish {capability}: the adapter manifest under adapters/ is "
            "not in this build (AEGIS_ADAPTER_MANIFESTS / deploy) - run the stack from this "
            "checkout",
        )
    support.line("discovery capabilities", DISCOVER, FINGERPRINT, PROBE_HTTP)

    support.section("1. campaign (POST /campaigns, lab web seeds, RoE lab only)")
    body = support.campaign_body(
        "G1.6b service discovery",
        "Enumerate the subdomains of the authorized lab zone, resolve the names the enumeration "
        "found, then discover which ports and services those addresses expose and which product "
        "and version sits behind every open port, so each service is linked to its software",
    )
    body["targets"] = {"domains": [support.LAB_ZONE]}
    created = support.api(
        "POST",
        "/api/v2/campaigns",
        payload=body,
        token=support.operator_token(),
        headers={"Idempotency-Key": f"demo-g16b:{support.now()}"},
    )
    campaign_id = str(created["campaign_id"])
    support.line("campaign_id", campaign_id)
    support.line("seeds", support.LAB_ZONE)

    support.section("2. campaign runs: ports -> fingerprintx -> httpx")
    ticks = 0

    def progress(document: dict[str, Any]) -> None:
        nonlocal ticks
        ticks += 1
        if ticks % 5 == 0:
            support.line(
                "status", document.get("status"), "|", (document.get("status_reason") or "-")
            )

    try:
        finished = support.wait_campaign(campaign_id, timeout_seconds=timeout, on_tick=progress)
    except support.DemoError as error:
        support.section("result")
        support.line(f"FAILED: {error}")
        return 1
    status = str(finished.get("status"))
    support.line("status", status, "|", finished.get("status_reason") or "-")
    if status == "PAUSED":
        support.section("result")
        support.line(
            "BLOCKED: the campaign paused with nothing to propose. This build has no provider that "
            "turns an address into services (port discovery, slice A of item 61); merge that slice "
            "into integ/g16-discovery and re-run.",
        )
        return 2
    connection = support.pg()
    try:
        evidence = _collect(connection, campaign_id)
    finally:
        connection.close()
    evidence["campaign"] = {
        "campaign_id": campaign_id,
        "status": status,
        "status_reason": finished.get("status_reason"),
        "policy_version": finished.get("policy_version"),
        "started_at": finished.get("started_at"),
        "ended_at": finished.get("ended_at"),
    }
    evidence["finished_at"] = support.now()
    if not evidence["services"]:
        support.section("result")
        support.line(
            "BLOCKED: no service asset appeared in the campaign. This build has no provider that "
            "turns an address into services (port discovery, slice A of item 61); merge that slice "
            "into integ/g16-discovery and re-run.",
        )
        return 2
    _check(evidence, status)
    artifact = support.write_artifact(f"g16b-{_stamp()}.json", evidence)
    support.section("evidence file")
    support.line(str(artifact))
    support.section("result")
    support.line("PASS - every G1.6b evidence check passed")
    return 0


def _stack_check() -> None:
    stack = [item for item in support.processes() if item.alive]
    for name in ("api", "m06", "m23"):
        support.require(
            any(item.name == name for item in stack),
            f"{name} is not running: run `make run-local` (workers and projector included) first",
        )
    if os.environ.get("AEGIS_WORKERS") == "0":
        support.fail("run-local was started with WORKERS=0, so no job can run")


def _capabilities() -> set[str]:
    document = support.api("GET", "/api/v2/capabilities", token=support.operator_token())
    items = document.get("items") if isinstance(document, dict) else document
    names: set[str] = set()
    for item in items or []:
        name = item.get("capability") if isinstance(item, dict) else None
        if name:
            names.add(str(name))
    return names


def _collect(connection: Any, campaign_id: str) -> dict[str, Any]:
    document: dict[str, Any] = {}

    support.section("3. job chain (scan_job + job_dependency)")
    document["jobs"] = support.rows(
        connection,
        """
        SELECT j.job_id, j.capability, j.provider, j.provider_version, j.status, j.created_at,
               j.started_at, j.finished_at,
               (SELECT array_agg(d.depends_on_job_id::text) FROM job_dependency d
                 WHERE d.job_id = j.job_id) AS depends_on
          FROM scan_job j WHERE j.campaign_id = %s ORDER BY j.created_at
        """,
        (campaign_id,),
    )
    for job in document["jobs"]:
        support.line(
            "job",
            job["capability"],
            job["provider"],
            job["provider_version"],
            job["status"],
            "depends_on=" + (",".join(str(item) for item in job["depends_on"] or []) or "-"),
        )

    support.section("4. services and their product/version/CPE (PostgreSQL)")
    # The asset rows are shared across campaigns (`asset_campaign`); every read below is restricted
    # to the assets this campaign touched, so a re-run in a shared database shows only this run.
    document["asset_ids"] = [
        str(row["asset_id"])
        for row in support.rows(
            connection,
            "SELECT a.asset_id FROM asset a JOIN asset_campaign ac ON ac.asset_id = a.asset_id"
            " WHERE ac.campaign_id = %s",
            (campaign_id,),
        )
    ]
    asset_ids = document["asset_ids"]
    document["services"] = support.rows(
        connection,
        """
        SELECT a.canonical_key, s.ip::text AS ip, s.port, s.transport,
               (SELECT o.value->>'product' FROM observation o
                 WHERE o.subject_asset_id = a.asset_id AND o.predicate = 'service.product'
                 ORDER BY o.observed_at DESC LIMIT 1) AS product,
               (SELECT o.value->>'version' FROM observation o
                 WHERE o.subject_asset_id = a.asset_id AND o.predicate = 'service.product'
                 ORDER BY o.observed_at DESC LIMIT 1) AS version,
               (SELECT o.value->>'cpe' FROM observation o
                 WHERE o.subject_asset_id = a.asset_id AND o.predicate = 'service.product'
                 ORDER BY o.observed_at DESC LIMIT 1) AS cpe,
               (SELECT o.value #>> '{}' FROM observation o
                 WHERE o.subject_asset_id = a.asset_id AND o.predicate = 'service.protocol'
                 ORDER BY o.observed_at DESC LIMIT 1) AS protocol
          FROM asset a JOIN asset_service s ON s.asset_id = a.asset_id
          JOIN asset_campaign ac ON ac.asset_id = a.asset_id
         WHERE ac.campaign_id = %s ORDER BY a.canonical_key
        """,
        (campaign_id,),
    )
    for service in document["services"]:
        support.line(
            "service",
            service["canonical_key"],
            service["protocol"] or "-",
            f"{service['product'] or '-'} {service['version'] or ''}".strip(),
            service["cpe"] or "(no cpe)",
        )

    support.section("5. applications, technologies and TLS (PostgreSQL)")
    document["applications"] = support.rows(
        connection,
        """
        SELECT a.canonical_key,
               (SELECT o.value FROM observation o
                 WHERE o.subject_asset_id = a.asset_id AND o.predicate = 'http.technology'
                 ORDER BY o.observed_at DESC LIMIT 1) AS technologies,
               (SELECT o.value->>'subject_cn' FROM observation o
                 WHERE o.subject_asset_id = a.asset_id AND o.predicate = 'tls.certificate'
                 ORDER BY o.observed_at DESC LIMIT 1) AS tls_subject_cn,
               (SELECT o.value->>'sha256' FROM observation o
                 WHERE o.subject_asset_id = a.asset_id AND o.predicate = 'tls.certificate'
                 ORDER BY o.observed_at DESC LIMIT 1) AS tls_sha256
          FROM asset a JOIN asset_campaign ac ON ac.asset_id = a.asset_id
         WHERE ac.campaign_id = %s AND a.kind = 'application' ORDER BY a.canonical_key
        """,
        (campaign_id,),
    )
    for application in document["applications"]:
        support.line(
            "application",
            application["canonical_key"],
            json.dumps(application["technologies"] or []),
            "tls=" + (application["tls_subject_cn"] or "-"),
        )

    support.section("6. SERVES Service -> Application (PostgreSQL)")
    document["serves"] = support.rows(
        connection,
        """
        SELECT f.canonical_key AS service, t.canonical_key AS application, r.confidence
          FROM relationship r
          JOIN asset f ON f.asset_id = r.from_asset_id
          JOIN asset t ON t.asset_id = r.to_asset_id
         WHERE r.type = 'SERVES'
           AND r.from_asset_id = ANY(%s::uuid[]) AND r.to_asset_id = ANY(%s::uuid[])
         ORDER BY f.canonical_key, t.canonical_key
        """,
        (asset_ids, asset_ids),
    )
    for edge in document["serves"]:
        support.line("serves", edge["service"], "->", edge["application"])

    support.section("7. the same graph in Neo4j")
    document["neo4j"] = _neo4j(campaign_id)

    support.section("8. flow read model (GET /campaigns/{id}/flow)")
    flow = support.campaign_flow(campaign_id)
    kinds: dict[str, int] = {}
    for node in flow.get("nodes") or []:
        kinds[str(node.get("type"))] = kinds.get(str(node.get("type")), 0) + 1
    document["flow"] = {
        "nodes": len(flow.get("nodes") or []),
        "edges": len(flow.get("edges") or []),
        "kinds": kinds,
    }
    support.line("flow", json.dumps(document["flow"], sort_keys=True))

    support.section("9. no duplicates")
    document["duplicates"] = {
        "observation": support.duplicate_groups(
            connection,
            # "No duplicates" for observations means one producer did not record the same claim
            # twice in the campaign (a replay/idempotency defect). Two providers that agree -
            # fingerprintx and httpx both naming nginx 1.18.0 - are corroboration, not duplication,
            # and M27 keeps one row per producer on purpose.
            "SELECT count(*) FROM observation o JOIN asset a ON a.asset_id = o.subject_asset_id"
            " WHERE o.campaign_id = %s"
            " GROUP BY a.canonical_key, o.predicate, o.value_hash, o.provider, o.scan_id"
            " HAVING count(*) > 1",
            (campaign_id,),
        ),
        "relationship": support.duplicate_groups(
            connection,
            "SELECT count(*) FROM relationship"
            " WHERE from_asset_id = ANY(%s::uuid[]) AND valid_to IS NULL"
            " GROUP BY type, from_asset_id, to_asset_id HAVING count(*) > 1",
            (asset_ids,),
        ),
    }
    support.line(
        "duplicate groups", json.dumps({k: len(v) for k, v in document["duplicates"].items()})
    )
    return document


def _neo4j(campaign_id: str) -> dict[str, Any]:
    """The same knowledge in Neo4j: assets, edge types and `:Observation` values.

    `support.neo4j_query` reads `cypher-shell --format plain`, which joins columns with the same
    `|` a CSV row would use, so every attribute comes back as its own single-column query and the
    lists are zipped (the queries share their ORDER BY). Observations are scoped by the subject keys
    of this campaign, since an observation node carries no campaign id.
    """
    scope = (
        "MATCH (a:Asset) WHERE $campaign IN coalesce(a.campaign_ids, [])"
        " RETURN a.{field} AS entry ORDER BY a.{field}"
    )

    def column(cypher: str, **parameters: Any) -> list[str]:
        return [str(row["entry"]) for row in support.neo4j_query(cypher, **parameters)]

    kinds = column(scope.format(field="kind"), campaign=campaign_id)
    keys = column(scope.format(field="canonical_key"), campaign=campaign_id)
    nodes = [{"kind": kind, "key": key} for kind, key in zip(kinds, keys, strict=True)]

    edge_types = column(
        "MATCH (f:Asset)-[r]->(t:Asset) WHERE $campaign IN coalesce(f.campaign_ids, [])"
        " AND $campaign IN coalesce(t.campaign_ids, [])"
        " RETURN DISTINCT type(r) AS entry ORDER BY type(r)",
        campaign=campaign_id,
    )

    observation_scope = (
        "MATCH (o:Observation) WHERE o.subject IN $keys RETURN {field} AS entry"
        " ORDER BY o.subject, o.predicate"
    )
    campaign_keys = [node["key"] for node in nodes]
    predicates = column(observation_scope.format(field="o.predicate"), keys=campaign_keys)
    subjects = column(observation_scope.format(field="o.subject"), keys=campaign_keys)
    summaries = column(
        observation_scope.format(field="coalesce(o.value_summary, '')"), keys=campaign_keys
    )
    observations = [
        {"predicate": predicate, "subject": subject, "summary": summary}
        for predicate, subject, summary in zip(predicates, subjects, summaries, strict=True)
    ]

    counts: dict[str, int] = {}
    for node in nodes:
        counts[node["kind"]] = counts.get(node["kind"], 0) + 1
    support.line("nodes", json.dumps(counts, sort_keys=True))
    support.line("edges", ", ".join(edge_types) or "none")
    for observation in observations[:12]:
        support.line("observation", observation["predicate"], "on", observation["subject"])
    return {"nodes": nodes, "edge_types": edge_types, "observations": observations}


def _check(evidence: dict[str, Any], status: str) -> None:
    support.section("checks")
    support.require(
        status == "COMPLETED",
        f"the campaign ended {status}, not COMPLETED (logs in .local/m02-*.log)",
    )

    capabilities = {str(job["capability"]) for job in evidence["jobs"]}
    statuses = {(str(job["capability"]), str(job["status"])) for job in evidence["jobs"]}
    for capability in (DISCOVER, FINGERPRINT, PROBE_HTTP):
        support.require(capability in capabilities, f"no {capability} job ran in the campaign")
        support.require(
            (capability, "SUCCEEDED") in statuses,
            f"{capability} did not succeed: {sorted(statuses)}",
        )
    for job in evidence["jobs"]:
        if job["capability"] == PROBE_HTTP:
            support.require(
                job["depends_on"], "the web.probe_http job has no dependency on the fingerprint job"
            )

    products = {
        (service["product"], service["version"], service["cpe"])
        for service in evidence["services"]
        if service["product"]
    }
    shown = {(product, version) for product, version, _ in products}
    missing_products = sorted(
        expected
        for expected in EXPECTED_PRODUCTS
        if not any(product == expected[0] and version == expected[1] for product, version in shown)
    )
    support.require(
        not missing_products,
        f"no service carries the lab's {missing_products} with a version (got {sorted(shown)})",
    )
    support.require(
        all(cpe for _, _, cpe in products),
        f"a fingerprinted service carries no CPE: {sorted(products)}",
    )
    cpes = [cpe for _, _, cpe in products if cpe]
    support.require(
        all(str(cpe).startswith("cpe:2.3:a:") for cpe in cpes),
        f"a service CPE is not CPE 2.3: {sorted(cpes)}",
    )
    protocols = {service["canonical_key"]: service["protocol"] for service in evidence["services"]}
    support.require(
        "http" in protocols.values() and "https" in protocols.values(),
        f"the lab services were not identified as http and https: {protocols}",
    )

    applications = {
        application["canonical_key"]: application for application in evidence["applications"]
    }
    support.require(
        len(applications) >= 3, f"expected the lab's web origins, got {sorted(applications)}"
    )
    support.require(
        EXPECTED_TLS_ORIGIN in applications,
        f"the HTTPS origin {EXPECTED_TLS_ORIGIN} is not an application "
        f"(got {sorted(applications)})",
    )
    support.require(
        bool(applications[EXPECTED_TLS_ORIGIN]["tls_sha256"]),
        f"{EXPECTED_TLS_ORIGIN} carries no TLS certificate observation",
    )
    technologies = {
        key: {str(item) for item in application["technologies"] or []}
        for key, application in applications.items()
    }
    support.require(
        any(
            any(str(item).startswith("nginx:") for item in items) for items in technologies.values()
        ),
        f"no application carries the nginx technology (got {technologies})",
    )
    serves = {(edge["service"], edge["application"]) for edge in evidence["serves"]}
    support.require(
        all(
            (str(application["canonical_key"]).startswith("app:"))
            for application in evidence["applications"]
        ),
        "an application key is not an app: canonical key",
    )
    for key in applications:
        support.require(
            any(application == key for _, application in serves),
            f"no SERVES edge points at {key}",
        )

    graph = evidence["neo4j"]
    node_kinds = {str(node["kind"]) for node in graph["nodes"]}
    support.require("service" in node_kinds, "no :Service node in Neo4j")
    support.require("application" in node_kinds, "no :Application node in Neo4j")
    support.require("SERVES" in graph["edge_types"], "no SERVES edge in Neo4j")
    summaries = [str(observation["summary"] or "") for observation in graph["observations"]]
    support.require(
        any("1.18.0" in summary or "2.4.49" in summary for summary in summaries),
        "no :Observation node in Neo4j carries a product version",
    )
    support.require(
        any("cpe:2.3:a:" in summary for summary in summaries),
        "no :Observation node in Neo4j carries a CPE",
    )

    flow = evidence["flow"]
    support.require(flow["kinds"].get("job"), "the flow read model carries no job node")
    support.require(flow["kinds"].get("session"), "the flow read model carries no session node")

    duplicates = evidence["duplicates"]
    for table, groups in duplicates.items():
        support.require(not groups, f"{table} has duplicate rows: {groups}")


def _stamp() -> str:
    return support.now().replace(":", "").replace("-", "").replace(".", "")[:15]


if __name__ == "__main__":
    sys.exit(main())
