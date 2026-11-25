#!/usr/bin/env python3
"""`make demo-discovery` - the G1.6a slice: the G1 chain plus the ports/services step.

The demo runs one campaign through the whole platform on the authorized lab, then prints the
evidence that the discovered surface is linked up to the service level:

1. `POST /campaigns` - a campaign whose only target is the lab zone `lab.aegis.test`, the lab-only
   policy and an objective that asks for the services on the resolved addresses (the scripted
   policy reads the objective; `make demo-g1` uses an objective that stops after resolution).
2. The M03 session proposes, in order: `dns.enumerate_subdomains` (Subfinder), `dns.resolve`
   (DNSx, `depends_on` the enumeration) and `network.discover_services` (naabu, `depends_on` the
   resolution). M05 signs each task with the resolved addresses and the input port set as the
   egress binding; M06 runs the pinned CONNECT scan on the lab network.
3. M27 ingests the envelope: `service` assets, `asset.seen` / `net.port_state: open` /
   `service.protocol` observations and `EXPOSES` edges IP -> Service. M23 projects them.
4. Evidence printed: the three jobs and their dependency chain, the services in PostgreSQL with
   their `asset_service` detail rows and the IP they are exposed from, the same services and edges
   read back from Neo4j, the set comparison between the two (equal), the observations, the
   receipts (nothing quarantined) and the provenance of a service back to its job.

Exit codes: 0 = every check passed, 1 = a check failed (the failing line is printed), 2 = the stack
is not ready (the message says which command starts it).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import support  # noqa: E402 - the demo scripts' shared helpers, a sibling module

DEMO_TIMEOUT_ENV = "DEMO_TIMEOUT_SECONDS"
DEFAULT_TIMEOUT = 420.0
OBJECTIVE = (
    "Enumerate the subdomains of the authorized lab zone, resolve the names the enumeration "
    "found, then discover which ports and services those addresses expose so the graph links "
    "every address to the services behind it"
)


def main(argv: list[str] | None = None) -> int:
    support.load_demo_env()
    timeout = float(os.environ.get(DEMO_TIMEOUT_ENV) or DEFAULT_TIMEOUT)
    support.section("0. stack")
    stack = _stack_check()
    support.line("api", os.environ["AEGIS_API_URL"])
    support.line("processes", ", ".join(f"{item.name}:{item.pid}" for item in stack) or "none")

    support.section("1. campaign (POST /campaigns, lab seed, objective asks for services)")
    campaign_id = support.create_campaign("G1.6a discovery demo", OBJECTIVE)
    support.line("campaign_id", campaign_id)
    support.line("seed", support.LAB_ZONE)
    support.line("ports", ",".join(str(port) for port in support.SERVICE_PORTS))

    support.section("2. campaign runs: Subfinder -> DNSx -> naabu")
    finished = support.wait_campaign(campaign_id, timeout_seconds=timeout)
    status = str(finished.get("status"))
    support.line("status", status, "|", finished.get("status_reason") or "-")
    if status != "COMPLETED":
        support.fail(f"the campaign ended {status}, not COMPLETED (logs in .local/m02-*.log)")

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
        "created_at": finished.get("created_at"),
        "ended_at": finished.get("ended_at"),
    }
    evidence["finished_at"] = support.now()
    _check(evidence)
    artifact = support.write_artifact(f"g16a-{_stamp()}.json", evidence)
    support.section("evidence file")
    support.line(str(artifact))
    support.section("result")
    support.line("PASS - IP -> Service nodes and EXPOSES edges agree between PostgreSQL and Neo4j")
    return 0


def _stack_check() -> list[support.ProcessState]:
    stack = [item for item in support.processes() if item.alive]
    for name in ("api", "m06"):
        support.require(
            any(item.name == name for item in stack),
            f"{name} is not running: run `make run-local` (workers included) first",
        )
    if os.environ.get("AEGIS_WORKERS") == "0":
        support.fail("run-local was started with WORKERS=0, so no job can run")
    return stack


def _collect(connection: Any, campaign_id: str) -> dict[str, Any]:
    document: dict[str, Any] = {"campaign_id": campaign_id}

    support.section("3. jobs and their dependency chain")
    jobs = support.rows(
        connection,
        """
        SELECT j.job_id, j.capability, j.provider, j.provider_version, j.status, j.attempt,
               j.started_at, j.finished_at, j.proposed_by
          FROM scan_job j WHERE j.campaign_id = %s ORDER BY j.created_at
        """,
        (campaign_id,),
    )
    document["jobs"] = jobs
    for job in jobs:
        support.line(
            job["capability"],
            job["provider"],
            job["provider_version"],
            job["status"],
            "| attempt",
            job["attempt"],
        )
        support.require(job["status"] == "SUCCEEDED", f"job {job['job_id']} ended {job['status']}")
    capabilities = [job["capability"] for job in jobs]
    support.require(support.ENUMERATE in capabilities, "no enumeration job in the campaign")
    support.require(support.RESOLVE in capabilities, "no DNS resolution job in the campaign")
    support.require(support.DISCOVER in capabilities, "no service discovery job in the campaign")

    dependencies = support.rows(
        connection,
        """
        SELECT d.job_id, j.capability, d.depends_on_job_id, p.capability AS depends_on
          FROM job_dependency d
          JOIN scan_job j ON j.job_id = d.job_id
          JOIN scan_job p ON p.job_id = d.depends_on_job_id
         WHERE j.campaign_id = %s
        """,
        (campaign_id,),
    )
    document["dependencies"] = dependencies
    for item in dependencies:
        support.line(
            f"{item['capability']} depends_on {item['depends_on']}", item["depends_on_job_id"]
        )
    pairs = {(item["capability"], item["depends_on"]) for item in dependencies}
    support.require(
        (support.RESOLVE, support.ENUMERATE) in pairs,
        "the resolution job does not depend on the enumeration job",
    )
    support.require(
        (support.DISCOVER, support.RESOLVE) in pairs,
        "the service discovery job does not depend on the resolution job",
    )

    support.section("4. services in PostgreSQL (asset_service + EXPOSES)")
    services = support.rows(
        connection,
        """
        SELECT a.asset_id, a.canonical_key, s.ip::text AS ip, s.port, s.transport,
               f.canonical_key AS exposed_from, r.relationship_id, r.observed_at, r.confidence
          FROM asset a
          JOIN asset_campaign ac ON ac.asset_id = a.asset_id AND ac.campaign_id = %s
          JOIN asset_service s ON s.asset_id = a.asset_id
          LEFT JOIN relationship r ON r.to_asset_id = a.asset_id AND r.type = 'EXPOSES'
          LEFT JOIN asset f ON f.asset_id = r.from_asset_id
         WHERE a.kind = 'service'
         ORDER BY a.canonical_key
        """,
        (campaign_id,),
    )
    document["services"] = services
    for service in services:
        support.line(
            service["canonical_key"],
            "| exposed from",
            service["exposed_from"] or "(none)",
            "| observed",
            service["observed_at"],
        )
    support.require(services, "no service asset was ingested: the discovery job produced nothing")
    support.require(
        all(service["exposed_from"] for service in services),
        "a service has no EXPOSES edge from its address",
    )
    support.require(
        all(str(service["exposed_from"]).startswith("ip:") for service in services),
        "an EXPOSES edge does not start at an ip: asset",
    )
    support.require(
        all(
            service["asset_id"] and service["port"] and service["transport"] for service in services
        ),
        "an asset_service detail row is missing",
    )

    support.section("5. observations the discovery job recorded")
    observations = support.rows(
        connection,
        """
        SELECT a.canonical_key, o.predicate, o.value
          FROM observation o
          JOIN asset a ON a.asset_id = o.subject_asset_id
          JOIN asset_campaign ac ON ac.asset_id = a.asset_id AND ac.campaign_id = %s
         WHERE a.kind = 'service' AND o.campaign_id = %s
         ORDER BY a.canonical_key, o.predicate
        """,
        (campaign_id, campaign_id),
    )
    document["observations"] = observations
    by_service: dict[str, dict[str, Any]] = {}
    for item in observations:
        by_service.setdefault(str(item["canonical_key"]), {})[str(item["predicate"])] = item[
            "value"
        ]
    for key, values in by_service.items():
        support.line(key, json.dumps(values, sort_keys=True))
    support.require(by_service, "the services carry no observation")
    for key, values in by_service.items():
        support.require(
            values.get("net.port_state") == "open", f"{key} has no net.port_state: open"
        )
        support.require(
            values.get("service.protocol") == "tcp", f"{key} has no service.protocol observation"
        )

    support.section("6. the same services and edges in Neo4j, as sets")
    pg_service_keys = sorted(str(service["canonical_key"]) for service in services)
    pg_edges = sorted(
        (str(service["exposed_from"]), str(service["canonical_key"])) for service in services
    )
    graph_nodes = support.neo4j_query(
        "MATCH (a:Service) WHERE $campaign IN coalesce(a.campaign_ids, [])"
        " RETURN a.canonical_key AS key ORDER BY a.canonical_key",
        campaign=campaign_id,
    )
    graph_service_keys = sorted(str(node["key"]) for node in graph_nodes)
    # One column: `support.neo4j_query` reads `cypher-shell --format plain`, whose header/values
    # are separated by `|` per row but by `, ` between columns; a single rendered cell keeps the
    # readback mechanical (both keys are canonical keys and contain no spaces).
    graph_edge_rows = support.neo4j_query(
        "MATCH (f:IP)-[r:EXPOSES]->(t:Service)"
        " WHERE $campaign IN coalesce(f.campaign_ids, [])"
        "   AND $campaign IN coalesce(t.campaign_ids, [])"
        " RETURN f.canonical_key + ' -> ' + t.canonical_key AS edge",
        campaign=campaign_id,
    )
    graph_edges = sorted(
        (str(edge["edge"]).split(" -> ", 1)[0], str(edge["edge"]).split(" -> ", 1)[1])
        for edge in graph_edge_rows
    )
    document["neo4j"] = {
        "services": graph_service_keys,
        "exposes": [{"from": source, "to": target} for source, target in graph_edges],
    }
    support.line(
        "postgres services", len(pg_service_keys), "| neo4j services", len(graph_service_keys)
    )
    support.line("postgres EXPOSES", len(pg_edges), "| neo4j EXPOSES", len(graph_edges))
    support.require(
        pg_service_keys == graph_service_keys,
        "Service nodes differ: only in PostgreSQL "
        f"{sorted(set(pg_service_keys) - set(graph_service_keys))}, only in the graph "
        f"{sorted(set(graph_service_keys) - set(pg_service_keys))}",
    )
    support.require(
        pg_edges == graph_edges,
        f"EXPOSES edges differ: only in PostgreSQL {sorted(set(pg_edges) - set(graph_edges))}, "
        f"only in the graph {sorted(set(graph_edges) - set(pg_edges))}",
    )

    support.section("7. ingestion receipts (nothing quarantined)")
    receipts = support.rows(
        connection,
        """
        SELECT i.event_id, i.dedup_key, i.status, i.receipt -> 'quarantined' AS quarantined
          FROM ingestion_inbox i JOIN scan_job j ON j.job_id = i.job_id
         WHERE j.campaign_id = %s ORDER BY i.received_at
        """,
        (campaign_id,),
    )
    document["receipts"] = receipts
    for receipt in receipts:
        quarantined = receipt["quarantined"] or []
        support.line(
            receipt["status"], "| quarantined", len(quarantined), "|", receipt["dedup_key"]
        )
        support.require(not quarantined, f"ingestion quarantined records: {quarantined}")
        support.require(
            receipt["status"] == "accepted", f"envelope {receipt['event_id']} not accepted"
        )

    support.section("8. provenance: service -> job -> evidence")
    provenance = support.rows(
        connection,
        """
        SELECT a.canonical_key, p.provider, p.source_job_id, j.capability
          FROM asset_provenance p
          JOIN asset a ON a.asset_id = p.asset_id
          JOIN scan_job j ON j.job_id = p.source_job_id
         WHERE j.campaign_id = %s AND a.kind = 'service'
         ORDER BY a.canonical_key
        """,
        (campaign_id,),
    )
    document["provenance"] = provenance
    for item in provenance:
        support.line(item["canonical_key"], "via", item["capability"], item["provider"])
    support.require(
        {item["capability"] for item in provenance} == {support.DISCOVER},
        "a service asset is not traced to the discovery job",
    )
    return document


def _check(evidence: dict[str, Any]) -> None:
    """One place for the cross-record expectations the sections above only print."""
    services = evidence["services"]
    keys = [str(service["canonical_key"]) for service in services]
    support.require(len(keys) == len(set(keys)), "a service appears twice")
    support.require(
        all(str(service["canonical_key"]).startswith("service:") for service in services),
        "a service asset does not use the service: canonical key",
    )
    addresses = {str(service["exposed_from"]) for service in services}
    support.require(
        bool(addresses), "no address is linked to a service, so the graph has no IP -> Service path"
    )


def _stamp() -> str:
    return support.now().replace(":", "").replace("-", "").split(".")[0]


if __name__ == "__main__":
    sys.exit(main())
