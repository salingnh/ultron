#!/usr/bin/env python3
"""`make demo-g1` - the G1 gate: one campaign through every component, on the authorized lab.

The demo does exactly what an operator does, then prints the evidence the plan's G1 row asks for
(`docs/living/02-ke-hoach-trien-khai.md`, "Campaign thật → agent/MCP → container →
metadata/raw/graph/UI"):

1. `POST /campaigns` - a campaign whose only target is the lab zone `lab.aegis.test`, the lab-only
   policy (rate limit 5/s, at most 2 parallel jobs) and the fake model (the scripted G1 policy).
2. The M02 workflow starts, the M03 session builds its context over MCP, and the scripted policy
   proposes `dns.enumerate_subdomains` (Subfinder). M05 signs the task, M06 runs the pinned image
   on the lab network; the raw JSONL goes to the evidence store, the envelope goes to M27, which
   writes assets/observations/relationships and publishes the outbox events M23 projects to Neo4j.
3. The next session sees the discovered names in its context and proposes `dns.resolve` (DNSx) with
   `depends_on`; M02 dispatches it only after the enumeration succeeded. Then the policy stops
   (`objective_met`) and the campaign completes.
4. Evidence printed: job history and status chain, dependency edge, evidence objects and receipts,
   asset/observation/relationship counts in PostgreSQL and Neo4j, the provenance chain, the audit
   rows with their actors, the JSON view of the published events and of the flow read model, a
   network-isolation probe on the same lab network the job container ran on, and the no-duplicate
   queries (job fingerprint, canonical key, observation, outbox, ingestion).

Exit codes: 0 = every check passed, 1 = a check failed (the failing line is printed), 2 = the stack
is not ready (the message says which command starts it).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import support  # noqa: E402 - the demo scripts' shared helpers, a sibling module

DEMO_TIMEOUT_ENV = "DEMO_TIMEOUT_SECONDS"
DEFAULT_TIMEOUT = 420.0


def main(argv: list[str] | None = None) -> int:
    support.load_demo_env()
    timeout = float(os.environ.get(DEMO_TIMEOUT_ENV) or DEFAULT_TIMEOUT)
    support.section("0. stack")
    stack = _stack_check()
    support.line("api", os.environ["AEGIS_API_URL"])
    support.line("processes", ", ".join(f"{item.name}:{item.pid}" for item in stack) or "none")

    support.section("1. campaign (POST /campaigns, lab seed, RoE lab only)")
    campaign_id = support.create_campaign("G1.5c lab demo")
    support.line("campaign_id", campaign_id)
    support.line("seed", support.LAB_ZONE)
    support.line("policy", json.dumps(support.DEMO_POLICY, sort_keys=True))

    support.section("2. campaign runs: agent/MCP -> Subfinder -> DNSx")
    ticks = 0

    def progress(body: dict[str, Any]) -> None:
        nonlocal ticks
        ticks += 1
        if ticks % 5 == 0:
            support.line("status", body.get("status"), "|", (body.get("status_reason") or "-"))

    finished = support.wait_campaign(campaign_id, timeout_seconds=timeout, on_tick=progress)
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
        "started_at": finished.get("started_at"),
        "ended_at": finished.get("ended_at"),
    }
    evidence["finished_at"] = support.now()
    _check(evidence)
    artifact = support.write_artifact(f"g1-{_stamp()}.json", evidence)
    support.section("evidence file")
    support.line(str(artifact))
    support.section("result")
    support.line("PASS - every G1 evidence check passed")
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

    support.section("3. job history (scan_job + job_status_change)")
    jobs = support.rows(
        connection,
        """
        SELECT j.job_id, j.capability, j.provider, j.provider_version, j.status, j.attempt,
               j.generation, j.job_fingerprint, j.envelope_event_id, j.created_at, j.started_at,
               j.finished_at, j.proposed_by
          FROM scan_job j WHERE j.campaign_id = %s ORDER BY j.created_at
        """,
        (campaign_id,),
    )
    document["jobs"] = jobs
    for job in jobs:
        chain = support.rows(
            connection,
            "SELECT seq, from_status, to_status, created_at FROM job_status_change"
            " WHERE job_id = %s ORDER BY seq",
            (job["job_id"],),
        )
        job["status_chain"] = [
            f"{row['from_status'] or 'NULL'}→{row['to_status']}" for row in chain
        ]
        support.line(
            job["capability"],
            job["provider"],
            job["provider_version"],
            job["status"],
            "| attempt",
            job["attempt"],
            "| envelope" if job["envelope_event_id"] else "| no envelope",
        )
        support.line("   ", " -> ".join(job["status_chain"]))
        support.require(job["status"] == "SUCCEEDED", f"job {job['job_id']} ended {job['status']}")
        support.require(
            job["envelope_event_id"] is not None, f"job {job['job_id']} has no envelope receipt"
        )
    capabilities = [job["capability"] for job in jobs]
    support.require(support.ENUMERATE in capabilities, "no enumeration job in the campaign")
    support.require(support.RESOLVE in capabilities, "no DNSx job in the campaign")
    support.require(len(jobs) == 2, f"expected exactly 2 jobs, found {len(jobs)}")

    support.section("4. dependency: DNSx waits for Subfinder")
    dependencies = support.rows(
        connection,
        """
        SELECT d.depends_on_job_id, p.capability AS depends_on_capability, d.job_id,
               j.capability
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
            f"{item['capability']} depends_on {item['depends_on_capability']}",
            f"({item['depends_on_job_id']})",
        )
    support.require(
        len(dependencies) == 1, f"expected one dependency edge, found {len(dependencies)}"
    )
    enumerate_job = next(job for job in jobs if job["capability"] == support.ENUMERATE)
    support.require(
        dependencies[0]["depends_on_job_id"] == enumerate_job["job_id"],
        "the DNSx job does not depend on the enumeration job",
    )

    support.section("5. raw output and ingestion receipts")
    evidence_rows = support.rows(
        connection,
        """
        SELECT e.evidence_id, e.storage_uri, e.sha256, e.size_bytes, e.media_type, e.classification,
               e.verified_at, e.job_id
          FROM evidence e JOIN scan_job j ON j.job_id = e.job_id
         WHERE j.campaign_id = %s ORDER BY e.created_at
        """,
        (campaign_id,),
    )
    document["evidence"] = evidence_rows
    for item in evidence_rows:
        support.line(
            item["media_type"],
            f"{item['size_bytes']} B",
            item["sha256"][:16] + "…",
            "verified" if item["verified_at"] else "unverified",
            "|",
            item["storage_uri"],
        )
    support.require(len(evidence_rows) >= 2, "expected evidence for both jobs")
    receipts = support.rows(
        connection,
        """
        SELECT i.event_id, i.dedup_key, i.status, i.revision,
               i.receipt -> 'quarantined' AS quarantined
          FROM ingestion_inbox i JOIN scan_job j ON j.job_id = i.job_id
         WHERE j.campaign_id = %s ORDER BY i.received_at
        """,
        (campaign_id,),
    )
    document["receipts"] = receipts
    for receipt in receipts:
        quarantined = receipt["quarantined"] or []
        support.line(
            receipt["status"],
            "| revision",
            receipt["revision"],
            "| quarantined",
            len(quarantined),
            "|",
            receipt["dedup_key"],
        )
        support.require(not quarantined, f"ingestion quarantined records: {quarantined}")
        support.require(
            receipt["status"] == "accepted", f"envelope {receipt['event_id']} not accepted"
        )

    support.section("6. metadata and graph counts")
    counts = {
        "assets": support.count(
            connection,
            "SELECT count(*) AS n FROM asset_campaign WHERE campaign_id = %s",
            (campaign_id,),
        ),
        "observations": support.count(
            connection,
            "SELECT count(*) AS n FROM observation WHERE campaign_id = %s",
            (campaign_id,),
        ),
        # An edge is a fact about the world, not about one campaign (`relationship_one_open` is
        # unique on (type, from, to)): a second campaign on the same lab zone *sees* the same edges
        # and records a sighting, so "this campaign's relationships" means "opened by it or seen by
        # one of its jobs".
        "relationships": support.count(
            connection,
            """
            SELECT count(*) AS n
              FROM relationship r
             WHERE r.campaign_id = %s
                OR EXISTS (
                     SELECT 1 FROM relationship_sighting s
                       JOIN scan_job j ON j.job_id = s.scan_id
                      WHERE s.relationship_id = r.relationship_id AND j.campaign_id = %s)
            """,
            (campaign_id, campaign_id),
        ),
        "graph_revisions": support.count(
            connection,
            "SELECT count(*) AS n FROM graph_revision WHERE campaign_id = %s",
            (campaign_id,),
        ),
        "outbox_events": support.count(
            connection,
            "SELECT count(*) AS n FROM outbox_event WHERE campaign_id = %s",
            (campaign_id,),
        ),
    }
    graph = support.neo4j_query(
        "MATCH (a:Asset) WHERE $campaign IN coalesce(a.campaign_ids, []) RETURN count(a) AS assets",
        campaign=campaign_id,
    )
    counts["neo4j_assets"] = int(graph[0]["assets"]) if graph else 0
    edges = support.neo4j_query(
        "MATCH (a:Asset)-[r]->(b:Asset)"
        " WHERE $campaign IN coalesce(a.campaign_ids, [])"
        "   AND $campaign IN coalesce(b.campaign_ids, [])"
        " RETURN count(r) AS relations",
        campaign=campaign_id,
    )
    counts["neo4j_relationships"] = int(edges[0]["relations"]) if edges else 0
    # An edge can only be in the graph when both of its ends are this campaign's assets: this is
    # the number the live projection must reach, without a rebuild.
    counts["projectable_relationships"] = support.count(
        connection,
        """
        SELECT count(*) AS n
          FROM relationship r
          JOIN asset_campaign fc ON fc.asset_id = r.from_asset_id AND fc.campaign_id = %s
          JOIN asset_campaign tc ON tc.asset_id = r.to_asset_id AND tc.campaign_id = %s
        """,
        (campaign_id, campaign_id),
    )
    document["counts"] = counts
    for name, value in counts.items():
        support.line(name, value)
    support.require(counts["assets"] >= 4, "the campaign should know the seed and three subdomains")
    support.require(counts["observations"] >= 6, "too few observations: ingestion lost records")
    support.require(counts["relationships"] >= 3, "too few relationships: the graph lost the edges")
    support.require(counts["neo4j_assets"] >= 4, "the M23 projection did not reach Neo4j")
    support.require(counts["neo4j_relationships"] >= 3, "the projection lost the relationships")
    # Counts are not enough: the sets must be equal. A seed that only exists as a campaign row (no
    # job observed it) used to be in PostgreSQL and missing from the graph, and a count of "lab
    # assets" hid it (the G1 final walkthrough's 7-vs-6).
    sets = _graph_sets(connection, campaign_id)
    document["graph_sets"] = sets
    support.line(
        "assets only in PostgreSQL",
        sets["assets_only_in_postgres"] or "none",
    )
    support.line(
        "assets only in the graph",
        sets["assets_only_in_graph"] or "none",
    )
    support.line(
        "edges only in PostgreSQL",
        sets["edges_only_in_postgres"] or "none",
    )
    support.line(
        "edges only in the graph",
        sets["edges_only_in_graph"] or "none",
    )
    support.require(
        not sets["assets_only_in_postgres"],
        "the graph is missing assets PostgreSQL has: "
        f"{sets['assets_only_in_postgres']} (every asset needs its event; a seed is published by "
        "M01 in the campaign transaction)",
    )
    support.require(
        not sets["assets_only_in_graph"],
        f"the graph has assets this campaign does not: {sets['assets_only_in_graph']}",
    )
    support.require(
        not sets["edges_only_in_postgres"],
        "the graph is missing relationships PostgreSQL has: "
        f"{sets['edges_only_in_postgres']} (a rebuild would produce them, so this is the "
        "incremental projection)",
    )
    support.require(
        not sets["edges_only_in_graph"],
        f"the graph has relationships PostgreSQL does not: {sets['edges_only_in_graph']}",
    )
    support.require(counts["outbox_events"] > 0, "no outbox events were published")

    support.section("7. provenance: seed -> asset -> observation -> evidence")
    provenance = support.rows(
        connection,
        """
        SELECT a.canonical_key, source.raw_value AS seed_value, source.kind AS seed_kind,
               p.source_job_id, p.provider
          FROM asset_provenance p
          JOIN asset a ON a.asset_id = p.asset_id
          LEFT JOIN campaign_target source ON source.target_id = p.from_target_id
          JOIN scan_job j ON j.job_id = p.source_job_id
         WHERE j.campaign_id = %s ORDER BY a.canonical_key
        """,
        (campaign_id,),
    )
    document["provenance"] = provenance
    for item in provenance:
        support.line(
            item["canonical_key"],
            "from seed",
            item["seed_value"] or "(asset source)",
            "via",
            item["provider"],
        )
    support.require(provenance, "no asset provenance rows: the chain from the seed is missing")
    observed = support.rows(
        connection,
        """
        SELECT a.canonical_key, o.predicate, o.observed_at, o.evidence_ids, e.sha256, e.storage_uri
          FROM observation o
          JOIN asset a ON a.asset_id = o.subject_asset_id
          LEFT JOIN evidence e ON e.evidence_id = (o.evidence_ids)[1]
         WHERE o.campaign_id = %s ORDER BY a.canonical_key, o.predicate LIMIT 8
        """,
        (campaign_id,),
    )
    document["observations_with_evidence"] = observed
    for item in observed:
        support.line(
            item["canonical_key"],
            item["predicate"],
            "| evidence",
            (item["sha256"] or "-")[:16],
        )
    support.require(
        any(item["sha256"] for item in observed),
        "no observation points at its evidence object",
    )

    support.section("8. audit (who did what)")
    audit = support.rows(
        connection,
        """
        SELECT action, actor -> 'kind' AS kind, actor -> 'id' AS actor, count(*) AS n
          FROM audit_log WHERE campaign_id = %s GROUP BY 1, 2, 3 ORDER BY 1
        """,
        (campaign_id,),
    )
    document["audit"] = audit
    for item in audit:
        support.line(item["action"], "|", item["kind"], item["actor"], "|", item["n"])
    support.require(audit, "no audit rows for the campaign")

    support.section("9. network isolation (the job container had no route out)")
    isolation = _isolation_probe()
    document["isolation"] = isolation
    for name, value in isolation.items():
        support.line(name, value)
    support.require(isolation.get("internal") is True, "the lab network is not internal")
    support.require(
        isolation.get("published_ports") in (0, "0"), "the lab network publishes a port"
    )
    support.require(isolation.get("internet_reachable") is False, "the probe reached the internet")
    support.require(isolation.get("control_plane_reachable") is False, "the probe reached the API")

    support.section("10. no duplicates")
    duplicates = _duplicates(connection, campaign_id)
    document["duplicates"] = duplicates
    for name, groups in duplicates.items():
        support.line(name, "duplicates:", len(groups))
    for name, groups in duplicates.items():
        support.require(
            not groups, f"{name} has duplicates: {json.dumps(groups, default=str)[:800]}"
        )

    support.section("11. published events (SSE source) and flow read model")
    events = support.campaign_events(campaign_id)
    flow = support.campaign_flow(campaign_id)
    document["events"] = events
    document["flow"] = flow
    types = sorted({str(item.get("type")) for item in events})
    support.line("events", len(events), "| types", ", ".join(types))
    nodes = flow.get("nodes") or []
    edges = flow.get("edges") or []
    support.line("flow nodes", len(nodes), "| edges", len(edges))
    support.require(events, "the campaign has no published events (the SSE stream would be empty)")
    support.require(nodes, "the flow read model is empty")
    support.require(
        any(str(item.get("type")) == "job.completed.v2" for item in events),
        "no job.completed.v2 event was published",
    )
    return document


def _graph_sets(connection: Any, campaign_id: str) -> dict[str, list[str]]:
    """The campaign's assets and edges, in PostgreSQL and in Neo4j, as comparable sets."""
    pg_assets = {
        str(row["canonical_key"])
        for row in support.rows(
            connection,
            "SELECT a.canonical_key FROM asset a"
            " JOIN asset_campaign ac ON ac.asset_id = a.asset_id WHERE ac.campaign_id = %s",
            (campaign_id,),
        )
    }
    graph_nodes = support.neo4j_query(
        "MATCH (a:Asset) WHERE $campaign IN coalesce(a.campaign_ids, [])"
        " RETURN a.canonical_key AS key",
        campaign=campaign_id,
    )
    graph_assets = {str(node["key"]) for node in graph_nodes}
    pg_edges = {
        str(row["relationship_id"])
        for row in support.rows(
            connection,
            "SELECT r.relationship_id FROM relationship r"
            " JOIN asset_campaign fc ON fc.asset_id = r.from_asset_id AND fc.campaign_id = %s"
            " JOIN asset_campaign tc ON tc.asset_id = r.to_asset_id AND tc.campaign_id = %s",
            (campaign_id, campaign_id),
        )
    }
    graph_edge_rows = support.neo4j_query(
        "MATCH (a:Asset)-[r]->(b:Asset)"
        " WHERE $campaign IN coalesce(a.campaign_ids, [])"
        "   AND $campaign IN coalesce(b.campaign_ids, [])"
        " RETURN r.relationship_id AS id",
        campaign=campaign_id,
    )
    graph_edges = {str(edge["id"]) for edge in graph_edge_rows}
    return {
        "assets_only_in_postgres": sorted(pg_assets - graph_assets),
        "assets_only_in_graph": sorted(graph_assets - pg_assets),
        "edges_only_in_postgres": sorted(pg_edges - graph_edges),
        "edges_only_in_graph": sorted(graph_edges - pg_edges),
    }


def _isolation_probe() -> dict[str, Any]:
    """Run a throwaway container on the lab network and show it cannot reach anything else.

    The job container itself is removed after the run (`PodmanRunner.remove` keeps only its output),
    so the proof is made the same way the G0.4c lab proves its boundary: a container on the same
    network, with the same image family, asked for its routes and for two connections it must not
    be able to make.
    """
    inspect = subprocess.run(
        ["podman", "network", "inspect", support.LAB_NETWORK, "--format", "{{.Internal}}"],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    internal = inspect.stdout.strip() == "true"
    published = subprocess.run(
        ["podman", "port", next(iter(_lab_containers()), "")],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    probe = _probe_script()
    completed = subprocess.run(
        ["podman", "run", "--rm", "--network", support.LAB_NETWORK, *_probe_image_args(), probe],
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )
    if completed.returncode != 0:
        support.fail(f"the isolation probe could not run: {completed.stderr.strip()[:2000]}")
    report = json.loads(completed.stdout.strip().splitlines()[-1])
    return {
        "network": support.LAB_NETWORK,
        "internal": internal,
        "published_ports": 0 if not published.stdout.strip() else published.stdout.strip(),
        "routes": report["routes"],
        "internet_reachable": report["internet"],
        "control_plane_reachable": report["control_plane"],
    }


def _probe_script() -> str:
    return (
        "import json, socket\n"
        "routes = [line.split()[0] for line in open('/proc/net/route')"
        " if line.split()[2] == '00000000']\n"
        "def reachable(host, port):\n"
        "    try:\n"
        "        socket.create_connection((host, port), timeout=3).close()\n"
        "        return True\n"
        "    except OSError:\n"
        "        return False\n"
        "print(json.dumps({'routes': routes, 'internet': reachable('1.1.1.1', 443),"
        " 'control_plane': reachable('10.88.0.1', 8000)}))\n"
    )


def _probe_image_args() -> list[str]:
    """The pinned Python image of the dev stack (deploy/dev/images.env), read from the checkout."""
    pins = (support.REPO / "deploy/dev/images.env").read_text(encoding="utf-8")
    for raw in pins.splitlines():
        if raw.startswith("AEGIS_PYTHON_IMAGE="):
            return [raw.partition("=")[2].strip(), "python3", "-c"]
    support.fail("deploy/dev/images.env has no AEGIS_PYTHON_IMAGE pin")
    raise AssertionError("unreachable")


def _lab_containers() -> list[str]:
    completed = subprocess.run(
        [
            "podman",
            "ps",
            "--filter",
            "label=io.podman.compose.project=aegis-lab",
            "--format",
            "{{.Names}}",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    return completed.stdout.split()


def _duplicates(connection: Any, campaign_id: str) -> dict[str, list[dict[str, Any]]]:
    """The plan's no-duplicate queries: same job twice, same asset twice, same event twice."""
    return {
        "jobs_by_fingerprint": support.duplicate_groups(
            connection,
            """
            SELECT job_fingerprint, count(*) AS n FROM scan_job
             WHERE campaign_id = %s GROUP BY 1 HAVING count(*) > 1
            """,
            (campaign_id,),
        ),
        "assets_by_canonical_key": support.duplicate_groups(
            connection,
            "SELECT canonical_key, count(*) AS n FROM asset GROUP BY 1 HAVING count(*) > 1",
        ),
        "observations": support.duplicate_groups(
            connection,
            """
            SELECT subject_asset_id, predicate, value_hash, observed_at, count(*) AS n
              FROM observation
             WHERE campaign_id = %s
             GROUP BY 1, 2, 3, 4 HAVING count(*) > 1
            """,
            (campaign_id,),
        ),
        "outbox_events": support.duplicate_groups(
            connection,
            "SELECT type, dedup_key, count(*) AS n FROM outbox_event"
            " GROUP BY 1, 2 HAVING count(*) > 1",
        ),
        "ingestion_receipts": support.duplicate_groups(
            connection,
            "SELECT dedup_key, count(*) AS n FROM ingestion_inbox GROUP BY 1 HAVING count(*) > 1",
        ),
        "evidence_objects": support.duplicate_groups(
            connection,
            """
            SELECT e.storage_uri, count(*) AS n
              FROM evidence e JOIN scan_job j ON j.job_id = e.job_id
             WHERE j.campaign_id = %s GROUP BY 1 HAVING count(*) > 1
            """,
            (campaign_id,),
        ),
    }


def _check(document: dict[str, Any]) -> None:
    """The one summary every gate reader looks at: all checks above passed, nothing quarantined."""
    document["checks"] = {
        "campaign_completed": True,
        "two_jobs_succeeded": len(document["jobs"]) == 2,
        "dependency_edge": len(document["dependencies"]) == 1,
        "envelopes_accepted": all(
            receipt["status"] == "accepted" for receipt in document["receipts"]
        ),
        "graph_projected": document["counts"]["neo4j_assets"] >= 4,
        "graph_asset_sets_match": not document["graph_sets"]["assets_only_in_postgres"]
        and not document["graph_sets"]["assets_only_in_graph"],
        "graph_edge_sets_match": not document["graph_sets"]["edges_only_in_postgres"]
        and not document["graph_sets"]["edges_only_in_graph"],
        "no_duplicates": not any(document["duplicates"].values()),
        "network_isolated": document["isolation"]["internet_reachable"] is False,
    }


def _stamp() -> str:
    return str(support.now()).replace(":", "").replace("-", "").replace(".", "")


if __name__ == "__main__":
    sys.exit(main())
