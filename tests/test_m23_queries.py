"""The six `graph.*` query functions against PostgreSQL 18 and Neo4j 2026.10 (G1.4b).

Every output is checked against `contracts/mcp/graph-queries.v2.schema.json` with the shared
`aegis.validation` hook, and the acceptance items of the card are the ones asserted hardest:
`truncated` must be true exactly when a ceiling cut the answer, `limits_applied` must report the
server ceiling, edges must respect `as_of`, and every query must stay inside its campaign.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
import pytest

from aegis import validation
from aegis.common.ports import Excerpt
from aegis.m23_graph import graph, queries
from aegis.m23_graph.models import AssetSnapshot, RelationshipSnapshot
from aegis.m23_graph.plan import plan_round
from tests.m23_support import (
    CAMPAIGN_ID,
    connect,
    graph_driver,
    ingest,
    pipeline_database,
    project_all,
    requires_pipeline,
)

pytestmark = requires_pipeline

NEIGHBORS_OUTPUT = "mcp/graph-queries.v2.schema.json#/$defs/get_asset_neighbors/properties/output"
OBSERVATIONS_OUTPUT = (
    "mcp/graph-queries.v2.schema.json#/$defs/get_recent_observations/properties/output"
)
HYPOTHESES_OUTPUT = (
    "mcp/graph-queries.v2.schema.json#/$defs/get_unverified_hypotheses/properties/output"
)
MATCHES_OUTPUT = "mcp/graph-queries.v2.schema.json#/$defs/get_package_cve_matches/properties/output"
DELTA_OUTPUT = "mcp/graph-queries.v2.schema.json#/$defs/summarize_campaign_delta/properties/output"
EXCERPT_OUTPUT = "mcp/graph-queries.v2.schema.json#/$defs/get_evidence_excerpt/properties/output"


def fetch(connection: psycopg.Connection[Any], statement: tuple[str, tuple[Any, ...]]) -> Any:
    """Run one INSERT ... RETURNING and return its row (`mypy` needs the None check here)."""
    found = connection.execute(*statement).fetchone()
    assert found is not None, statement[0]
    return found


@pytest.fixture
def database() -> Iterator[tuple[str, list[str]]]:
    with pipeline_database(jobs=4) as value:
        yield value


def write_graph(
    driver: Any,
    *,
    assets: list[AssetSnapshot],
    edges: list[RelationshipSnapshot],
    partitions: int = 2,
) -> None:
    """Project synthetic snapshots through the same planner the projector uses."""
    from datetime import UTC

    from aegis.m23_graph.models import ASSET_EVENT, OutboxEvent

    moment = datetime(2026, 11, 24, 10, 0, tzinfo=UTC)
    events = [
        OutboxEvent(
            seq=index + 1,
            event_id=f"ev-{asset.asset_id}",
            type=ASSET_EVENT,
            dedup_key=f"{asset.asset_id}:1",
            campaign_id=CAMPAIGN_ID,
            payload={
                "asset_id": asset.asset_id,
                "canonical_key": asset.canonical_key,
                "kind": asset.kind,
                "revision": 1,
                "causal_job_id": "01900000-0000-7000-8000-0000000c0003",
                "campaign_id": CAMPAIGN_ID,
                "discovered_from": [],
                "first_seen": moment.isoformat(),
            },
            trace={},
            occurred_at=moment,
        )
        for index, asset in enumerate(assets)
    ]
    by_asset: dict[str, list[RelationshipSnapshot]] = {}
    for edge in edges:
        by_asset.setdefault(edge.from_asset_id, []).append(edge)
    plan = plan_round(
        events,
        seen=set(),
        assets={asset.asset_id: asset for asset in assets},
        relationships=by_asset,
        findings={},
        evidence={},
        partitions=partitions,
    )
    for phase, ops in plan.phases().items():
        graph.apply_ops(driver, ops)
        assert phase in (0, 1)


def ident(name: str) -> str:
    """A deterministic UUIDv7-shaped id for a symbolic name (the contract requires Id = UUIDv7)."""
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()
    return (
        f"{digest[0:8]}-{digest[8:12]}-7{digest[13:16]}-"
        f"{'89ab'[int(digest[16], 16) % 4]}{digest[17:20]}-{digest[20:32]}"
    )


def asset(
    asset_id: str,
    key: str,
    *,
    kind: str = "domain",
    last_seen: datetime | None = None,
    campaign_ids: tuple[str, ...] = (CAMPAIGN_ID,),
) -> AssetSnapshot:
    moment = last_seen or datetime(2026, 11, 24, 10, 0, tzinfo=UTC)
    return AssetSnapshot(
        asset_id=ident(asset_id),
        canonical_key=key,
        kind=kind,
        first_seen=moment,
        last_seen=moment,
        owner=None,
        exposure=None,
        criticality=None,
        campaign_ids=campaign_ids,
        first_job_id=None,
    )


def edge(
    relationship_id: str,
    from_id: str,
    to_id: str,
    *,
    valid_from: datetime | None = None,
    valid_to: datetime | None = None,
    campaign_id: str = CAMPAIGN_ID,
) -> RelationshipSnapshot:
    moment = valid_from or datetime(2026, 11, 24, 10, 0, tzinfo=UTC)
    return RelationshipSnapshot(
        relationship_id=ident(relationship_id),
        type="SUBDOMAIN_OF",
        from_asset_id=ident(from_id),
        to_asset_id=ident(to_id),
        observed_at=moment,
        valid_from=moment,
        valid_to=valid_to,
        source_job_id="01900000-0000-7000-8000-0000000c0003",
        confidence=0.9,
        campaign_id=campaign_id,
    )


def test_neighbors_output_is_the_contract_shape_without_truncation() -> None:
    with graph_driver() as driver:
        write_graph(
            driver,
            assets=[asset("asset-a", "dns:a.test"), asset("asset-b", "dns:b.test")],
            edges=[edge("rel-1", "asset-b", "asset-a")],
        )
        result = queries.get_asset_neighbors(
            driver, campaign_id=CAMPAIGN_ID, canonical_key="dns:a.test", limit=10
        )
    validation.validate(NEIGHBORS_OUTPUT, result)
    assert result["truncated"] is False
    assert result["limits_applied"] == {"max_hops": 2, "limit": 200, "timeout_ms": 2000}
    assert {node["canonical_key"] for node in result["nodes"]} == {"dns:a.test", "dns:b.test"}
    assert result["edges"][0]["type"] == "SUBDOMAIN_OF"
    assert result["edges"][0]["from"] == "dns:b.test"
    assert result["edges"][0]["valid_to"] is None


def test_neighbors_truncate_at_the_record_ceiling_and_say_so() -> None:
    with graph_driver() as driver:
        assets = [asset("asset-root", "dns:root.test")] + [
            asset(f"asset-{index}", f"dns:s{index}.test") for index in range(5)
        ]
        edges = [edge(f"rel-{index}", f"asset-{index}", "asset-root") for index in range(5)]
        write_graph(driver, assets=assets, edges=edges)
        limited = queries.get_asset_neighbors(
            driver, campaign_id=CAMPAIGN_ID, canonical_key="dns:root.test", limit=2
        )
    validation.validate(NEIGHBORS_OUTPUT, limited)
    assert limited["truncated"] is True
    assert len(limited["nodes"]) <= 2
    assert limited["limits_applied"]["limit"] == 200


def test_neighbors_respect_as_of_time() -> None:
    start = datetime(2026, 11, 1, tzinfo=UTC)
    closed = start + timedelta(days=5)
    with graph_driver() as driver:
        write_graph(
            driver,
            assets=[asset("asset-a", "dns:a.test"), asset("asset-old", "dns:old.test")],
            edges=[
                edge("rel-open", "asset-old", "asset-a", valid_from=start),
                edge("rel-closed", "asset-old", "asset-a", valid_from=start, valid_to=closed),
            ],
        )
        at_start = queries.get_asset_neighbors(
            driver,
            campaign_id=CAMPAIGN_ID,
            canonical_key="dns:a.test",
            as_of=start.isoformat(),
            limit=10,
        )
        after_close = queries.get_asset_neighbors(
            driver,
            campaign_id=CAMPAIGN_ID,
            canonical_key="dns:a.test",
            as_of=(closed + timedelta(days=1)).isoformat(),
            limit=10,
        )
    # At `start` both intervals are open (the closed one closes five days later).
    assert len(at_start["edges"]) >= 1
    keys_after = {edge_item["valid_to"] for edge_item in after_close["edges"]}
    assert len(after_close["edges"]) <= len(at_start["edges"])
    assert keys_after == {None} or not after_close["edges"]
    # The closed interval is not visible after it closed.
    assert all(edge_item["from"] == "dns:old.test" for edge_item in after_close["edges"])


def test_neighbors_never_walk_through_a_node_that_is_not_an_asset() -> None:
    """D2 (item 61 trial): two services sharing a CVE are a legal 2-hop path with a null endpoint.

    The projection's `AFFECTED_BY` candidate edge ends at a `:Vulnerability`, which has no
    `canonical_key`; returning that edge made the output violate its own contract and the REST
    endpoint answered an opaque 500. The asset neighbourhood is asset nodes and asset-to-asset
    edges only (`contracts/graph/model.md`); candidates are read per asset instead.
    """
    service_a, service_b = "service:10.114.53.61:80/tcp", "service:10.114.53.61:443/tcp"
    with graph_driver() as driver:
        write_graph(
            driver,
            assets=[
                asset("svc-a", service_a, kind="service"),
                asset("svc-b", service_b, kind="service"),
            ],
            edges=[],
        )
        with driver.session() as session:
            session.run(
                "MATCH (a:Asset {canonical_key: $a}), (b:Asset {canonical_key: $b})"
                " MERGE (v:Vulnerability {vulnerability_id: 'CVE-2021-41773'})"
                " MERGE (a)-[ra:AFFECTED_BY]->(v)"
                "   SET ra.valid_from = datetime(), ra.observed_at = datetime(),"
                "       ra.confidence = 0.7, ra.campaign_id = $cid"
                " MERGE (b)-[rb:AFFECTED_BY]->(v)"
                "   SET rb.valid_from = datetime(), rb.observed_at = datetime(),"
                "       rb.confidence = 0.7, rb.campaign_id = $cid",
                a=service_a,
                b=service_b,
                cid=CAMPAIGN_ID,
            ).consume()
        result = queries.get_asset_neighbors(
            driver, campaign_id=CAMPAIGN_ID, canonical_key=service_a, max_hops=2, limit=10
        )
    validation.validate(NEIGHBORS_OUTPUT, result)
    assert {node["canonical_key"] for node in result["nodes"]} == {service_a}
    assert result["edges"] == []


def test_neighbors_are_limited_to_the_campaign() -> None:
    other = "01900000-0000-7000-8000-0000000c0009"
    with graph_driver() as driver:
        write_graph(
            driver,
            assets=[
                asset("asset-a", "dns:a.test"),
                asset("asset-b", "dns:b.test"),
                asset("asset-c", "dns:c.test", campaign_ids=(other,)),
            ],
            edges=[edge("rel-1", "asset-b", "asset-a"), edge("rel-2", "asset-c", "asset-a")],
        )
        result = queries.get_asset_neighbors(
            driver, campaign_id=CAMPAIGN_ID, canonical_key="dns:a.test", limit=10
        )
    assert {node["canonical_key"] for node in result["nodes"]} == {"dns:a.test", "dns:b.test"}
    assert [item["from"] for item in result["edges"]] == ["dns:b.test"]


def test_a_stale_node_is_flagged() -> None:
    old = datetime.now(UTC) - timedelta(days=30)
    with graph_driver() as driver:
        write_graph(driver, assets=[asset("asset-a", "dns:a.test", last_seen=old)], edges=[])
        result = queries.get_asset_neighbors(
            driver, campaign_id=CAMPAIGN_ID, canonical_key="dns:a.test", limit=10
        )
    assert result["nodes"][0]["stale"] is True


def test_recent_observations_are_bounded_by_revision_and_contract_shaped(
    database: tuple[str, list[str]],
) -> None:
    dsn, jobs = database
    with graph_driver() as driver:
        ingest(
            dsn,
            jobs[0],
            assets=[{"kind": "domain", "canonical_key": "dns:obs.test"}],
            observations=[
                {
                    "subject": "dns:obs.test",
                    "predicate": "dns.record",
                    "value": {"type": "A", "value": "192.0.2.10", "ttl": 60},
                    "observed_at": "2026-11-24T10:00:00Z",
                }
            ],
            coverage=["dns:obs.test"],
        )
        project_all(dsn, driver, consumer="obs#g1")
    with connect(dsn) as connection:
        all_recent = queries.get_recent_observations(
            connection, campaign_id=CAMPAIGN_ID, since_revision=0, limit=10
        )
        none_newer = queries.get_recent_observations(
            connection, campaign_id=CAMPAIGN_ID, since_revision=10**9, limit=10
        )
        filtered = queries.get_recent_observations(
            connection, campaign_id=CAMPAIGN_ID, since_revision=0, predicates=["net.asn"], limit=10
        )
    validation.validate(OBSERVATIONS_OUTPUT, all_recent)
    assert len(all_recent["observations"]) == 1
    observation = all_recent["observations"][0]
    assert observation["subject"] == "dns:obs.test"
    assert observation["predicate"] == "dns.record"
    assert observation["polarity"] == "present"
    assert "192.0.2.10" in observation["value_summary"]
    assert all_recent["revision"] >= 1
    assert none_newer["observations"] == []
    assert filtered["observations"] == []


def test_recent_observations_truncate(database: tuple[str, list[str]]) -> None:
    dsn, jobs = database
    with graph_driver() as driver:
        ingest(
            dsn,
            jobs[0],
            assets=[{"kind": "domain", "canonical_key": "dns:many.test"}],
            observations=[
                {
                    "subject": "dns:many.test",
                    "predicate": "dns.record",
                    "value": {"type": "A", "value": f"192.0.2.{index}", "ttl": 60},
                    "observed_at": f"2026-11-24T10:0{index}:00Z",
                }
                for index in range(3)
            ],
            coverage=["dns:many.test"],
        )
        project_all(dsn, driver, consumer="obs2#g1")
    with connect(dsn) as connection:
        page = queries.get_recent_observations(
            connection, campaign_id=CAMPAIGN_ID, since_revision=0, limit=2
        )
    validation.validate(OBSERVATIONS_OUTPUT, page)
    assert page["truncated"] is True
    assert len(page["observations"]) == 2


def test_unverified_hypotheses_read_the_latest_revision(
    database: tuple[str, list[str]],
) -> None:
    dsn, jobs = database
    with connect(dsn) as connection:
        # M03 (G1.2c) owns sessions; the hypothesis ledger needs one to hang its revisions on.
        session_id = str(
            fetch(
                connection,
                (
                    "INSERT INTO agent_session (session_id, campaign_id, policy_version,"
                    " revision_from, status) VALUES (%s, %s, 'roe-1', 0, 'RUNNING')"
                    " RETURNING session_id",
                    ("01900000-0000-7000-8000-0000000c00a1", CAMPAIGN_ID),
                ),
            )["session_id"]
        )
        hypothesis_id = fetch(
            connection,
            (
                "INSERT INTO hypothesis (hypothesis_id, campaign_id, created_session)"
                " VALUES (%s, %s, %s) RETURNING hypothesis_id",
                ("01900000-0000-7000-8000-0000000c00aa", CAMPAIGN_ID, session_id),
            ),
        )["hypothesis_id"]
        for revision, (status, confidence) in enumerate(
            (("OPEN", 0.4), ("SUPPORTED", 0.9)), start=1
        ):
            connection.execute(
                "INSERT INTO hypothesis_revision (hypothesis_id, revision, claim, status,"
                " confidence, session_id) VALUES (%s, %s, 'claim', %s, %s, %s)",
                (hypothesis_id, revision, status, confidence, session_id),
            )
        result = queries.get_unverified_hypotheses(connection, campaign_id=CAMPAIGN_ID, limit=10)
    validation.validate(HYPOTHESES_OUTPUT, result)
    # The latest revision is SUPPORTED, so the hypothesis is no longer unverified.
    assert result["hypotheses"] == []
    assert result["truncated"] is False


def test_package_matches_are_contract_shaped(database: tuple[str, list[str]]) -> None:
    dsn, jobs = database
    with connect(dsn) as connection:
        asset_id = fetch(
            connection,
            (
                "INSERT INTO asset (asset_id, canonical_key, kind, first_seen, last_seen,"
                " normalization_version) VALUES (%s, 'purl:pkg:npm/left-pad@1.0.0', 'package',"
                " now(), now(), 'aegis-norm/1') RETURNING asset_id",
                ("01900000-0000-7000-8000-0000000c00bb",),
            ),
        )["asset_id"]
        connection.execute(
            "INSERT INTO asset_campaign (asset_id, campaign_id, first_seen) VALUES (%s, %s, now())",
            (asset_id, CAMPAIGN_ID),
        )
        snapshot_id = fetch(
            connection,
            (
                "INSERT INTO intel_snapshot (snapshot_id, feed, version, snapshot_at,"
                " record_count, source_uri)"
                " VALUES (%s, 'osv', 'v1', now(), 1, 'fixture://osv') RETURNING snapshot_id",
                ("01900000-0000-7000-8000-0000000c00cc",),
            ),
        )["snapshot_id"]
        vuln_rev = fetch(
            connection,
            (
                "INSERT INTO vulnerability_revision (vuln_rev_id, vulnerability_id, source,"
                " snapshot_id, cvss, kev, epss, content_hash)"
                " VALUES (%s, 'CVE-2024-0001', 'osv', %s, %s, %s, %s, %s) RETURNING vuln_rev_id",
                (
                    "01900000-0000-7000-8000-0000000c00dd",
                    snapshot_id,
                    psycopg.types.json.Jsonb([{"version": "3.1", "base_score": 7.5}]),
                    psycopg.types.json.Jsonb({"listed": True, "date_added": "2026-01-01"}),
                    psycopg.types.json.Jsonb({"score": 0.42}),
                    "c" * 64,
                ),
            ),
        )["vuln_rev_id"]
        connection.execute(
            "INSERT INTO package_vuln_match (match_id, package_asset_id, vulnerability_id,"
            " vuln_rev_id, match_method, matched) VALUES (%s, %s, 'CVE-2024-0001', %s,"
            " 'purl_range', true)",
            ("01900000-0000-7000-8000-0000000c00ee", asset_id, vuln_rev),
        )
        result = queries.get_package_cve_matches(
            connection,
            campaign_id=CAMPAIGN_ID,
            canonical_key="purl:pkg:npm/left-pad@1.0.0",
            limit=10,
        )
        kev_only = queries.get_package_cve_matches(
            connection,
            campaign_id=CAMPAIGN_ID,
            canonical_key="purl:pkg:npm/left-pad@1.0.0",
            include_kev_only=True,
            limit=10,
        )
    validation.validate(MATCHES_OUTPUT, result)
    assert result["matches"][0]["vulnerability_id"] == "CVE-2024-0001"
    assert result["matches"][0]["cvss_base"] == pytest.approx(7.5)
    assert result["matches"][0]["kev"] is True
    assert result["matches"][0]["epss"] == pytest.approx(0.42)
    assert kev_only["matches"] == result["matches"]


def test_campaign_delta_summarizes_the_published_deltas(database: tuple[str, list[str]]) -> None:
    dsn, jobs = database
    with graph_driver() as driver:
        ingest(dsn, jobs[0], assets=[{"kind": "domain", "canonical_key": "dns:delta1.test"}])
        ingest(dsn, jobs[1], assets=[{"kind": "domain", "canonical_key": "dns:delta2.test"}])
        project_all(dsn, driver, consumer="delta#g1")
    with connect(dsn) as connection:
        result = queries.summarize_campaign_delta(
            connection, campaign_id=CAMPAIGN_ID, from_revision=0, limit=10
        )
        empty = queries.summarize_campaign_delta(
            connection, campaign_id=CAMPAIGN_ID, from_revision=10**9, limit=10
        )
    validation.validate(DELTA_OUTPUT, result)
    assert result["counts"].get("asset.created") == 2
    assert result["from_revision"] == 0
    assert len(result["highlights"]) == 2
    assert result["truncated"] is False
    assert empty["counts"] == {}


def test_evidence_excerpt_needs_a_store_and_serves_metadata(
    database: tuple[str, list[str]],
) -> None:
    dsn, jobs = database
    with graph_driver():
        # Ingest seeds the evidence row M28 would have written before the envelope arrived.
        ingest(dsn, jobs[0], assets=[{"kind": "domain", "canonical_key": "dns:evidence.test"}])
    with connect(dsn) as connection:
        row = connection.execute(
            "SELECT evidence_id FROM evidence WHERE campaign_id = %s", (CAMPAIGN_ID,)
        ).fetchone()
        assert row is not None
        evidence_id = str(row["evidence_id"])
        with pytest.raises(queries.GraphQueryUnavailable):
            queries.get_evidence_excerpt(
                connection, None, campaign_id=CAMPAIGN_ID, evidence_id=evidence_id
            )

        class Store:
            def excerpt(self, evidence: str, offset: int, max_bytes: int) -> Excerpt:
                return Excerpt(
                    evidence_id=evidence, offset=offset, data=b"raw output", truncated=False
                )

            def put(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover - not used
                raise NotImplementedError

            def signed_url(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover
                raise NotImplementedError

            def verify(self, *args: Any, **kwargs: Any) -> bool:  # pragma: no cover
                raise NotImplementedError

        result = queries.get_evidence_excerpt(
            connection, Store(), campaign_id=CAMPAIGN_ID, evidence_id=evidence_id
        )
        validation.validate(EXCERPT_OUTPUT, result)
        assert result["excerpt"] == "raw output"
        assert result["total_bytes"] > 0
        assert result["limits_applied"] == {"max_bytes": 4096, "timeout_ms": 2000}
        with pytest.raises(queries.EvidenceNotFound):
            queries.get_evidence_excerpt(
                connection,
                Store(),
                campaign_id=CAMPAIGN_ID,
                evidence_id="01900000-0000-7000-8000-0000000c00ff",
            )
