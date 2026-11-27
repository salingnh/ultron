"""M23 projector against PostgreSQL 18 and Neo4j 5.26 (G1.4b).

The contract chain, M27 and the committed Cypher are the real ones; the two services are
throwaway (see `tests/m23_support.py`). What these tests pin, in the order the card asks for:

* an ingested envelope reaches the graph with the properties PostgreSQL holds;
* per-key order survives partitioning (highest revision wins on `pg_revision`);
* batching statements is equivalent to executing the committed statement per entity;
* a redelivered batch is idempotent and the cursor only moves after the graph commit;
* one `knowledge.delta.v2` per revision, valid against the contract, published once;
* rebuild under a new consumer generation reproduces the original graph exactly;
* the dispatcher lease and fence are enforced.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from typing import Any

import psycopg
import pytest
from psycopg.types.json import Jsonb

from aegis import validation
from aegis.m23_graph import graph, pg
from aegis.m23_graph.contract import RELATIONSHIP_TYPES
from aegis.m23_graph.models import ASSET_EVENT
from aegis.m23_graph.projector import Projector, ProjectorBusy, ProjectorConfig
from aegis.m27_ingestion.ids import uuid7
from tests import graph_support
from tests.m23_support import (
    CAMPAIGN_ID,
    assert_deltas_satisfy_contract,
    connect,
    cursor,
    graph_driver,
    ingest,
    outbox,
    pipeline_database,
    project_all,
    projector,
    requires_pipeline,
    two_campaign_subdomains,
    wipe_graph,
)
from tests.support_ingestion import observation

pytestmark = requires_pipeline

DELTA = "knowledge.delta.v2"


def domain(key: str) -> dict[str, Any]:
    return {"kind": "domain", "canonical_key": key}


def row(connection: psycopg.Connection[Any], sql: str, params: tuple[Any, ...] = ()) -> Any:
    found = connection.execute(sql, params).fetchone()
    assert found is not None, sql
    return found


def analytic_assets(driver: Any) -> dict[str, dict[str, Any]]:
    return {
        key: node
        for key, node in graph.snapshot(driver)["nodes"].items()
        if "Asset" in node["labels"]
    }


def append_asset_event(
    connection: psycopg.Connection[Any],
    *,
    asset_id: str,
    canonical_key: str,
    campaign_id: str,
    job_id: str,
) -> int:
    """One `asset.discovered.v2` for an existing asset, in its own revision and transaction.

    M27 emits these; a test that needs several revisions of *one* asset cannot get them from M27
    (it emits `asset.discovered` only when the asset is new to the campaign), and the projector is
    indifferent to who wrote the event as long as the transaction and the allocator are the real
    ones.
    """
    with connection.transaction():
        revision = int(
            row(
                connection,
                "INSERT INTO graph_revision (campaign_id, causal_job_id) VALUES (%s, %s)"
                " RETURNING revision",
                (campaign_id, job_id),
            )["revision"]
        )
        connection.execute(
            "INSERT INTO outbox_event (event_id, type, producer, dedup_key, campaign_id, payload,"
            " trace) VALUES (%s, %s, 'M27', %s, %s, %s, '{}')",
            (
                str(uuid7()),
                ASSET_EVENT,
                f"{asset_id}:{revision}",
                campaign_id,
                Jsonb(
                    {
                        "asset_id": asset_id,
                        "canonical_key": canonical_key,
                        "kind": "domain",
                        "revision": revision,
                        "causal_job_id": job_id,
                        "campaign_id": campaign_id,
                        "discovered_from": [],
                        "first_seen": "2026-11-24T10:00:00Z",
                    }
                ),
            ),
        )
    return revision


@pytest.fixture
def database() -> Iterator[tuple[str, list[str]]]:
    """A fresh migrated database per test: the projector reads the whole outbox, so tests must
    not see each other's events (a shared database would make node counts meaningless)."""
    with pipeline_database(jobs=6) as value:
        yield value


def test_projection_end_to_end(database: tuple[str, list[str]]) -> None:
    dsn, jobs = database
    payload = two_campaign_subdomains(jobs[0])
    with graph_driver() as driver:
        receipt = ingest(
            dsn,
            jobs[0],
            assets=payload["assets"],
            observations=payload["observations"],
            relationships=payload["relationships"],
            coverage=payload["coverage"],
        )
        assert receipt.accepted and not receipt.quarantined, receipt.quarantined
        stats = project_all(dsn, driver)
        assert stats.events_applied == len(outbox(dsn))
        assert stats.events_skipped == 0

        nodes = analytic_assets(driver)
        assert set(nodes) == {
            "Asset:dns:seed.internal.example",
            "Asset:dns:www.internal.example",
            "Asset:ip:192.0.2.10",
        }
        assert nodes["Asset:dns:www.internal.example"]["labels"] == ["Asset", "Domain"]
        assert nodes["Asset:ip:192.0.2.10"]["labels"] == ["Asset", "IP"]
        properties = nodes["Asset:dns:www.internal.example"]["properties"]
        assert properties["kind"] == "domain"
        assert properties["campaign_ids"] == [CAMPAIGN_ID]
        assert properties["pg_revision"] >= 1

        edges = graph.snapshot(driver)["edges"]
        assert {"DISCOVERED_FROM", "SUBDOMAIN_OF", "RESOLVES_TO"} <= {
            edge["type"] for edge in edges.values()
        }
        subdomain = next(e for e in edges.values() if e["type"] == "SUBDOMAIN_OF")
        assert subdomain["properties"]["confidence"] == pytest.approx(0.9)
        # `SET r.valid_to = null` removes the property in Neo4j: an open interval has no valid_to.
        assert "valid_to" not in subdomain["properties"]
        # The runtime validates deltas with the generated DTO; this is the contract-bundle check
        # (semantic aegis-* formats included) on what the projector really emitted.
        assert assert_deltas_satisfy_contract(dsn) >= 1


def test_a_graph_predicate_is_projected_as_an_observation_node(
    database: tuple[str, list[str]],
) -> None:
    """G1.6b: `service.product`/`http.technology` get a :Observation node, port state does not.

    The graph is the product view: `contracts/ingestion/predicates.v2.yaml` marks the predicates
    worth projecting (`graph: true`) and every other observation stays a PostgreSQL row. The node
    carries the subject's canonical key and the same `value_summary` the MCP read model publishes,
    read from PostgreSQL at apply time - not from the event payload.
    """
    dsn, jobs = database
    key = "service:203.0.113.10:8080/tcp"
    product = {
        "product": "nginx",
        "version": "1.29.8",
        "cpe": "cpe:2.3:a:f5:nginx:1.29.8:*:*:*:*:*:*:*",
    }
    with graph_driver() as driver:
        receipt = ingest(
            dsn,
            jobs[2],
            assets=[
                {"kind": "service", "canonical_key": key},
                {"kind": "application", "canonical_key": "app:http://203.0.113.10:8080"},
            ],
            observations=[
                {**observation(key, "service.product", product), "confidence": 0.9},
                observation(key, "net.port_state", "open"),
                observation("app:http://203.0.113.10:8080", "http.technology", ["nginx:1.29.8"]),
            ],
            relationships=[
                {
                    "type": "SERVES",
                    "from": key,
                    "to": "app:http://203.0.113.10:8080",
                    "confidence": 1.0,
                    "observed_at": "2026-11-24T10:00:00Z",
                }
            ],
        )
        assert receipt.accepted and not receipt.quarantined, receipt.quarantined
        project_all(dsn, driver)

        nodes = graph.snapshot(driver)["nodes"]
        projected = {k: v for k, v in nodes.items() if "Observation" in v["labels"]}
        assert len(projected) == 2, sorted(projected)
        predicates = {node["properties"]["predicate"] for node in projected.values()}
        assert predicates == {"service.product", "http.technology"}
        node = next(
            n for n in projected.values() if n["properties"]["predicate"] == "service.product"
        )
        assert node["properties"]["subject"] == key
        assert "nginx" in node["properties"]["value_summary"]
        assert node["properties"]["value_summary"] == json.dumps(product, sort_keys=True)
        assert node["properties"]["confidence"] == pytest.approx(0.9)
        assert node["properties"]["pg_revision"] >= 1
        # The SERVES edge is the traversal path Service -> Application, the observation node is
        # the value hanging off the asset's canonical key (G1.6b keeps the model's labels/edges).
        assert "SERVES" in {edge["type"] for edge in graph.snapshot(driver)["edges"].values()}


def test_per_key_order_survives_partitioning(database: tuple[str, list[str]]) -> None:
    """20 revisions of one asset, 8 partitions and 3-event batches: the last wins `pg_revision`."""
    dsn, jobs = database
    with graph_driver() as driver, connect(dsn) as connection:
        ingest(dsn, jobs[1], assets=[domain("dns:ordered.test")])
        asset_id = str(
            row(connection, "SELECT asset_id FROM asset WHERE canonical_key = 'dns:ordered.test'")[
                "asset_id"
            ]
        )
        revisions = [
            append_asset_event(
                connection,
                asset_id=asset_id,
                canonical_key="dns:ordered.test",
                campaign_id=CAMPAIGN_ID,
                job_id=jobs[1],
            )
            for _ in range(20)
        ]
        assert revisions == sorted(revisions)
        stats = project_all(dsn, driver, partitions=8, batch=3)
        assert stats.events_applied >= 20

        node = analytic_assets(driver)["Asset:dns:ordered.test"]["properties"]
        assert node["pg_revision"] == max(revisions)
        assert node["campaign_ids"] == [CAMPAIGN_ID]


def test_batched_statements_are_equivalent_to_the_committed_statements(
    database: tuple[str, list[str]],
) -> None:
    dsn, jobs = database
    with graph_driver() as driver:
        ingest(dsn, jobs[2], assets=[domain(f"dns:batch{index}.test") for index in range(20)])
        project_all(dsn, driver, consumer="batched#g1", partitions=4)
        batched = graph.snapshot(driver)
        assert {f"Asset:dns:batch{index}.test" for index in range(20)} <= set(
            analytic_assets(driver)
        )

        wipe_graph(driver)
        instance = projector(dsn, driver, consumer="single#g1", partitions=4)
        instance.config = ProjectorConfig(
            consumer="single#g1", batch=500, partitions=4, batched_statements=False
        )
        with instance:
            instance.run(drain_rounds=3, timeout=120)
        assert graph.snapshot(driver) == batched


def test_a_redelivered_batch_does_not_change_the_graph(database: tuple[str, list[str]]) -> None:
    dsn, jobs = database
    with graph_driver() as driver, connect(dsn) as connection:
        ingest(dsn, jobs[3], assets=[domain("dns:replay.test")])
        project_all(dsn, driver, consumer="replay#g1")
        before = graph.snapshot(driver)
        applied = cursor(dsn, "replay#g1")

        # The crash window: the graph is committed, the inbox has the events, the cursor is behind.
        # `consumer_cursor` accepts a value on INSERT and `consumer_inbox` is append-only, so a new
        # consumer with copies of the original inbox rows is exactly that state.
        connection.execute(
            "INSERT INTO consumer_cursor (consumer, last_seq) VALUES ('replay#g1-again', 0)"
        )
        connection.execute(
            "INSERT INTO consumer_inbox (consumer, dedup_key, event_id)"
            " SELECT 'replay#g1-again', dedup_key, event_id FROM consumer_inbox"
            "  WHERE consumer = 'replay#g1'"
        )
        stats = project_all(dsn, driver, consumer="replay#g1-again")
        assert stats.events_applied == 0
        assert stats.events_skipped > 0
        assert cursor(dsn, "replay#g1-again") == applied
        assert graph.snapshot(driver) == before


def test_the_cursor_does_not_move_when_the_graph_write_fails(
    database: tuple[str, list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    dsn, jobs = database
    with graph_driver() as driver, connect(dsn):
        ingest(dsn, jobs[4], assets=[domain("dns:atomic.test")])
        instance = projector(dsn, driver, consumer="atomic#g1", partitions=1)
        with instance:
            before = cursor(dsn, "atomic#g1")

            def boom(*_: object, **__: object) -> int:
                raise RuntimeError("neo4j is down")

            monkeypatch.setattr(graph, "apply_ops", boom)
            with pytest.raises(RuntimeError):
                instance.round()
            assert cursor(dsn, "atomic#g1") == before
        monkeypatch.undo()
        project_all(dsn, driver, consumer="atomic#g1")
        assert cursor(dsn, "atomic#g1") > before


def test_one_delta_per_revision_that_validates_against_the_contract(
    database: tuple[str, list[str]],
) -> None:
    dsn, jobs = database
    with graph_driver() as driver:
        ingest(dsn, jobs[5], assets=[domain("dns:delta.test")])
        project_all(dsn, driver, consumer="delta#g1")
        deltas = outbox(dsn, DELTA)
        assert deltas, "the projector must publish a knowledge.delta.v2 for the revision"
        revisions = [str(entry["dedup_key"]) for entry in deltas]
        assert len(set(revisions)) == len(deltas), "one delta per revision, dedup key = revision"
        for entry in deltas:
            validation.validate("events/knowledge.delta.v2.schema.json", entry["payload"])
            assert entry["payload"]["changed_entities"]
            for entity in entry["payload"]["changed_entities"]:
                assert entity["entity_type"] in {
                    "asset",
                    "observation",
                    "relationship",
                    "finding",
                    "hypothesis",
                }

        before = len(deltas)
        project_all(dsn, driver, consumer="delta#g1")
        assert len(outbox(dsn, DELTA)) == before


def test_a_revision_split_across_batches_is_not_published_half_done(
    database: tuple[str, list[str]],
) -> None:
    """Batch size 1 and a two-event revision: the delta waits for the whole revision."""
    dsn, jobs = database
    with graph_driver() as driver, connect(dsn) as connection:
        keys = ("dns:split-a.test", "dns:split-b.test")
        with connection.transaction():
            revision = int(
                row(
                    connection,
                    "INSERT INTO graph_revision (campaign_id, causal_job_id) VALUES (%s, %s)"
                    " RETURNING revision",
                    (CAMPAIGN_ID, jobs[0]),
                )["revision"]
            )
            for index, key in enumerate(keys):
                asset_id = str(uuid7())
                connection.execute(
                    "INSERT INTO asset (asset_id, canonical_key, kind, first_seen, last_seen,"
                    " normalization_version)"
                    " VALUES (%s, %s, 'domain', now(), now(), 'aegis-norm/1')",
                    (asset_id, key),
                )
                connection.execute(
                    "INSERT INTO asset_campaign (asset_id, campaign_id, first_seen)"
                    " VALUES (%s, %s, now())",
                    (asset_id, CAMPAIGN_ID),
                )
                connection.execute(
                    "INSERT INTO outbox_event (event_id, type, producer, dedup_key, campaign_id,"
                    " payload, trace) VALUES (%s, %s, 'M27', %s, %s, %s, '{}')",
                    (
                        str(uuid7()),
                        ASSET_EVENT,
                        f"split-{index}:{revision}",
                        CAMPAIGN_ID,
                        Jsonb(
                            {
                                "asset_id": asset_id,
                                "canonical_key": key,
                                "kind": "domain",
                                "revision": revision,
                                "causal_job_id": jobs[0],
                                "campaign_id": CAMPAIGN_ID,
                                "discovered_from": [],
                                "first_seen": "2026-11-24T10:00:00Z",
                            }
                        ),
                    ),
                )
        instance = projector(dsn, driver, consumer="split#g1", partitions=1, batch=1)
        with instance:
            first = instance.round()
            assert first.events == 1
            assert outbox(dsn, DELTA) == [], "a half-applied revision must not publish its delta"
            instance.run(drain_rounds=3, timeout=120)
        deltas = outbox(dsn, DELTA)
        assert len(deltas) == 1
        payload = deltas[0]["payload"]
        assert payload["revision"] == revision
        assert len(payload["changed_entities"]) == 2
        assert payload["truncated"] is False
        assert assert_deltas_satisfy_contract(dsn) >= 1


def test_a_revision_larger_than_the_delta_window_is_published_truncated_once(
    database: tuple[str, list[str]],
) -> None:
    """A read cut inside a revision must close it (`truncated=true`), not starve the emitter."""
    dsn, jobs = database
    with graph_driver() as driver, connect(dsn) as connection:
        keys = [f"dns:big{index}.test" for index in range(6)]
        with connection.transaction():
            revision = int(
                row(
                    connection,
                    "INSERT INTO graph_revision (campaign_id, causal_job_id) VALUES (%s, %s)"
                    " RETURNING revision",
                    (CAMPAIGN_ID, jobs[0]),
                )["revision"]
            )
            for index, key in enumerate(keys):
                asset_id = str(uuid7())
                connection.execute(
                    "INSERT INTO asset (asset_id, canonical_key, kind, first_seen, last_seen,"
                    " normalization_version)"
                    " VALUES (%s, %s, 'domain', now(), now(), 'aegis-norm/1')",
                    (asset_id, key),
                )
                connection.execute(
                    "INSERT INTO asset_campaign (asset_id, campaign_id, first_seen)"
                    " VALUES (%s, %s, now())",
                    (asset_id, CAMPAIGN_ID),
                )
                connection.execute(
                    "INSERT INTO outbox_event (event_id, type, producer, dedup_key, campaign_id,"
                    " payload, trace) VALUES (%s, %s, 'M27', %s, %s, %s, '{}')",
                    (
                        str(uuid7()),
                        ASSET_EVENT,
                        f"big-{index}:{revision}",
                        CAMPAIGN_ID,
                        Jsonb(
                            {
                                "asset_id": asset_id,
                                "canonical_key": key,
                                "kind": "domain",
                                "revision": revision,
                                "causal_job_id": jobs[0],
                                "campaign_id": CAMPAIGN_ID,
                                "discovered_from": [],
                                "first_seen": "2026-11-24T10:00:00Z",
                            }
                        ),
                    ),
                )
        instance = Projector(
            dsn,
            driver,
            ProjectorConfig(
                consumer="bigdelta#g1",
                batch=3,
                partitions=1,
                poll_seconds=0.001,
                delta_batch=2,
            ),
        )
        with instance:
            instance.run(drain_rounds=4, timeout=120)
        deltas = [entry for entry in outbox(dsn, DELTA) if entry["payload"]["revision"] == revision]
        assert len(deltas) == 1, "one delta per revision, even when the window cuts it"
        assert deltas[0]["payload"]["truncated"] is True
        assert 0 < len(deltas[0]["payload"]["changed_entities"]) <= 2
        assert cursor(dsn, "bigdelta#g1#delta") >= 2
        assert assert_deltas_satisfy_contract(dsn) >= 1


def test_rebuild_under_a_new_generation_reproduces_the_original(
    database: tuple[str, list[str]],
) -> None:
    dsn, jobs = database
    with graph_driver() as driver, connect(dsn) as connection:
        ingest(dsn, jobs[0], assets=[domain("dns:rebuild-a.test")])
        ingest(
            dsn,
            jobs[1],
            assets=[
                {
                    "kind": "domain",
                    "canonical_key": "dns:rebuild-b.test",
                    "discovered_from": ["dns:rebuild-a.test"],
                }
            ],
        )
        first = project_all(dsn, driver, consumer="m23-projector#gtest1", partitions=2)
        original = graph.snapshot(driver)
        original_cursor = cursor(dsn, "m23-projector#gtest1")
        assert first.events_applied > 0

        wipe_graph(driver)
        rebuilt = project_all(dsn, driver, consumer="m23-projector#gtest2", partitions=4)
        assert graph.snapshot(driver) == original
        # Rebuild output (the second generation re-reads every event) still satisfies the
        # contract bundle, and re-emitting a revision's delta does not duplicate it.
        assert assert_deltas_satisfy_contract(dsn) >= 1
        assert len(outbox(dsn, DELTA)) == len(
            {str(entry["dedup_key"]) for entry in outbox(dsn, DELTA)}
        )
        assert rebuilt.events_applied == first.events_applied
        assert cursor(dsn, "m23-projector#gtest1") == original_cursor

        # PostgreSQL reconciliation: the projection covers exactly the assets and the edges of the
        # relationship types the events describe, not one node more or less.
        assets = int(row(connection, "SELECT count(*) AS n FROM asset")["n"])
        relationships = int(
            row(
                connection,
                "SELECT count(*) AS n FROM relationship WHERE type = ANY(%s::text[])",
                (list(RELATIONSHIP_TYPES),),
            )["n"]
        )
        edges = [
            edge
            for edge in graph.snapshot(driver)["edges"].values()
            if edge["type"] in RELATIONSHIP_TYPES
        ]
        assert len(analytic_assets(driver)) == assets
        assert len(edges) == relationships


def test_the_lease_is_exclusive_and_the_fence_is_enforced(
    database: tuple[str, list[str]],
) -> None:
    dsn, _ = database
    with graph_driver() as driver:
        first = projector(dsn, driver, consumer="lease#g1", partitions=1)
        first.start()
        with pytest.raises(ProjectorBusy):
            second = Projector(
                dsn,
                driver,
                ProjectorConfig(
                    consumer="lease#g1", holder="another", partitions=1, poll_seconds=0.001
                ),
            )
            second.start()
        fence = first._fence
        assert fence is not None
        with connect(dsn) as connection, pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
            connection.execute(
                "SELECT aegis.consumer_advance('lease#g1', 0, 'm23-projector', %s)", (fence - 1,)
            )
        first.close()


def test_a_wipe_without_a_new_generation_replays_nothing(
    database: tuple[str, list[str]],
) -> None:
    """The graph is a projection: a wipe needs a new generation, not a cursor reset."""
    dsn, jobs = database
    with graph_driver() as driver:
        ingest(dsn, jobs[2], assets=[domain("dns:wipe.test")])
        project_all(dsn, driver, consumer="wipe#g1")
        assert analytic_assets(driver)
        wipe_graph(driver)
        stats = project_all(dsn, driver, consumer="wipe#g1")
        assert stats.events_applied == 0
        assert analytic_assets(driver) == {}
        stats = project_all(dsn, driver, consumer="wipe#g1-rebuilt")
        assert stats.events_applied > 0
        assert analytic_assets(driver)


def test_a_non_graph_event_only_moves_the_cursor(database: tuple[str, list[str]]) -> None:
    dsn, jobs = database
    with graph_driver() as driver, connect(dsn) as connection:
        ingest(dsn, jobs[3], assets=[domain("dns:noop.test")])
        with connection.transaction():
            revision = int(
                row(
                    connection,
                    "INSERT INTO graph_revision (campaign_id, causal_job_id) VALUES (%s, %s)"
                    " RETURNING revision",
                    (CAMPAIGN_ID, jobs[3]),
                )["revision"]
            )
            connection.execute(
                "INSERT INTO outbox_event (event_id, type, producer, dedup_key, campaign_id,"
                " payload, trace) VALUES (%s, 'job.started.v2', 'M05', %s, %s, %s, '{}')",
                (
                    str(uuid7()),
                    f"job-started-{revision}",
                    CAMPAIGN_ID,
                    Jsonb({"job_id": jobs[3], "campaign_id": CAMPAIGN_ID, "attempt": 1}),
                ),
            )
        target = int(row(connection, "SELECT max(seq) AS n FROM outbox_event")["n"])
        stats = project_all(dsn, driver, consumer="noop#g1")
        assert stats.events_applied >= 2  # the asset event and the job.started.v2 one
        # The projector's own knowledge.delta.v2 rows get their own (higher) sequences, so the
        # cursor ends at or beyond the job event, never before it.
        assert cursor(dsn, "noop#g1") >= target


def test_emit_deltas_is_a_no_op_when_every_revision_is_published(
    database: tuple[str, list[str]],
) -> None:
    dsn, jobs = database
    with graph_driver() as driver:
        ingest(dsn, jobs[4], assets=[domain("dns:caught.test")])
        project_all(dsn, driver, consumer="caught#g1")
        with connect(dsn) as connection:
            applied = cursor(dsn, "caught#g1")
            watermark = pg.read_watermark(connection)
            # The projector that just ran still holds a live lease; reuse its fence (a second
            # holder could not take the lease, which `test_the_lease_is_exclusive...` asserts).
            fence = int(
                row(
                    connection,
                    "SELECT fence FROM outbox_dispatcher WHERE name = 'm23-projector'"
                    " AND leased_until > now()",
                )["fence"]
            )
            assert (
                pg.emit_deltas(
                    connection,
                    consumer="caught#g1",
                    applied_cursor=applied,
                    watermark=watermark,
                    dispatcher="m23-projector",
                    fence=fence,
                )
                == 0
            )


def test_a_projector_run_reports_its_counters(database: tuple[str, list[str]]) -> None:
    dsn, jobs = database
    with graph_driver() as driver:
        ingest(dsn, jobs[5], assets=[domain("dns:counters.test")])
        started = time.monotonic()
        stats = project_all(dsn, driver, consumer="counters#g1")
        assert stats.batches >= 1
        assert stats.checkpoints == stats.batches
        assert stats.ops_applied >= 1
        assert stats.deltas_emitted >= 1
        assert stats.started_at is not None and stats.finished_at is not None
        assert stats.finished_at - stats.started_at <= time.monotonic() - started
        assert stats.error is None


def test_the_rebuild_command_replays_under_a_new_generation(
    database: tuple[str, list[str]],
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`rebuild` writes a snapshot, wipes, replays with `m23-projector#g<N+1>`, and compares."""
    from aegis.m23_graph import cli

    dsn, jobs = database
    monkeypatch.setenv("AEGIS_PG_DSN", dsn)
    graph_uri, graph_password = graph_support.ensure_test_graph()
    monkeypatch.setenv("AEGIS_NEO4J_URI", graph_uri)
    monkeypatch.setenv("AEGIS_NEO4J_PASSWORD", graph_password)
    with graph_driver() as driver:
        ingest(dsn, jobs[0], assets=[domain("dns:cli.test")])
        project_all(dsn, driver, consumer="m23-projector#g7", partitions=2)
        original = tmp_path / "graph.json"
        assert (
            cli.main(
                [
                    "rebuild",
                    "--snapshot-out",
                    str(original),
                    "--compare-with",
                    str(original),
                    "--partitions",
                    "2",
                ]
            )
            == 0
        )
        assert original.exists()
        assert cursor(dsn, "m23-projector#g8") >= 1
        assert cursor(dsn, "m23-projector#g7") >= 1
        assets_after = analytic_assets(driver)
        assert assets_after, "the rebuild must repopulate the graph"
        assert cli.main(["status"]) == 0
