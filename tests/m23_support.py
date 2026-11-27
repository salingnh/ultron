"""Fixtures for the M23 projector/query tests (G1.4b): a throwaway database and graph.

Two external services are needed, and both are **throwaway**: a PostgreSQL 18 the test may
create and drop databases on (`AEGIS_TEST_PG_DSN`, the same variable the other DB tests use) and
a Neo4j 5.26 that the test may wipe. The graph is not taken from whatever `AEGIS_TEST_NEO4J_URI`
happens to point at: `tests/graph_support.ensure_test_graph` accepts only a container carrying the
`aegis.test.graph=1` label and otherwise starts its own, so a run can never wipe a shared graph
(the incident that produced that guard is described there).

A wipe is `graph.wipe(driver, context=graph.RebuildContext(<generation>))`: the destructive step
belongs to a rebuild, and nothing here reaches it by accident.
"""

from __future__ import annotations

import hashlib
import os
import shutil
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from typing import Any, cast

import psycopg
import pytest
from neo4j import Driver
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from aegis.m23_graph import graph
from aegis.m23_graph.projector import Projector, ProjectorConfig
from aegis.m27_ingestion.service import IngestionService
from aegis.migrations import apply_contract_migrations
from tests import graph_support
from tests.pg import throwaway_database
from tests.support_ingestion import (
    CAMPAIGN_ID,
    SEED_ASSET_KEY,
    SEED_ID,
    asset,
    build_envelope,
    observation,
    relationship,
    seed_campaign,
    seed_evidence,
    seed_jobs,
)

NEO4J_URI_ENV = graph_support.NEO4J_URI_ENV
NEO4J_PASSWORD_ENV = graph_support.NEO4J_PASSWORD_ENV
PG_DSN_ENV = "AEGIS_TEST_PG_DSN"
#: The generation a test wipe pretends to rebuild into; it never reaches production data.
TEST_GENERATION = "m23-projector#g-test"

requires_neo4j = pytest.mark.skipif(
    not os.environ.get(NEO4J_URI_ENV) and shutil.which("podman") is None,
    reason=f"set {NEO4J_URI_ENV} (+ {NEO4J_PASSWORD_ENV}) or install podman so the harness can "
    "start a throwaway Neo4j 5.26",
)
requires_pipeline = pytest.mark.skipif(
    not os.environ.get(PG_DSN_ENV)
    or (not os.environ.get(NEO4J_URI_ENV) and shutil.which("podman") is None),
    reason=f"set {PG_DSN_ENV} and either {NEO4J_URI_ENV} (+ {NEO4J_PASSWORD_ENV}) or podman",
)

RAW_EVIDENCE = b'{"A": "192.0.2.10"}\n'
EVIDENCE_SHA = hashlib.sha256(RAW_EVIDENCE).hexdigest()


def evidence_entry(job_id: str) -> dict[str, Any]:
    return {
        "local_ref": "raw",
        "sha256": EVIDENCE_SHA,
        "uri": f"s3://evidence/{CAMPAIGN_ID}/{job_id}/{EVIDENCE_SHA}",
        "size_bytes": len(RAW_EVIDENCE),
        "media_type": "application/json",
        "classification": "INTERNAL",
        "kind": "raw_output",
    }


@contextmanager
def graph_driver() -> Iterator[Driver]:
    """A driver on the harness-owned Neo4j, wiped before and after the test.

    `ensure_test_graph` runs first and raises `SharedGraphRefused` when the configured Neo4j is not
    a test resource, so the wipe below can never reach a shared graph.
    """
    uri, password = graph_support.ensure_test_graph()
    driver = graph.connect(uri, "neo4j", password)
    wipe_graph(driver)
    try:
        yield driver
    finally:
        wipe_graph(driver)
        driver.close()


def wipe_graph(driver: Driver) -> int:
    """The test-side wipe: explicit rebuild context, never a bare destruct call."""
    return graph.wipe(driver, context=graph.RebuildContext(TEST_GENERATION))


@contextmanager
def pipeline_database(jobs: int = 3) -> Iterator[tuple[str, list[str]]]:
    """A migrated throwaway database with one campaign and `jobs` approved jobs."""
    with throwaway_database() as dsn, psycopg.connect(dsn, autocommit=True) as connection:
        apply_contract_migrations(connection)
        connection.execute("SET search_path = aegis, public")
        seed_campaign(connection)
        yield dsn, seed_jobs(connection, jobs)


def connect(dsn: str) -> psycopg.Connection[dict[str, Any]]:
    connection: psycopg.Connection[dict[str, Any]] = psycopg.connect(
        dsn, autocommit=True, row_factory=dict_row
    )
    connection.execute("SET search_path = aegis, public")
    return connection


def ingest(
    dsn: str,
    job_id: str,
    *,
    assets: Sequence[dict[str, Any]],
    observations: Sequence[dict[str, Any]] = (),
    relationships: Sequence[dict[str, Any]] = (),
    findings: Sequence[dict[str, Any]] = (),
    coverage: Sequence[str] = (),
    event_id: str | None = None,
) -> Any:
    """One M27 envelope, exactly as the collector posts it.

    The raw evidence row M28 would have written first is seeded for the job, so the G3 evidence
    gate accepts the observation's `{"local_ref": "raw"}` instead of quarantining it.
    """
    with connect(dsn) as connection:
        seed_evidence(  # same rows M28 writes before the collector posts the envelope
            cast(psycopg.Connection[tuple[object, ...]], connection),
            job_id,
            sha256=EVIDENCE_SHA,
            size_bytes=len(RAW_EVIDENCE),
        )
    return IngestionService.from_dsn(dsn).submit_payload(
        build_envelope(
            job_id,
            event_id=event_id,
            assets=assets,
            observations=observations,
            relationships=relationships,
            findings=findings,
            coverage=coverage,
            evidence=[evidence_entry(job_id)],
        )
    )


def outbox(dsn: str, event_type: str | None = None) -> list[dict[str, Any]]:
    with connect(dsn) as connection:
        if event_type is None:
            rows = connection.execute(
                "SELECT seq, type, dedup_key, campaign_id, payload FROM outbox_event ORDER BY seq"
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT seq, type, dedup_key, campaign_id, payload FROM outbox_event"
                " WHERE type = %s ORDER BY seq",
                (event_type,),
            ).fetchall()
    return [dict(row.items()) for row in rows]


def cursor(dsn: str, consumer: str) -> int:
    with connect(dsn) as connection:
        row = connection.execute(
            "SELECT last_seq FROM consumer_cursor WHERE consumer = %s", (consumer,)
        ).fetchone()
    return 0 if row is None else int(row["last_seq"])


def projector(
    dsn: str,
    driver: Driver,
    *,
    consumer: str = "m23-projector#test",
    partitions: int = 2,
    batch: int = 500,
    deltas: bool = True,
) -> Projector:
    return Projector(
        dsn,
        driver,
        ProjectorConfig(
            consumer=consumer,
            batch=batch,
            partitions=partitions,
            poll_seconds=0.001,
            emit_deltas=deltas,
        ),
    )


def project_all(
    dsn: str,
    driver: Driver,
    *,
    consumer: str = "m23-projector#test",
    partitions: int = 2,
    batch: int = 500,
    deltas: bool = True,
    timeout: float = 120.0,
) -> Any:
    """Run a fresh consumer from its cursor until the outbox is drained."""
    projector_instance = projector(
        dsn, driver, consumer=consumer, partitions=partitions, batch=batch, deltas=deltas
    )
    with projector_instance:
        return projector_instance.run(drain_rounds=3, timeout=timeout)


def two_campaign_subdomains(job_id: str) -> dict[str, Any]:
    """A small envelope: a root asset, a subdomain discovered from it and one observation."""
    return {
        "assets": [
            asset(SEED_ASSET_KEY, "domain"),
            asset("dns:www.internal.example", "domain", discovered_from=[SEED_ASSET_KEY]),
            asset("ip:192.0.2.10", "ip"),
        ],
        "observations": [
            observation(
                "dns:www.internal.example",
                "dns.record",
                {"type": "A", "value": "192.0.2.10", "ttl": 300},
                evidence_refs=[{"local_ref": "raw"}],
            )
        ],
        "relationships": [
            relationship("SUBDOMAIN_OF", "dns:www.internal.example", SEED_ASSET_KEY),
            relationship("RESOLVES_TO", "dns:www.internal.example", "ip:192.0.2.10"),
        ],
        "coverage": ["dns:www.internal.example", "ip:192.0.2.10"],
    }


def assert_deltas_satisfy_contract(dsn: str) -> int:
    """Validate **every** `knowledge.delta.v2` the projector emitted with the JSON-Schema hook.

    The runtime validates with the generated DTO (cheap enough for the hot path, see the report),
    and Pydantic ignores the semantic `aegis-*` formats; this is the check that the emitted payload
    still satisfies the contract bundle itself (`aegis.validation` loads `contracts/validation.py`,
    so `aegis-canonical-key`/`aegis-id` formats are really checked). It is called on the output of
    the real projector runs (e2e, delta split, rebuild), not on hand-built fixtures.
    """
    from aegis import validation

    rows = outbox(dsn, "knowledge.delta.v2")
    for entry in rows:
        validation.validate("events/knowledge.delta.v2.schema.json", entry["payload"])
    return len(rows)


def jsonb(value: Mapping[str, Any]) -> Jsonb:
    return Jsonb(dict(value))


__all__ = [
    "CAMPAIGN_ID",
    "EVIDENCE_SHA",
    "NEO4J_PASSWORD_ENV",
    "NEO4J_URI_ENV",
    "PG_DSN_ENV",
    "RAW_EVIDENCE",
    "SEED_ID",
    "assert_deltas_satisfy_contract",
    "connect",
    "cursor",
    "evidence_entry",
    "graph_driver",
    "ingest",
    "jsonb",
    "outbox",
    "pipeline_database",
    "project_all",
    "projector",
    "requires_neo4j",
    "requires_pipeline",
    "two_campaign_subdomains",
]
