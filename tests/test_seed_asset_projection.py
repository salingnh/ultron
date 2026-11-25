"""A campaign seed reaches the graph (G1 final walkthrough: `dns:internal.example` was missing).

`contracts/graph/model.md` makes the outbox the only source of the projection: M23 reads events, not
`asset`/`campaign_target`. M01 creates the campaign's seed assets (G1.5c: "campaign seeds were not
assets") and, before this test existed, wrote the asset rows **without** an event, so a seed whose
only appearance is the campaign row never reached Neo4j. The lab seed looked fine by luck: Subfinder
also observed it, so an edge named it.

The contract's event now describes a seed (`asset.discovered.v2`: `revision` 0, no
`causal_job_id`), M01 publishes it in the campaign transaction, and this test compares the **full**
sets: every asset PostgreSQL links to the campaign is a node in the graph, and nothing else is.
"""

from __future__ import annotations

from typing import Any

import psycopg
from psycopg.rows import dict_row

from aegis import validation
from aegis.m01_campaign.campaigns import create_campaign
from aegis.migrations import apply_contract_migrations
from tests.m23_support import graph_driver, project_all, requires_pipeline
from tests.pg import throwaway_database

CAMPAIGN: dict[str, Any] = {
    "name": "Seed only",
    "objective": "A campaign whose only assets are its seed targets",
    "targets": {"domains": ["seed-only.example"], "ips": ["10.20.30.40"], "keywords": ["acme"]},
    "policy": {"max_parallel_jobs": 2, "max_duration_hours": 24},
}
ACTOR = {"kind": "operator", "id": "op-seed-test"}
EXPECTED = {"dns:seed-only.example", "ip:10.20.30.40"}


def _created_campaign(dsn: str) -> str:
    # The API's request connection is a dict-row one (m26_api.db); create_campaign reads by name.
    with psycopg.connect(dsn, row_factory=dict_row) as connection:
        created = create_campaign(connection, body=CAMPAIGN, actor=ACTOR, trace_id="a" * 32)
        connection.commit()
    return created.campaign_id


def _pg_assets(dsn: str, campaign_id: str) -> set[str]:
    with psycopg.connect(dsn, row_factory=dict_row) as connection:
        rows = connection.execute(
            "SELECT a.canonical_key FROM aegis.asset a"
            " JOIN aegis.asset_campaign ac ON ac.asset_id = a.asset_id"
            " WHERE ac.campaign_id = %s",
            (campaign_id,),
        ).fetchall()
    return {str(row["canonical_key"]) for row in rows}


def _graph_nodes(driver: Any, campaign_id: str) -> list[dict[str, Any]]:
    with driver.session() as session:
        result = session.run(
            "MATCH (a:Asset) WHERE $campaign IN coalesce(a.campaign_ids, [])"
            " RETURN a.canonical_key AS canonical_key, a.pg_revision AS pg_revision"
            " ORDER BY a.canonical_key",
            campaign=campaign_id,
        )
        return [dict(record) for record in result]


# A database test like the other projector ones: the throwaway PostgreSQL (AEGIS_TEST_PG_DSN) and a
# harness-owned Neo4j are required, so an environment without them skips here instead of failing
# inside the fixture with KeyError('AEGIS_TEST_PG_DSN'). AEGIS_NO_SKIPS=1 (CI, scripts/ci/
# python-gate.sh) turns that skip into a failure, which is the loud behaviour a gate wants.
@requires_pipeline
def test_a_seed_only_campaign_has_the_same_assets_in_postgres_and_neo4j() -> None:
    with throwaway_database() as dsn, graph_driver() as driver:
        with psycopg.connect(dsn, autocommit=True) as connection:
            apply_contract_migrations(connection)
        campaign_id = _created_campaign(dsn)

        # The event is written in the campaign's transaction, one per new seed (the keyword seed has
        # no identity and no asset).
        with psycopg.connect(dsn, row_factory=dict_row) as connection:
            events = connection.execute(
                "SELECT payload FROM aegis.outbox_event"
                " WHERE campaign_id = %s AND type = 'asset.discovered.v2' ORDER BY dedup_key",
                (campaign_id,),
            ).fetchall()
        assert len(events) == 2, events
        for event in events:
            payload = event["payload"]
            assert payload["revision"] == 0
            assert "causal_job_id" not in payload
            assert payload["campaign_id"] == campaign_id

        project_all(dsn, driver, consumer="seed-only#g1")

        nodes = _graph_nodes(driver, campaign_id)
        assert (
            {str(node["canonical_key"]) for node in nodes}
            == _pg_assets(dsn, campaign_id)
            == EXPECTED
        )
        assert all(int(node["pg_revision"] or 0) == 0 for node in nodes), nodes


def test_an_m27_asset_event_still_carries_its_job_and_revision() -> None:
    """The seed shape is additive: the producer that reports a job keeps its fields.

    Pure schema check: it needs no database and no graph, so it runs in every environment.
    """
    payload = {
        "asset_id": "01a20c00-0000-7000-8000-000000000001",
        "canonical_key": "dns:seed-only.example",
        "kind": "domain",
        "revision": 0,
        "campaign_id": "01a20c00-0000-7000-8000-000000000002",
        "discovered_from": [],
        "first_seen": "2026-11-24T00:00:00Z",
    }
    validation.validate("events/asset.discovered.v2.schema.json", payload)
    validation.validate(
        "events/asset.discovered.v2.schema.json",
        {
            **payload,
            "revision": 7,
            "causal_job_id": "01a20c00-0000-7000-8000-000000000003",
        },
    )
