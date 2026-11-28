"""One asset in many campaigns (G2 P0): the projected node must stay writable.

`contracts/graph/projector-upserts.cypher` statement 1 appends one campaign id per projection and
nothing bounds that list: an asset seen by many campaigns is normal (the 24 h soak put one lab zone
into ~500). A RANGE index on that list property used to make Neo4j refuse the write once the list
exceeded its index key size ("Property value is too large to index ... property size: 8181",
`g1-final/.local/m23.log`, 2026-11-25), the projector round failed and the projector process died;
nothing restarted it. No query used the index: the campaign filter is an *element membership* test
(`$campaign_id IN coalesce(a.campaign_ids, [])`, `m23_graph/queries.py`), which PROFILE answers with
`NodeByLabelScan` + `Filter`; a RANGE index only serves comparing the whole list value.

So the committed Cypher drops the retired index (also on an existing database) and these tests pin
both halves: the drop is idempotent through the real constraints path, and 500 campaign writes to
one asset succeed. Without the drop the second test fails with `ExecutionFailed`; that is the
regression this file exists for.
"""

from __future__ import annotations

from aegis.m23_graph import graph
from aegis.m23_graph.contract import asset_upsert
from aegis.m23_graph.models import CypherOp
from aegis.m23_graph.plan import PHASE_ASSET
from tests.m23_support import graph_driver, requires_neo4j

pytestmark = requires_neo4j

#: Comfortably past the ~240 campaign ids (8 KiB) that broke the index key on 2026-11-25.
CAMPAIGNS = 500
ASSET_ID = "01a20000-0000-7000-8000-000000000001"
CANONICAL_KEY = "dns:many-campaigns.example"


def _asset_op(campaign_id: str) -> CypherOp:
    """Statement 1 for `CANONICAL_KEY`, as `plan._asset_op` builds it (one per campaign)."""
    return CypherOp(
        statement=asset_upsert("domain"),
        parameters={
            "canonical_key": CANONICAL_KEY,
            "asset_id": ASSET_ID,
            "kind": "domain",
            "first_seen": "2026-11-25T00:00:00+00:00",
            "last_seen": "2026-11-25T00:00:00+00:00",
            "campaign_id": campaign_id,
            "revision": 1,
        },
        partition=0,
        phase=PHASE_ASSET,
        entity="asset",
    )


def _indexes(driver: object) -> dict[str, dict[str, object]]:
    with driver.session() as session:  # type: ignore[attr-defined]
        return {
            record["name"]: dict(record)
            for record in session.run(
                "SHOW INDEXES YIELD name, type, labelsOrTypes, properties, state RETURN *"
            )
        }


def test_install_constraints_drops_the_retired_campaigns_index() -> None:
    """A database that still has `asset_campaigns` loses it on the next projector start."""
    with graph_driver() as driver:
        with driver.session() as session:
            session.run(
                "CREATE INDEX asset_campaigns IF NOT EXISTS FOR (a:Asset) ON (a.campaign_ids)"
            ).consume()
        assert "asset_campaigns" in _indexes(driver)

        graph.install_constraints(driver)
        assert "asset_campaigns" not in _indexes(driver)

        # Idempotent: the projector applies the same file on every start.
        graph.install_constraints(driver)
        indexes = _indexes(driver)
        assert "asset_campaigns" not in indexes
        # The indexes that do have users survive the drop.
        assert indexes["asset_kind"]["type"] == "RANGE"
        assert indexes["asset_key"]["type"] == "RANGE"


def test_one_asset_can_be_projected_into_many_campaigns() -> None:
    """500 memberships in one batched round: the node is written, not rejected by an index key."""
    campaign_ids = [f"01a20000-0000-7000-8000-{index:012d}" for index in range(CAMPAIGNS)]
    with graph_driver() as driver:
        graph.install_constraints(driver)
        # One statement text and 500 rows: `apply_ops` batches exactly as the projector does.
        attempts = graph.apply_ops(driver, [_asset_op(campaign) for campaign in campaign_ids])
        assert attempts == 1

        with driver.session() as session:
            record = session.run(
                "MATCH (a:Asset {canonical_key: $key}) RETURN a.campaign_ids AS ids",
                key=CANONICAL_KEY,
            ).single()
        assert record is not None
        assert len(record["ids"]) == CAMPAIGNS
        assert set(record["ids"]) == set(campaign_ids)

        # A replay adds nothing (the statement is idempotent per campaign id).
        graph.apply_ops(driver, [_asset_op(campaign) for campaign in campaign_ids])
        with driver.session() as session:
            count = session.run(
                "MATCH (a:Asset {canonical_key: $key}) RETURN size(a.campaign_ids) AS ids",
                key=CANONICAL_KEY,
            ).single()
        assert count is not None and count["ids"] == CAMPAIGNS
