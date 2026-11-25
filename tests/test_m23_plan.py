"""Planning one outbox batch: partitions, phases, dedup and the checkpoint facts (G1.4b).

Pure tests - no database, no Neo4j. They pin the two properties the projector's correctness rests
on: an asset's operations always land in one partition in publication order (per-key order), and
every `:Asset` upsert of a batch is in an earlier phase than the edge that `MATCH`es it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from aegis.m23_graph import contract
from aegis.m23_graph.models import (
    ASSET_EVENT,
    FINDING_EVENT,
    OBSERVATION_EVENT,
    AssetSnapshot,
    EvidenceSnapshot,
    FindingSnapshot,
    ObservationSnapshot,
    OutboxEvent,
    RelationshipSnapshot,
)
from aegis.m23_graph.plan import PHASE_ASSET, PHASE_GRAPH, partition_of, plan_round

MOMENT = datetime(2026, 11, 24, 10, 0, tzinfo=UTC)
CAMPAIGN_A = "01900000-0000-7000-8000-0000000c0001"
CAMPAIGN_B = "01900000-0000-7000-8000-0000000c0002"
JOB = "01900000-0000-7000-8000-0000000c0003"


def asset_event(asset_id: str, key: str, revision: int, *, seq: int | None = None) -> OutboxEvent:
    return OutboxEvent(
        seq=seq if seq is not None else revision,
        event_id=f"ev-{revision}-{asset_id}",
        type=ASSET_EVENT,
        dedup_key=f"{asset_id}:{revision}",
        campaign_id=CAMPAIGN_A,
        payload={
            "asset_id": asset_id,
            "canonical_key": key,
            "kind": "domain",
            "revision": revision,
            "causal_job_id": JOB,
            "campaign_id": CAMPAIGN_A,
            "discovered_from": [],
            "first_seen": MOMENT.isoformat(),
        },
        trace={"trace_id": "0123456789abcdef0123456789abcdef"},
        occurred_at=MOMENT,
    )


def observation_event(observation_id: str, subject_key: str, *, seq: int = 1) -> OutboxEvent:
    return OutboxEvent(
        seq=seq,
        event_id=f"obs-{observation_id}",
        type=OBSERVATION_EVENT,
        dedup_key=observation_id,
        campaign_id=CAMPAIGN_A,
        payload={
            "observation_id": observation_id,
            "subject_id": "asset-1",
            "subject_key": subject_key,
            "predicate": "dns.record",
            "new_value": {"type": "A"},
            "causal_job_id": JOB,
            "campaign_id": CAMPAIGN_A,
            "observed_at": MOMENT.isoformat(),
        },
        trace={},
        occurred_at=MOMENT,
    )


def snapshot(
    asset_id: str, key: str, *, campaigns: tuple[str, ...] = (CAMPAIGN_A,)
) -> AssetSnapshot:
    return AssetSnapshot(
        asset_id=asset_id,
        canonical_key=key,
        kind="domain",
        first_seen=MOMENT,
        last_seen=MOMENT,
        owner=None,
        exposure=None,
        criticality=None,
        campaign_ids=campaigns,
        first_job_id=None,
    )


def edge(
    relationship_id: str, from_id: str, to_id: str, *, edge_type: str = "SUBDOMAIN_OF"
) -> RelationshipSnapshot:
    return RelationshipSnapshot(
        relationship_id=relationship_id,
        type=edge_type,
        from_asset_id=from_id,
        to_asset_id=to_id,
        observed_at=MOMENT,
        valid_from=MOMENT,
        valid_to=None,
        source_job_id=JOB,
        confidence=0.9,
        campaign_id=CAMPAIGN_A,
    )


def finding(finding_id: str, asset_id: str) -> FindingSnapshot:
    return FindingSnapshot(
        finding_id=finding_id,
        asset_id=asset_id,
        fingerprint="a" * 64,
        rule_id="rule-1",
        title="fixture",
        status="CANDIDATE",
        severity="LOW",
        transition_seq=1,
        confidence=0.8,
        secret_value=None,
        first_seen=MOMENT,
        first_job_id=JOB,
    )


def plan(
    batch: list[OutboxEvent],
    *,
    assets: dict[str, AssetSnapshot] | None = None,
    relationships: dict[str, tuple[RelationshipSnapshot, ...]] | None = None,
    findings: dict[str, FindingSnapshot] | None = None,
    evidence: dict[str, EvidenceSnapshot] | None = None,
    observations: dict[str, ObservationSnapshot] | None = None,
    seen: set[str] | None = None,
    partitions: int = 4,
) -> Any:
    return plan_round(
        batch,
        seen=seen or set(),
        assets=assets or {},
        relationships=relationships or {},
        findings=findings or {},
        evidence=evidence or {},
        observations=observations or {},
        partitions=partitions,
    )


def test_one_statement_per_asset_campaign_and_all_edges_of_the_asset() -> None:
    asset_id, other_id = "asset-1", "asset-2"
    planned = plan(
        [asset_event(asset_id, "dns:www.internal.example", 7)],
        assets={
            asset_id: snapshot(
                asset_id, "dns:www.internal.example", campaigns=(CAMPAIGN_A, CAMPAIGN_B)
            )
        },
        relationships={
            asset_id: (
                edge("rel-1", asset_id, other_id),
                edge("rel-2", asset_id, other_id, edge_type="DISCOVERED_FROM"),
            )
        },
    )
    assert [op.entity for op in planned.ops] == ["asset", "asset", "relationship", "relationship"]
    assert {op.parameters["campaign_id"] for op in planned.ops[:2]} == {CAMPAIGN_A, CAMPAIGN_B}
    assert {op.parameters["relationship_id"] for op in planned.ops[2:]} == {"rel-1", "rel-2"}
    assert all(op.parameters["revision"] == 7 for op in planned.ops[:2])


def test_asset_operations_are_one_phase_ahead_of_the_edges() -> None:
    asset_id = "asset-1"
    planned = plan(
        [asset_event(asset_id, "dns:www.internal.example", 1)],
        assets={asset_id: snapshot(asset_id, "dns:www.internal.example")},
        relationships={asset_id: (edge("rel-1", asset_id, "asset-2"),)},
    )
    phases = planned.phases()
    assert set(phases) == {PHASE_ASSET, PHASE_GRAPH}
    assert [op.entity for op in phases[PHASE_ASSET]] == ["asset"]
    assert [op.entity for op in phases[PHASE_GRAPH]] == ["relationship"]


def test_observation_events_checkpoint_but_write_nothing() -> None:
    planned = plan([observation_event("obs-1", "dns:www.internal.example")])
    assert planned.ops == ()
    assert planned.applied == (("obs-obs-1", "observation.changed.v2:obs-1"),)
    assert planned.last_seq == 1


def observation_snapshot(
    observation_id: str, key: str, predicate: str, value: Any, revision: int = 7
) -> ObservationSnapshot:
    return ObservationSnapshot(
        observation_id=observation_id,
        revision=revision,
        campaign_id=CAMPAIGN_A,
        predicate=predicate,
        subject_asset_id="asset-1",
        subject_key=key,
        observed_at=MOMENT,
        polarity="present",
        value=value,
        confidence=0.8,
    )


def test_a_graph_predicate_projects_its_observation_node() -> None:
    """G1.6b: `service.product` is `graph: true`, so the projector writes its :Observation node."""
    key = "service:203.0.113.10:8080/tcp"
    planned = plan(
        [observation_event("obs-2", key)],
        assets={"asset-1": snapshot("asset-1", key)},
        observations={
            "obs-2": observation_snapshot(
                "obs-2",
                key,
                "service.product",
                {
                    "product": "nginx",
                    "version": "1.29.8",
                    "cpe": "cpe:2.3:a:f5:nginx:1.29.8:*:*:*:*:*:*:*",
                },
            )
        },
    )
    nodes = [op for op in planned.ops if op.entity == "observation"]
    assert len(nodes) == 1
    assert nodes[0].statement == contract.observation_upsert()
    assert nodes[0].parameters["predicate"] == "service.product"
    assert nodes[0].parameters["subject"] == key
    assert nodes[0].parameters["confidence"] == 0.8
    assert nodes[0].parameters["revision"] == 7
    assert "nginx" in (nodes[0].parameters["value_summary"] or "")
    assert nodes[0].partition == partition_of(key, 4)
    assert nodes[0].phase == PHASE_GRAPH


def test_a_predicate_without_graph_stays_in_postgres() -> None:
    """`net.port_state` has no `graph: true`: the graph must not grow one node per port state."""
    key = "service:203.0.113.10:8080/tcp"
    planned = plan(
        [observation_event("obs-3", key)],
        assets={"asset-1": snapshot("asset-1", key)},
        observations={"obs-3": observation_snapshot("obs-3", key, "net.port_state", "open")},
    )
    assert [op.entity for op in planned.ops] == ["asset"]


def test_an_observation_without_a_snapshot_writes_no_node() -> None:
    """The row is gone (append-only, so a data bug): nothing is invented from the payload."""
    planned = plan(
        [observation_event("obs-4", "service:203.0.113.10:8080/tcp")],
        assets={"asset-1": snapshot("asset-1", "service:203.0.113.10:8080/tcp")},
        observations={},
    )
    assert [op.entity for op in planned.ops] == ["asset"]


def test_events_already_in_the_inbox_still_move_the_cursor() -> None:
    event = asset_event("asset-1", "dns:www.internal.example", 3, seq=9)
    planned = plan(
        [event],
        assets={"asset-1": snapshot("asset-1", "dns:www.internal.example")},
        seen={event.inbox_key},
    )
    assert planned.ops == ()
    assert planned.applied == ()
    assert planned.last_seq == 9


def test_the_same_asset_twice_in_a_batch_keeps_the_highest_revision() -> None:
    asset_id = "asset-1"
    planned = plan(
        [
            asset_event(asset_id, "dns:www.internal.example", 5, seq=5),
            asset_event(asset_id, "dns:www.internal.example", 9, seq=9),
        ],
        assets={asset_id: snapshot(asset_id, "dns:www.internal.example")},
    )
    asset_ops = [op for op in planned.ops if op.entity == "asset"]
    assert len(asset_ops) == 1
    assert asset_ops[0].parameters["revision"] == 9


def test_the_same_edge_twice_in_a_batch_is_applied_once() -> None:
    planned = plan(
        [
            asset_event("asset-1", "dns:a.internal.example", 1),
            asset_event("asset-2", "dns:b.internal.example", 2),
        ],
        assets={
            "asset-1": snapshot("asset-1", "dns:a.internal.example"),
            "asset-2": snapshot("asset-2", "dns:b.internal.example"),
        },
        relationships={
            "asset-1": (edge("rel-1", "asset-1", "asset-2"),),
            "asset-2": (edge("rel-1", "asset-1", "asset-2"),),
        },
    )
    assert [
        op.parameters["relationship_id"] for op in planned.ops if op.entity == "relationship"
    ] == ["rel-1"]


def test_a_partition_is_a_pure_function_of_the_key_and_holds_all_its_operations() -> None:
    keys = [f"dns:host{index}.internal.example" for index in range(50)]
    assert [partition_of(key, 8) for key in keys] == [partition_of(key, 8) for key in keys]
    assert len({partition_of(key, 8) for key in keys}) > 1

    planned = plan(
        [asset_event(f"asset-{index}", key, 1, seq=index) for index, key in enumerate(keys)],
        assets={
            f"asset-{index}": snapshot(f"asset-{index}", key) for index, key in enumerate(keys)
        },
    )
    for op in planned.ops:
        key = op.parameters["canonical_key"]
        assert op.partition == partition_of(key, 4), op.entity


def test_an_asset_and_its_edges_are_in_one_partition_whatever_the_partition_count() -> None:
    for partitions in (1, 2, 3, 8, 16):
        planned = plan(
            [asset_event("asset-1", "dns:www.internal.example", 1)],
            assets={"asset-1": snapshot("asset-1", "dns:www.internal.example")},
            relationships={"asset-1": (edge("rel-1", "asset-1", "asset-2"),)},
            partitions=partitions,
        )
        assert len({op.partition for op in planned.ops}) == 1


def test_an_unknown_asset_event_writes_nothing_instead_of_inventing_properties() -> None:
    planned = plan([asset_event("ghost", "dns:ghost.internal.example", 1)])
    assert planned.ops == ()
    assert len(planned.applied) == 1


def test_a_finding_event_applies_the_finding_statement_then_the_evidence_one() -> None:
    finding_id, evidence_id = "finding-1", "evidence-1"
    event = OutboxEvent(
        seq=1,
        event_id="ev-finding",
        type=FINDING_EVENT,
        dedup_key=f"{finding_id}:1",
        campaign_id=CAMPAIGN_A,
        payload={
            "finding_id": finding_id,
            "asset_id": "asset-1",
            "transition_seq": 1,
            "new_status": "CANDIDATE",
            "reason": "fixture",
            "changed_by": {"kind": "system", "id": "fixture"},
            "cause": "scan",
            "changed_at": MOMENT.isoformat(),
            "evidence_ref": evidence_id,
        },
        trace={},
        occurred_at=MOMENT,
    )
    planned = plan(
        [event],
        assets={"asset-1": snapshot("asset-1", "dns:www.internal.example")},
        findings={finding_id: finding(finding_id, "asset-1")},
        evidence={
            evidence_id: EvidenceSnapshot(
                evidence_id=evidence_id,
                sha256="b" * 64,
                storage_uri=f"s3://evidence/{CAMPAIGN_A}/{JOB}/{'b' * 64}",
                source_tool="fixture",
                job_id=JOB,
            )
        },
    )
    assert [op.statement for op in planned.ops] == [
        contract.finding_upsert(),
        contract.evidence_upsert(),
    ]
    assert planned.ops[0].parameters["finding_id"] == finding_id
    assert planned.ops[1].parameters["sha256"] == "b" * 64


def test_partition_count_must_be_positive() -> None:
    with pytest.raises(ValueError):
        partition_of("dns:a.internal.example", 0)


def test_an_unknown_kind_is_a_contract_gap_not_a_silent_skip() -> None:
    asset_id = "asset-1"
    broken = AssetSnapshot(
        asset_id=asset_id,
        canonical_key="dns:www.internal.example",
        kind="quantum_thing",
        first_seen=MOMENT,
        last_seen=MOMENT,
        owner=None,
        exposure=None,
        criticality=None,
        campaign_ids=(CAMPAIGN_A,),
        first_job_id=None,
    )
    with pytest.raises(contract.ContractMismatch):
        plan([asset_event(asset_id, "dns:www.internal.example", 1)], assets={asset_id: broken})


def test_datetimes_cross_the_contract_as_iso_strings() -> None:
    asset_id = "asset-1"
    planned = plan(
        [asset_event(asset_id, "dns:www.internal.example", 1)],
        assets={asset_id: snapshot(asset_id, "dns:www.internal.example")},
    )
    parameters = planned.ops[0].parameters
    assert parameters["first_seen"] == MOMENT.isoformat()
    assert parameters["last_seen"] == MOMENT.isoformat()
    assert isinstance(parameters["revision"], int)
