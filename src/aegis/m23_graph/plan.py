"""Planning one outbox batch into partitioned Neo4j work (G1.4b).

This module is pure: it turns the events of one `aegis.outbox_batch` call plus the PostgreSQL
snapshots of the entities they touch into the exact statement executions the projector runs. The
tests drive it without a database, and the projector only adds I/O and a transaction boundary.

Two properties the planner is responsible for:

* **per-key order.** Every operation of one asset (its `:Asset` node and every edge whose start is
  that asset) is hashed to one partition, and a partition is executed by one worker in plan order,
  which is publication (`seq`) order. Two events of the same asset can therefore never be applied
  concurrently or out of order, while different assets project in parallel. `pg_revision` of a
  node is "last writer wins", so a serialization bug would show up as the lower revision winning
  (tests assert the highest one).
* **two phases.** All `:Asset` upserts run before any edge/finding statement of the same batch.
  `projector-upserts.cypher` matches the other end of an edge with `MATCH (t:Asset …)`, which
  silently matches nothing when the node is not committed yet; phases remove that race while
  keeping the parallelism.

Properties are read from PostgreSQL at apply time, never from the event payload, as
`contracts/graph/model.md` requires; the payload only identifies the entity and carries `revision`.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence, Set
from typing import Any

from aegis.m23_graph import contract
from aegis.m23_graph.models import (
    ASSET_EVENT,
    FINDING_EVENT,
    OBSERVATION_EVENT,
    VULNERABILITY_EVENT,
    AssetSnapshot,
    CypherOp,
    EvidenceSnapshot,
    FindingSnapshot,
    ObservationSnapshot,
    OutboxEvent,
    RelationshipSnapshot,
    RoundPlan,
    VulnerabilityMatchSnapshot,
    VulnerabilitySnapshot,
)
from aegis.m27_ingestion.predicates import graph_predicate

__all__ = [
    "PHASE_ASSET",
    "PHASE_GRAPH",
    "plan_round",
    "partition_of",
]

PHASE_ASSET = 0
PHASE_GRAPH = 1


def partition_of(key: str, partitions: int) -> int:
    """Stable partition of an ordering key (`canonical_key`), independent of the batch.

    blake2b (not `hash()`) because Python's string hash is salted per process: a restart would
    otherwise move a key to another partition and could interleave it with its own older events
    that are still queued.
    """
    if partitions < 1:
        raise ValueError("partitions must be at least 1")
    digest = hashlib.blake2b(key.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, "big") % partitions


class _Builder:
    """Accumulates ops with per-entity deduplication, preserving first-seen order."""

    def __init__(self) -> None:
        self.ops: list[CypherOp] = []
        self._asset_index: dict[tuple[str, str], int] = {}
        self._edge_index: dict[str, int] = {}
        self._observation_index: dict[str, int] = {}

    def append(self, op: CypherOp) -> None:
        self.ops.append(op)

    def upsert_asset(self, op: CypherOp, asset_id: str, campaign_id: str) -> None:
        """Keep one asset statement per (asset, campaign); the highest revision wins.

        Applying two identical statements whose only difference is `$revision` leaves the same
        node as applying both in order (the template takes `last_seen` with max and unions
        `campaign_ids`), so collapsing them keeps the outcome and halves the work when an asset
        is redelivered inside one batch.
        """
        key = (asset_id, campaign_id)
        index = self._asset_index.get(key)
        if index is None:
            self._asset_index[key] = len(self.ops)
            self.ops.append(op)
            return
        previous = self.ops[index]
        if int(op.parameters["revision"]) > int(previous.parameters["revision"]):
            self.ops[index] = op

    def upsert_observation(self, op: CypherOp, observation_id: str) -> None:
        """One statement per observation id (MERGE is idempotent; redelivery keeps the last one)."""
        index = self._observation_index.get(observation_id)
        if index is None:
            self._observation_index[observation_id] = len(self.ops)
            self.ops.append(op)
            return
        self.ops[index] = op

    def upsert_edge(self, op: CypherOp, relationship_id: str) -> None:
        index = self._edge_index.get(relationship_id)
        if index is None:
            self._edge_index[relationship_id] = len(self.ops)
            self.ops.append(op)
            return
        self.ops[index] = op


def _asset_op(snapshot: AssetSnapshot, campaign_id: str, revision: int, partition: int) -> CypherOp:
    return CypherOp(
        statement=contract.asset_upsert(snapshot.kind),
        parameters={
            "canonical_key": snapshot.canonical_key,
            "asset_id": snapshot.asset_id,
            "kind": snapshot.kind,
            "first_seen": snapshot.first_seen.isoformat(),
            "last_seen": snapshot.last_seen.isoformat(),
            "campaign_id": campaign_id,
            "revision": revision,
        },
        partition=partition,
        phase=PHASE_ASSET,
        entity="asset",
    )


def _edge_op(snapshot: RelationshipSnapshot, partition: int) -> CypherOp:
    return CypherOp(
        statement=contract.relationship_upsert(snapshot.type),
        parameters={
            "from_asset_id": snapshot.from_asset_id,
            "to_asset_id": snapshot.to_asset_id,
            "relationship_id": snapshot.relationship_id,
            "observed_at": snapshot.observed_at.isoformat(),
            "valid_from": snapshot.valid_from.isoformat(),
            "valid_to": snapshot.valid_to.isoformat() if snapshot.valid_to is not None else None,
            "source_job_id": snapshot.source_job_id,
            "confidence": float(snapshot.confidence),
            "campaign_id": snapshot.campaign_id,
        },
        partition=partition,
        phase=PHASE_GRAPH,
        entity="relationship",
    )


def _finding_ops(
    finding: FindingSnapshot,
    evidence: EvidenceSnapshot | None,
    partition: int,
) -> list[CypherOp]:
    """Statement 3 (finding + HAS_FINDING) then statement 4 (evidence + SUPPORTED_BY), in order."""
    observed_at = finding.first_seen.isoformat()
    ops = [
        CypherOp(
            statement=contract.finding_upsert(),
            parameters={
                "asset_id": finding.asset_id,
                "finding_id": finding.finding_id,
                "fingerprint": finding.fingerprint,
                "rule_id": finding.rule_id,
                "title": finding.title,
                "status": finding.status,
                "severity": finding.severity,
                "transition_seq": finding.transition_seq,
                "secret_value": finding.secret_value,
                "observed_at": observed_at,
                "source_job_id": finding.first_job_id,
                "confidence": float(finding.confidence or 1.0),
            },
            partition=partition,
            phase=PHASE_GRAPH,
            entity="finding",
        )
    ]
    if evidence is not None:
        ops.append(
            CypherOp(
                statement=contract.evidence_upsert(),
                parameters={
                    "finding_id": finding.finding_id,
                    "evidence_id": evidence.evidence_id,
                    "sha256": evidence.sha256,
                    "storage_uri": evidence.storage_uri,
                    "source_tool": evidence.source_tool,
                    "observed_at": observed_at,
                    "source_job_id": evidence.job_id,
                },
                partition=partition,
                phase=PHASE_GRAPH,
                entity="evidence",
            )
        )
    return ops


def plan_round(
    batch: Sequence[OutboxEvent],
    *,
    seen: Set[str],
    assets: Mapping[str, AssetSnapshot],
    relationships: Mapping[str, Sequence[RelationshipSnapshot]],
    findings: Mapping[str, FindingSnapshot],
    evidence: Mapping[str, EvidenceSnapshot],
    partitions: int,
    incoming: Mapping[str, Sequence[RelationshipSnapshot]] | None = None,
    vulnerabilities: Mapping[str, VulnerabilitySnapshot] | None = None,
    matches: Mapping[str, VulnerabilityMatchSnapshot] | None = None,
    observations: Mapping[str, ObservationSnapshot] | None = None,
) -> RoundPlan:
    """The Neo4j work and the checkpoint facts of one batch.

    `seen` is the set of `consumer_inbox.dedup_key` values this consumer already applied; those
    events are skipped (at-least-once delivery) but still counted in the checkpoint target, since
    the cursor must move past them.
    """
    builder = _Builder()
    applied: list[tuple[str, str]] = []
    for event in batch:
        if event.inbox_key in seen:
            continue
        applied.append((event.event_id, event.inbox_key))
        if event.type == ASSET_EVENT:
            _plan_asset(builder, event, assets, relationships, partitions, incoming or {})
        elif event.type == OBSERVATION_EVENT:
            _plan_observation(
                builder,
                event,
                assets,
                relationships,
                partitions,
                incoming or {},
                observations or {},
            )
        elif event.type == FINDING_EVENT:
            _plan_finding(builder, event, assets, findings, evidence, partitions)
        elif event.type == VULNERABILITY_EVENT:
            _plan_vulnerability(
                builder, event, matches or {}, vulnerabilities or {}, assets, partitions
            )
        # Every other event has no statement in the committed template: the projector still
        # checkpoints past it (the node types it would feed - `:Target`/`:Campaign`/`:Job` - have
        # no projector statement yet; `:Observation` is projected for `graph: true` predicates).
    return RoundPlan(
        ops=tuple(builder.ops),
        applied=tuple(applied),
        events=len(batch),
        last_seq=batch[-1].seq if batch else 0,
    )


def _plan_asset(
    builder: _Builder,
    event: OutboxEvent,
    assets: Mapping[str, AssetSnapshot],
    relationships: Mapping[str, Sequence[RelationshipSnapshot]],
    partitions: int,
    incoming: Mapping[str, Sequence[RelationshipSnapshot]],
) -> None:
    asset_id = str(event.payload.get("asset_id") or "")
    revision = int(event.payload.get("revision") or 0) or 0
    _plan_asset_state(builder, asset_id, revision, assets, relationships, incoming, partitions)


def _plan_observation(
    builder: _Builder,
    event: OutboxEvent,
    assets: Mapping[str, AssetSnapshot],
    relationships: Mapping[str, Sequence[RelationshipSnapshot]],
    partitions: int,
    incoming: Mapping[str, Sequence[RelationshipSnapshot]],
    observations: Mapping[str, ObservationSnapshot],
) -> None:
    """An observation's subject is an asset: plan that asset, its edges, and its `:Observation`.

    The *asset* an observation is about is in the graph, and this is the event that makes a later
    edge projectable: `dns.resolve` creates `RESOLVES_TO` edges between a name discovered by an
    earlier envelope and an address discovered by this one, so no `asset.discovered.v2` in this
    batch names the edge's start. The payload carries the subject (`subject_id`) and the revision,
    so re-merging the node and its edges is idempotent (MERGE by `canonical_key`/`relationship_id`)
    and the incremental projection matches what a rebuild produces.

    G1.6b: predicates the registry marks `graph: true` (`service.product`, `tls.certificate`,
    `http.technology`, ...) also get their `:Observation` node, with the `value_summary` the read
    model publishes and the subject's canonical key. Every other predicate stays PostgreSQL-only,
    which is what keeps the graph from growing one node per port state.
    """
    subject_id = str(event.payload.get("subject_id") or "")
    observation = observations.get(str(event.payload.get("observation_id") or ""))
    # `observation.changed.v2` carries no revision in its payload: the row does (M23 reads
    # properties from PostgreSQL), and it is the revision of the state this event applied.
    revision = int(event.payload.get("revision") or 0) or (
        observation.revision if observation is not None else 0
    )
    _plan_asset_state(builder, subject_id, revision, assets, relationships, incoming, partitions)
    if observation is None or not graph_predicate(observation.predicate):
        return
    builder.upsert_observation(
        _observation_op(observation, revision, partition_of(observation.subject_key, partitions)),
        observation.observation_id,
    )


def _observation_op(snapshot: ObservationSnapshot, revision: int, partition: int) -> CypherOp:
    return CypherOp(
        statement=contract.observation_upsert(),
        parameters={
            "observation_id": snapshot.observation_id,
            "predicate": snapshot.predicate,
            "value_summary": value_summary(snapshot.value),
            "polarity": snapshot.polarity,
            "subject": snapshot.subject_key,
            "observed_at": snapshot.observed_at.isoformat(),
            "confidence": snapshot.confidence,
            "revision": revision,
        },
        partition=partition,
        phase=PHASE_GRAPH,
        entity="observation",
    )


def value_summary(value: Any) -> str | None:
    """The one textual summary of an observation value, as the read model publishes it.

    PostgreSQL keeps the whole JSON value; the graph node and `get_recent_observations` keep this
    summary so a query never has to move an arbitrary-sized object out of the graph.
    """
    if value is None:
        return None
    text = (
        value if isinstance(value, str) else json.dumps(value, sort_keys=True, ensure_ascii=False)
    )
    return text[:500]


def _plan_vulnerability(
    builder: _Builder,
    event: OutboxEvent,
    matches: Mapping[str, VulnerabilityMatchSnapshot],
    vulnerabilities: Mapping[str, VulnerabilitySnapshot],
    assets: Mapping[str, AssetSnapshot],
    partitions: int,
) -> None:
    """The `:Vulnerability` node and its candidate `AFFECTED_BY` edge, from PostgreSQL rows.

    The event only names the match: `match_method`, `affected_range`, `confidence`, the intel
    snapshot and the campaign are read from `package_vuln_match`, and CVSS/KEV/EPSS from
    `vulnerability_current` (model.md: properties come from PostgreSQL, not from the payload). A
    match whose vulnerability is withdrawn everywhere has no node and plans nothing; a start asset
    whose kind the model does not allow is a `ContractMismatch`, never a silently dropped edge.
    """
    match = matches.get(str(event.payload.get("match_id") or ""))
    if match is None:
        return
    vulnerability = vulnerabilities.get(match.vulnerability_id)
    if vulnerability is None:
        return
    contract.affected_by_source(match.asset_kind)
    owner = assets.get(match.asset_id)
    key = owner.canonical_key if owner is not None else match.canonical_key
    partition = partition_of(key, partitions)
    builder.append(
        CypherOp(
            statement=contract.vulnerability_upsert(),
            parameters={
                "asset_id": match.asset_id,
                "vulnerability_id": match.vulnerability_id,
                "cvss_base": vulnerability.cvss_base,
                "kev": vulnerability.kev,
                "epss": vulnerability.epss,
                "node_snapshot_id": vulnerability.snapshot_id,
                "observed_at": match.observed_at.isoformat(),
                "match_method": match.match_method,
                "affected_range": match.affected_range,
                "confidence": match.confidence,
                "snapshot_id": match.snapshot_id,
                "match_id": match.match_id,
                "campaign_id": match.campaign_id,
            },
            partition=partition,
            phase=PHASE_GRAPH,
            entity="vulnerability",
        )
    )


def _plan_asset_state(
    builder: _Builder,
    asset_id: str,
    revision: int,
    assets: Mapping[str, AssetSnapshot],
    relationships: Mapping[str, Sequence[RelationshipSnapshot]],
    incoming: Mapping[str, Sequence[RelationshipSnapshot]],
    partitions: int,
) -> None:
    snapshot = assets.get(asset_id)
    if snapshot is None:
        return  # the asset row is gone (append-only, so this is a data bug the caller logs)
    _plan_node(builder, snapshot, revision, partitions)
    # The asset's whole neighbourhood, in both directions: M27 opens `DISCOVERED_FROM` from the
    # source to the asset it found, so a batch naming only the found asset would never plan it.
    for edge in (*relationships.get(asset_id, ()), *incoming.get(asset_id, ())):
        # Both ends of an edge must be committed before the statement of phase 1 runs: an edge can
        # point at an asset no event of this batch discovered (a seed the campaign started from, an
        # address a later resolver found).
        start = None
        for endpoint_id in (edge.from_asset_id, edge.to_asset_id):
            endpoint = assets.get(endpoint_id)
            if endpoint is None:
                continue
            _plan_node(builder, endpoint, revision, partitions)
            if endpoint_id == edge.from_asset_id:
                start = endpoint
        partition = (
            partition_of(start.canonical_key, partitions)
            if start is not None
            else partition_of(snapshot.canonical_key, partitions)
        )
        builder.upsert_edge(_edge_op(edge, partition), edge.relationship_id)


def _plan_node(builder: _Builder, snapshot: AssetSnapshot, revision: int, partitions: int) -> int:
    """Plan one asset node for every campaign it belongs to; returns its partition.

    `campaign_ids` is M27's data (`asset_campaign`): the projector never adds a membership because
    an edge happens to cross campaigns, it only writes the node with the memberships PostgreSQL
    already states.
    """
    partition = partition_of(snapshot.canonical_key, partitions)
    for campaign_id in snapshot.campaign_ids:
        builder.upsert_asset(
            _asset_op(snapshot, campaign_id, revision, partition), snapshot.asset_id, campaign_id
        )
    return partition


def _plan_finding(
    builder: _Builder,
    event: OutboxEvent,
    assets: Mapping[str, AssetSnapshot],
    findings: Mapping[str, FindingSnapshot],
    evidence: Mapping[str, EvidenceSnapshot],
    partitions: int,
) -> None:
    finding_id = str(event.payload.get("finding_id") or "")
    finding = findings.get(finding_id)
    if finding is None:
        return
    owner = assets.get(finding.asset_id)
    key = owner.canonical_key if owner is not None else finding.finding_id
    partition = partition_of(key, partitions)
    evidence_id = str(event.payload.get("evidence_ref") or "")
    for op in _finding_ops(finding, evidence.get(evidence_id), partition):
        builder.append(op)
