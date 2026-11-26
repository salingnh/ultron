"""Internal value types of M23 (G1.4b).

The wire shapes live in `contracts/` and are never redefined here: these dataclasses are the
in-process snapshots the projector reads from PostgreSQL, the Cypher operations it applies to
Neo4j, and the counters the operator sees. Deliberately dependency-free (no psycopg/neo4j types)
so planning is a pure function the tests can drive without a database.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

__all__ = [
    "AssetSnapshot",
    "CypherOp",
    "EvidenceSnapshot",
    "FindingSnapshot",
    "ObservationSnapshot",
    "OutboxEvent",
    "ProjectorStats",
    "RelationshipSnapshot",
    "RoundPlan",
    "RoundResult",
    "VulnerabilityMatchSnapshot",
    "VulnerabilitySnapshot",
]

ASSET_EVENT = "asset.discovered.v2"
OBSERVATION_EVENT = "observation.changed.v2"
FINDING_EVENT = "finding.changed.v2"
VULNERABILITY_EVENT = "vulnerability.matched.v2"
DELTA_EVENT = "knowledge.delta.v2"


@dataclass(frozen=True, slots=True)
class OutboxEvent:
    """One `aegis.outbox_event` row as `aegis.outbox_batch` returns it."""

    seq: int
    event_id: str
    type: str
    dedup_key: str
    campaign_id: str | None
    payload: dict[str, Any]
    trace: dict[str, Any]
    occurred_at: datetime

    @property
    def inbox_key(self) -> str:
        """The `consumer_inbox.dedup_key` of this event: `<type>:<dedup_key>` (0001 comment)."""
        return f"{self.type}:{self.dedup_key}"


@dataclass(frozen=True, slots=True)
class AssetSnapshot:
    """`aegis.asset` plus the campaigns that reached it (`asset_campaign`)."""

    asset_id: str
    canonical_key: str
    kind: str
    first_seen: datetime
    last_seen: datetime
    owner: str | None
    exposure: str | None
    criticality: str | None
    campaign_ids: tuple[str, ...]
    first_job_id: str | None


@dataclass(frozen=True, slots=True)
class RelationshipSnapshot:
    """One validity interval of an edge (`aegis.relationship`); `valid_to` NULL means open."""

    relationship_id: str
    type: str
    from_asset_id: str
    to_asset_id: str
    observed_at: datetime
    valid_from: datetime
    valid_to: datetime | None
    source_job_id: str
    confidence: float
    campaign_id: str


@dataclass(frozen=True, slots=True)
class ObservationSnapshot:
    """`aegis.observation` row needed for a delta, the subject key and the `:Observation` node."""

    observation_id: str
    revision: int
    campaign_id: str
    predicate: str
    subject_asset_id: str
    subject_key: str
    observed_at: datetime
    polarity: str
    value: Any = None
    confidence: float | None = None


@dataclass(frozen=True, slots=True)
class FindingSnapshot:
    finding_id: str
    asset_id: str
    fingerprint: str
    rule_id: str
    title: str
    status: str
    severity: str
    transition_seq: int
    confidence: float | None
    secret_value: str | None
    first_seen: datetime
    first_job_id: str


@dataclass(frozen=True, slots=True)
class EvidenceSnapshot:
    evidence_id: str
    sha256: str
    storage_uri: str
    source_tool: str
    job_id: str


@dataclass(frozen=True, slots=True)
class VulnerabilitySnapshot:
    """`:Vulnerability` of model.md, assembled from the four `vulnerability_current` sources.

    `cvss_base`/`cvss_severity` come from the NVD row, `kev` is true when the KEV feed lists the
    CVE (and it is not withdrawn there), `epss` is the EPSS score; `snapshot_id` is the intel
    snapshot that supplied them (NVD first, then KEV, then EPSS), so a graph node always says which
    pinned feed set it was projected from.
    """

    vulnerability_id: str
    cvss_base: float | None
    cvss_severity: str | None
    kev: bool
    epss: float | None
    snapshot_id: str


@dataclass(frozen=True, slots=True)
class VulnerabilityMatchSnapshot:
    """The current candidate row of an (asset, vulnerability) pair (`package_vuln_match`)."""

    match_id: str
    asset_id: str
    asset_kind: str
    canonical_key: str
    vulnerability_id: str
    campaign_id: str
    match_method: str
    affected_range: str | None
    confidence: float
    snapshot_id: str
    observed_at: datetime
    #: `False` on a retraction row (migration 0008): the edge must go, history stays in PostgreSQL.
    matched: bool = True


@dataclass(frozen=True, slots=True)
class CypherOp:
    """One statement execution: the parameterized contract Cypher and its parameters."""

    statement: str
    parameters: dict[str, Any]
    partition: int
    phase: int
    entity: str


@dataclass(frozen=True, slots=True)
class RoundPlan:
    """Everything one outbox batch needs: Neo4j work, the checkpoint facts, the event count."""

    ops: tuple[CypherOp, ...]
    applied: tuple[tuple[str, str], ...]
    events: int
    last_seq: int

    @property
    def partitions(self) -> int:
        return 1 + max((op.partition for op in self.ops), default=-1)

    def phases(self) -> dict[int, list[CypherOp]]:
        """Ops grouped by execution phase, in phase order (see plan.py: assets first)."""
        grouped: dict[int, list[CypherOp]] = {}
        for op in self.ops:
            grouped.setdefault(op.phase, []).append(op)
        return grouped


@dataclass
class ProjectorStats:
    """Operator-facing counters; the same object is returned by a bounded run."""

    consumer: str
    events_applied: int = 0
    events_skipped: int = 0
    deltas_emitted: int = 0
    ops_applied: int = 0
    batches: int = 0
    checkpoints: int = 0
    retries: dict[str, int] = field(default_factory=dict)
    refresh_attempts: int = 0
    refresh_blocked: int = 0
    refresh_throttled: int = 0
    first_event_at: float | None = None
    last_event_at: float | None = None
    started_at: float | None = None
    finished_at: float | None = None
    cursor: int = 0
    watermark: int = 0
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass(frozen=True, slots=True)
class RoundResult:
    """One projector iteration: what it read, applied and checkpointed."""

    events: int
    ops: int
    applied: int
    last_seq: int
    cursor: int
    watermark: int
    deltas: int
    blocked: bool = False
