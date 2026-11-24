"""`knowledge.delta.v2` emission rules (G1.4b).

The projector publishes one delta per knowledge revision (`graph_revision.revision`, i.e. one
accepted ingestion envelope): the revision, the campaign, the causing job and the changed
entities, capped at 1000 with `truncated` telling the consumer to call
`graph.summarize_campaign_delta` instead of trusting an incomplete list.

A delta may only be published **once** (`outbox_event` is unique on `type, dedup_key` and the
dedup key here is the revision), so it may only be published when the revision is provably
complete. Two facts make that decidable:

* a revision's events commit atomically with the revision (M27 writes them in one transaction), so
  a revision is either fully published or not published at all;
* their publication numbers are contiguous (the allocator holds the counter row until commit), so
  a revision's events form one run in `seq` order.

The last run of a window is therefore complete exactly when the window ends at the publication
watermark and was not cut by the read limit; earlier runs are complete because a different
revision's event follows them. Nothing here is remembered in memory: the emitter has its own
durable `consumer_cursor` row, so a restart re-reads the same tail instead of publishing a partial
delta.

`DeltaRow` is the narrow projection of an `outbox_event` row the emitter needs. Reading only the
payload fields it uses (instead of decoding every payload into Python) is part of what the
throughput acceptance measures.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from aegis.m23_graph.models import ASSET_EVENT, FINDING_EVENT, OBSERVATION_EVENT

__all__ = [
    "MAX_ENTITIES",
    "DeltaDraft",
    "DeltaEntity",
    "DeltaRow",
    "draft",
    "revision_of",
    "runs",
]

#: `knowledge.delta.v2.changed_entities.maxItems`.
MAX_ENTITIES = 1000


@dataclass(frozen=True, slots=True)
class DeltaRow:
    """The fields of one outbox event that the delta emitter uses."""

    seq: int
    type: str
    campaign_id: str | None
    trace: dict[str, Any]
    revision: int | None
    observation_id: str | None
    asset_id: str | None
    canonical_key: str | None
    subject_key: str | None
    finding_id: str | None
    causal_job_id: str | None


@dataclass(frozen=True, slots=True)
class DeltaEntity:
    """One `changed_entities[]` item; the wire shape is built by `DeltaDraft.payload()`."""

    entity_type: str
    entity_id: str
    canonical_key: str | None
    change: str


@dataclass(frozen=True, slots=True)
class DeltaDraft:
    """A complete revision delta, ready to be written to `outbox_event`."""

    revision: int
    campaign_id: str
    causal_job_id: str | None
    entities: tuple[DeltaEntity, ...]
    truncated: bool
    upto_seq: int
    trace: dict[str, Any]

    def payload(self) -> dict[str, Any]:
        changed: list[dict[str, Any]] = []
        for entity in self.entities:
            item: dict[str, Any] = {
                "entity_type": entity.entity_type,
                "entity_id": entity.entity_id,
                "change": entity.change,
            }
            if entity.canonical_key is not None:
                item["canonical_key"] = entity.canonical_key
            changed.append(item)
        payload: dict[str, Any] = {
            "revision": self.revision,
            "campaign_id": self.campaign_id,
            "changed_entities": changed,
            "truncated": self.truncated,
        }
        if self.causal_job_id is not None:
            payload["causal_job_id"] = self.causal_job_id
        return payload


def revision_of(row: DeltaRow, observation_revisions: Mapping[str, int]) -> int | None:
    """The knowledge revision an event belongs to, or None when it changes no graph entity.

    `asset.discovered.v2` carries its revision in the payload. `observation.changed.v2` does not,
    so the revision comes from the `aegis.observation` row (`observation_revisions`). Every other
    type (job/policy/artifact/intel events and `knowledge.delta.v2` itself) is passed over.
    """
    if row.type == ASSET_EVENT:
        return row.revision
    if row.type == OBSERVATION_EVENT and row.observation_id is not None:
        return observation_revisions.get(row.observation_id)
    return None


def runs(rows: Sequence[tuple[DeltaRow, int]]) -> list[list[tuple[DeltaRow, int]]]:
    """Group `(row, revision)` pairs into contiguous revision runs, in publication order."""
    grouped: list[list[tuple[DeltaRow, int]]] = []
    for pair in rows:
        if grouped and grouped[-1][-1][1] == pair[1]:
            grouped[-1].append(pair)
        else:
            grouped.append([pair])
    return grouped


def _entity(row: DeltaRow) -> DeltaEntity | None:
    if row.type == ASSET_EVENT and row.asset_id is not None:
        return DeltaEntity(
            entity_type="asset",
            entity_id=row.asset_id,
            canonical_key=row.canonical_key,
            change="created",
        )
    if row.type == OBSERVATION_EVENT and row.observation_id is not None:
        return DeltaEntity(
            entity_type="observation",
            entity_id=row.observation_id,
            canonical_key=row.subject_key,
            change="changed",
        )
    if row.type == FINDING_EVENT and row.finding_id is not None:
        return DeltaEntity(
            entity_type="finding",
            entity_id=row.finding_id,
            canonical_key=None,
            change="changed",
        )
    return None


def draft(
    run: Sequence[tuple[DeltaRow, int]],
    *,
    max_entities: int = MAX_ENTITIES,
    truncated: bool = False,
) -> DeltaDraft:
    """Turn one revision run into a delta draft.

    Entities keep publication order; the cap keeps the first `max_entities` and sets `truncated`.
    `truncated=True` from the caller says the run itself was cut (the emitter's read limit landed
    inside it), which is also what `truncated` means to a consumer: call `summarize_campaign_delta`.
    """
    if not run:
        raise ValueError("a delta run must not be empty")
    revision = run[0][1]
    entities = [entity for row, _ in run if (entity := _entity(row)) is not None]
    last = run[-1][0]
    campaign_id = last.campaign_id or ""
    if not campaign_id:
        raise ValueError(f"revision {revision} has no campaign_id to publish a delta for")
    return DeltaDraft(
        revision=revision,
        campaign_id=campaign_id,
        causal_job_id=last.causal_job_id,
        entities=tuple(entities[:max_entities]),
        truncated=truncated or len(entities) > max_entities,
        upto_seq=last.seq,
        trace=dict(last.trace),
    )
