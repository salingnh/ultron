"""The projector's PostgreSQL side (G1.4b): outbox, cursor, lease, prefetch, checkpoint.

Everything here goes through the functions and tables migration 0008/0013 publish, never through
a private copy of the ordering algorithm:

* `aegis.outbox_dispatch_lease` - take/renew the dispatcher lease and get the fencing token;
* `aegis.outbox_watermark_refresh` - advance the publication watermark, in its **own** short
  transaction (0013 holds the exclusive publication lock until commit; sharing a transaction with
  other work would block every writer for that long);
* `aegis.outbox_batch` - the next published events after the consumer cursor, never past the
  watermark;
* `aegis.consumer_advance` - checkpoint, fenced, never past the watermark (D25).

Properties of an entity (asset, relationship, finding, evidence) are read from PostgreSQL at apply
time, never from the event payload, as `contracts/graph/model.md` requires. They are prefetched one
round trip each for the whole batch: the per-event lookup of the G0.3b prototype was the cheapest
single lever on throughput (see the G1.4b report).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from aegis.contracts_gen.events.knowledge_delta_v2_schema import KnowledgeDelta
from aegis.m23_graph import deltas
from aegis.m23_graph.contract import RELATIONSHIP_TYPES
from aegis.m23_graph.models import (
    OBSERVATION_EVENT,
    AssetSnapshot,
    EvidenceSnapshot,
    FindingSnapshot,
    ObservationSnapshot,
    OutboxEvent,
    RelationshipSnapshot,
    VulnerabilityMatchSnapshot,
    VulnerabilitySnapshot,
)

#: ids.v2 requires UUIDv7 and neither PostgreSQL 16 nor Python 3.12 can mint one; M27 owns the
#: helper today (G1.4a proposal 2 asks for one shared `aegis.common` copy).
from aegis.m27_ingestion.ids import uuid7  # noqa: E402

__all__ = [
    "DELTA_CONSUMER_SUFFIX",
    "checkpoint",
    "configure_watermark_bound",
    "connect",
    "current_matched_pairs",
    "emit_deltas",
    "prefetch_assets",
    "prefetch_evidence",
    "prefetch_findings",
    "prefetch_incoming_relationships",
    "prefetch_matches",
    "prefetch_observations",
    "prefetch_relationships",
    "prefetch_vulnerabilities",
    "read_batch",
    "read_cursor",
    "read_inbox",
    "read_watermark",
    "refresh_watermark",
    "take_lease",
]

SEARCH_PATH = "SET search_path = aegis, public"

#: Suffix of the delta emitter's own consumer id: it is a consumer of the outbox like any other.
DELTA_CONSUMER_SUFFIX = "#delta"


def connect(dsn: str, *, autocommit: bool = True) -> psycopg.Connection[dict[str, Any]]:
    """A connection in the contract search_path; every read here is fine outside a transaction."""
    conn: psycopg.Connection[dict[str, Any]] = psycopg.connect(
        dsn, autocommit=autocommit, row_factory=dict_row
    )
    conn.execute(SEARCH_PATH)
    return conn


def configure_watermark_bound(conn: psycopg.Connection[dict[str, Any]], bound: str) -> None:
    """Bound how long a watermark refresh may queue for the publication lock (0013's GUC).

    The refresh waits while holding its place in the lock queue, and new writer transactions queue
    behind it; that is the price of a provable watermark. With a long writer transaction the wait
    would be seconds and the projector would stall the writers it needs, so the projector uses a
    short bound and retries with backoff instead of waiting out the default.
    """
    conn.execute("SELECT set_config('aegis.outbox_watermark_lock_timeout', %s, false)", (bound,))


def read_cursor(conn: psycopg.Connection[dict[str, Any]], consumer: str) -> int:
    row = conn.execute(
        "SELECT last_seq FROM consumer_cursor WHERE consumer = %s", (consumer,)
    ).fetchone()
    return 0 if row is None else int(row["last_seq"])


def read_watermark(conn: psycopg.Connection[dict[str, Any]]) -> int:
    row = conn.execute("SELECT published_upto FROM outbox_watermark").fetchone()
    if row is None:
        raise RuntimeError("aegis.outbox_watermark is empty: migration 0008 did not run")
    return int(row["published_upto"])


def take_lease(
    conn: psycopg.Connection[dict[str, Any]], dispatcher: str, holder: str, ttl_seconds: int
) -> int | None:
    """Take or renew the dispatcher lease; None means another live holder owns it."""
    row = conn.execute(
        "SELECT aegis.outbox_dispatch_lease(%s, %s, %s) AS fence",
        (dispatcher, holder, ttl_seconds),
    ).fetchone()
    if row is None or row["fence"] is None:
        return None
    return int(row["fence"])


def refresh_watermark(conn: psycopg.Connection[dict[str, Any]], dispatcher: str, fence: int) -> int:
    """Advance and return the watermark; raises `psycopg.errors.LockNotAvailable` on the 0013 wait.

    Must run in its own transaction (autocommit connection): the exclusive publication lock is
    transaction-scoped and blocks new writers until commit.
    """
    row = conn.execute(
        "SELECT aegis.outbox_watermark_refresh(%s, %s) AS watermark", (dispatcher, fence)
    ).fetchone()
    if row is None:
        raise RuntimeError("aegis.outbox_watermark_refresh returned no row")
    return int(row["watermark"])


def read_batch(
    conn: psycopg.Connection[dict[str, Any]], consumer: str, limit: int
) -> list[OutboxEvent]:
    rows = conn.execute(
        "SELECT seq, event_id, type, dedup_key, campaign_id, payload, trace, occurred_at"
        "  FROM aegis.outbox_batch(%s, %s)",
        (consumer, limit),
    ).fetchall()
    return [
        OutboxEvent(
            seq=int(row["seq"]),
            event_id=str(row["event_id"]),
            type=str(row["type"]),
            dedup_key=str(row["dedup_key"]),
            campaign_id=None if row["campaign_id"] is None else str(row["campaign_id"]),
            payload=dict(row["payload"]),
            trace=dict(row["trace"]),
            occurred_at=row["occurred_at"],
        )
        for row in rows
    ]


def read_inbox(
    conn: psycopg.Connection[dict[str, Any]], consumer: str, keys: Iterable[str]
) -> set[str]:
    """Which of `keys` this consumer already applied (`consumer_inbox` is append-only)."""
    wanted = list(dict.fromkeys(keys))
    if not wanted:
        return set()
    rows = conn.execute(
        "SELECT dedup_key FROM consumer_inbox WHERE consumer = %s AND dedup_key = ANY(%s)",
        (consumer, wanted),
    ).fetchall()
    return {str(row["dedup_key"]) for row in rows}


def _uuid_list(values: Iterable[str]) -> list[str]:
    return [str(value) for value in dict.fromkeys(values)]


def prefetch_assets(
    conn: psycopg.Connection[dict[str, Any]], asset_ids: Iterable[str]
) -> dict[str, AssetSnapshot]:
    ids = _uuid_list(asset_ids)
    if not ids:
        return {}
    rows = conn.execute(
        "SELECT a.asset_id, a.canonical_key, a.kind, a.first_seen, a.last_seen, a.owner,"
        "       a.exposure, a.criticality, a.first_job_id,"
        "       coalesce(array_agg(ac.campaign_id ORDER BY ac.first_seen, ac.campaign_id)"
        "                FILTER (WHERE ac.campaign_id IS NOT NULL), '{}') AS campaign_ids"
        "  FROM asset a LEFT JOIN asset_campaign ac ON ac.asset_id = a.asset_id"
        " WHERE a.asset_id = ANY(%s::uuid[])"
        " GROUP BY a.asset_id",
        (ids,),
    ).fetchall()
    return {
        str(row["asset_id"]): AssetSnapshot(
            asset_id=str(row["asset_id"]),
            canonical_key=str(row["canonical_key"]),
            kind=str(row["kind"]),
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            owner=row["owner"],
            exposure=row["exposure"],
            criticality=row["criticality"],
            campaign_ids=tuple(str(campaign) for campaign in row["campaign_ids"]),
            first_job_id=None if row["first_job_id"] is None else str(row["first_job_id"]),
        )
        for row in rows
    }


def prefetch_relationships(
    conn: psycopg.Connection[dict[str, Any]], from_asset_ids: Iterable[str]
) -> dict[str, tuple[RelationshipSnapshot, ...]]:
    """Every projectable edge whose start is one of `from_asset_ids`, ordered per asset."""
    ids = _uuid_list(from_asset_ids)
    if not ids:
        return {}
    rows = conn.execute(
        "SELECT relationship_id, type, from_asset_id, to_asset_id, observed_at, valid_from,"
        "       valid_to, source_job_id, confidence, campaign_id"
        "  FROM relationship"
        " WHERE from_asset_id = ANY(%s::uuid[]) AND type = ANY(%s::text[])"
        " ORDER BY from_asset_id, valid_from, relationship_id",
        (ids, list(RELATIONSHIP_TYPES)),
    ).fetchall()
    grouped: dict[str, list[RelationshipSnapshot]] = {}
    for row in rows:
        snapshot = RelationshipSnapshot(
            relationship_id=str(row["relationship_id"]),
            type=str(row["type"]),
            from_asset_id=str(row["from_asset_id"]),
            to_asset_id=str(row["to_asset_id"]),
            observed_at=row["observed_at"],
            valid_from=row["valid_from"],
            valid_to=row["valid_to"],
            source_job_id=str(row["source_job_id"]),
            confidence=float(row["confidence"]),
            campaign_id=str(row["campaign_id"]),
        )
        grouped.setdefault(snapshot.from_asset_id, []).append(snapshot)
    return {key: tuple(value) for key, value in grouped.items()}


def prefetch_incoming_relationships(
    conn: psycopg.Connection[dict[str, Any]], to_asset_ids: Iterable[str]
) -> dict[str, tuple[RelationshipSnapshot, ...]]:
    """Every projectable edge whose *end* is one of `to_asset_ids`, grouped per end asset.

    An asset's neighbourhood has to be complete whenever any of its ends is projected: M27 opens
    `DISCOVERED_FROM` from the source to the discovered asset, and a batch that only names the
    discovered asset would otherwise never plan that edge.
    """
    ids = _uuid_list(to_asset_ids)
    if not ids:
        return {}
    rows = conn.execute(
        "SELECT relationship_id, type, from_asset_id, to_asset_id, observed_at, valid_from,"
        "       valid_to, source_job_id, confidence, campaign_id"
        "  FROM relationship"
        " WHERE to_asset_id = ANY(%s::uuid[]) AND type = ANY(%s::text[])"
        " ORDER BY to_asset_id, valid_from, relationship_id",
        (ids, list(RELATIONSHIP_TYPES)),
    ).fetchall()
    grouped: dict[str, list[RelationshipSnapshot]] = {}
    for row in rows:
        snapshot = RelationshipSnapshot(
            relationship_id=str(row["relationship_id"]),
            type=str(row["type"]),
            from_asset_id=str(row["from_asset_id"]),
            to_asset_id=str(row["to_asset_id"]),
            observed_at=row["observed_at"],
            valid_from=row["valid_from"],
            valid_to=row["valid_to"],
            source_job_id=str(row["source_job_id"]),
            confidence=float(row["confidence"]),
            campaign_id=str(row["campaign_id"]),
        )
        grouped.setdefault(snapshot.to_asset_id, []).append(snapshot)
    return {key: tuple(value) for key, value in grouped.items()}


def prefetch_observations(
    conn: psycopg.Connection[dict[str, Any]], observation_ids: Iterable[str]
) -> dict[str, ObservationSnapshot]:
    ids = _uuid_list(observation_ids)
    if not ids:
        return {}
    rows = conn.execute(
        "SELECT o.observation_id, o.revision, o.campaign_id, o.predicate, o.subject_asset_id,"
        "       a.canonical_key AS subject_key, o.observed_at, o.polarity, o.value, o.confidence"
        "  FROM observation o JOIN asset a ON a.asset_id = o.subject_asset_id"
        " WHERE o.observation_id = ANY(%s::uuid[])",
        (ids,),
    ).fetchall()
    return {
        str(row["observation_id"]): ObservationSnapshot(
            observation_id=str(row["observation_id"]),
            revision=int(row["revision"]),
            campaign_id=str(row["campaign_id"]),
            predicate=str(row["predicate"]),
            subject_asset_id=str(row["subject_asset_id"]),
            subject_key=str(row["subject_key"]),
            observed_at=row["observed_at"],
            polarity=str(row["polarity"]),
            value=row["value"],
            confidence=None if row["confidence"] is None else float(row["confidence"]),
        )
        for row in rows
    }


def prefetch_vulnerabilities(
    conn: psycopg.Connection[dict[str, Any]], vulnerability_ids: Iterable[str]
) -> dict[str, VulnerabilitySnapshot]:
    """`:Vulnerability` properties, assembled from the per-source `vulnerability_current` rows.

    A CVE has one current revision per feed (`nvd`, `kev`, `epss`), so the node is a merge of up to
    three rows: NVD supplies CVSS, KEV membership is a boolean, EPSS the score. `snapshot_id` is
    the snapshot of the row that supplied CVSS (NVD), else KEV, else EPSS, so a node always names
    the pinned feed set it came from. A withdrawn CVE contributes nothing and is skipped.
    """
    wanted = list(dict.fromkeys(vulnerability_ids))
    if not wanted:
        return {}
    rows = conn.execute(
        "SELECT vulnerability_id, source, cvss, kev, epss, snapshot_id"
        "  FROM vulnerability_current"
        " WHERE vulnerability_id = ANY(%s) AND NOT withdrawn",
        (wanted,),
    ).fetchall()
    grouped: dict[str, dict[str, dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(str(row["vulnerability_id"]), {})[str(row["source"])] = dict(row)
    snapshots: dict[str, VulnerabilitySnapshot] = {}
    for vulnerability_id, sources in grouped.items():
        nvd = sources.get("nvd")
        kev_row = sources.get("kev")
        epss_row = sources.get("epss")
        cvss = _json_object(nvd.get("cvss") if nvd else None)
        epss = _json_object(epss_row.get("epss") if epss_row else None)
        source_row = nvd or kev_row or epss_row
        if source_row is None:  # pragma: no cover - grouped is built from rows
            continue
        base_score = cvss.get("base_score")
        snapshots[vulnerability_id] = VulnerabilitySnapshot(
            vulnerability_id=vulnerability_id,
            cvss_base=float(base_score) if isinstance(base_score, (int, float)) else None,
            cvss_severity=_text(cvss.get("base_severity")),
            kev=kev_row is not None,
            epss=_score(epss.get("score")),
            snapshot_id=str(source_row["snapshot_id"]),
        )
    return snapshots


def prefetch_matches(
    conn: psycopg.Connection[dict[str, Any]], match_ids: Iterable[str]
) -> dict[str, VulnerabilityMatchSnapshot]:
    """The candidate rows a `vulnerability.matched.v2` event names, with their asset."""
    ids = _uuid_list(match_ids)
    if not ids:
        return {}
    rows = conn.execute(
        "SELECT m.match_id, m.package_asset_id, a.kind, a.canonical_key, m.vulnerability_id,"
        "       m.campaign_id, m.match_method, m.affected_range, m.confidence, m.snapshot_id,"
        "       m.created_at, m.matched"
        "  FROM package_vuln_match m JOIN asset a ON a.asset_id = m.package_asset_id"
        " WHERE m.match_id = ANY(%s::uuid[])",
        (ids,),
    ).fetchall()
    matches: dict[str, VulnerabilityMatchSnapshot] = {}
    for row in rows:
        if row["campaign_id"] is None or row["snapshot_id"] is None:
            raise RuntimeError(
                f"package_vuln_match {row['match_id']} has no campaign/snapshot: migration 0004 "
                "requires both on a candidate written by M20"
            )
        matches[str(row["match_id"])] = VulnerabilityMatchSnapshot(
            match_id=str(row["match_id"]),
            asset_id=str(row["package_asset_id"]),
            asset_kind=str(row["kind"]),
            canonical_key=str(row["canonical_key"]),
            vulnerability_id=str(row["vulnerability_id"]),
            campaign_id=str(row["campaign_id"]),
            match_method=str(row["match_method"]),
            affected_range=None if row["affected_range"] is None else str(row["affected_range"]),
            confidence=float(row["confidence"] if row["confidence"] is not None else 0.0),
            snapshot_id=str(row["snapshot_id"]),
            observed_at=row["created_at"],
            matched=bool(row["matched"]),
        )
    return matches


def current_matched_pairs(
    conn: psycopg.Connection[dict[str, Any]], asset_ids: Iterable[str]
) -> set[tuple[str, str]]:
    """The (asset, vulnerability) pairs whose newest decision is a match, for these assets.

    A retraction is one campaign's decision, while the graph edge is one per pair: the projector
    removes the edge only when PostgreSQL says no decision of that pair still matches, so a
    campaign that retracted a candidate another campaign still holds cannot delete a live edge.
    """
    assets = _uuid_list(asset_ids)
    if not assets:
        return set()
    rows = conn.execute(
        "WITH latest AS ("
        "  SELECT DISTINCT ON (package_asset_id, vulnerability_id)"
        "         package_asset_id, vulnerability_id, matched"
        "    FROM package_vuln_match"
        "   WHERE package_asset_id = ANY(%s::uuid[])"
        "   ORDER BY package_asset_id, vulnerability_id, created_at DESC, match_id DESC"
        ")"
        " SELECT package_asset_id, vulnerability_id FROM latest WHERE matched",
        (assets,),
    ).fetchall()
    return {(str(row["package_asset_id"]), str(row["vulnerability_id"])) for row in rows}


def _json_object(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _score(value: object) -> float | None:
    return float(value) if isinstance(value, (int, float)) else None


def prefetch_findings(
    conn: psycopg.Connection[dict[str, Any]], finding_ids: Iterable[str]
) -> dict[str, FindingSnapshot]:
    ids = _uuid_list(finding_ids)
    if not ids:
        return {}
    rows = conn.execute(
        "SELECT finding_id, asset_id, fingerprint, rule_id, title, status, severity,"
        "       transition_seq, confidence, secret_value, first_seen, first_job_id"
        "  FROM finding WHERE finding_id = ANY(%s::uuid[])",
        (ids,),
    ).fetchall()
    return {
        str(row["finding_id"]): FindingSnapshot(
            finding_id=str(row["finding_id"]),
            asset_id=str(row["asset_id"]),
            fingerprint=str(row["fingerprint"]),
            rule_id=str(row["rule_id"]),
            title=str(row["title"]),
            status=str(row["status"]),
            severity=str(row["severity"]),
            transition_seq=int(row["transition_seq"]),
            confidence=None if row["confidence"] is None else float(row["confidence"]),
            secret_value=None if row["secret_value"] is None else str(row["secret_value"]),
            first_seen=row["first_seen"],
            first_job_id=str(row["first_job_id"]),
        )
        for row in rows
    }


def prefetch_evidence(
    conn: psycopg.Connection[dict[str, Any]], evidence_ids: Iterable[str]
) -> dict[str, EvidenceSnapshot]:
    ids = _uuid_list(evidence_ids)
    if not ids:
        return {}
    rows = conn.execute(
        "SELECT evidence_id, sha256, storage_uri, source_tool, job_id"
        "  FROM evidence WHERE evidence_id = ANY(%s::uuid[])",
        (ids,),
    ).fetchall()
    return {
        str(row["evidence_id"]): EvidenceSnapshot(
            evidence_id=str(row["evidence_id"]),
            sha256=str(row["sha256"]),
            storage_uri=str(row["storage_uri"]),
            source_tool=str(row["source_tool"]),
            job_id=str(row["job_id"]),
        )
        for row in rows
    }


def event_ids(batch: Sequence[OutboxEvent], event_type: str, field: str) -> list[str]:
    """The `field` ids of the batch's events of `event_type`, for a prefetch."""
    return [
        str(event.payload[field])
        for event in batch
        if event.type == event_type and event.payload.get(field)
    ]


def checkpoint(
    conn: psycopg.Connection[dict[str, Any]],
    *,
    consumer: str,
    upto: int,
    dispatcher: str,
    fence: int,
    applied: Sequence[tuple[str, str]],
) -> int:
    """Record the applied events and advance the cursor, atomically and fenced.

    Neo4j is already committed when this runs (model.md: "chỉ checkpoint cursor sau khi commit
    Neo4j"), so a crash here replays the batch; `MERGE` and `consumer_inbox` make that safe.
    """
    with conn.transaction():
        if applied:
            conn.cursor().executemany(
                "INSERT INTO consumer_inbox (consumer, dedup_key, event_id) VALUES (%s, %s, %s)"
                " ON CONFLICT DO NOTHING",
                [(consumer, inbox_key, event_id) for event_id, inbox_key in applied],
            )
        row = conn.execute(
            "SELECT aegis.consumer_advance(%s, %s, %s, %s) AS cursor",
            (consumer, upto, dispatcher, fence),
        ).fetchone()
    if row is None:
        raise RuntimeError("aegis.consumer_advance returned no row")
    return int(row["cursor"])


def revision_events(
    conn: psycopg.Connection[dict[str, Any]], *, after: int, upto: int, limit: int
) -> tuple[list[deltas.DeltaRow], bool]:
    """Events in `(after, upto]` in publication order, and whether the read was truncated.

    Only the payload fields the delta needs are projected out of `jsonb` (`payload->>'field'`),
    so the emitter does not decode every event payload into Python for a batch of thousands.

    A campaign seed (`asset.discovered.v2` with `revision` 0, published by M01) is left out: it is
    projected as a node, but it belongs to no knowledge revision - it exists before the first one -
    so there is no delta to publish for it (`knowledge.delta.v2.revision` starts at 1).
    """
    rows = conn.execute(
        "SELECT seq, type, campaign_id, trace,"
        "       (payload->>'revision')::bigint AS revision,"
        "       payload->>'observation_id' AS observation_id,"
        "       payload->>'asset_id' AS asset_id,"
        "       payload->>'canonical_key' AS canonical_key,"
        "       payload->>'subject_key' AS subject_key,"
        "       payload->>'finding_id' AS finding_id,"
        "       payload->>'causal_job_id' AS causal_job_id"
        "  FROM outbox_event WHERE seq > %s AND seq <= %s"
        "   AND NOT (type = 'asset.discovered.v2'"
        "            AND coalesce((payload->>'revision')::bigint, 0) = 0)"
        " ORDER BY seq LIMIT %s",
        (after, upto, limit + 1),
    ).fetchall()
    truncated = len(rows) > limit
    events = [
        deltas.DeltaRow(
            seq=int(row["seq"]),
            type=str(row["type"]),
            campaign_id=None if row["campaign_id"] is None else str(row["campaign_id"]),
            trace=dict(row["trace"]),
            revision=None if row["revision"] is None else int(row["revision"]),
            observation_id=row["observation_id"],
            asset_id=row["asset_id"],
            canonical_key=row["canonical_key"],
            subject_key=row["subject_key"],
            finding_id=row["finding_id"],
            causal_job_id=row["causal_job_id"],
        )
        for row in rows[:limit]
    ]
    return events, truncated


def emit_deltas(
    conn: psycopg.Connection[dict[str, Any]],
    *,
    consumer: str,
    applied_cursor: int,
    watermark: int,
    dispatcher: str,
    fence: int,
    limit: int = 2000,
    maximum: int = 1000,
) -> int:
    """Publish every provably complete `knowledge.delta.v2` and advance the delta cursor.

    Returns how many deltas were written. Runs after the batch checkpoint: a crash between the two
    only re-reads events, and `(type, dedup_key)` plus `ON CONFLICT DO NOTHING` keep a rebuild or a
    retry from duplicating a delta.

    All deltas of one call are written in **one** transaction. Each `outbox_event` INSERT draws a
    publication number and therefore takes the C04 publication lock; in autocommit each insert
    queued for that lock separately behind the producers, and at 100 M27 writers the projector
    spent 22 s of a 28 s run queueing for it. One transaction per call takes the lock once.
    """
    delta_consumer = consumer + DELTA_CONSUMER_SUFFIX
    cursor = read_cursor(conn, delta_consumer)
    if applied_cursor <= cursor:
        return 0
    events, truncated_read = revision_events(conn, after=cursor, upto=applied_cursor, limit=limit)
    observation_ids = [
        row.observation_id
        for row in events
        if row.type == OBSERVATION_EVENT and row.observation_id is not None
    ]
    revisions = {
        observation_id: snapshot.revision
        for observation_id, snapshot in prefetch_observations(conn, observation_ids).items()
    }
    pairs = [
        (row, revision)
        for row in events
        if (revision := deltas.revision_of(row, revisions)) is not None
    ]
    groups = deltas.runs(pairs)
    # The last run is complete when the window reaches the publication watermark and the read was
    # not cut. A read cut by the limit is the other closing case: the run is published **once**,
    # with `truncated=true` (the consumer then calls graph.summarize_campaign_delta), because
    # deferring it would starve the emitter - the next window starts at the same run and reads the
    # same cut.
    complete = groups if (truncated_read or applied_cursor >= watermark) else groups[:-1]
    last_index = len(complete) - 1
    drafts = [
        deltas.draft(
            group,
            max_entities=maximum,
            truncated=truncated_read and index == last_index,
        )
        for index, group in enumerate(complete)
    ]
    if not drafts:
        return 0
    rows = []
    for draft in drafts:
        payload = draft.payload()
        KnowledgeDelta.model_validate(payload)
        rows.append(
            (
                str(uuid7()),
                "knowledge.delta.v2",
                "M23",
                str(draft.revision),
                draft.campaign_id,
                _jsonb(payload),
                _jsonb(draft.trace),
            )
        )
    upto = max(draft.upto_seq for draft in drafts)
    written = 0
    with conn.transaction():
        with conn.cursor() as insert_cursor:
            insert_cursor.executemany(
                "INSERT INTO outbox_event (event_id, type, producer, dedup_key, campaign_id,"
                " payload, trace) VALUES (%s, %s, %s, %s, %s, %s, %s)"
                " ON CONFLICT (type, dedup_key) DO NOTHING RETURNING event_id",
                rows,
                returning=True,
            )
            # A rebuild or a crash retry re-inserts the same revisions; the conflict makes those
            # no-ops, so count what the database actually inserted, not what was attempted.
            written = len(list(insert_cursor.results()))
        conn.execute(
            "SELECT aegis.consumer_advance(%s, %s, %s, %s)",
            (delta_consumer, upto, dispatcher, fence),
        ).fetchone()
    return written


def _jsonb(value: Mapping[str, Any]) -> Jsonb:
    return Jsonb(dict(value))
