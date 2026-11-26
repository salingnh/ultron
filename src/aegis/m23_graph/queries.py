"""The six `graph.*` query functions of M23 (G1.4b).

Contract: `contracts/mcp/graph-queries.v2.schema.json` - one read-only query per entry, shared by
the MCP server (G1.2b) and the REST API (this card adds `/assets/{id}/graph` and
`/assets/{id}/history`). Every output carries `truncated` and `limits_applied`, because a reader
must be able to tell "this is all of it" from "the server cut it":

* `max_hops` 2, `limit` 200 records, `timeout_ms` 2000 are **server ceilings**; a caller may ask
  for less, `limits_applied` reports the ceiling that was in force, never the caller's number;
* `truncated` is true when a ceiling actually cut the answer (record cap, hop cap, a query that hit
  the time budget, or an excerpt cut at `max_bytes`);
* every query filters by `campaign_id`, as the contract requires.

`get_asset_neighbors` reads the Neo4j projection (edges carry `valid_from`/`valid_to`, which is what
"the graph at time T" needs); the other five read PostgreSQL, which owns the rows and the revision
order. `get_evidence_excerpt` needs the M28 evidence store (G1.3a) and refuses loudly when none is
configured instead of returning an empty excerpt that would look like real (empty) evidence.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
from neo4j import Driver
from neo4j.exceptions import Neo4jError

from aegis.common.ports import EvidenceStore

__all__ = [
    "SERVER_LIMIT",
    "SERVER_MAX_HOPS",
    "SERVER_TIMEOUT_MS",
    "DocumentNotFound",
    "EvidenceNotFound",
    "GraphQueryUnavailable",
    "get_asset_neighbors",
    "get_evidence_excerpt",
    "get_package_cve_matches",
    "get_recent_observations",
    "get_unverified_hypotheses",
    "iso_z",
    "limits_applied",
    "summarize_campaign_delta",
]

SERVER_MAX_HOPS = 2
SERVER_LIMIT = 200
SERVER_TIMEOUT_MS = 2000
#: `graph/model.md` "Dữ liệu quá hạn": a node whose `last_seen` is older than this is `stale`.
STALE_AFTER = timedelta(days=7)
MAX_EXCERPT_BYTES = 8192

DEFAULT_CONSUMER = "m23-projector#g1"


class GraphQueryUnavailable(RuntimeError):
    """A query needs a component that is not configured (evidence store, graph driver)."""


class DocumentNotFound(LookupError):
    """The requested asset/evidence does not exist; the API maps it to 404."""


class EvidenceNotFound(DocumentNotFound):
    """The evidence id is unknown for this campaign."""


def limits_applied(
    *, hops: bool = False, excerpt: bool = False, max_bytes: int = 0
) -> dict[str, int]:
    """The server ceilings in force for one call (`limits_applied` of the output schema)."""
    limits: dict[str, int] = {}
    if hops:
        limits["max_hops"] = SERVER_MAX_HOPS
    if excerpt:
        limits["max_bytes"] = min(max(max_bytes, 0), MAX_EXCERPT_BYTES)
    else:
        limits["limit"] = SERVER_LIMIT
    limits["timeout_ms"] = SERVER_TIMEOUT_MS
    return limits


def iso_z(moment: Any) -> str | None:
    """RFC 3339 in UTC with `Z`, the `Timestamp` contract format."""
    if moment is None:
        return None
    if isinstance(moment, str):
        return moment
    native = getattr(moment, "to_native", None)
    value: datetime = native() if callable(native) else moment
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _confidence(value: Any) -> float:
    return float(value) if value is not None else 1.0


# --------------------------------------------------------------------------- graph (Neo4j)


_NEIGHBORS = """
MATCH (a:Asset {canonical_key: $canonical_key})
WHERE $campaign_id IN coalesce(a.campaign_ids, [])
OPTIONAL MATCH p = (a)-[rels*1..%d]-(b:Asset)
WHERE $campaign_id IN coalesce(b.campaign_ids, [])
  AND all(n IN nodes(p) WHERE n:Asset)
  AND all(r IN rels WHERE r.campaign_id = $campaign_id)
  AND ($types IS NULL OR all(r IN rels WHERE type(r) IN $types))
  AND ($as_of IS NULL OR all(r IN rels WHERE r.valid_from <= $as_of
        AND (r.valid_to IS NULL OR r.valid_to > $as_of)))
RETURN [n IN coalesce(nodes(p), [a]) |
          {asset_id: n.asset_id, canonical_key: n.canonical_key, kind: n.kind,
           first_seen: n.first_seen, last_seen: n.last_seen}] AS nodes,
       [r IN coalesce(rels, []) |
          {type: type(r), from: startNode(r).canonical_key, to: endNode(r).canonical_key,
           observed_at: r.observed_at, valid_from: r.valid_from, valid_to: r.valid_to,
           source_job_id: r.source_job_id, confidence: r.confidence}] AS edges
LIMIT $rows
"""


def get_asset_neighbors(
    driver: Driver,
    *,
    campaign_id: str,
    canonical_key: str,
    limit: int = 50,
    max_hops: int = 1,
    relationship_types: Sequence[str] | None = None,
    as_of: str | None = None,
    stale_after: timedelta = STALE_AFTER,
) -> dict[str, Any]:
    """The asset neighbourhood of one asset, at most two hops, filtered by campaign and time.

    Only paths whose every node is an `:Asset` are walked. `contracts/graph/model.md` defines this
    answer as asset nodes and asset-to-asset edges (the ones carrying `relationship_id`);
    `AFFECTED_BY` ends at a `:Vulnerability`, `HAS_FINDING` at a `:Finding` and `DISCOVERED_FROM`
    may end at a `:Target` with no `canonical_key`, so walking through them produced an edge with
    a null endpoint that the output schema rejects (D2, item 61 trial). Candidates stay reachable
    through `get_package_cve_matches` and the REST vulnerability read model, which are per asset.
    """
    hops = max(1, min(int(max_hops), SERVER_MAX_HOPS))
    records_limit = max(1, min(int(limit), SERVER_LIMIT))
    moment = None
    if as_of is not None:
        moment = datetime.fromisoformat(as_of.replace("Z", "+00:00"))
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=UTC)
    statement = _NEIGHBORS % hops
    parameters: dict[str, Any] = {
        "canonical_key": canonical_key,
        "campaign_id": campaign_id,
        "as_of": moment,
        "types": list(relationship_types) if relationship_types else None,
        "rows": records_limit + 1,
    }
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}
    truncated = max_hops > SERVER_MAX_HOPS
    try:
        with driver.session() as session:
            result = session.run(statement, parameters, timeout=SERVER_TIMEOUT_MS / 1000)
            read = 0
            for record in result:
                read += 1
                for node in record["nodes"]:
                    if node["asset_id"] is None:
                        continue
                    nodes.setdefault(str(node["asset_id"]), dict(node))
                for edge in record["edges"]:
                    key = "|".join(
                        (
                            str(edge["type"]),
                            str(edge["from"]),
                            str(edge["to"]),
                            str(edge["valid_from"]),
                        )
                    )
                    edges.setdefault(key, dict(edge))
            result.consume()
    except Neo4jError as error:
        if "Timeout" not in (getattr(error, "code", "") or ""):
            raise
        return {
            "nodes": [],
            "edges": [],
            "truncated": True,
            "limits_applied": limits_applied(hops=True),
        }

    now = datetime.now(UTC)
    node_items: list[dict[str, Any]] = []
    for node in list(nodes.values())[:records_limit]:
        last_seen = node.get("last_seen")
        item: dict[str, Any] = {
            "asset_id": node["asset_id"],
            "canonical_key": node["canonical_key"],
            "kind": node["kind"],
        }
        if node.get("first_seen") is not None:
            item["first_seen"] = iso_z(node["first_seen"])
        if last_seen is not None:
            item["last_seen"] = iso_z(last_seen)
            native = last_seen.to_native() if hasattr(last_seen, "to_native") else last_seen
            item["stale"] = (now - native) > stale_after
        node_items.append(item)
    edge_items: list[dict[str, Any]] = []
    for edge in list(edges.values())[:records_limit]:
        edge_items.append(
            {
                "type": edge["type"],
                "from": edge["from"],
                "to": edge["to"],
                "observed_at": iso_z(edge.get("observed_at")),
                "valid_from": iso_z(edge.get("valid_from")),
                "valid_to": iso_z(edge.get("valid_to")) if edge.get("valid_to") else None,
                "source_job_id": edge["source_job_id"],
                "confidence": _confidence(edge.get("confidence")),
            }
        )
    if len(nodes) > records_limit or len(edges) > records_limit or read > records_limit:
        truncated = True
    return {
        "nodes": node_items,
        "edges": edge_items,
        "truncated": truncated,
        "limits_applied": limits_applied(hops=True),
    }


# --------------------------------------------------------------------------- relational


def revision_cursor(conn: psycopg.Connection[Any], consumer: str = DEFAULT_CONSUMER) -> int:
    """The highest revision whose changes are visible in the graph (`consumer_cursor.last_seq`).

    Publication sequences and knowledge revisions come from the same allocator (0008), so the
    projector's cursor is exactly "the last revision the graph reflects".
    """
    row = conn.execute(
        "SELECT last_seq FROM consumer_cursor WHERE consumer = %s", (consumer,)
    ).fetchone()
    if row is not None:
        return int(row["last_seq"])
    row = conn.execute(
        "SELECT coalesce(max(revision), 0) AS revision FROM graph_revision"
    ).fetchone()
    return 0 if row is None else int(row["revision"])


def _value_summary(value: Any) -> str | None:
    if value is None:
        return None
    text = (
        value if isinstance(value, str) else json.dumps(value, sort_keys=True, ensure_ascii=False)
    )
    return text[:500]


def get_recent_observations(
    conn: psycopg.Connection[Any],
    *,
    campaign_id: str,
    since_revision: int,
    limit: int = 50,
    subject: str | None = None,
    predicates: Sequence[str] | None = None,
    consumer: str = DEFAULT_CONSUMER,
) -> dict[str, Any]:
    records = max(1, min(int(limit), SERVER_LIMIT))
    rows = conn.execute(
        "SELECT o.observation_id, o.subject_asset_id, a.canonical_key AS subject, o.predicate,"
        "       o.value, o.polarity, o.confidence, o.observed_at, o.evidence_ids"
        "  FROM observation o JOIN asset a ON a.asset_id = o.subject_asset_id"
        " WHERE o.campaign_id = %s AND o.revision > %s"
        "   AND (%s::text IS NULL OR a.canonical_key = %s)"
        "   AND (%s::text[] IS NULL OR o.predicate = ANY(%s::text[]))"
        " ORDER BY o.observed_at DESC, o.observation_id DESC LIMIT %s",
        (
            campaign_id,
            int(since_revision),
            subject,
            subject,
            list(predicates) if predicates else None,
            list(predicates) if predicates else None,
            records + 1,
        ),
    ).fetchall()
    truncated = len(rows) > records
    observations: list[dict[str, Any]] = []
    for row in rows[:records]:
        item: dict[str, Any] = {
            "observation_id": str(row["observation_id"]),
            "subject": row["subject"],
            "predicate": row["predicate"],
            "polarity": row["polarity"],
            "observed_at": iso_z(row["observed_at"]),
        }
        summary = _value_summary(row["value"])
        if summary is not None:
            item["value_summary"] = summary
        if row["confidence"] is not None:
            item["confidence"] = float(row["confidence"])
        evidence = list(row["evidence_ids"] or ())
        if evidence:
            item["evidence_id"] = str(evidence[0])
        observations.append(item)
    return {
        "observations": observations,
        "revision": revision_cursor(conn, consumer),
        "truncated": truncated,
        "limits_applied": limits_applied(),
    }


def get_unverified_hypotheses(
    conn: psycopg.Connection[Any],
    *,
    campaign_id: str,
    limit: int = 50,
    min_confidence: float | None = None,
) -> dict[str, Any]:
    records = max(1, min(int(limit), SERVER_LIMIT))
    rows = conn.execute(
        # The ledger is append-only: the status to judge is the *latest* revision's, so the
        # filter runs after DISTINCT ON, never inside it.
        "WITH latest AS ("
        "  SELECT DISTINCT ON (r.hypothesis_id) r.hypothesis_id, r.claim, r.status, r.confidence,"
        "         r.revision"
        "    FROM hypothesis_revision r JOIN hypothesis h ON h.hypothesis_id = r.hypothesis_id"
        "   WHERE h.campaign_id = %s"
        "   ORDER BY r.hypothesis_id, r.revision DESC)"
        " SELECT * FROM latest"
        "  WHERE status IN ('OPEN', 'INCONCLUSIVE')"
        "    AND (%s::numeric IS NULL OR confidence >= %s::numeric)"
        "  ORDER BY confidence DESC, hypothesis_id LIMIT %s",
        (campaign_id, min_confidence, min_confidence, records + 1),
    ).fetchall()
    truncated = len(rows) > records
    hypotheses = [
        {
            "hypothesis_id": str(row["hypothesis_id"]),
            "claim": row["claim"],
            "status": row["status"],
            "confidence": float(row["confidence"]),
            "revision": int(row["revision"]),
        }
        for row in rows[:records]
    ]
    return {
        "hypotheses": hypotheses,
        "truncated": truncated,
        "limits_applied": limits_applied(),
    }


def get_package_cve_matches(
    conn: psycopg.Connection[Any],
    *,
    campaign_id: str,
    canonical_key: str,
    limit: int = 50,
    include_kev_only: bool = False,
) -> dict[str, Any]:
    records = max(1, min(int(limit), SERVER_LIMIT))
    rows = conn.execute(
        "WITH latest AS ("
        "  SELECT DISTINCT ON (m.package_asset_id, m.vulnerability_id)"
        "         m.package_asset_id, m.vulnerability_id, m.match_method, m.affected_range,"
        "         m.matched"
        "    FROM package_vuln_match m JOIN asset a ON a.asset_id = m.package_asset_id"
        "   WHERE a.canonical_key = %s"
        "   ORDER BY m.package_asset_id, m.vulnerability_id, m.created_at DESC)"
        " SELECT latest.vulnerability_id, latest.match_method, latest.affected_range,"
        "        a.canonical_key AS package, vc.cvss, vc.kev, vc.epss,"
        "        (SELECT f.finding_id FROM finding f"
        "          WHERE f.asset_id = latest.package_asset_id"
        "            AND latest.vulnerability_id = ANY(f.vulnerability_ids) LIMIT 1) AS finding_id"
        "   FROM latest JOIN asset a ON a.asset_id = latest.package_asset_id"
        "   LEFT JOIN vulnerability_current vc ON vc.vulnerability_id = latest.vulnerability_id"
        "  WHERE latest.matched"
        "    AND EXISTS (SELECT 1 FROM asset_campaign ac"
        "                 WHERE ac.asset_id = latest.package_asset_id AND ac.campaign_id = %s)"
        "    AND (%s = false OR coalesce((vc.kev->>'listed')::boolean, false))"
        "  ORDER BY latest.vulnerability_id LIMIT %s",
        (canonical_key, campaign_id, bool(include_kev_only), records + 1),
    ).fetchall()
    truncated = len(rows) > records
    matches: list[dict[str, Any]] = []
    for row in rows[:records]:
        item: dict[str, Any] = {
            "package": row["package"],
            "vulnerability_id": row["vulnerability_id"],
            "match_method": row["match_method"],
        }
        if row["affected_range"] is not None:
            item["affected_range"] = row["affected_range"]
        scores = row["cvss"] or []
        if isinstance(scores, list) and scores:
            base = (scores[0] or {}).get("base_score")
            if base is not None:
                item["cvss_base"] = float(base)
        if row["epss"]:
            item["epss"] = float(row["epss"].get("score", 0.0))
        if row["kev"] is not None:
            item["kev"] = bool(row["kev"].get("listed", False))
        if row["finding_id"] is not None:
            item["finding_id"] = str(row["finding_id"])
        matches.append(item)
    return {"matches": matches, "truncated": truncated, "limits_applied": limits_applied()}


def summarize_campaign_delta(
    conn: psycopg.Connection[Any],
    *,
    campaign_id: str,
    from_revision: int,
    to_revision: int | None = None,
    limit: int = 50,
    consumer: str = DEFAULT_CONSUMER,
) -> dict[str, Any]:
    """Counts and highlights of the revisions in `(from_revision, to_revision]`.

    Reads the `knowledge.delta.v2` events the projector published (not the graph): that is the
    contract's fallback for a consumer that received a `truncated` delta - "không quét toàn đồ thị".
    """
    records = max(1, min(int(limit), SERVER_LIMIT))
    upper = revision_cursor(conn, consumer) if to_revision is None else int(to_revision)
    rows = conn.execute(
        "SELECT payload FROM outbox_event"
        " WHERE type = 'knowledge.delta.v2' AND campaign_id = %s"
        "   AND (payload->>'revision')::bigint > %s"
        "   AND (payload->>'revision')::bigint <= %s"
        " ORDER BY (payload->>'revision')::bigint",
        (campaign_id, int(from_revision), upper),
    ).fetchall()
    counts: dict[str, int] = {}
    highlights: list[dict[str, str]] = []
    truncated = False
    for row in rows:
        payload = row["payload"]
        if payload.get("truncated"):
            truncated = True
        for entity in payload.get("changed_entities", []):
            key = f"{entity['entity_type']}.{entity['change']}"
            counts[key] = counts.get(key, 0) + 1
            if len(highlights) < min(records, 30):
                reference = entity.get("canonical_key") or entity["entity_id"]
                highlights.append(
                    {
                        "ref": str(reference),
                        "summary": f"{entity['entity_type']} {entity['change']} {reference}"[:500],
                    }
                )
            elif len(highlights) >= 30:
                truncated = True
    if len(highlights) > min(records, 30):
        truncated = True
    return {
        "from_revision": int(from_revision),
        "to_revision": upper,
        "counts": counts,
        "highlights": highlights[: min(records, 30)],
        "truncated": truncated,
        "limits_applied": limits_applied(),
    }


def get_evidence_excerpt(
    conn: psycopg.Connection[Any],
    store: EvidenceStore | None,
    *,
    campaign_id: str,
    evidence_id: str,
    offset: int = 0,
    max_bytes: int = 4096,
    limit: int = 50,
) -> dict[str, Any]:
    """A bounded excerpt of one evidence object, always UNTRUSTED for the caller's prompt."""
    row = conn.execute(
        "SELECT evidence_id, sha256, size_bytes, media_type FROM evidence"
        " WHERE evidence_id = %s AND campaign_id = %s",
        (evidence_id, campaign_id),
    ).fetchone()
    if row is None:
        raise EvidenceNotFound(evidence_id)
    if store is None:
        raise GraphQueryUnavailable(
            "no evidence store is configured (M28/G1.3a owns evidence content); "
            "the excerpt cannot be served from metadata alone"
        )
    capped = min(max(int(max_bytes), 64), MAX_EXCERPT_BYTES)
    excerpt = store.excerpt(evidence_id, int(offset), capped)
    text = excerpt.data.decode("utf-8", errors="replace")
    total = int(row["size_bytes"])
    return {
        "evidence_id": str(row["evidence_id"]),
        "sha256": row["sha256"],
        "media_type": row["media_type"],
        "excerpt": text,
        "total_bytes": total,
        "truncated": bool(excerpt.truncated) or (int(offset) + len(excerpt.data)) < total,
        "limits_applied": limits_applied(excerpt=True, max_bytes=capped),
    }
