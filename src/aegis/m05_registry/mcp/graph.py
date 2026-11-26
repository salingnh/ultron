"""The contract's six read-only `graph.*` tools, and the server-side caps applied to them.

`contracts/mcp/graph-queries.v2.schema.json` defines the interface and M23 owns the projection. This
module is the **boundary**: it names the tools from the contract (never a second list), enforces the
caps the contract states for the M23 side (<=2 hops, <=200 records, 2 s, <=8192 excerpt bytes) and
always composes `truncated` + `limits_applied` from the server's own caps, so a client cannot widen
a limit and a caller can tell "everything" from "cut off".

Until G1.4b lands there is no projection to read. The default service refuses loudly
(`GraphUnavailable` -> `DEPENDENCY_MISSING`) instead of answering an empty page: `truncated=false`
with no records is a claim that the campaign knows nothing, which would be a lie about an
unbuilt component. G1.4b swaps in a provider; the interface and the limits do not change.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, cast

import psycopg
from neo4j import Driver
from neo4j.exceptions import Neo4jError
from psycopg.rows import dict_row

from aegis.common.ports import EvidenceStore
from aegis.m23_graph import queries as m23_queries

__all__ = [
    "CAPS",
    "DEFAULTS",
    "GraphInputError",
    "GraphLimits",
    "GraphQueryResult",
    "GraphQueryService",
    "GraphUnavailable",
    "M23GraphQueries",
    "UnavailableGraphQueries",
    "limits_for",
]

# Server ceilings, from the graph-queries.v2 descriptions (M23 applies the same numbers).
CAPS: Mapping[str, int] = {"max_hops": 2, "limit": 200, "timeout_ms": 2000, "max_bytes": 8192}
# Contract defaults for a call that does not name the value (schema `default`s).
DEFAULTS: Mapping[str, int] = {"max_hops": 1, "limit": 50, "max_bytes": 4096}
TIMEOUT_MS = CAPS["timeout_ms"]


@dataclass(frozen=True, slots=True)
class GraphLimits:
    """The ceilings applied to one call; serialised as the output's `limits_applied`."""

    applied: Mapping[str, int] = field(default_factory=dict)

    def as_json(self) -> dict[str, int]:
        return dict(self.applied)


def limits_for(query: str, inputs: Mapping[str, Any]) -> GraphLimits:
    """Clamp the call to the server caps and return the ceilings that apply to it.

    The keys come from the contract output (`limits_applied.required`): the neighbours query caps
    hops, the evidence excerpt caps bytes, every query caps records and time. The value is the
    ceiling actually applied - the client's smaller request counts, a larger one is refused by the
    input schema before this point.
    """
    applied: dict[str, int] = {}
    if query == "get_asset_neighbors":
        applied["max_hops"] = _cap(inputs.get("max_hops"), "max_hops")
    if query == "get_evidence_excerpt":
        # The excerpt output caps bytes, not records (graph-queries.v2 `limits_applied`).
        applied["max_bytes"] = _cap(inputs.get("max_bytes"), "max_bytes")
    else:
        applied["limit"] = _cap(inputs.get("limit"), "limit")
    applied["timeout_ms"] = TIMEOUT_MS
    return GraphLimits(applied=applied)


def _cap(requested: Any, name: str) -> int:
    value = DEFAULTS.get(name, CAPS[name])
    if isinstance(requested, int) and not isinstance(requested, bool):
        value = requested
    return max(1, min(value, CAPS[name]))


@dataclass(frozen=True, slots=True)
class GraphQueryResult:
    """What a projection returns: the query's own fields, plus whether a ceiling cut the answer."""

    data: Mapping[str, Any]
    truncated: bool = False


class GraphUnavailable(RuntimeError):
    """No projection is wired (or a required backend is absent); never answer empty."""


class GraphInputError(ValueError):
    """A graph query referenced a missing record for the bound campaign (e.g. evidence id)."""


class GraphQueryService(Protocol):
    def run(
        self,
        query: str,
        inputs: Mapping[str, Any],
        *,
        campaign_id: str,
        limits: GraphLimits,
    ) -> GraphQueryResult:
        """Answer one query for one campaign; `campaign_id` is the bound session's campaign."""
        ...


class UnavailableGraphQueries:
    """Fallback test double: refuses loudly instead of claiming an empty graph."""

    def run(
        self,
        query: str,
        inputs: Mapping[str, Any],
        *,
        campaign_id: str,
        limits: GraphLimits,
    ) -> GraphQueryResult:
        raise GraphUnavailable(
            f"graph.{query} needs the M23 projection (G1.4b); it is not wired in this deployment"
        )


class M23GraphQueries:
    """M23 projection-backed `GraphQueryService` for all six `graph.*` tools."""

    def __init__(
        self,
        connect: Callable[[], psycopg.Connection[Any]],
        *,
        driver: Driver | None = None,
        store: EvidenceStore | None = None,
    ) -> None:
        self._connect = connect
        self._driver = driver
        self._store = store

    def run(
        self,
        query: str,
        inputs: Mapping[str, Any],
        *,
        campaign_id: str,
        limits: GraphLimits,
    ) -> GraphQueryResult:
        if query == "get_asset_neighbors":
            if self._driver is None:
                raise GraphUnavailable(
                    "graph.get_asset_neighbors needs Neo4j: set "
                    "AEGIS_NEO4J_URI, AEGIS_NEO4J_USER and AEGIS_NEO4J_PASSWORD"
                )
            try:
                payload = m23_queries.get_asset_neighbors(
                    self._driver,
                    campaign_id=campaign_id,
                    canonical_key=str(inputs["canonical_key"]),
                    limit=limits.applied["limit"],
                    max_hops=limits.applied["max_hops"],
                    relationship_types=inputs.get("relationship_types"),
                    as_of=inputs.get("as_of"),
                )
            except Neo4jError as error:
                raise GraphUnavailable(f"graph.{query} unavailable: {error}") from error
        else:
            try:
                payload = self._run_relational(
                    query, inputs, campaign_id=campaign_id, limits=limits
                )
            except m23_queries.GraphQueryUnavailable as error:
                raise GraphUnavailable(str(error)) from error
            except m23_queries.DocumentNotFound as error:
                raise GraphInputError(str(error)) from error
        truncated = bool(payload.pop("truncated", False))
        payload.pop("limits_applied", None)
        return GraphQueryResult(data=payload, truncated=truncated)

    def _run_relational(
        self,
        query: str,
        inputs: Mapping[str, Any],
        *,
        campaign_id: str,
        limits: GraphLimits,
    ) -> dict[str, Any]:
        with self._connect() as conn:
            conn.row_factory = cast(Any, dict_row)
            conn.execute("SET search_path = aegis, public")
            if query == "get_recent_observations":
                return m23_queries.get_recent_observations(
                    conn,
                    campaign_id=campaign_id,
                    since_revision=int(inputs["since_revision"]),
                    limit=limits.applied["limit"],
                    subject=inputs.get("subject"),
                    predicates=inputs.get("predicates"),
                )
            if query == "get_unverified_hypotheses":
                return m23_queries.get_unverified_hypotheses(
                    conn,
                    campaign_id=campaign_id,
                    limit=limits.applied["limit"],
                    min_confidence=inputs.get("min_confidence"),
                )
            if query == "get_package_cve_matches":
                return m23_queries.get_package_cve_matches(
                    conn,
                    campaign_id=campaign_id,
                    canonical_key=str(inputs["canonical_key"]),
                    limit=limits.applied["limit"],
                    include_kev_only=bool(inputs.get("include_kev_only", False)),
                )
            if query == "summarize_campaign_delta":
                return m23_queries.summarize_campaign_delta(
                    conn,
                    campaign_id=campaign_id,
                    from_revision=int(inputs["from_revision"]),
                    to_revision=inputs.get("to_revision"),
                    limit=limits.applied["limit"],
                )
            if query == "get_evidence_excerpt":
                return m23_queries.get_evidence_excerpt(
                    conn,
                    self._store,
                    campaign_id=campaign_id,
                    evidence_id=str(inputs["evidence_id"]),
                    offset=int(inputs.get("offset", 0)),
                    max_bytes=limits.applied["max_bytes"],
                )
        raise GraphInputError(f"unknown graph query: {query}")
