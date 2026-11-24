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

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

__all__ = [
    "CAPS",
    "DEFAULTS",
    "GraphLimits",
    "GraphQueryResult",
    "GraphQueryService",
    "GraphUnavailable",
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
    """No projection is wired (G1.4b has not landed); the caller must not read an empty answer."""


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
    """The G1.2b default: the interface exists, the projection does not."""

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
