"""`BuildContext`'s read model: what a session may know before it reasons (read-only, one shot).

`fetch_delta(campaign_id, cursor) -> ContextBundle` is the interface activity (interfaces §7). This
module is its M03 half: a set of read-only queries over the campaign's own rows (M01's targets,
M27's
observations, M05's `scan_job` status, M04's `model_usage` spend, M03's `agent_session` count) that
fills a `context-bundle.v2` document. Nothing here writes except the ledger entries the session
records elsewhere.

Why the database and not only `graph.*`: M23's projection is the authoritative read path
(`contracts/interfaces/README.md` §ContextBundle), and the session prefers it -
`nodes.build_context` asks `graph.get_recent_observations` first and uses its typed output. Until
G1.4b wires M23 that call
answers `DEPENDENCY_MISSING`, so this read model is the honest fallback: it reads the same M27 rows
the projector would, records a `blocker` ledger entry saying the graph path is unavailable, and
keeps
the campaign runnable on the lab.

Every field a session puts in front of the model is either typed data or text that
`prompt.py` wraps as untrusted; a seed's raw value is the reason `Observation.untrusted` exists.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

__all__ = [
    "CampaignContext",
    "ContextSource",
    "ContextSourceError",
    "PostgresContextSource",
    "UNBOUNDED",
]

#: `Budget.remaining_tokens`/`remaining_cost_usd` are plain numbers (M04); a policy that sets no
#: token or cost ceiling is expressed as this ceiling rather than as a zero budget.
UNBOUNDED = 1_000_000_000
#: context-bundle.v2 caps: 10..30 observations (design), 2000 chars of untrusted text per item.
MAX_OBSERVATIONS = 30
MAX_UNTRUSTED = 2000
MAX_SUMMARY = 1000


class ContextSourceError(RuntimeError):
    """The campaign the session was asked to work on cannot be read (missing or no policy)."""


@dataclass(frozen=True, slots=True)
class CampaignContext:
    """The read model one session builds its bundle from."""

    campaign_id: str
    objective_text: str
    policy_version: str
    policy: Mapping[str, Any]
    graph_revision: int
    #: M01 seed targets: [{"target_id", "kind", "raw_value", "canonical_key"}]
    targets: tuple[Mapping[str, Any], ...] = ()
    #: M27 observations (newest first): [{"observation_id", "subject", "predicate", "value",
    #: "revision", "confidence"}]
    observations: tuple[Mapping[str, Any], ...] = ()
    #: M05 jobs of the campaign: [{"job_id", "capability", "status"}]
    jobs: tuple[Mapping[str, Any], ...] = ()
    spent_tokens: int = 0
    spent_cost_usd: float = 0.0
    sessions_used: int = 0
    idle_cycles: int = 0
    detail: dict[str, Any] = field(default_factory=dict)

    def budget_item(self, key: str, default: Any = None) -> Any:
        budget = self.policy.get("budget") or {}
        return budget.get(key, default) if isinstance(budget, Mapping) else default


class ContextSource(Protocol):
    """Read-only campaign view for one session (the `fetch_delta` seam)."""

    def load(self, campaign_id: str, *, cursor: int) -> CampaignContext: ...


class PostgresContextSource:
    """The read model over PostgreSQL; one connection, one transaction, read-only statements."""

    def __init__(self, connect: Any) -> None:
        self._connect = connect

    def load(self, campaign_id: str, *, cursor: int) -> CampaignContext:
        del cursor  # the caller passes the cursor to the graph query; the read model is current
        with self._connect() as conn, conn.transaction():
            conn.execute("SET TRANSACTION READ ONLY")
            campaign = conn.execute(
                """
                SELECT c.objective, c.current_policy_version, p.policy, c.scope_id
                  FROM campaign c
                  JOIN policy_snapshot p ON p.policy_version = c.current_policy_version
                 WHERE c.campaign_id = %s
                """,
                (campaign_id,),
            ).fetchone()
            if campaign is None:
                raise ContextSourceError(
                    f"campaign {campaign_id} does not exist or has no policy snapshot"
                )
            targets = conn.execute(
                """
                SELECT target_id, kind, raw_value, canonical_key
                  FROM campaign_target WHERE scope_id = %s
                 ORDER BY created_at, target_id
                """,
                (str(campaign["scope_id"]),),
            ).fetchall()
            observations = conn.execute(
                """
                SELECT o.observation_id, o.predicate, o.value, o.revision, o.confidence,
                       a.canonical_key AS subject
                  FROM observation o
                  JOIN asset a ON a.asset_id = o.subject_asset_id
                 WHERE o.campaign_id = %s
                 ORDER BY o.revision DESC, o.observed_at DESC
                 LIMIT %s
                """,
                (campaign_id, MAX_OBSERVATIONS),
            ).fetchall()
            revision = conn.execute(
                "SELECT coalesce(max(revision), 0) AS revision FROM graph_revision "
                "WHERE campaign_id = %s",
                (campaign_id,),
            ).fetchone()
            jobs = conn.execute(
                """
                SELECT job_id, capability, status FROM scan_job
                 WHERE campaign_id = %s ORDER BY created_at DESC, job_id DESC LIMIT 200
                """,
                (campaign_id,),
            ).fetchall()
            spend = conn.execute(
                """
                SELECT coalesce(sum(input_tokens + output_tokens), 0) AS tokens,
                       coalesce(sum(cost_usd), 0) AS cost
                  FROM model_usage WHERE campaign_id = %s
                """,
                (campaign_id,),
            ).fetchone()
            sessions = conn.execute(
                "SELECT count(*) AS n FROM agent_session WHERE campaign_id = %s", (campaign_id,)
            ).fetchone()
            idle = conn.execute(
                """
                SELECT kind FROM campaign_ledger
                 WHERE campaign_id = %s AND kind IN ('cycle_finished', 'idle_cycle')
                 ORDER BY seq DESC LIMIT 50
                """,
                (campaign_id,),
            ).fetchall()
        return CampaignContext(
            campaign_id=campaign_id,
            objective_text=str(campaign["objective"]),
            policy_version=str(campaign["current_policy_version"]),
            policy=dict(campaign["policy"] or {}),
            graph_revision=int(revision["revision"]) if revision else 0,
            targets=tuple(
                {
                    "target_id": str(row["target_id"]),
                    "kind": str(row["kind"]),
                    "raw_value": str(row["raw_value"]),
                    "canonical_key": (
                        None if row["canonical_key"] is None else str(row["canonical_key"])
                    ),
                }
                for row in targets
            ),
            observations=tuple(
                {
                    "observation_id": str(row["observation_id"]),
                    "subject": str(row["subject"]),
                    "predicate": str(row["predicate"]),
                    "value": row["value"],
                    "revision": int(row["revision"]),
                    "confidence": None if row["confidence"] is None else float(row["confidence"]),
                }
                for row in observations
            ),
            jobs=tuple(
                {
                    "job_id": str(row["job_id"]),
                    "capability": str(row["capability"]),
                    "status": str(row["status"]),
                }
                for row in jobs
            ),
            spent_tokens=int(spend["tokens"]) if spend else 0,
            spent_cost_usd=float(spend["cost"]) if spend else 0.0,
            sessions_used=int(sessions["n"]) if sessions else 0,
            idle_cycles=_trailing_idle(idle),
        )


def _trailing_idle(rows: list[Mapping[str, Any]]) -> int:
    """Consecutive idle cycles at the end of the campaign's ledger (newest first)."""
    count = 0
    for row in rows:
        if str(row["kind"]) != "idle_cycle":
            break
        count += 1
    return count
