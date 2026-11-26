"""M01 campaign repository: create, read and list (the campaign.v2 read model).

The wire shape is built here and validated by the router against
`campaign/campaign.v2.schema.json`; this module never invents a field the contract
does not publish. One create is one transaction: the scope snapshot, the seed rows,
the first policy snapshot, the campaign row, its status history and the audit row
are committed together or not at all, so `campaign.current_policy_version` and
`scope_id` can never point at a row that does not exist.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from .audit import record_audit
from .ids import new_id
from .targets import SeedTarget, insert_seed_assets, insert_seeds

__all__ = [
    "CreatedCampaign",
    "create_campaign",
    "get_campaign",
    "list_campaigns",
]

CAMPAIGN_COLUMNS = """
  c.campaign_id, c.name, c.objective, c.status, c.status_reason,
  c.current_policy_version, c.scope_id, c.created_at, c.started_at, c.ended_at
"""


@dataclass(frozen=True, slots=True)
class CreatedCampaign:
    """The 202 body of POST /campaigns (contract: campaign-create response)."""

    campaign_id: str
    status: str
    policy_version: str
    scope_id: str

    def as_response(self) -> dict[str, str]:
        return {
            "campaign_id": self.campaign_id,
            "status": self.status,
            "policy_version": self.policy_version,
            "scope_id": self.scope_id,
        }


def timestamp(value: datetime) -> str:
    """Contract Timestamp: RFC 3339 in UTC with a `Z` suffix."""
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


_STATS_CTES = """
job_status_counts AS (
  SELECT j.campaign_id, j.status, count(*)::bigint AS cnt
    FROM aegis.scan_job j
   WHERE j.campaign_id IN (SELECT campaign_id FROM page)
   GROUP BY j.campaign_id, j.status
),
job_agg AS (
  SELECT campaign_id,
         jsonb_object_agg(status, cnt) AS jobs_by_status,
         coalesce(sum(cnt) FILTER (WHERE status <> 'CANCELLED'), 0)::bigint AS jobs_used
    FROM job_status_counts
   GROUP BY campaign_id
),
asset_kind_counts AS (
  SELECT ac.campaign_id, a.kind, count(*)::bigint AS cnt
    FROM aegis.asset_campaign ac
    JOIN aegis.asset a ON a.asset_id = ac.asset_id
   WHERE ac.campaign_id IN (SELECT campaign_id FROM page)
   GROUP BY ac.campaign_id, a.kind
),
asset_agg AS (
  SELECT campaign_id,
         jsonb_object_agg(kind, cnt) AS assets_by_kind
    FROM asset_kind_counts
   GROUP BY campaign_id
),
usage_agg AS (
  SELECT u.campaign_id,
         coalesce(sum(u.input_tokens::bigint + u.output_tokens::bigint), 0)::bigint AS tokens_used,
         coalesce(sum(u.cost_usd), 0)::double precision AS cost_used,
         bool_or(u.input_tokens < 0 OR u.output_tokens < 0 OR u.cost_usd < 0) AS has_negative
    FROM aegis.model_usage u
   WHERE u.campaign_id IN (SELECT campaign_id FROM page)
   GROUP BY u.campaign_id
),
session_agg AS (
  SELECT s.campaign_id, count(*)::bigint AS sessions_used
    FROM aegis.agent_session s
   WHERE s.campaign_id IN (SELECT campaign_id FROM page)
   GROUP BY s.campaign_id
)
"""

_STATS_SELECT = """
  pg.*,
  now() AS as_of,
  coalesce(ja.jobs_by_status, '{}'::jsonb) AS jobs_by_status,
  coalesce(ja.jobs_used, 0)::bigint AS jobs_used,
  coalesce(aa.assets_by_kind, '{}'::jsonb) AS assets_by_kind,
  coalesce(ua.tokens_used, 0)::bigint AS tokens_used,
  coalesce(ua.cost_used, 0.0)::double precision AS cost_used,
  coalesce(ua.has_negative, false) AS has_negative_usage,
  coalesce(sa.sessions_used, 0)::bigint AS sessions_used
"""

_STATS_JOINS = """
  LEFT JOIN job_agg ja ON ja.campaign_id = pg.campaign_id
  LEFT JOIN asset_agg aa ON aa.campaign_id = pg.campaign_id
  LEFT JOIN usage_agg ua ON ua.campaign_id = pg.campaign_id
  LEFT JOIN session_agg sa ON sa.campaign_id = pg.campaign_id
"""


def _counters_of(row: Mapping[str, Any]) -> dict[str, dict[str, int]]:
    jobs_raw = row.get("jobs_by_status") or {}
    assets_raw = row.get("assets_by_kind") or {}
    return {
        "jobs_by_status": {str(key): int(val) for key, val in jobs_raw.items()},
        "assets_by_kind": {str(key): int(val) for key, val in assets_raw.items()},
    }


def _budget_of(row: Mapping[str, Any]) -> dict[str, Any]:
    if row.get("has_negative_usage"):
        raise ValueError(f"campaign {row['campaign_id']} has negative model_usage rows")
    policy = row["policy"] or {}
    policy_budget = policy.get("budget") or {}
    max_hours = int(policy["max_duration_hours"])
    limits: dict[str, Any] = {"max_duration_hours": max_hours}
    if policy_budget.get("max_llm_cost_usd") is not None:
        limits["max_llm_cost_usd"] = float(policy_budget["max_llm_cost_usd"])
    if policy_budget.get("max_llm_tokens") is not None:
        limits["max_llm_tokens"] = int(policy_budget["max_llm_tokens"])
    if policy_budget.get("max_jobs") is not None:
        limits["max_jobs"] = int(policy_budget["max_jobs"])
    if policy_budget.get("max_agent_sessions") is not None:
        limits["max_agent_sessions"] = int(policy_budget["max_agent_sessions"])

    started_at = row["started_at"]
    ended_at = row["ended_at"]
    as_of = row["as_of"]
    if started_at is None:
        hours_used = 0.0
    else:
        hours_used = round(max(0.0, ((ended_at or as_of) - started_at).total_seconds() / 3600.0), 6)

    used: dict[str, Any] = {
        "hours": hours_used,
        "llm_cost_usd": round(float(row["cost_used"] or 0.0), 6),
        "llm_tokens": int(row["tokens_used"] or 0),
        "jobs": int(row["jobs_used"] or 0),
        "agent_sessions": int(row["sessions_used"] or 0),
    }

    remaining: dict[str, Any] = {"hours": round(max(0.0, float(max_hours) - hours_used), 6)}
    if "max_llm_cost_usd" in limits:
        remaining["llm_cost_usd"] = round(
            max(0.0, float(limits["max_llm_cost_usd"]) - used["llm_cost_usd"]), 6
        )
    if "max_llm_tokens" in limits:
        remaining["llm_tokens"] = max(0, int(limits["max_llm_tokens"]) - used["llm_tokens"])
    if "max_jobs" in limits:
        remaining["jobs"] = max(0, int(limits["max_jobs"]) - used["jobs"])
    if "max_agent_sessions" in limits:
        remaining["agent_sessions"] = max(
            0, int(limits["max_agent_sessions"]) - used["agent_sessions"]
        )

    return {"limits": limits, "used": used, "remaining": remaining}


def _row_to_wire(row: Mapping[str, Any], *, with_snapshots: bool) -> dict[str, Any]:
    campaign: dict[str, Any] = {
        "campaign_id": str(row["campaign_id"]),
        "name": row["name"],
        "objective": row["objective"],
        "status": row["status"],
        "policy_version": row["current_policy_version"],
        "scope_id": str(row["scope_id"]),
        "created_at": timestamp(row["created_at"]),
        "counters": _counters_of(row),
        "budget": _budget_of(row),
    }
    if row["status_reason"] is not None:
        campaign["status_reason"] = row["status_reason"]
    if row["started_at"] is not None:
        campaign["started_at"] = timestamp(row["started_at"])
    if row["ended_at"] is not None:
        campaign["ended_at"] = timestamp(row["ended_at"])
    if with_snapshots:
        # campaign-create.v2#/$defs/Targets is stored verbatim; roe-policy.v2 is the snapshot row.
        campaign["policy"] = row["policy"]
        campaign["targets"] = row["targets"]
    return campaign


def create_campaign(
    connection: psycopg.Connection[Any],
    *,
    body: Mapping[str, Any],
    actor: Mapping[str, Any],
    trace_id: str,
) -> CreatedCampaign:
    """Insert the whole campaign aggregate for an already contract-validated body."""
    campaign_id = new_id()
    scope_id = new_id()
    targets = body["targets"]
    policy = body["policy"]

    # FK campaign_scope_fk is DEFERRABLE INITIALLY DEFERRED, so the snapshot and its
    # seeds are written before the campaign row they belong to.
    connection.execute(
        """
        INSERT INTO aegis.scope_snapshot (scope_id, campaign_id, targets)
        VALUES (%s, %s, %s)
        """,
        (scope_id, campaign_id, Jsonb(targets)),
    )
    seeds = insert_seeds(connection, scope_id=scope_id, targets=targets)

    policy_version = connection.execute(
        "SELECT aegis.next_policy_version() AS policy_version"
    ).fetchone()
    if policy_version is None:  # pragma: no cover - the SQL function always returns a row
        raise RuntimeError("aegis.next_policy_version() returned no row")
    version = str(policy_version["policy_version"])
    connection.execute(
        """
        INSERT INTO aegis.policy_snapshot
          (policy_version, campaign_id, policy, policy_hash, created_by)
        VALUES (%s, %s, %s, aegis.policy_hash(%s), %s)
        """,
        (version, campaign_id, Jsonb(policy), Jsonb(policy), Jsonb(dict(actor))),
    )

    connection.execute(
        """
        INSERT INTO aegis.campaign
          (campaign_id, name, objective, status, current_policy_version, scope_id,
           labels, created_by)
        VALUES (%s, %s, %s, 'CREATED', %s, %s, %s, %s)
        """,
        (
            campaign_id,
            body["name"],
            body["objective"],
            version,
            scope_id,
            Jsonb(dict(body.get("labels") or {})),
            Jsonb(dict(actor)),
        ),
    )
    # The seed targets become assets in the same transaction (see `insert_seed_assets`), after the
    # campaign row exists: `asset_campaign` has a non-deferrable foreign key to it. M27 can then
    # resolve a seed as a coverage subject and as a relationship parent, and the asset graph has
    # the campaign's seeds before the first job runs.
    insert_seed_assets(connection, campaign_id=campaign_id, seeds=seeds, trace_id=trace_id)
    connection.execute(
        """
        INSERT INTO aegis.campaign_status_change
          (campaign_id, seq, from_status, to_status, reason, actor, trace_id)
        VALUES (%s, 1, NULL, 'CREATED', NULL, %s, %s)
        """,
        (campaign_id, Jsonb(dict(actor)), trace_id),
    )

    counts = _counts_by_array(seeds)
    labels = body.get("labels") or {}
    record_audit(
        connection,
        actor=actor,
        action="campaign.create",
        trace_id=trace_id,
        campaign_id=campaign_id,
        policy_version=version,
        scope_id=scope_id,
        details={
            "policy_version": version,
            "scope_id": scope_id,
            "targets": counts,
            # The network profile is the campaign's declared scanning network (G1.6) and the
            # authorization reference is the operator's statement that the targets are his; both
            # belong to the immutable trail next to the RoE snapshot, not only to the row.
            "network_profile": str((policy or {}).get("network_profile") or "internet"),
            # The structured authorization of the RoE (owner, reference, date, suffixes); the free
            # text label stays on the campaign row for humans, the audit carries the signed source.
            "authorization": (policy or {}).get("authorization") or {},
            "labels": dict(labels),
        },
    )
    return CreatedCampaign(campaign_id, "CREATED", version, scope_id)


_ARRAY_OF_KIND = {
    "domain": "domains",
    "ip": "ips",
    "cidr": "ips",
    "url": "urls",
    "email": "emails",
    "keyword": "keywords",
}


def _counts_by_array(seeds: Sequence[SeedTarget]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for seed in seeds:
        array = _ARRAY_OF_KIND[seed.kind]
        counts[array] = counts.get(array, 0) + 1
    return counts


def get_campaign(connection: psycopg.Connection[Any], campaign_id: str) -> dict[str, Any] | None:
    """The campaign.v2 read model of one campaign, or None when it does not exist."""
    row = connection.execute(
        f"""
        WITH page AS (
          SELECT {CAMPAIGN_COLUMNS}, p.policy AS policy, s.targets AS targets
            FROM aegis.campaign c
            JOIN aegis.policy_snapshot p ON p.policy_version = c.current_policy_version
            JOIN aegis.scope_snapshot s ON s.scope_id = c.scope_id
           WHERE c.campaign_id = %s
        ),
        {_STATS_CTES}
        SELECT {_STATS_SELECT}
          FROM page pg
          {_STATS_JOINS}
        """,
        (campaign_id,),
    ).fetchone()
    return None if row is None else _row_to_wire(row, with_snapshots=True)


def list_campaigns(
    connection: psycopg.Connection[Any],
    *,
    status: str | None,
    limit: int,
    after: tuple[datetime, str] | None = None,
) -> tuple[list[dict[str, Any]], tuple[datetime, str] | None]:
    """One page of campaigns, newest first, keyset-paginated by (created_at, campaign_id)."""
    after_at = after[0] if after else None
    after_id = after[1] if after else None
    rows = connection.execute(
        f"""
        WITH page AS (
          SELECT {CAMPAIGN_COLUMNS}, p.policy AS policy
            FROM aegis.campaign c
            JOIN aegis.policy_snapshot p ON p.policy_version = c.current_policy_version
           WHERE (%(status)s::text IS NULL OR c.status = %(status)s::text)
             AND (
               %(after_at)s::timestamptz IS NULL
               OR (c.created_at, c.campaign_id) < (%(after_at)s::timestamptz, %(after_id)s::uuid)
             )
           ORDER BY c.created_at DESC, c.campaign_id DESC
           LIMIT %(limit)s
        ),
        {_STATS_CTES}
        SELECT {_STATS_SELECT}
          FROM page pg
          {_STATS_JOINS}
         ORDER BY pg.created_at DESC, pg.campaign_id DESC
        """,
        {
            "status": status,
            "after_at": after_at,
            "after_id": after_id,
            "limit": limit + 1,
        },
    ).fetchall()

    page = rows[:limit]
    next_after: tuple[datetime, str] | None = None
    if len(rows) > limit and page:
        last = page[-1]
        next_after = (last["created_at"], str(last["campaign_id"]))
    return [_row_to_wire(row, with_snapshots=False) for row in page], next_after
