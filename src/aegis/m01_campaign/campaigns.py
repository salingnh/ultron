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


def _row_to_wire(row: Mapping[str, Any], *, with_snapshots: bool) -> dict[str, Any]:
    campaign: dict[str, Any] = {
        "campaign_id": str(row["campaign_id"]),
        "name": row["name"],
        "objective": row["objective"],
        "status": row["status"],
        "policy_version": row["current_policy_version"],
        "scope_id": str(row["scope_id"]),
        "created_at": timestamp(row["created_at"]),
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
            "authorization": str(labels.get("authorization", "")),
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
        SELECT {CAMPAIGN_COLUMNS}, p.policy AS policy, s.targets AS targets
          FROM aegis.campaign c
          JOIN aegis.policy_snapshot p ON p.policy_version = c.current_policy_version
          JOIN aegis.scope_snapshot s ON s.scope_id = c.scope_id
         WHERE c.campaign_id = %s
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
        SELECT {CAMPAIGN_COLUMNS}
          FROM aegis.campaign c
         WHERE (%(status)s::text IS NULL OR c.status = %(status)s::text)
           AND (
             %(after_at)s::timestamptz IS NULL
             OR (c.created_at, c.campaign_id) < (%(after_at)s::timestamptz, %(after_id)s::uuid)
           )
         ORDER BY c.created_at DESC, c.campaign_id DESC
         LIMIT %(limit)s
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
