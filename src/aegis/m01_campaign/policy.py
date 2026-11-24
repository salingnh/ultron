"""M01 policy snapshots: adopting a new RoE never edits the previous row.

`POST /campaigns/{id}/policy` appends one `policy_snapshot` row with a fresh
`roe-<n>` version (allocated by the database) and then promotes it as the
campaign's `current_policy_version`. The old snapshot stays byte-identical: 0009
forbids rewriting history and the adopt is the *only* way `current_policy_version`
moves. The reason for the change has no column of its own by contract, so it is
recorded in the audit row of the same transaction.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from .audit import record_audit
from .errors import CampaignNotFound, CampaignStateConflict

__all__ = ["TERMINAL_STATUSES", "adopt_policy"]

#: A campaign whose work has ended cannot change its execution configuration.
TERMINAL_STATUSES = frozenset({"COMPLETED", "FAILED", "CANCELLED"})


def adopt_policy(
    connection: psycopg.Connection[Any],
    *,
    campaign_id: str,
    policy: Mapping[str, Any],
    reason: str,
    actor: Mapping[str, Any],
    trace_id: str,
) -> str:
    """Append a policy snapshot and adopt it; returns the new `roe-<n>` version."""
    # A FOR UPDATE lock on the campaign row is the serialisation point of concurrent
    # adoptions and of pause/resume/cancel: the version read below cannot go stale.
    row = connection.execute(
        """
        SELECT current_policy_version, status
          FROM aegis.campaign
         WHERE campaign_id = %s
           FOR UPDATE
        """,
        (campaign_id,),
    ).fetchone()
    if row is None:
        raise CampaignNotFound(campaign_id)
    previous = str(row["current_policy_version"])
    status = str(row["status"])
    if status in TERMINAL_STATUSES:
        raise CampaignStateConflict(
            campaign_id,
            "adopt a policy",
            status,
            "an ended campaign keeps its last policy snapshot",
        )

    next_version = connection.execute(
        "SELECT aegis.next_policy_version() AS policy_version"
    ).fetchone()
    if next_version is None:  # pragma: no cover - the SQL function always returns a row
        raise RuntimeError("aegis.next_policy_version() returned no row")
    version = str(next_version["policy_version"])
    connection.execute(
        """
        INSERT INTO aegis.policy_snapshot
          (policy_version, campaign_id, policy, policy_hash, created_by)
        VALUES (%s, %s, %s, aegis.policy_hash(%s), %s)
        """,
        (version, campaign_id, Jsonb(dict(policy)), Jsonb(dict(policy)), Jsonb(dict(actor))),
    )
    connection.execute(
        "UPDATE aegis.campaign SET current_policy_version = %s WHERE campaign_id = %s",
        (version, campaign_id),
    )
    record_audit(
        connection,
        actor=actor,
        action="campaign.policy_adopt",
        trace_id=trace_id,
        campaign_id=campaign_id,
        policy_version=version,
        details={
            "previous_policy_version": previous,
            "policy_version": version,
            "reason": reason,
        },
    )
    return version
