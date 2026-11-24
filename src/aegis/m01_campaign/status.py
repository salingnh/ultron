"""M01 campaign state transitions: pause, resume, cancel (with status history).

The REST action is safe to resend: when the target state is already reached the call
answers with the current state and writes no history row. Every real transition
writes one `campaign_status_change` row and one audit row in the same transaction.

Signalling the campaign workflow (M02/Temporal) is *not* done here: G1.1d owns the
workflow, and this transition point is the seam it must hook. Until then the REST
API is still the single writer of `campaign.status`, which keeps the read model
consistent for the UI.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from .audit import record_audit
from .campaigns import get_campaign
from .errors import CampaignNotFound, CampaignStateConflict

__all__ = ["ACTIONS", "Transition", "change_status"]


@dataclass(frozen=True, slots=True)
class Transition:
    """Allowed source states of one action and the state it moves to."""

    to_status: str
    allowed_from: frozenset[str]
    #: Source states that already satisfy the intent: answer 200 without a history row.
    satisfied_by: frozenset[str]


ACTIONS: dict[str, Transition] = {
    "pause": Transition(
        "PAUSED",
        frozenset({"CREATED", "RUNNING", "WAITING"}),
        frozenset({"PAUSED"}),
    ),
    "resume": Transition(
        "RUNNING",
        frozenset({"PAUSED"}),
        frozenset({"CREATED", "RUNNING", "WAITING"}),
    ),
    "cancel": Transition(
        "CANCELLED",
        frozenset({"CREATED", "RUNNING", "WAITING", "PAUSED"}),
        frozenset({"CANCELLED"}),
    ),
}

_ENDED = frozenset({"COMPLETED", "FAILED", "CANCELLED"})


def change_status(
    connection: psycopg.Connection[Any],
    *,
    campaign_id: str,
    action: str,
    reason: str | None,
    actor: Mapping[str, Any],
    trace_id: str,
) -> dict[str, Any]:
    """Apply one action and return the campaign.v2 read model after it."""
    transition = ACTIONS.get(action)
    if transition is None:  # pragma: no cover - the router only exposes the three actions
        raise ValueError(f"unknown campaign action {action!r}")

    row = connection.execute(
        "SELECT status FROM aegis.campaign WHERE campaign_id = %s FOR UPDATE",
        (campaign_id,),
    ).fetchone()
    if row is None:
        raise CampaignNotFound(campaign_id)
    status = str(row["status"])

    if status in transition.satisfied_by:
        current = get_campaign(connection, campaign_id)
        if current is None:  # pragma: no cover - locked row exists in this transaction
            raise CampaignNotFound(campaign_id)
        return current

    if status not in transition.allowed_from:
        detail = (
            "an ended campaign cannot change state"
            if status in _ENDED
            else f"allowed from {sorted(transition.allowed_from)}"
        )
        raise CampaignStateConflict(campaign_id, action, status, detail)

    target = transition.to_status
    # `status_reason` explains the state the campaign is in now: a pause/cancel keeps
    # the operator's reason, a resume has no reason to record on the RUNNING state
    # (its reason lives in the history row and the audit row).
    status_reason = None if target == "RUNNING" else (reason or None)
    connection.execute(
        """
        UPDATE aegis.campaign
           SET status = %s,
               status_reason = %s,
               started_at = CASE
                              WHEN %s = 'RUNNING' AND started_at IS NULL THEN now()
                              ELSE started_at
                            END,
               ended_at = CASE WHEN %s THEN now() ELSE ended_at END
         WHERE campaign_id = %s
        """,
        (target, status_reason, target, target == "CANCELLED", campaign_id),
    )
    connection.execute(
        """
        INSERT INTO aegis.campaign_status_change
          (campaign_id, seq, from_status, to_status, reason, actor, trace_id)
        SELECT %s, coalesce(max(seq), 0) + 1, %s, %s, %s, %s, %s
          FROM aegis.campaign_status_change
         WHERE campaign_id = %s
        """,
        (
            campaign_id,
            status,
            target,
            reason or None,
            Jsonb(dict(actor)),
            trace_id,
            campaign_id,
        ),
    )
    record_audit(
        connection,
        actor=actor,
        action=f"campaign.{action}",
        trace_id=trace_id,
        campaign_id=campaign_id,
        details={"from_status": status, "to_status": target, "reason": reason or None},
    )
    current = get_campaign(connection, campaign_id)
    if current is None:  # pragma: no cover - the campaign row is locked and exists
        raise CampaignNotFound(campaign_id)
    return current
