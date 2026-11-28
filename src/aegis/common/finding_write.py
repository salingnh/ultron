"""The one write path of a finding status change (M20, M21, M26).

`contracts/finding/transitions.v2.yaml` says which changes are allowed and by whom; this module is
the only place that applies one. Before it existed M20 (`m20_vuln/findings.py`) and the operator API
(`m26_api/findings.py`) each had their own copy of "update the row guarded by the old sequence,
insert one `finding_transition`, publish one `finding.changed.v2` event", and M21 would have been
the third. Three copies drift in the details that matter: the guard, the event shape, the dedup key
and the actor recorded in history.

One call is one transition:

1. ask the transition table whether `(from_status -> to_status)` is allowed for the acting side;
2. `UPDATE finding ... WHERE transition_seq = <seq - 1>` - a concurrent writer that already moved
   the row is refused, never overwritten;
3. insert the `finding_transition` row (`seq`, actor, cause, evidence);
4. validate and insert the `finding.changed.v2` outbox event with dedup key `<finding_id>:<seq>`.

The caller owns the transaction: everything commits together or not at all. `seq` is the sequence
the caller read; a row that already moved raises `TransitionRefused`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

import psycopg
from psycopg.types.json import Jsonb

from aegis import validation
from aegis.common.finding_transitions import rule_for

__all__ = [
    "EVENT_SCHEMA",
    "EVENT_TYPE",
    "TransitionRefused",
    "TransitionWrite",
    "now",
    "write_transition",
]

EVENT_TYPE = "finding.changed.v2"
EVENT_SCHEMA = "events/finding.changed.v2.schema.json"


class TransitionRefused(ValueError):
    """The change is not allowed by the table, or the finding is no longer at `seq - 1`."""


@dataclass(frozen=True, slots=True)
class TransitionWrite:
    """What one transition wrote; `event_written` is false for a duplicate dedup key."""

    finding_id: str
    seq: int
    changed_at: str
    event_written: bool


def now(connection: psycopg.Connection[Any]) -> str:
    """The database clock as the contract's timestamp shape (`...Z`)."""
    row = connection.execute("SELECT now() AS at").fetchone()
    if row is None:  # pragma: no cover - PostgreSQL always answers now()
        raise RuntimeError("SELECT now() returned no row")
    return str(row["at"].isoformat()).replace("+00:00", "Z")


def _actor_token(actor: Mapping[str, Any]) -> str:
    """The table's `by` token for one actor: modules act as their id, an operator as `operator`."""
    kind = str(actor.get("kind"))
    if kind == "operator":
        return "operator"
    return str(actor.get("id"))


def _campaign_of(connection: psycopg.Connection[Any], finding_id: str) -> str:
    row = connection.execute(
        "SELECT first_campaign_id FROM finding WHERE finding_id = %s", (finding_id,)
    ).fetchone()
    if row is None:
        raise TransitionRefused(f"finding {finding_id} does not exist")
    return str(row["first_campaign_id"])


def _asset_of(connection: psycopg.Connection[Any], finding_id: str) -> str:
    row = connection.execute(
        "SELECT asset_id FROM finding WHERE finding_id = %s", (finding_id,)
    ).fetchone()
    if row is None:
        raise TransitionRefused(f"finding {finding_id} does not exist")
    return str(row["asset_id"])


def write_transition(
    connection: psycopg.Connection[Any],
    *,
    finding_id: str,
    from_status: str | None,
    to_status: str,
    reason: str,
    evidence_id: str | None,
    actor: Mapping[str, Any],
    cause: str,
    old_severity: str | None,
    new_severity: str | None,
    seq: int,
    producer: str,
    campaign_id: str | None = None,
    trace: Mapping[str, Any] | None = None,
) -> TransitionWrite:
    """Apply one allowed status change and publish it; raises `TransitionRefused` otherwise.

    `producer` is the outbox `producer` column (the module that wrote the event), while `actor` is
    the side the transition table authorises - both are explicit because a module acts as itself
    and an operator acts as `operator`, whatever the authenticated principal id is.
    """
    if seq < 1:
        raise TransitionRefused(f"transition seq {seq} is not a positive sequence")
    rule = rule_for(from_status, to_status, _actor_token(actor))
    if rule is None:
        raise TransitionRefused(
            f"transitions.v2.yaml refuses {from_status} -> {to_status} by {_actor_token(actor)}"
        )
    if "reason" in rule.requires and not reason:
        raise TransitionRefused("transitions.v2.yaml requires a reason for this change")
    if "evidence" in rule.requires and not evidence_id:
        raise TransitionRefused("transitions.v2.yaml requires evidence for this change")
    campaign = campaign_id if campaign_id is not None else _campaign_of(connection, finding_id)
    asset_id = _asset_of(connection, finding_id)
    changed_at = now(connection)
    if from_status is None:
        # Creation: M20 inserted the row in this transaction with transition_seq = 1, and there is
        # no sequence 0 to guard against - the insert itself is the creation.
        if seq != 1:
            raise TransitionRefused("a creating transition is always seq 1")
    else:
        updated = connection.execute(
            "UPDATE finding SET status = %s, transition_seq = %s"
            " WHERE finding_id = %s AND transition_seq = %s RETURNING transition_seq",
            (to_status, seq, finding_id, seq - 1),
        ).fetchone()
        if updated is None:
            raise TransitionRefused(
                f"finding {finding_id} is not at transition_seq {seq - 1}: a concurrent writer "
                "moved it"
            )
    connection.execute(
        "INSERT INTO finding_transition (finding_id, seq, from_status, to_status, reason,"
        " evidence_id, actor, cause, created_at)"
        " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (
            finding_id,
            seq,
            from_status,
            to_status,
            reason,
            evidence_id,
            Jsonb(dict(actor)),
            cause,
            changed_at,
        ),
    )
    payload: dict[str, Any] = {
        "finding_id": finding_id,
        "transition_seq": seq,
        "asset_id": asset_id,
        "campaign_id": campaign,
        "old_status": from_status,
        "new_status": to_status,
        "old_severity": old_severity,
        "new_severity": new_severity,
        "reason": reason,
        "changed_by": dict(actor),
        "cause": cause,
        "changed_at": changed_at,
    }
    if evidence_id is not None:
        payload["evidence_ref"] = evidence_id
    problems = validation.problems(EVENT_SCHEMA, payload)
    if problems:
        pointer, message = problems[0]
        raise TransitionRefused(
            f"finding.changed.v2 payload violates the contract at {pointer or '/'}: {message}"
        )
    inserted = connection.execute(
        "INSERT INTO outbox_event (event_id, type, producer, dedup_key, campaign_id, payload,"
        " trace) VALUES (%s, %s, %s, %s, %s, %s, %s)"
        " ON CONFLICT (type, dedup_key) DO NOTHING RETURNING event_id",
        (
            _uuid7(),
            EVENT_TYPE,
            producer,
            f"{finding_id}:{seq}",
            campaign,
            Jsonb(payload),
            Jsonb(dict(trace) if trace is not None else {"trace_id": uuid4().hex}),
        ),
    ).fetchone()
    return TransitionWrite(
        finding_id=finding_id,
        seq=seq,
        changed_at=changed_at,
        event_written=inserted is not None,
    )


def _uuid7() -> str:
    """A UUIDv7, imported lazily so this module needs no ingestion import at load time."""
    from aegis.m27_ingestion.ids import uuid7

    return str(uuid7())
