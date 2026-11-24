"""M25 audit rows written by the M01 operations (C05: the actor is server-derived).

Every state-changing M01 call writes exactly one `audit_log` row in the same
transaction as the change, so an audit trail can never disagree with the campaign
row it describes. The actor is a verified principal or a platform module id; it is
validated against `common/ids.v2#/$defs/Actor` here, which catches a caller that
passes the raw bearer token or a client-declared identity.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from aegis import validation

__all__ = ["record_audit"]

TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
ACTOR_REFERENCE = "common/ids.v2.schema.json#/$defs/Actor"


def record_audit(
    connection: psycopg.Connection[Any],
    *,
    actor: Mapping[str, Any],
    action: str,
    trace_id: str,
    campaign_id: str | None = None,
    session_id: str | None = None,
    job_id: str | None = None,
    capability_id: str | None = None,
    policy_version: str | None = None,
    scope_id: str | None = None,
    targets: Sequence[str] | None = None,
    details: Mapping[str, Any] | None = None,
) -> None:
    """Append one audit row; raises when the actor or trace id is not contract-shaped.

    `targets` is the raw text the caller asked for (M05 keeps the requested seed/canonical
    values of a refused request here, never a resolved TargetRef list); `capability_id` is the
    requested capability, which may be unknown to the registry at the time of refusal.
    """
    validation.validate(ACTOR_REFERENCE, dict(actor))
    if not TRACE_ID.fullmatch(trace_id):
        raise ValueError(f"trace_id must be 32 lowercase hex characters, got {trace_id!r}")
    connection.execute(
        """
        INSERT INTO aegis.audit_log
          (actor, action, campaign_id, session_id, job_id, capability_id, policy_version,
           scope_id, targets, details, trace_id)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            Jsonb(dict(actor)),
            action,
            campaign_id,
            session_id,
            job_id,
            capability_id,
            policy_version,
            scope_id,
            list(targets) if targets is not None else None,
            Jsonb(dict(details or {})),
            trace_id,
        ),
    )
