"""The `agent_session` lifecycle M03 owns (0001) - the authority the MCP server checks.

`contracts/mcp/README.md` (G1.2b) makes the row the authority: a `tools/call` is accepted only when
`agent_session.session_id` exists, belongs to the same campaign and is `RUNNING`. So the session row
must be committed **before** the first MCP call, and it must be the *same* row when the activity is
retried: M02 labels a session `<campaign_id>:cycle-<n>` (a `SessionRequest.session_id`, not a
contract `Id`), while the database key is the UUIDv7 the checkpointer also uses as its thread id.

The durable link between the two is the ledger entry this module writes in the same transaction as
the row (`cycle_started` with `workflow_session`), because `agent_session` has no column for M02's
label and the table is M03's own append-only-status table. Consequences, both required:

* a retried activity call finds the row through the ledger and resumes the same LangGraph thread;
* a crash between "row inserted" and "graph started" cannot leave two `RUNNING` sessions for one
  cycle, and `Run_agent_session` stays idempotent by `session_id` as the interface states.

`finish` writes the contract `session-result.v2` into `agent_session.result` together with the
status columns the table allows to change (`status`, `decision`, `stop_reason`, `steps_used`,
`result`, `finished_at`; 0001's `cols_only` trigger refuses anything else), plus the
`cycle_finished` ledger entry that `SessionOutcome` is rebuilt from on a retry.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

import psycopg
from psycopg.types.json import Jsonb

from aegis.m01_campaign.ids import new_id
from aegis.m02_orchestrator.types import SessionRequest
from aegis.m03_agent import ledger as ledger_module

__all__ = [
    "AgentSessionStore",
    "PostgresAgentSessionStore",
    "SessionRef",
    "SessionRefused",
    "workflow_session_label",
]

#: Local actor for rows M03 creates (0001 actors are `{kind: module|operator|agent, id}`).
MODULE_ACTOR = {"kind": "module", "id": "M03"}
TERMINAL_STATUSES = frozenset({"SUCCEEDED", "FAILED", "CANCELLED"})


class SessionRefused(RuntimeError):
    """The campaign may not start another session (not RUNNING, session budget spent)."""


def workflow_session_label(request: SessionRequest) -> str:
    """M02's session identity: the key the row is found by, never a contract `Id`."""
    return request.session_id


class SessionRef:
    """The session row this activity call works on."""

    __slots__ = (
        "campaign_id",
        "created",
        "cycle",
        "objective_id",
        "policy_version",
        "session_id",
        "status",
        "workflow_session",
    )

    def __init__(
        self,
        *,
        session_id: str,
        campaign_id: str,
        objective_id: str,
        policy_version: str,
        cycle: int,
        status: str,
        created: bool,
        workflow_session: str,
    ) -> None:
        self.session_id = session_id
        self.campaign_id = campaign_id
        self.objective_id = objective_id
        self.policy_version = policy_version
        self.cycle = cycle
        self.status = status
        self.created = created
        self.workflow_session = workflow_session

    @property
    def thread_id(self) -> str:
        """LangGraph thread id: the `agent_session.session_id` (0001: `-- = thread_id`)."""
        return self.session_id

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"SessionRef(session_id={self.session_id!r}, cycle={self.cycle}, "
            f"status={self.status!r}, created={self.created})"
        )


class AgentSessionStore(Protocol):
    """Open (or find) the session row for one activity call, then finish it."""

    def open(
        self,
        request: SessionRequest,
        *,
        revision_from: int,
        max_sessions: int | None = None,
    ) -> SessionRef:
        """The `RUNNING` row for this label, creating it and its objective once."""
        ...

    def finish(
        self,
        ref: SessionRef,
        *,
        status: str,
        decision: str,
        stop_reason: str | None,
        steps_used: int,
        result: Mapping[str, Any],
        cursor: int = 0,
        idle: bool = False,
        detail: str | None = None,
    ) -> bool:
        """Write the session result once; False when the row was already final (retried call)."""
        ...

    def finished_outcome(self, ref: SessionRef) -> dict[str, Any] | None:
        """The `cycle_finished` payload of a session that already finished, if any."""
        ...


class PostgresAgentSessionStore:
    """`agent_session` + the ledger link, one short transaction per transition."""

    def __init__(self, connect: Any) -> None:
        self._connect = connect
        self.ledger = ledger_module.PostgresCampaignLedger(connect)

    # --- open -------------------------------------------------------------------------------
    def open(
        self,
        request: SessionRequest,
        *,
        revision_from: int,
        max_sessions: int | None = None,
    ) -> SessionRef:
        label = workflow_session_label(request)
        found = self.ledger.find(
            request.campaign_id,
            "cycle_started",
            match={"workflow_session": label},
        )
        if found is not None:
            return self._existing(request, str(found["payload"]["session_id"]))

        with self._connect() as conn, conn.transaction():
            ledger_module.lock_campaign(conn, request.campaign_id)
            campaign = conn.execute(
                """
                SELECT c.status, c.current_policy_version, c.objective,
                       p.policy -> 'budget' ->> 'max_agent_sessions' AS max_sessions
                  FROM campaign c
                  JOIN policy_snapshot p ON p.policy_version = c.current_policy_version
                 WHERE c.campaign_id = %s
                """,
                (request.campaign_id,),
            ).fetchone()
            if campaign is None:
                raise SessionRefused(f"campaign {request.campaign_id} does not exist")
            if str(campaign["status"]) != "RUNNING":
                raise SessionRefused(
                    f"campaign {request.campaign_id} is {campaign['status']}, not RUNNING"
                )
            ceiling = max_sessions
            if ceiling is None and campaign["max_sessions"] is not None:
                ceiling = int(campaign["max_sessions"])
            if ceiling is not None:
                used = conn.execute(
                    "SELECT count(*) AS n FROM agent_session WHERE campaign_id = %s",
                    (request.campaign_id,),
                ).fetchone()
                if used is not None and int(used["n"]) >= ceiling:
                    raise SessionRefused(
                        f"campaign {request.campaign_id} already used {used['n']} of its "
                        f"{ceiling} agent sessions (policy budget.max_agent_sessions)"
                    )
            objective_id = self._objective(conn, request.campaign_id, str(campaign["objective"]))
            session_id = new_id()
            conn.execute(
                """
                INSERT INTO agent_session
                       (session_id, campaign_id, objective_id, policy_version,
                        revision_from, status)
                VALUES (%s, %s, %s, %s, %s, 'RUNNING')
                """,
                (
                    session_id,
                    request.campaign_id,
                    objective_id,
                    str(campaign["current_policy_version"]),
                    revision_from,
                ),
            )
            ledger_module.append_locked(
                conn,
                request.campaign_id,
                "cycle_started",
                {
                    "workflow_session": label,
                    "session_id": session_id,
                    "cycle": request.cycle,
                    "cursor": request.cursor,
                    "objective_id": objective_id,
                    "policy_version": str(campaign["current_policy_version"]),
                    "actor": MODULE_ACTOR,
                },
            )
        return SessionRef(
            session_id=session_id,
            campaign_id=request.campaign_id,
            objective_id=objective_id,
            policy_version=str(campaign["current_policy_version"]),
            cycle=request.cycle,
            status="RUNNING",
            created=True,
            workflow_session=label,
        )

    def _existing(self, request: SessionRequest, session_id: str) -> SessionRef:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT campaign_id, objective_id, policy_version, status
                  FROM agent_session WHERE session_id = %s
                """,
                (session_id,),
            ).fetchone()
        if row is None:  # pragma: no cover - the ledger row and the session row are one transaction
            raise SessionRefused(
                f"ledger names session {session_id} of campaign {request.campaign_id} "
                "but the agent_session row is gone"
            )
        if str(row["campaign_id"]) != request.campaign_id:
            raise SessionRefused(
                f"session {session_id} belongs to campaign {row['campaign_id']}, not "
                f"{request.campaign_id}"
            )
        return SessionRef(
            session_id=session_id,
            campaign_id=request.campaign_id,
            objective_id=str(row["objective_id"]) if row["objective_id"] else "",
            policy_version=str(row["policy_version"]),
            cycle=request.cycle,
            status=str(row["status"]),
            created=False,
            workflow_session=workflow_session_label(request),
        )

    def _objective(self, conn: psycopg.Connection[Any], campaign_id: str, text: str) -> str:
        """The campaign's top-level objective row, created on first use (M01/M03 table)."""
        row = conn.execute(
            """
            SELECT objective_id FROM objective
             WHERE campaign_id = %s AND parent_id IS NULL
             ORDER BY created_at, objective_id
             LIMIT 1
            """,
            (campaign_id,),
        ).fetchone()
        if row is not None:
            return str(row["objective_id"])
        objective_id = new_id()
        conn.execute(
            """
            INSERT INTO objective (objective_id, campaign_id, parent_id, text, created_by)
            VALUES (%s, %s, NULL, %s, %s)
            """,
            (objective_id, campaign_id, text, Jsonb(dict(MODULE_ACTOR))),
        )
        return objective_id

    # --- finish -----------------------------------------------------------------------------
    def finish(
        self,
        ref: SessionRef,
        *,
        status: str,
        decision: str,
        stop_reason: str | None,
        steps_used: int,
        result: Mapping[str, Any],
        cursor: int = 0,
        idle: bool = False,
        detail: str | None = None,
    ) -> bool:
        """Finalise the row; returns False when it was already final (a retried activity call)."""
        if status not in TERMINAL_STATUSES:
            raise ValueError(f"{status!r} is not a terminal agent_session status")
        with self._connect() as conn, conn.transaction():
            ledger_module.lock_campaign(conn, ref.campaign_id)
            updated = conn.execute(
                """
                UPDATE agent_session
                   SET status = %s, decision = %s, stop_reason = %s, steps_used = %s,
                       result = %s, finished_at = now()
                 WHERE session_id = %s AND status = 'RUNNING'
                """,
                (
                    status,
                    decision,
                    stop_reason,
                    steps_used,
                    Jsonb(dict(result)),
                    ref.session_id,
                ),
            )
            if updated.rowcount == 0:
                return False
            ledger_module.append_locked(
                conn,
                ref.campaign_id,
                "cycle_finished",
                {
                    "workflow_session": ref.workflow_session,
                    "session_id": ref.session_id,
                    "cycle": ref.cycle,
                    "status": status,
                    "decision": decision,
                    "stop_reason": stop_reason,
                    "steps_used": steps_used,
                    "cursor": cursor,
                    "idle": idle,
                    "detail": detail,
                    "requested_jobs": list(result.get("requested_jobs") or []),
                    "denied": list(result.get("denied") or []),
                    "usage": dict(result.get("usage") or {}),
                },
            )
        ref.status = status
        return True

    def finished_outcome(self, ref: SessionRef) -> dict[str, Any] | None:
        found = self.ledger.find(
            ref.campaign_id, "cycle_finished", match={"session_id": ref.session_id}
        )
        return None if found is None else dict(found["payload"])
