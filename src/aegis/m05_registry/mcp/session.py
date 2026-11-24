"""The server-side session context an MCP transport session is bound to.

`contracts/mcp/README.md:2` states the rule this module implements: the server compares
`params._meta` with the session context **it** holds, and an id the model writes never becomes
authority. Two implementations of the same small interface:

* `PostgresSessionDirectory` - production: the `agent_session` row (0001) is the authority, so a
  session that does not exist, belongs to another campaign or is no longer `RUNNING` cannot call a
  tool, whatever `_meta` claims;
* `InMemorySessionDirectory` - tests and the transport tests (no database).

The transport session (`Mcp-Session-Id`, assigned by the SDK) is bound to exactly one
`(campaign, agent session)` pair on first use; a later call on the same transport session that
claims another pair is `INPUT_INVALID` (G0.3a §Session authority). A server restart loses the
binding, not the authority: the next call is verified against PostgreSQL again.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

import psycopg

__all__ = [
    "InMemorySessionDirectory",
    "PostgresSessionDirectory",
    "SessionContext",
    "SessionDirectory",
]


@dataclass(frozen=True, slots=True)
class SessionContext:
    """What the server knows about the caller: campaign, agent session, objective and scan cycle."""

    campaign_id: str
    session_id: str
    scan_cycle: str
    objective_id: str | None = None


class SessionDirectory(Protocol):
    def resolve(
        self, transport_session_id: str | None, *, campaign_id: str, session_id: str
    ) -> tuple[SessionContext | None, str | None]:
        """Return the bound context, or `(None, reason)`; the reason is safe to show the caller."""
        ...

    def bound(self, transport_session_id: str | None) -> SessionContext | None:
        """The context this transport session is already bound to, without verifying again."""
        ...


# More transport sessions than this in one process are forgotten oldest-first. Forgetting a binding
# never grants anything: the next call is verified against the source again and re-bound.
_MAX_BINDINGS = 4096


class _Bindings:
    """Transport session id -> context, with the mismatch rule shared by both implementations."""

    def __init__(self, *, limit: int = _MAX_BINDINGS) -> None:
        self._lock = threading.Lock()
        self._limit = limit
        self._bound: OrderedDict[str, SessionContext] = OrderedDict()

    def get(self, transport_session_id: str | None) -> SessionContext | None:
        if transport_session_id is None:
            return None
        with self._lock:
            return self._bound.get(transport_session_id)

    def resolve(
        self,
        transport_session_id: str | None,
        context: SessionContext,
        *,
        campaign_id: str,
        session_id: str,
    ) -> tuple[SessionContext | None, str | None]:
        if campaign_id != context.campaign_id or session_id != context.session_id:
            return None, (
                "_meta names campaign/session that do not match the session this transport "
                "connection is bound to"
            )
        if transport_session_id is None:
            # Stateless transport: nothing to bind, every call is verified again.
            return context, None
        with self._lock:
            bound = self._bound.get(transport_session_id)
            if bound is None:
                self._bound[transport_session_id] = context
                while len(self._bound) > self._limit:
                    self._bound.popitem(last=False)
                return context, None
            if (bound.campaign_id, bound.session_id) != (context.campaign_id, context.session_id):
                return None, (
                    "this transport session is already bound to another campaign/session; "
                    "open a new MCP session for a new agent session"
                )
            return bound, None


class InMemorySessionDirectory:
    """Sessions the test (or a single-process demo) registered, without a database."""

    def __init__(self, sessions: Mapping[str, SessionContext] | None = None) -> None:
        self._sessions: dict[str, SessionContext] = dict(sessions or {})
        self._bindings = _Bindings()

    def register(self, context: SessionContext) -> None:
        self._sessions[context.session_id] = context

    def resolve(
        self, transport_session_id: str | None, *, campaign_id: str, session_id: str
    ) -> tuple[SessionContext | None, str | None]:
        context = self._sessions.get(session_id)
        if context is None:
            return None, "the server has no such agent session"
        return self._bindings.resolve(
            transport_session_id, context, campaign_id=campaign_id, session_id=session_id
        )

    def bound(self, transport_session_id: str | None) -> SessionContext | None:
        return self._bindings.get(transport_session_id)


class PostgresSessionDirectory:
    """`agent_session` rows are the authority; the scan cycle is the session in G1.2b.

    The contract gives `scan_cycle` no `_meta` key (`contracts/mcp/README.md`), so the server must
    supply it: one agent session is one scan cycle, which makes a retry inside the session reuse
    the same scan (and the same job) and a restart of the same session resume it, while a
    deliberate new scan needs a new agent session (M03). The value satisfies
    `common/ids.v2#/$defs/Id` because `agent_session.session_id` does.
    """

    def __init__(self, connect: Callable[[], psycopg.Connection[Any]]) -> None:
        self._connect = connect
        self._bindings = _Bindings()

    def bound(self, transport_session_id: str | None) -> SessionContext | None:
        return self._bindings.get(transport_session_id)

    def resolve(
        self, transport_session_id: str | None, *, campaign_id: str, session_id: str
    ) -> tuple[SessionContext | None, str | None]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT campaign_id, status, objective_id FROM agent_session WHERE session_id = %s",
                (session_id,),
            ).fetchone()
        if row is None:
            return None, "the server has no such agent session"
        if str(row[0]) != campaign_id:
            return None, "the agent session belongs to another campaign"
        if str(row[1]) != "RUNNING":
            return None, f"the agent session is {row[1]}, not RUNNING"
        context = SessionContext(
            campaign_id=campaign_id,
            session_id=session_id,
            scan_cycle=session_id,
            objective_id=None if row[2] is None else str(row[2]),
        )
        return self._bindings.resolve(
            transport_session_id, context, campaign_id=campaign_id, session_id=session_id
        )
