"""The campaign ledger entries an agent session writes (M03's provenance record).

`campaign_ledger` (0001) is append-only and already carries every kind this card needs:
`cycle_started`, `cycle_finished`, `budget`, `idle_cycle`, `blocker`, `stop_condition`. The ledger
is
the durable record of what a session did outside the model conversation - which job it proposed with
which idempotency key, what the budget was before and after, and why it stopped - and it is also
where the durable link between M02's session label (`<campaign_id>:cycle-<n>`) and the
`agent_session` row lives, so a retried activity call finds the same session instead of opening a
second one.

M02 owns the table (`COMMENT ON TABLE campaign_ledger IS 'M02. ...'`), so M03 writes exactly the six
kinds above, never rewrites a row, and allocates `seq` under the campaign row lock the way M02 does
(one writer at a time per campaign).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

__all__ = [
    "KINDS",
    "CampaignLedger",
    "LedgerError",
    "PostgresCampaignLedger",
    "append_locked",
    "connect",
]

#: The kinds `campaign_ledger` allows (0001 CHECK). M03 writes the six the session owns.
KINDS = frozenset(
    {
        "cycle_started",
        "cycle_finished",
        "objective_done",
        "objective_blocked",
        "blocker",
        "cursor",
        "budget",
        "idle_cycle",
        "stop_condition",
    }
)


class LedgerError(RuntimeError):
    """A ledger write was refused (unknown kind, unknown campaign)."""


class CampaignLedger(Protocol):
    """Append-only campaign ledger, read back by payload match."""

    def append(self, campaign_id: str, kind: str, payload: Mapping[str, Any]) -> int:
        """Append one entry and return its `seq`."""
        ...

    def find(
        self, campaign_id: str, kind: str, *, match: Mapping[str, Any]
    ) -> dict[str, Any] | None:
        """The newest entry of `kind` whose payload carries every `match` value, or None."""
        ...

    def entries(
        self, campaign_id: str, *, kinds: tuple[str, ...], limit: int = 20
    ) -> list[dict[str, Any]]:
        """The newest entries of the given kinds (newest last, so the list reads forward)."""
        ...


class PostgresCampaignLedger:
    """`campaign_ledger` over a short connection per call (no long-lived transaction)."""

    def __init__(self, connect: Any) -> None:
        self._connect = connect

    def append(self, campaign_id: str, kind: str, payload: Mapping[str, Any]) -> int:
        if kind not in KINDS:
            raise LedgerError(f"{kind!r} is not a campaign_ledger kind (0001)")
        with self._connect() as conn, conn.transaction():
            lock_campaign(conn, campaign_id)
            return append_locked(conn, campaign_id, kind, payload)

    def find(
        self, campaign_id: str, kind: str, *, match: Mapping[str, Any]
    ) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT seq, kind, payload, created_at
                  FROM campaign_ledger
                 WHERE campaign_id = %s AND kind = %s AND payload @> %s
                 ORDER BY seq DESC
                 LIMIT 1
                """,
                (campaign_id, kind, Jsonb(dict(match))),
            ).fetchone()
        if row is None:
            return None
        return {
            "seq": int(row["seq"]),
            "kind": str(row["kind"]),
            "payload": dict(row["payload"]),
            "at": row["created_at"],
        }

    def entries(
        self, campaign_id: str, *, kinds: tuple[str, ...], limit: int = 20
    ) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT seq, kind, payload FROM (
                    SELECT seq, kind, payload, created_at
                      FROM campaign_ledger
                     WHERE campaign_id = %s AND kind = ANY(%s)
                     ORDER BY seq DESC
                     LIMIT %s
                ) AS newest ORDER BY seq
                """,
                (campaign_id, list(kinds), max(1, limit)),
            ).fetchall()
        return [
            {"seq": int(row["seq"]), "kind": str(row["kind"]), "payload": dict(row["payload"])}
            for row in rows
        ]


def connect(dsn: str) -> psycopg.Connection[Any]:
    """A connection with the `aegis` schema on the search path (0005 functions need it)."""
    conn: psycopg.Connection[Any] = psycopg.connect(dsn, autocommit=True, row_factory=dict_row)
    conn.execute("SET search_path = aegis, public")
    return conn


def lock_campaign(conn: psycopg.Connection[Any], campaign_id: str) -> None:
    """Serialise this campaign's ledger writers the way M02 does (row lock, then max(seq)+1)."""
    locked = conn.execute(
        "SELECT 1 FROM campaign WHERE campaign_id = %s FOR UPDATE", (campaign_id,)
    ).fetchone()
    if locked is None:
        raise LedgerError(f"campaign {campaign_id} does not exist")


def append_locked(
    conn: psycopg.Connection[Any], campaign_id: str, kind: str, payload: Mapping[str, Any]
) -> int:
    """Insert one ledger entry inside a transaction that already holds the campaign row lock."""
    if kind not in KINDS:
        raise LedgerError(f"{kind!r} is not a campaign_ledger kind (0001)")
    row = conn.execute(
        """
        INSERT INTO campaign_ledger (campaign_id, seq, kind, payload)
        SELECT %s, coalesce(max(seq), 0) + 1, %s, %s
          FROM campaign_ledger WHERE campaign_id = %s
        RETURNING seq
        """,
        (campaign_id, kind, Jsonb(dict(payload)), campaign_id),
    ).fetchone()
    if row is None:  # pragma: no cover - INSERT ... RETURNING always returns a row
        raise LedgerError("campaign_ledger insert returned no seq")
    return int(row["seq"])
