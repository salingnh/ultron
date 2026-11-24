"""PostgreSQL connections of the M02 dispatchers (R-6).

The outbox dispatcher refreshes the publication watermark while holding the exclusive publication
lock; that lock is transaction-scoped and holds every writer until the transaction ends. Two
session settings keep a mistake from becoming a platform-wide stall (TASKS.md R-6):

* `statement_timeout` bounds any single statement, so a refresh or a batch can never run forever;
* `idle_in_transaction_session_timeout` kills a session that forgets to close its transaction, so
  an aborted dispatcher cannot keep the publication lock after its work is over.

Both are applied at connect time on an autocommit connection (a `SET` outside a transaction is
immediate) and every unit of work is an explicit `conn.transaction()` block, so the watermark
refresh runs in its own short transaction and commits (releasing the publication lock) before the
events are read or delivered. `tests/test_m02_dispatcher_db.py` proves both settings are live and
that an idle transaction is actually terminated.
"""

from __future__ import annotations

import os
from typing import Any

import psycopg
from psycopg.rows import dict_row

__all__ = [
    "DEFAULT_IDLE_IN_TRANSACTION_TIMEOUT_MS",
    "DEFAULT_STATEMENT_TIMEOUT_MS",
    "DSN_ENV",
    "IDLE_IN_TRANSACTION_TIMEOUT_ENV",
    "STATEMENT_TIMEOUT_ENV",
    "connect",
    "dsn_from_env",
    "search_path",
]

DSN_ENV = "AEGIS_PG_DSN"
STATEMENT_TIMEOUT_ENV = "AEGIS_DISPATCHER_STATEMENT_TIMEOUT_MS"
IDLE_IN_TRANSACTION_TIMEOUT_ENV = "AEGIS_DISPATCHER_IDLE_TX_TIMEOUT_MS"

#: A statement that takes longer than this is a bug or a lost connection, not a slow scheduler.
DEFAULT_STATEMENT_TIMEOUT_MS = 15_000
#: After this long with an open, idle transaction the server terminates the session (R-6).
DEFAULT_IDLE_IN_TRANSACTION_TIMEOUT_MS = 5_000

SEARCH_PATH = "SET search_path = aegis, public"


def dsn_from_env() -> str:
    dsn = os.environ.get(DSN_ENV)
    if not dsn:
        raise RuntimeError(f"{DSN_ENV} is not set: M02 needs the control-plane PostgreSQL DSN")
    return dsn


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    value = int(raw)
    if value <= 0:
        raise ValueError(f"{name} must be a positive number of milliseconds, got {raw!r}")
    return value


def connect(
    dsn: str | None = None,
    *,
    statement_timeout_ms: int | None = None,
    idle_in_transaction_timeout_ms: int | None = None,
) -> psycopg.Connection[Any]:
    """An autocommit dispatcher connection with the R-6 timeouts already in force."""
    statement = (
        _int_env(STATEMENT_TIMEOUT_ENV, DEFAULT_STATEMENT_TIMEOUT_MS)
        if statement_timeout_ms is None
        else statement_timeout_ms
    )
    idle = (
        _int_env(IDLE_IN_TRANSACTION_TIMEOUT_ENV, DEFAULT_IDLE_IN_TRANSACTION_TIMEOUT_MS)
        if idle_in_transaction_timeout_ms is None
        else idle_in_transaction_timeout_ms
    )
    if statement <= 0 or idle <= 0:
        raise ValueError("statement and idle-in-transaction timeouts must be positive")
    conn = psycopg.connect(dsn or dsn_from_env(), autocommit=True, row_factory=dict_row)
    try:
        conn.execute(SEARCH_PATH)
        conn.execute(f"SET statement_timeout = {int(statement)}")
        conn.execute(f"SET idle_in_transaction_session_timeout = {int(idle)}")
    except BaseException:  # pragma: no cover - connect-time failure must not leak a session
        conn.close()
        raise
    return conn


def search_path(conn: psycopg.Connection[Any]) -> None:
    """Pin the schema on a connection that was not created by `connect` (tests, activities)."""
    conn.execute(SEARCH_PATH)
