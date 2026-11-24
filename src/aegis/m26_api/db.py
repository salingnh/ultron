"""The PostgreSQL connection of one M26 request.

One connection per request, in a transaction the dependency commits on a clean
return and rolls back when the route raises: a campaign create that fails at any
step leaves no scope snapshot, seed, policy snapshot or audit row behind. The DSN
comes from the app (`AEGIS_PG_DSN` in `create_production_app`), never from a query
parameter or a header, and the search_path is pinned to the contract schema because
a few trigger functions older than 0011 still resolve unqualified names.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import psycopg
from fastapi import Request
from psycopg.rows import dict_row

__all__ = ["connection", "database_dsn_of"]

SEARCH_PATH = "SET search_path = aegis, public"


def database_dsn_of(request: Request) -> str:
    """The app's database DSN; a missing one is a deployment error, not a 500 surprise."""
    dsn = getattr(request.app.state, "database_dsn", None)
    if not dsn:
        raise RuntimeError(
            "the app has no database DSN: build it with create_app(database_dsn=...) or set "
            "AEGIS_PG_DSN for create_production_app()"
        )
    return str(dsn)


def connection(request: Request) -> Iterator[psycopg.Connection[Any]]:
    """FastAPI dependency: one transaction per request, committed on success."""
    with psycopg.connect(database_dsn_of(request), row_factory=dict_row) as conn:
        conn.execute(SEARCH_PATH)
        yield conn
