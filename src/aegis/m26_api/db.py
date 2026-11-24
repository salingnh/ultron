"""The PostgreSQL connection of one M26 request.

One connection per request, in a transaction the dependency commits on a clean
return and rolls back when the route raises: a campaign create that fails at any
step leaves no scope snapshot, seed, policy snapshot or audit row behind. The DSN
comes from the app (`AEGIS_PG_DSN` in `create_production_app`), never from a query
parameter or a header, and the search_path is pinned to the contract schema because
a few trigger functions older than 0011 still resolve unqualified names.

`ConnectionDep` pins the dependency's teardown to `scope="function"`, so the commit
happens **before** the response is sent. Without it FastAPI tears a `yield`
dependency down after the response, and a client that reads what it just created (a
`POST /campaigns` followed by `GET /campaigns/{id}`, which the G1.5c demo does) can
see a 404 for a row that is about to be committed - the create answered 202 for a
transaction that had not committed yet.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated, Any

import psycopg
from fastapi import Depends, Request
from psycopg.rows import dict_row

__all__ = ["ConnectionDep", "connection", "database_dsn_of"]

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


#: The request's database connection, committed before the response leaves the app.
ConnectionDep = Annotated[psycopg.Connection[Any], Depends(connection, scope="function")]
