"""Throwaway PostgreSQL database for the M04 usage-sink test (same rule as tests/test_migrations).

The test needs a real PostgreSQL 18 (`AEGIS_TEST_PG_DSN`) because `aegis.model_usage` is DDL, not a
fake table; it creates its own database, applies the contract chain and drops it again.
"""

from __future__ import annotations

import os
import re
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Protocol

import psycopg
import pytest
from psycopg.conninfo import conninfo_to_dict, make_conninfo

DSN_ENV = "AEGIS_TEST_PG_DSN"
requires_postgres = pytest.mark.skipif(
    not os.environ.get(DSN_ENV),
    reason=f"set {DSN_ENV} to a PostgreSQL 18 server to run the M04 usage database test",
)


#: The names this harness generates: `aegis_<task>_<12 hex>`. Only they may ever be dropped.
THROWAWAY_NAME = re.compile(r"^aegis_[a-z0-9]{2,12}_[0-9a-f]{12}$")


class SharedDatabaseRefused(RuntimeError):
    """A test asked to drop a database the harness did not create; it must not."""


class _Admin(Protocol):
    def execute(self, statement: str) -> object: ...


def drop_throwaway_database(admin: _Admin, name: str) -> None:
    """Drop a database this harness created; refuse any other name.

    Creating a throwaway database on any server is harmless (it is a new one), but a drop is the
    operation that can lose shared data if a DSN or a name is wrong. So the name must be one of the
    harness's own (`aegis_<task>_<12 hex>`), which the environment cannot influence.
    """
    if not THROWAWAY_NAME.fullmatch(name):
        raise SharedDatabaseRefused(
            f"refusing to drop {name!r}: only a harness throwaway database "
            "(aegis_<task>_<12 hex>) may be dropped by a test, never a shared one"
        )
    admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


@contextmanager
def throwaway_database() -> Iterator[str]:
    """Create an empty database on the test server and drop it afterwards."""
    base_dsn = os.environ[DSN_ENV]
    name = f"aegis_g12a_{uuid.uuid4().hex[:12]}"
    parameters = conninfo_to_dict(base_dsn)
    parameters["dbname"] = "postgres"
    with psycopg.connect(make_conninfo("", **parameters), autocommit=True) as admin:
        admin.execute(f'CREATE DATABASE "{name}"')
    parameters["dbname"] = name
    dsn = make_conninfo("", **parameters)
    try:
        yield dsn
    finally:
        with psycopg.connect(
            make_conninfo("", **{**parameters, "dbname": "postgres"}), autocommit=True
        ) as admin:
            drop_throwaway_database(admin, name)
