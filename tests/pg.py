"""Throwaway PostgreSQL database for the M04 usage-sink test (same rule as tests/test_migrations).

The test needs a real PostgreSQL 16 (`AEGIS_TEST_PG_DSN`) because `aegis.model_usage` is DDL, not a
fake table; it creates its own database, applies the contract chain and drops it again.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

import psycopg
import pytest
from psycopg.conninfo import conninfo_to_dict, make_conninfo

DSN_ENV = "AEGIS_TEST_PG_DSN"
requires_postgres = pytest.mark.skipif(
    not os.environ.get(DSN_ENV),
    reason=f"set {DSN_ENV} to a PostgreSQL 16 server to run the M04 usage database test",
)


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
            admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
