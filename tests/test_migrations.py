"""The migration runner applies the README chain, records what it applied and refuses drift.

The database tests need a PostgreSQL 16 server (`AEGIS_TEST_PG_DSN`, the same variable the contract
harnesses use). They create their own throwaway database and drop it again; they never touch a
shared schema.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import psycopg
import pytest
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from aegis.migrations import (
    BOOKKEEPING_TABLE,
    MigrationDrift,
    MigrationError,
    apply_contract_migrations,
    apply_migrations,
    contract_migrations,
    contract_plan,
    read_migration,
)

DSN_ENV = "AEGIS_TEST_PG_DSN"
requires_postgres = pytest.mark.skipif(
    not os.environ.get(DSN_ENV),
    reason=f"set {DSN_ENV} to a PostgreSQL 16 server to run the migration database tests",
)


def test_chain_is_the_readme_order_and_matches_disk() -> None:
    plan = contract_plan()
    migrations = contract_migrations()
    versions = [migration.version for migration in migrations]

    on_disk = sorted(
        path.relative_to(Path(__file__).resolve().parents[1]).as_posix()
        for path in (Path(__file__).resolve().parents[1] / "contracts/db/postgres").glob("0*.sql")
    )
    assert versions == on_disk, "the runner must apply every migration in numeric order"
    assert all(version in plan.clean_chain for version in versions)
    assert all(migration.sha256 and len(migration.sha256) == 64 for migration in migrations)


def test_missing_ci_reader_is_a_loud_error(tmp_path: Path) -> None:
    with pytest.raises(MigrationError, match="read-contract-gate"):
        contract_plan(tmp_path)


@contextmanager
def throwaway_database() -> Iterator[str]:
    """Create an empty database on the test server and drop it afterwards."""
    base_dsn = os.environ[DSN_ENV]
    name = f"aegis_g11a_{uuid.uuid4().hex[:12]}"
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


@requires_postgres
def test_contract_chain_applies_once_and_is_rerunnable() -> None:
    with throwaway_database() as dsn, psycopg.connect(dsn, autocommit=True) as connection:
        report = apply_contract_migrations(connection)
        assert report.applied, "the README chain has migrations to apply"
        assert report.skipped == ()
        assert connection.execute("SELECT count(*) FROM " + BOOKKEEPING_TABLE).fetchone() == (
            len(report.applied),
        )

        # The chain really built the contract schema, not just bookkeeping rows.
        assert connection.execute("SELECT to_regclass('aegis.scan_job')").fetchone() != (None,)
        assert connection.execute(
            "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace"
            " WHERE n.nspname = 'aegis' AND p.proname = 'record_job_callback'"
        ).fetchone() != (0,)

        again = apply_contract_migrations(connection)
        assert again.applied == ()
        assert again.skipped == report.applied


@requires_postgres
def test_edited_migration_is_refused(tmp_path: Path) -> None:
    first = tmp_path / "0001_probe.sql"
    second = tmp_path / "0002_probe.sql"
    first.write_text("CREATE SCHEMA g11a_probe; CREATE TABLE g11a_probe.first(x int);\n")
    second.write_text("CREATE TABLE g11a_probe.second(y int);\n")

    with throwaway_database() as dsn, psycopg.connect(dsn, autocommit=True) as connection:
        report = apply_migrations(
            connection,
            [read_migration(first, "0001_probe.sql"), read_migration(second, "0002_probe.sql")],
        )
        assert report.applied == ("0001_probe.sql", "0002_probe.sql")
        assert connection.execute("SELECT count(*) FROM g11a_probe.second").fetchone() == (0,)

        second.write_text("CREATE TABLE g11a_probe.second(y int, z int);\n")
        with pytest.raises(MigrationDrift, match="0002_probe.sql"):
            apply_migrations(
                connection,
                [
                    read_migration(first, "0001_probe.sql"),
                    read_migration(second, "0002_probe.sql"),
                ],
            )
