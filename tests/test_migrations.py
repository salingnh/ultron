"""The migration runner applies the README chain, records what it applied and refuses drift.

The database tests need a PostgreSQL 16 server (`AEGIS_TEST_PG_DSN`, the same variable the contract
harnesses use). They create their own throwaway database and drop it again; they never touch a
shared schema.
"""

from __future__ import annotations

import os
import time
import uuid
from collections.abc import Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

import psycopg
import pytest
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from aegis import migrations as migrations_module
from aegis.migrations import (
    BOOKKEEPING_TABLE,
    PENDING_TABLE,
    ApplyReport,
    Migration,
    MigrationDrift,
    MigrationError,
    UnfinishedMigration,
    apply_contract_migrations,
    apply_migrations,
    contract_migrations,
    contract_plan,
    discard_attempt,
    mark_applied,
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


def test_advisory_lock_key_is_the_documented_constant() -> None:
    # A change here would silently stop two runner processes from meeting on the same lock.
    assert migrations_module.ADVISORY_LOCK_KEY == 7_399_474_447_980_216_404
    assert migrations_module.LOCK_NAME == "aegis.contract_migration"


def test_missing_ci_reader_is_a_loud_error(tmp_path: Path) -> None:
    with pytest.raises(MigrationError, match="read-contract-gate"):
        contract_plan(tmp_path)


def write_chain(tmp_path: Path, statements: dict[str, str]) -> list[Migration]:
    """Write a temporary migration chain (same shape as contracts/db/postgres) and read it."""
    chain: list[Migration] = []
    for name, sql in statements.items():
        path = tmp_path / name
        path.write_text(sql, encoding="utf-8")
        chain.append(read_migration(path, name))
    return chain


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


def bookkeeping(dsn: str, table: str) -> list[tuple[str, str]]:
    with psycopg.connect(dsn, autocommit=True) as connection:
        rows = connection.execute(
            f"SELECT version, sha256 FROM {table} ORDER BY version"
        ).fetchall()
    return [(str(version), str(sha256)) for version, sha256 in rows]


@requires_postgres
def test_contract_chain_applies_once_and_is_rerunnable() -> None:
    with throwaway_database() as dsn, psycopg.connect(dsn, autocommit=True) as connection:
        report = apply_contract_migrations(connection)
        assert report.applied, "the README chain has migrations to apply"
        assert report.skipped == ()
        assert len(bookkeeping(dsn, BOOKKEEPING_TABLE)) == len(report.applied)
        assert bookkeeping(dsn, PENDING_TABLE) == []

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
def test_replaced_chain_is_refused_with_the_reset_command() -> None:
    # The old 0001..0016 chain (or the same objects applied by hand with psql) is never adopted:
    # the baseline creates the final schema directly, so the only correct action is a reset.
    with throwaway_database() as dsn, psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute("CREATE SCHEMA aegis")
        connection.execute("CREATE TABLE aegis.scan_job (job_id uuid PRIMARY KEY)")
        with pytest.raises(migrations_module.ReplacedChain) as refused:
            apply_contract_migrations(connection)
        message = str(refused.value)
        assert "make dev-reset" in message
        assert "0001_baseline.sql" in message
        # It refused before touching anything: no bookkeeping was written.
        assert connection.execute(
            "SELECT to_regclass('aegis_migrations.contract_migration')"
        ).fetchone() == (None,)


@requires_postgres
def test_a_recorded_old_version_is_refused() -> None:
    with throwaway_database() as dsn, psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute("CREATE SCHEMA aegis_migrations")
        connection.execute(
            "CREATE TABLE aegis_migrations.contract_migration ("
            " version text PRIMARY KEY, sha256 text NOT NULL,"
            " applied_at timestamptz NOT NULL DEFAULT now())"
        )
        connection.execute(
            "INSERT INTO aegis_migrations.contract_migration (version, sha256)"
            " VALUES ('contracts/db/postgres/0016_manifest_registry_and_signed_task.sql', %s)",
            ("0" * 64,),
        )
        with pytest.raises(migrations_module.ReplacedChain, match="0016_manifest_registry"):
            apply_contract_migrations(connection)


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
                [read_migration(first, "0001_probe.sql"), read_migration(second, "0002_probe.sql")],
            )


@requires_postgres
def test_two_concurrent_runs_apply_each_migration_once(tmp_path: Path) -> None:
    migrations = write_chain(
        tmp_path,
        {
            # The file owns a transaction and is slow enough for the second run to arrive while
            # the first one is between BEGIN and COMMIT; without the advisory lock the second run
            # would insert the same attempt marker, or re-run the DDL and fail on duplicate objects.
            "0001_slow.sql": (
                "BEGIN;\n"
                "SELECT pg_sleep(0.3);\n"
                "CREATE SCHEMA g11a_conc;\n"
                "CREATE TABLE g11a_conc.marker(x int);\n"
                "INSERT INTO g11a_conc.marker VALUES (1);\n"
                "COMMIT;\n"
            ),
            "0002_next.sql": "CREATE TABLE g11a_conc.marker2(y int);\n",
        },
    )
    reports: list[ApplyReport] = []
    errors: list[BaseException] = []

    def run(dsn: str) -> None:
        try:
            with psycopg.connect(dsn, autocommit=True) as connection:
                connection.execute("SET lock_timeout = '30s'")
                reports.append(apply_migrations(connection, migrations))
        except BaseException as error:  # noqa: BLE001 - re-raised by the assertions below
            errors.append(error)

    with throwaway_database() as dsn, ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(run, dsn)
        time.sleep(0.1)
        second = pool.submit(run, dsn)
        first.result(timeout=120)
        second.result(timeout=120)

        assert errors == [], f"a concurrent run failed: {errors}"
        applied = [version for report in reports for version in report.applied]
        assert sorted(applied) == sorted(migration.version for migration in migrations), (
            "each migration must be applied by exactly one run"
        )
        assert connection_count(dsn, "g11a_conc.marker") == 1
        assert len(bookkeeping(dsn, BOOKKEEPING_TABLE)) == len(migrations)
        assert bookkeeping(dsn, PENDING_TABLE) == []


def connection_count(dsn: str, table: str) -> int:
    with psycopg.connect(dsn, autocommit=True) as connection:
        row = connection.execute(f"SELECT count(*) FROM {table}").fetchone()
    assert row is not None
    return int(row[0])


@requires_postgres
def test_unrecorded_attempt_is_detected_with_the_recovery_commands(tmp_path: Path) -> None:
    migrations = write_chain(
        tmp_path,
        {
            "0001_half.sql": (
                "CREATE SCHEMA g11a_half;\n"
                "CREATE TABLE g11a_half.t(x int);\n"
                "SELECT * FROM g11a_half.does_not_exist;\n"
            )
        },
    )
    with throwaway_database() as dsn, psycopg.connect(dsn, autocommit=True) as connection:
        with pytest.raises(MigrationError, match="does_not_exist"):
            apply_migrations(connection, migrations)

        with pytest.raises(UnfinishedMigration) as failure:
            apply_migrations(connection, migrations)
        message = str(failure.value)
        assert "0001_half.sql" in message
        assert f"mark-applied 0001_half.sql --sha256 {migrations[0].sha256}" in message
        assert "discard-attempt 0001_half.sql" in message
        assert "Inspect the database" in message

        # The operator decided the file's effects are complete: record it, then the run skips it.
        assert "recorded" in mark_applied(connection, migrations[0], migrations[0].sha256)
        report = apply_migrations(connection, migrations)
        assert report.applied == () and report.skipped == ("0001_half.sql",)
        assert bookkeeping(dsn, PENDING_TABLE) == []


@requires_postgres
def test_objects_without_a_marker_are_detected(tmp_path: Path) -> None:
    migrations = write_chain(
        tmp_path,
        {"0001_manual.sql": ("CREATE SCHEMA g11a_manual;\nCREATE TABLE g11a_manual.t(x int);\n")},
    )
    with throwaway_database() as dsn:
        # Applied by hand (or by an older runner): objects exist, no bookkeeping row, no marker.
        with psycopg.connect(dsn, autocommit=True) as manual:
            manual.execute("CREATE SCHEMA g11a_manual; CREATE TABLE g11a_manual.t(x int);")
        with psycopg.connect(dsn, autocommit=True) as connection:
            with pytest.raises(UnfinishedMigration) as failure:
                apply_migrations(connection, migrations)
            assert "already contains objects" in str(failure.value)
            assert "mark-applied 0001_manual.sql" in str(failure.value)

            # The marker this run wrote now blocks a blind retry, naming the earlier attempt.
            with pytest.raises(UnfinishedMigration, match="earlier run started"):
                apply_migrations(connection, migrations)

            mark_applied(connection, migrations[0], migrations[0].sha256)
            report = apply_migrations(connection, migrations)
            assert report.applied == () and report.skipped == ("0001_manual.sql",)


@requires_postgres
def test_crash_between_commit_and_bookkeeping_is_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    migrations = write_chain(
        tmp_path,
        {"0001_commit.sql": "CREATE SCHEMA g11a_crash;\nCREATE TABLE g11a_crash.t(x int);\n"},
    )
    original = migrations_module._record_committed
    calls = {"count": 0}

    def flaky(connection: psycopg.Connection[tuple[object, ...]], migration: Migration) -> None:
        calls["count"] += 1
        if calls["count"] == 1:
            raise psycopg.OperationalError("simulated crash before the bookkeeping row")
        original(connection, migration)

    monkeypatch.setattr(migrations_module, "_record_committed", flaky)
    with throwaway_database() as dsn, psycopg.connect(dsn, autocommit=True) as connection:
        with pytest.raises(UnfinishedMigration, match="bookkeeping row"):
            apply_migrations(connection, migrations)
        # The file committed; only its bookkeeping row is missing.
        assert connection.execute("SELECT to_regclass('g11a_crash.t')").fetchone() != (None,)
        assert bookkeeping(dsn, BOOKKEEPING_TABLE) == []
        assert len(bookkeeping(dsn, PENDING_TABLE)) == 1

        with pytest.raises(UnfinishedMigration, match="earlier run started"):
            apply_migrations(connection, migrations)

        mark_applied(connection, migrations[0], migrations[0].sha256)
        assert apply_migrations(connection, migrations).skipped == ("0001_commit.sql",)
        assert bookkeeping(dsn, PENDING_TABLE) == []


@requires_postgres
def test_mark_applied_refuses_any_sha_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "0001_mark.sql"
    path.write_text("CREATE SCHEMA g11a_mark;\n")
    migration = read_migration(path, "0001_mark.sql")

    with throwaway_database() as dsn, psycopg.connect(dsn, autocommit=True) as connection:
        # A wrong sha is refused before any write: no bookkeeping row is created by the refusal.
        with pytest.raises(MigrationError, match="not the file's sha256"):
            mark_applied(connection, migration, "0" * 64)

        mark_applied(connection, migration, migration.sha256)
        assert bookkeeping(dsn, BOOKKEEPING_TABLE) == [("0001_mark.sql", migration.sha256)]

        # Same version, different bytes now: applying or marking it is drift, not an update.
        path.write_text("CREATE SCHEMA g11a_mark;\nCREATE TABLE g11a_mark.t(x int);\n")
        edited = read_migration(path, "0001_mark.sql")
        assert edited.sha256 != migration.sha256
        with pytest.raises(MigrationDrift, match="0001_mark.sql"):
            mark_applied(connection, edited, edited.sha256)
        with pytest.raises(MigrationDrift, match="0001_mark.sql"):
            apply_migrations(connection, [edited])


@requires_postgres
def test_discard_attempt_allows_a_clean_retry(tmp_path: Path) -> None:
    path = tmp_path / "0001_retry.sql"
    path.write_text("CREATE SCHEMA g11a_retry;\nTHIS IS NOT SQL;\n")
    broken = read_migration(path, "0001_retry.sql")

    with throwaway_database() as dsn, psycopg.connect(dsn, autocommit=True) as connection:
        with pytest.raises(MigrationError, match="syntax error"):
            apply_migrations(connection, [broken])
        with pytest.raises(UnfinishedMigration):
            apply_migrations(connection, [broken])

        with pytest.raises(MigrationError, match="no interrupted attempt"):
            discard_attempt(connection, "0002_not_attempted.sql")

        assert "discarded" in discard_attempt(connection, "0001_retry.sql")
        assert bookkeeping(dsn, PENDING_TABLE) == []

        path.write_text("CREATE SCHEMA g11a_retry;\nCREATE TABLE g11a_retry.t(x int);\n")
        fixed = read_migration(path, "0001_retry.sql")
        report = apply_migrations(connection, [fixed])
        assert report.applied == ("0001_retry.sql",)


@requires_postgres
def test_recorded_version_with_a_leftover_marker_is_cleaned_on_the_next_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    migrations = write_chain(tmp_path, {"0001_ok.sql": "CREATE SCHEMA g11a_leftover;\n"})
    original = migrations_module._clear_pending
    calls = {"count": 0}

    def flaky(connection: psycopg.Connection[tuple[object, ...]], version: str) -> None:
        calls["count"] += 1
        if calls["count"] == 1:
            raise psycopg.OperationalError("simulated crash after the bookkeeping row")
        original(connection, version)

    monkeypatch.setattr(migrations_module, "_clear_pending", flaky)
    with throwaway_database() as dsn, psycopg.connect(dsn, autocommit=True) as connection:
        with pytest.raises(psycopg.OperationalError):
            apply_migrations(connection, migrations)
        # The version is recorded and only the stale attempt marker is left.
        assert [version for version, _ in bookkeeping(dsn, BOOKKEEPING_TABLE)] == ["0001_ok.sql"]
        assert len(bookkeeping(dsn, PENDING_TABLE)) == 1

        report = apply_migrations(connection, migrations)
        assert report.applied == () and report.skipped == ("0001_ok.sql",)
        assert bookkeeping(dsn, PENDING_TABLE) == []


@requires_postgres
def test_cli_refuses_mark_applied_with_a_wrong_sha(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    with throwaway_database() as dsn:
        exit_code = migrations_module.main(
            [
                "mark-applied",
                "contracts/db/postgres/0001_baseline.sql",
                "--sha256",
                "0" * 64,
                "--dsn",
                dsn,
            ]
        )
    assert exit_code == 1
    assert "not the file's sha256" in capsys.readouterr().err


def test_write_chain_helper_versions(tmp_path: Path) -> None:
    chain: Sequence[Migration] = write_chain(tmp_path, {"0001_a.sql": "SELECT 1;\n"})
    assert [migration.version for migration in chain] == ["0001_a.sql"]
