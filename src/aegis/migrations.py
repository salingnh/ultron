"""Apply the contract PostgreSQL chain in the order contracts/README.md publishes.

There is exactly one source for "which migrations, in which order": the `## Kiểm tra` section of
contracts/README.md. The CI contract gate reads it with scripts/ci/read-contract-gate.py, and this
runner calls the same script and parses the same `clean` plan lines, so a developer's database and
CI can never disagree about the chain (and a new migration that the README does not run fails the
gate instead of silently being skipped here).

Bookkeeping lives in its own schema (`aegis_migrations`, not the contract-owned `aegis` schema):

* an applied file is recorded with its sha256; re-running the runner skips it;
* the files run like `psql -f` does in the CI gate: in autocommit, because migrations 0002+ open
  and close their own transaction (`BEGIN; ... COMMIT;`). The runner does not wrap them a second
  time - that would nest transactions and move the commit boundary. The bookkeeping row is written
  immediately after each file commits; if the process dies in between, the next run fails loudly
  on the unrecorded file instead of re-applying (or silently skipping) it;
* an applied file whose bytes changed is a hard error (`MigrationDrift`), because the repository
  rule is "an applied migration is never edited - add a new one".

The runner never writes to a database on its own: `python -m aegis.migrations --dsn ...` (or
`AEGIS_PG_DSN`) is an explicit operator action, and the tests use throwaway databases only.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import psycopg

from aegis.common.repo import repository_root

DSN_ENV = "AEGIS_PG_DSN"
READER = Path("scripts/ci/read-contract-gate.py")
MIGRATION_RE = re.compile(r"^contracts/db/postgres/0[0-9]+_[0-9a-z_]+\.sql$")
BOOKKEEPING_SCHEMA = "aegis_migrations"
BOOKKEEPING_TABLE = f"{BOOKKEEPING_SCHEMA}.contract_migration"

__all__ = [
    "ApplyReport",
    "ContractPlan",
    "Migration",
    "MigrationDrift",
    "MigrationError",
    "apply_contract_migrations",
    "apply_migrations",
    "contract_migrations",
    "contract_plan",
    "main",
    "read_migration",
]


class MigrationError(RuntimeError):
    """The contract chain cannot be read or applied; the message says which part and why."""


class MigrationDrift(MigrationError):
    """A migration that was already applied has different bytes now."""


@dataclass(frozen=True, slots=True)
class ContractPlan:
    """What contracts/README.md says the gate runs, in published order."""

    requirements: tuple[str, ...]
    python_suites: tuple[str, ...]
    clean_chain: tuple[str, ...]
    upgrade_chain: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Migration:
    """One migration file of the chain."""

    path: Path
    version: str
    sha256: str


@dataclass(frozen=True, slots=True)
class ApplyReport:
    """What one runner invocation did: applied files and already-recorded ones."""

    applied: tuple[str, ...]
    skipped: tuple[str, ...]


def contract_plan(root: Path | None = None) -> ContractPlan:
    """Read the gate plan from contracts/README.md through the CI reader script."""
    repository = (root or repository_root()).resolve()
    reader = repository / READER
    if not reader.is_file():
        raise MigrationError(f"missing {reader} - cannot read the contract chain")
    completed = subprocess.run(
        [sys.executable, str(reader), str(repository)],
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip().splitlines()
        raise MigrationError(
            "the contract gate plan in contracts/README.md is not readable: "
            + (" / ".join(detail[-3:]) if detail else f"reader exit {completed.returncode}")
        )
    plan: dict[str, list[str]] = {"requirement": [], "python": [], "clean": [], "upgrade": []}
    for line in completed.stdout.splitlines():
        kind, _, value = line.partition(" ")
        if kind in plan and value:
            plan[kind].append(value)
    for kind, values in plan.items():
        if not values:
            raise MigrationError(f"the contract gate plan has no `{kind}` entries")
    return ContractPlan(
        requirements=tuple(plan["requirement"]),
        python_suites=tuple(plan["python"]),
        clean_chain=tuple(plan["clean"]),
        upgrade_chain=tuple(plan["upgrade"]),
    )


def read_migration(path: Path, version: str | None = None) -> Migration:
    """Build a `Migration` from a file; `version` defaults to the path as given."""
    try:
        content = path.read_bytes()
    except OSError as error:
        raise MigrationError(f"cannot read migration {path}: {error}") from error
    return Migration(
        path=path,
        version=version if version is not None else path.as_posix(),
        sha256=hashlib.sha256(content).hexdigest(),
    )


def contract_migrations(root: Path | None = None) -> tuple[Migration, ...]:
    """The README clean-chain migrations (`contracts/db/postgres/0*.sql`), in README order."""
    repository = (root or repository_root()).resolve()
    chain = contract_plan(repository).clean_chain
    versions = [entry for entry in chain if MIGRATION_RE.match(entry)]
    on_disk = sorted(
        path.relative_to(repository).as_posix()
        for path in (repository / "contracts/db/postgres").glob("0*.sql")
    )
    if not versions:
        raise MigrationError("contracts/README.md runs no migration of contracts/db/postgres")
    if sorted(versions) != on_disk:
        missing = sorted(set(on_disk) - set(versions))
        unknown = sorted(set(versions) - set(on_disk))
        raise MigrationError(
            "contracts/README.md clean chain and contracts/db/postgres disagree "
            f"(not in chain: {missing}; not on disk: {unknown})"
        )
    if versions != on_disk:
        raise MigrationError(
            "contracts/README.md clean chain runs the migrations out of numeric order: "
            + ", ".join(versions)
        )
    return tuple(read_migration(repository / version, version) for version in versions)


def _ensure_bookkeeping(connection: psycopg.Connection[tuple[object, ...]]) -> None:
    with connection.transaction():
        connection.execute(f"CREATE SCHEMA IF NOT EXISTS {BOOKKEEPING_SCHEMA}")
        connection.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {BOOKKEEPING_TABLE} (
                version text PRIMARY KEY,
                sha256 text NOT NULL,
                applied_at timestamptz NOT NULL DEFAULT now()
            )
            """
        )


def apply_migrations(
    connection: psycopg.Connection[tuple[object, ...]],
    migrations: Sequence[Migration],
) -> ApplyReport:
    """Apply each migration once, in the given order, recording its version and sha256."""
    previous_autocommit = connection.autocommit
    if not previous_autocommit:
        if connection.info.transaction_status in {
            psycopg.pq.TransactionStatus.INTRANS,
            psycopg.pq.TransactionStatus.INERROR,
        }:
            raise MigrationError(
                "the connection already has an open transaction; commit or roll it back first"
            )
        # Migrations own their transaction, exactly as `psql -f` runs them in the CI gate.
        connection.autocommit = True
    try:
        _ensure_bookkeeping(connection)
        applied: list[str] = []
        skipped: list[str] = []
        for migration in migrations:
            row = connection.execute(
                f"SELECT sha256 FROM {BOOKKEEPING_TABLE} WHERE version = %s",
                (migration.version,),
            ).fetchone()
            if row is not None:
                recorded = str(row[0])
                if recorded != migration.sha256:
                    raise MigrationDrift(
                        f"{migration.version} was applied with sha256 {recorded} but is now "
                        f"{migration.sha256}; applied migrations are never edited - add a new one"
                    )
                skipped.append(migration.version)
                continue
            try:
                sql = migration.path.read_text(encoding="utf-8")
            except OSError as error:
                raise MigrationError(f"cannot read {migration.version}: {error}") from error
            try:
                connection.execute(sql)
                connection.execute(
                    f"INSERT INTO {BOOKKEEPING_TABLE} (version, sha256) VALUES (%s, %s)",
                    (migration.version, migration.sha256),
                )
            except psycopg.Error as error:
                raise MigrationError(
                    f"{migration.version} failed: {error} (the bookkeeping row is written only "
                    "after the file commits; an unrecorded file fails loudly on the next run)"
                ) from error
            applied.append(migration.version)
        return ApplyReport(applied=tuple(applied), skipped=tuple(skipped))
    finally:
        connection.autocommit = previous_autocommit


def apply_contract_migrations(
    connection: psycopg.Connection[tuple[object, ...]],
    root: Path | None = None,
) -> ApplyReport:
    """Apply the README chain (the same chain the contract CI gate runs)."""
    return apply_migrations(connection, contract_migrations(root))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Apply contracts/db/postgres in the order contracts/README.md publishes."
    )
    parser.add_argument(
        "--dsn",
        default=os.environ.get(DSN_ENV),
        help=f"PostgreSQL DSN (default: ${DSN_ENV})",
    )
    arguments = parser.parse_args(argv)
    if not arguments.dsn:
        parser.error(f"no DSN: pass --dsn or set {DSN_ENV}")
    try:
        migrations = contract_migrations()
        with psycopg.connect(arguments.dsn) as connection:
            report = apply_migrations(connection, migrations)
    except (MigrationError, psycopg.Error) as error:
        print(f"migrations: error: {error}", file=sys.stderr)
        return 1
    print(
        f"migrations: {len(report.applied)} applied, {len(report.skipped)} already recorded "
        f"({len(migrations)} in the README chain)"
    )
    for version in report.applied:
        print(f"  applied {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
