"""Apply the contract PostgreSQL chain in the order contracts/README.md publishes.

There is exactly one source for "which migrations, in which order": the `## Kiểm tra` section of
contracts/README.md. The CI contract gate reads it with scripts/ci/read-contract-gate.py, and this
runner calls the same script and parses the same `clean` plan lines, so a developer's database and
CI can never disagree about the chain (and a new migration that the README does not run fails the
gate instead of silently being skipped here).

Concurrency and crash safety:

* one apply run holds a **session-level advisory lock** (`pg_advisory_lock`), key
  `ADVISORY_LOCK_KEY` below, for as long as it is applying files. Two app/worker instances that
  start together therefore serialise: the second one sees the first one's bookkeeping rows and
  skips them instead of executing the same DDL twice. The lock is session-level, not
  transaction-level, because a run spans the files' own transactions; PostgreSQL releases it if
  the session dies. The key is a constant of the runner, not configuration, so every process of
  the same runner meets on the same lock;
* before a file runs, an attempt row is written to `aegis_migrations.pending_migration` and it is
  removed only after the bookkeeping row exists. A run that dies between a file's `COMMIT` and its
  bookkeeping row - or inside 0001, which has no `BEGIN/COMMIT` - leaves that marker behind. The
  next run then refuses with `UnfinishedMigration`, naming the version and the two recovery
  commands, instead of re-applying or silently adopting the file. Objects that appear without any
  marker (applied by hand or by an older runner) are detected as duplicate-object errors from the
  file itself and reported the same way;
* an applied file whose bytes changed is a hard error (`MigrationDrift`), because the repository
  rule is "an applied migration is never edited - add a new one";
* a database that carries a schema the repository no longer builds - the replaced 0001..0016 chain,
  or contract objects without a recorded baseline - is **not** adopted: the runner refuses with the
  reset command (`ReplacedChain`), because the baseline creates the final schema directly and there
  is nothing to upgrade from. No database held data worth migrating when the chain was squashed.

Recovery (after inspecting the database, with the same DSN as the failed run):

    python -m aegis.migrations mark-applied VERSION --sha256 EXPECTED
        the file's effects are present and complete; record it without executing anything.
        Refuses when EXPECTED is not the file's current sha256, when VERSION is already recorded
        with another sha256, or when the interrupted attempt ran a different file (sha mismatch).

    python -m aegis.migrations discard-attempt VERSION
        the interrupted attempt had no effect; drop its marker so the next run applies the file.

The runner never re-applies, deletes or repairs database objects on its own: it records what an
operator verified, or it fails loudly. It also never writes to a database unless asked to:
`python -m aegis.migrations` is an explicit operator action and the tests use throwaway databases.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import psycopg

from aegis.common.repo import repository_root

DSN_ENV = "AEGIS_PG_DSN"
READER = Path("scripts/ci/read-contract-gate.py")
MIGRATION_RE = re.compile(r"^contracts/db/postgres/0[0-9]+_[0-9a-z_]+\.sql$")
BOOKKEEPING_SCHEMA = "aegis_migrations"
BOOKKEEPING_TABLE = f"{BOOKKEEPING_SCHEMA}.contract_migration"
PENDING_TABLE = f"{BOOKKEEPING_SCHEMA}.pending_migration"

# Session-level advisory lock of one apply run. The key is int64(sha256(name)[:8], big-endian,
# signed) = 7399474447980216404; it is fixed in code so two runner processes always meet on it.
LOCK_NAME = "aegis.contract_migration"
ADVISORY_LOCK_KEY = int.from_bytes(
    hashlib.sha256(LOCK_NAME.encode()).digest()[:8], "big", signed=True
)

# A file that failed because its objects already exist was applied without a bookkeeping row
# (by hand, or by a runner that died before writing one). These SQLSTATEs are the observable
# signal; the pending marker is the precise one for attempts this runner started.
ALREADY_APPLIED_ERRORS = (
    psycopg.errors.DuplicateTable,
    psycopg.errors.DuplicateObject,
    psycopg.errors.DuplicateSchema,
    psycopg.errors.DuplicateFunction,
    psycopg.errors.DuplicateColumn,
)

__all__ = [
    "ADVISORY_LOCK_KEY",
    "ApplyReport",
    "ContractPlan",
    "Migration",
    "MigrationDrift",
    "MigrationError",
    "ReplacedChain",
    "UnfinishedMigration",
    "apply_contract_migrations",
    "apply_migrations",
    "contract_migrations",
    "contract_plan",
    "discard_attempt",
    "main",
    "mark_applied",
    "read_migration",
]


class MigrationError(RuntimeError):
    """The contract chain cannot be read or applied; the message says which part and why."""


class MigrationDrift(MigrationError):
    """A migration that was already applied has different bytes now."""


class ReplacedChain(MigrationError):
    """The database was built by the replaced migration chain; it is reset, never adopted."""

    def __init__(self, found: str) -> None:
        super().__init__(
            "this database carries a schema this repository no longer builds ("
            f"{found}). contracts/db/postgres has one migration, 0001_baseline.sql, which creates "
            "the contract schema directly; a replaced chain is never adopted.\n"
            "Drop the database and apply the baseline again. On the dev stack that is exactly:\n"
            "  make dev-reset\n"
            "(elsewhere: drop the database, then `python -m aegis.migrations` again)"
        )


class UnfinishedMigration(MigrationError):
    """A file started but was never recorded; its effects may be complete or partial."""

    def __init__(self, migration: Migration, attempted_sha256: str, reason: str) -> None:
        self.version = migration.version
        self.sha256 = migration.sha256
        self.attempted_sha256 = attempted_sha256
        self.reason = reason
        super().__init__(
            f"{migration.version}: {reason}. The version is not recorded in "
            f"{BOOKKEEPING_TABLE} and its effects may be fully or partially in the database.\n"
            "Inspect the database, then run exactly one of (same DSN as this run):\n"
            f"  python -m aegis.migrations mark-applied {migration.version} "
            f"--sha256 {migration.sha256}\n"
            "      the file's effects are present and complete; record it\n"
            "      (refuses on sha mismatch)\n"
            f"  python -m aegis.migrations discard-attempt {migration.version}\n"
            "      the attempt had no effect; drop the marker so the next run applies the file"
        )


@dataclass(frozen=True, slots=True)
class ContractPlan:
    """What contracts/README.md says the gate runs, in published order."""

    requirements: tuple[str, ...]
    python_suites: tuple[str, ...]
    clean_chain: tuple[str, ...]


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
    plan: dict[str, list[str]] = {"requirement": [], "python": [], "clean": []}
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
        connection.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {PENDING_TABLE} (
                version text PRIMARY KEY,
                sha256 text NOT NULL,
                started_at timestamptz NOT NULL DEFAULT now()
            )
            """
        )


@contextmanager
def _session_lock(connection: psycopg.Connection[tuple[object, ...]]) -> Iterator[None]:
    """Hold the runner's advisory lock for the whole run (session-level, released on exit)."""
    previous_autocommit = connection.autocommit
    if not previous_autocommit:
        if connection.info.transaction_status in {
            psycopg.pq.TransactionStatus.INTRANS,
            psycopg.pq.TransactionStatus.INERROR,
        }:
            raise MigrationError(
                "the connection already has an open transaction; commit or roll it back first"
            )
        # Migrations own their transactions (like `psql -f`), and a session-level advisory lock
        # must survive their COMMITs, so the runner works in autocommit for the whole run.
        connection.autocommit = True
    try:
        connection.execute("SELECT pg_advisory_lock(%s)", (ADVISORY_LOCK_KEY,))
        try:
            yield
        finally:
            connection.execute("SELECT pg_advisory_unlock(%s)", (ADVISORY_LOCK_KEY,))
    finally:
        connection.autocommit = previous_autocommit


def _recorded_sha256(
    connection: psycopg.Connection[tuple[object, ...]], version: str
) -> str | None:
    row = connection.execute(
        f"SELECT sha256 FROM {BOOKKEEPING_TABLE} WHERE version = %s", (version,)
    ).fetchone()
    return None if row is None else str(row[0])


def _pending_sha256(connection: psycopg.Connection[tuple[object, ...]], version: str) -> str | None:
    row = connection.execute(
        f"SELECT sha256 FROM {PENDING_TABLE} WHERE version = %s", (version,)
    ).fetchone()
    return None if row is None else str(row[0])


def _record_committed(
    connection: psycopg.Connection[tuple[object, ...]], migration: Migration
) -> None:
    connection.execute(
        f"INSERT INTO {BOOKKEEPING_TABLE} (version, sha256) VALUES (%s, %s)",
        (migration.version, migration.sha256),
    )


def _begin_attempt(
    connection: psycopg.Connection[tuple[object, ...]], migration: Migration
) -> None:
    connection.execute(
        f"INSERT INTO {PENDING_TABLE} (version, sha256) VALUES (%s, %s)",
        (migration.version, migration.sha256),
    )


def _clear_pending(connection: psycopg.Connection[tuple[object, ...]], version: str) -> None:
    connection.execute(f"DELETE FROM {PENDING_TABLE} WHERE version = %s", (version,))


def _attempt_left_note(migration: Migration) -> str:
    return (
        f" (the attempt marker for {migration.version} was kept: inspect the database, then "
        f"`python -m aegis.migrations mark-applied {migration.version} "
        f"--sha256 {migration.sha256}` if the file's effects are complete, or "
        f"`python -m aegis.migrations discard-attempt {migration.version}` if they are not)"
    )


def apply_migrations(
    connection: psycopg.Connection[tuple[object, ...]],
    migrations: Sequence[Migration],
) -> ApplyReport:
    """Apply each migration once, in the given order, recording its version and sha256."""
    with _session_lock(connection):
        _ensure_bookkeeping(connection)
        applied: list[str] = []
        skipped: list[str] = []
        for migration in migrations:
            recorded = _recorded_sha256(connection, migration.version)
            if recorded is not None:
                if recorded != migration.sha256:
                    raise MigrationDrift(
                        f"{migration.version} was applied with sha256 {recorded} but is now "
                        f"{migration.sha256}; applied migrations are never edited - add a new one"
                    )
                if _pending_sha256(connection, migration.version) is not None:
                    # Recorded, but the run died before removing its attempt marker: the database
                    # state is exactly what the bookkeeping row says, so drop the stale marker.
                    _clear_pending(connection, migration.version)
                skipped.append(migration.version)
                continue
            pending = _pending_sha256(connection, migration.version)
            if pending is not None:
                raise UnfinishedMigration(
                    migration,
                    pending,
                    "an earlier run started this file but never recorded completion",
                )
            try:
                sql = migration.path.read_text(encoding="utf-8")
            except OSError as error:
                raise MigrationError(f"cannot read {migration.version}: {error}") from error
            _begin_attempt(connection, migration)
            try:
                connection.execute(sql)
            except psycopg.Error as error:
                if isinstance(error, ALREADY_APPLIED_ERRORS):
                    raise UnfinishedMigration(
                        migration,
                        migration.sha256,
                        "the database already contains objects this file creates "
                        f"({error.sqlstate}: {error.diag.message_primary or error})",
                    ) from error
                raise MigrationError(
                    f"{migration.version} failed: {error}{_attempt_left_note(migration)}"
                ) from error
            try:
                _record_committed(connection, migration)
            except psycopg.Error as error:
                raise UnfinishedMigration(
                    migration,
                    migration.sha256,
                    "the file finished but its bookkeeping row could not be written",
                ) from error
            _clear_pending(connection, migration.version)
            applied.append(migration.version)
        return ApplyReport(applied=tuple(applied), skipped=tuple(skipped))


def replaced_chain_state(
    connection: psycopg.Connection[tuple[object, ...]],
    migrations: Sequence[Migration],
) -> str | None:
    """Describe the state that must be reset, or None when the database is fresh or current.

    Two symptoms, one cause: the database was built by something other than this repository's chain.
    `aegis_migrations.contract_migration` names the replaced files, and contract objects without a
    recorded baseline are the same thing applied by hand (`psql -f`) or by the old chain.
    """
    has_bookkeeping = connection.execute(
        "SELECT to_regclass(%s)",
        (f"{BOOKKEEPING_SCHEMA}.{BOOKKEEPING_TABLE.split('.', 1)[1]}",),
    ).fetchone()
    recorded: list[str] = []
    if has_bookkeeping is not None and has_bookkeeping[0] is not None:
        recorded = [
            str(row[0])
            for row in connection.execute(f"SELECT version FROM {BOOKKEEPING_TABLE}").fetchall()
        ]
    known = {migration.version for migration in migrations}
    stale = sorted(set(recorded) - known)
    if stale:
        return "recorded versions " + ", ".join(stale)
    has_objects = connection.execute("SELECT to_regclass('aegis.scan_job')").fetchone()
    if has_objects is not None and has_objects[0] is not None and not known & set(recorded):
        return "contract objects without a recorded baseline"
    return None


def apply_contract_migrations(
    connection: psycopg.Connection[tuple[object, ...]],
    root: Path | None = None,
) -> ApplyReport:
    """Apply the README chain (the same chain the contract CI gate runs)."""
    migrations = contract_migrations(root)
    found = replaced_chain_state(connection, migrations)
    if found is not None:
        raise ReplacedChain(found)
    return apply_migrations(connection, migrations)


def mark_applied(
    connection: psycopg.Connection[tuple[object, ...]],
    migration: Migration,
    expected_sha256: str,
) -> str:
    """Record a migration as applied without executing it (operator recovery, no repair).

    Refuses on any sha mismatch: `expected_sha256` must be the file's current sha256, and an
    interrupted attempt must have run that same file. A version already recorded with the same
    sha256 is a no-op; recorded with another sha256 is `MigrationDrift`.
    """
    if expected_sha256 != migration.sha256:
        raise MigrationError(
            f"refusing mark-applied {migration.version}: --sha256 {expected_sha256} is not the "
            f"file's sha256 {migration.sha256}; pass the sha256 of the file that was applied"
        )
    with _session_lock(connection):
        _ensure_bookkeeping(connection)
        recorded = _recorded_sha256(connection, migration.version)
        if recorded is not None:
            if recorded != migration.sha256:
                raise MigrationDrift(
                    f"{migration.version} was applied with sha256 {recorded} but is now "
                    f"{migration.sha256}; applied migrations are never edited - add a new one"
                )
            _clear_pending(connection, migration.version)
            return (
                f"{migration.version} is already recorded with sha256 {recorded}; nothing changed"
            )
        pending = _pending_sha256(connection, migration.version)
        if pending is not None and pending != migration.sha256:
            raise MigrationError(
                f"refusing mark-applied {migration.version}: the interrupted attempt ran sha256 "
                f"{pending}, the file is now {migration.sha256}; restore the file that ran, or "
                "rebuild the database"
            )
        _record_committed(connection, migration)
        _clear_pending(connection, migration.version)
        return (
            f"recorded {migration.version} as applied with sha256 {migration.sha256}; "
            "nothing was executed"
        )


def discard_attempt(connection: psycopg.Connection[tuple[object, ...]], version: str) -> str:
    """Drop the pending marker of an attempt that had no effect, so the file can run again."""
    with _session_lock(connection):
        _ensure_bookkeeping(connection)
        recorded = _recorded_sha256(connection, version)
        if recorded is not None:
            raise MigrationError(
                f"{version} is already recorded as applied (sha256 {recorded}); "
                "there is no attempt to discard"
            )
        pending = _pending_sha256(connection, version)
        if pending is None:
            raise MigrationError(
                f"no interrupted attempt for {version} in {PENDING_TABLE}; nothing to discard"
            )
        _clear_pending(connection, version)
        return (
            f"discarded the interrupted attempt for {version} (sha256 {pending}); "
            "the next run applies the file again"
        )


def _find_migration(version: str) -> Migration:
    migrations = contract_migrations()
    for migration in migrations:
        if migration.version == version:
            return migration
    known = ", ".join(migration.version for migration in migrations)
    raise MigrationError(f"unknown migration {version!r}; the README chain has: {known}")


def _required(value: str | None, name: str) -> str:
    """Narrow a validated CLI value; the parser already rejected a missing one."""
    if value is None:
        raise MigrationError(f"{name} is required")
    return value


def _apply(dsn: str) -> int:
    migrations = contract_migrations()
    with psycopg.connect(dsn) as connection:
        report = apply_migrations(connection, migrations)
    print(
        f"migrations: {len(report.applied)} applied, {len(report.skipped)} already recorded "
        f"({len(migrations)} in the README chain)"
    )
    for version in report.applied:
        print(f"  applied {version}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Apply contracts/db/postgres in the order contracts/README.md publishes, or resolve "
            "an interrupted attempt with `mark-applied` / `discard-attempt`."
        )
    )
    parser.add_argument(
        "command",
        nargs="?",
        default="apply",
        choices=["apply", "mark-applied", "discard-attempt"],
        help="apply (default), mark-applied or discard-attempt",
    )
    parser.add_argument("version", nargs="?", help="migration version (contracts/-relative path)")
    parser.add_argument(
        "--sha256",
        dest="sha256",
        help="expected sha256 of the migration file (mark-applied; refuses on mismatch)",
    )
    parser.add_argument(
        "--dsn",
        default=os.environ.get(DSN_ENV),
        help=f"PostgreSQL DSN (default: ${DSN_ENV})",
    )
    arguments = parser.parse_args(argv)
    if not arguments.dsn:
        parser.error(f"no DSN: pass --dsn or set {DSN_ENV}")
    if arguments.command == "apply":
        if arguments.version is not None or arguments.sha256 is not None:
            parser.error("apply takes neither VERSION nor --sha256")
    else:
        if arguments.version is None:
            parser.error(f"{arguments.command} needs VERSION")
        if arguments.command == "mark-applied" and arguments.sha256 is None:
            parser.error("mark-applied needs --sha256 EXPECTED")
        if arguments.command == "discard-attempt" and arguments.sha256 is not None:
            parser.error("discard-attempt takes no --sha256 (nothing is recorded)")

    try:
        if arguments.command == "apply":
            return _apply(arguments.dsn)
        migration = _find_migration(_required(arguments.version, "VERSION"))
        with psycopg.connect(arguments.dsn) as connection:
            if arguments.command == "mark-applied":
                print(mark_applied(connection, migration, _required(arguments.sha256, "--sha256")))
            else:
                print(discard_attempt(connection, migration.version))
        return 0
    except (MigrationError, psycopg.Error) as error:
        print(f"migrations: error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
