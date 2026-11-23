"""Shared helpers for the G0.3b graph spike (Neo4j concurrency + outbox rebuild).

Spike-only code: nothing here is product code and nothing is imported by the contract
tests. It exists to measure the contract artifacts as they are on the integration branch:

  * contracts/graph/projector-upserts.cypher        (the template every test executes)
  * contracts/graph/constraints.cypher              (unique keys the template relies on)
  * contracts/db/postgres/0008_outbox_publication_order.sql (allocator/watermark)

Environment (defaults target the throwaway containers named g03b-pg / g03b-neo4j):
  G03B_PG_DSN      postgresql://aegis:g03b-spike-pg@127.0.0.1:55471/spike
  G03B_NEO4J_URI   bolt://127.0.0.1:57687
  G03B_NEO4J_AUTH  neo4j/g03b-spike-neo4j
"""

from __future__ import annotations

import json
import os
import random
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import psycopg
from neo4j import GraphDatabase
from neo4j.exceptions import Neo4jError

SPIKE_DIR = Path(__file__).resolve().parent
REPO_ROOT = SPIKE_DIR.parents[1]
CONTRACTS = REPO_ROOT / "contracts"
CYPHER_PATH = CONTRACTS / "graph" / "projector-upserts.cypher"
CONSTRAINTS_PATH = CONTRACTS / "graph" / "constraints.cypher"
MIGRATIONS_DIR = CONTRACTS / "db" / "postgres"
SQL_DIR = SPIKE_DIR / "sql"
OUT_DIR = SPIKE_DIR / "out"

PG_DSN = os.environ.get("G03B_PG_DSN", "postgresql://aegis:g03b-spike-pg@127.0.0.1:55471/spike")
NEO4J_URI = os.environ.get("G03B_NEO4J_URI", "bolt://127.0.0.1:57687")
NEO4J_AUTH = tuple(os.environ.get("G03B_NEO4J_AUTH", "neo4j/g03b-spike-neo4j").split("/", 1))
TEMPLATE_DB = os.environ.get("G03B_TEMPLATE_DB", "spike")

NS = uuid.NAMESPACE_URL
NS_PREFIX = "aegis-g03b/"


def uid(name: str) -> uuid.UUID:
    """Deterministic UUIDv7 (ids.v2 requires version 7, and 0005's seed_id guard enforces it).

    The name fixes the timestamp bits too, so runs are reproducible; uniqueness comes from
    the 74 random bits, which are derived from the same name.
    """
    import hashlib

    digest = hashlib.sha256((NS_PREFIX + name).encode()).digest()
    timestamp_ms = int.from_bytes(digest[:6], "big")
    rand = bytearray(digest[6:16])
    rand[0] = (rand[0] & 0x0F) | 0x70  # version 7
    rand[2] = (rand[2] & 0x3F) | 0x80  # RFC 4122 variant
    return uuid.UUID(bytes=timestamp_ms.to_bytes(6, "big") + bytes(rand))


def sha256_hex(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode()).hexdigest()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def dsn_for(db: str) -> str:
    m = re.match(r"^(.*/)([^/?]+)(\?.*)?$", PG_DSN)
    if not m:
        raise ValueError(f"cannot derive a database name from G03B_PG_DSN={PG_DSN!r}")
    return m.group(1) + db + (m.group(3) or "")


def connect(db: str | None = None, autocommit: bool = False) -> psycopg.Connection:
    return psycopg.connect(dsn_for(db) if db else PG_DSN, autocommit=autocommit)


def admin_conn() -> psycopg.Connection:
    # `postgres` is not the template database, so CREATE DATABASE ... TEMPLATE works.
    return connect("postgres", autocommit=True)


def neo4j_driver(*, auth: bool = True):
    return GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH if auth else None)


# ---------------------------------------------------------------------------
# Contract artifacts
# ---------------------------------------------------------------------------
def load_cypher_statements(path: Path = CYPHER_PATH) -> list[str]:
    """Return the statements of a Cypher template, comments stripped.

    The template is the contract artifact; the spike must execute it verbatim rather
    than keep a copy, otherwise the measurement would describe another query.
    """
    text = path.read_text(encoding="utf-8")
    lines = [ln for ln in text.splitlines() if not ln.lstrip().startswith("//")]
    statements = [s.strip() for s in "\n".join(lines).split(";")]
    return [s for s in statements if s]


def load_constraints(path: Path = CONSTRAINTS_PATH) -> list[str]:
    text = path.read_text(encoding="utf-8")
    lines = [ln for ln in text.splitlines() if not ln.lstrip().startswith("//")]
    return [s.strip() for s in "\n".join(lines).split(";") if s.strip()]


def migration_files() -> list[Path]:
    return sorted(MIGRATIONS_DIR.glob("*.sql"))


def apply_sql_file(conn: psycopg.Connection, path: Path) -> None:
    conn.execute(path.read_text(encoding="utf-8"))


def apply_migrations(conn: psycopg.Connection) -> list[str]:
    applied = []
    for path in migration_files():
        apply_sql_file(conn, path)
        applied.append(path.name)
    return applied


def apply_constraints(driver, path: Path = CONSTRAINTS_PATH) -> None:
    statements = load_constraints(path)
    with driver.session() as session:
        for stmt in statements:
            session.run(stmt).consume()


def wipe_graph(driver) -> None:
    with driver.session() as session:
        session.run("MATCH (n) DETACH DELETE n").consume()


class RunDatabase:
    """A fresh database copied from the already-migrated template."""

    def __init__(self, label: str):
        self.name = f"g03b_{re.sub(r'[^a-z0-9_]', '_', label.lower())}"

    def __enter__(self) -> str:
        self.drop()
        with admin_conn() as admin:
            admin.execute(f'CREATE DATABASE "{self.name}" TEMPLATE "{TEMPLATE_DB}"')
        return self.name

    def __exit__(self, *exc) -> None:
        self.drop()

    def drop(self) -> None:
        with admin_conn() as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{self.name}" WITH (FORCE)')


# ---------------------------------------------------------------------------
# Neo4j retry policy (what a projector needs, measured instead of assumed)
# ---------------------------------------------------------------------------
RETRIABLE_PREFIXES = ("Neo.TransientError.",)
RETRIABLE_CODES = {
    # Concurrent MERGE on a unique-constrained property: the loser must retry, the
    # unique constraint is what guarantees one node. This is the case NFR-03 tests.
    "Neo.ClientError.Schema.ConstraintValidationFailed",
}


def retriable(err: Neo4jError) -> bool:
    code = getattr(err, "code", "") or ""
    return code.startswith(RETRIABLE_PREFIXES) or code in RETRIABLE_CODES


def run_cypher_retry(
    driver,
    query: str,
    params: dict,
    *,
    max_attempts: int = 200,
    stats: dict | None = None,
    deadline: float = 60.0,
) -> int:
    """Run one statement in its own transaction, retrying retriable errors.

    Returns the number of attempts used. `stats` accumulates per-code counts so the
    report can state which error the projector must handle, not just "it worked".
    """
    started = time.monotonic()
    attempt = 0
    while True:
        attempt += 1
        try:
            with driver.session() as session:
                with session.begin_transaction() as tx:
                    tx.run(query, params).consume()
            if stats is not None:
                stats["success"] = stats.get("success", 0) + 1
                stats["attempts"] = stats.get("attempts", 0) + attempt
            return attempt
        except Neo4jError as err:
            code = getattr(err, "code", "<no-code>") or "<no-code>"
            if stats is not None:
                stats.setdefault("errors", {}).setdefault(code, 0)
                stats["errors"][code] += 1
            if not retriable(err) or attempt >= max_attempts or time.monotonic() - started > deadline:
                raise
            time.sleep(min(0.05, 0.001 * (2 ** min(attempt, 6))) * (0.5 + random.random()))


def apply_batch_retry(
    driver,
    ops: Iterable[dict],
    *,
    max_attempts: int = 20,
    stats: dict | None = None,
) -> int:
    """Apply a list of {'query','params'} in one Neo4j transaction with retry."""
    ops = list(ops)
    attempt = 0
    while True:
        attempt += 1
        try:
            with driver.session() as session:
                with session.begin_transaction() as tx:
                    for op in ops:
                        tx.run(op["query"], op.get("params") or {}).consume()
            if stats is not None:
                stats["batches"] = stats.get("batches", 0) + 1
                stats["attempts"] = stats.get("attempts", 0) + attempt
            return attempt
        except Neo4jError as err:
            code = getattr(err, "code", "<no-code>") or "<no-code>"
            if stats is not None:
                stats.setdefault("errors", {}).setdefault(code, 0)
                stats["errors"][code] += 1
            if not retriable(err) or attempt >= max_attempts:
                raise
            time.sleep(min(0.05, 0.002 * attempt) * (0.5 + random.random()))


# ---------------------------------------------------------------------------
# Graph snapshot: what "rebuild equals original" is compared on
# ---------------------------------------------------------------------------
def _norm(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _norm(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_norm(v) for v in value]
    if isinstance(value, datetime):
        return iso(value)
    if hasattr(value, "to_native"):  # neo4j.time.DateTime
        return iso(value.to_native())
    if hasattr(value, "iso_format"):
        return value.iso_format()
    if isinstance(value, float):
        return round(value, 6)
    return value


IDENTITY_PROPS = (
    ("Asset", "canonical_key"),
    ("Finding", "finding_id"),
    ("Evidence", "evidence_id"),
    ("Target", "target_id"),
    ("Campaign", "campaign_id"),
    ("Job", "job_id"),
    ("Observation", "observation_id"),
    ("Vulnerability", "vulnerability_id"),
    ("Hypothesis", "hypothesis_id"),
)


def node_identity(labels: list[str], props: dict) -> str:
    for label, prop in IDENTITY_PROPS:
        if label in labels and prop in props:
            return f"{label}:{props[prop]}"
    raise ValueError(f"node without a known identity property: labels={labels} props={props}")


def graph_snapshot(driver) -> dict:
    nodes: dict[str, dict] = {}
    edges: dict[str, dict] = {}
    with driver.session() as session:
        for rec in session.run("MATCH (n) RETURN labels(n) AS labels, properties(n) AS props"):
            labels = sorted(rec["labels"])
            props = _norm(dict(rec["props"]))
            nodes[node_identity(labels, props)] = {"labels": labels, "properties": props}
        for rec in session.run(
            "MATCH (a)-[r]->(b) "
            "RETURN type(r) AS type, labels(a) AS la, properties(a) AS pa, "
            "labels(b) AS lb, properties(b) AS pb, properties(r) AS pr"
        ):
            fa = node_identity(sorted(rec["la"]), _norm(dict(rec["pa"])))
            fb = node_identity(sorted(rec["lb"]), _norm(dict(rec["pb"])))
            props = _norm(dict(rec["pr"]))
            key = f"{rec['type']}|{fa}|{fb}|{props.get('relationship_id', '')}"
            edges[key] = {"type": rec["type"], "from": fa, "to": fb, "properties": props}
    return {"nodes": dict(sorted(nodes.items())), "edges": dict(sorted(edges.items()))}


def snapshot_diff(left: dict, right: dict, max_items: int = 20) -> dict:
    """Compare two graph snapshots; 'equal' means metadata/revision/evidence identical."""
    diffs: list[str] = []
    for section in ("nodes", "edges"):
        a, b = left[section], right[section]
        missing = sorted(set(a) - set(b))
        extra = sorted(set(b) - set(a))
        if missing:
            diffs.append(f"{section} only in original: {missing[:max_items]}")
        if extra:
            diffs.append(f"{section} only in rebuild: {extra[:max_items]}")
        for key in sorted(set(a) & set(b)):
            if a[key] != b[key]:
                diffs.append(f"{section} differs: {key}: {a[key]} != {b[key]}")
                if len(diffs) >= max_items:
                    break
    return {
        "equal": not diffs,
        "original_counts": {k: len(v) for k, v in left.items()},
        "rebuild_counts": {k: len(v) for k, v in right.items()},
        "diffs": diffs[:max_items],
    }


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=1, sort_keys=True, default=str), encoding="utf-8")


def median(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    n = len(ordered)
    mid = n // 2
    return ordered[mid] if n % 2 else (ordered[mid - 1] + ordered[mid]) / 2


def percentile(values: list[float], q: float) -> float:
    """Nearest-rank percentile (q in (0, 1]); stable for the latency samples reported here."""
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, min(len(ordered), int(-(-q * len(ordered) // 1))))
    return ordered[rank - 1]


def latency_summary(values: list[float]) -> dict:
    if not values:
        return {"samples": 0}
    return {
        "samples": len(values),
        "p50": round(percentile(values, 0.50), 4),
        "p90": round(percentile(values, 0.90), 4),
        "p99": round(percentile(values, 0.99), 4),
        "max": round(max(values), 4),
    }
