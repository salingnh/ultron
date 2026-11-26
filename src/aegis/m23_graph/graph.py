"""Neo4j client of M23 (G1.4b): constraints, upserts, retry, snapshots and wipe.

Neo4j is a rebuildable projection of PostgreSQL (`contracts/graph/model.md`): the only writer is
the projector, which applies the committed Cypher of `contracts/graph/projector-upserts.cypher`
verbatim (see `contract.py`). This module owns everything about the server:

* `install_constraints` applies `constraints.cypher` plus the per-edge-type `relationship_id`
  schema it asks the projector to generate; every statement is idempotent, so it runs on start.
* `apply_ops` runs one batch of operations in **one** Neo4j transaction per worker, with retry.
  Neo4j 5.26 serializes concurrent `MERGE` on a unique index instead of failing, but a batch that
  waits on a lock can still surface `Neo.TransientError.*`; the constraint violation a lost
  create race can raise is retried too, because the statement is idempotent.
* `snapshot` reads every node and edge into a comparable structure; rebuild equality and the
  replay tests compare that, not node counts (card acceptance: "rebuild with new generation
  equals original").
"""

from __future__ import annotations

import os
import random
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from neo4j import Driver, GraphDatabase
from neo4j.exceptions import Neo4jError

from aegis.m23_graph.contract import batched, constraint_statements
from aegis.m23_graph.models import CypherOp

__all__ = [
    "GRAPH_NODE_KEYS",
    "NEO4J_PASSWORD_ENV",
    "NEO4J_URI_ENV",
    "NEO4J_USER_ENV",
    "RebuildContext",
    "apply_ops",
    "connect",
    "connect_from_env",
    "install_constraints",
    "plain",
    "snapshot",
    "wipe",
]

NEO4J_URI_ENV = "AEGIS_NEO4J_URI"
NEO4J_USER_ENV = "AEGIS_NEO4J_USER"
NEO4J_PASSWORD_ENV = "AEGIS_NEO4J_PASSWORD"

#: Property holding the stable identity of each node label, for comparison across rebuilds.
#: Neo4j `elementId` cannot be used: it is a store-local value and changes on rebuild.
GRAPH_NODE_KEYS: tuple[tuple[str, str], ...] = (
    ("Asset", "canonical_key"),
    ("Target", "target_id"),
    ("Campaign", "campaign_id"),
    ("Job", "job_id"),
    ("Observation", "observation_id"),
    ("Vulnerability", "vulnerability_id"),
    ("Finding", "finding_id"),
    ("Evidence", "evidence_id"),
    ("Hypothesis", "hypothesis_id"),
)

RETRY_PREFIXES = ("Neo.TransientError", "Neo.ClientError.Schema.ConstraintValidationFailed")


def connect(uri: str, user: str, password: str) -> Driver:
    """A driver for `uri`; the caller closes it (FastAPI/driver pools are not used here)."""
    return GraphDatabase.driver(uri, auth=(user, password))


def connect_from_env(env: Mapping[str, str] | None = None) -> Driver | None:
    """Build the Neo4j driver from env when configured; fail loudly on partial config."""
    source = os.environ if env is None else env
    uri = (source.get(NEO4J_URI_ENV) or "").strip()
    password = (source.get(NEO4J_PASSWORD_ENV) or "").strip()
    user = (source.get(NEO4J_USER_ENV) or "neo4j").strip() or "neo4j"
    if uri and not password:
        raise RuntimeError(f"{NEO4J_PASSWORD_ENV} is required when {NEO4J_URI_ENV} is set")
    if not password:
        return None
    return connect(uri or "bolt://127.0.0.1:7687", user, password)


def _retryable(error: BaseException) -> bool:
    code = getattr(error, "code", "") or ""
    return code.startswith(RETRY_PREFIXES)


def _run_all(tx: Any, statements: Sequence[CypherOp], *, use_batches: bool) -> None:
    """One transaction: the committed statements, grouped into one round trip per distinct text.

    Without batching, every operation is its own `RUN`/`PULL` round trip (~0.5 ms of client work
    each on this host, ~2 250 statements/s). With batching, all rows of one statement text go in
    one `UNWIND $rows AS row` execution (~5 600 rows/s); the statement text itself is the
    committed one, see `contract.batched`.

    The results must stay referenced until the transaction ends: a dropped `Result` is detached
    immediately, which forces the driver to fetch that statement's summary before sending the
    next one.
    """
    if not use_batches:
        results = [tx.run(op.statement, op.parameters) for op in statements]
        for result in results:
            result.consume()
        return
    groups: dict[str, list[dict[str, Any]]] = {}
    for op in statements:
        groups.setdefault(op.statement, []).append(op.parameters)
    results = [tx.run(batched(statement), {"rows": rows}) for statement, rows in groups.items()]
    for result in results:
        result.consume()


def apply_ops(
    driver: Driver,
    ops: Iterable[CypherOp],
    *,
    max_attempts: int = 20,
    retries: dict[str, int] | None = None,
    use_batches: bool = True,
) -> int:
    """Apply `ops` in one transaction, retrying retryable failures; returns the attempts used."""
    statements = list(ops)
    if not statements:
        return 0
    attempt = 0
    while True:
        attempt += 1
        try:
            with driver.session() as session:
                session.execute_write(_run_all, statements, use_batches=use_batches)
            return attempt
        except Neo4jError as error:
            code = getattr(error, "code", "<no-code>") or "<no-code>"
            if retries is not None:
                retries[code] = retries.get(code, 0) + 1
            if not _retryable(error) or attempt >= max_attempts:
                raise
            time.sleep(min(0.05, 0.002 * attempt) * (0.5 + random.random()))


def install_constraints(driver: Driver) -> int:
    """Apply the committed constraints (and the generated per-type ones); returns the count."""
    statements = constraint_statements()
    with driver.session() as session:
        for statement in statements:
            session.run(statement).consume()
    return len(statements)


def plain(value: Any) -> Any:
    """A JSON-comparable copy of a Neo4j property value (temporal values become ISO strings)."""
    if isinstance(value, Mapping):
        return {str(key): plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    native = getattr(value, "to_native", None)
    if callable(native):
        return str(native())
    return str(value)


def _node_key(labels: Sequence[str], properties: Mapping[str, Any]) -> str:
    for label, property_name in GRAPH_NODE_KEYS:
        if label in labels and property_name in properties:
            return f"{label}:{properties[property_name]}"
    return f"?:{sorted(labels)}:{sorted(properties.items())!r}"


def snapshot(driver: Driver) -> dict[str, dict[str, Any]]:
    """Every node and edge of the graph, keyed by a rebuild-stable identity.

    Node key: `<label>:<identity property>` (see `GRAPH_NODE_KEYS`). Edge key: the endpoint keys,
    the type and the `relationship_id` when the edge carries one (finding/evidence edges do not).
    Values are `plain()` so two snapshots compare with `==`.
    """
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}
    with driver.session() as session:
        for record in session.run(
            "MATCH (n) RETURN labels(n) AS labels, properties(n) AS properties"
        ):
            properties = plain(record["properties"])
            labels = list(record["labels"])
            nodes[_node_key(labels, properties)] = {"labels": labels, "properties": properties}
        for record in session.run(
            "MATCH (a)-[r]->(b) RETURN labels(a) AS from_labels, properties(a) AS from_properties,"
            " labels(b) AS to_labels, properties(b) AS to_properties, type(r) AS type,"
            " properties(r) AS properties"
        ):
            from_key = _node_key(record["from_labels"], record["from_properties"])
            to_key = _node_key(record["to_labels"], record["to_properties"])
            properties = plain(record["properties"])
            relationship_id = properties.get("relationship_id")
            edge_key = (
                f"{from_key}|{record['type']}|{to_key}|{relationship_id}"
                if relationship_id
                else f"{from_key}|{record['type']}|{to_key}"
            )
            edges[edge_key] = {"type": record["type"], "properties": properties}
    return {"nodes": nodes, "edges": edges}


@dataclass(frozen=True, slots=True)
class RebuildContext:
    """The explicit rebuild the wipe belongs to: the consumer generation it is being built into.

    A wipe is not an operation of the running projector - it deletes every node and edge and is only
    correct as the first step of rebuilding under a **new** consumer generation (`model.md` "Dựng
    lại toàn bộ": xóa database Neo4j rồi chạy projector). Requiring this value is what keeps a plain
    run (`python -m aegis.m23_graph run`, `Projector`) from ever reaching the wipe: neither has a
    generation to rebuild into, so neither can call `wipe()`. Only the rebuild command
    (`cli.rebuild`) and the throughput bench construct it.
    """

    generation: str

    def __post_init__(self) -> None:
        if not self.generation.strip():
            raise ValueError("a rebuild context needs the consumer generation it rebuilds into")


def wipe(driver: Driver, *, context: RebuildContext, batch: int = 10_000) -> int:
    """Delete every node and edge of the graph in batches; returns how many nodes were removed.

    `context` is mandatory on purpose: this is the destructive step of a rebuild, never something a
    normal projector run does (`RebuildContext`). The type is checked at runtime too, so a string
    passed by mistake is refused instead of wiping the graph.
    """
    if not isinstance(context, RebuildContext):
        raise TypeError(
            "graph.wipe needs an explicit graph.RebuildContext (the rebuild it belongs to); a "
            f"plain value {type(context).__name__!r} must not delete the graph"
        )
    removed = 0
    with driver.session() as session:
        while True:
            record = session.run(
                "MATCH (n) WITH n LIMIT $batch DETACH DELETE n RETURN count(*) AS removed",
                {"batch": batch},
            ).single()
            deleted = int(record["removed"]) if record is not None else 0
            removed += deleted
            if deleted == 0:
                break
    return removed
