"""Operator CLI of M23 (G1.4b): `python -m aegis.m23_graph <run|rebuild|status>`.

* `run` - the projector loop (what a service unit starts), until stopped or drained.
* `rebuild` - the documented rebuild of `contracts/graph/model.md`: wipe the projection and replay
  the whole outbox under a **new consumer generation** (`m23-projector#g<N>`), because
  `consumer_inbox` dedup is permanent and reusing a generation would silently skip events. Prints
  the evidence the card asks for (events, seconds, events/s, node/edge counts) and can write/compare
  a graph snapshot, which is what "rebuild equals original" means: property-by-property equality,
  not node counts.
* `status` - cursors, watermark and projection size, for an operator looking at a lagging graph.

Every command reads `AEGIS_PG_DSN` and `AEGIS_NEO4J_URI`/`AEGIS_NEO4J_USER`/`AEGIS_NEO4J_PASSWORD`
and nothing else; a missing one fails before any work is done.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

from aegis.m23_graph import graph, pg
from aegis.m23_graph.projector import (
    DEFAULT_CONSUMER,
    Projector,
    ProjectorConfig,
    neo4j_from_env,
    projector_from_env,
)

__all__ = ["main", "next_generation", "rebuild", "snapshot_counts"]

GENERATION = re.compile(r"^m23-projector#g(\d+)$")


def next_generation(connection: Any) -> str:
    """`m23-projector#g<N+1>`: the next unused generation, never one with inbox rows."""
    rows = connection.execute("SELECT consumer FROM consumer_cursor").fetchall()
    highest = 0
    for row in rows:
        match = GENERATION.match(str(row["consumer"]))
        if match:
            highest = max(highest, int(match.group(1)))
    return f"m23-projector#g{highest + 1}"


def snapshot_counts(driver: Any) -> dict[str, int]:
    nodes = driver.execute_query("MATCH (n) RETURN count(n) AS nodes").records[0]["nodes"]
    edges = driver.execute_query("MATCH ()-[r]->() RETURN count(r) AS edges").records[0]["edges"]
    return {"nodes": int(nodes), "edges": int(edges)}


def _write_snapshot(driver: Any, path: Path) -> dict[str, int]:
    snapshot = graph.snapshot(driver)
    path.write_text(json.dumps(snapshot, indent=1, sort_keys=True), encoding="utf-8")
    return {"nodes": len(snapshot["nodes"]), "edges": len(snapshot["edges"])}


def _compare_snapshot(driver: Any, path: Path) -> tuple[bool, str]:
    original = json.loads(path.read_text(encoding="utf-8"))
    rebuilt = graph.snapshot(driver)
    if rebuilt == original:
        return True, "rebuild equals the recorded graph, property by property"
    missing = sorted(set(original["nodes"]) - set(rebuilt["nodes"]))
    extra = sorted(set(rebuilt["nodes"]) - set(original["nodes"]))
    differing = [
        key
        for key in set(original["nodes"]) & set(rebuilt["nodes"])
        if original["nodes"][key] != rebuilt["nodes"][key]
    ]
    return False, (
        f"rebuild differs: {len(missing)} node(s) missing, {len(extra)} extra, "
        f"{len(differing)} changed, first missing {missing[:3]}, first extra {extra[:3]}, "
        f"first changed {differing[:3]}"
    )


def rebuild(args: argparse.Namespace) -> int:
    config = ProjectorConfig.from_env()
    dsn = os.environ["AEGIS_PG_DSN"]
    driver = neo4j_from_env()
    connection = pg.connect(dsn)
    try:
        consumer = args.consumer or next_generation(connection)
        config = ProjectorConfig(
            consumer=consumer,
            batch=args.batch or config.batch,
            partitions=args.partitions or config.partitions,
            emit_deltas=False,  # the deltas of these revisions were published by the first run
        )
        if args.snapshot_out and not args.keep_graph:
            counts = _write_snapshot(driver, Path(args.snapshot_out))
            print(
                f"snapshot written to {args.snapshot_out} "
                f"({counts['nodes']} nodes, {counts['edges']} edges)"
            )
        if args.snapshot_out and args.keep_graph:
            raise SystemExit(
                "--snapshot-out records the graph that a rebuild replaces: drop --keep-graph"
            )
        if args.keep_graph:
            print("keeping the existing graph (only new events are replayed into it)")
        else:
            removed = graph.wipe(driver)
            print(f"graph wiped ({removed} nodes removed)")
        target = pg.read_watermark(connection)
        instance = Projector(dsn, driver, config)
        started = time.monotonic()
        with instance:
            stats = instance.run(until=target, timeout=args.timeout)
        seconds = time.monotonic() - started
        counts = snapshot_counts(driver)
        print(
            f"generation {consumer}: {stats.events_applied} events in {seconds:.2f}s "
            f"({stats.events_applied / seconds:.1f} events/s), cursor {instance.cursor}/{target}"
        )
        print(
            f"graph: {counts['nodes']} nodes, {counts['edges']} edges "
            f"({stats.ops_applied} statements, {stats.retries or 0} retries)"
        )
        if args.compare_with:
            equal, detail = _compare_snapshot(driver, Path(args.compare_with))
            print(("PASS " if equal else "FAIL ") + detail)
            return 0 if equal else 1
        return 0 if instance.cursor >= target else 2
    finally:
        connection.close()
        driver.close()


def status(_: argparse.Namespace) -> int:
    dsn = os.environ["AEGIS_PG_DSN"]
    driver = neo4j_from_env()
    connection = pg.connect(dsn)
    try:
        watermark = pg.read_watermark(connection)
        rows = connection.execute(
            "SELECT consumer, last_seq FROM consumer_cursor ORDER BY consumer"
        ).fetchall()
        print(f"publication watermark: {watermark}")
        for row in rows:
            lag = watermark - int(row["last_seq"])
            print(f"  {row['consumer']}: cursor {row['last_seq']} (lag {lag})")
        events = connection.execute(
            "SELECT count(*) AS n, max(seq) AS high FROM outbox_event"
        ).fetchone()
        if events is not None:
            print(f"outbox: {events['n']} events, highest seq {events['high']}")
        counts = snapshot_counts(driver)
        print(f"graph: {counts['nodes']} nodes, {counts['edges']} edges")
        return 0
    finally:
        connection.close()
        driver.close()


def run(args: argparse.Namespace) -> int:
    config = ProjectorConfig.from_env()
    if args.consumer or args.partitions or args.batch:
        config = ProjectorConfig(
            consumer=args.consumer or config.consumer,
            dispatcher=config.dispatcher,
            holder=config.holder,
            batch=args.batch or config.batch,
            partitions=args.partitions or config.partitions,
            poll_seconds=config.poll_seconds,
            lease_ttl=config.lease_ttl,
            refresh_seconds=config.refresh_seconds,
            emit_deltas=config.emit_deltas,
            delta_batch=config.delta_batch,
            delta_seconds=config.delta_seconds,
            batched_statements=config.batched_statements,
        )
    instance = projector_from_env(consumer=config.consumer)
    if args.partitions or args.batch:
        instance.config = config
    started = time.monotonic()
    with instance:
        stats = instance.run(drain_rounds=2 if args.drain else 0, timeout=args.timeout)
    seconds = max(time.monotonic() - started, 0.001)
    print(
        f"{stats.consumer}: {stats.events_applied} events in {seconds:.2f}s "
        f"({stats.events_applied / seconds:.1f} events/s), {stats.ops_applied} statements, "
        f"cursor {instance.cursor}, deltas {stats.deltas_emitted}"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m aegis.m23_graph", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    run_parser = commands.add_parser("run", help="run the projector")
    run_parser.add_argument("--consumer", default=None, help=f"default {DEFAULT_CONSUMER}")
    run_parser.add_argument("--partitions", type=int, default=None)
    run_parser.add_argument("--batch", type=int, default=None)
    run_parser.add_argument("--drain", action="store_true", help="stop when the outbox is drained")
    run_parser.add_argument("--timeout", type=float, default=None)
    run_parser.set_defaults(handler=run)

    rebuild_parser = commands.add_parser("rebuild", help="rebuild the projection, new generation")
    rebuild_parser.add_argument("--consumer", default=None, help="default: next free generation")
    rebuild_parser.add_argument("--partitions", type=int, default=None)
    rebuild_parser.add_argument("--batch", type=int, default=None)
    rebuild_parser.add_argument(
        "--keep-graph", action="store_true", help="replay into the existing projection"
    )
    rebuild_parser.add_argument(
        "--snapshot-out", default=None, help="record the current graph before wiping it"
    )
    rebuild_parser.add_argument(
        "--compare-with", default=None, help="snapshot file the rebuilt graph must equal"
    )
    rebuild_parser.add_argument("--timeout", type=float, default=3600.0)
    rebuild_parser.set_defaults(handler=rebuild)

    status_parser = commands.add_parser("status", help="cursors, watermark and graph size")
    status_parser.set_defaults(handler=status)

    args = parser.parse_args(argv)
    handler: Any = args.handler
    return int(handler(args))


if __name__ == "__main__":  # pragma: no cover - exercised through __main__
    sys.exit(main())
