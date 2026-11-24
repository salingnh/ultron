#!/usr/bin/env python3
"""Projector throughput harness (G1.4b): measures events/s and how it scales with partitions.

This is an operator/measurement script, not product code. It builds a real pipeline on a
throwaway database - the contract migration chain, one campaign and job seeded the way M01/M05
write them, `M27` envelopes submitted through the real `IngestionService` - and then runs the real
`Projector` against a real Neo4j. Nothing here copies a schema or an event shape: the events are
the ones M27 publishes, and the Cypher is the committed template.

Two modes answer the two different questions behind NFR-03:

  backlog  the outbox is already published; the projector drains it from cursor 0. This is the
           projection ceiling - the number to compare with the ~833 events/s peak.
  live     `--writers` concurrent M27 writers publish while the projector runs. This is the
           end-to-end rate, bounded by whichever stage is slower (writer or projector); the
           report prints both so the bottleneck is visible.

Usage (from the repository root, with a PostgreSQL and a Neo4j to use):

    export AEGIS_TEST_PG_DSN=postgresql://...      # any PostgreSQL 16 server
    export AEGIS_NEO4J_URI=bolt://127.0.0.1:7687
    export AEGIS_NEO4J_PASSWORD=...
    uv run --frozen python scripts/bench/projector_throughput.py backlog \
        --events 20000 --partitions 8
    uv run --frozen python scripts/bench/projector_throughput.py live \
        --writers 100 --seconds 30

The throwaway database is created and dropped here; the graph is wiped before measuring (the
harness refuses to run against a database that already has outbox events, so it cannot disturb
anything but its own).
"""

from __future__ import annotations

import argparse
import statistics
import sys
import threading
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import psycopg
from neo4j import Driver
from psycopg.conninfo import conninfo_to_dict, make_conninfo

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT))

from aegis.m23_graph import graph  # noqa: E402
from aegis.m23_graph.projector import Projector, ProjectorConfig  # noqa: E402
from aegis.m27_ingestion.service import IngestionService  # noqa: E402
from aegis.migrations import apply_contract_migrations  # noqa: E402
from tests.support_ingestion import (  # noqa: E402
    asset,
    build_envelope,
    seed_campaign,
    seed_jobs,
)

DSN_ENV = "AEGIS_TEST_PG_DSN"
NEO4J_URI_ENV = "AEGIS_NEO4J_URI"
NEO4J_PASSWORD_ENV = "AEGIS_NEO4J_PASSWORD"


@dataclass
class Published:
    """What the writers managed to publish, for the end-to-end rate."""

    events: int = 0
    envelopes: int = 0
    seconds: float = 0.0
    latencies: list[float] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def events_per_second(self) -> float:
        return self.events / self.seconds if self.seconds else 0.0


def _fresh_database() -> tuple[str, Callable[[], None]]:
    base = conninfo_to_dict(__import__("os").environ[DSN_ENV])
    name = f"aegis_g14b_bench_{uuid.uuid4().hex[:10]}"
    admin = make_conninfo("", **{**base, "dbname": "postgres"})
    with psycopg.connect(admin, autocommit=True) as connection:
        connection.execute(f'CREATE DATABASE "{name}"')
    dsn = make_conninfo("", **{**base, "dbname": name})

    def drop() -> None:
        with psycopg.connect(admin, autocommit=True) as connection:
            connection.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')

    return dsn, drop


def _connect(dsn: str) -> psycopg.Connection[tuple[object, ...]]:
    connection: psycopg.Connection[tuple[object, ...]] = psycopg.connect(dsn, autocommit=True)
    connection.execute("SET search_path = aegis, public")
    return connection


def _envelope(job_id: str, index: int, assets_per_envelope: int, shape: str) -> dict[str, Any]:
    """One M27 envelope; `subdomains` also makes M27 write a DISCOVERED_FROM edge per asset."""
    host = f"bench-{index}.internal.example"
    root = f"dns:{host}"
    keys = [root] + [f"dns:sub{position}.{host}" for position in range(assets_per_envelope - 1)]
    if shape == "subdomains":
        assets = [asset(root, "domain")] + [
            asset(key, "domain", discovered_from=[root]) for key in keys[1:]
        ]
    else:
        assets = [asset(key, "domain") for key in keys]
    return build_envelope(
        job_id,
        # M27 requires exactly `job:<job_id>:envelope`; one job per envelope is what makes each
        # envelope a distinct logical result instead of a replay.
        assets=assets,
        coverage=keys,
    )


def _event_count(dsn: str) -> int:
    with _connect(dsn) as connection:
        row = connection.execute("SELECT count(*) FROM outbox_event").fetchone()
    if row is None:  # pragma: no cover - count(*) always returns a row
        raise RuntimeError("count(*) returned no row")
    return int(str(row[0]))


def _neo4j() -> Driver:
    import os

    password = os.environ.get(NEO4J_PASSWORD_ENV)
    if not password:
        raise SystemExit(f"{NEO4J_PASSWORD_ENV} is required")
    return graph.connect(os.environ.get(NEO4J_URI_ENV, "bolt://127.0.0.1:7687"), "neo4j", password)


def _summary(label: str, values: Sequence[float]) -> str:
    if not values:
        return f"{label}: n/a"
    ordered = sorted(values)
    p50 = statistics.median(ordered)
    p95 = ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))]
    return f"{label}: p50 {p50:.3f}s p95 {p95:.3f}s max {ordered[-1]:.3f}s"


def _report(
    *,
    mode: str,
    settings: str,
    stats: Any,
    seconds: float,
    events: int,
    published: Published | None,
) -> None:
    print(f"mode: {mode} ({settings})")
    if published is not None:
        print(
            f"writers: {published.envelopes} envelopes, {published.events} events in "
            f"{published.seconds:.2f}s = {published.events_per_second:.1f} events/s"
        )
        print(f"  {_summary('writer submit latency', published.latencies)}")
        if published.errors:
            print(f"  writer errors: {len(published.errors)}; first: {published.errors[0]}")
    print(f"projected: {stats.events_applied} events in {seconds:.2f}s")
    print(f"  events/s: {stats.events_applied / seconds:.1f}")
    print(f"  ops/s: {stats.ops_applied / seconds:.1f} ({stats.ops_applied} statements)")
    print(
        f"  batches: {stats.batches}, retries: {stats.retries or 0}, "
        f"deltas: {stats.deltas_emitted}, skipped duplicates: {stats.events_skipped}"
    )


def run_backlog(args: argparse.Namespace) -> None:
    dsn, drop = _fresh_database()
    driver = _neo4j()
    try:
        with psycopg.connect(dsn, autocommit=True) as connection:
            apply_contract_migrations(connection)
        with _connect(dsn) as connection:
            if _event_count(dsn):
                raise SystemExit("the throwaway database already has events")
            seed_campaign(connection)
            assets_per_envelope = args.envelope_assets
            envelopes = max(1, args.events // assets_per_envelope)
            jobs = seed_jobs(connection, envelopes)
        service = IngestionService.from_dsn(dsn)
        started = time.monotonic()
        for index, job_id in enumerate(jobs):
            service.submit_payload(_envelope(job_id, index, assets_per_envelope, args.shape))
        published = time.monotonic() - started
        events = _event_count(dsn)
        print(
            f"published {events} events in {envelopes} envelopes in {published:.2f}s "
            f"({events / published:.1f} events/s through M27)"
        )
        bench_consumer = f"m23-projector#bench-{uuid.uuid4().hex[:6]}"
        graph.wipe(driver, context=graph.RebuildContext(bench_consumer))
        config = ProjectorConfig(
            consumer=bench_consumer,
            batch=args.batch,
            partitions=args.partitions,
            poll_seconds=0.005,
            emit_deltas=args.deltas,
            batched_statements=args.batched,
        )
        projector = Projector(dsn, driver, config)
        projector.start()
        begin = time.monotonic()
        stats = projector.run(until=None, drain_rounds=2, timeout=args.timeout)
        seconds = time.monotonic() - begin
        projector.close()
        _report(
            mode="backlog",
            settings=(
                f"batch {args.batch}, partitions {args.partitions}, "
                f"{assets_per_envelope} assets/envelope, shape {args.shape}, "
                f"batched statements {args.batched}, deltas {args.deltas}"
            ),
            stats=stats,
            seconds=seconds,
            events=events,
            published=None,
        )
    finally:
        driver.close()
        drop()


def run_live(args: argparse.Namespace) -> None:
    dsn, drop = _fresh_database()
    driver = _neo4j()
    try:
        with psycopg.connect(dsn, autocommit=True) as connection:
            apply_contract_migrations(connection)
        with _connect(dsn) as connection:
            if _event_count(dsn):
                raise SystemExit("the throwaway database already has events")
            seed_campaign(connection)
            jobs = seed_jobs(connection, args.jobs)
        bench_consumer = f"m23-projector#bench-{uuid.uuid4().hex[:6]}"
        graph.wipe(driver, context=graph.RebuildContext(bench_consumer))
        config = ProjectorConfig(
            consumer=bench_consumer,
            batch=args.batch,
            partitions=args.partitions,
            poll_seconds=0.005,
            emit_deltas=args.deltas,
            batched_statements=args.batched,
        )
        projector = Projector(dsn, driver, config)
        projector.start()
        stop = threading.Event()

        def project() -> None:
            try:
                projector.run(stop=stop, drain_rounds=0, timeout=args.timeout + 60)
            except Exception as error:  # noqa: BLE001 - a dead projector thread must be reported
                errors.append(f"projector: {type(error).__name__}: {error}")

        project_thread = threading.Thread(target=project, daemon=True)
        project_thread.start()

        published = Published()
        before_events = _event_count(dsn)
        errors: list[str] = []
        counters = {"next": 0}
        lock = threading.Lock()

        def write(index: int) -> None:
            service = IngestionService.from_dsn(dsn)
            while not stop.is_set():
                with lock:
                    envelope_index = counters["next"]
                    counters["next"] += 1
                if envelope_index >= len(jobs):
                    errors.append(f"writer {index}: job pool of {len(jobs)} exhausted")
                    return
                started = time.monotonic()
                try:
                    service.submit_payload(
                        _envelope(
                            jobs[envelope_index], envelope_index, args.envelope_assets, args.shape
                        )
                    )
                except Exception as error:  # noqa: BLE001 - reported, never hidden
                    errors.append(f"writer {index}: {type(error).__name__}: {error}")
                    return
                with lock:
                    published.envelopes += 1
                    published.latencies.append(time.monotonic() - started)

        begin = time.monotonic()
        threads = [
            threading.Thread(target=write, args=(index,), daemon=True)
            for index in range(args.writers)
        ]
        for thread in threads:
            thread.start()
        time.sleep(args.seconds)
        stop.set()
        for thread in threads:
            thread.join(timeout=60)
        published.seconds = max(time.monotonic() - begin, 0.001)
        published.events = _event_count(dsn) - before_events
        published.errors = errors
        project_thread.join(timeout=args.timeout)
        during = dict(projector.stats.__dict__)
        # Drain whatever the writers published after the projector was stopped, so the run's
        # totals match what was published instead of stopping mid-stream. The drain time is part
        # of the end-to-end rate: with 100 continuously submitting M27 writers the publication
        # watermark cannot advance until their queue drains (each writer holds the C04 shared
        # lock until commit), so the projector reads the backlog only once writing stops.
        drain_began = time.monotonic()
        projector.run(drain_rounds=3, timeout=args.timeout)
        drain_seconds = time.monotonic() - drain_began
        projector.close()
        stats = projector.stats
        _report(
            mode="live",
            settings=(
                f"{args.writers} writers, batch {args.batch}, partitions {args.partitions}, "
                f"{args.envelope_assets} assets/envelope, shape {args.shape}, "
                f"batched statements {args.batched}"
            ),
            stats=stats,
            seconds=max(
                (stats.finished_at or time.monotonic()) - (stats.started_at or begin), 0.001
            ),
            events=published.events,
            published=published,
        )
        rows = _event_count(dsn)
        drained = stats.events_applied - during["events_applied"]
        print(
            f"during the writer window the projector applied {during['events_applied']} events "
            f"({during['events_applied'] / published.seconds:.1f} events/s); watermark refreshes "
            f"{during['refresh_attempts']} attempted, {during['refresh_blocked']} blocked"
        )
        print(
            f"drain after the writers stopped: {drained} events in {drain_seconds:.2f}s "
            f"({drained / max(drain_seconds, 0.001):.1f} events/s)"
        )
        print(
            f"end-to-end: {published.events} events in "
            f"{published.seconds + drain_seconds:.2f}s = "
            f"{published.events / max(published.seconds + drain_seconds, 0.001):.1f} events/s"
        )
        print(f"projector cursor {projector.cursor} of {rows} published events")
    finally:
        driver.close()
        drop()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["backlog", "live"])
    parser.add_argument(
        "--events", type=int, default=20_000, help="backlog mode: events to publish"
    )
    parser.add_argument("--envelope-assets", type=int, default=500)
    parser.add_argument("--batch", type=int, default=1000)
    parser.add_argument("--partitions", type=int, default=4)
    parser.add_argument(
        "--shape",
        choices=["flat", "subdomains"],
        default="subdomains",
        help="flat = one asset per event; subdomains = a DISCOVERED_FROM edge per asset too",
    )
    parser.add_argument("--writers", type=int, default=100)
    parser.add_argument(
        "--jobs", type=int, default=4000, help="live mode: envelopes one job pool can carry"
    )
    parser.add_argument("--seconds", type=float, default=30.0)
    parser.add_argument("--timeout", type=float, default=900.0)
    parser.add_argument("--deltas", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument(
        "--batched",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="one UNWIND statement per distinct text instead of one round trip per entity",
    )
    args = parser.parse_args(argv)
    if args.mode == "backlog":
        run_backlog(args)
    else:
        run_live(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
