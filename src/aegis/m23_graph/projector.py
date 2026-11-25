"""The M23 projector (G1.4b): one consumer of the outbox, partitioned over keys.

The loop is the C04/D25 consumer contract of `contracts/graph/model.md`:

1. renew the dispatcher lease and keep its fencing token (`aegis.outbox_dispatch_lease`);
2. refresh the publication watermark in its own short transaction
   (`aegis.outbox_watermark_refresh`, 0013 waits for the publication lock instead of starving);
3. read the next published events (`aegis.outbox_batch`) - never past the watermark, gaps legal;
4. prefetch the entity rows of the whole batch from PostgreSQL (properties come from PG, not from
   the payload: assets, relationships, findings, evidence, vulnerabilities), plan the Cypher
   operations, and apply them **partitioned by key** (per-key order)
   and in two phases (assets before the edges that `MATCH` them);
5. check the batchpoint: `consumer_inbox` rows for the applied events and `aegis.consumer_advance`
   with the fence - Neo4j first, cursor second, so a crash replays instead of skipping;
6. publish the `knowledge.delta.v2` events of every provably complete revision.

Everything the consumer keeps in memory is a cache of what PostgreSQL already says: the durable
state is `consumer_cursor` (one row per consumer generation) and `consumer_inbox` (append-only
dedup). A rebuild is therefore "new generation, cursor 0" - see `rebuild.py`.
"""

from __future__ import annotations

import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace

import psycopg
from neo4j import Driver

from aegis.m23_graph import graph, pg
from aegis.m23_graph.models import (
    ASSET_EVENT,
    FINDING_EVENT,
    OBSERVATION_EVENT,
    VULNERABILITY_EVENT,
    CypherOp,
    OutboxEvent,
    ProjectorStats,
    RoundResult,
)
from aegis.m23_graph.plan import plan_round

__all__ = [
    "CONSUMER_ENV",
    "DEFAULT_CONSUMER",
    "NEO4J_PASSWORD_ENV",
    "NEO4J_URI_ENV",
    "NEO4J_USER_ENV",
    "PG_DSN_ENV",
    "Projector",
    "ProjectorBusy",
    "ProjectorConfig",
    "neo4j_from_env",
    "projector_from_env",
]

PG_DSN_ENV = "AEGIS_PG_DSN"
NEO4J_URI_ENV = "AEGIS_NEO4J_URI"
NEO4J_USER_ENV = "AEGIS_NEO4J_USER"
NEO4J_PASSWORD_ENV = "AEGIS_NEO4J_PASSWORD"
CONSUMER_ENV = "AEGIS_PROJECTOR_CONSUMER"

DEFAULT_CONSUMER = "m23-projector#g1"


class ProjectorBusy(RuntimeError):
    """Another live holder owns the dispatcher lease; a second projector must not run."""


HOLDER_ENV = "AEGIS_PROJECTOR_HOLDER"


@dataclass(frozen=True, slots=True)
class ProjectorConfig:
    """Tunables of one projector process; all of them have an environment override."""

    consumer: str = DEFAULT_CONSUMER
    dispatcher: str = "m23-projector"
    #: Identity that holds the dispatcher lease. Default: this process (`host:pid`), so a restart
    #: waits out the previous lease (60 s). A deployment that restarts the projector as a service
    #: pins `AEGIS_PROJECTOR_HOLDER` to a stable name: the restart takes its own lease back at once,
    #: and the fencing token (`take_lease` increments it) still invalidates the old process, so two
    #: projectors can never write at the same time.
    holder: str = f"{socket.gethostname()}:{os.getpid()}"
    batch: int = 1000
    partitions: int = 4
    poll_seconds: float = 0.05
    lease_ttl: int = 60
    refresh_seconds: float = 0.1
    lock_timeout_ms: int = 250
    emit_deltas: bool = True
    delta_batch: int = 500
    delta_seconds: float = 1.0
    batched_statements: bool = True

    @classmethod
    def from_env(cls) -> ProjectorConfig:
        return cls(
            consumer=os.environ.get(CONSUMER_ENV, DEFAULT_CONSUMER),
            holder=os.environ.get(HOLDER_ENV, "") or f"{socket.gethostname()}:{os.getpid()}",
            batch=int(os.environ.get("AEGIS_PROJECTOR_BATCH", "1000")),
            partitions=int(os.environ.get("AEGIS_PROJECTOR_PARTITIONS", "4")),
            poll_seconds=int(os.environ.get("AEGIS_PROJECTOR_POLL_MS", "50")) / 1000,
            lease_ttl=int(os.environ.get("AEGIS_PROJECTOR_LEASE_TTL", "60")),
            refresh_seconds=int(os.environ.get("AEGIS_PROJECTOR_REFRESH_MS", "100")) / 1000,
            lock_timeout_ms=int(os.environ.get("AEGIS_PROJECTOR_LOCK_TIMEOUT_MS", "250")),
            emit_deltas=os.environ.get("AEGIS_PROJECTOR_DELTAS", "1") not in {"0", "false", "off"},
            batched_statements=os.environ.get("AEGIS_PROJECTOR_BATCHED", "1")
            not in {"0", "false", "off"},
            delta_seconds=int(os.environ.get("AEGIS_PROJECTOR_DELTA_MS", "1000")) / 1000,
        )


def neo4j_from_env() -> Driver:
    """The projector's Neo4j driver; missing credentials fail here, not on the first batch."""
    password = os.environ.get(NEO4J_PASSWORD_ENV)
    if not password:
        raise RuntimeError(f"{NEO4J_PASSWORD_ENV} is required to project the graph")
    return graph.connect(
        os.environ.get(NEO4J_URI_ENV, "bolt://127.0.0.1:7687"),
        os.environ.get(NEO4J_USER_ENV, "neo4j"),
        password,
    )


class Projector:
    """Runs rounds against one PostgreSQL DSN and one Neo4j driver."""

    def __init__(
        self,
        dsn: str,
        driver: Driver,
        config: ProjectorConfig | None = None,
        *,
        stats: ProjectorStats | None = None,
    ) -> None:
        self.dsn = dsn
        self.driver = driver
        self.config = config or ProjectorConfig()
        self.stats = stats or ProjectorStats(consumer=self.config.consumer)
        self._conn = pg.connect(dsn)
        pg.configure_watermark_bound(self._conn, f"{self.config.lock_timeout_ms}ms")
        self._fence: int | None = None
        self._needs_refresh = True
        self._last_refresh = 0.0
        self._last_delta = 0.0
        self._backoff = 0.0
        self._last_lease = 0.0
        self.watermark = 0
        self._executor = ThreadPoolExecutor(
            max_workers=max(self.config.partitions, 1),
            thread_name_prefix="m23-partition",
        )
        self._closed = False
        self.cursor = pg.read_cursor(self._conn, self.config.consumer)

    # -- lifecycle -------------------------------------------------------------------------
    def start(self) -> None:
        """Take the lease and make sure the graph schema exists; safe to call twice."""
        fence = pg.take_lease(
            self._conn, self.config.dispatcher, self.config.holder, self.config.lease_ttl
        )
        if fence is None:
            raise ProjectorBusy(
                f"dispatcher {self.config.dispatcher!r} is held by another live lease; "
                "one projector per dispatcher"
            )
        self._fence = fence
        self._last_lease = time.monotonic()
        graph.install_constraints(self.driver)
        self.cursor = pg.read_cursor(self._conn, self.config.consumer)
        self.stats.started_at = time.monotonic()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._executor.shutdown(wait=True)
        self._conn.close()

    def __enter__(self) -> Projector:
        self.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- one round -------------------------------------------------------------------------
    def _lease(self) -> int:
        """Renew the dispatcher lease when half its TTL has passed; reuse the fence otherwise."""
        if (
            self._fence is not None
            and time.monotonic() - self._last_lease < self.config.lease_ttl / 2
        ):
            return self._fence
        fence = pg.take_lease(
            self._conn, self.config.dispatcher, self.config.holder, self.config.lease_ttl
        )
        if fence is None:
            raise ProjectorBusy(
                f"dispatcher {self.config.dispatcher!r} lost its lease to another holder"
            )
        self._fence = fence
        self._last_lease = time.monotonic()
        return fence

    def _refresh(self) -> int | None:
        """Advance the watermark, at a bounded rate; None means "wait and retry".

        `outbox_watermark_refresh` waits for the publication lock, and while it waits new writer
        transactions queue **behind it** (0013: that is how the watermark stays provable). Calling
        it in a tight loop therefore starves the writers it protects: measured at 100 M27 writers,
        an unthrottled projector (one refresh per round, ~200/s while idle) pushed writer p50 from
        0.15 s to ~8 s and let almost nothing publish. `contracts/graph/model.md` states the rule -
        "dispatcher thật phải có nhịp refresh giới hạn, không spin" - so a refresh happens at most
        once per `refresh_seconds`, and only when the last batch did not fill the read limit (a
        full batch means there is still published data to read above the consumer cursor).
        """
        if not self._needs_refresh:
            return self.watermark
        now = time.monotonic()
        wait = self.config.refresh_seconds + self._backoff
        if self._last_refresh and now - self._last_refresh < wait:
            self.stats.refresh_throttled += 1
            return None
        self.stats.refresh_attempts += 1
        try:
            self.watermark = pg.refresh_watermark(self._conn, self.config.dispatcher, self._lease())
        except psycopg.errors.LockNotAvailable:
            self.stats.refresh_blocked += 1
            self._backoff = min(max(self._backoff * 2, self.config.poll_seconds), 2.0)
            self._last_refresh = now
            return None
        self._backoff = 0.0
        self._last_refresh = time.monotonic()
        self.stats.watermark = self.watermark
        return self.watermark

    def round(self) -> RoundResult:
        """One batch: refresh, read, plan, apply, checkpoint, deltas."""
        fence = self._lease()
        watermark = self._refresh()
        if watermark is None:
            return RoundResult(
                events=0,
                ops=0,
                applied=0,
                last_seq=0,
                cursor=self.cursor,
                watermark=self.watermark,
                deltas=0,
                blocked=True,
            )
        batch = pg.read_batch(self._conn, self.config.consumer, self.config.batch)
        self._needs_refresh = len(batch) < self.config.batch
        if not batch:
            return RoundResult(
                events=0,
                ops=0,
                applied=0,
                last_seq=0,
                cursor=self.cursor,
                watermark=watermark,
                deltas=0,
            )
        seen = pg.read_inbox(self._conn, self.config.consumer, [event.inbox_key for event in batch])
        assets = pg.prefetch_assets(self._conn, self._asset_ids(batch))
        # An edge's other end may be an asset no event of this batch names (a seed, an address a
        # later resolver found): fetch those nodes too, so the edge's phase can MERGE onto them.
        edges = pg.prefetch_relationships(self._conn, list(assets))
        incoming = pg.prefetch_incoming_relationships(self._conn, list(assets))
        endpoint_ids = {
            endpoint
            for group in (*edges.values(), *incoming.values())
            for edge in group
            for endpoint in (edge.from_asset_id, edge.to_asset_id)
        } - set(assets)
        if endpoint_ids:
            assets = {**assets, **pg.prefetch_assets(self._conn, sorted(endpoint_ids))}
        findings = pg.prefetch_findings(
            self._conn, pg.event_ids(batch, FINDING_EVENT, "finding_id")
        )
        vulnerabilities = pg.prefetch_vulnerabilities(
            self._conn, pg.event_ids(batch, VULNERABILITY_EVENT, "vulnerability_id")
        )
        matches = pg.prefetch_matches(
            self._conn, pg.event_ids(batch, VULNERABILITY_EVENT, "match_id")
        )
        evidence = pg.prefetch_evidence(
            self._conn,
            [
                str(event.payload["evidence_ref"])
                for event in batch
                if event.type == FINDING_EVENT and event.payload.get("evidence_ref")
            ],
        )
        # G1.6b: the `:Observation` node of a `graph: true` predicate reads its value and
        # confidence from PostgreSQL at apply time, like every other node property.
        observations = pg.prefetch_observations(
            self._conn, pg.event_ids(batch, OBSERVATION_EVENT, "observation_id")
        )
        planned = plan_round(
            batch,
            seen=seen,
            assets=assets,
            relationships=edges,
            incoming=incoming,
            findings=findings,
            evidence=evidence,
            observations=observations,
            partitions=max(self.config.partitions, 1),
            vulnerabilities=vulnerabilities,
            matches=matches,
        )
        applied_ops = 0
        phases = planned.phases()
        for phase in sorted(phases):
            applied_ops += self._apply(phases[phase])
        cursor = pg.checkpoint(
            self._conn,
            consumer=self.config.consumer,
            upto=planned.last_seq,
            dispatcher=self.config.dispatcher,
            fence=fence,
            applied=planned.applied,
        )
        self.cursor = cursor
        self.stats.events_applied += len(planned.applied)
        self.stats.events_skipped += planned.events - len(planned.applied)
        self.stats.ops_applied += applied_ops
        self.stats.batches += 1
        self.stats.checkpoints += 1
        now = time.monotonic()
        if planned.applied:
            self.stats.first_event_at = self.stats.first_event_at or now
            self.stats.last_event_at = now
        self.stats.cursor = cursor
        deltas = 0
        # Delta publication writes to the same outbox as the producers, so under sustained write
        # load its INSERT queues behind the publication counter like any writer. Emitting on every
        # round made the projector spend more time queueing for the counter than projecting; a
        # revision's delta only has to exist before a consumer builds its next context bundle, so
        # it is published at most once per `delta_seconds` and immediately when caught up.
        if self.config.emit_deltas and (
            cursor >= watermark or time.monotonic() - self._last_delta >= self.config.delta_seconds
        ):
            self._last_delta = time.monotonic()
            deltas = pg.emit_deltas(
                self._conn,
                consumer=self.config.consumer,
                applied_cursor=cursor,
                watermark=watermark,
                dispatcher=self.config.dispatcher,
                fence=fence,
                limit=self.config.delta_batch,
            )
            self.stats.deltas_emitted += deltas
        return RoundResult(
            events=planned.events,
            ops=applied_ops,
            applied=len(planned.applied),
            last_seq=planned.last_seq,
            cursor=cursor,
            watermark=watermark,
            deltas=deltas,
        )

    def _asset_ids(self, batch: list[OutboxEvent]) -> list[str]:
        """Every asset this batch can change: a discovered one, or an observation's subject."""
        return [
            *pg.event_ids(batch, ASSET_EVENT, "asset_id"),
            *pg.event_ids(batch, OBSERVATION_EVENT, "subject_id"),
        ]

    def _apply(self, ops: list[CypherOp]) -> int:
        """Apply one phase, one Neo4j transaction per partition, all partitions in parallel."""
        if not ops:
            return 0
        grouped: dict[int, list[CypherOp]] = {}
        for op in ops:
            grouped.setdefault(op.partition, []).append(op)
        futures = [
            self._executor.submit(graph.apply_ops, self.driver, group, retries=self.stats.retries)
            for group in grouped.values()
        ]
        for future in futures:
            future.result()  # first failure wins: the round is not checkpointed
        return len(ops)

    # -- loops -----------------------------------------------------------------------------
    def run(
        self,
        *,
        stop: threading.Event | None = None,
        until: int | None = None,
        drain_rounds: int = 0,
        timeout: float | None = None,
    ) -> ProjectorStats:
        """Project until `stop` is set, the cursor reaches `until`, or `drain_rounds` idle rounds.

        `until` is a publication sequence (rebuild/benchmark: the last published seq at start);
        `drain_rounds` stops a benchmark that waits for producers. Both are optional so the
        daemon form (neither) simply keeps running.
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        empty = 0
        while True:
            if stop is not None and stop.is_set():
                break
            if deadline is not None and time.monotonic() > deadline:
                self.stats.error = f"timeout after {timeout}s at cursor {self.cursor}"
                raise TimeoutError(self.stats.error)
            result = self.round()
            if until is not None and result.cursor >= until:
                break
            if result.events:
                empty = 0
            elif not result.blocked:
                # A non-blocked empty round means the watermark was refreshed in this very round
                # and nothing is published above the cursor: the stream is drained.
                empty += 1
                if drain_rounds and empty >= drain_rounds:
                    break
            if result.events == 0:
                time.sleep(self.config.poll_seconds)
        self.stats.finished_at = time.monotonic()
        self.stats.cursor = self.cursor
        return self.stats


def projector_from_env(*, consumer: str | None = None) -> Projector:
    """Build a projector from the environment (`AEGIS_PG_DSN`, `AEGIS_NEO4J_*`)."""
    dsn = os.environ.get(PG_DSN_ENV)
    if not dsn:
        raise RuntimeError(f"{PG_DSN_ENV} is required to run the projector")
    config = ProjectorConfig.from_env()
    if consumer is not None:
        config = replace(config, consumer=consumer)
    return Projector(dsn, neo4j_from_env(), config)
