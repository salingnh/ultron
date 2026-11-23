"""S1.3 / C04: publication ordering under real concurrency (dispatcher prototype + race harness).

What this proves (see contracts/graph/model.md#c04 and 0008_outbox_publication_order.sql):
  * writers take the shared publication lock and draw outbox_event.seq / graph_revision.revision
    from one transactional counter, so commit order equals sequence order;
  * a rollback returns its number, and a number that never commits can never stall a consumer;
  * the dispatcher publishes only up to a watermark it reads while holding the publication lock
    exclusively (exclusive try-lock), never blocks behind a slow writer, and is fenced on failover;
  * a consumer may not checkpoint past the watermark; retry is idempotent; a rebuild under a new
    consumer generation reproduces exactly the same applied events.

The prototype and the s13_harness schema live in this test file on purpose: they are evidence for
the G0 gate and a reference for G1.1d, not product code. None of it is applied to a real database:
every test gets its own throwaway database, created and dropped by the harness.

    export AEGIS_TEST_PG_DSN=postgresql://postgres:<pw>@127.0.0.1:<port>/<db>
    python3 -I contracts/tests/test_outbox_ordering.py

Point it at a throwaway PostgreSQL 16 server, never a shared one. Optional measurement tuning:
AEGIS_S13_WRITERS (8), AEGIS_S13_EVENTS (50); the S1.3 report records the 8x250 run.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
PG_DIR = ROOT / "db/postgres"
# 0008 is deliberately applied straight after 0004: it must stay independent of 0005..0007.
MIGRATIONS = (
    "0001_init.sql",
    "0002_tool_orchestration.sql",
    "0003_task_manifest_binding.sql",
    "0004_usage_nonnegative.sql",
    "0008_outbox_publication_order.sql",
)
HARNESS_SCHEMA = "s13_harness"
CAMPAIGN = "01900000-0000-7000-8000-000000000882"

try:
    import psycopg
    from psycopg import errors as pg_errors
    from psycopg.conninfo import make_conninfo
except ModuleNotFoundError:                                   # pragma: no cover - env guard
    psycopg = None
    pg_errors = None
    make_conninfo = None

DSN = os.environ.get("AEGIS_TEST_PG_DSN", "").strip()


class Harness:
    """One throwaway database per test: product migrations plus test-only helper objects."""

    def __init__(self, admin_dsn: str, migrations=MIGRATIONS):
        self.name = "aegis_s13_" + uuid.uuid4().hex[:12]
        self.admin_dsn = admin_dsn
        with psycopg.connect(admin_dsn, autocommit=True) as conn:
            conn.execute(f'CREATE DATABASE "{self.name}"')
        self.dsn = make_conninfo(admin_dsn, dbname=self.name)
        with psycopg.connect(self.dsn, autocommit=True) as conn:
            for migration in migrations:
                conn.execute((PG_DIR / migration).read_text())
            conn.execute(self._fixtures())

    def apply(self, migration: str) -> None:
        with psycopg.connect(self.dsn, autocommit=True) as conn:
            conn.execute((PG_DIR / migration).read_text())

    @staticmethod
    def _fixtures() -> str:
        # A second, test-only stream reproduces C04's failure modes on purpose (non-transactional
        # allocation: a rollback leaves a permanent gap and a later commit can land before an
        # earlier one), so the dispatcher is proven against the case it must tolerate, not only
        # against the case the locked algorithm makes impossible. Everything is in its own schema.
        return f"""
CREATE SCHEMA {HARNESS_SCHEMA};
-- campaign rows for the graph_revision foreign key
INSERT INTO aegis.policy_snapshot VALUES ('roe-8','{CAMPAIGN}',
  '{{"max_parallel_jobs":10,"max_duration_hours":168}}',repeat('a',64),'{{"kind":"operator","id":"soc-8"}}');
INSERT INTO aegis.scope_snapshot VALUES ('01900000-0000-7000-8000-000000000881',
  '{CAMPAIGN}','{{"domains":["internal.example"]}}');
INSERT INTO aegis.campaign (campaign_id,name,objective,current_policy_version,scope_id,created_by)
  VALUES ('{CAMPAIGN}','C04 ordering','Publication order','roe-8',
  '01900000-0000-7000-8000-000000000881','{{"kind":"operator","id":"soc-8"}}');
-- projection the fake consumer writes; dedup uses the real aegis.consumer_inbox
CREATE TABLE {HARNESS_SCHEMA}.projection (consumer text, seq bigint, event_id uuid, type text,
  PRIMARY KEY (consumer, seq));
-- alternative allocator: nextval under the same shared publication lock (non-transactional)
CREATE TABLE {HARNESS_SCHEMA}.alt_event (
  seq bigint PRIMARY KEY, event_id uuid NOT NULL UNIQUE, type text NOT NULL, producer text NOT NULL,
  dedup_key text NOT NULL, campaign_id uuid, payload jsonb NOT NULL, trace jsonb NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT now(), UNIQUE (type, dedup_key));
CREATE SEQUENCE {HARNESS_SCHEMA}.alt_seq;
CREATE TABLE {HARNESS_SCHEMA}.alt_watermark (id boolean PRIMARY KEY DEFAULT true CHECK (id),
  published_upto bigint NOT NULL DEFAULT 0, updated_at timestamptz NOT NULL DEFAULT now());
INSERT INTO {HARNESS_SCHEMA}.alt_watermark (id) VALUES (true);
CREATE TABLE {HARNESS_SCHEMA}.alt_cursor (consumer text PRIMARY KEY, last_seq bigint NOT NULL DEFAULT 0);
CREATE FUNCTION {HARNESS_SCHEMA}.alt_alloc() RETURNS bigint LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_advisory_xact_lock_shared(aegis.outbox_publication_lock_key());
  RETURN nextval('{HARNESS_SCHEMA}.alt_seq');
END $$;
-- no allocator at all: raw insert cost, the baseline for the cost of the C04 machinery
CREATE TABLE {HARNESS_SCHEMA}.baseline (id bigserial PRIMARY KEY, key text NOT NULL);
"""

    def connect(self, autocommit: bool = False):
        return psycopg.connect(self.dsn, autocommit=autocommit)

    def drop(self) -> None:
        with psycopg.connect(self.admin_dsn, autocommit=True) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{self.name}" WITH (FORCE)')


# ---------------------------------------------------------------------------
# Dispatcher prototype (C04): fenced, watermark-bounded, gap tolerant
# ---------------------------------------------------------------------------
class ProductStream:
    """The algorithm 0008 locks: transactional counter plus publication watermark."""

    kind = "transactional-counter"

    def insert_event(self, conn, dedup_key: str, etype: str = "job.started.v2", producer: str = "M02"):
        event_id = uuid.uuid4()
        seq = conn.execute(
            "INSERT INTO aegis.outbox_event (event_id,type,producer,dedup_key,payload,trace)"
            " VALUES (%s,%s,%s,%s,'{}'::jsonb,'{}'::jsonb) RETURNING seq",
            (event_id, etype, producer, dedup_key),
        ).fetchone()[0]
        return seq, event_id

    def refresh(self, conn, dispatcher: str, fence: int) -> int:
        return conn.execute("SELECT aegis.outbox_watermark_refresh(%s,%s)", (dispatcher, fence)).fetchone()[0]

    def watermark(self, conn) -> int:
        return conn.execute("SELECT published_upto FROM aegis.outbox_watermark").fetchone()[0]

    def batch(self, conn, consumer: str, limit: int = 100):
        return conn.execute(
            "SELECT seq,event_id,type,dedup_key FROM aegis.outbox_batch(%s,%s)", (consumer, limit)
        ).fetchall()

    def advance(self, conn, consumer: str, upto: int, dispatcher: str, fence: int) -> int:
        return conn.execute(
            "SELECT aegis.consumer_advance(%s,%s,%s,%s)", (consumer, upto, dispatcher, fence)
        ).fetchone()[0]


class SequenceStream:
    """Test-only C04 variant: nextval under the same publication lock (non-transactional)."""

    kind = "non-transactional-sequence"

    def insert_event(self, conn, dedup_key: str, etype: str = "job.started.v2", producer: str = "M02"):
        event_id = uuid.uuid4()
        # one round trip, like the product trigger: the allocator runs inside the INSERT. No
        # conn.transaction() here either: it would commit the caller's transaction and hide an
        # in-flight (slow or inverted-commit) writer from the watermark barrier.
        seq = conn.execute(
            f"INSERT INTO {HARNESS_SCHEMA}.alt_event (seq,event_id,type,producer,dedup_key,payload,trace)"
            f" VALUES ({HARNESS_SCHEMA}.alt_alloc(),%s,%s,%s,%s,'{{}}'::jsonb,'{{}}'::jsonb) RETURNING seq",
            (event_id, etype, producer, dedup_key),
        ).fetchone()[0]
        return seq, event_id

    def refresh(self, conn, dispatcher: str, fence: int) -> int:
        with conn.transaction():          # hold the exclusive lock until this short transaction ends
            conn.execute("SELECT aegis.outbox_fence_check(%s,%s)", (dispatcher, fence))
            if conn.execute("SELECT pg_try_advisory_xact_lock(aegis.outbox_publication_lock_key())").fetchone()[0]:
                conn.execute(
                    f"UPDATE {HARNESS_SCHEMA}.alt_watermark SET updated_at = now(),"
                    f" published_upto = greatest(published_upto, (SELECT CASE WHEN is_called THEN last_value ELSE 0 END"
                    f" FROM {HARNESS_SCHEMA}.alt_seq)) WHERE id"
                )
        return self.watermark(conn)

    def watermark(self, conn) -> int:
        return conn.execute(f"SELECT published_upto FROM {HARNESS_SCHEMA}.alt_watermark").fetchone()[0]

    def batch(self, conn, consumer: str, limit: int = 100):
        cursor = conn.execute(
            f"SELECT last_seq FROM {HARNESS_SCHEMA}.alt_cursor WHERE consumer = %s", (consumer,)
        ).fetchone()
        return conn.execute(
            f"SELECT seq,event_id,type,dedup_key FROM {HARNESS_SCHEMA}.alt_event"
            " WHERE seq > %s AND seq <= %s ORDER BY seq LIMIT %s",
            (cursor[0] if cursor else 0, self.watermark(conn), limit),
        ).fetchall()

    def advance(self, conn, consumer: str, upto: int, dispatcher: str, fence: int) -> int:
        conn.execute("SELECT aegis.outbox_fence_check(%s,%s)", (dispatcher, fence))
        watermark = self.watermark(conn)
        if upto > watermark:
            raise pg_errors.ObjectNotInPrerequisiteState(
                f"checkpoint {upto} past published watermark {watermark}"
            )
        return conn.execute(
            f"INSERT INTO {HARNESS_SCHEMA}.alt_cursor (consumer,last_seq) VALUES (%s,%s)"
            " ON CONFLICT (consumer) DO UPDATE SET last_seq = greatest(alt_cursor.last_seq, EXCLUDED.last_seq)"
            " RETURNING last_seq",
            (consumer, upto),
        ).fetchone()[0]


class Dispatcher:
    """Fenced outbox dispatcher prototype: lease -> watermark -> deliver -> checkpoint.

    The watermark refresh runs on its own autocommit connection: it takes the publication lock
    exclusively, and that transaction-scoped lock must be released before the (slower) delivery
    transaction, so writers are never blocked behind delivery. Delivery is at-least-once and the
    consumer inbox makes a retry idempotent.
    """

    def __init__(self, harness: Harness, stream, name: str = "s13-dispatcher", holder: str = "dispatcher-1"):
        self.stream = stream
        self.name = name
        self.holder = holder
        self.fence: int | None = None
        self.harness = harness
        self.refresh_conn = harness.connect(autocommit=True)   # short transactions only

    def take_lease(self, ttl_seconds: int = 300) -> int | None:
        self.fence = self.refresh_conn.execute(
            "SELECT aegis.outbox_dispatch_lease(%s,%s,%s)", (self.name, self.holder, ttl_seconds)
        ).fetchone()[0]
        return self.fence

    def refresh(self) -> int:
        if self.fence is None:
            raise RuntimeError("dispatcher has no lease")
        return self.stream.refresh(self.refresh_conn, self.name, self.fence)

    def dispatch_once(self, conn, consumer: str, limit: int = 100) -> int:
        batch = self.stream.batch(conn, consumer, limit)
        if not batch:
            return 0
        with conn.transaction():
            apply_batch(conn, consumer, batch)
            self.stream.advance(conn, consumer, batch[-1][0], self.name, self.fence)
        return len(batch)

    def run(self, consumer: str, limit: int = 100, max_batches: int = 1000) -> int:
        delivered = 0
        with self.harness.connect() as conn:
            for _ in range(max_batches):
                self.refresh()
                count = self.dispatch_once(conn, consumer, limit)
                conn.commit()
                if not count:
                    break
                delivered += count
        return delivered

    def close(self) -> None:
        self.refresh_conn.close()


def apply_batch(conn, consumer: str, batch) -> None:
    """At-least-once apply: inbox first, projection only on a first delivery."""
    for seq, event_id, etype, dedup_key in batch:
        inserted = conn.execute(
            "INSERT INTO aegis.consumer_inbox (consumer,dedup_key,event_id) VALUES (%s,%s,%s)"
            " ON CONFLICT DO NOTHING",
            (consumer, dedup_key, event_id),
        ).rowcount
        if inserted:
            conn.execute(
                f"INSERT INTO {HARNESS_SCHEMA}.projection (consumer,seq,event_id,type) VALUES (%s,%s,%s,%s)",
                (consumer, seq, event_id, etype),
            )


PRODUCT = ProductStream()
SEQUENCE = SequenceStream()


def setUpModule():
    if not DSN:
        raise unittest.SkipTest("AEGIS_TEST_PG_DSN is not set: the C04 harness needs a PostgreSQL 16 server")
    if psycopg is None:
        raise unittest.SkipTest("psycopg is not installed (pip install -r contracts/tests/requirements-db.txt)")


class C04(unittest.TestCase):
    def setUp(self):
        self.harness = Harness(DSN)
        self.addCleanup(self.harness.drop)
        self.p = uuid.uuid4().hex[:10]

    def event(self, conn, stream=PRODUCT, suffix: str = "", commit: bool = True):
        seq_event = stream.insert_event(conn, f"{self.p}:{stream.kind}:{suffix or uuid.uuid4().hex}")
        if commit:
            conn.commit()
        return seq_event

    def dispatcher(self, stream=PRODUCT, ttl: int = 300, name: str | None = None) -> Dispatcher:
        disp = Dispatcher(self.harness, stream, name=name or f"s13-{self.p}", holder="holder-1")
        self.addCleanup(disp.close)
        self.assertIsNotNone(disp.take_lease(ttl), "could not take the dispatcher lease")
        return disp

    def consumer(self, suffix: str = "g1") -> str:
        return f"m23-projector#{self.p}#{suffix}"

    # -- allocation -------------------------------------------------------
    def test_total_order_under_concurrent_writers(self):
        """6 connections x 40 events: one dense, strictly increasing order, nothing reused."""
        threads, per_writer, seen, failures = 6, 40, [], []
        barrier = threading.Barrier(threads)

        def writer(index):
            try:
                with self.harness.connect() as conn:
                    barrier.wait(timeout=10)
                    for k in range(per_writer):
                        seq, _ = stream_event(conn, self.p, index, k)
                        seen.append(seq)
            except BaseException as exc:                       # noqa: BLE001 - surfaced below
                failures.append(exc)

        workers = [threading.Thread(target=writer, args=(i,)) for i in range(threads)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=120)
        self.assertEqual(failures, [])
        self.assertEqual(len(seen), threads * per_writer)
        self.assertEqual(len(set(seen)), len(seen), "a publication sequence was reused")
        self.assertEqual(sorted(seen), list(range(1, threads * per_writer + 1)),
                         "publication sequence is not dense and ordered")

    def test_rollback_returns_its_number(self):
        """A rolled-back writer consumes nothing, so history has no hole to explain."""
        with self.harness.connect() as conn:
            rolled_back, _ = self.event(conn, commit=False)
            conn.rollback()
            committed, _ = self.event(conn)
        self.assertEqual(committed, rolled_back, "rollback leaked a publication sequence")

    def test_graph_revision_shares_the_publication_order(self):
        with self.harness.connect() as conn:
            event_seq, _ = self.event(conn)
            revision = conn.execute(
                "INSERT INTO aegis.graph_revision (campaign_id) VALUES (%s) RETURNING revision", (CAMPAIGN,)
            ).fetchone()[0]
            conn.commit()
        self.assertEqual(revision, event_seq + 1, "revision did not draw from the shared counter")

    # -- publication watermark -------------------------------------------
    def test_slow_writer_neither_blocks_nor_publishes_early(self):
        """An in-flight writer holds the prefix back without blocking the dispatcher."""
        disp = self.dispatcher()
        with self.harness.connect() as conn:
            published, _ = self.event(conn)
        self.assertEqual(disp.refresh(), published)

        slow = self.harness.connect()
        self.addCleanup(slow.close)
        slow_seq, _ = self.event(slow, suffix="slow", commit=False)

        started = threading.Event()
        self.addCleanup(started.set)
        thread = threading.Thread(target=lambda: (started.wait(10), slow.commit()))
        thread.start()

        began = time.monotonic()
        watermark = disp.refresh()
        elapsed = time.monotonic() - began
        self.assertLess(elapsed, 2.0, "dispatcher blocked behind a slow writer")
        self.assertEqual(watermark, published, "watermark passed an uncommitted allocation")

        consumer = self.consumer()
        with self.harness.connect() as reader:
            delivered = [row[0] for row in disp.stream.batch(reader, consumer, 100)]
            self.assertEqual(delivered, [published], "already-published prefix was withheld")
            self.assertEqual(disp.dispatch_once(reader, consumer), 1)

        started.set()
        thread.join(timeout=30)
        self.assertFalse(thread.is_alive(), "slow writer did not commit")
        self.assertEqual(disp.refresh(), slow_seq, "watermark did not advance after the slow commit")
        with self.harness.connect() as reader:
            delivered = [row[0] for row in disp.stream.batch(reader, consumer, 100)]
        self.assertEqual(delivered, [slow_seq], "the slow writer's event was skipped")

    def test_inverted_commit_is_never_published_early(self):
        """C04's hard case: seq n+1 commits while seq n is open, so n must not be skipped."""
        disp = self.dispatcher(SEQUENCE)
        slow = self.harness.connect()
        self.addCleanup(slow.close)
        first, first_event = self.event(slow, SEQUENCE, "inverted-first", commit=False)
        with self.harness.connect() as fast:
            second, _ = self.event(fast, SEQUENCE, "inverted-second", commit=True)
        self.assertEqual(second, first + 1)
        self.assertEqual(disp.refresh(), first - 1, "published past the uncommitted lower sequence")
        consumer = self.consumer()
        with self.harness.connect() as reader:
            self.assertEqual(disp.stream.batch(reader, consumer, 100), [])
            self.assertEqual(disp.dispatch_once(reader, consumer), 0)
        slow.commit()
        self.assertEqual(disp.refresh(), second)
        with self.harness.connect() as reader:
            delivered = disp.stream.batch(reader, consumer, 100)
            self.assertEqual([row[0] for row in delivered], [first, second], "an event was skipped")
            self.assertEqual(delivered[0][1], first_event)
            self.assertEqual(disp.dispatch_once(reader, consumer), 2)

    def test_crash_mid_transaction_never_stalls_a_consumer(self):
        """A writer that dies after allocating: the product reuses the number, the sequence leaves a
        permanent gap; in both cases the dispatcher moves past it and delivers every committed event."""
        for stream in (PRODUCT, SEQUENCE):
            with self.subTest(stream=stream.kind):
                crash_key = f"{self.p}:crash:{stream.kind}"
                crashed = crash_writer(self.harness, stream, crash_key)
                with self.harness.connect() as conn:
                    next_seq, _ = self.event(conn, stream, "after-crash")
                self.assertNotEqual(crash_key, f"{self.p}:{stream.kind}:after-crash")
                disp = self.dispatcher(stream)
                self.assertGreaterEqual(disp.refresh(), next_seq)
                consumer = self.consumer(stream.kind)
                with self.harness.connect() as reader:
                    delivered = disp.stream.batch(reader, consumer, 1000)
                    keys = [row[3] for row in delivered]
                    self.assertNotIn(crash_key, keys, "an event that never committed was published")
                    self.assertIn(f"{self.p}:{stream.kind}:after-crash", keys,
                                  "consumer stalled behind a dead transaction")
                    self.assertEqual(disp.dispatch_once(reader, consumer), len(delivered))
                if stream is PRODUCT:
                    self.assertEqual(next_seq, crashed, "the counter did not return the crashed number")
                else:
                    self.assertEqual(next_seq, crashed + 1, "the non-transactional sequence should have a gap")

    # -- transactions and delivery ---------------------------------------
    def test_multi_event_transaction_is_published_atomically(self):
        """A transaction's events are published together or not at all, never a prefix."""
        disp = self.dispatcher()
        conn = self.harness.connect()
        self.addCleanup(conn.close)
        seqs = [self.event(conn, suffix=f"multi:{k}", commit=False)[0] for k in range(3)]
        self.assertEqual(seqs, [seqs[0], seqs[0] + 1, seqs[0] + 2])
        self.assertLess(disp.refresh(), seqs[0], "watermark covered an uncommitted multi-event transaction")
        consumer = self.consumer()
        with self.harness.connect() as reader:
            self.assertEqual(disp.stream.batch(reader, consumer, 100), [])
        conn.commit()
        disp.refresh()
        with self.harness.connect() as reader:
            delivered = [row[0] for row in disp.stream.batch(reader, consumer, 100)]
            self.assertEqual(delivered, seqs, "multi-event transaction was published partially")
            self.assertEqual(disp.dispatch_once(reader, consumer), 3)

    def test_consumer_retry_applies_once(self):
        """At-least-once: apply committed, checkpoint lost, redelivery must not duplicate work."""
        disp = self.dispatcher()
        with self.harness.connect() as conn:
            seq, _ = self.event(conn)
        disp.refresh()
        consumer = self.consumer()
        with self.harness.connect() as reader:
            batch = disp.stream.batch(reader, consumer, 100)
            self.assertEqual([row[0] for row in batch], [seq])
            apply_batch(reader, consumer, batch)          # applied, then the process dies here
        with self.harness.connect() as reader:
            self.assertEqual(disp.dispatch_once(reader, consumer), 1)   # redelivery
            applied = reader.execute(
                f"SELECT count(*) FROM {HARNESS_SCHEMA}.projection WHERE consumer = %s AND seq = %s",
                (consumer, seq),
            ).fetchone()[0]
        self.assertEqual(applied, 1, "redelivery duplicated the projection")
        with self.harness.connect() as reader:
            self.assertEqual(disp.stream.batch(reader, consumer, 100), [])

    def test_checkpoint_cannot_pass_the_watermark(self):
        """D25: adding a consumer cannot checkpoint past data that is not published yet."""
        disp = self.dispatcher()
        with self.harness.connect() as conn:
            self.event(conn)
        disp.refresh()
        consumer = self.consumer()
        with self.harness.connect() as conn:
            with self.assertRaises(pg_errors.ObjectNotInPrerequisiteState):
                PRODUCT.advance(conn, consumer, disp.stream.watermark(conn) + 5, disp.name, disp.fence)
            conn.rollback()

    def test_fencing_rejects_a_superseded_dispatcher(self):
        """Failover: a new holder wins the lease and the old holder's writes are rejected."""
        name = f"s13-fence-{self.p}"
        first = self.dispatcher(name=name)
        second = Dispatcher(self.harness, PRODUCT, name=name, holder="holder-2")
        self.addCleanup(second.close)
        self.assertIsNone(second.take_lease(), "two dispatchers held the same lease")
        with self.harness.connect(autocommit=True) as admin:
            admin.execute(
                "UPDATE aegis.outbox_dispatcher SET leased_until = now() - interval '1 second' WHERE name = %s",
                (name,),
            )
        fence = second.take_lease()
        self.assertEqual(fence, first.fence + 1)
        with self.assertRaises(pg_errors.ObjectNotInPrerequisiteState):
            first.refresh()
        self.assertEqual(second.refresh(), 0)
        with self.harness.connect() as conn:
            self.event(conn)
        self.assertEqual(second.refresh(), 1)

    def test_rebuild_with_a_new_consumer_generation_matches(self):
        """model.md: rebuild under a new consumer generation reproduces the same applied events."""
        disp = self.dispatcher()
        for cycle in range(4):
            with self.harness.connect() as conn:
                for k in range(5):
                    self.event(conn, suffix=f"rebuild:{cycle}:{k}", commit=False)
                conn.commit()
        dispersion = self.consumer("g1")
        self.assertEqual(disp.run(dispersion, max_batches=100), 20)
        rebuilt_consumer = self.consumer("g2")
        self.assertEqual(disp.run(rebuilt_consumer, max_batches=100), 20)
        with self.harness.connect() as conn:
            original = conn.execute(
                f"SELECT seq,event_id,type FROM {HARNESS_SCHEMA}.projection WHERE consumer = %s ORDER BY seq",
                (dispersion,),
            ).fetchall()
            rebuilt = conn.execute(
                f"SELECT seq,event_id,type FROM {HARNESS_SCHEMA}.projection WHERE consumer = %s ORDER BY seq",
                (rebuilt_consumer,),
            ).fetchall()
        self.assertEqual(len(original), 20)
        self.assertEqual(rebuilt, original, "rebuild under a new generation differs from the original")

    # -- measurement ------------------------------------------------------
    def test_measured_throughput(self):
        """events/s for the locked algorithm, the C04 alternative and a no-allocator baseline."""
        writers = int(os.environ.get("AEGIS_S13_WRITERS", "8"))
        events = int(os.environ.get("AEGIS_S13_EVENTS", "50"))
        rows = []
        for label, stream, batch in (
            ("transactional-counter, 1/commit", PRODUCT, 1),
            ("transactional-counter, 10/commit", PRODUCT, 10),
            ("non-transactional-sequence, 1/commit", SEQUENCE, 1),
            ("no allocator baseline, 1/commit", None, 1),
        ):
            duration = measure(self.harness, stream, writers, events, self.p, label.replace(" ", "-"), batch)
            rows.append((label, writers * events / duration))
        report = (f"C04 throughput: {writers} writers x {events} events"
                  + "".join(f"\n  {label:<38} {rate:9.1f} events/s" for label, rate in rows))
        print(report, file=sys.stderr)
        self.assertGreater(min(rate for _, rate in rows), 0)


class UpgradeC04(unittest.TestCase):
    """0008 lands on a database that already has outbox/revision history (0001..0004 rows)."""

    def test_upgrade_seeds_the_counter_above_historical_rows(self):
        history = Harness(DSN, migrations=MIGRATIONS[:4])       # 0001..0004 only: bigserial seq
        self.addCleanup(history.drop)
        with history.connect() as conn:
            old_events = [conn.execute(
                "INSERT INTO aegis.outbox_event (event_id,type,producer,dedup_key,payload,trace)"
                " VALUES (%s,'job.started.v1','M02',%s,'{}'::jsonb,'{}'::jsonb) RETURNING seq",
                (uuid.uuid4(), f"history:{k}")).fetchone()[0] for k in range(2)]
            old_revision = conn.execute(
                "INSERT INTO aegis.graph_revision (campaign_id) VALUES (%s) RETURNING revision", (CAMPAIGN,)
            ).fetchone()[0]
            conn.commit()
        history.apply("0008_outbox_publication_order.sql")
        highest = max(old_events + [old_revision])
        with history.connect() as conn:
            counter, watermark = conn.execute(
                "SELECT next_seq, published_upto FROM aegis.outbox_publication, aegis.outbox_watermark"
            ).fetchone()
            self.assertEqual(counter, highest + 1, "counter was not seeded above historical seq values")
            self.assertEqual(watermark, highest, "historical rows were not treated as published")
            new_seq = PRODUCT.insert_event(conn, "after-upgrade")[0]
            conn.commit()
        self.assertEqual(new_seq, highest + 1, "new allocation is not ordered after history")
        disp = Dispatcher(history, PRODUCT, name="upgrade-dispatcher", holder="upgrade")
        self.addCleanup(disp.close)
        self.assertIsNotNone(disp.take_lease())
        self.assertEqual(disp.refresh(), new_seq)
        with history.connect() as conn:
            delivered = [row[0] for row in PRODUCT.batch(conn, "m23-projector#upgrade", 100)]
            self.assertEqual(delivered[:2], old_events, "historical events are no longer deliverable")
            self.assertEqual(delivered[-1], new_seq)
            self.assertEqual(PRODUCT.advance(conn, "m23-projector#upgrade", new_seq, disp.name, disp.fence), new_seq)


def stream_event(conn, prefix, index, k):
    seq = conn.execute(
        "INSERT INTO aegis.outbox_event (event_id,type,producer,dedup_key,payload,trace)"
        " VALUES (%s,'job.started.v2','M02',%s,'{}'::jsonb,'{}'::jsonb) RETURNING seq",
        (uuid.uuid4(), f"{prefix}:ordered:{index}:{k}"),
    ).fetchone()[0]
    conn.commit()
    return seq, None


def crash_writer(harness: Harness, stream, dedup_key: str) -> int:
    """A writer that allocates a publication number and dies before commit (SIGKILL-like)."""
    script = f"""
import os, sys, uuid, psycopg
dsn, kind, dedup = sys.argv[1], sys.argv[2], sys.argv[3]
conn = psycopg.connect(dsn)
if kind == "transactional-counter":
    seq = conn.execute(
        "INSERT INTO aegis.outbox_event (event_id,type,producer,dedup_key,payload,trace)"
        " VALUES (%s,'job.started.v2','M02',%s,'{{}}'::jsonb,'{{}}'::jsonb) RETURNING seq",
        (uuid.uuid4(), dedup)).fetchone()[0]
else:
    seq = conn.execute("SELECT {HARNESS_SCHEMA}.alt_alloc()").fetchone()[0]
    conn.execute(
        "INSERT INTO {HARNESS_SCHEMA}.alt_event (seq,event_id,type,producer,dedup_key,payload,trace)"
        " VALUES (%s,%s,'job.started.v2','M02',%s,'{{}}'::jsonb,'{{}}'::jsonb)",
        (seq, uuid.uuid4(), dedup))
print(seq, flush=True)
os._exit(9)          # no commit, no clean close: the server aborts the transaction
"""
    process = subprocess.run(
        [sys.executable, "-c", script, harness.dsn, stream.kind, dedup_key],
        capture_output=True, text=True, timeout=60,
    )
    if process.returncode != 9:
        raise AssertionError(f"crash writer failed: {process.returncode} {process.stderr}")
    return int(process.stdout.strip().splitlines()[-1])


def measure(harness: Harness, stream, writers: int, events: int, prefix: str, label: str,
            batch: int = 1) -> float:
    barrier = threading.Barrier(writers)
    errors: list[BaseException] = []

    def writer(index: int) -> None:
        try:
            with harness.connect() as conn:
                barrier.wait(timeout=30)
                for k in range(events):
                    if stream is None:
                        conn.execute(f"INSERT INTO {HARNESS_SCHEMA}.baseline (key) VALUES (%s)",
                                     (f"{prefix}:{label}:{index}:{k}",))
                    else:
                        stream.insert_event(conn, f"{prefix}:{label}:{index}:{k}")
                    if (k + 1) % batch == 0 or k == events - 1:
                        conn.commit()
        except BaseException as exc:                            # noqa: BLE001 - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(writers)]
    began = time.monotonic()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=600)
    duration = time.monotonic() - began
    if errors:
        raise errors[0]
    return duration


if __name__ == "__main__":
    unittest.main(verbosity=2)
