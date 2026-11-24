#!/usr/bin/env python3
"""C06 with live connections: exactly one terminal result under contention, late results quarantined.

The reference calls are the executable form of docs/living/dac-ta-ky-thuat/05 §C06 and of
contracts/db/postgres/0001_baseline.sql (`aegis.record_job_callback`, `aegis.request_job_cancel`).

    export AEGIS_TEST_PG_DSN=postgresql://postgres:<pw>@127.0.0.1:<port>/<db>
    python3 -I contracts/tests/test_job_lifecycle_race.py

Every test provisions its own throwaway database: it applies 0001..0007 and drops the database at
the end, so the DSN only needs a PostgreSQL 16 server, not a migrated schema, and nothing touches a
shared database. A missing DSN skips (the gate sets it); once the DSN is set, any provisioning
failure fails the test instead of skipping, so the gate cannot pass without running it.
"""
from __future__ import annotations

import os
from pathlib import Path
import threading
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
PG_DIR = ROOT / "db/postgres"
MIGRATIONS = ("0001_baseline.sql",)
DSN = os.environ.get("AEGIS_TEST_PG_DSN", "").strip()

try:  # psycopg is only needed for DB tests; schema tests must keep working without it.
    import psycopg
    from psycopg.types.json import Jsonb
    from psycopg.conninfo import make_conninfo
except ImportError:  # pragma: no cover
    psycopg = None
    Jsonb = None
    make_conninfo = None

SCOPE = "01900000-0000-7000-8000-0000000c0601"
CAMP = "01900000-0000-7000-8000-0000000c0602"
SEED = "01900000-0000-7000-8000-0000000c0603"
POLICY = "roe-43"
ACTOR = {"kind": "operator", "id": "c06-fixture"}
TERMINAL = ("SUCCEEDED", "FAILED", "CANCELLED")


def new_id() -> str:
    raw = uuid.uuid4()
    return str(uuid.UUID(int=(raw.int & ~(0xF << 76)) | (7 << 76) | (0b10 << 62)))


def connect(dsn: str, autocommit: bool = True):
    conn = psycopg.connect(dsn, autocommit=autocommit)
    # The AEGIS tables live in schema `aegis` (0001); trigger functions resolve unqualified names
    # through this search_path, as the psql chains and the services do.
    conn.execute("SET search_path = aegis, public")
    conn.execute("SET TIME ZONE 'UTC'")
    return conn


class Harness:
    """One throwaway database per test, created and dropped here; never a shared database."""

    def __init__(self, admin_dsn: str):
        self.name = "aegis_c06_" + uuid.uuid4().hex[:12]
        self.admin_dsn = admin_dsn
        with psycopg.connect(admin_dsn, autocommit=True) as conn:
            conn.execute(f'CREATE DATABASE "{self.name}"')
        self.dsn = make_conninfo(admin_dsn, dbname=self.name)
        with psycopg.connect(self.dsn, autocommit=True) as conn:
            for migration in MIGRATIONS:
                conn.execute((PG_DIR / migration).read_text())

    def connect(self, autocommit: bool = True):
        return connect(self.dsn, autocommit)

    def drop(self) -> None:
        with psycopg.connect(self.admin_dsn, autocommit=True) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{self.name}" WITH (FORCE)')


def setUpModule():
    if not DSN:
        raise unittest.SkipTest("AEGIS_TEST_PG_DSN is not set: the C06 harness needs a PostgreSQL 16 server")
    if psycopg is None:
        # The gate installs requirements-db.txt; a DSN without the driver is a broken gate, not a skip.
        raise RuntimeError("psycopg is not installed: pip install -r contracts/tests/requirements-db.txt")


class JobLifecycleRace(unittest.TestCase):
    def setUp(self):
        self.harness = Harness(DSN)  # a provisioning failure is an error, never a skip
        self.addCleanup(self.harness.drop)
        self.conns = []
        self.seed()

    def tearDown(self):
        for conn in self.conns:
            conn.close()

    def connection(self, autocommit: bool = True):
        conn = self.harness.connect(autocommit)
        self.conns.append(conn)
        return conn

    def seed(self) -> None:
        conn = self.connection()
        with conn.transaction():
            conn.execute(
                "INSERT INTO aegis.policy_snapshot (policy_version,campaign_id,policy,policy_hash,created_by)"
                " VALUES (%s,%s,%s,%s,%s) ON CONFLICT (policy_version) DO NOTHING",
                (POLICY, CAMP, Jsonb({"max_parallel_jobs": 50, "max_duration_hours": 168}), "7" * 64, Jsonb(ACTOR)))
            conn.execute(
                "INSERT INTO aegis.scope_snapshot (scope_id,campaign_id,targets) VALUES (%s,%s,%s)"
                " ON CONFLICT (scope_id) DO NOTHING",
                (SCOPE, CAMP, Jsonb({"domains": ["c06.example"]})))
            conn.execute(
                "INSERT INTO aegis.campaign (campaign_id,name,objective,current_policy_version,scope_id,created_by)"
                " VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT (campaign_id) DO NOTHING",
                (CAMP, "C06 lifecycle", "cancel/complete race", POLICY, SCOPE, Jsonb(ACTOR)))
            conn.execute(
                "INSERT INTO aegis.campaign_target (target_id,scope_id,kind,raw_value,canonical_key)"
                " VALUES (%s,%s,'domain','c06.example','dns:c06.example') ON CONFLICT (target_id) DO NOTHING",
                (SEED, SCOPE))

    def running_job(self, status: str = "RUNNING") -> str:
        """A fresh dispatched job; the fingerprint is unique per run, DELETE is forbidden."""
        job, decision, extra = new_id(), new_id(), uuid.uuid4().hex
        conn = self.connection()
        with conn.transaction():
            conn.execute(
                "INSERT INTO aegis.policy_decision (decision_id,campaign_id,capability,provider,targets,input,"
                "decision,rationale,requested_by,target_refs,policy_version,scope_id,idempotency_key,trace_id)"
                " VALUES (%s,%s,'dns.enumerate_subdomains','subfinder',%s,%s,'approved','c06 fixture',%s,%s,%s,%s,%s,%s)",
                (decision, CAMP, [], Jsonb({"targets": ["c06.example"]}),
                 Jsonb({"kind": "operator", "id": "fixture-operator"}), Jsonb([{"seed_id": SEED}]),
                 POLICY, SCOPE, f"c06:{extra}", "7" * 32))
            conn.execute(
                "INSERT INTO aegis.scan_job (job_id,campaign_id,decision_id,capability,provider,provider_version,"
                "adapter_version,image_digest,manifest_sha256,scan_cycle,job_fingerprint,policy_version,scope_id,"
                "input,targets,target_refs,requested_by,rationale,trace_id,status,attempt,started_at)"
                " VALUES (%s,%s,%s,'dns.enumerate_subdomains','subfinder','v2.6.6','1.0.0',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,"
                "'c06 fixture',%s,%s,1,now())",
                (job, CAMP, decision, "sha256:" + "5" * 64, "6" * 64, new_id(), (uuid.uuid4().hex * 2)[:64],
                 POLICY, SCOPE, Jsonb({"targets": ["c06.example"]}), [],
                 Jsonb([{"seed_id": SEED}]), Jsonb({"kind": "operator", "id": "fixture-operator"}),
                 "7" * 32, status))
        return job

    # --- reference calls -------------------------------------------------------------------
    def callback(self, conn, job: str, status: str, attempt: int = 1, generation: int = 1,
                 envelope: str | None = None, error: dict | None = None):
        return conn.execute(
            "SELECT aegis.record_job_callback(%s,%s,%s,%s,%s,%s)",
            (job, generation, attempt, status, envelope, Jsonb(error) if error else None)).fetchone()[0]

    def cancel(self, conn, job: str):
        return conn.execute("SELECT aegis.request_job_cancel(%s,%s,%s)",
                            (job, Jsonb(ACTOR), "c06 fixture")).fetchone()[0]

    def state(self, conn, job: str):
        return conn.execute(
            "SELECT status, attempt, generation, cancel_requested_at IS NOT NULL, envelope_event_id"
            " FROM aegis.scan_job WHERE job_id=%s", (job,)).fetchone()

    def terminal_rows(self, conn, job: str) -> int:
        return conn.execute(
            "SELECT count(*) FROM aegis.job_status_change WHERE job_id=%s AND to_status IN"
            " ('SUCCEEDED','FAILED','CANCELLED')", (job,)).fetchone()[0]

    def quarantine(self, conn, job: str):
        return conn.execute(
            "SELECT reason FROM aegis.job_callback_quarantine WHERE job_id=%s ORDER BY recorded_at, reason",
            (job,)).fetchall()

    # --- tests ------------------------------------------------------------------------------
    def test_a_second_callback_waits_on_the_row_and_cannot_terminalize(self):
        job = self.running_job()
        writer = self.connection(autocommit=False)
        loser = self.connection()
        self.assertEqual(self.cancel(loser, job), "requested")
        # The winner holds the row lock inside its own transaction, exactly like a slow M06 commit.
        self.assertEqual(self.callback(writer, job, "CANCELLED"), "terminalized")
        loser.execute("SET lock_timeout = '300ms'")
        try:
            with self.assertRaises(psycopg.errors.LockNotAvailable):
                self.callback(loser, job, "SUCCEEDED")
        finally:
            loser.execute("SET lock_timeout = 0")
        writer.commit()
        self.assertEqual(self.callback(loser, job, "SUCCEEDED", envelope=new_id()), "quarantined")
        status, attempt, generation, has_intent, envelope = self.state(loser, job)
        self.assertEqual(status, "CANCELLED")
        self.assertEqual((attempt, generation), (1, 1))
        self.assertTrue(has_intent)  # the intent stays recorded; it just lost the race for the result
        self.assertIsNone(envelope)
        self.assertEqual(self.terminal_rows(loser, job), 1)
        self.assertEqual(self.quarantine(loser, job), [("terminal_already_recorded",)])

    def test_concurrent_complete_and_cancel_leave_exactly_one_terminal(self):
        for _ in range(3):  # repeated so the two orders both show up on a busy runner
            job = self.running_job()
            setter = self.connection()
            self.assertEqual(self.cancel(setter, job), "requested")
            outcomes: dict[str, str] = {}
            barrier = threading.Barrier(2)

            def run(status: str):
                conn = connect(self.harness.dsn)
                try:
                    barrier.wait(10)
                    outcomes[status] = self.callback(conn, job, status, envelope=new_id() if status == "SUCCEEDED" else None)
                finally:
                    conn.close()

            threads = [threading.Thread(target=run, args=(status,)) for status in ("SUCCEEDED", "CANCELLED")]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(20)
                self.assertFalse(thread.is_alive(), "callback did not finish")
            self.assertEqual(sorted(outcomes.values()), ["quarantined", "terminalized"], outcomes)
            status, _, _, has_intent, _ = self.state(setter, job)
            self.assertIn(status, TERMINAL)
            self.assertTrue(has_intent)
            self.assertEqual(self.terminal_rows(setter, job), 1)
            self.assertEqual(len(self.quarantine(setter, job)), 1)

    def test_duplicate_completion_is_idempotent_under_contention(self):
        job = self.running_job()
        envelope = new_id()
        outcomes: dict[str, list[str]] = {"a": [], "b": []}
        barrier = threading.Barrier(2)

        def run(name: str):
            conn = connect(self.harness.dsn)
            try:
                barrier.wait(10)
                outcomes[name].append(self.callback(conn, job, "SUCCEEDED", envelope=envelope))
            finally:
                conn.close()

        threads = [threading.Thread(target=run, args=(name,)) for name in ("a", "b")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(20)
        self.assertEqual(sorted(outcomes["a"] + outcomes["b"]), ["duplicate", "terminalized"])
        checker = self.connection()
        status, _, _, _, stored = self.state(checker, job)
        self.assertEqual(status, "SUCCEEDED")
        self.assertEqual(str(stored), envelope)
        self.assertEqual(self.terminal_rows(checker, job), 1)
        self.assertEqual(self.quarantine(checker, job), [])
        self.assertEqual(checker.execute(
            "SELECT count(*) FROM aegis.evidence WHERE job_id=%s", (job,)).fetchone()[0], 0)

    def test_cancel_intent_is_written_once_across_connections(self):
        job = self.running_job(status="QUEUED")
        outcomes: dict[str, list[str]] = {"a": [], "b": []}
        barrier = threading.Barrier(2)

        def run(name: str):
            conn = connect(self.harness.dsn)
            try:
                barrier.wait(10)
                outcomes[name].append(self.cancel(conn, job))
            finally:
                conn.close()

        threads = [threading.Thread(target=run, args=(name,)) for name in ("a", "b")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(20)
        self.assertEqual(sorted(outcomes["a"] + outcomes["b"]), ["already_requested", "requested"])
        conn = self.connection()
        self.assertEqual(conn.execute(
            "SELECT count(*) FROM aegis.job_lifecycle_change WHERE job_id=%s AND field='cancel_request'"
            " AND new_value->>'requested_at' IS NOT NULL", (job,)).fetchone()[0], 1)
        # A queued job can be cancelled outright, without any container ever starting.
        self.assertEqual(self.callback(conn, job, "CANCELLED"), "terminalized")
        self.assertEqual(self.state(conn, job)[0], "CANCELLED")


if __name__ == "__main__":
    unittest.main()
