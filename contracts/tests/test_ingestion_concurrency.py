#!/usr/bin/env python3
"""C03 with live connections: one logical result per dedup_key, first receipt replay, 409 conflict.

The reference flow below is the executable form of contracts/ingestion/canonicalization.v2.yaml
(§receipt) and of docs/living/dac-ta-ky-thuat/05 §C03. It is tests-only: it proves what the DDL
(0006) enforces and that the hash projection makes event_id/trace non-content.

    export AEGIS_TEST_PG_DSN=postgresql://postgres:<pw>@127.0.0.1:<port>/<db>
    python3 -I contracts/tests/test_ingestion_concurrency.py

Every test provisions its own throwaway database: it applies 0001..0006 and drops the database at
the end, so the DSN only needs a PostgreSQL 16 server, not a migrated schema, and nothing touches a
shared database. A missing DSN skips (the gate sets it); once the DSN is set, any provisioning
failure fails the test instead of skipping, so the gate cannot pass without running it.
"""
from __future__ import annotations

import json
import os
import runpy
import threading
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PG_DIR = ROOT / "db/postgres"
MIGRATIONS = ("0001_baseline.sql",)
DSN = os.environ.get("AEGIS_TEST_PG_DSN", "").strip()
CANON = runpy.run_path(str(ROOT / "tests/canonicalization.py"))
payload_hash = CANON["payload_hash"]
HASH_VERSION = CANON["HASH_VERSION"]

try:  # psycopg is only needed for DB tests; schema tests must keep working without it.
    import psycopg
    from psycopg.types.json import Jsonb
    from psycopg.conninfo import make_conninfo
except ImportError:  # pragma: no cover
    psycopg = None
    Jsonb = None
    make_conninfo = None

SCOPE = "01900000-0000-7000-8000-0000000c0301"
CAMP = "01900000-0000-7000-8000-0000000c0302"
SEED = "01900000-0000-7000-8000-0000000c0303"
POLICY = "roe-42"
NOW = "2026-11-24T02:00:00Z"


def new_id() -> str:
    """A UUIDv7-shaped id; the contract only requires the v7 layout in these tests."""
    raw = uuid.uuid4()
    return str(uuid.UUID(int=(raw.int & ~(0xF << 76)) | (7 << 76) | (0b10 << 62)))


def connect(dsn: str, autocommit: bool = True):
    # autocommit: each submit() opens and commits its own transaction, exactly as M27 must, so a
    # connection closed after the commit (a crash before responding) keeps the committed receipt.
    conn = psycopg.connect(dsn, autocommit=autocommit)
    # Same session contract as the psql chains and the services: the AEGIS tables live in schema
    # `aegis` (0001). Trigger functions resolve unqualified names through this search_path.
    conn.execute("SET search_path = aegis, public")
    conn.execute("SET TIME ZONE 'UTC'")
    return conn


class Harness:
    """One throwaway database per test, created and dropped here; never a shared database."""

    def __init__(self, admin_dsn: str):
        self.name = "aegis_c03_" + uuid.uuid4().hex[:12]
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


def seed(conn) -> None:
    """Fixed campaign/scope/target rows (idempotent) plus one fresh job for this run."""
    with conn.transaction():
        conn.execute(
            "INSERT INTO aegis.policy_snapshot (policy_version,campaign_id,policy,policy_hash,created_by)"
            " VALUES (%s,%s,%s,%s,%s) ON CONFLICT (policy_version) DO NOTHING",
            (POLICY, CAMP, Jsonb({"max_parallel_jobs": 50, "max_duration_hours": 168}), "6" * 64,
             Jsonb({"kind": "operator", "id": "c03-fixture"})))
        conn.execute(
            "INSERT INTO aegis.scope_snapshot (scope_id,campaign_id,targets) VALUES (%s,%s,%s)"
            " ON CONFLICT (scope_id) DO NOTHING",
            (SCOPE, CAMP, Jsonb({"domains": ["c03.example"]})))
        conn.execute(
            "INSERT INTO aegis.campaign (campaign_id,name,objective,current_policy_version,scope_id,created_by)"
            " VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT (campaign_id) DO NOTHING",
            (CAMP, "C03 hash/receipt", "ingestion dedup", POLICY, SCOPE,
             Jsonb({"kind": "operator", "id": "c03-fixture"})))
        conn.execute(
            "INSERT INTO aegis.campaign_target (target_id,scope_id,kind,raw_value,canonical_key)"
            " VALUES (%s,%s,'domain','c03.example','dns:c03.example') ON CONFLICT (target_id) DO NOTHING",
            (SEED, SCOPE))


def new_job(conn) -> str:
    """A fresh accepted job; the fingerprint is unique per run, the schema forbids DELETE."""
    job = new_id()
    decision = new_id()
    run = uuid.uuid4().hex
    with conn.transaction():
        conn.execute(
            "INSERT INTO aegis.policy_decision (decision_id,campaign_id,capability,provider,targets,input,"
            "decision,rationale,requested_by,target_refs,policy_version,scope_id,idempotency_key,trace_id)"
            " VALUES (%s,%s,'dns.enumerate_subdomains','subfinder',%s,%s,'approved','c03 fixture',%s,%s,%s,%s,%s,%s)",
            (decision, CAMP, [], Jsonb({"targets": ["c03.example"]}),
             Jsonb({"kind": "operator", "id": "fixture-operator"}), Jsonb([{"seed_id": SEED}]),
             POLICY, SCOPE, f"c03:{run}", "6" * 32))
        conn.execute(
            "INSERT INTO aegis.scan_job (job_id,campaign_id,decision_id,capability,provider,provider_version,"
            "adapter_version,image_digest,manifest_sha256,scan_cycle,job_fingerprint,policy_version,scope_id,"
            "input,targets,target_refs,requested_by,rationale,trace_id)"
            " VALUES (%s,%s,%s,'dns.enumerate_subdomains','subfinder','v2.6.6','1.0.0',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'c03 fixture',%s)",
            (job, CAMP, decision, "sha256:" + "5" * 64, "6" * 64, new_id(), (uuid.uuid4().hex * 2)[:64],
             POLICY, SCOPE, Jsonb({"targets": ["c03.example"]}), [],
             Jsonb([{"seed_id": SEED}]), Jsonb({"kind": "operator", "id": "fixture-operator"}), "6" * 32))
    return job


def envelope(job: str, **overrides) -> dict:
    """A minimal but schema-shaped ResultEnvelope; overrides model a different logical result."""
    env = {
        "schema_version": "2.0",
        "event_id": new_id(),
        "dedup_key": f"job:{job}:envelope",
        "job_id": job,
        "campaign_id": CAMP,
        "scope_id": SCOPE,
        "capability": "dns.enumerate_subdomains",
        "provider": {"name": "subfinder", "version": "v2.6.6", "adapter_version": "1.0.0"},
        "policy_version": POLICY,
        "status": "succeeded",
        "coverage": {"subjects": ["dns:c03.example"], "complete": True},
        "results": {
            "assets": [{"kind": "domain", "canonical_key": "dns:c03.example"}],
            "observations": [{"subject": "dns:c03.example", "predicate": "asset.seen",
                              "value": True, "observed_at": NOW}],
            "relationships": [],
            "findings": [],
        },
        "evidence": [{"local_ref": "raw", "sha256": "1" * 64,
                      "uri": f"s3://evidence/{CAMP}/{job}/" + "1" * 64,
                      "size_bytes": 10, "media_type": "text/plain", "classification": "INTERNAL"}],
        "errors": [],
        "provenance": {"input_fingerprint": "2" * 64, "started_at": NOW, "finished_at": NOW,
                       "seed_targets": [{"seed_id": SEED}]},
        "trace": {"trace_id": uuid.uuid4().hex, "span_id": uuid.uuid4().hex[:16]},
    }
    env.update(overrides)
    return env


def submit(conn, env: dict, on_first_insert=None):
    """M27 reference flow for one submission.

    Returns ("accepted"|"duplicate"|"conflict", payload) where payload is the IngestReceipt for the
    first two outcomes and an Error for a conflict. The receipt is written in the same transaction
    as the inbox row, so a crash after commit always leaves a complete first receipt behind.
    """
    content_hash = payload_hash(env)
    with conn.transaction():
        row = conn.execute(
            "INSERT INTO aegis.ingestion_inbox (event_id,dedup_key,job_id,payload_hash,hash_version,status)"
            " VALUES (%s,%s,%s,%s,%s,'received') ON CONFLICT (dedup_key) DO NOTHING RETURNING event_id",
            (env["event_id"], env["dedup_key"], env["job_id"], content_hash, HASH_VERSION)).fetchone()
        if row is not None:
            if on_first_insert is not None:
                # Test hook: hold the row lock while a second connection races for the same key.
                on_first_insert(conn)
            revision = conn.execute(
                "INSERT INTO aegis.graph_revision (campaign_id,causal_job_id,envelope_event_id)"
                " VALUES (%s,%s,%s) RETURNING revision",
                (env["campaign_id"], env["job_id"], env["event_id"])).fetchone()[0]
            receipt = {
                "event_id": env["event_id"], "dedup_key": env["dedup_key"], "accepted": True,
                "duplicate": False, "revision": revision, "quarantined": [],
                "payload_hash": content_hash, "hash_version": HASH_VERSION,
                "decided_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            conn.execute(
                "UPDATE aegis.ingestion_inbox SET status='accepted', receipt=%s, revision=%s, processed_at=now()"
                " WHERE event_id=%s AND receipt IS NULL", (Jsonb(receipt), revision, env["event_id"]))
            conn.execute(
                "INSERT INTO aegis.ingestion_attempt (event_id,dedup_key,inbox_event_id,payload_hash,hash_version,outcome)"
                " VALUES (%s,%s,%s,%s,%s,'first')",
                (env["event_id"], env["dedup_key"], env["event_id"], content_hash, HASH_VERSION))
            return "accepted", receipt

        existing = conn.execute(
            "SELECT event_id,payload_hash,hash_version,receipt FROM aegis.ingestion_inbox WHERE dedup_key=%s",
            (env["dedup_key"],)).fetchone()
        if existing is None:  # pragma: no cover - would mean the unique index lied
            raise AssertionError("inbox row disappeared between insert and read")
        inbox_event, stored_hash, stored_version, stored_receipt = existing
        if stored_receipt is not None and stored_hash == content_hash and stored_version == HASH_VERSION:
            conn.execute(
                "INSERT INTO aegis.ingestion_attempt (event_id,dedup_key,inbox_event_id,payload_hash,hash_version,outcome)"
                " VALUES (%s,%s,%s,%s,%s,'duplicate')",
                (env["event_id"], env["dedup_key"], inbox_event, content_hash, HASH_VERSION))
            return "duplicate", stored_receipt

        if stored_version != HASH_VERSION:
            reason = "hash_version_mismatch"
        else:
            reason = "hash_mismatch"
        detail = {"reason": reason, "existing_payload_hash": stored_hash,
                  "existing_hash_version": stored_version, "submitted_payload_hash": content_hash}
        conn.execute(
            "INSERT INTO aegis.ingestion_attempt"
            " (event_id,dedup_key,inbox_event_id,payload_hash,hash_version,outcome,detail)"
            " VALUES (%s,%s,%s,%s,%s,'conflict',%s)",
            (env["event_id"], env["dedup_key"], inbox_event, content_hash, HASH_VERSION, Jsonb(detail)))
        return "conflict", {
            "code": "IDEMPOTENCY_CONFLICT",
            "message": f"dedup_key {env['dedup_key']} already holds different content ({reason})",
            "next_action": "ESCALATE",
            "retryable": False,
            "trace_id": env["trace"]["trace_id"],
        }


def attempts(conn, dedup_key: str) -> list[tuple[str, str]]:
    return conn.execute(
        "SELECT outcome,payload_hash FROM aegis.ingestion_attempt WHERE dedup_key=%s ORDER BY attempt_seq",
        (dedup_key,)).fetchall()


def setUpModule():
    if not DSN:
        raise unittest.SkipTest("AEGIS_TEST_PG_DSN is not set: the C03 harness needs a PostgreSQL 16 server")
    if psycopg is None:
        # The gate installs requirements-db.txt; a DSN without the driver is a broken gate, not a skip.
        raise RuntimeError("psycopg is not installed: pip install -r contracts/tests/requirements-db.txt")


class IngestionConcurrency(unittest.TestCase):
    def setUp(self):
        self.harness = Harness(DSN)  # a provisioning failure is an error, never a skip
        self.addCleanup(self.harness.drop)
        self.conns = []

    def tearDown(self):
        for conn in self.conns:
            conn.close()

    def connection(self, autocommit: bool = True):
        conn = self.harness.connect(autocommit)
        self.conns.append(conn)
        return conn

    def job(self) -> str:
        conn = self.connection()
        seed(conn)
        return new_job(conn)

    def test_event_id_and_trace_are_not_content(self):
        job = self.job()
        conn = self.connection()
        first = envelope(job)
        outcome, receipt = submit(conn, first)
        self.assertEqual(outcome, "accepted")
        retry = envelope(job)  # same business content, new event_id and trace
        self.assertNotEqual(first["event_id"], retry["event_id"])
        self.assertNotEqual(first["trace"]["trace_id"], retry["trace"]["trace_id"])
        self.assertEqual(payload_hash(first), payload_hash(retry))
        outcome, replay = submit(conn, retry)
        self.assertEqual(outcome, "duplicate")
        self.assertEqual(replay, receipt)  # the first committed receipt, byte for byte
        self.assertEqual(len(conn.execute(
            "SELECT 1 FROM aegis.ingestion_inbox WHERE dedup_key=%s", (first["dedup_key"],)).fetchall()), 1)
        self.assertEqual([a[0] for a in attempts(conn, first["dedup_key"])], ["first", "duplicate"])

    def test_each_changed_result_field_is_a_conflict_and_overwrites_nothing(self):
        cases = {
            "evidence": {"evidence": []},
            "coverage": {"coverage": {"subjects": ["dns:c03.example"], "complete": False}},
            "value": {"results": {"assets": [{"kind": "domain", "canonical_key": "dns:c03.example"}],
                                  "observations": [{"subject": "dns:c03.example", "predicate": "asset.seen",
                                                    "value": False, "observed_at": NOW}],
                                  "relationships": [], "findings": []}},
            "status": {"status": "partial"},
            "provenance": {"provenance": {"input_fingerprint": "3" * 64, "started_at": NOW,
                                          "finished_at": NOW, "seed_targets": [{"seed_id": SEED}]}},
        }
        for name, change in cases.items():
            with self.subTest(changed=name):
                job = self.job()
                conn = self.connection()
                first = envelope(job)
                outcome, receipt = submit(conn, first)
                self.assertEqual(outcome, "accepted")
                changed = envelope(job, **change)
                self.assertNotEqual(payload_hash(first), payload_hash(changed), name)
                outcome, error = submit(conn, changed)
                self.assertEqual(outcome, "conflict")
                self.assertEqual(error["code"], "IDEMPOTENCY_CONFLICT")
                self.assertEqual(self.check_error(error), [])
                row = conn.execute(
                    "SELECT payload_hash,hash_version,receipt FROM aegis.ingestion_inbox WHERE dedup_key=%s",
                    (first["dedup_key"],)).fetchone()
                self.assertEqual(row, (payload_hash(first), HASH_VERSION, receipt))
                self.assertEqual([a[0] for a in attempts(conn, first["dedup_key"])], ["first", "conflict"])

    def check_error(self, error: dict) -> list[str]:
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource
        docs = [json.loads(p.read_text()) for p in ROOT.rglob("*.schema.json")]
        registry = Registry().with_resources((d["$id"], Resource.from_contents(d)) for d in docs)
        validator = Draft202012Validator(
            {"$ref": "https://aegis.io/contracts/common/error.v2.schema.json"},
            registry=registry)
        return [f"{'/'.join(map(str, e.absolute_path))}: {e.message}" for e in validator.iter_errors(error)]

    def test_retry_after_crash_returns_the_committed_receipt(self):
        job = self.job()
        crashed = self.connection()
        outcome, receipt = submit(crashed, envelope(job))
        self.assertEqual(outcome, "accepted")
        crashed.close()  # the process dies after COMMIT, before the caller sees the response
        self.conns.remove(crashed)
        retry = self.connection()
        outcome, replay = submit(retry, envelope(job))
        self.assertEqual(outcome, "duplicate")
        self.assertEqual(replay, receipt)
        self.assertEqual(replay["event_id"], receipt["event_id"])

    def test_two_racing_connections_write_one_logical_result(self):
        job = self.job()
        first, second = envelope(job), envelope(job)
        a = self.connection()
        b = self.connection()
        inserted, release = threading.Event(), threading.Event()

        def hold(conn):
            inserted.set()
            self.assertTrue(release.wait(10), "test did not release the first submission")

        def first_submission():
            try:
                outcome, _ = submit(a, first, on_first_insert=hold)
                self.first_outcome = outcome
            except Exception as exc:  # pragma: no cover - surfaced by the assertion below
                self.first_error = exc

        thread = threading.Thread(target=first_submission)
        thread.start()
        try:
            self.assertTrue(inserted.wait(10), "first submission never inserted")
            # The second connection must wait on the dedup_key unique index, not insert a second row.
            b.execute("SET lock_timeout = '300ms'")
            with self.assertRaises(psycopg.errors.LockNotAvailable):
                b.execute(
                    "INSERT INTO aegis.ingestion_inbox (event_id,dedup_key,job_id,payload_hash,hash_version,status)"
                    " VALUES (%s,%s,%s,%s,%s,'received') ON CONFLICT (dedup_key) DO NOTHING",
                    (second["event_id"], second["dedup_key"], second["job_id"], payload_hash(second), HASH_VERSION))
        finally:
            b.execute("SET lock_timeout = 0")
            release.set()
            thread.join(15)
        self.assertFalse(thread.is_alive(), "first submission did not finish")
        self.assertIsNone(getattr(self, "first_error", None))
        self.assertEqual(getattr(self, "first_outcome", None), "accepted")

        outcome, replay = submit(b, envelope(job))
        self.assertEqual(outcome, "duplicate")
        self.assertEqual(len(b.execute(
            "SELECT 1 FROM aegis.ingestion_inbox WHERE dedup_key=%s", (first["dedup_key"],)).fetchall()), 1)
        self.assertEqual([a[0] for a in attempts(b, first["dedup_key"])], ["first", "duplicate"])
        self.assertEqual(replay["event_id"], first["event_id"])


if __name__ == "__main__":
    unittest.main()
