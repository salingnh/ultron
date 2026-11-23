#!/usr/bin/env python3
"""S1.6: the legacy (roe-policy.v1) configuration path, in two layers.

Schema layer (always runs): a v1 policy is not valid roe-policy.v2 configuration, the mapped policy
is, and the DDL of 0009 publishes the same v2 key set and required limits as the schema.

Database layer (needs AEGIS_TEST_PG_DSN): a real upgrade 0001..0008 + the historical fixture, then
0009. The new snapshot must validate against campaign/roe-policy.v2.schema.json with the bundle's own
validator, the source row must stay byte-identical, current_policy_version must not move, the legacy
campaign must not be running and every legacy job must be held with its reasons. A policy the mapping
cannot express must abort the migration instead of dropping a setting.

    export AEGIS_TEST_PG_DSN=postgresql://postgres:<pw>@127.0.0.1:<port>/<db>
    python3 -I contracts/tests/test_legacy_policy_migration.py

Each database test provisions its own throwaway database (0001..0008, fixture, then 0009) and drops
it afterwards, so the DSN only needs a PostgreSQL 16 server. Without a DSN the database tests skip
(skip is not pass: the gate sets the DSN); with a DSN, a provisioning failure is an error.
"""
from __future__ import annotations

import json
import os
import re
import runpy
import unittest
import uuid
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

try:  # psycopg is only needed for the database layer; the schema layer must run without it.
    import psycopg
    from psycopg.conninfo import make_conninfo
except ImportError:  # pragma: no cover
    psycopg = None
    make_conninfo = None

ROOT = Path(__file__).resolve().parents[1]
PG_DIR = ROOT / "db/postgres"
FIXTURE = PG_DIR / "tests/fixtures/v1-policy-jobs.sql"
MIGRATION_NAME = "0009_legacy_policy_migration.sql"
MIGRATION = (PG_DIR / MIGRATION_NAME).read_text()
BEFORE_0009 = (
    "0001_init.sql",
    "0002_tool_orchestration.sql",
    "0003_task_manifest_binding.sql",
    "0004_usage_nonnegative.sql",
    "0005_job_target_refs.sql",
    "0006_ingestion_hash_receipt.sql",
    "0007_job_lifecycle.sql",
    "0008_outbox_publication_order.sql",
)
DSN = os.environ.get("AEGIS_TEST_PG_DSN", "").strip()
POLICY_SCHEMA = json.loads((ROOT / "campaign/roe-policy.v2.schema.json").read_text())
LEGACY_POLICY = json.loads((ROOT / "fixtures/invalid/roe-policy.legacy-v1.json").read_text())
MAPPED_POLICY = json.loads((ROOT / "fixtures/valid/roe-policy.from-v1.json").read_text())
V1_ONLY = {"scan_profile", "max_impact_tier", "approval_required_tiers"}

CAMPAIGN = "01900000-0000-7000-8000-0000000d1601"
CREATED_CAMPAIGN = "01900000-0000-7000-8000-0000000d1611"
JOB_QUEUED = "01900000-0000-7000-8000-0000000d1641"
JOB_RUNNING = "01900000-0000-7000-8000-0000000d1642"
JOB_FINISHED = "01900000-0000-7000-8000-0000000d1643"
ACTOR = {"kind": "module", "id": "s1.6-test"}
MIGRATION_ACTOR = {"kind": "module", "id": "migration/0009"}


def validator() -> Draft202012Validator:
    docs = [json.loads(p.read_text()) for p in ROOT.rglob("*.schema.json")]
    registry = Registry().with_resources((d["$id"], Resource.from_contents(d)) for d in docs)
    checker = runpy.run_path(str(ROOT / "validation.py"))["format_checker"]()
    return Draft202012Validator(
        {"$ref": "https://aegis.io/contracts/campaign/roe-policy.v2.schema.json"},
        registry=registry, format_checker=checker)


class LegacyPolicySchema(unittest.TestCase):
    def test_v1_configuration_is_not_v2_configuration(self):
        v = validator()
        self.assertNotEqual(list(v.iter_errors(LEGACY_POLICY)), [], "a v1 policy passed the v2 schema")
        self.assertEqual(list(v.iter_errors(MAPPED_POLICY)), [])

    def test_the_mapping_leaves_only_the_taxonomy_behind(self):
        self.assertEqual(set(LEGACY_POLICY) - set(MAPPED_POLICY), V1_ONLY)
        self.assertEqual(set(MAPPED_POLICY) - set(LEGACY_POLICY), set())
        for key, value in MAPPED_POLICY.items():
            self.assertEqual(LEGACY_POLICY[key], value, key)

    def test_ddl_mirrors_the_schema_key_set_and_required_limits(self):
        body = MIGRATION.split("CREATE FUNCTION aegis.is_roe_policy_v2", 1)[1]
        keys = re.findall(r"'([a-z_]+)'", body.split("k NOT IN (", 1)[1].split("))", 1)[0])
        self.assertEqual(sorted(keys), sorted(POLICY_SCHEMA["properties"]))
        for name in POLICY_SCHEMA["required"]:
            self.assertIn(name, keys)
            self.assertIn(f"is_json_int(policy->'{name}', "
                          f"{POLICY_SCHEMA['properties'][name]['minimum']}, "
                          f"{POLICY_SCHEMA['properties'][name]['maximum']})", MIGRATION)
        self.assertFalse(POLICY_SCHEMA.get("additionalProperties", True),
                         "the schema must stay closed for the shape discriminator to be total")

    def test_ddl_fixes_the_v1_only_keys_and_the_conversion_rule(self):
        keys = MIGRATION.split("v1_only constant text[] := ARRAY[", 1)[1].split("]", 1)[0]
        self.assertEqual(set(re.findall(r"'([a-z_]+)'", keys)), V1_ONLY)
        self.assertIn("converted := legacy - v1_only", MIGRATION)
        self.assertIn("refusing to drop a setting silently", MIGRATION)
        # The migration converts and holds; it never edits the source row or promotes a campaign.
        self.assertNotIn("UPDATE policy_snapshot", MIGRATION)
        self.assertNotRegex(MIGRATION, r"(?i)\bset\b[^;]*current_policy_version")


class Harness:
    """One throwaway database per test: 0001..0008, the historical fixture, optional extra rows, 0009."""

    def __init__(self, admin_dsn: str, extra: tuple[str, ...] = (), migrate: bool = True):
        self.name = "aegis_s16_" + uuid.uuid4().hex[:12]
        self.admin_dsn = admin_dsn
        with psycopg.connect(admin_dsn, autocommit=True) as conn:
            conn.execute(f'CREATE DATABASE "{self.name}"')
        self.dsn = make_conninfo(admin_dsn, dbname=self.name)
        with psycopg.connect(self.dsn, autocommit=True) as conn:
            conn.execute("SET search_path = aegis, public")
            for migration in BEFORE_0009:
                conn.execute((PG_DIR / migration).read_text())
            conn.execute(FIXTURE.read_text())
            for statement in extra:
                conn.execute(statement)
        if migrate:
            self.apply_migration()

    def apply_migration(self) -> None:
        with psycopg.connect(self.dsn, autocommit=True) as conn:
            conn.execute((PG_DIR / MIGRATION_NAME).read_text())

    def connect(self):
        conn = psycopg.connect(self.dsn, autocommit=True)
        conn.execute("SET search_path = aegis, public")
        return conn

    def drop(self) -> None:
        with psycopg.connect(self.admin_dsn, autocommit=True) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{self.name}" WITH (FORCE)')


def snapshot_rows(conn) -> list[tuple]:
    return conn.execute(
        "SELECT policy_version,campaign_id,policy,policy_hash,created_by,created_at"
        " FROM aegis.policy_snapshot ORDER BY policy_version").fetchall()


class LegacyPolicyMigration(unittest.TestCase):
    """Database layer only: without a DSN this class skips and the schema layer still runs."""

    @classmethod
    def setUpClass(cls):
        if not DSN:
            raise unittest.SkipTest("AEGIS_TEST_PG_DSN is not set: the S1.6 upgrade harness needs PostgreSQL 16")
        if psycopg is None:  # a DSN without the driver is a broken gate, not a skip
            raise RuntimeError("psycopg is not installed: pip install -r contracts/tests/requirements-db.txt")

    def setUp(self):
        # The migration is applied by the test itself so the source rows can be captured first.
        self.harness = Harness(DSN, migrate=False)
        self.addCleanup(self.harness.drop)
        self.conn = self.harness.connect()
        self.addCleanup(self.conn.close)

    def test_upgrade_creates_a_schema_valid_v2_snapshot_without_touching_history(self):
        before = {row[0]: row for row in snapshot_rows(self.conn)}
        self.harness.apply_migration()
        converted = self.conn.execute(
            "SELECT source_policy_version,new_policy_version,campaign_id,mapping_version,"
            "dropped_keys,dropped_values,converted_by FROM aegis.policy_snapshot_migration"
            " ORDER BY source_policy_version").fetchall()
        self.assertEqual([row[0] for row in converted], ["roe-101", "roe-102"])
        after = {row[0]: row for row in snapshot_rows(self.conn)}
        self.assertEqual(len(after), 4, "expected 2 historical + 2 v2 candidates")

        # 1. The historical rows are the same tuples as before the migration: version, campaign,
        #    policy value, hash, author and created_at, all byte for byte.
        self.assertEqual(set(after), set(before) | {row[1] for row in converted})
        for version, policy_hash in (("roe-101", "b" * 64), ("roe-102", "c" * 64)):
            self.assertEqual(after[version], before[version], version)
            self.assertEqual(after[version][3], policy_hash)
            self.assertEqual(after[version][4], {"kind": "operator", "id": "soc-legacy"})
            self.assertIn("scan_profile", after[version][2])
        self.assertEqual(after["roe-102"][2], {"scan_profile": "passive", "max_parallel_jobs": 10,
                                               "max_duration_hours": 168})

        # 2. Every new row is a different version, in the same campaign, validating as v2 config.
        v = validator()
        for source, new, campaign_id, mapping_version, _, _, actor in converted:
            self.assertEqual(mapping_version, "aegis-roe/1")
            self.assertEqual(actor, MIGRATION_ACTOR)
            self.assertNotEqual(new, source)
            self.assertEqual(after[new][1], campaign_id)
            self.assertEqual(after[new][2], MAPPED_POLICY if source == "roe-101"
                             else {"max_parallel_jobs": 10, "max_duration_hours": 168})
            self.assertEqual(list(v.iter_errors(after[new][2])), [], new)
            self.assertEqual(self.conn.execute(
                "SELECT 1 FROM aegis.policy_snapshot WHERE policy_version=%s AND policy_hash="
                "aegis.policy_hash(policy)", (new,)).fetchall(), [(1,)])

        # 3. The mapping kept every executable setting and recorded the taxonomy it removed.
        full = {row[0]: row for row in converted}
        _, new, _, _, dropped_keys, dropped_values, _ = full["roe-101"]
        self.assertEqual(sorted(dropped_keys), sorted(V1_ONLY))
        self.assertEqual(dropped_values, {k: LEGACY_POLICY[k] for k in V1_ONLY})
        self.assertEqual(sorted(full["roe-102"][4]), ["scan_profile"])

        # 4. No promotion, a paused legacy campaign with history, an untouched pending campaign.
        self.assertEqual(self.conn.execute(
            "SELECT campaign_id::text,status,status_reason,current_policy_version FROM aegis.campaign"
            " ORDER BY campaign_id").fetchall(),
            [(CAMPAIGN, "PAUSED", "LEGACY_POLICY_V1", "roe-101"),
             (CREATED_CAMPAIGN, "CREATED", None, "roe-102")])
        self.assertEqual(self.conn.execute(
            "SELECT from_status,to_status,actor FROM aegis.campaign_status_change WHERE campaign_id=%s",
            (CAMPAIGN,)).fetchall(),
            [("RUNNING", "PAUSED", MIGRATION_ACTOR)])

        # 5. Every legacy job is held, and the hold is what stops a dispatch and a resume.
        self.assertEqual(self.conn.execute(
            "SELECT job_id::text,status,dispatch_block_reasons FROM aegis.scan_job ORDER BY job_id").fetchall(),
            [(JOB_QUEUED, "QUEUED", ["LEGACY_POLICY_V1"]),
             (JOB_RUNNING, "RUNNING", ["LEGACY_POLICY_V1"]),
             (JOB_FINISHED, "SUCCEEDED", ["LEGACY_POLICY_V1"])])
        for statement, params in (
                ("UPDATE aegis.scan_job SET status='VALIDATING' WHERE job_id=%s", (JOB_QUEUED,)),
                ("UPDATE aegis.scan_job SET status='RUNNING',started_at=now() WHERE job_id=%s", (JOB_QUEUED,)),
                ("UPDATE aegis.scan_job SET attempt=attempt+1 WHERE job_id=%s", (JOB_RUNNING,)),
                ("UPDATE aegis.campaign SET status='RUNNING' WHERE campaign_id=%s", (CAMPAIGN,))):
            with self.subTest(statement=statement), self.assertRaises(psycopg.errors.CheckViolation):
                self.conn.execute(statement, params)

        # 6. The operator path still works: adopt the candidate, then the campaign runs; v1 is closed.
        self.conn.execute("UPDATE aegis.campaign SET current_policy_version=%s,status='RUNNING'"
                          " WHERE campaign_id=%s", (new, CAMPAIGN))
        self.assertEqual(self.conn.execute(
            "SELECT status FROM aegis.campaign WHERE campaign_id=%s", (CAMPAIGN,)).fetchone(), ("RUNNING",))
        with self.assertRaises(psycopg.errors.CheckViolation):
            self.conn.execute("UPDATE aegis.campaign SET current_policy_version='roe-101' WHERE campaign_id=%s",
                              (CAMPAIGN,))

        # 7. A second run of the tool converts nothing (idempotent under a maintenance window).
        self.assertEqual(self.conn.execute(
            "SELECT count(*) FROM aegis.migrate_legacy_policy_snapshots(%s::jsonb)",
            (json.dumps(ACTOR),)).fetchone(), (0,))
        self.assertEqual(len(snapshot_rows(self.conn)), 4)

    def test_unmappable_legacy_policy_aborts_the_migration(self):
        bad = ('{"scan_profile":"passive","max_parallel_jobs":10,"max_duration_hours":168,'
               '"log_retention_days":30}')
        harness = Harness(DSN, extra=(
            "INSERT INTO aegis.policy_snapshot (policy_version,campaign_id,policy,policy_hash,created_by)"
            f" VALUES ('roe-150','{CAMPAIGN}','{bad}',repeat('e',64),'{json.dumps(ACTOR)}')",),
            migrate=False)
        self.addCleanup(harness.drop)
        with self.assertRaises(psycopg.errors.CheckViolation) as caught:
            harness.apply_migration()
        self.assertIn("roe-150", str(caught.exception))
        self.assertIn("log_retention_days", str(caught.exception))

        # The migration is one transaction: nothing was converted, paused or held.
        conn = harness.connect()
        self.addCleanup(conn.close)
        self.assertEqual(conn.execute("SELECT to_regclass('aegis.policy_snapshot_migration')").fetchone(),
                         (None,))
        self.assertEqual(conn.execute(
            "SELECT status,current_policy_version FROM aegis.campaign WHERE campaign_id=%s",
            (CAMPAIGN,)).fetchone(), ("RUNNING", "roe-101"))
        self.assertEqual(conn.execute(
            "SELECT count(*) FROM information_schema.columns WHERE table_schema='aegis'"
            " AND table_name='scan_job' AND column_name='dispatch_block_reasons'").fetchone(), (0,))


if __name__ == "__main__":
    unittest.main()
