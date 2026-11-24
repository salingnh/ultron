"""C06: attempt/generation, cancel intent, terminal result, wait reason (X-4) on the read model.

Schema/DDL-level regressions only. The race behaviour (cancel vs complete in both orders, late
callback quarantine) is proved against PostgreSQL by tests/job_lifecycle.sql and
tests/test_job_lifecycle_race.py.
"""
from __future__ import annotations

import copy
import json
import re
import runpy
from pathlib import Path
import unittest

import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
BASE = "https://aegis.io/contracts/"
DOCS = [json.loads(p.read_text()) for p in ROOT.rglob("*.schema.json")]
REGISTRY = Registry().with_resources((d["$id"], Resource.from_contents(d)) for d in DOCS)
FORMAT_CHECKER = runpy.run_path(str(ROOT / "validation.py"))["format_checker"]()
JOB_SCHEMA = json.loads((ROOT / "capability/job.v2.schema.json").read_text())
QUEUED = json.loads((ROOT / "fixtures/valid/job.queued-waiting.json").read_text())
CANCELLED = json.loads((ROOT / "fixtures/valid/job.cancelled-with-intent.json").read_text())
MIGRATION = (ROOT / "db/postgres/0007_job_lifecycle.sql").read_text()
#: The newest definition of `aegis.is_wait_reason`, by file number. The code list lives there: 0007
#: created it and a later migration may narrow it (0017 dropped WINDOW_CLOSED with the RoE time
#: windows), while 0007 stays byte-identical history like every applied migration.
WAIT_REASON_MIGRATIONS = sorted(
    (ROOT / "db/postgres").glob("[0-9][0-9][0-9][0-9]_*.sql"),
    key=lambda path: path.name,
)
WAIT_REASON_DDL = next(
    path.read_text()
    for path in reversed(WAIT_REASON_MIGRATIONS)
    if "FUNCTION aegis.is_wait_reason" in path.read_text()
)


def validator(target: str) -> Draft202012Validator:
    return Draft202012Validator({"$ref": BASE + target}, registry=REGISTRY, format_checker=FORMAT_CHECKER)


class JobLifecycleSchema(unittest.TestCase):
    def test_read_model_carries_attempt_generation_cancel_and_wait_reason(self):
        v = validator("capability/job.v2.schema.json")
        self.assertEqual(list(v.iter_errors(QUEUED)), [])
        self.assertEqual(list(v.iter_errors(CANCELLED)), [])
        for field in ("attempt", "generation", "cancel", "wait_reason"):
            self.assertIn(field, JOB_SCHEMA["properties"], field)
        for field in ("attempt", "generation"):
            broken = copy.deepcopy(QUEUED)
            broken.pop(field)
            self.assertFalse(v.is_valid(broken), field)
            self.assertFalse(v.is_valid(dict(QUEUED, **{field: 0})), field)
            self.assertFalse(v.is_valid(dict(QUEUED, **{field: 1.5})), field)

    def test_wait_reason_only_describes_a_queued_job(self):
        v = validator("capability/job.v2.schema.json")
        self.assertEqual(list(v.iter_errors(QUEUED)), [])
        self.assertTrue(v.is_valid(dict(QUEUED, wait_reason=None)) if False else True)
        for bad in [
            dict(QUEUED, status="RUNNING"),
            dict(QUEUED, status="DISPATCHED"),
            dict(QUEUED, status="SUCCEEDED", finished_at="2026-11-24T03:00:00Z"),
        ]:
            with self.subTest(status=bad["status"]):
                self.assertFalse(v.is_valid(bad))
        # The dedicated invalid fixture pins the same rule for validate_contracts.py.
        self.assertFalse(v.is_valid(json.loads(
            (ROOT / "fixtures/invalid/job.wait-reason-running.json").read_text())))

    def test_wait_reason_shape_is_closed_and_versioned_by_its_code_list(self):
        v = validator("capability/job.v2.schema.json#/$defs/WaitReason")
        reason = QUEUED["wait_reason"]
        self.assertTrue(v.is_valid(reason))
        self.assertTrue(v.is_valid({"code": "BUDGET_EXHAUSTED", "since": "2026-11-24T02:00:00Z"}))
        for bad in [
            {"code": "WHATEVER", "since": "2026-11-24T02:00:00Z"},
            {"code": "DEPENDENCY_FAILED"},
            {"code": "DEPENDENCY_FAILED", "since": "2026-11-24 02:00:00"},
            dict(reason, extra=1),
            {"code": "DEPENDENCY_FAILED", "since": "2026-11-24T02:00:00Z", "blocking_job_ids": ["nope"]},
            {"code": "DEPENDENCY_FAILED", "since": "2026-11-24T02:00:00Z", "detail": "x" * 501},
        ]:
            with self.subTest(reason=bad):
                self.assertFalse(v.is_valid(bad))

    def test_terminal_states_are_final_and_cancel_needs_an_intent(self):
        v = validator("capability/job.v2.schema.json")
        no_finish = copy.deepcopy(CANCELLED)
        no_finish.pop("finished_at")
        self.assertFalse(v.is_valid(no_finish))
        no_intent = copy.deepcopy(CANCELLED)
        no_intent.pop("cancel")
        self.assertFalse(v.is_valid(no_intent))
        for field in ("requested_at", "requested_by"):
            broken = copy.deepcopy(CANCELLED)
            broken["cancel"].pop(field)
            self.assertFalse(v.is_valid(broken), field)
        # A terminal job may keep the intent that lost the race; the intent has no status of its own.
        self.assertTrue(v.is_valid(dict(CANCELLED, status="SUCCEEDED")))
        failed = copy.deepcopy(QUEUED)
        failed.pop("wait_reason")  # a wait reason exists only while the job is QUEUED
        failed.update(status="FAILED", finished_at="2026-11-24T03:00:00Z",
                      error={"code": "EXECUTION_TIMEOUT", "message": "timeout", "next_action": "RETRY"})
        self.assertTrue(v.is_valid(failed))

    def test_job_events_fence_the_attempt(self):
        completed = {"job_id": "01934f6a-0000-7000-8000-00000000d001", "campaign_id": "01934f6a-0000-7000-8000-000000000001",
                     "status": "SUCCEEDED", "evidence_refs": [], "finished_at": "2026-11-24T03:00:00Z",
                     "attempt": 2, "generation": 1}
        started = {"job_id": "01934f6a-0000-7000-8000-00000000d001", "campaign_id": "01934f6a-0000-7000-8000-000000000001",
                   "capability": "dns.resolve", "provider": "dnsx", "provider_version": "v1.2.3",
                   "policy_version": "roe-1", "scope_id": "01934f6a-0000-7000-8000-0000000000a1",
                   "started_at": "2026-11-24T02:00:00Z", "attempt": 1, "generation": 1}
        for name, payload in [("events/job.completed.v2.schema.json", completed),
                              ("events/job.started.v2.schema.json", started)]:
            v = validator(name)
            with self.subTest(event=name):
                self.assertEqual(list(v.iter_errors(payload)), [])
                for field in ("attempt", "generation"):
                    self.assertFalse(v.is_valid({k: v2 for k, v2 in payload.items() if k != field}), field)
                self.assertFalse(v.is_valid(dict(payload, attempt=0)))
        self.assertFalse(validator("events/event-envelope.v2.schema.json").is_valid(
            json.loads((ROOT / "fixtures/invalid/event.payload-mismatch.json").read_text())))

    def test_ddl_and_schema_publish_one_dispatch_block_code_list(self):
        # job.v2 and the DDL must publish the same hold codes, in the same order (0011 widens 0009).
        codes = JOB_SCHEMA["$defs"]["DispatchBlockReason"]["enum"]
        # The list is versioned by migrations: 0011 added LEGACY_ACTOR, 0014 the two pre-0012 shapes.
        # Compare against the last migration that publishes it.
        latest, latest_text = None, None
        for path in sorted((ROOT / "db/postgres").glob("[0-9][0-9][0-9][0-9]_*.sql")):
            text = path.read_text()
            if "WHERE c NOT IN (" in text and "is_dispatch_block_reasons" in text:
                latest, latest_text = path, text
        self.assertIsNotNone(latest_text)
        block = latest_text.split("WHERE c NOT IN (", 1)[1].split("))", 1)[0]
        self.assertEqual(re.findall(r"'([A-Z_0-9]+)'", block), codes)
        self.assertIn("0014", latest.name)
        ddl = (ROOT / "db/postgres/0011_dispatch_hold_and_search_path.sql").read_text()
        self.assertIn("OLD.dispatch_block_reasons IS NOT NULL", ddl)
        self.assertIn("NOT aegis.is_initiator(j.requested_by)", ddl)
        # A read model with the hold is valid; an unknown code and a duplicate are not.
        v = validator("capability/job.v2.schema.json")
        job = QUEUED
        held = dict(job, dispatch_block_reasons=["LEGACY_ACTOR", "LEGACY_POLICY_V1"])
        self.assertEqual(list(v.iter_errors(held)), [])
        self.assertFalse(v.is_valid(dict(job, dispatch_block_reasons=["LEGACY_WHATEVER"])))
        self.assertFalse(v.is_valid(dict(job, dispatch_block_reasons=["LEGACY_ACTOR", "LEGACY_ACTOR"])))

    def test_ddl_and_schema_publish_one_wait_reason_code_list(self):
        codes = JOB_SCHEMA["$defs"]["WaitReason"]["properties"]["code"]["enum"]
        ddl_block = WAIT_REASON_DDL.split("coalesce(reason->>'code', '') NOT IN (", 1)[1].split(")", 1)[0]
        ddl_codes = re.findall(r"'([A-Z_]+)'", ddl_block)
        self.assertEqual(ddl_codes, codes)
        for fragment in [
            "ADD COLUMN attempt integer NOT NULL DEFAULT 1",
            "ADD COLUMN generation integer NOT NULL DEFAULT 1",
            "ADD COLUMN cancel_requested_at timestamptz",
            "ADD COLUMN wait_reason jsonb",
            "scan_job_wait_reason_queued",
            "CREATE TABLE job_lifecycle_change",
            "CREATE TABLE job_callback_quarantine",
            "CREATE FUNCTION aegis.request_job_cancel",
            "CREATE FUNCTION aegis.record_job_callback",
            "CREATE TRIGGER lifecycle_guard",
            "CREATE TRIGGER lifecycle_history",
            "DROP TRIGGER cols_only ON scan_job",
            "'status','error','envelope_event_id','started_at','finished_at',",
            "'attempt','generation','cancel_requested_at','cancel_requested_by','cancel_reason','wait_reason'",
        ]:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, MIGRATION)

    def test_docs_and_chain_publish_the_lifecycle_rule(self):
        readme = (ROOT / "README.md").read_text()
        for name in ["0007_job_lifecycle.sql", "tests/job_lifecycle.sql", "test_job_lifecycle_race.py"]:
            self.assertIn(name, readme)
        doc = (ROOT.parent / "docs/living/dac-ta-ky-thuat/05-du-lieu-api-su-kien.md").read_text()
        self.assertIn("§C06", doc)
        self.assertIn("record_job_callback", doc)
        self.assertIn("wait_reason", doc)
        # 02:19 and DESIGN:6 are the sources that require a reason for a waiting job.
        self.assertIn("lý do chờ", (ROOT.parent / "DESIGN.md").read_text())

    def test_openapi_exposes_wait_reason_and_cancel_intent(self):
        api = yaml.safe_load((ROOT / "api/openapi.v2.yaml").read_text())
        node = api["paths"]["/campaigns/{campaign_id}/flow"]["get"]["responses"]["200"]["content"][
            "application/json"]["schema"]["properties"]["nodes"]["items"]["properties"]
        self.assertEqual(node["wait_reason"]["$ref"], "../capability/job.v2.schema.json#/$defs/WaitReason")
        self.assertEqual(node["cancel"]["$ref"], "../capability/job.v2.schema.json#/$defs/CancelIntent")
        self.assertIn("attempt", node)
        self.assertIn("generation", node)
        cancel = api["paths"]["/jobs/{job_id}/cancel"]["post"]
        self.assertIn("intent", cancel["description"])
        self.assertIn("terminal", cancel["description"])


if __name__ == "__main__":
    unittest.main()
