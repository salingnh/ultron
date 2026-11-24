"""C03: canonical hash version and projection, golden vectors, IngestReceipt duplicate semantics.

Schema/registry-level regressions only. The live-connection behaviour (one row per dedup_key, first
receipt replay, 409 conflict) is proved by tests/test_ingestion_concurrency.py against PostgreSQL.
"""
from __future__ import annotations

import copy
import json
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
CANON = runpy.run_path(str(ROOT / "tests/canonicalization.py"))
REGISTRY_DOC = yaml.safe_load((ROOT / "ingestion/canonicalization.v2.yaml").read_text())
VECTORS = json.loads((ROOT / "fixtures/golden/hash/canonicalization.vectors.json").read_text())
ENVELOPE = json.loads((ROOT / "fixtures/valid/result-envelope.subfinder.json").read_text())
SEEDED_ENVELOPE = json.loads((ROOT / "fixtures/valid/result-envelope.seed-provenance.json").read_text())


def validator(target: str) -> Draft202012Validator:
    return Draft202012Validator({"$ref": BASE + target}, registry=REGISTRY, format_checker=FORMAT_CHECKER)


def load(path: str) -> dict:
    return json.loads((ROOT / path).read_text())


class CanonicalHash(unittest.TestCase):
    def test_golden_vectors_are_reproduced_exactly(self):
        self.assertEqual(VECTORS["version"], CANON["HASH_VERSION"])
        for vector in VECTORS["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(CANON["canonical_text"](vector["input"]), vector["canonical"])
                self.assertEqual(CANON["sha256_hex"](vector["input"]), vector["sha256"])
        for case in VECTORS["rejected"]:
            with self.subTest(rejected=case["name"]):
                with self.assertRaises(CANON["CanonicalizationError"]):
                    CANON["canonical_bytes_from_json"](case["raw"])

    def test_non_json_values_are_rejected_not_coerced(self):
        from decimal import Decimal
        for value in [Decimal("1.5"), {1: "int-key"}, {"s": {1, 2}}, {"b": b"bytes"}, {"n": float("inf")}]:
            with self.subTest(value=repr(value)):
                with self.assertRaises(CANON["CanonicalizationError"]):
                    CANON["canonical_bytes"](value)

    def test_registry_classifies_every_envelope_field(self):
        schema = load("ingestion/result-envelope.v2.schema.json")
        projection = REGISTRY_DOC["hashes"]["envelope.payload_hash"]
        included, excluded = set(projection["include"]), set(projection["exclude"])
        self.assertEqual(projection["version"], CANON["HASH_VERSION"])
        self.assertIs(schema["additionalProperties"], False)
        self.assertEqual(included | excluded, set(schema["properties"]))
        self.assertEqual(excluded, set(CANON["PAYLOAD_HASH_EXCLUDE"]))
        self.assertEqual(included, set(schema["properties"]) - excluded)
        self.assertEqual(set(projection["exclude"]), {"event_id", "dedup_key", "trace"})

    def test_submission_identity_is_not_content(self):
        base = CANON["payload_hash"](ENVELOPE)
        self.assertEqual(base, VECTORS["envelope_payload_hash"]["valid/result-envelope.subfinder.json"])
        self.assertEqual(CANON["payload_hash"](SEEDED_ENVELOPE),
                         VECTORS["envelope_payload_hash"]["valid/result-envelope.seed-provenance.json"])
        for name, change in {
            "event_id": {"event_id": "01934f6a-0000-7000-8000-0000000000aa"},
            "dedup_key": {"dedup_key": "job:01934f6a-0000-7000-8000-0000000000d1:envelope-retry"},
            "trace": {"trace": {"trace_id": "b" * 32, "span_id": "c" * 16}},
        }.items():
            with self.subTest(unchanged=name):
                self.assertEqual(CANON["payload_hash"](dict(ENVELOPE, **change)), base)

    def test_changed_business_content_is_different_content(self):
        base = CANON["payload_hash"](ENVELOPE)
        schema = validator("ingestion/result-envelope.v2.schema.json")
        changed = {
            "evidence": dict(ENVELOPE, evidence=[]),
            "coverage": dict(ENVELOPE, coverage=dict(ENVELOPE["coverage"], complete=False)),
            "value": copy.deepcopy(ENVELOPE),
            "status": dict(ENVELOPE, status="partial"),
            "seed_targets": dict(ENVELOPE, provenance=dict(ENVELOPE["provenance"], seed_targets=[
                {"seed_id": "01934f6a-0000-7000-8000-0000000000b2"}])),
            "campaign": dict(ENVELOPE, campaign_id="01934f6a-0000-7000-8000-0000000000bb"),
            "provider": dict(ENVELOPE, provider=dict(ENVELOPE["provider"], adapter_version="1.0.1")),
        }
        changed["value"]["results"]["observations"][0]["value"] = "changed"
        for name, envelope in changed.items():
            with self.subTest(changed=name):
                self.assertEqual(list(schema.iter_errors(envelope)), [], f"{name} must stay a valid envelope")
                self.assertNotEqual(CANON["payload_hash"](envelope), base, name)


class ReceiptContract(unittest.TestCase):
    def test_receipt_schema_pins_the_first_committed_decision(self):
        schema = load("ingestion/ingest-receipt.v2.schema.json")
        self.assertIs(schema["additionalProperties"], False)
        self.assertEqual(set(schema["required"]), {
            "event_id", "dedup_key", "accepted", "duplicate", "revision", "quarantined",
            "payload_hash", "hash_version", "decided_at"})
        v = validator("ingestion/ingest-receipt.v2.schema.json")
        fixture = load("fixtures/valid/ingest-receipt.json")
        self.assertTrue(v.is_valid(fixture))
        self.assertTrue(v.is_valid(dict(fixture, duplicate=True)))
        for missing in schema["required"]:
            with self.subTest(missing=missing):
                broken = dict(fixture)
                broken.pop(missing)
                self.assertFalse(v.is_valid(broken))
        # The receipt fixture describes the subfinder envelope fixture, not an unrelated result.
        self.assertEqual(fixture["event_id"], ENVELOPE["event_id"])
        self.assertEqual(fixture["dedup_key"], ENVELOPE["dedup_key"])
        self.assertEqual(fixture["payload_hash"], CANON["payload_hash"](ENVELOPE))
        self.assertFalse(v.is_valid(dict(fixture, hash_version="jcs-1")))
        self.assertFalse(v.is_valid(dict(fixture, unknown_field=1)))
        self.assertFalse(v.is_valid(dict(fixture, quarantined=["/results/assets/0"])))

    def test_conflict_has_one_error_code_and_the_api_says_so(self):
        codes = load("common/error.v2.schema.json")["$defs"]["ErrorCode"]["enum"]
        self.assertIn("IDEMPOTENCY_CONFLICT", codes)
        self.assertEqual(len(codes), len(set(codes)))
        error = {"code": "IDEMPOTENCY_CONFLICT", "message": "dedup_key already holds other content",
                 "next_action": "ESCALATE", "retryable": False, "trace_id": "d" * 32}
        self.assertEqual(list(validator("common/error.v2.schema.json").iter_errors(error)), [])
        api = yaml.safe_load((ROOT / "api/openapi.v2.yaml").read_text())
        conflict = api["paths"]["/ingestion/results"]["post"]["responses"]["409"]
        self.assertIn("IDEMPOTENCY_CONFLICT", conflict["description"])
        self.assertIn("không thay đổi", conflict["description"])
        accepted = api["paths"]["/ingestion/results"]["post"]["responses"]["202"]["description"]
        self.assertIn("receipt", accepted)
        self.assertIn("trước đó", accepted)

    def test_hash_composition_is_one_statement_in_registry_ddl_and_docs(self):
        fields = list(CANON["JOB_FINGERPRINT_FIELDS"])
        self.assertEqual(REGISTRY_DOC["hashes"]["job.fingerprint"]["fields"], fields)
        migration = (ROOT / "db/postgres/0001_baseline.sql").read_text()
        comment = migration.split("COMMENT ON COLUMN aegis.scan_job.job_fingerprint IS", 1)[1].split(";", 1)[0]
        self.assertIn("{" + ",".join(fields) + "}", comment)
        self.assertIn("never the targets canonical-key projection", comment)
        self.assertIn("aegis-c14n/1", comment)
        self.assertIn("X-1", comment)
        readme = (ROOT / "README.md").read_text()
        self.assertIn("canonicalization.v2.yaml", readme)
        doc = (ROOT.parent / "docs/living/dac-ta-ky-thuat/05-du-lieu-api-su-kien.md").read_text()
        self.assertIn("canonicalization.v2.yaml", doc)
        self.assertIn("aegis-c14n/1", doc)
        mcp = (ROOT / "mcp/README.md").read_text()
        self.assertIn("canonicalization.v2.yaml", mcp)
        agents = (ROOT.parent / "AGENTS.md").read_text()
        self.assertIn("Job fingerprint gồm campaign", agents)  # the highest source X-1 aligns to

    def test_fingerprint_is_independent_of_scheduling_and_projection(self):
        job = {"campaign_id": "01934f6a-0000-7000-8000-000000000001", "capability": "dns.enumerate_subdomains",
               "policy_version": "roe-1", "provider": "subfinder", "provider_version": "v2.6.6",
               "adapter_version": "1.0.0", "image_digest": "sha256:" + "5" * 64,
               "manifest_sha256": "6" * 64, "target_refs": [{"seed_id": "01934f6a-0000-7000-8000-0000000000b1"}],
               "input": {"targets": ["internal.example"]}, "scan_cycle": "01934f6a-0000-7000-8000-0000000000f1"}
        first = CANON["job_fingerprint"](job)
        self.assertEqual(first, CANON["job_fingerprint"](dict(job, targets=["dns:internal.example"],
                                                              priority=99, depends_on=[], rationale="x")))
        # The TargetRef list is identity: two different keyword seeds must not collide.
        other = dict(job, target_refs=[{"seed_id": "01934f6a-0000-7000-8000-0000000000b2"}])
        self.assertNotEqual(first, CANON["job_fingerprint"](other))
        self.assertNotEqual(first, CANON["job_fingerprint"](
            dict(job, scan_cycle="01934f6a-0000-7000-8000-0000000000f2")))
        for missing in ["manifest_sha256", "image_digest", "target_refs", "scan_cycle"]:
            with self.subTest(missing=missing):
                broken = dict(job)
                broken.pop(missing)
                with self.assertRaises(CANON["CanonicalizationError"]):
                    CANON["job_fingerprint"](broken)


if __name__ == "__main__":
    unittest.main()
