"""C02: TargetRef seed reference across request, task, job and envelope provenance.

Schema-level regressions only. The "seed belongs to this campaign" rule needs rows, so it is
proved by contracts/db/postgres/tests/job_target_refs.sql (trigger aegis.require_job_target_refs).
"""
from __future__ import annotations

import copy
import json
import runpy
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
BASE = "https://aegis.io/contracts/"
DOCS = [json.loads(p.read_text()) for p in ROOT.rglob("*.schema.json")]
REGISTRY = Registry().with_resources((d["$id"], Resource.from_contents(d)) for d in DOCS)
FORMAT_CHECKER = runpy.run_path(str(ROOT / "validation.py"))["format_checker"]()
ID = "01934f6a-0000-7000-8000-0000000000b1"
OTHER = "01934f6a-0000-7000-8000-0000000000b2"


def validator(target: str) -> Draft202012Validator:
    return Draft202012Validator({"$ref": BASE + target}, registry=REGISTRY, format_checker=FORMAT_CHECKER)


def load(path: str) -> dict:
    return json.loads((ROOT / path).read_text())


class SeedReference(unittest.TestCase):
    def test_target_ref_is_exactly_one_of_seed_or_asset(self):
        v = validator("common/ids.v2.schema.json#/$defs/TargetRef")
        for ref in [{"seed_id": ID}, {"canonical_key": "dns:seed.example"},
                    {"canonical_key": "ip:10.20.0.5"}, {"canonical_key": "oci:sha256:" + "6" * 64}]:
            with self.subTest(valid=ref): self.assertTrue(v.is_valid(ref))
        for ref in [{"seed_id": ID, "canonical_key": "dns:seed.example"}, {}, {"seed_id": "acme corp"},
                    {"canonical_key": "keyword:acme corp"}, {"canonical_key": "10.20.0.0/24"},
                    {"seed_id": ID, "note": "extra"}, "dns:seed.example", {"canonical_key": "dns:SEED.example"}]:
            with self.subTest(invalid=ref): self.assertFalse(v.is_valid(ref), ref)

    def test_targets_and_provenance_use_target_ref_while_coverage_stays_asset_keys(self):
        pairs = [("capability/approved-task.v2.schema.json", ("properties", "targets")),
                 ("capability/job.v2.schema.json", ("properties", "targets")),
                 ("ingestion/result-envelope.v2.schema.json", ("properties", "provenance", "properties", "seed_targets"))]
        for name, path in pairs:
            node = load(name)
            for step in path:
                node = node[step]
            with self.subTest(schema=name):
                self.assertTrue(node["items"]["$ref"].endswith("#/$defs/TargetRef"))
        envelope = load("ingestion/result-envelope.v2.schema.json")
        self.assertTrue(envelope["properties"]["coverage"]["properties"]["subjects"]["items"]["$ref"]
                        .endswith("#/$defs/CanonicalKey"))
        self.assertTrue(envelope["$defs"]["Asset"]["properties"]["discovered_from"]["items"]["$ref"]
                        .endswith("#/$defs/CanonicalKey"))

    def test_campaign_accepts_keyword_and_cidr_seeds_without_canonical_key(self):
        v = validator("campaign/campaign-create.v2.schema.json")
        fixture = load("fixtures/valid/campaign-create.json")
        self.assertTrue(v.is_valid(fixture))
        self.assertEqual({"domains", "ips", "keywords"} - set(fixture["targets"]), set())
        self.assertTrue(any("/" in value for value in fixture["targets"]["ips"]))
        self.assertTrue(fixture["targets"]["keywords"])
        # These seeds cannot be expressed as a canonical key, so a task target for them is a seed_id.
        key = validator("common/ids.v2.schema.json#/$defs/CanonicalKey")
        for seed in fixture["targets"]["keywords"] + fixture["targets"]["ips"]:
            with self.subTest(seed=seed):
                self.assertFalse(key.is_valid(seed))

    def test_seed_kinds_fixture_covers_every_supported_seed(self):
        v = validator("capability/approved-task.v2.schema.json")
        task = load("fixtures/valid/approved-task.seed-kinds.json")
        self.assertEqual(list(v.iter_errors(task)), [])
        seeds = [ref["seed_id"] for ref in task["targets"] if "seed_id" in ref]
        self.assertEqual(len(seeds), 6)
        self.assertEqual(len(set(seeds)), 6)
        self.assertEqual([ref for ref in task["targets"] if "canonical_key" in ref],
                         [{"canonical_key": "dns:www.seed.example"}])
        self.assertEqual(task["input"]["targets"], ["seed.example"])

    def test_ambiguous_and_retired_target_shapes_are_rejected_at_the_target(self):
        v = validator("capability/approved-task.v2.schema.json")
        for name in ["fixtures/invalid/approved-task.target-ref-ambiguous.json",
                     "fixtures/invalid/approved-task.target-ref-raw-key.json"]:
            with self.subTest(fixture=name):
                errors = list(v.iter_errors(load(name)))
                self.assertTrue(errors)
                self.assertTrue(any(list(e.absolute_path)[:1] == ["targets"] for e in errors), str(errors[0])[:200])

    def test_fake_keyword_asset_is_rejected_in_provenance(self):
        v = validator("ingestion/result-envelope.v2.schema.json")
        envelope = load("fixtures/valid/result-envelope.seed-provenance.json")
        self.assertEqual(list(v.iter_errors(envelope)), [])
        self.assertEqual(len(envelope["provenance"]["seed_targets"]), 2)
        self.assertTrue(all("seed_id" in ref for ref in envelope["provenance"]["seed_targets"]))
        # The expanded ip is an asset subject; the CIDR seed is not copied into coverage.
        self.assertEqual(envelope["coverage"]["subjects"], ["ip:10.20.0.5"])
        bad = load("fixtures/invalid/result-envelope.fake-keyword-asset.json")
        errors = list(v.iter_errors(bad))
        self.assertTrue(errors)
        self.assertTrue(any(list(e.absolute_path)[:2] == ["provenance", "seed_targets"] for e in errors))
        seeded_coverage = copy.deepcopy(envelope)
        seeded_coverage["coverage"]["subjects"] = [{"seed_id": ID}]
        self.assertFalse(v.is_valid(seeded_coverage))

    def test_job_response_and_migration_expose_the_same_rule(self):
        v = validator("capability/job.v2.schema.json")
        job = {"job_id": ID, "campaign_id": ID, "capability": "dns.enumerate_subdomains", "provider": "subfinder",
               "status": "QUEUED", "job_fingerprint": "a" * 64, "policy_version": "roe-1", "scope_id": ID,
               "created_at": "2026-11-15T03:00:00Z", "priority": 50, "depends_on": [],
               "requested_by": {"kind": "operator", "id": "fixture-operator"},
               "adapter_version": "1.0.0", "manifest_sha256": "b" * 64, "attempt": 1, "generation": 1}
        self.assertTrue(v.is_valid(job))
        self.assertTrue(v.is_valid(dict(job, targets=[{"seed_id": OTHER}, {"canonical_key": "dns:seed.example"}])))
        self.assertFalse(v.is_valid(dict(job, targets=["dns:seed.example"])))
        migration = (ROOT / "db/postgres/0001_baseline.sql").read_text()
        for fragment in ["target_refs jsonb NOT NULL", "aegis.is_target_refs(target_refs)",
                         "CREATE TRIGGER target_refs_required BEFORE INSERT ON aegis.scan_job",
                         "campaign_target ct"]:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, migration)
        chain = (ROOT / "README.md").read_text()
        for name in ["0001_baseline.sql", "tests/job_target_refs.sql"]:
            with self.subTest(migration_list=name):
                self.assertIn(name, chain)


if __name__ == "__main__":
    unittest.main()
