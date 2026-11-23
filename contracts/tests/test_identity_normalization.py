"""G0.3c: versioned identity normalization (`aegis-norm/1`) and its golden fixtures.

Schema/registry/DDL-level regressions only; no service imports the reference implementation. The
suite proves four things: the registry, the DDL detail columns and the reference implementation
describe one set of rules; the hand-written golden expectations are reproduced exactly; a stored
CanonicalKey normalizes back to itself (replay keeps the canonical id); and the sensitive
query-parameter list is one list, effective for every entry.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import runpy
import unittest

import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
BASE = "https://aegis.io/contracts/"
DOCS = [json.loads(path.read_text()) for path in ROOT.rglob("*.schema.json")]
SCHEMAS = Registry().with_resources((doc["$id"], Resource.from_contents(doc)) for doc in DOCS)
VALIDATION = runpy.run_path(str(ROOT / "validation.py"))
FORMAT_CHECKER = VALIDATION["format_checker"]()
NORM = runpy.run_path(str(ROOT / "tests/normalization.py"))
VECTORS = json.loads((ROOT / "fixtures/golden/identity/normalization.vectors.json").read_text())
REGISTRY_DOC = yaml.safe_load((ROOT / "ingestion/normalization.v2.yaml").read_text())
IDS = json.loads((ROOT / "common/ids.v2.schema.json").read_text())
DDL = (ROOT / "db/postgres/0001_init.sql").read_text()
README = (ROOT / "README.md").read_text()
SPEC = (ROOT.parent / "docs/living/dac-ta-ky-thuat/05-du-lieu-api-su-kien.md").read_text()

CANONICAL_KEY = Draft202012Validator(
    {"$ref": BASE + "common/ids.v2.schema.json#/$defs/CanonicalKey"},
    registry=SCHEMAS,
    format_checker=FORMAT_CHECKER,
)
KEY_PREFIXES = tuple(f"{prefix}:" for prefix in NORM["KEY_PREFIX_KINDS"])
SQL_KEY = re.compile(r"'((?:%s)[^']*)'" % "|".join(re.escape(prefix) for prefix in KEY_PREFIXES))



def strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from strings(value)


def ddl_columns(table: str) -> list[str]:
    match = re.search(rf"CREATE TABLE {table} \((.*?)\n\);", DDL, re.S)
    if match is None:
        raise AssertionError(f"no CREATE TABLE {table} in 0001_init.sql")
    columns = []
    for line in match.group(1).splitlines():
        token = line.strip().split(" ")[0] if line.strip() else ""
        if token and token not in {"UNIQUE", "PRIMARY", "CHECK", "CONSTRAINT"}:
            columns.append(token)
    return columns


class RegistryIsTheSingleSource(unittest.TestCase):
    def test_versions_match(self):
        self.assertEqual(REGISTRY_DOC["version"], NORM["NORM_VERSION"])
        self.assertEqual(VECTORS["version"], NORM["NORM_VERSION"])
        self.assertRegex(NORM["NORM_VERSION"], r"^aegis-norm/[1-9][0-9]*$")

    def test_every_asset_kind_is_classified(self):
        kinds = REGISTRY_DOC["kinds"]
        unsupported = REGISTRY_DOC["unsupported_kinds"]
        self.assertEqual(set(kinds) | set(unsupported), set(IDS["$defs"]["AssetKind"]["enum"]))
        self.assertFalse(set(kinds) & set(unsupported))
        self.assertEqual(set(kinds), set(REGISTRY_DOC["rules"]))
        self.assertEqual(set(kinds), set(NORM["RULES"]))
        for kind, spec in kinds.items():
            with self.subTest(kind=kind):
                self.assertIn(spec["prefix"], NORM["KEY_PREFIX_KINDS"])
                self.assertEqual(NORM["KEY_PREFIX_KINDS"][spec["prefix"]], kind)
                self.assertEqual(NORM["RULES"][kind], NORM["RULES"][NORM["KEY_PREFIX_KINDS"][spec["prefix"]]])
        for kind in unsupported:
            with self.subTest(unsupported=kind):
                with self.assertRaises(NORM["NormalizationError"]) as caught:
                    NORM["normalize"](kind, "x")
                self.assertEqual(caught.exception.reason, "kind_not_supported")

    def test_detail_columns_match_the_ddl(self):
        for kind, spec in REGISTRY_DOC["kinds"].items():
            with self.subTest(kind=kind):
                expected = [c for c in ddl_columns(spec["detail"]) if c != "asset_id"] if spec["detail"] else None
                produced = [v["detail"] for v in VECTORS["vectors"] if v["kind"] == kind and "detail" in v]
                if expected is None:
                    self.assertEqual(produced, [], f"{kind} must not produce a detail row")
                else:
                    self.assertTrue(produced, f"{kind} needs a golden detail vector")
                    for detail in produced:
                        self.assertEqual(sorted(detail), sorted(expected))

    def test_reason_codes_and_query_lists_match(self):
        self.assertEqual(set(REGISTRY_DOC["rejected_reasons"]), set(NORM["REASONS"]))
        self.assertEqual(set(REGISTRY_DOC["sensitive_query_params"]), set(NORM["SENSITIVE_QUERY_PARAMS"]))
        self.assertEqual(
            tuple(REGISTRY_DOC["sensitive_query_param_suffixes"]), NORM["SENSITIVE_QUERY_PARAM_SUFFIXES"]
        )
        self.assertEqual(
            tuple(REGISTRY_DOC["sensitive_query_param_prefixes"]), NORM["SENSITIVE_QUERY_PARAM_PREFIXES"]
        )
        self.assertEqual(len(REGISTRY_DOC["sensitive_query_params"]), len(set(REGISTRY_DOC["sensitive_query_params"])))
        for name in REGISTRY_DOC["sensitive_query_params"]:
            self.assertEqual(name, name.lower(), f"{name} must be stored lowercase")
        used = {case["reason"] for case in VECTORS["rejected"]}
        self.assertLessEqual(used, set(REGISTRY_DOC["rejected_reasons"]))
        self.assertEqual(set(REGISTRY_DOC["rejected_reasons"]) - used, {"too_long"})

    def test_every_rule_is_documented(self):
        for kind, rule in REGISTRY_DOC["rules"].items():
            with self.subTest(kind=kind):
                self.assertTrue(rule["output"].strip())
                self.assertTrue(rule["notes"].strip())
                self.assertTrue(rule["steps"])
                self.assertTrue(all(step.strip() for step in rule["steps"]))

    def test_the_schema_limit_is_the_one_the_code_enforces(self):
        canonical = IDS["$defs"]["CanonicalKey"]
        self.assertEqual(canonical["maxLength"], NORM["CANONICAL_KEY_MAX_LENGTH"])
        self.assertEqual(canonical["format"], "aegis-canonical-key")
        self.assertIn("none", REGISTRY_DOC["identity_contract"]["pattern_changes"])


class GoldenVectors(unittest.TestCase):
    def test_golden_vectors_are_reproduced_exactly(self):
        for vector in VECTORS["vectors"]:
            with self.subTest(vector=vector["name"]):
                normalized = NORM["normalize"](vector["kind"], vector["raw"])
                self.assertEqual(normalized.canonical_key, vector["canonical_key"])
                self.assertEqual(normalized.detail, vector.get("detail"))
                self.assertEqual(normalized.version, NORM["NORM_VERSION"])
                self.assertEqual(normalized.kind, vector["kind"])

    def test_expected_keys_are_valid_canonical_keys(self):
        for vector in VECTORS["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(list(CANONICAL_KEY.iter_errors(vector["canonical_key"])), [])
                self.assertLessEqual(len(vector["canonical_key"]), NORM["CANONICAL_KEY_MAX_LENGTH"])
                prefix = REGISTRY_DOC["kinds"][vector["kind"]]["prefix"]
                self.assertTrue(vector["canonical_key"].startswith(prefix + ":"))
                self.assertTrue(any(vector["canonical_key"].startswith(f"{p}:") for p in NORM["KEY_PREFIX_KINDS"]))

    def test_the_ip_pattern_is_why_mapped_ipv6_collapses(self):
        # Neither IPv6 spelling of an IPv4-mapped address is a valid v2 key: RFC 5952 mixed
        # notation fails the `ip:` regex, and the hex form fails validation.py because
        # `str(ip_address(...))` prints mixed notation. Collapsing to the IPv4 key is therefore the
        # only pattern-preserving rule; lock that premise.
        self.assertTrue(list(CANONICAL_KEY.iter_errors("ip:::ffff:192.0.2.1")))
        self.assertFalse(VALIDATION["canonical_key"]("ip:::ffff:c000:201"))
        self.assertTrue(VALIDATION["canonical_key"]("ip:192.0.2.1"))
        self.assertEqual(NORM["canonical_key"]("ip", "::ffff:192.0.2.1"), "ip:192.0.2.1")

    def test_rejected_values_are_quarantined_with_the_registered_reason(self):
        for case in VECTORS["rejected"]:
            with self.subTest(case=case["name"]):
                with self.assertRaises(NORM["NormalizationError"]) as caught:
                    NORM["normalize"](case["kind"], case["raw"])
                self.assertEqual(caught.exception.reason, case["reason"])
                self.assertIn(caught.exception.reason, REGISTRY_DOC["rejected_reasons"])

    def test_two_spellings_of_one_asset_collapse_to_one_key(self):
        for case in VECTORS["collapses"]:
            with self.subTest(case=case["name"]):
                keys = {NORM["canonical_key"](case["kind"], raw) for raw in case["raws"]}
                self.assertEqual(keys, {case["canonical_key"]})

    def test_a_non_canonical_adapter_key_is_detectable_not_rewritten(self):
        # fixtures/invalid/result-envelope.bad-key.json carries `dns:VPN.Internal.Example.`; the
        # schema rejects it, and M07 detects it with the same rule: re-deriving the key does not
        # return the reported string, so the record is quarantined instead of silently re-keyed.
        reported = "dns:VPN.Internal.Example."
        self.assertTrue(list(CANONICAL_KEY.iter_errors(reported)))
        self.assertNotEqual(NORM["renormalize_key"](reported), reported)

    def test_replay_keeps_the_canonical_id(self):
        stored = {vector["canonical_key"] for vector in VECTORS["vectors"]}
        for case in VECTORS["collapses"]:
            stored.add(case["canonical_key"])
        for path in sorted((ROOT / "fixtures/valid").glob("*.json")):
            stored |= {s for s in strings(json.loads(path.read_text())) if s.startswith(KEY_PREFIXES)}
        for path in sorted((ROOT / "db/postgres/tests").rglob("*.sql")):
            stored |= set(SQL_KEY.findall(path.read_text()))
        self.assertGreater(len(stored), 60)
        for key in sorted(stored):
            with self.subTest(key=key):
                self.assertEqual(NORM["renormalize_key"](key), key)


class SensitiveParameters(unittest.TestCase):
    def test_every_listed_parameter_is_dropped(self):
        for name in REGISTRY_DOC["sensitive_query_params"]:
            with self.subTest(parameter=name):
                raw = f"https://portal.example.com/a?{name}=s3cr3t&keep=1"
                self.assertEqual(
                    NORM["canonical_key"]("url", raw), "url:https://portal.example.com:443/a?keep=1"
                )
                self.assertTrue(NORM["is_sensitive_param"](name.upper()))

    def test_suffixes_and_prefixes_are_dropped(self):
        for family in ("refresh", "my", "user"):
            for suffix in REGISTRY_DOC["sensitive_query_param_suffixes"]:
                name = f"{family}_{suffix}"
                with self.subTest(parameter=name):
                    self.assertTrue(NORM["is_sensitive_param"](name))
        for prefix in REGISTRY_DOC["sensitive_query_param_prefixes"]:
            with self.subTest(prefix=prefix):
                self.assertTrue(NORM["is_sensitive_param"](prefix + "signature"))
        self.assertTrue(NORM["is_sensitive_param"]("access-token"))
        self.assertTrue(NORM["is_sensitive_param"]("user.token"))

    def test_benign_lookalikes_survive(self):
        for name in ("tokenizer", "monkey", "order", "page", "id", "keys", "sessionize"):
            with self.subTest(parameter=name):
                self.assertFalse(NORM["is_sensitive_param"](name))
                raw = f"https://portal.example.com/a?{name}=7"
                self.assertEqual(
                    NORM["canonical_key"]("url", raw),
                    f"url:https://portal.example.com:443/a?{name}=7",
                )

    def test_the_raw_value_is_not_rewritten(self):
        raw = "https://portal.example.com/a?token=abc&id=7#section"
        first = NORM["normalize"]("url", raw)
        self.assertEqual(raw, "https://portal.example.com/a?token=abc&id=7#section")
        self.assertNotIn("abc", first.canonical_key)
        self.assertNotIn("section", first.canonical_key)
        first.detail["path"] = "/mutated"
        self.assertEqual(NORM["normalize"]("url", raw).detail["path"], "/a")


class LimitsFailLoudly(unittest.TestCase):
    def test_empty_and_non_string_inputs(self):
        for raw in ("", "   ", None):  # type: ignore[arg-type]
            with self.subTest(raw=raw):
                with self.assertRaises(NORM["NormalizationError"]) as caught:
                    NORM["normalize"]("domain", raw)
                self.assertEqual(caught.exception.reason, "empty_input")

    def test_over_long_keys_are_rejected_not_truncated(self):
        raw = "https://example.com/" + "a" * 2100
        with self.assertRaises(NORM["NormalizationError"]) as caught:
            NORM["normalize"]("url", raw)
        self.assertEqual(caught.exception.reason, "too_long")

    def test_over_long_labels_are_rejected(self):
        with self.assertRaises(NORM["NormalizationError"]) as caught:
            NORM["normalize"]("domain", "a" * 64 + ".example")
        self.assertEqual(caught.exception.reason, "invalid_domain")

    def test_unknown_kind_is_not_invented(self):
        with self.assertRaises(NORM["NormalizationError"]) as caught:
            NORM["normalize"]("not_a_kind", "x")
        self.assertEqual(caught.exception.reason, "kind_not_supported")


class DocsAndGate(unittest.TestCase):
    def test_the_spec_points_at_the_locked_list(self):
        self.assertIn("contracts/ingestion/normalization.v2.yaml", SPEC)
        self.assertIn("aegis-norm/1", SPEC)

    def test_the_gate_lists_every_contract_test(self):
        gate = README.split("## Kiểm tra", 1)[1].split("```", 2)[1]
        self.assertIn("test_identity_normalization.py", gate)
        for path in sorted((ROOT / "tests").glob("test_*.py")):
            self.assertIn(path.name, gate, f"{path.name} is missing from the README gate")
        self.assertIn("normalization.v2.yaml", README)


if __name__ == "__main__":
    unittest.main()
