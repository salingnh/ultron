"""N01-N06 regressions: reject invalid inputs and preserve valid boundaries."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import runpy
import unittest

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
import yaml

ROOT = Path(__file__).resolve().parents[1]
CONFORMANCE = runpy.run_path(str(ROOT / "validation.py"))
CHECKER = CONFORMANCE["format_checker"]()
DOCS = [json.loads(p.read_text()) for p in ROOT.rglob("*.schema.json")]
REGISTRY = Registry().with_resources((d["$id"], Resource.from_contents(d)) for d in DOCS)
BASE = "https://aegis.io/contracts/"


def validator(target):
    return Draft202012Validator({"$ref": BASE + target}, registry=REGISTRY, format_checker=CHECKER)


class SchemaBoundaries(unittest.TestCase):
    def test_n01_full_openapi_validation(self):
        path = ROOT / "api/openapi.v2.yaml"
        document = yaml.safe_load(path.read_text())
        self.assertEqual(CONFORMANCE["openapi_errors"](document, path), [])
        document["paths"]["/jobs"]["post"]["responses"]["200"]["trả job cũ"] = None
        errors = CONFORMANCE["openapi_errors"](document, path)
        self.assertTrue(any("trả job cũ" in error for error in errors))

    def test_n02_identity_and_tool_targets(self):
        v = validator("common/ids.v2.schema.json#/$defs/CanonicalKey")
        good = ["dns:example.test", "dns:_sip._tcp.example.test", "ip:0.0.0.0",
                "ip:255.255.255.255", "ip:2001:db8::1", "service:10.0.0.1:1/tcp",
                "service:[2001:db8::1]:65535/udp", "app:https://example.test:443",
                "url:https://example.test:443/path?q=one", "app:https://[2001:db8::1]:443"]
        bad = ["dns:...", "ip:999.999.999.999", "ip:01.2.3.4", "ip:deadbeef",
               "ip:2001:::1", "ip:fe80::1%eth0", "service:10.0.0.1:0/tcp",
               "service:10.0.0.1:65536/tcp", "service:10.0.0.1:99999/tcp",
               "service:[2001:::1]:80/tcp", "app:https://example.test:99999",
               "url:https://example.test:99999/", "url:https://user:pw@example.test:443/",
               "app:https://EXAMPLE.test:443", "url:https://EXAMPLE.test:443/"]
        for value in good:
            with self.subTest(valid=value): self.assertTrue(v.is_valid(value))
        for value in bad:
            with self.subTest(invalid=value): self.assertFalse(v.is_valid(value))
        for target in ["dns/enumerate-subdomains", "dns/resolve"]:
            v = validator(f"capabilities/{target}.v2.schema.json")
            for domain in ["example.test", "dns:example.test", "xn--bcher-kva.example"]:
                with self.subTest(tool=target, valid=domain):
                    self.assertTrue(v.is_valid({"targets": [domain]}))
            for domain in ["...", "-bad.example", "bad..example", "dns:bad.", "a" * 64 + ".test"]:
                with self.subTest(tool=target, invalid=domain):
                    self.assertFalse(v.is_valid({"targets": [domain]}))
        v = validator("capabilities/dns/resolve.v2.schema.json")
        for resolver, valid in [("8.8.8.8", True), ("2001:db8::1", True),
                                ("999.999.999.999", False), ("...", False)]:
            with self.subTest(resolver=resolver):
                self.assertEqual(v.is_valid({"targets": ["example.test"], "resolvers": [resolver]}), valid)
        v = validator("capabilities/network/discover-services.v2.schema.json")
        for request, valid in [({"targets": ["ip:10.0.0.1"], "ports": [1, 65535]}, True),
                               ({"targets": ["service:[2001:db8::1]:53/udp"]}, True),
                               ({"targets": ["ip:garbage"], "ports": [80]}, False),
                               ({"targets": ["ip:10.0.0.1"]}, False),
                               ({"targets": ["ip:10.0.0.1"], "ports": []}, False),
                               ({"targets": ["ip:10.0.0.1"], "ports": [65536]}, False)]:
            with self.subTest(request=request): self.assertEqual(v.is_valid(request), valid)

    def test_n02_campaign_seed_validation_preserves_raw_input(self):
        v = validator("campaign/campaign-create.v2.schema.json")
        base = json.loads((ROOT / "fixtures/valid/campaign-create.json").read_text())
        for targets, valid in [({"domains": ["Bücher.Example."]}, True),
                               ({"ips": ["10.0.0.1/24", "2001:db8::/32"]}, True),
                               ({"domains": ["..."]}, False),
                               ({"ips": ["999.999.999.999"]}, False),
                               ({"ips": ["10.0.0.0/33"]}, False),
                               ({"ips": ["2001:db8::/129"]}, False),
                               ({"ips": ["10.0.0.0/255.255.255.0"]}, False)]:
            with self.subTest(targets=targets):
                data = dict(base, targets=targets); before = copy.deepcopy(data)
                self.assertEqual(v.is_valid(data), valid)
                self.assertEqual(data, before)

    def test_n03_event_uses_shared_severity(self):
        v = validator("events/event-envelope.v2.schema.json")
        base = json.loads((ROOT / "fixtures/valid/event.finding-changed.json").read_text())
        for field in ["old_severity", "new_severity"]:
            for severity in [None, "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNRATED", "BANANA", "high"]:
                data = copy.deepcopy(base); data["payload"][field] = severity
                with self.subTest(field=field, severity=severity):
                    self.assertEqual(v.is_valid(data), severity not in {"BANANA", "high"})

    def test_n05_nonnegative_consumed_usage(self):
        v = validator("agent/session-result.v2.schema.json#/properties/usage")
        base = {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0}
        self.assertTrue(v.is_valid(base))
        for field in base:
            with self.subTest(field=field):
                self.assertFalse(v.is_valid(dict(base, **{field: -1})))
        self.assertTrue(v.is_valid({"input_tokens": 1, "output_tokens": 2, "cost_usd": 0.000001}))

    def test_n06_only_json_export_is_advertised(self):
        api = yaml.safe_load((ROOT / "api/openapi.v2.yaml").read_text())
        operation = api["paths"]["/findings"]["get"]
        schema = next(p["schema"] for p in operation["parameters"] if p.get("name") == "format")
        v = Draft202012Validator(schema)
        self.assertTrue(v.is_valid("json")); self.assertFalse(v.is_valid("sarif"))
        self.assertEqual(set(operation["responses"]["200"]["content"]), {"application/json"})


if __name__ == "__main__":
    unittest.main()
