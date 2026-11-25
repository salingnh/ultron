"""C05/S1.5a: provider egress shape and server-derived actor attribution.

Schema-level regressions plus the cross-layer checks that keep JSON Schema, DDL and the specs on one
rule. Runtime enforcement (the broker itself, M05 resolving the principal) belongs to G1.3a/G1.1c.
The egress evidence is the G0.2 spike (docs/living/dac-ta-ky-thuat/02-nen-tang.md §Sandbox).
"""

from __future__ import annotations

import copy
import json
import runpy
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
import yaml

ROOT = Path(__file__).resolve().parents[1]
BASE = "https://aegis.io/contracts/"
DOCS = [json.loads(p.read_text()) for p in ROOT.rglob("*.schema.json")]
REGISTRY = Registry().with_resources((d["$id"], Resource.from_contents(d)) for d in DOCS)
VALIDATION = runpy.run_path(str(ROOT / "validation.py"))
FORMAT_CHECKER = VALIDATION["format_checker"]()
DENIED_EGRESS_HOST = VALIDATION["denied_egress_host"]
DOCS_ROOT = ROOT.parent / "docs/living/dac-ta-ky-thuat"
EGRESS_FIELDS = {
    "egressMode",
    "proxyAware",
    "proxyFlag",
    "proxyFlagFormat",
    "egressSources",
    "targetBinding",
    "targetPorts",
}
INITIATOR = {"kind": "operator", "id": "soc-1"}
PROPOSER = {"kind": "agent", "id": "01934f6a-0000-7000-8000-0000000000c1"}


def validator(target: str) -> Draft202012Validator:
    return Draft202012Validator(
        {"$ref": BASE + target}, registry=REGISTRY, format_checker=FORMAT_CHECKER
    )


def load(path: str):
    text = (ROOT / path).read_text(encoding="utf-8")
    return yaml.safe_load(text) if path.endswith((".yaml", ".yml")) else json.loads(text)


def manifest() -> dict:
    return load("fixtures/valid/manifest.subfinder.yaml")


def manifest_validator() -> Draft202012Validator:
    return validator("capability/provider-manifest.v2.schema.json")


class Egress(unittest.TestCase):
    def test_egress_without_a_declared_destination_is_rejected(self):
        v = manifest_validator()
        base = manifest()
        self.assertEqual(sorted(v.iter_errors(base), key=str), [])
        permissions = base["spec"]["permissions"]
        self.assertEqual(permissions["networkAccess"], "egress")
        self.assertEqual(permissions["targetBinding"], "none")  # passive: only its declared sources
        self.assertTrue(permissions["egressSources"])
        # A provider that reaches neither the target nor a declared source has no destination at all.
        no_destination = copy.deepcopy(base)
        no_destination["spec"]["permissions"]["egressSources"] = []
        errors = list(v.iter_errors(no_destination))
        self.assertTrue(
            any(
                list(e.absolute_path)[:3] == ["spec", "permissions", "egressSources"]
                for e in errors
            ),
            str(errors[0])[:200],
        )
        # Declaring egress but omitting the source list is the same gap, in a form that cannot be audited.
        undeclared = copy.deepcopy(base)
        del undeclared["spec"]["permissions"]["egressSources"]
        self.assertTrue(
            any(
                list(e.absolute_path)[:3] == ["spec", "permissions"]
                for e in v.iter_errors(undeclared)
            )
        )

    def test_target_ports_follow_the_target_binding(self):
        v = manifest_validator()
        target_bound = load("fixtures/valid/manifest.naabu.yaml")
        self.assertEqual(list(v.iter_errors(target_bound)), [])
        permissions = target_bound["spec"]["permissions"]
        self.assertEqual(permissions["targetBinding"], "required")
        self.assertEqual(permissions["targetPorts"], "from_input")
        # G1.6 caps a port scan's list by the pinned input schema (`network/discover-services/v2`
        # `ports.maxItems`), not by a second manifest field: the manifest already pins that schema.
        discover = json.loads(
            (ROOT / "capabilities/network/discover-services.v2.schema.json").read_text()
        )
        self.assertEqual(discover["properties"]["ports"]["maxItems"], 1000)
        # Target-bound without the from_input port rule: the broker would not know which ports to open.
        missing_ports = copy.deepcopy(target_bound)
        del missing_ports["spec"]["permissions"]["targetPorts"]
        self.assertFalse(v.is_valid(missing_ports))
        # A source-only provider must not declare target ports: it never connects to the target.
        for path in ["fixtures/invalid/manifest.target-ports-without-binding.yaml"]:
            with self.subTest(fixture=path):
                errors = list(v.iter_errors(load(path)))
                self.assertTrue(
                    any(list(e.absolute_path)[:3] == ["spec", "permissions"] for e in errors)
                )
        for path in ["fixtures/valid/manifest.subfinder.yaml", "fixtures/valid/manifest.dnsx.yaml"]:
            with self.subTest(source_only=path):
                doc = load(path)
                self.assertEqual(list(v.iter_errors(doc)), [])
                self.assertEqual(doc["spec"]["permissions"]["targetBinding"], "none")
                self.assertNotIn("targetPorts", doc["spec"]["permissions"])

    def test_input_destinations_must_be_declared_egress_sources(self):
        """S1.5b binds sources/resolvers to the manifest; S1.5a owns the set they must come from."""
        subfinder = load("fixtures/valid/manifest.subfinder.yaml")["spec"]["permissions"]
        dnsx = load("fixtures/valid/manifest.dnsx.yaml")["spec"]["permissions"]
        subfinder_ids = {source["id"] for source in subfinder["egressSources"]}
        dns_hosts = {
            host
            for source in dnsx["egressSources"]
            if source["protocol"] == "dns"
            for host in source["hosts"]
        }
        self.assertTrue(subfinder_ids)
        self.assertTrue(dns_hosts)
        task = load("fixtures/valid/approved-task.subfinder.json")
        for source in task["input"].get("sources", ["crtsh"]):
            with self.subTest(subfinder_source=source):
                self.assertIn(source, subfinder_ids)
        dnsx_task = load("fixtures/valid/approved-task.dnsx.json")
        for resolver in dnsx_task["input"].get("resolvers", ["9.9.9.9"]):
            with self.subTest(resolver=resolver):
                self.assertIn(resolver, dns_hosts)
        # The reference registry enforces it, and the two negatives live in its fixture set.
        harness = (ROOT / "tests/conformance/harness.py").read_text()
        for fragment in [
            "không nằm trong egressSources của manifest đã pin",
            "không nằm trong nguồn dns của manifest đã pin",
        ]:
            with self.subTest(harness=fragment):
                self.assertIn(fragment, harness)
        for fixture in ["source-not-declared.json", "resolver-not-declared.json"]:
            with self.subTest(policy_fixture=fixture):
                case = load(f"tests/conformance/fixtures/policy/{fixture}")
                self.assertEqual(
                    case["expect"], {"code": "POLICY_DENIED", "next_action": "FIX_INPUT"}
                )
        capabilities_readme = (ROOT / "capabilities/README.md").read_text()
        self.assertIn("egressSources", capabilities_readme)

    def test_egress_rejects_what_g1_cannot_enforce(self):
        v = manifest_validator()
        cases = {
            "no raw socket without an L3 mode": {"rawSocket": True},
            "single documented mode": {"egressMode": "router"},
        }
        for name, change in cases.items():
            with self.subTest(rule=name):
                doc = manifest()
                doc["spec"]["permissions"].update(change)
                self.assertFalse(v.is_valid(doc))
        # G1.6b: `proxyAware: false` is a truthful declaration for a tool that dials directly, and
        # such a tool cannot ride the L7 broker - it asks for the L3 channel, whose gateway filters
        # by the signed IP:port set (G1.6 L3). The manifest is accepted; M06 refuses a broker job
        # for it before a container exists.
        truthful = manifest()
        truthful["spec"]["permissions"]["proxyAware"] = False
        truthful["spec"]["permissions"]["egressMode"] = "l3"
        # An L3 job has no L7 proxy, so it declares no proxy flag.
        truthful["spec"]["permissions"].pop("proxyFlag", None)
        self.assertTrue(v.is_valid(truthful))
        on_broker = manifest()
        on_broker["spec"]["permissions"]["proxyAware"] = False
        self.assertFalse(v.is_valid(on_broker))  # the broker needs a proxy-aware tool
        undeclared = manifest()
        del undeclared["spec"]["permissions"]["proxyAware"]
        self.assertFalse(v.is_valid(undeclared))  # egress still has to declare it
        udp = manifest()
        udp["spec"]["permissions"]["egressSources"][0]["protocol"] = "udp"
        self.assertFalse(v.is_valid(udp))  # the broker relays no UDP, so it cannot be declared
        wildcard = manifest()
        wildcard["spec"]["permissions"]["egressSources"][0]["hosts"] = ["*.crt.sh"]
        self.assertFalse(v.is_valid(wildcard))  # exact hosts only; no suffix match
        prefixed = manifest()
        prefixed["spec"]["permissions"]["egressSources"][0]["hosts"] = ["dns:crt.sh"]
        self.assertFalse(v.is_valid(prefixed))
        for fixture in [
            "fixtures/invalid/manifest.egress-proxy-undeclared.yaml",
            "fixtures/invalid/manifest.egress-raw-socket.yaml",
            "fixtures/invalid/manifest.egress-udp-source.yaml",
        ]:
            with self.subTest(fixture=fixture):
                self.assertFalse(v.is_valid(load(fixture)))

    def test_platform_deny_set_is_a_constant_not_provider_data(self):
        v = manifest_validator()
        for field in ["deniedHosts", "allowHosts", "egressDenyList", "denyList"]:
            with self.subTest(field=field):
                doc = manifest()
                doc["spec"]["permissions"][field] = ["169.254.169.254", "::1"]
                self.assertFalse(v.is_valid(doc), field)
        self.assertFalse(
            v.is_valid(load("fixtures/invalid/manifest.egress-declared-deny-list.yaml"))
        )
        permissions = json.loads((ROOT / "capability/provider-manifest.v2.schema.json").read_text())
        permissions = permissions["properties"]["spec"]["properties"]["permissions"]
        self.assertEqual(
            set(permissions["properties"]),
            {"scopeRequired", "networkAccess", "credentials", "rawSocket"} | EGRESS_FIELDS,
        )
        self.assertEqual(permissions["properties"]["rawSocket"]["const"], False)
        sandbox = (DOCS_ROOT / "02-nen-tang.md").read_text()
        for fragment in ["loopback", "link-local", "169.254", "hằng của nền tảng", "multicast"]:
            with self.subTest(deny_set=fragment):
                self.assertIn(fragment, sandbox)

    def test_a_tool_that_ignores_the_proxy_environment_declares_its_flag(self):
        """`proxyFlag` is the truthful declaration; it only makes sense on the broker channel."""
        v = manifest_validator()
        subfinder = load("fixtures/valid/manifest.subfinder.yaml")
        permissions = subfinder["spec"]["permissions"]
        self.assertEqual(permissions["proxyFlag"], "-proxy")
        self.assertTrue(permissions["proxyAware"])
        naabu = load("fixtures/valid/manifest.naabu.yaml")
        self.assertEqual(naabu["spec"]["permissions"]["proxyFlag"], "-proxy")
        self.assertEqual(naabu["spec"]["permissions"]["proxyFlagFormat"], "host_port")
        # l3 has no L7 proxy: a flag there is a contradiction.
        l3_with_flag = copy.deepcopy(load("fixtures/valid/manifest.fingerprintx.yaml"))
        l3_with_flag["spec"]["permissions"]["proxyFlag"] = "-proxy"
        self.assertFalse(v.is_valid(l3_with_flag))
        # A flag without proxyAware is a contradiction too.
        broker_without_aware = copy.deepcopy(load("fixtures/valid/manifest.subfinder.yaml"))
        del broker_without_aware["spec"]["permissions"]["proxyAware"]
        self.assertFalse(v.is_valid(broker_without_aware))
        # A free-form value is not a flag.
        prefixed = copy.deepcopy(load("fixtures/valid/manifest.subfinder.yaml"))
        prefixed["spec"]["permissions"]["proxyFlag"] = "--proxy=http://x"
        self.assertFalse(v.is_valid(prefixed))

    def test_l3_is_the_channel_for_a_non_proxy_aware_tool(self):
        """G1.6 item 5: `egressMode: l3` is for tools that cannot use the L7 broker."""
        v = manifest_validator()
        # fingerprintx is the real l3 provider: it dials directly and declares no proxy flag.
        doc = load("fixtures/valid/manifest.fingerprintx.yaml")
        self.assertEqual(list(v.iter_errors(doc)), [])
        l3_with_proxy_flag = load("fixtures/valid/manifest.naabu.yaml")
        l3_with_proxy_flag["spec"]["permissions"]["egressMode"] = "l3"
        self.assertFalse(v.is_valid(l3_with_proxy_flag))
        # A tool that says it cannot speak to a proxy cannot run on the L7 channel.
        broker_without_proxy = copy.deepcopy(doc)
        broker_without_proxy["spec"]["permissions"]["egressMode"] = "broker"
        self.assertFalse(v.is_valid(broker_without_proxy))

    def test_egress_configuration_cannot_exist_without_the_network(self):
        v = manifest_validator()
        self.assertFalse(v.is_valid(load("fixtures/invalid/manifest.none-with-egress.yaml")))
        doc = manifest()
        doc["spec"]["permissions"] = {"networkAccess": "none", "rawSocket": False}
        self.assertEqual(list(v.iter_errors(doc)), [])


class ActorAttribution(unittest.TestCase):
    def test_initiator_is_server_derived_and_proposer_is_a_session(self):
        v = validator("capability/approved-task.v2.schema.json")
        task = load("fixtures/valid/approved-task.subfinder.json")
        self.assertEqual(list(v.iter_errors(task)), [])
        self.assertEqual(task["requested_by"]["kind"], "operator")
        self.assertEqual(task["proposed_by"]["kind"], "agent")
        # An agent (or any self-declared identity) can never be the initiator of a task.
        for invalid in [
            {"kind": "agent", "id": "session-1"},
            {"kind": "Agent", "id": "x"},
            {"kind": "operator"},
        ]:
            with self.subTest(invalid_initiator=invalid):
                doc = copy.deepcopy(task)
                doc["requested_by"] = invalid
                self.assertFalse(v.is_valid(doc))
        # Module-driven work is a valid initiator; a proposer is never an operator/module.
        module = copy.deepcopy(task)
        module["requested_by"] = {"kind": "module", "id": "M20"}
        self.assertTrue(v.is_valid(module))
        for invalid in [
            {"kind": "operator", "id": "soc-1"},
            {"kind": "module", "id": "M20"},
            {"kind": "agent"},
        ]:
            with self.subTest(invalid_proposer=invalid):
                doc = copy.deepcopy(task)
                doc["proposed_by"] = invalid
                self.assertFalse(v.is_valid(doc))
        # A direct operator submission has no proposer; nothing is invented for it.
        direct = copy.deepcopy(task)
        del direct["proposed_by"]
        self.assertEqual(list(v.iter_errors(direct)), [])
        missing = copy.deepcopy(task)
        del missing["requested_by"]
        self.assertFalse(v.is_valid(missing))
        no_extra = copy.deepcopy(task)
        no_extra["requested_by"] = dict(INITIATOR, display_name="SOC")
        self.assertFalse(v.is_valid(no_extra))

    def test_job_read_model_carries_both_actors(self):
        v = validator("capability/job.v2.schema.json")
        job = load("fixtures/valid/job.queued-waiting.json")
        self.assertEqual(list(v.iter_errors(job)), [])
        self.assertEqual(job["requested_by"]["kind"], "operator")
        self.assertEqual(job["proposed_by"], PROPOSER)
        cancelled = load("fixtures/valid/job.cancelled-with-intent.json")
        self.assertEqual(list(v.iter_errors(cancelled)), [])
        self.assertFalse(v.is_valid(load("fixtures/invalid/job.actor-proposer-module.json")))
        # The stored row cannot differ from this shape: the DDL refuses an agent initiator on INSERT.
        self.assertFalse(v.is_valid(dict(job, requested_by={"kind": "agent", "id": "planner"})))
        # Without an initiator there is nothing to trace the job back to.
        untraceable = copy.deepcopy(job)
        del untraceable["requested_by"]
        self.assertFalse(v.is_valid(untraceable))
        # The task and the job read model must agree on the two actors.
        task = load("fixtures/valid/approved-task.subfinder.json")
        self.assertEqual(job["requested_by"], task["requested_by"])
        self.assertEqual(job["proposed_by"], task["proposed_by"])

    def test_deny_set_wins_over_declared_egress_sources(self):
        # OI-5/P7: the platform deny set takes precedence over egressSources, so the registry refuses a
        # manifest that declares one of those hosts, and fe80::/10 is named explicitly (S-9).
        for host in [
            "169.254.169.254",
            "127.0.0.1",
            "::1",
            "::ffff:7f00:1",
            "fe80::1",
            "fe80::",
            "0.0.0.0",
            "224.0.0.251",
            "ff02::1",
            "::",
            "64:ff9b::7f00:1",
            "2002:7f00:1::",
            "localhost",
            "metadata.google.internal",
        ]:
            with self.subTest(denied=host):
                self.assertTrue(DENIED_EGRESS_HOST(host), host)
        for host in ["1.1.1.1", "9.9.9.9", "10.0.0.5", "resolver.example", "8.8.8.8"]:
            with self.subTest(allowed=host):
                self.assertFalse(DENIED_EGRESS_HOST(host), host)
        # The conformance check that the registry runs rejects the fixture (validate_contracts.py holds
        # that assertion); the fixture is valid JSON Schema on purpose, which is why the check exists.
        fixture = load("fixtures/invalid/manifest.egress-source-in-deny-set.yaml")
        self.assertTrue(manifest_validator().is_valid(fixture))
        source_hosts = [
            h for s in fixture["spec"]["permissions"]["egressSources"] for h in s["hosts"]
        ]
        self.assertTrue(any(DENIED_EGRESS_HOST(h) for h in source_hosts))
        sandbox = (DOCS_ROOT / "02-nen-tang.md").read_text()
        self.assertIn("fe80::/10", sandbox)
        self.assertIn("− tập luôn chặn", sandbox)

    def test_requests_carry_no_execution_authority(self):
        request = json.loads((ROOT / "mcp/capability-request.v2.schema.json").read_text())
        for field in ["actor", "requested_by", "proposed_by", "operator", "session_id"]:
            with self.subTest(field=field):
                self.assertNotIn(field, request["properties"])
        # A REST body carries no actor at all (OI-10): the server derives requested_by from the
        # principal it verified, and a REST call has no agent session, so proposed_by is never set.
        submit = json.loads((ROOT / "capability/job-submit.v2.schema.json").read_text())
        create = json.loads((ROOT / "campaign/campaign-create.v2.schema.json").read_text())
        transition = json.loads((ROOT / "finding/transition-request.v2.schema.json").read_text())
        for name, body in [
            ("job-submit.v2", submit),
            ("campaign-create.v2", create),
            ("transition-request.v2", transition),
        ]:
            with self.subTest(body=name):
                self.assertNotIn("actor", body["properties"])
                self.assertNotIn("actor", body["required"])
                self.assertIn("KHÔNG mang actor", body["description"])
        self.assertNotIn("proposed_by", submit["properties"])
        self.assertNotIn("requested_by", submit["properties"])
        mcp_readme = (ROOT / "mcp/README.md").read_text()
        self.assertIn("không dùng ID do LLM khai làm quyền truy cập", mcp_readme)

    def test_ddl_and_docs_lock_the_same_actor_rule(self):
        migration = (ROOT / "db/postgres/0001_baseline.sql").read_text()
        for fragment in [
            "aegis.is_initiator",
            "aegis.is_proposer",
            "CREATE TRIGGER initiator_required BEFORE INSERT ON aegis.policy_decision",
            "CREATE TRIGGER initiator_required BEFORE INSERT ON aegis.scan_job",
            "proposed_by jsonb,",
            "CREATE TRIGGER proposer_session_required BEFORE INSERT ON aegis.scan_job",
        ]:
            with self.subTest(ddl=fragment):
                self.assertIn(fragment, migration)
        test = (ROOT / "db/postgres/tests/job_actor.sql").read_text()
        for fragment in [
            "proposer was rewritable after acceptance",
            "invented proposer",
            "blocked <> 6",
        ]:
            with self.subTest(sql_test=fragment):
                self.assertIn(fragment, test)
        chain = (ROOT / "README.md").read_text()
        for name in ["0001_baseline.sql", "tests/job_actor.sql", "tests/test_egress_actor.py"]:
            with self.subTest(chain=name):
                self.assertIn(name, chain)
        c05 = (DOCS_ROOT / "04-module-ket-noi-oss.md").read_text()
        self.assertNotIn("còn cần khóa ở S1.5", c05)
        self.assertIn("proposed_by", c05)
        self.assertIn("OD-5", c05)
        sandbox = (DOCS_ROOT / "02-nen-tang.md").read_text()
        self.assertNotIn("còn cần khóa ở S1.5", sandbox)
        for field in EGRESS_FIELDS:
            with self.subTest(sandbox_field=field):
                self.assertIn(field, sandbox)
        contract_readme = (ROOT / "README.md").read_text()
        self.assertNotIn("Schema tool và actor", contract_readme)


if __name__ == "__main__":
    unittest.main()
