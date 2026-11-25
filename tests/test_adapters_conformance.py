"""Adapter packages under `adapters/` against the contract conformance suite (G1.3b).

Discovery is data driven on purpose: a tool is added to the platform by adding
`adapters/<module>/<tool>/` with a `manifest.yaml`, a pure `parser.py` and `fixtures/lab/`.
Nothing in this file names a provider, so the "second tool" PR is a pure addition under
`adapters/` - no core change, no test change (the G1 gate "add a tool without changing the core").

What each adapter has to show:

* `manifest.yaml` is admitted by M05 (`aegis.m05_registry.manifest.admit_manifest`), its pins match
  the contract fixture of the same provider byte for byte, and its image digest is the pin the
  authorized lab ran (`deploy/lab/images.env`). The registry "config" is the start-up scan of
  `adapters/**/manifest.yaml` (`aegis.m26_api.manifests.adapter_manifests`), so that scan is checked
  here as well.
* the real parser passes the same seven-handler conformance suite as the contract reference
  (`contracts/tests/conformance/harness.py`, `run_provider_suite(..., parser=...)`): envelope equal
  to `contracts/fixtures/valid/result-envelope.<provider>.json`, deterministic, replayable.
* the lab fixture (`fixtures/lab/result.jsonl`, the byte-for-byte output of the G0.4c run) parses to
  `expected.json` twice in a row, every predicate is in `contracts/ingestion/predicates.v2.yaml`,
  every canonical key passes the contract `CanonicalKey` format, and the assets agree with the
  independent lab fixture list - the golden is not only "whatever the parser says".
* a corrupt output file fails loudly and `input.max_results` (when the capability schema has it) is
  enforced after collection, in the parser.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import re
import runpy
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

from aegis import validation
from aegis.common.repo import repository_root
from aegis.m05_registry.manifest import admit_manifest
from aegis.m26_api.manifests import adapter_manifests

REPO_ROOT = repository_root()
CONTRACTS = REPO_ROOT / "contracts"
ADAPTERS = REPO_ROOT / "adapters"
CONF = CONTRACTS / "tests/conformance"
LAB_IMAGES = REPO_ROOT / "deploy/lab/images.env"

HARNESS = runpy.run_path(str(CONF / "harness.py"))
CONTEXT = HARNESS["load"](CONF / "fixtures/context.json")
PREDICATES = yaml.safe_load((CONTRACTS / "ingestion/predicates.v2.yaml").read_text())["predicates"]
MIN_CHECKS = 9


class Adapter:
    """One adapter package: its manifest bytes, the pinned document and the parser entrypoint."""

    def __init__(self, package: Path) -> None:
        self.package = package
        self.manifest_bytes = (package / "manifest.yaml").read_bytes()
        self.manifest: dict[str, Any] = yaml.safe_load(self.manifest_bytes)
        self.provider = str(self.manifest["metadata"]["name"])
        self.entrypoint = str(self.manifest["spec"]["parser"]["entrypoint"])
        self.digest = str(self.manifest["spec"]["runtime"]["imageDigest"])
        self.lab_fixture = package / "fixtures/lab"

    @property
    def lab_run(self) -> dict[str, Any] | None:
        path = self.lab_fixture / "run.json"
        if not path.is_file():
            return None
        document: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        return document

    def parse_function(self) -> Callable[..., dict[str, Any]]:
        module_name, _, function_name = self.entrypoint.partition(":")
        module = importlib.import_module(module_name)
        function = getattr(module, function_name)
        assert callable(function), f"{self.entrypoint} is not callable"
        return cast(Callable[..., dict[str, Any]], function)

    def input_schema(self) -> dict[str, Any]:
        reference = str(self.manifest["spec"]["inputSchemaRef"])
        match = re.fullmatch(r"schema://([a-z0-9-]+)/([a-z0-9-]+)/v(\d+)", reference)
        assert match is not None, f"{reference} is not a schema:// reference"
        group, name, version = match.groups()
        path = CONTRACTS / "capabilities" / group / f"{name}.v{version}.schema.json"
        document: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        return document


def _discover() -> list[Adapter]:
    return [Adapter(path.parent) for path in sorted(ADAPTERS.glob("**/manifest.yaml"))]


ADAPTERS_FOUND = _discover()


def _id(adapter: Adapter) -> str:
    return f"{adapter.package.relative_to(ADAPTERS).as_posix()}:{adapter.provider}"


def _lab_pin(provider: str) -> str | None:
    """The digest `deploy/lab/images.env` pins for this tool, when the lab runs it."""
    if not LAB_IMAGES.is_file():
        return None
    for line in LAB_IMAGES.read_text(encoding="utf-8").splitlines():
        name, _, value = line.strip().partition("=")
        if name.startswith("AEGIS_LAB_") and name.endswith("_IMAGE") and provider.upper() in name:
            return value
    return None


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _conformance_scenario(adapter: Adapter) -> dict[str, Any] | None:
    path = CONF / "fixtures" / f"{adapter.provider}.json"
    if not path.is_file():
        return None
    scenario: dict[str, Any] = HARNESS["load"](path)
    return scenario


def _assert_key(key: str) -> None:
    problems = validation.errors("common/ids.v2.schema.json#/$defs/CanonicalKey", key)
    assert not problems, f"{key}: {problems}"


KEY_NAMESPACES = (
    "dns:",
    "ip:",
    "service:",
    "app:",
    "url:",
    "email:",
    "purl:",
    "oci:",
    "repo:",
    "git:",
    "artifact:",
    "cloud:",
    "k8s:",
)


def _canonical_key(value: str) -> str:
    """A target as the canonical key it names: a key stays one, a bare name is a domain."""
    text = str(value).strip().lower().rstrip(".")
    return text if text.startswith(KEY_NAMESPACES) else f"dns:{text}"


def _assert_keys_and_predicates(parsed: dict[str, Any]) -> None:
    for asset in parsed["assets"]:
        _assert_key(asset["canonical_key"])
    for observation in parsed["observations"]:
        _assert_key(observation["subject"])
        assert observation["predicate"] in PREDICATES, (
            f"{observation['predicate']} is not in contracts/ingestion/predicates.v2.yaml"
        )
    for relationship in parsed["relationships"]:
        _assert_key(relationship["from"])
        _assert_key(relationship["to"])


def _assert_lab_cross_check(adapter: Adapter, run: dict[str, Any], parsed: dict[str, Any]) -> None:
    """Compare the parser's view of the run with the committed G0.4c lab fixture."""
    cross_check = run.get("cross_check")
    if not cross_check:
        return  # a tool without a committed lab fixture list has nothing independent to compare to
    path = REPO_ROOT / str(cross_check["file"])
    assert path.is_file(), f"{adapter.provider}: the cross-check fixture {path} is missing"
    expected: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    keys = {asset["canonical_key"] for asset in parsed["assets"]}
    if cross_check["kind"] == "domains":
        assert keys == {f"dns:{str(host).lower().rstrip('.')}" for host in expected["hosts"]}
        return
    if cross_check["kind"] == "resolutions":
        expected_ips = {
            f"ip:{address}"
            for probe in expected["probes"]
            for address in [*(probe.get("a") or []), *(probe.get("aaaa") or [])]
        }
        assert keys == expected_ips, f"IP assets differ from the lab fixture: {keys ^ expected_ips}"
        edges = {(edge["from"], edge["to"]) for edge in parsed["relationships"]}
        expected_edges = {
            (f"dns:{probe['host'].lower().rstrip('.')}", f"ip:{address}")
            for probe in expected["probes"]
            for address in [*(probe.get("a") or []), *(probe.get("aaaa") or [])]
        }
        assert edges == expected_edges, f"RESOLVES_TO mismatch: {edges ^ expected_edges}"
        silent = {
            f"dns:{probe['host'].lower().rstrip('.')}"
            for probe in expected["probes"]
            if not probe.get("a") and not probe.get("aaaa")
        }
        claimed = {observation["subject"] for observation in parsed["observations"]}
        assert not (silent & claimed), (
            f"a name with no answer must not be reported as resolving: {silent & claimed}"
        )
        return
    if cross_check["kind"] == "services":
        # The inventory declares, per lab service, the address its zone name resolves to and the
        # ports the container answers on; the run's ports are the ones the job bound from input.
        ports = {int(port) for port in run["input"].get("ports") or []}
        expected_services = {
            f"service:{service['address']}:{int(port)}/tcp"
            for service in expected["services"]
            for port in service.get("ports") or []
            if int(port) in ports
        }
        assert keys == expected_services, (
            f"service assets differ from the lab inventory: {keys ^ expected_services}"
        )
        edges = {(edge["from"], edge["to"]) for edge in parsed["relationships"]}
        expected_edges = {(f"ip:{key.split(':')[1]}", key) for key in expected_services}
        assert edges == expected_edges, f"EXPOSES mismatch: {edges ^ expected_edges}"
        return
    pytest.fail(f"{adapter.provider}: unknown cross_check kind {cross_check['kind']!r}")


def test_adapters_are_discovered() -> None:
    assert ADAPTERS_FOUND, "no adapters/**/manifest.yaml found: the registry would publish nothing"


@pytest.mark.parametrize("adapter", ADAPTERS_FOUND, ids=[_id(item) for item in ADAPTERS_FOUND])
def test_manifest_is_admitted_and_pinned(adapter: Adapter) -> None:
    record = admit_manifest(adapter.manifest_bytes)
    assert record.provider == adapter.provider
    assert record.image_digest == adapter.digest
    assert record.capability == adapter.manifest["spec"]["capability"]

    fixture = CONTRACTS / "fixtures/valid" / f"manifest.{adapter.provider}.yaml"
    assert fixture.is_file(), f"the contract fixture for {adapter.provider} is missing"
    assert adapter.manifest_bytes == fixture.read_bytes(), (
        f"{adapter.package}/manifest.yaml drifted from {fixture}: the contract fixture is the "
        "pinned bytes every fixture and the conformance suite were written against"
    )

    pin = _lab_pin(adapter.provider)
    if pin is not None:
        assert adapter.digest in pin, (
            f"{adapter.provider}: manifest digest {adapter.digest} is not the image the authorized "
            f"lab ran ({pin})"
        )

    module_name, _, function_name = adapter.entrypoint.partition(":")
    assert module_name.startswith("adapters."), adapter.entrypoint
    relative = Path(*module_name.split(".")).with_suffix(".py")
    assert (REPO_ROOT / relative).is_file(), f"{adapter.entrypoint}: {relative} does not exist"
    assert callable(adapter.parse_function())


@pytest.mark.parametrize("adapter", ADAPTERS_FOUND, ids=[_id(item) for item in ADAPTERS_FOUND])
def test_conformance_suite_with_the_real_parser(adapter: Adapter) -> None:
    scenario = _conformance_scenario(adapter)
    assert scenario is not None, (
        f"{adapter.provider} has no contract conformance scenario "
        f"(contracts/tests/conformance/fixtures/{adapter.provider}.json); a tool is "
        "registered only after its schema/parser/fixture are in the contract bundle"
    )
    assert scenario["manifest"] == f"fixtures/valid/manifest.{adapter.provider}.yaml"
    failures, checks = HARNESS["run_provider_suite"](
        adapter.provider, CONTEXT, parser=adapter.parse_function()
    )
    assert checks >= MIN_CHECKS, f"{adapter.provider}: the suite ran only {checks} checks"
    assert failures == [], "\n".join(failures)


@pytest.mark.parametrize("adapter", ADAPTERS_FOUND, ids=[_id(item) for item in ADAPTERS_FOUND])
def test_lab_fixture_is_the_committed_run(adapter: Adapter) -> None:
    run = adapter.lab_run
    assert run is not None, f"{adapter.package}/fixtures/lab/run.json is missing"
    raw = adapter.lab_fixture / str(run["raw"]["file"])
    assert raw.is_file(), raw
    assert _sha256(raw) == run["raw"]["sha256"], f"{raw} is not the file the run recorded"
    assert raw.stat().st_size == run["raw"]["size_bytes"]

    parse = adapter.parse_function()
    task = {"input": run["input"]}
    evidence = [{"local_ref": "raw"}]
    first = parse(adapter.lab_fixture, task, evidence)
    second = parse(adapter.lab_fixture, task, evidence)
    assert first == second, "the parser is not deterministic on the lab fixture"
    expected = json.loads((adapter.lab_fixture / str(run["expected"])).read_text(encoding="utf-8"))
    assert first == expected, "the parser no longer produces the committed lab expectation"

    _assert_keys_and_predicates(first)
    expected_coverage = sorted(_canonical_key(value) for value in run["input"]["targets"])
    assert first["coverage_subjects"] == expected_coverage, (
        f"coverage must be the input targets, got {first['coverage_subjects']}"
    )
    _assert_lab_cross_check(adapter, run, first)


@pytest.mark.parametrize("adapter", ADAPTERS_FOUND, ids=[_id(item) for item in ADAPTERS_FOUND])
def test_registry_scan_finds_every_adapter(adapter: Adapter) -> None:
    scanned = {hashlib.sha256(raw).hexdigest() for raw in adapter_manifests()}
    assert hashlib.sha256(adapter.manifest_bytes).hexdigest() in scanned, (
        f"{adapter.package} is not picked up by the start-up scan of adapters/**/manifest.yaml, so "
        "M05 would never register it"
    )


@pytest.mark.parametrize("adapter", ADAPTERS_FOUND, ids=[_id(item) for item in ADAPTERS_FOUND])
def test_parser_fails_loudly_on_corrupt_output(adapter: Adapter, tmp_path: Path) -> None:
    (tmp_path / "result.jsonl").write_text('{"host": "ok.example"}\n{"host": \n', encoding="utf-8")
    with pytest.raises(ValueError):
        adapter.parse_function()(tmp_path, {"input": {"targets": ["lab.aegis.test"]}}, [])
    with pytest.raises(ValueError):
        adapter.parse_function()(tmp_path / "missing", {"input": {"targets": ["x.example"]}}, [])


def _adapters_with_result_cap() -> list[Adapter]:
    """Adapters whose capability schema caps the number of results (`input.max_results`)."""
    return [
        adapter
        for adapter in ADAPTERS_FOUND
        if "max_results" in (adapter.input_schema().get("properties") or {})
    ]


@pytest.mark.parametrize(
    "adapter", _adapters_with_result_cap(), ids=[_id(item) for item in _adapters_with_result_cap()]
)
def test_parser_applies_the_result_cap(adapter: Adapter) -> None:
    run = adapter.lab_run
    assert run is not None
    task = {"input": {**run["input"], "max_results": 1}}
    parsed = adapter.parse_function()(adapter.lab_fixture, task, [])
    assert len(parsed["assets"]) <= 1, f"{adapter.provider} ignored input.max_results"
