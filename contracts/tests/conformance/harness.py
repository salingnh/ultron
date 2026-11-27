"""Registry + adapter conformance harness for the first tool chain (S1.5b).

This is a *contract conformance reference for tests only*; no service imports it and
no product code exists yet. It runs the M05/M06 rules that the contract already fixes
against the checked-in Subfinder and DNSx fixtures, so:

  * an adapter implementation can be dropped in (same seven handlers) and must pass
    the same suite;
  * the contract rules that are not expressible in JSON Schema (caps, target binding,
    pinned manifest, credential refusal, envelope provenance) fail loudly here.

Rules the harness enforces (sources: contracts/interfaces/README.md §1, contracts/capabilities/README.md,
contracts/mcp/README.md, contracts/README.md):
  describe   no side effect; the manifest is the immutable bytes M05 accepted.
  validate   schema-invalid input -> INPUT_INVALID; value over a pinned cap -> POLICY_DENIED;
             nothing is executed before a valid task.
  start      idempotent per idempotency key; re-checks pin and policy before any side effect;
             missing pinned manifest -> DEPENDENCY_MISSING, mismatched pin -> POLICY_DENIED.
  status     carries retry_after for non-terminal states, 0 when terminal.
  cancel     best effort, appends audit, idempotent; a cancelled job never produces an envelope.
  collect    envelope validates, evidence sha256 equals the raw bytes, provenance copies the task
             pins and seed targets, coverage lists what was checked, parser is deterministic.
  health     reports the pinned upstream version and dependencies, never a live lookup.

Output envelope rules (see build_envelope): the parser is pure and has no clock; the collector
stamps observed_at = finished_at and input_fingerprint = aegis-c14n/1 sha256 of the accepted input.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import re
import runpy
import tempfile
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator
from referencing import Registry as RefRegistry, Resource

ROOT = Path(__file__).resolve().parents[2]  # contracts/
CONF = ROOT / "tests/conformance"
BASE_ID = "https://aegis.io/contracts/"

CANON = runpy.run_path(str(ROOT / "tests/canonicalization.py"))
FORMAT_CHECKER = runpy.run_path(str(ROOT / "validation.py"))["format_checker"]()
CHECK_MANIFEST_BINDING = runpy.run_path(str(ROOT / "tests/manifest_binding.py"))["check_manifest_binding"]


def load(path) -> dict:
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    return yaml.safe_load(text) if path.suffix in {".yaml", ".yml"} else json.loads(text)


_SCHEMAS = {p.relative_to(ROOT).as_posix(): load(p) for p in sorted(ROOT.rglob("*.schema.json"))}
REF_REGISTRY = RefRegistry().with_resources(
    (BASE_ID + rel, Resource.from_contents(doc)) for rel, doc in _SCHEMAS.items())


def validator(relpath: str) -> Draft202012Validator:
    return Draft202012Validator(load(ROOT / relpath), registry=REF_REGISTRY, format_checker=FORMAT_CHECKER)


TASK_VALIDATOR = validator("capability/approved-task.v2.schema.json")
ENVELOPE_VALIDATOR = validator("ingestion/result-envelope.v2.schema.json")
MANIFEST_VALIDATOR = validator("capability/provider-manifest.v2.schema.json")
SNAPSHOT_VALIDATOR = validator("campaign/roe-policy.v2.schema.json")
ERROR_VALIDATOR = validator("common/error.v2.schema.json")


class ContractError(Exception):
    """A refusal the contract already names: code and next_action come from error.v2."""

    def __init__(self, code: str, next_action: str, message: str, field: str | None = None):
        super().__init__(message)
        self.code = code
        self.next_action = next_action
        self.message = message
        self.field = field

    def as_error(self) -> dict:
        err = {"code": self.code, "message": self.message, "next_action": self.next_action}
        if self.field:
            err["field"] = self.field
        return err


def _deny(message: str, field: str | None = None) -> ContractError:
    return ContractError("POLICY_DENIED", "FIX_INPUT", message, field)


def _invalid(message: str, field: str | None = None) -> ContractError:
    return ContractError("INPUT_INVALID", "FIX_INPUT", message, field)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


#: CanonicalKey namespaces (common/ids.v2). A target that already carries one is that asset; a
#: bare value is a domain, the form both DNS capabilities take.
KEY_NAMESPACES = (
    "dns:", "ip:", "service:", "app:", "url:", "email:", "purl:", "oci:", "repo:", "git:",
    "artifact:", "cloud:", "k8s:",
)


def domain_key(value: str) -> str:
    """Capability input target -> CanonicalKey. M07 owns normalization; the fixture inputs are already ASCII."""
    text = value.lower().rstrip(".")
    return text if text.startswith("dns:") else "dns:" + text


def canonical_key(value: str) -> str:
    """A target as the CanonicalKey it names: an existing key stays one, a bare name is a domain."""
    text = value.lower().rstrip(".")
    return text if text.startswith(KEY_NAMESPACES) else "dns:" + text


def kind_for_key(key: str) -> str:
    prefix = key.split(":", 1)[0]
    return {
        "dns": "domain", "ip": "ip", "service": "service", "url": "url", "email": "email",
        "purl": "package", "oci": "oci_image", "app": "application", "repo": "repo",
        "repodigest": "repo_snapshot", "artifact": "artifact", "cloud": "cloud_resource",
        "k8s": "k8s_workload",
    }.get(prefix, "artifact")


def dotted_patch(document: dict, patch: dict) -> dict:
    out = copy.deepcopy(document)
    for path, value in patch.items():
        node = out
        parts = path.split(".")
        for part in parts[:-1]:
            node = node[part]
        node[parts[-1]] = copy.deepcopy(value)
    return out


class Audit:
    """Records every effect the harness can see, so "no side effect" is a check, not a claim."""

    def __init__(self):
        self.reads: list[str] = []
        self.writes: list[str] = []
        self.network: list[str] = []
        self.executions = 0
        self.rows: list[dict] = []

    def read(self, path) -> None:
        self.reads.append(str(path))

    def write(self, path) -> None:
        self.writes.append(str(path))

    def connect(self, target: str) -> None:
        self.network.append(target)


class Registry:
    """M05-shaped registry: immutable manifests by sha256 plus the campaign snapshot the job pins."""

    def __init__(self, raw_manifests: list[bytes], context: dict):
        self.by_sha: dict[str, tuple[bytes, dict]] = {}
        self.by_capability: dict[tuple[str, str], str] = {}
        self.context = context
        for raw in raw_manifests:
            manifest = yaml.safe_load(raw)
            errors = list(MANIFEST_VALIDATOR.iter_errors(manifest))
            if errors:
                raise ValueError(f"manifest không hợp lệ: {errors[0].message}")
            digest = sha256_bytes(raw)
            if digest in self.by_sha and self.by_sha[digest][0] != raw:
                raise ValueError("cùng sha256 nhưng khác byte")
            self.by_sha[digest] = (raw, manifest)
            self.by_capability[(manifest["spec"]["capability"], manifest["metadata"]["name"])] = digest
        for version, snapshot in context["policy_snapshots"].items():
            problems = list(SNAPSHOT_VALIDATOR.iter_errors(snapshot))
            if problems:
                raise ValueError(f"policy snapshot {version} không hợp lệ: {problems[0].message}")

    # -- read side -----------------------------------------------------------
    def describe(self, capability: str, provider: str | None = None) -> dict:
        digest = self.by_capability.get((capability, provider)) if provider else None
        if digest is None:
            matches = [sha for (cap, _), sha in self.by_capability.items()
                       if cap == capability and (provider is None or self.by_sha[sha][1]["metadata"]["name"] == provider)]
            if not matches:
                raise _deny(f"capability {capability} chưa được đăng ký", "/capability")
            if len(matches) > 1:
                raise _deny(f"capability {capability} có nhiều provider, phải chọn rõ", "/provider")
            digest = matches[0]
        return copy.deepcopy(self.by_sha[digest][1])

    def manifest_for(self, task: dict) -> dict:
        entry = self.by_sha.get(task.get("manifest_sha256", ""))
        if entry is None:
            raise ContractError("DEPENDENCY_MISSING", "ESCALATE",
                                "manifest đã pin không còn trong registry (không dùng latest)", "/manifest_sha256")
        raw, manifest = entry
        mismatches = CHECK_MANIFEST_BINDING(task, raw)
        if mismatches:
            raise _deny("; ".join(mismatches), "/manifest_sha256")
        if manifest["spec"]["capability"] != task["capability"]:
            raise _deny("manifest đã pin không phục vụ capability này", "/capability")
        return manifest

    def input_validator(self, manifest: dict) -> Draft202012Validator:
        match = re.fullmatch(r"schema://([a-z0-9-]+)/([a-z0-9-]+)/v(\d+)",
                             manifest["spec"]["inputSchemaRef"])
        relpath = f"capabilities/{match[1]}/{match[2]}.v{match[3]}.schema.json"
        if relpath not in _SCHEMAS:
            raise ContractError("DEPENDENCY_MISSING", "ESCALATE",
                                f"inputSchemaRef trỏ tới schema không có: {relpath}", "/inputSchemaRef")
        return validator(relpath)

    def merged_input(self, manifest: dict, task_input: dict) -> dict:
        defaults = manifest["spec"].get("inputDefaults", {}) or {}
        return {**copy.deepcopy(defaults), **copy.deepcopy(task_input)}

    # -- policy --------------------------------------------------------------
    def resolve_targets(self, merged: dict, task: dict) -> list[dict]:
        context = self.context
        refs, kinds = [], []
        for index, value in enumerate(merged.get("targets", [])):
            seed_hits = [s for s in context["seeds"] if self._matches_seed(value, s)]
            asset_key = canonical_key(value)
            if len(seed_hits) > 1:
                raise _invalid(f"target {value} khớp nhiều seed", f"/input/targets/{index}")
            if seed_hits:
                seed = seed_hits[0]
                if seed["scope_id"] != task["scope_id"]:
                    raise _deny(f"seed {value} không thuộc scope của job", f"/input/targets/{index}")
                refs.append({"seed_id": seed["target_id"]})
                kinds.append(seed["kind"])
                continue
            if asset_key in context["assets"]:
                refs.append({"canonical_key": asset_key})
                kinds.append(kind_for_key(asset_key))
                continue
            raise _invalid(f"target {value} không khớp seed campaign hay asset đã biết",
                           f"/input/targets/{index}")
        return list(zip(refs, kinds))

    @staticmethod
    def _matches_seed(value: str, seed: dict) -> bool:
        text = value.lower().rstrip(".")
        candidate = text[4:] if text.startswith("dns:") else text
        raw = (seed["raw_value"] or "").lower().rstrip(".")
        key = (seed["canonical_key"] or "").lower()
        return candidate == raw or ("dns:" + candidate) == key

    def check_task(self, task: dict) -> dict:
        """Raise ContractError on the first refusal; return the merged input when acceptable."""
        problems = sorted(TASK_VALIDATOR.iter_errors(task), key=str)
        if problems:
            problem = problems[0]
            raise _invalid(f"ApprovedTask không hợp lệ: {problem.message}",
                           "/" + "/".join(str(p) for p in problem.absolute_path))
        manifest = self.manifest_for(task)
        if task["policy_version"] not in self.context["policy_snapshots"]:
            raise _deny("policy_version chưa có snapshot trong campaign", "/policy_version")
        merged = self.merged_input(manifest, task["input"])
        input_problems = sorted(self.input_validator(manifest).iter_errors(merged), key=str)
        if input_problems:
            problem = input_problems[0]
            raise _invalid(f"input không hợp lệ: {problem.message}",
                           "/input/" + "/".join(str(p) for p in problem.absolute_path))
        for default_field in (manifest["spec"].get("inputDefaults") or {}):
            if default_field not in task["input"]:
                raise _deny(f"M05 chưa ghép inputDefaults ({default_field}) vào ApprovedTask",
                            f"/input/{default_field}")

        resolved = self.resolve_targets(merged, task)
        seeds = {seed["target_id"]: seed for seed in self.context["seeds"]}
        accepted = set(manifest["spec"].get("acceptsTargetKinds", []))
        for ref in task["targets"]:
            if "seed_id" in ref:
                seed = seeds.get(ref["seed_id"])
                if seed is None:
                    raise _deny("task.targets tham chiếu seed không thuộc campaign", "/targets")
                kind = seed["kind"]
            else:
                kind = kind_for_key(ref["canonical_key"])
            if accepted and kind not in accepted:
                raise _deny(f"provider không nhận target kind {kind}", "/targets")
        if [ref for ref, _ in resolved] != task["targets"]:
            raise _deny("task.targets không khớp phân giải input.targets (giữ seed, không mở rộng)",
                        "/targets")
        permissions = manifest["spec"]["permissions"]
        needs_network = bool(merged.get("sources")) or bool(merged.get("resolvers"))
        if needs_network and permissions.get("networkAccess") != "egress":
            raise _deny("input cần mạng nhưng manifest đã pin không khai báo egress",
                        "/input")
        declared = permissions.get("egressSources") or []
        if merged.get("sources"):
            unknown = sorted(set(merged["sources"]) - {source["id"] for source in declared})
            if unknown:
                raise _deny(f"nguồn {unknown} không nằm trong egressSources của manifest đã pin",
                            "/input/sources")
        if merged.get("resolvers"):
            allowed = {host for source in declared if source.get("protocol") == "dns"
                       for host in source.get("hosts") or []}
            unknown = sorted(set(merged["resolvers"]) - allowed)
            if unknown:
                raise _deny(f"resolver {unknown} không nằm trong nguồn dns của manifest đã pin "
                            "(C05 egressSources là tập duy nhất)", "/input/resolvers")
        if permissions.get("credentials"):
            raise ContractError("TOOL_UNAVAILABLE", "CHECK_PROVIDER",
                                "manifest cần credential vận hành mà harness không cấp", "/permissions")
        cap = manifest["spec"]["budget"]["maxConcurrency"]
        if merged.get("concurrency", 0) > cap:
            raise _deny(f"concurrency {merged['concurrency']} vượt trần manifest {cap}", "/input/concurrency")
        if "rate_limit" in merged:
            rate_caps = (self.context["policy_snapshots"][task["policy_version"]]
                         .get("rate_limits") or {}).get("requests_per_second_per_host")
            if rate_caps is None:
                raise _deny("snapshot campaign không khai báo trần rate, không thể cưỡng chế",
                            "/input/rate_limit")
            if merged["rate_limit"] > rate_caps:
                raise _deny(f"rate_limit {merged['rate_limit']} vượt trần campaign {rate_caps}",
                            "/input/rate_limit")
        return merged


# ---------------------------------------------------------------------------
# Fixture parsers: pure functions over the container output, no clock, no env.
# They are the reference shape for `adapters/<module>/<tool>/parser.py`, not that code.
# ---------------------------------------------------------------------------
def _ndjson(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _evidence_ref(name: str = "raw") -> list[dict]:
    return [{"local_ref": name}]


def parse_subfinder(output_dir: Path, task: dict, evidence: list[dict]) -> dict:
    targets = sorted({domain_key(t) for t in task["input"]["targets"]})
    assets, observations, relationships, seen = [], [], [], []
    for record in _ndjson(output_dir / "result.jsonl"):
        host = str(record["host"]).lower().rstrip(".")
        key = "dns:" + host
        if key in targets or key in seen:
            continue  # discovering the seed back is not a new asset
        seen.append(key)
        aliases = []
        try:
            decoded = host.encode("ascii").decode("idna")
        except UnicodeError:
            decoded = host
        if decoded != host:
            aliases = [{"namespace": "original", "value": decoded}]
        asset = {"kind": "domain", "canonical_key": key, "discovered_from": targets,
                 "confidence": 0.7, "evidence_refs": _evidence_ref()}
        if aliases:
            asset["aliases"] = aliases
        assets.append(asset)
        observations.append({"subject": key, "predicate": "asset.seen", "value": True,
                             "confidence": 0.7, "evidence_refs": _evidence_ref()})
        for parent in targets:
            relationships.append({"type": "SUBDOMAIN_OF", "from": key, "to": parent,
                                  "confidence": 1.0, "evidence_refs": _evidence_ref()})
    return {"assets": assets, "observations": observations, "relationships": relationships,
            "findings": [], "coverage_subjects": targets}


def parse_dnsx(output_dir: Path, task: dict, evidence: list[dict]) -> dict:
    targets = sorted({domain_key(t) for t in task["input"]["targets"]})
    assets, records, resolutions, resolved_hosts = [], [], [], []
    seen_ips: dict[str, dict] = {}
    for record in _ndjson(output_dir / "result.jsonl"):
        host_key = domain_key(str(record["host"]))
        resolved_hosts.append(host_key)
        for field, rtype in (("a", "A"), ("aaaa", "AAAA")):
            for value in record.get(field, []) or []:
                ip_key = "ip:" + str(ipaddress.ip_address(value))
                records.append({"subject": host_key, "predicate": "dns.record",
                                "value": {"type": rtype, "value": ip_key[3:], "ttl": record.get("ttl")},
                                "confidence": 1.0, "evidence_refs": _evidence_ref()})
                resolutions.append({"type": "RESOLVES_TO", "from": host_key, "to": ip_key,
                                    "confidence": 1.0, "evidence_refs": _evidence_ref()})
                if ip_key not in seen_ips:
                    seen_ips[ip_key] = {"kind": "ip", "canonical_key": ip_key,
                                        "discovered_from": [host_key], "confidence": 1.0,
                                        "evidence_refs": _evidence_ref()}
    assets = list(seen_ips.values())
    observations = list(records)
    for host_key in dict.fromkeys(resolved_hosts):
        observations.append({"subject": host_key, "predicate": "dns.resolves", "value": True,
                             "confidence": 1.0, "evidence_refs": _evidence_ref()})
    for key in seen_ips:
        observations.append({"subject": key, "predicate": "asset.seen", "value": True,
                             "confidence": 1.0, "evidence_refs": _evidence_ref()})
    return {"assets": assets, "observations": observations, "relationships": resolutions,
            "findings": [], "coverage_subjects": targets}


PARSERS = {"subfinder": parse_subfinder, "dnsx": parse_dnsx}


def _capability_properties(manifest: dict) -> dict:
    """The pinned capability input schema's properties (the one place a field's cap is declared)."""
    match = re.fullmatch(r"schema://([a-z0-9-]+)/([a-z0-9-]+)/v(\d+)",
                         str(manifest["spec"]["inputSchemaRef"]))
    if match is None:
        return {}
    relpath = f"capabilities/{match[1]}/{match[2]}.v{match[3]}.schema.json"
    document = _SCHEMAS.get(relpath) or {}
    properties = document.get("properties")
    return properties if isinstance(properties, dict) else {}


def _trace(task: dict, manifest: dict, job_id: str) -> dict:
    trace = {"trace_id": task["trace"]["trace_id"]}
    trace.update({"campaign_id": task["campaign_id"], "job_id": job_id,
                  "capability_id": task["capability"],
                  "provider_version": manifest["spec"]["providerVersion"],
                  "policy_version": task["policy_version"]})
    return trace


def build_envelope(task: dict, manifest: dict, scenario: dict, parsed: dict,
                   evidence: list[dict], event_id: str, merged_input: dict) -> dict:
    """Collector output: raw evidence + parsed results + task pins. Pure apart from the passed snapshot."""
    observations, relationships = [], []
    for observation in parsed["observations"]:
        item = dict(observation)
        item.setdefault("observed_at", scenario["finished_at"])
        observations.append(item)
    for relationship in parsed["relationships"]:
        item = dict(relationship)
        item.setdefault("observed_at", scenario["finished_at"])
        relationships.append(item)
    return {
        "schema_version": "2.0",
        "event_id": event_id,
        "dedup_key": f"job:{scenario['job_id']}:envelope",
        "job_id": scenario["job_id"],
        "campaign_id": task["campaign_id"],
        "scope_id": task["scope_id"],
        "capability": task["capability"],
        "provider": {
            "name": manifest["metadata"]["name"],
            "version": manifest["spec"]["providerVersion"],
            "adapter_version": manifest["metadata"]["version"],
            "image_digest": manifest["spec"]["runtime"]["imageDigest"],
        },
        "policy_version": task["policy_version"],
        "status": "succeeded",
        "coverage": {"subjects": sorted(set(parsed["coverage_subjects"])), "complete": True},
        "results": {"assets": parsed["assets"], "observations": observations,
                    "relationships": relationships, "findings": parsed["findings"]},
        "evidence": evidence,
        "errors": [],
        "provenance": {
            "input_fingerprint": CANON["sha256_hex"](merged_input),
            "started_at": scenario["started_at"],
            "finished_at": scenario["finished_at"],
            "seed_targets": copy.deepcopy(task["targets"]),
            "exit_code": 0,
        },
        "trace": _trace(task, manifest, scenario["job_id"]),
    }


class FixtureAdapter:
    """The seven adapter handlers over fixture files. A real adapter must satisfy the same checks."""

    def __init__(self, registry: Registry, scenario: dict, audit: Audit, parser=None):
        self.registry = registry
        self.scenario = scenario
        self.audit = audit
        self.manifest_raw = registry.by_sha[self._scenario_sha()][0]
        self.manifest = registry.by_sha[self._scenario_sha()][1]
        # `parser` is the real adapter entrypoint (`adapters.<module>.<tool>:<func>`, G1.3b); the
        # reference parser below is the fallback for the contract suite. Everything else - the
        # pins, the policy checks and the envelope comparison - stays the same for both.
        self.parser = parser or PARSERS[scenario["provider"]]
        self.handles: dict[str, dict] = {}
        self.calls = {"describe": 0, "validate": 0, "start": 0, "status": 0,
                      "cancel": 0, "collect": 0, "health": 0}

    def _scenario_sha(self) -> str:
        for sha, (_, manifest) in self.registry.by_sha.items():
            if manifest["metadata"]["name"] == self.scenario["provider"]:
                return sha
        raise KeyError(self.scenario["provider"])

    # -- handlers ------------------------------------------------------------
    def describe(self) -> dict:
        self.calls["describe"] += 1
        return copy.deepcopy(self.manifest)

    def validate(self, task: dict) -> dict:
        self.calls["validate"] += 1
        merged = self.registry.check_task(task)
        return {"valid": True, "input": merged}

    def start(self, task: dict, key: str) -> dict:
        self.calls["start"] += 1
        self.registry.check_task(task)  # pin/policy re-check before any side effect
        if key in self.handles:
            return self.handles[key]
        output_dir = Path(tempfile.mkdtemp(prefix=f"aegis-{self.scenario['provider']}-"))
        source = ROOT / self.scenario["raw"] / self.scenario["raw_file"]
        target = output_dir / self.scenario["raw_file"]
        target.write_bytes(source.read_bytes())
        self.audit.write(target)
        handle = {"job_id": self.scenario["job_id"], "key": key, "state": "RUNNING",
                  "output_dir": output_dir, "attempt": 1, "task": copy.deepcopy(task),
                  "campaign_id": task["campaign_id"]}
        self.handles[key] = handle
        self.audit.executions += 1
        return handle

    def status(self, handle: dict) -> dict:
        self.calls["status"] += 1
        terminal = handle["state"] in {"SUCCEEDED", "FAILED", "CANCELLED"}
        return {"job_id": handle["job_id"], "status": handle["state"],
                "retry_after_seconds": 0 if terminal else self.scenario["retry_after_seconds"]}

    def cancel(self, handle: dict) -> dict:
        self.calls["cancel"] += 1
        row = {"job_id": handle["job_id"], "at": self.scenario["finished_at"],
               "requested_by": {"kind": "operator", "id": "fixture-operator"}}
        if handle["state"] in {"SUCCEEDED", "FAILED", "CANCELLED"}:
            row["result"] = "noop-terminal"
        else:
            handle["state"] = "CANCELLED"
            row["result"] = "cancelled"
        self.audit.rows.append(row)
        return {"cancelled": row["result"] == "cancelled", "state": handle["state"]}

    def collect(self, handle: dict, event_id: str | None = None) -> dict:
        self.calls["collect"] += 1
        if handle["state"] == "CANCELLED":
            raise ContractError("EVIDENCE_INCOMPLETE", "REVIEW_QUARANTINE",
                                "job đã huỷ: không dựng envelope từ bằng chứng dở dang", "/status")
        task = handle["task"]
        manifest = self.registry.manifest_for(task)
        evidence = self._evidence(handle)
        parsed = self.parser(handle["output_dir"], task, evidence)
        envelope = build_envelope(task, manifest, self.scenario, parsed, evidence,
                                  event_id or self.scenario["event_id"],
                                  self.registry.merged_input(manifest, task["input"]))
        problems = sorted(ENVELOPE_VALIDATOR.iter_errors(envelope), key=str)
        if problems:
            raise ContractError("OUTPUT_INVALID", "REVIEW_QUARANTINE",
                                f"envelope không hợp lệ: {problems[0].message}")
        handle["state"] = "SUCCEEDED"
        return envelope

    def health(self) -> dict:
        self.calls["health"] += 1
        return {"provider": self.manifest["metadata"]["name"],
                "tool_version": self.manifest["spec"]["providerVersion"],
                "image_digest": self.manifest["spec"]["runtime"]["imageDigest"],
                "dependencies": sorted({"image:" + self.manifest["spec"]["runtime"]["imageDigest"],
                                        *self.scenario.get("dependencies", [])}),
                "status": "ok"}

    # -- internals -----------------------------------------------------------
    def _evidence(self, handle: dict) -> list[dict]:
        path = handle["output_dir"] / self.scenario["raw_file"]
        data = path.read_bytes()
        digest = sha256_bytes(data)
        return [{
            "local_ref": "raw",
            "sha256": digest,
            "uri": f"s3://evidence/{handle['campaign_id']}/{handle['job_id']}/{digest}",
            "size_bytes": len(data),
            "media_type": "application/x-ndjson",
            "classification": "INTERNAL",
            "kind": "raw_output",
        }]

    def parse_twice(self, handle: dict) -> tuple[dict, dict]:
        task = handle["task"]
        evidence = self._evidence(handle)
        return (self.parser(handle["output_dir"], task, evidence),
                self.parser(handle["output_dir"], task, evidence))


# ---------------------------------------------------------------------------
# Suites
# ---------------------------------------------------------------------------
def _equal(name: str, left, right, failures: list[str]) -> None:
    if left != right:
        failures.append(f"{name}: {left!r} != {right!r}")


def _expect_error(name: str, fn, code: str, next_action: str, failures: list[str]) -> ContractError | None:
    try:
        fn()
    except ContractError as exc:
        ERROR_VALIDATOR.validate(exc.as_error())
        if (exc.code, exc.next_action) != (code, next_action):
            failures.append(f"{name}: ({exc.code},{exc.next_action}) != ({code},{next_action})")
        return exc
    failures.append(f"{name}: không bị từ chối như mong đợi")
    return None


def run_provider_suite(provider: str, context: dict, parser=None) -> tuple[list[str], int]:
    """Run the seven-handler suite; `parser` replaces the reference parser (a real adapter)."""
    scenario = load(CONF / "fixtures" / f"{provider}.json")
    task = load(ROOT / scenario["task"])
    envelope_fixture = load(ROOT / scenario["envelope"])
    audit = Audit()
    registry = Registry([(ROOT / scenario["manifest"]).read_bytes()], context)
    adapter = FixtureAdapter(registry, scenario, audit, parser=parser)
    failures: list[str] = []
    checks = 0

    def check(name: str, fn):
        nonlocal checks
        checks += 1
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - a failing check is data, not a crash
            failures.append(f"{provider}/{name}: {exc.__class__.__name__}: {exc}")

    # 1. describe: immutable manifest, no side effect
    def describe_no_side_effect():
        writes, network, executions = len(audit.writes), len(audit.network), audit.executions
        first, second = adapter.describe(), adapter.describe()
        _equal("describe idempotent", first, second, failures)
        _equal("describe bytes", sha256_bytes(adapter.manifest_raw), task["manifest_sha256"], failures)
        _equal("describe không ghi file", len(audit.writes), writes, failures)
        _equal("describe không mở mạng", len(audit.network), network, failures)
        _equal("describe không chạy job", audit.executions, executions, failures)
        _equal("describe provider", first["metadata"]["name"], task["provider"], failures)
        _equal("describe pin provider_version", first["spec"]["providerVersion"],
               task["provider_version"], failures)
        _equal("describe pin image", first["spec"]["runtime"]["imageDigest"],
               task["image_digest"], failures)
    check("describe", describe_no_side_effect)

    # 2. validate: rejects bad/over-cap input before any execution
    def validate_before_execution():
        result = adapter.validate(task)
        _equal("validate merged input", result["input"], registry.merged_input(adapter.manifest, task["input"]), failures)
        # A capability only has a concurrency cap when its input declares the field (the two DNS
        # capabilities do). A target-bound capability is capped by its port set instead, so the
        # negative case there is input the pinned schema refuses.
        properties = _capability_properties(adapter.manifest)
        if "concurrency" in properties:
            over_cap = adapter.manifest["spec"]["budget"]["maxConcurrency"] + 1
            _expect_error(f"{provider}/validate over-cap",
                          lambda: adapter.validate(dict(copy.deepcopy(task),
                                                        input={**task["input"], "concurrency": over_cap})),
                          "POLICY_DENIED", "FIX_INPUT", failures)
        elif "ports" in properties:
            _expect_error(f"{provider}/validate empty ports",
                          lambda: adapter.validate(dict(copy.deepcopy(task),
                                                        input={**task["input"], "ports": []})),
                          "INPUT_INVALID", "FIX_INPUT", failures)
        if provider == "dnsx":
            _expect_error(f"{provider}/validate schema",
                          lambda: adapter.validate(dict(copy.deepcopy(task),
                                                        input={**task["input"], "targets": ["10.20.0.0/24"]})),
                          "INPUT_INVALID", "FIX_INPUT", failures)
        _expect_error(f"{provider}/validate unknown capability",
                      lambda: adapter.validate(dict(copy.deepcopy(task), capability="dns.nope")),
                      "POLICY_DENIED", "FIX_INPUT", failures)
        _equal("validate không chạy OSS", audit.executions, 0, failures)
    check("validate", validate_before_execution)

    # 3./4./5./6. start/status/cancel/collect on one job
    state: dict = {}

    def start_idempotent():
        first = adapter.start(task, task["idempotency_key"])
        second = adapter.start(task, task["idempotency_key"])
        _equal("start cùng key trả cùng handle", first is second, True, failures)
        _equal("start chỉ chạy một lần", audit.executions, 1, failures)
        other = adapter.start(task, "fixture:second-key")
        _equal("start key khác tạo handle mới", other is not first, True, failures)
        _equal("start hai lần chạy", audit.executions, 2, failures)
        state["handle"], state["other"] = first, other
    check("start", start_idempotent)

    def status_retry_after():
        response = adapter.status(state["handle"])
        job_status = set(_SCHEMAS["capability/job.v2.schema.json"]["$defs"]["JobStatus"]["enum"])
        if response["status"] not in job_status:
            failures.append(f"{provider}/status: trạng thái lạ {response['status']}")
        if not isinstance(response.get("retry_after_seconds"), int):
            failures.append(f"{provider}/status: thiếu retry_after_seconds")
        elif response["status"] in {"QUEUED", "VALIDATING", "DISPATCHED", "RUNNING"} and response["retry_after_seconds"] <= 0:
            failures.append(f"{provider}/status: trạng thái chưa terminal phải có retry_after > 0")
    check("status", status_retry_after)

    def cancel_is_audited_and_idempotent():
        result = adapter.cancel(state["other"])
        _equal("cancel dừng job", (result["cancelled"], result["state"]), (True, "CANCELLED"), failures)
        again = adapter.cancel(state["other"])
        _equal("cancel lần hai không đổi", (again["cancelled"], again["state"]), (False, "CANCELLED"), failures)
        if not audit.rows or audit.rows[-1].get("result") not in {"cancelled", "noop-terminal"}:
            failures.append(f"{provider}/cancel: thiếu audit")
        _equal("status sau cancel", adapter.status(state["other"])["retry_after_seconds"], 0, failures)
        _expect_error(f"{provider}/collect sau cancel",
                      lambda: adapter.collect(state["other"]), "EVIDENCE_INCOMPLETE", "REVIEW_QUARANTINE", failures)
    check("cancel", cancel_is_audited_and_idempotent)

    def collect_envelope():
        envelope = adapter.collect(state["handle"])
        _equal("collect == fixture envelope", envelope, envelope_fixture, failures)
        _equal("collect idempotent state", adapter.status(state["handle"])["retry_after_seconds"], 0, failures)
        raw = (ROOT / scenario["raw"] / scenario["raw_file"]).read_bytes()
        _equal("evidence sha256 == raw bytes", envelope["evidence"][0]["sha256"], sha256_bytes(raw), failures)
        _equal("evidence size", envelope["evidence"][0]["size_bytes"], len(raw), failures)
        _equal("coverage", envelope["coverage"]["subjects"], scenario["coverage_subjects"], failures)
        _equal("provenance seed_targets == task.targets", envelope["provenance"]["seed_targets"],
               task["targets"], failures)
        _equal("input_fingerprint == aegis-c14n/1(input)",
               envelope["provenance"]["input_fingerprint"],
               CANON["sha256_hex"](registry.merged_input(adapter.manifest, task["input"])), failures)
        _equal("dedup_key từ job_id", envelope["dedup_key"], f"job:{scenario['job_id']}:envelope", failures)
        state["envelope"] = envelope
    check("collect", collect_envelope)

    def parser_deterministic_and_replayable():
        _, fresh = adapter.parse_twice(state["handle"])
        _equal("parser chạy hai lần", fresh, adapter.parser(
            state["handle"]["output_dir"], task, adapter._evidence(state["handle"])), failures)
        first_hash = CANON["payload_hash"](state["envelope"])
        replay = adapter.collect(state["handle"], event_id="01934f6a-0000-7000-8000-00000000ff01")
        _equal("payload_hash bỏ event_id (C03)", CANON["payload_hash"](replay), first_hash, failures)
        _equal("event_id mới mỗi lần nộp", replay["event_id"] != state["envelope"]["event_id"], True, failures)
    check("replay", parser_deterministic_and_replayable)

    def health_reports_pins():
        before = len(audit.writes)
        health = adapter.health()
        _equal("health tool_version", health["tool_version"], task["provider_version"], failures)
        _equal("health image pin", health["image_digest"], task["image_digest"], failures)
        if not health.get("dependencies"):
            failures.append(f"{provider}/health: thiếu danh sách phụ thuộc")
        _equal("health không ghi file", len(audit.writes), before, failures)
    check("health", health_reports_pins)

    def start_refuses_broken_pin():
        tampered = copy.deepcopy(task)
        tampered["image_digest"] = "sha256:" + "0" * 64
        _expect_error(f"{provider}/start pin lệch",
                      lambda: adapter.start(tampered, "fixture:tampered-pin"),
                      "POLICY_DENIED", "FIX_INPUT", failures)
        missing = copy.deepcopy(task)
        missing["manifest_sha256"] = "9" * 64
        _expect_error(f"{provider}/start manifest thiếu",
                      lambda: adapter.start(missing, "fixture:missing-manifest"),
                      "DEPENDENCY_MISSING", "ESCALATE", failures)
    check("pin", start_refuses_broken_pin)

    def no_network_and_writes_confined():
        _equal("không có kết nối mạng", audit.network, [], failures)
        outside = [path for path in audit.writes if not path.startswith(tempfile.gettempdir())]
        _equal("chỉ ghi trong thư mục output tạm", outside, [], failures)
    check("isolation", no_network_and_writes_confined)

    return failures, checks


POLICY_DIR = CONF / "fixtures" / "policy"


def run_policy_suite(context: dict) -> tuple[list[str], int]:
    """Contract-level negatives that must be refused by the registry, not by JSON Schema."""
    failures: list[str] = []
    checks = 0
    manifests = [(ROOT / "fixtures/valid/manifest.subfinder.yaml").read_bytes(),
                 (ROOT / "fixtures/valid/manifest.dnsx.yaml").read_bytes()]
    registry = Registry(manifests, context)
    for path in sorted(POLICY_DIR.glob("*.json")):
        checks += 1
        case = load(path)
        task = dotted_patch(load(ROOT / case["base_task"]), case["patch"])
        expect = case["expect"]
        denied = expect["code"] == "POLICY_DENIED"
        schema_problems = list(TASK_VALIDATOR.iter_errors(task))
        if denied and schema_problems:
            failures.append(f"{path.name}: POLICY_DENIED case phải hợp lệ theo schema, lỗi: "
                            f"{schema_problems[0].message}")
            continue
        try:
            registry.check_task(task)
        except ContractError as exc:
            ERROR_VALIDATOR.validate(exc.as_error())
            if (exc.code, exc.next_action) != (expect["code"], expect["next_action"]):
                failures.append(f"{path.name}: ({exc.code},{exc.next_action}) != "
                                f"({expect['code']},{expect['next_action']})")
        else:
            failures.append(f"{path.name}: không bị từ chối như mong đợi")

    # Cap source is the *pinned manifest*: flipping egress off must deny network-needing input.
    checks += 1
    manifest = yaml.safe_load(manifests[1])
    # egressMode/proxyAware/egressSources/targetBinding only exist with egress; flipping the network off
    # means dropping them, not leaving a manifest the pinned shape rejects.
    manifest["spec"]["permissions"] = {"networkAccess": "none", "rawSocket": False}
    no_egress = Registry([yaml.safe_dump(manifest, sort_keys=False).encode()], context)
    task = load(ROOT / "fixtures/valid/approved-task.dnsx.json")
    task["input"]["resolvers"] = ["10.20.0.53"]  # a declared egress destination
    task["manifest_sha256"] = sha256_bytes(yaml.safe_dump(manifest, sort_keys=False).encode())
    try:
        no_egress.check_task(task)
    except ContractError as exc:
        if (exc.code, exc.next_action) != ("POLICY_DENIED", "FIX_INPUT"):
            failures.append(f"networkAccess=none: ({exc.code},{exc.next_action}) != (POLICY_DENIED,FIX_INPUT)")
    else:
        failures.append("networkAccess=none: input cần mạng vẫn được chấp nhận")

    # Registered DNS manifests must declare the network/credential shape the chain needs.
    checks += 1
    for provider in ("subfinder", "dnsx"):
        deployed = registry.describe(
            {"subfinder": "dns.enumerate_subdomains", "dnsx": "dns.resolve"}[provider], provider)
        permissions = deployed["spec"]["permissions"]
        if permissions.get("networkAccess") != "egress":
            failures.append(f"{provider}: phải khai báo networkAccess=egress")
        if permissions.get("rawSocket"):
            failures.append(f"{provider}: DNS tool không được yêu cầu rawSocket")
        if permissions.get("egressMode") != "broker" or permissions.get("proxyAware") is not True:
            failures.append(f"{provider}: egress phải qua broker và proxy-aware (C05)")
        if not permissions.get("egressSources"):
            failures.append(f"{provider}: chuỗi DNS thụ động phải khai egressSources")
        if permissions.get("credentials"):
            failures.append(f"{provider}: G1 không cấp credential cho chuỗi DNS")
    return failures, checks
