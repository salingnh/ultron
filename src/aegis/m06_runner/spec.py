"""Build the `ContainerSpec` of a job from its approved task and pinned manifest (M06).

Four rules live here, all of them "check before the container exists":

* **argv rendering (OI-12).** A template element is a literal or exactly one
  `${input.<field>}` occupying the whole element. Only integer/number/boolean values, strings with
  a fixed `enum`, and arrays of those may be inserted; arrays become one argv element per item in
  input order. A rendered value can never start with `-`, so a value can never become a flag. A
  template that breaks the rule is `POLICY_DENIED`; the argv is never "fixed up".
* **target binding (P3c).** `input.targets` must resolve onto the task's `targets`; a job that
  widened or dropped targets is refused before a container exists. M06 cannot resolve `seed_id`
  without the campaign tables, so the check is exact on what it can see: the input has one entry
  per ref, no duplicates, every input value that projects to a canonical key is one of the task's
  `{canonical_key}` refs, and everything unmatched is covered by a `{seed_id}` ref.
* **pinned identity (interfaces §2).** capability, provider, provider version, adapter version,
  image digest and - when the manifest bytes are supplied - the manifest SHA-256 must equal the
  task's pins.
* **egress binding (E-1).** M06 recomputes the effective binding from the task's canonical-key
  targets plus the manifest's `egressSources`, drops the platform deny set and refuses a declared
  source that hits it. `ApprovedTask` carries no binding field, so this recomputation is the M06
  side of E-1; seed targets contribute nothing (fail closed) and are called out in the report.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from aegis import validation
from aegis.common.ports import ContainerSpec
from aegis.common.repo import repository_root
from aegis.contracts_gen.capability.approved_task_v2_schema import ApprovedTask
from aegis.contracts_gen.capability.provider_manifest_v2_schema import ProviderManifest
from aegis.m06_runner import denyset, netpolicy
from aegis.m06_runner.values import text

MIB = 1048576
DEFAULT_MAX_OUTPUT_MB = 256
PLACEHOLDER = re.compile(r"^\$\{input\.([A-Za-z_][A-Za-z0-9_]*)\}$")
SCHEMA_REF = re.compile(
    r"^schema://(?P<group>[a-z0-9-]+)/(?P<name>[a-z0-9-]+)/v(?P<version>[0-9]+)$"
)
DOMAIN_TARGET = "aegis-domain-target"
CANONICAL_KEY_PREFIXES = ("dns:", "ip:", "service:", "app:", "url:")


class SpecError(RuntimeError):
    """The job cannot be turned into a sandbox spec; `code` is the contract error code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


# --- input schema ---------------------------------------------------------------------------


def input_schema_path(reference: str) -> Path:
    match = SCHEMA_REF.fullmatch(reference)
    if match is None:
        raise SpecError(
            "DEPENDENCY_MISSING", f"inputSchemaRef is not a schema:// reference: {reference!r}"
        )
    name = f"{match.group('name')}.v{match.group('version')}.schema.json"
    return repository_root() / "contracts" / "capabilities" / match.group("group") / name


def load_input_schema(reference: str) -> dict[str, Any]:
    path = input_schema_path(reference)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SpecError("DEPENDENCY_MISSING", f"cannot read {path}: {error}") from error
    if not isinstance(document, dict):
        raise SpecError("DEPENDENCY_MISSING", f"{path} is not a JSON Schema object")
    return document


def _resolve_local(schema: dict[str, Any], node: Any) -> dict[str, Any]:
    """Follow a local `#/$defs/...` reference; refuse anything else (fail closed)."""
    seen = 0
    while isinstance(node, dict) and "$ref" in node:
        reference = str(node["$ref"])
        if not reference.startswith("#/"):
            raise SpecError(
                "POLICY_DENIED",
                f"argsTemplate value has an unresolvable schema reference {reference!r}",
            )
        target: Any = schema
        for part in reference[2:].split("/"):
            if not isinstance(target, dict) or part not in target:
                raise SpecError(
                    "POLICY_DENIED", f"argsTemplate value reference {reference!r} is missing"
                )
            target = target[part]
        node = target
        seen += 1
        if seen > 16:
            raise SpecError(
                "POLICY_DENIED", f"argsTemplate value reference {reference!r} is cyclic"
            )
    if not isinstance(node, dict):
        raise SpecError("POLICY_DENIED", "argsTemplate value schema is not an object")
    return node


# --- argv rendering (OI-12) -----------------------------------------------------------------


def _scalar_text(value: object, schema: dict[str, Any], field: str) -> str:
    kind = schema.get("type")
    if isinstance(value, bool):
        if kind != "boolean":
            raise SpecError(
                "POLICY_DENIED", f"input.{field}: boolean does not fit schema type {kind}"
            )
        return "true" if value else "false"
    if isinstance(value, int) and kind in {"integer", "number"}:
        return str(value)
    if isinstance(value, float) and kind in {"number", "integer"}:
        if kind == "integer":
            raise SpecError("POLICY_DENIED", f"input.{field}: {value!r} is not an integer")
        return str(int(value)) if value.is_integer() else repr(value)
    if isinstance(value, str) and kind == "string":
        allowed = schema.get("enum")
        if not isinstance(allowed, list) or value not in allowed:
            raise SpecError("POLICY_DENIED", f"input.{field}: free-form strings cannot be rendered")
        return value
    raise SpecError(
        "POLICY_DENIED",
        f"input.{field}: {type(value).__name__} cannot be rendered into argv "
        "(only numbers, booleans, enum strings and arrays of those)",
    )


def _array_texts(value: object, schema: dict[str, Any], field: str) -> list[str]:
    if not isinstance(value, list):
        raise SpecError("POLICY_DENIED", f"input.{field}: expected an array")
    items = schema.get("items")
    if not isinstance(items, dict):
        raise SpecError("POLICY_DENIED", f"input.{field}: array items schema is missing")
    item_schema = _resolve_local_items(items)
    return [_scalar_text(item, item_schema, field) for item in value]


def _resolve_local_items(items: dict[str, Any]) -> dict[str, Any]:
    if "$ref" in items:
        raise SpecError(
            "POLICY_DENIED",
            "array items with a $ref cannot be rendered; use a scalar type or enum items",
        )
    return items


def render_args(
    template: Sequence[str],
    input_values: Mapping[str, Any],
    schema: dict[str, Any],
) -> list[str]:
    """Render `runtime.argsTemplate` into the container argv under the OI-12 rule."""
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise SpecError("POLICY_DENIED", "input schema has no properties")
    argv: list[str] = []
    for element in template:
        if "${" not in element:
            argv.append(element)
            continue
        match = PLACEHOLDER.fullmatch(element)
        if match is None:
            raise SpecError(
                "POLICY_DENIED",
                f"argsTemplate element {element!r} is not a literal or exactly one "
                "${input.<field>} placeholder",
            )
        field = match.group(1)
        if field not in properties:
            raise SpecError("POLICY_DENIED", f"argsTemplate names unknown input field {field!r}")
        if field not in input_values:
            raise SpecError("POLICY_DENIED", f"argsTemplate needs input.{field}, which is missing")
        field_schema = _resolve_local(schema, properties[field])
        value = input_values[field]
        rendered = (
            _array_texts(value, field_schema, field)
            if field_schema.get("type") == "array"
            else [_scalar_text(value, field_schema, field)]
        )
        for rendered_element in rendered:
            if rendered_element.startswith("-"):
                raise SpecError(
                    "POLICY_DENIED",
                    f"input.{field} renders to {rendered_element!r}, which would become a flag",
                )
        argv.extend(rendered)
    return argv


# --- target binding (P3c) -------------------------------------------------------------------


def _canonical_refs(task: ApprovedTask) -> tuple[set[str], int]:
    canonical: set[str] = set()
    seeds = 0
    for reference in task.targets:
        branch = reference.root
        canonical_key = getattr(branch, "canonical_key", None)
        if canonical_key is not None:
            canonical.add(text(canonical_key))
        else:
            seeds += 1
    return canonical, seeds


def project_target(value: str) -> str:
    """Canonical key a raw input target projects to, when one is derivable.

    Domain tools take `example.com` / `dns:example.com` -> `dns:example.com`; address tools take a
    canonical key directly (`ip:10.0.0.5`, `service:10.0.0.5:443/tcp`), which is already a key.

    `contracts/validation.py::canonical_key` accepts unknown namespaces on purpose (their schema
    branch checks them), so it cannot tell a key from a name; the namespace prefix is checked here
    first.
    """
    checker = validation.format_checker()
    candidate = value.strip()
    if candidate.lower().startswith(CANONICAL_KEY_PREFIXES):
        if checker.conforms(candidate, "aegis-canonical-key"):
            return candidate
        raise SpecError("POLICY_DENIED", f"target {value!r} is not a valid canonical key")
    if not checker.conforms(candidate, DOMAIN_TARGET):
        raise SpecError(
            "POLICY_DENIED",
            f"input.targets entry {value!r} is neither a domain target nor a canonical key",
        )
    lowered = candidate.lower()
    if lowered.endswith("."):
        lowered = lowered[:-1]
    domain = lowered.removeprefix("dns:")
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise SpecError("POLICY_DENIED", f"target {value!r} is not IDNA encodable") from error
    return f"dns:{domain}"


def recheck_targets(task: ApprovedTask, input_values: Mapping[str, Any]) -> None:
    """Refuse a job whose `input.targets` diverges from the task's resolved `targets` (P3c)."""
    raw = input_values.get("targets")
    if raw is None:
        return
    if not isinstance(raw, list) or not raw or not all(isinstance(item, str) for item in raw):
        raise SpecError("POLICY_DENIED", "input.targets must be a non-empty array of strings")
    if len(set(raw)) != len(raw):
        raise SpecError("POLICY_DENIED", "input.targets contains duplicates")
    projections = [project_target(value) for value in raw]
    canonical, seeds = _canonical_refs(task)
    if len(projections) != len(task.targets):
        raise SpecError(
            "TARGET_REFS_MISMATCH",
            f"input has {len(projections)} targets, task has {len(task.targets)} target refs",
        )
    unmatched = [projection for projection in projections if projection not in canonical]
    if len(unmatched) > seeds:
        raise SpecError(
            "TARGET_REFS_MISMATCH",
            "input targets outside the task's canonical refs and not covered by a seed ref: "
            + ", ".join(sorted(unmatched)),
        )


# --- egress binding (E-1) -------------------------------------------------------------------


def _target_addresses(
    task: ApprovedTask, resolver: netpolicy.Resolver
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for reference in task.targets:
        branch = reference.root
        canonical_key = getattr(branch, "canonical_key", None)
        if canonical_key is None:
            # A seed ref has no address M06 can resolve; the binding stays fail-closed. M05 owns
            # seed resolution (interfaces §2) - see the E-1 proposal in the task report.
            continue
        key = text(canonical_key)
        kind, _, value = key.partition(":")
        if kind == "ip":
            try:
                address = ipaddress.ip_address(value)
            except ValueError as error:
                raise SpecError("POLICY_DENIED", f"target {key!r} is not a valid IP") from error
            denied = denyset.deny_reason(address)
            if denied is not None:
                raise SpecError(
                    "POLICY_DENIED",
                    f"target {key!r} is in the always-deny set ({denied.value})",
                )
            networks.append(ipaddress.ip_network(f"{address}/{address.max_prefixlen}"))
            continue
        if kind == "dns":
            for answer in resolver.resolve(value):
                try:
                    address = ipaddress.ip_address(answer)
                except ValueError:
                    continue
                networks.append(ipaddress.ip_network(f"{address}/{address.max_prefixlen}"))
            continue
        raise SpecError("POLICY_DENIED", f"target kind {kind!r} has no known resolution")
    return networks


def _target_ports(manifest: ProviderManifest, input_values: Mapping[str, Any]) -> tuple[int, ...]:
    permissions = manifest.spec.permissions
    if permissions.targetBinding != "required":
        return ()
    ports = input_values.get("ports")
    if not isinstance(ports, list) or not all(isinstance(port, int) for port in ports):
        raise SpecError(
            "POLICY_DENIED",
            "targetBinding=required and targetPorts=from_input need input.ports "
            "as an integer array",
        )
    for port in ports:
        if not 1 <= port <= 65535:
            raise SpecError("POLICY_DENIED", f"target port {port!r} is out of range")
    return tuple(ports)


def _declared_sources(manifest: ProviderManifest) -> tuple[netpolicy.SourceAllow, ...]:
    declared = manifest.spec.permissions.egressSources or []
    sources: list[netpolicy.SourceAllow] = []
    for source in declared:
        for host in source.hosts:
            value = str(host)
            denied = denyset.denied_host(value)
            if denied is not None:
                # Defence in depth: the registry refuses such a manifest, but a stale entry must
                # not become a connectable source.
                raise SpecError(
                    "POLICY_DENIED",
                    f"egress source {source.id!r} declares a denied destination {value!r} "
                    f"({denied.value})",
                )
        sources.append(
            netpolicy.SourceAllow(
                id=source.id,
                hosts=tuple(denyset.host_key(str(host)) for host in source.hosts),
                ports=tuple(int(text(port)) for port in source.ports),
            )
        )
    return tuple(sources)


def _denylist_networks(denylist: Sequence[str]) -> tuple[Any, ...]:
    networks: list[Any] = []
    for entry in denylist:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            # A denied *name* cannot be turned into a CIDR here; the broker only reaches names
            # that the manifest declared, so the name stays unreachable without a resolution rule.
            continue
    return tuple(networks)


def build_policy(
    task: ApprovedTask,
    manifest: ProviderManifest,
    input_values: Mapping[str, Any],
    *,
    job_id: str,
    platform_cidrs: Sequence[str] = (),
    target_denylist: Sequence[str] = (),
    resolver: netpolicy.Resolver | None = None,
) -> netpolicy.JobEgressPolicy:
    """The policy document of the job: recomputed binding minus the deny set (E-1)."""
    permissions = manifest.spec.permissions
    if permissions.networkAccess != "egress":
        return netpolicy.JobEgressPolicy(job_id=job_id, mode="none")
    sources = _declared_sources(manifest)
    if not sources and permissions.targetBinding != "required":
        raise SpecError(
            "POLICY_DENIED",
            "egress with no declared source and targetBinding=none has no reachable destination",
        )
    active_resolver = resolver or netpolicy.Resolver()
    return netpolicy.JobEgressPolicy(
        job_id=job_id,
        mode="egress",
        target_ips=tuple(_target_addresses(task, active_resolver)),
        target_ports=_target_ports(manifest, input_values),
        sources=sources,
        platform_cidrs=tuple(ipaddress.ip_network(entry) for entry in platform_cidrs),
        deny_cidrs=_denylist_networks(target_denylist),
        resolver=active_resolver,
    )


# --- spec assembly --------------------------------------------------------------------------


def _check_pins(
    task: ApprovedTask, manifest: ProviderManifest, manifest_bytes: bytes | None
) -> None:
    runtime = manifest.spec.runtime
    checks = {
        "capability": (task.capability, manifest.spec.capability),
        "provider": (task.provider, manifest.metadata.name),
        "provider_version": (task.provider_version, manifest.spec.providerVersion),
        "adapter_version": (task.adapter_version, manifest.metadata.version),
        "image_digest": (task.image_digest, runtime.imageDigest),
    }
    for name, (left, right) in checks.items():
        if right is not None and text(left) != text(right):
            raise SpecError(
                "POLICY_DENIED", f"{name} mismatch: task {left!r} != pinned manifest {right!r}"
            )
    if manifest_bytes is not None:
        digest = hashlib.sha256(manifest_bytes).hexdigest()
        if digest != text(task.manifest_sha256):
            raise SpecError(
                "POLICY_DENIED",
                f"manifest_sha256 mismatch: task {task.manifest_sha256} != bytes {digest}",
            )


def build_spec(
    task: ApprovedTask,
    manifest: ProviderManifest,
    input_values: Mapping[str, Any],
    *,
    job_id: str,
    broker_proxy: str | None = None,
    platform_cidrs: Sequence[str] = (),
    target_denylist: Sequence[str] = (),
    manifest_bytes: bytes | None = None,
    resolver: netpolicy.Resolver | None = None,
) -> ContainerSpec:
    """Assemble the sandbox spec of one job, or raise `SpecError` before anything runs."""
    _check_pins(task, manifest, manifest_bytes)
    runtime = manifest.spec.runtime
    if runtime.imageDigest is None:
        raise SpecError("DEPENDENCY_MISSING", "the pinned manifest declares no imageDigest")
    if runtime.argsTemplate is None:
        raise SpecError("DEPENDENCY_MISSING", "the pinned manifest declares no argsTemplate")
    recheck_targets(task, input_values)
    schema = load_input_schema(manifest.spec.inputSchemaRef)
    args = render_args(runtime.argsTemplate, input_values, schema)
    budget = manifest.spec.budget
    permissions = manifest.spec.permissions
    egress = permissions.networkAccess == "egress"
    if egress and str(permissions.egressMode) != "broker":
        raise SpecError(
            "POLICY_DENIED",
            f"G1 only enforces egressMode=broker, manifest declares {permissions.egressMode!r}",
        )
    policy = build_policy(
        task,
        manifest,
        input_values,
        job_id=job_id,
        platform_cidrs=platform_cidrs,
        target_denylist=target_denylist,
        resolver=resolver,
    )
    if egress and broker_proxy is None:
        raise SpecError("POLICY_DENIED", "an egress job needs the broker proxy of its network")
    if permissions.targetBinding == "required" and not policy.target_ips:
        raise SpecError(
            "POLICY_DENIED",
            "targetBinding=required but no task target could be resolved to an address",
        )
    return ContainerSpec(
        job_id=job_id,
        image_digest=text(runtime.imageDigest),
        args=args,
        cpu=float(budget.cpu),
        memory_mb=int(budget.memoryMb),
        timeout_seconds=int(budget.timeoutSeconds),
        max_output_bytes=int(budget.maxOutputMb or DEFAULT_MAX_OUTPUT_MB) * MIB,
        network="exec" if egress else "none",
        egress_mode="broker" if egress else None,
        egress_binding=policy.binding_hosts,
        egress_proxy=broker_proxy if egress else None,
        raw_socket=bool(permissions.rawSocket),
    )
