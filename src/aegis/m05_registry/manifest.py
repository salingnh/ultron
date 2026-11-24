"""Manifest admission for M05 (registry side of the immutable pin).

A manifest is admitted only when all of these hold, in this order:

1. it is YAML that parses to an object, with no duplicate keys (a duplicate key is two documents
   pretending to be one, and "last one wins" would silently change what was pinned);
2. it satisfies `capability/provider-manifest.v2.schema.json` **and** the shared semantic formats,
via
   `aegis.validation` (structural rules alone are not enough - the contract says so);
3. every rule the contract states outside JSON Schema, i.e. the ones the conformance reference
   (`contracts/tests/validate_contracts.py::check_manifest`) enforces:
   * `inputSchemaRef` resolves to a capability schema in `contracts/capabilities/`;
   * no argv element invokes a shell; every placeholder is exactly one `${input.<field>}` occupying
     the whole element; the field exists in the input schema and is a number/boolean/enum/fixed
     array
     (a free string like `-rf` must never reach argv);
   * `targetBinding: required` (+ `targetPorts: from_input`) names an integer `ports` field in the
     input schema, so the broker binding can be built from input and not from tool output;
   * no `egressSources` host is in the platform deny set: the deny set wins over provider data.

The SHA-256 is taken over the exact accepted bytes. A record keeps those bytes next to the parsed
document, and `registry` stores them that way, so M06 can re-hash what it fetches.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import yaml

from aegis import validation

__all__ = [
    "ManifestRejected",
    "ManifestRecord",
    "admit_manifest",
    "manifest_sha256",
    "parse_document",
    "schema_reference_path",
]

SCHEMA_REF = "capability/provider-manifest.v2.schema.json"
INPUT_SCHEMA_REF = re.compile(r"^schema://([a-z0-9-]+)/([a-z0-9-]+)/v([0-9]+)$")
PLACEHOLDER = re.compile(r"\$\{([^}]*)\}")
WHOLE_PLACEHOLDER = re.compile(r"\$\{input\.([a-z0-9_]+)\}")
SHELLS = frozenset({"sh", "bash", "ash", "dash", "zsh", "busybox", "ksh", "csh"})
SCALAR_ARGV_TYPES = frozenset({"integer", "number", "boolean"})


class ManifestRejected(ValueError):
    """A manifest the registry must not admit; `reasons` lists every problem found."""

    def __init__(self, reasons: tuple[str, ...]) -> None:
        self.reasons = reasons
        super().__init__("; ".join(reasons))


class _StrictLoader(yaml.SafeLoader):
    """Safe loader that refuses duplicate mapping keys instead of keeping the last value."""


def _construct_mapping(loader: _StrictLoader, node: yaml.MappingNode) -> dict[Any, Any]:
    seen: set[Any] = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=False)
        if key in seen:
            raise ManifestRejected((f"manifest repeats the YAML key {key!r}",))
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=False)


_StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def parse_document(raw: bytes) -> dict[str, Any]:
    """Parse the accepted bytes into the document the registry serves (hash stays over bytes)."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ManifestRejected((f"manifest is not UTF-8: {error}",)) from error
    try:
        document = yaml.load(text, Loader=_StrictLoader)  # noqa: S506 - SafeLoader subclass
    except ManifestRejected:
        raise
    except yaml.YAMLError as error:
        raise ManifestRejected((f"manifest is not valid YAML: {error}",)) from error
    if not isinstance(document, dict):
        raise ManifestRejected(("manifest must be a YAML object",))
    return document


def manifest_sha256(raw: bytes) -> str:
    """SHA-256 of the exact accepted bytes (contracts/tests/manifest_binding.py does the same)."""
    return hashlib.sha256(raw).hexdigest()


def schema_reference_path(reference: str) -> str | None:
    """Map `schema://dns/enumerate-subdomains/v2` to its contracts/ path."""
    match = INPUT_SCHEMA_REF.fullmatch(reference)
    if match is None:
        return None
    group, name, version = match.groups()
    return f"capabilities/{group}/{name}.v{version}.schema.json"


def _argv_eligible(prop: Mapping[str, Any] | None) -> bool:
    if not isinstance(prop, Mapping) or "$ref" in prop:
        return False
    kind = prop.get("type")
    if kind in SCALAR_ARGV_TYPES:
        return True
    if kind == "string":
        enum = prop.get("enum")
        return isinstance(enum, list) and len(enum) > 0
    if kind == "array":
        items = prop.get("items")
        return _argv_eligible(items if isinstance(items, Mapping) else None)
    return False


def _input_schema_properties(spec: Mapping[str, Any], reasons: list[str]) -> Mapping[str, Any]:
    reference = spec.get("inputSchemaRef")
    path = schema_reference_path(str(reference or ""))
    if path is None:
        reasons.append(f"inputSchemaRef {reference!r} is not 'schema://<group>/<name>/v<n>'")
        return {}
    document = validation.schemas().get(path)
    if document is None:
        reasons.append(f"inputSchemaRef {reference} does not resolve to contracts/{path}")
        return {}
    properties = document.get("properties")
    return properties if isinstance(properties, Mapping) else {}


def _check_args(spec: Mapping[str, Any], properties: Mapping[str, Any], reasons: list[str]) -> None:
    runtime = spec.get("runtime") or {}
    args = runtime.get("argsTemplate") or []
    if args and str(args[0]).rsplit("/", 1)[-1] in SHELLS:
        reasons.append("argsTemplate must not invoke a shell")
    for element in args:
        text = str(element)
        placeholders = PLACEHOLDER.findall(text)
        if len(placeholders) > 1:
            reasons.append(f"argv element {text!r} carries {len(placeholders)} placeholders")
            continue
        if not placeholders:
            continue
        match = WHOLE_PLACEHOLDER.fullmatch(text)
        if match is None:
            reasons.append(
                f"placeholder in {text!r} must occupy the whole element as ${{input.<field>}}"
            )
            continue
        field_name = match.group(1)
        prop = properties.get(field_name)
        if prop is None:
            reasons.append(f"placeholder input.{field_name} is not in the input schema")
        elif not _argv_eligible(prop):
            reasons.append(
                f"input.{field_name} may not be rendered into argv (only number/boolean/enum/"
                "array-of-those; a free string could become a flag)"
            )


def _check_permissions(
    spec: Mapping[str, Any], properties: Mapping[str, Any], reasons: list[str]
) -> None:
    permissions = spec.get("permissions") or {}
    for source in permissions.get("egressSources") or []:
        for host in source.get("hosts") or []:
            if validation.denied_egress_host(str(host)):
                reasons.append(
                    f"egressSources {source.get('id')!r} declares host {host!r}, which is in the "
                    "platform deny set (the deny set wins over egressSources)"
                )
    if permissions.get("targetBinding") == "required":
        ports = properties.get("ports")
        if not isinstance(ports, Mapping) or ports.get("type") != "array":
            reasons.append(
                "targetBinding=required needs an integer array field 'ports' in the input schema "
                "(targetPorts: from_input); the binding is built from input, never from output"
            )
        else:
            items = ports.get("items")
            if not isinstance(items, Mapping) or items.get("type") not in {"integer", "number"}:
                reasons.append("input.ports must be an array of integers to become target ports")


@dataclass(frozen=True, slots=True)
class ManifestRecord:
    """One accepted manifest: exact bytes, parsed document, and the pins a job copies."""

    sha256: str
    raw: bytes
    document: Mapping[str, Any]

    @property
    def capability(self) -> str:
        return str(self.document["spec"]["capability"])

    @property
    def provider(self) -> str:
        return str(self.document["metadata"]["name"])

    @property
    def provider_version(self) -> str:
        return str(self.document["spec"]["providerVersion"])

    @property
    def adapter_version(self) -> str:
        return str(self.document["metadata"]["version"])

    @property
    def image_digest(self) -> str:
        return str(self.document["spec"]["runtime"]["imageDigest"])

    @property
    def input_schema_ref(self) -> str:
        return str(self.document["spec"]["inputSchemaRef"])

    @property
    def spec(self) -> Mapping[str, Any]:
        spec = self.document.get("spec")
        if not isinstance(spec, Mapping):
            raise ManifestRejected(("manifest has no spec object",))
        return spec

    @property
    def permissions(self) -> Mapping[str, Any]:
        permissions = self.spec.get("permissions")
        return permissions if isinstance(permissions, Mapping) else {}

    @property
    def input_schema(self) -> dict[str, Any]:
        path = schema_reference_path(self.input_schema_ref)
        if path is None or path not in validation.schemas():
            raise ManifestRejected(
                (f"inputSchemaRef {self.input_schema_ref} does not resolve to contracts/{path}",)
            )
        return validation.schemas()[path]

    def pins(self) -> dict[str, str]:
        """The fields an ApprovedTask copies and M06 re-checks (interfaces §Manifest bất biến)."""
        return {
            "provider": self.provider,
            "provider_version": self.provider_version,
            "adapter_version": self.adapter_version,
            "image_digest": self.image_digest,
            "manifest_sha256": self.sha256,
            "capability": self.capability,
        }


def admit_manifest(raw: bytes) -> ManifestRecord:
    """Admit exact manifest bytes or raise `ManifestRejected` with every reason found."""
    if not raw:
        raise ManifestRejected(("manifest is empty",))
    document = parse_document(raw)
    reasons: list[str] = []
    try:
        validation.validate(SCHEMA_REF, document)
    except validation.ContractViolation as error:
        reasons.extend(error.errors)
    spec = document.get("spec")
    if isinstance(spec, Mapping):
        properties = _input_schema_properties(spec, reasons)
        if properties:
            _check_args(spec, properties, reasons)
        _check_permissions(spec, properties, reasons)
    if reasons:
        raise ManifestRejected(tuple(reasons))
    return ManifestRecord(sha256=manifest_sha256(raw), raw=raw, document=document)
