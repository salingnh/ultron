"""Load the locked contract bundle and build MCP tool schemas from it.

Spike G0.3a. contracts/mcp/README.md fixes the wire contract:

* tool name = capability id,
* ``inputSchema`` = ``capability-request.v2`` with ``properties.input`` replaced by
  the resolved capability input schema,
* ``outputSchema`` = ``capability-response.v2`` (returned in ``structuredContent``).

``$ref`` values in the bundle are relative to each schema's ``$id``.  A client of
``tools/list`` does not have the bundle, so every tool schema is published
*self-contained*: refs are resolved and hoisted into the tool schema's own
``$defs``.  This module is the reference implementation of that step; it is
throwaway spike code, not a product module.
"""

from __future__ import annotations

import copy
import json
import re
from functools import lru_cache
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urldefrag, urljoin

from jsonschema import Draft202012Validator

REPO_ROOT = Path(__file__).resolve().parents[3]
CONTRACTS_DIR = REPO_ROOT / "contracts"

REQUEST_SCHEMA = "mcp/capability-request.v2.schema.json"
RESPONSE_SCHEMA = "mcp/capability-response.v2.schema.json"
ERROR_SCHEMA = "common/error.v2.schema.json"

# Capability id -> schema file relative to contracts/.  The bundle ships exactly
# these three capability inputs (contracts/capabilities/README.md); a tool may
# only be published for a capability with a schema.
CAPABILITY_SCHEMAS = {
    "dns.enumerate_subdomains": "capabilities/dns/enumerate-subdomains.v2.schema.json",
    "dns.resolve": "capabilities/dns/resolve.v2.schema.json",
    "network.discover_services": "capabilities/network/discover-services.v2.schema.json",
}

_DOCUMENTS: dict[str, dict[str, Any]] = {
    document["$id"]: document
    for path in CONTRACTS_DIR.rglob("*.schema.json")
    for document in [json.loads(path.read_text(encoding="utf-8"))]
}


def document(relative_path: str) -> dict[str, Any]:
    """Return a contract schema by its repo-relative path."""
    return _DOCUMENTS[json.loads((CONTRACTS_DIR / relative_path).read_text(encoding="utf-8"))["$id"]]


def schema_uri(relative_path: str) -> str:
    return document(relative_path)["$id"]


@lru_cache(maxsize=1)
def format_checker():
    """The bundle's reference format checker (contracts/validation.py).

    AGENTS.md requires every schema consumer to enable the shared semantic
    formats (``aegis-domain-target`` and friends); re-implementing them in the
    MCP layer would be the second, drifting definition.
    """
    spec = spec_from_file_location("aegis_contract_validation", CONTRACTS_DIR / "validation.py")
    if spec is None or spec.loader is None:  # pragma: no cover - broken checkout
        raise RuntimeError("contracts/validation.py not importable")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.format_checker()


# --------------------------------------------------------------------------- refs


def _absolutize(node: Any, base: str) -> Any:
    """Rewrite every ``$ref`` to an absolute URI and drop per-document ``$id``."""
    if isinstance(node, dict):
        out: dict[str, Any] = {}
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                out[key] = urljoin(base, value)
            elif key in {"$id", "$schema"}:
                continue
            else:
                out[key] = _absolutize(value, base)
        return out
    if isinstance(node, list):
        return [_absolutize(item, base) for item in node]
    return node


def _pointer(document_: dict[str, Any], fragment: str) -> Any:
    value: Any = document_
    for token in (fragment.removeprefix("/").split("/") if fragment.strip("/") else []):
        value = value[token.replace("~1", "/").replace("~0", "~")]
    return value


_SAFE = re.compile(r"[^A-Za-z0-9_.-]+")


def _def_name(uri: str, fragment: str) -> str:
    stem = urldefrag(uri)[0].rsplit("/", 1)[-1].removesuffix(".schema.json")
    tokens = [token for token in fragment.split("/") if token]
    tail = "-".join(tokens[-2:]) if tokens else "root"
    return _SAFE.sub("_", f"{stem}.{tail}")


def _walk_objects(node: Any) -> Iterator[dict[str, Any]]:
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk_objects(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_objects(item)


def bundle(schema: dict[str, Any], base_uri: str) -> dict[str, Any]:
    """Return ``schema`` with every external ``$ref`` inlined under ``$defs``."""
    root = _absolutize(schema, base_uri)
    defs: dict[str, Any] = root.setdefault("$defs", {})
    pending = [root]
    while pending:
        for node in list(_walk_objects(pending.pop())):
            for key, value in list(node.items()):
                if key != "$ref" or not isinstance(value, str):
                    continue
                uri, fragment = urldefrag(value)
                if uri not in _DOCUMENTS:
                    raise ValueError(f"unknown contract document: {uri}")
                name = _def_name(uri, fragment)
                node[key] = f"#/$defs/{name}"
                if name in defs:
                    continue
                target = _pointer(_DOCUMENTS[uri], fragment) if fragment else _DOCUMENTS[uri]
                defs[name] = _absolutize(target, uri)
                pending.append(defs[name])
    return root


def _merge_defs(target: dict[str, Any], other: dict[str, Any]) -> None:
    defs = target.setdefault("$defs", {})
    for name, value in other.items():
        if name in defs:
            if defs[name] != value:
                raise ValueError(f"conflicting $defs entry while bundling: {name}")
            continue
        defs[name] = value


# ------------------------------------------------------------------------ schemas


@lru_cache(maxsize=1)
def request_schema() -> dict[str, Any]:
    rel = REQUEST_SCHEMA
    return bundle(document(rel), schema_uri(rel))


@lru_cache(maxsize=1)
def response_schema() -> dict[str, Any]:
    rel = RESPONSE_SCHEMA
    return bundle(document(rel), schema_uri(rel))


@lru_cache(maxsize=1)
def error_schema() -> dict[str, Any]:
    rel = ERROR_SCHEMA
    return bundle(document(rel), schema_uri(rel))


@lru_cache(maxsize=len(CAPABILITY_SCHEMAS))
def capability_schema(capability_id: str) -> dict[str, Any]:
    rel = CAPABILITY_SCHEMAS[capability_id]
    return bundle(document(rel), schema_uri(rel))


@lru_cache(maxsize=len(CAPABILITY_SCHEMAS))
def tool_input_schema(capability_id: str) -> dict[str, Any]:
    """capability-request.v2 with ``input`` replaced by the capability schema."""
    request = copy.deepcopy(request_schema())
    capability = capability_schema(capability_id)
    _merge_defs(request, capability.pop("$defs", {}))
    request["properties"]["input"] = capability
    request["title"] = f"{capability.get('title', capability_id)} request v2"
    return request


_VALIDATOR_CACHE: dict[int, tuple[dict[str, Any], Draft202012Validator]] = {}


def validator(schema: dict[str, Any]) -> Draft202012Validator:
    """Compile once per schema object; compiling per tools/call dominates latency.

    Schemas come from the module-level ``lru_cache`` builders, so the cache is
    bounded (three capability wrappers + response + error) and keeps a strong
    reference to the dict, which makes the ``id`` key safe.
    """
    cached = _VALIDATOR_CACHE.get(id(schema))
    if cached is not None and cached[0] is schema:
        return cached[1]
    Draft202012Validator.check_schema(schema)
    compiled = Draft202012Validator(schema, format_checker=format_checker())
    _VALIDATOR_CACHE[id(schema)] = (schema, compiled)
    return compiled


def errors_for(schema: dict[str, Any], value: Any) -> list[tuple[str, str]]:
    """Validate ``value``; return ``(json pointer, message)`` pairs."""
    found = []
    for error in sorted(validator(schema).iter_errors(value), key=lambda item: list(item.absolute_path)):
        pointer = "/" + "/".join(str(part) for part in error.absolute_path) if error.absolute_path else ""
        found.append((pointer, error.message))
    return found
