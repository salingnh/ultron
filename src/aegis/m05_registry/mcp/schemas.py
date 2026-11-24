"""Self-contained MCP tool schemas built from the contract bundle.

`contracts/mcp/README.md` fixes the wire contract:

* capability tool name = capability id, `inputSchema` = `capability-request.v2` with
  `properties.input` replaced by the capability input schema the pinned manifest names,
  `outputSchema` = `capability-response.v2` (returned in `structuredContent`);
* `graph.<name>` tools take their `input`/`output` from `graph-queries.v2`.

A `tools/list` client does not have the contract bundle, so every published schema is
**self-contained**: relative `$ref`s are resolved against their document `$id` and hoisted into the
tool schema's own `$defs` (G0.3a finding: a client cannot follow a relative ref).

Two rules from the egress review (`contracts/validation.py`, G0.3a):

* the bundle is loaded **once**, through `aegis.validation`, so the MCP layer cannot drift from the
  contract bundle every other consumer validates against;
* a validator is compiled once per schema object. Recompiling per `tools/call` cost ~18 ms in the
  spike; cached, the same call is 0.52 ms (G0.3a latency section).
"""

from __future__ import annotations

import copy
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from functools import cache
from typing import Any
from urllib.parse import urldefrag, urljoin

from jsonschema import Draft202012Validator

from aegis import validation

__all__ = [
    "CompiledSchema",
    "apply_defaults",
    "capability_input_schema",
    "capability_request_schema",
    "capability_response_schema",
    "error_schema",
    "graph_input_schema",
    "graph_output_schema",
    "graph_query_names",
]

REQUEST_SCHEMA = "mcp/capability-request.v2.schema.json"
RESPONSE_SCHEMA = "mcp/capability-response.v2.schema.json"
ERROR_SCHEMA = "common/error.v2.schema.json"
GRAPH_SCHEMA = "mcp/graph-queries.v2.schema.json"
DRAFT = "https://json-schema.org/draft/2020-12/schema"

_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]+")


@dataclass(frozen=True, slots=True)
class CompiledSchema:
    """One bundled schema plus its compiled validator (built once, reused for every call)."""

    key: str
    schema: Mapping[str, Any]
    validator: Draft202012Validator

    def problems(self, instance: Any) -> list[tuple[str, str]]:
        """Every violation as `(JSON Pointer, message)`, ordered by document path."""
        found = sorted(
            self.validator.iter_errors(instance), key=lambda error: list(error.absolute_path)
        )
        return [
            (
                "/" + "/".join(str(part) for part in error.absolute_path)
                if error.absolute_path
                else "",
                error.message,
            )
            for error in found
        ]


@cache
def _documents() -> dict[str, dict[str, Any]]:
    """Every contract document by `$id` (the bundle `aegis.validation` already loaded)."""
    return {str(schema["$id"]): schema for schema in validation.schemas().values()}


def _document(relative_path: str) -> tuple[dict[str, Any], str]:
    schema = validation.schemas().get(relative_path)
    if schema is None:
        raise validation.ContractUnavailable(f"no contract schema at {relative_path}")
    return schema, str(schema["$id"])


def _absolutize(node: Any, base: str) -> Any:
    """Rewrite every `$ref` to an absolute URI and drop per-document `$id`/`$schema`."""
    if isinstance(node, Mapping):
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


def _pointer(document: Mapping[str, Any], fragment: str) -> Any:
    value: Any = document
    for token in fragment.strip("/").split("/") if fragment.strip("/") else []:
        value = value[token.replace("~1", "/").replace("~0", "~")]
    return value


def _def_name(uri: str, fragment: str) -> str:
    stem = urldefrag(uri)[0].rsplit("/", 1)[-1].removesuffix(".schema.json")
    tokens = [token for token in fragment.split("/") if token]
    tail = "-".join(tokens[-2:]) if tokens else "root"
    return _SAFE_NAME.sub("_", f"{stem}.{tail}")


def _walk(node: Any) -> Iterator[dict[str, Any]]:
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item)


def _bundle(schema: Mapping[str, Any], base_uri: str) -> dict[str, Any]:
    """`schema` with every external `$ref` inlined under its own `$defs`."""
    documents = _documents()
    root: dict[str, Any] = _absolutize(schema, base_uri)
    root["$schema"] = DRAFT
    defs: dict[str, Any] = root.setdefault("$defs", {})
    pending: list[dict[str, Any]] = [root]
    while pending:
        # Materialise the walk: resolving a ref appends to ``$defs``, which the same tree holds.
        for node in list(_walk(pending.pop())):
            for key, value in list(node.items()):
                if key != "$ref" or not isinstance(value, str):
                    continue
                uri, fragment = urldefrag(value)
                if uri not in documents:
                    raise validation.ContractUnavailable(
                        f"tool schema references an unknown contract document: {uri}"
                    )
                name = _def_name(uri, fragment)
                node[key] = f"#/$defs/{name}"
                if name in defs:
                    continue
                target = _pointer(documents[uri], fragment) if fragment else documents[uri]
                defs[name] = _absolutize(target, uri)
                pending.append(defs[name])
    return root


def _merge_defs(target: dict[str, Any], other: Mapping[str, Any]) -> None:
    defs = target.setdefault("$defs", {})
    for name, value in other.items():
        if name in defs:
            if defs[name] != value:
                raise validation.ContractUnavailable(
                    f"conflicting $defs entry while bundling a tool schema: {name}"
                )
            continue
        defs[name] = value


_COMPILED: dict[str, CompiledSchema] = {}


def _compile(key: str, schema: dict[str, Any]) -> CompiledSchema:
    cached = _COMPILED.get(key)
    if cached is not None:
        return cached
    Draft202012Validator.check_schema(schema)
    compiled = CompiledSchema(
        key=key,
        schema=schema,
        validator=Draft202012Validator(schema, format_checker=validation.format_checker()),
    )
    _COMPILED[key] = compiled
    return compiled


def capability_response_schema() -> CompiledSchema:
    """`capability-response.v2`, self-contained: every capability call returns it."""
    schema, base = _document(RESPONSE_SCHEMA)
    return _compile("response", _bundle(schema, base))


def error_schema() -> CompiledSchema:
    """`error.v2`, self-contained (protocol error data and the `error` of a denied response)."""
    schema, base = _document(ERROR_SCHEMA)
    return _compile("error", _bundle(schema, base))


def capability_input_schema(relative_path: str) -> dict[str, Any]:
    """The capability input document the pinned manifest names (for `inputDefaults` merging)."""
    schema, _ = _document(relative_path)
    return schema


def capability_request_schema(input_schema_path: str) -> CompiledSchema:
    """`capability-request.v2` with `properties.input` replaced by the capability schema."""
    key = f"capability-request:{input_schema_path}"
    cached = _COMPILED.get(key)
    if cached is not None:
        return cached
    request, request_base = _document(REQUEST_SCHEMA)
    capability = _bundle(*_document(input_schema_path))
    wrapped = _bundle(request, request_base)
    _merge_defs(wrapped, capability.pop("$defs", {}))
    wrapped["properties"]["input"] = capability
    wrapped["title"] = f"{capability.get('title') or input_schema_path} request v2"
    return _compile(key, wrapped)


@cache
def _graph_schema() -> dict[str, Any]:
    schema, _ = _document(GRAPH_SCHEMA)
    return schema


@cache
def graph_query_names() -> tuple[str, ...]:
    """Contract query names (`get_asset_neighbors`, ...); the tool name is `graph.<name>`."""
    return tuple(sorted(_graph_schema().get("$defs", {})))


def _graph_entry(query: str) -> Mapping[str, Any]:
    entry = _graph_schema().get("$defs", {}).get(query)
    if not isinstance(entry, Mapping):
        raise validation.ContractUnavailable(f"graph-queries.v2 has no $defs/{query}")
    return entry


def _graph_part(query: str, part: str) -> CompiledSchema:
    properties = _graph_entry(query).get("properties")
    if not isinstance(properties, Mapping) or not isinstance(properties.get(part), Mapping):
        raise validation.ContractUnavailable(f"graph-queries.v2 has no $defs/{query}/{part}")
    _, base = _document(GRAPH_SCHEMA)
    return _compile(f"graph-{part}:{query}", _bundle(properties[part], base))


def graph_input_schema(query: str) -> CompiledSchema:
    return _graph_part(query, "input")


def graph_output_schema(query: str) -> CompiledSchema:
    return _graph_part(query, "output")


def graph_tool_description(query: str) -> str:
    """The contract description of one query (the MCP tool description)."""
    return str(_graph_entry(query).get("description") or query)


def apply_defaults(schema: Mapping[str, Any], value: Any, *, nested: bool = True) -> Any:
    """Merge the schema's own `default`s before validating, like the contract's reference does.

    `nested=False` applies the defaults of the root object only: the capability `input` subtree is
    defaulted by M05 (`inputDefaults` merge), so defaulting it here as well would give the MCP layer
    a second, drifting opinion about what the runner executes.
    """
    if isinstance(value, Mapping):
        result = dict(value)
        properties = schema.get("properties")
        if not isinstance(properties, Mapping):
            return result
        for name, subschema in properties.items():
            if not isinstance(subschema, Mapping):
                continue
            if "default" in subschema and name not in result:
                result[name] = copy.deepcopy(subschema["default"])
            if nested and name in result:
                result[name] = apply_defaults(subschema, result[name])
        return result
    if isinstance(value, list) and isinstance(schema.get("items"), Mapping):
        return [apply_defaults(schema["items"], item) for item in value]
    return value
