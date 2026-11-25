"""`tools/list`: the campaign-filtered catalogue with self-contained, contract-derived schemas.

Two things a client depends on and this suite pins:

* the list is what the campaign may actually request - an admitted capability, minus the policy's
  `capability_denylist` - plus the six contract `graph.*` queries, and nothing else;
* every published schema works without the contract bundle: no relative or absolute `$ref` points
  at another document, and the wrapped `input` is the pinned capability schema (G0.3a finding).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from aegis import validation
from aegis.m05_registry.registry import InMemoryManifestRegistry
from tests.mcp_support import (
    CAMPAIGN_ID,
    DISCOVER,
    ENUMERATE,
    GRAPH_TOOLS,
    RESOLVE,
    arguments,
    make_service,
    meta,
)


def _refs(node: Any) -> Iterator[str]:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                yield value
            else:
                yield from _refs(value)
    elif isinstance(node, list):
        for item in node:
            yield from _refs(item)


def _tools(service: Any, **kwargs: Any) -> dict[str, Any]:
    listed = service.list_tools(request_meta=meta(), mcp_session_id="transport-1")
    return {tool.name: tool for tool in listed.tools}


def test_the_catalogue_is_capabilities_plus_graph_queries() -> None:
    tools = _tools(make_service())

    assert sorted(tools) == sorted([ENUMERATE, RESOLVE, DISCOVER, *GRAPH_TOOLS])


def test_the_policy_denylist_hides_a_capability_for_that_campaign_only() -> None:
    service = make_service(denylists={CAMPAIGN_ID: frozenset({RESOLVE})})
    tools = _tools(service)

    assert RESOLVE not in tools
    assert ENUMERATE in tools
    assert all(name in tools for name in GRAPH_TOOLS)


def test_published_schemas_are_self_contained_and_wrapped() -> None:
    tools = _tools(make_service())
    for name in (ENUMERATE, RESOLVE):
        tool = tools[name]
        raw = json.dumps(tool.input_schema) + json.dumps(tool.output_schema)
        assert "aegis.io/contracts" not in raw
        assert all(ref.startswith("#/$defs/") for ref in _refs(tool.input_schema))
        assert all(ref.startswith("#/$defs/") for ref in _refs(tool.output_schema))
        schema = tool.input_schema
        assert set(schema["required"]) == {"input", "rationale", "objective_id"}
        assert schema["properties"]["input"]["type"] == "object"
        assert schema["properties"]["priority"]["default"] == 50
        assert schema["properties"]["depends_on"]["default"] == []
        assert tool.output_schema["properties"]["decision"]["enum"] == [
            "approved",
            "denied",
            "duplicate",
        ]


def test_the_capability_input_schema_is_the_pinned_one() -> None:
    tools = _tools(make_service())
    wrapped = tools[ENUMERATE].input_schema
    capability = validation.document("capabilities/dns/enumerate-subdomains.v2.schema.json")

    assert wrapped["properties"]["input"]["required"] == capability["required"]
    assert set(wrapped["properties"]["input"]["properties"]) == set(capability["properties"])
    assert (
        tools[RESOLVE].input_schema["properties"]["input"]["title"]
        == (validation.document("capabilities/dns/resolve.v2.schema.json")["title"])
    )


def test_a_contract_argument_validates_against_the_published_schema() -> None:
    tool = _tools(make_service())[ENUMERATE]
    validator = Draft202012Validator(tool.input_schema, format_checker=validation.format_checker())

    validator.validate(arguments())
    # The published `input` is the capability schema, not a free-form object.
    assert list(validator.iter_errors(arguments(input={"targets": ["UPPER.example"]})))
    assert list(validator.iter_errors(arguments(input={"targets": "internal.example"})))


def test_graph_tools_publish_the_contract_input_and_output() -> None:
    tools = _tools(make_service())
    definitions = validation.document("mcp/graph-queries.v2.schema.json")["$defs"]
    for name in GRAPH_TOOLS:
        query = name.removeprefix("graph.")
        tool = tools[name]
        contract = definitions[query]["properties"]
        assert set(tool.input_schema["properties"]) == set(contract["input"]["properties"])
        assert set(tool.output_schema["properties"]) == set(contract["output"]["properties"])
        assert tool.output_schema["properties"]["truncated"]["type"] == "boolean"
        assert "limits_applied" in tool.output_schema["required"]
        raw = json.dumps(tool.input_schema) + json.dumps(tool.output_schema)
        assert all(ref.startswith("#/$defs/") for ref in _refs(tool.input_schema))
        assert "aegis.io/contracts" not in raw


def test_the_bound_transport_filters_the_list_even_without_meta() -> None:
    """Refinement: the transport binding is the authority, `_meta` or not.

    An unbound transport gets the admitted catalogue (the SDK probes `tools/list` before it
    returns any call result). Once the same transport is bound to a campaign/session, a `_meta`-less
    list is that campaign's list - a client cannot drop the filter by omitting `_meta`.
    """
    service = make_service(denylists={CAMPAIGN_ID: frozenset({RESOLVE})})
    unbound = {
        tool.name for tool in service.list_tools(request_meta=None, mcp_session_id="t-1").tools
    }
    assert RESOLVE in unbound

    service.list_tools(request_meta=meta(), mcp_session_id="t-1")  # binds
    bound = {
        tool.name for tool in service.list_tools(request_meta=None, mcp_session_id="t-1").tools
    }
    assert RESOLVE not in bound
    assert ENUMERATE in bound


def test_a_stateless_transport_without_meta_stays_unfiltered() -> None:
    service = make_service(denylists={CAMPAIGN_ID: frozenset({RESOLVE})})
    tools = {tool.name for tool in service.list_tools(request_meta=None, mcp_session_id=None).tools}
    assert RESOLVE in tools


def test_a_capability_with_no_admitted_manifest_is_not_published() -> None:
    tools = _tools(make_service(manifest_registry=InMemoryManifestRegistry()))

    assert ENUMERATE not in tools
    assert sorted(name for name in tools) == sorted(GRAPH_TOOLS)


@pytest.mark.parametrize("name", [ENUMERATE, *GRAPH_TOOLS])
def test_every_published_schema_is_a_valid_json_schema(name: str) -> None:
    tool = _tools(make_service())[name]
    Draft202012Validator.check_schema(dict(tool.input_schema))
    Draft202012Validator.check_schema(dict(tool.output_schema))
