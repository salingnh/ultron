"""tools/list: wrapped, self-contained capability schemas (contracts/mcp/README.md)."""

from __future__ import annotations

import copy

import pytest
from jsonschema import Draft202012Validator

from aegis_mcp import contracts
from aegis_mcp.service import apply_defaults

from .support import make_service

ALL_CAPABILITIES = sorted(contracts.CAPABILITY_SCHEMAS)
OBJECTIVE = "01934f6a-0000-7000-8000-000000000006"


def _refs(node):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref":
                yield value
            else:
                yield from _refs(value)
    elif isinstance(node, list):
        for item in node:
            yield from _refs(item)


def _request(**overrides):
    value = {
        "input": {"targets": ["example.test"]},
        "rationale": "Spike fixture: enumerate subdomains for the lab domain",
        "objective_id": OBJECTIVE,
    }
    value.update(overrides)
    return value


def test_every_published_schema_is_self_contained():
    for capability in ALL_CAPABILITIES:
        schema = contracts.tool_input_schema(capability)
        Draft202012Validator.check_schema(schema)
        assert [ref for ref in _refs(schema) if not ref.startswith("#/")] == []
    response = contracts.response_schema()
    Draft202012Validator.check_schema(response)
    assert [ref for ref in _refs(response) if not ref.startswith("#/")] == []


def test_input_property_is_the_resolved_capability_schema():
    for capability in ALL_CAPABILITIES:
        wrapped = contracts.tool_input_schema(capability)
        expected = copy.deepcopy(contracts.capability_schema(capability))
        expected.pop("$defs", None)
        assert wrapped["properties"]["input"] == expected
        # request-level shape survives the substitution
        assert set(wrapped["required"]) == {"input", "rationale", "objective_id"}
        assert wrapped["properties"]["priority"]["default"] == 50
        assert wrapped["properties"]["depends_on"]["default"] == []


def test_valid_request_passes_and_defaults_are_applied():
    schema = contracts.tool_input_schema("dns.enumerate_subdomains")
    request = _request(input={"targets": ["example.test", "dns:sub.example.test"]})
    payload = apply_defaults(schema, request)
    assert contracts.errors_for(schema, payload) == []
    assert payload["priority"] == 50
    assert payload["depends_on"] == []
    assert payload["input"]["recursive"] is False
    assert payload["input"]["max_results"] == 10000


def test_capability_defaults_come_from_the_capability_schema():
    schema = contracts.tool_input_schema("dns.resolve")
    payload = apply_defaults(schema, _request())
    assert payload["input"]["record_types"] == ["A", "AAAA", "CNAME"]
    assert contracts.errors_for(schema, payload) == []


@pytest.mark.parametrize(
    ("mutation", "pointer_fragment"),
    [
        (lambda request: request["input"].update({"targets": ["UPPER.example"]}), "/input/targets/0"),
        (lambda request: request.pop("rationale"), ""),
        (lambda request: request.update({"objective_id": "not-an-id"}), "/objective_id"),
        (lambda request: request["input"].update({"nope": 1}), "/input"),
        (lambda request: request.update({"priority": 101}), "/priority"),
        (lambda request: request.update({"depends_on": []}), None),  # valid: control case
    ],
)
def test_schema_rejects_invalid_requests(mutation, pointer_fragment):
    schema = contracts.tool_input_schema("dns.enumerate_subdomains")
    request = _request()
    mutation(request)
    problems = contracts.errors_for(schema, apply_defaults(schema, request))
    if pointer_fragment is None:
        assert problems == []
        return
    assert problems, "invalid request must not validate"
    assert any(pointer_fragment in pointer for pointer, _ in problems), problems


def test_unknown_request_property_is_rejected():
    schema = contracts.tool_input_schema("dns.enumerate_subdomains")
    problems = contracts.errors_for(
        schema, apply_defaults(schema, _request(confidence=0.9))
    )
    assert problems


def test_service_publishes_one_tool_per_capability_with_wrapped_schemas():
    service = make_service()
    tools = {tool.name: tool for tool in service.list_tools()}
    assert sorted(tools) == ALL_CAPABILITIES
    for name, tool in tools.items():
        assert tool.input_schema == contracts.tool_input_schema(name)
        assert tool.output_schema == contracts.response_schema()
        assert tool.input_schema["properties"]["input"]["type"] == "object"


def test_denylist_and_campaign_filter_hide_tools():
    denied = make_service(denied_capabilities=frozenset({"dns.resolve"}))
    assert sorted(tool.name for tool in denied.list_tools()) == [
        "dns.enumerate_subdomains",
        "network.discover_services",
    ]
    filtered = make_service(campaign_capabilities=frozenset({"dns.enumerate_subdomains"}))
    assert [tool.name for tool in filtered.list_tools()] == ["dns.enumerate_subdomains"]


def test_bundling_does_not_mutate_contract_documents():
    before = copy.deepcopy(contracts.request_schema())
    contracts.tool_input_schema("dns.resolve")
    assert contracts.request_schema() == before
