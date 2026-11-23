"""Wire-level checks: Streamable HTTP framing and the JSON-RPC error body."""

from __future__ import annotations

import json

import httpx2
import pytest

from aegis_mcp import contracts
from aegis_mcp.client import parse_sse, wire_session, wire_tools_call

from .support import ENUMERATE, enumerate_request, make_service, meta, serve

pytestmark = pytest.mark.anyio


async def test_raw_tools_list_publishes_wrapped_self_contained_schemas():
    service = make_service()
    async with serve(service) as url, httpx2.AsyncClient(timeout=30.0) as http:
        async with wire_session(url, client=http) as session:
            response = await http.post(
                url,
                headers=session.headers,
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            )
    response.raise_for_status()
    tools = response.json()["result"]["tools"]
    assert sorted(tool["name"] for tool in tools) == sorted(contracts.CAPABILITY_SCHEMAS)
    for tool in tools:
        schema = tool["inputSchema"]
        assert set(schema["required"]) == {"input", "rationale", "objective_id"}
        assert schema["properties"]["input"]["type"] == "object"
        assert tool["outputSchema"]["properties"]["decision"]["enum"] == [
            "approved",
            "denied",
            "duplicate",
        ]
        raw = json.dumps(tool)
        assert "../common/" not in raw and "aegis.io/contracts" not in raw


async def test_raw_tools_call_returns_structured_content_matching_response_v2():
    service = make_service()
    async with serve(service) as url, httpx2.AsyncClient(timeout=30.0) as http:
        async with wire_session(url, client=http) as session:
            body = await wire_tools_call(http, session, ENUMERATE, enumerate_request(), meta())
    result = body["result"]
    assert result["isError"] is False
    structured = result["structuredContent"]
    assert contracts.errors_for(contracts.response_schema(), structured) == []
    assert json.loads(result["content"][0]["text"]) == structured


async def test_raw_missing_meta_is_jsonrpc_minus_32602_with_input_invalid():
    service = make_service()
    async with serve(service) as url, httpx2.AsyncClient(timeout=30.0) as http:
        async with wire_session(url, client=http) as session:
            body = await wire_tools_call(http, session, ENUMERATE, enumerate_request(), None)
    assert "result" not in body
    error = body["error"]
    assert error["code"] == -32602
    assert error["data"]["code"] == "INPUT_INVALID"
    assert error["data"]["next_action"] == "FIX_INPUT"
    assert error["data"]["field"] == "/_meta/aegis.io~1trace_id"
    assert service.registry.jobs == {}


async def test_raw_bad_tool_arguments_are_input_invalid_with_argument_pointer():
    service = make_service()
    bad = enumerate_request(input={"targets": ["UPPER.example"]})
    async with serve(service) as url, httpx2.AsyncClient(timeout=30.0) as http:
        async with wire_session(url, client=http) as session:
            body = await wire_tools_call(http, session, ENUMERATE, bad, meta())
    assert body["error"]["code"] == -32602
    assert body["error"]["data"]["field"].startswith("/arguments/input/targets/0")
    assert service.registry.jobs == {}


async def test_unknown_tool_is_a_protocol_error():
    service = make_service()
    async with serve(service) as url, httpx2.AsyncClient(timeout=30.0) as http:
        async with wire_session(url, client=http) as session:
            body = await wire_tools_call(http, session, "dns.not_a_capability", enumerate_request(), meta())
    assert body["error"]["code"] == -32602
    assert body["error"]["data"]["code"] == "INPUT_INVALID"


async def test_sse_responses_carry_the_same_structured_content():
    service = make_service()
    async with serve(service, json_response=False) as url, httpx2.AsyncClient(timeout=30.0) as http:
        async with wire_session(url, client=http) as session:
            response = await http.post(
                session.url,
                headers=session.headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "tools/call",
                    "params": {
                        "name": ENUMERATE,
                        "arguments": enumerate_request(),
                        "_meta": meta(),
                    },
                },
            )
            assert response.headers["content-type"].startswith("text/event-stream")
            body = parse_sse(response.text)
    structured = body["result"]["structuredContent"]
    assert contracts.errors_for(contracts.response_schema(), structured) == []
    assert len(service.registry.jobs) == 1
