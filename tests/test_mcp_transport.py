"""Wire-level checks of the Streamable HTTP boundary (real uvicorn, real SDK client).

G0.3a proved the SDK carries `aegis.io/*` in `params._meta` to the handler and that a bad `_meta`
becomes a JSON-RPC `-32602` with an `error.v2` payload. Those facts are what an MCP client depends
on, so they are asserted on the wire here, not only at the service seam:

* a session is opened and its `Mcp-Session-Id` binds the tools to one campaign/session;
* `tools/list` publishes the filtered catalogue for that session;
* `tools/call` returns `structuredContent` matching `capability-response.v2`, and a replay returns
  `duplicate` with the same `job_id`;
* the transport answers JSON (the mode the app ships with).
"""

from __future__ import annotations

import json
from typing import cast

import httpx
import pytest
from mcp import types
from mcp.shared.exceptions import MCPError
from mcp.types import INVALID_PARAMS, RequestParamsMeta

from tests.mcp_support import (
    CAMPAIGN_ID,
    DISCOVER,
    ENUMERATE,
    ENVELOPE_META,
    GRAPH_TOOLS,
    RESOLVE,
    arguments,
    connected,
    make_service,
    meta,
    serve,
    wire_request,
    wire_session,
)

pytestmark = pytest.mark.anyio


async def test_wire_tools_list_is_filtered_and_self_contained() -> None:
    service = make_service()
    async with serve(service) as url, httpx.AsyncClient(timeout=30.0) as http:
        async with wire_session(url, client=http) as session:
            body = await wire_request(
                http, session, "tools/list", {"_meta": {**ENVELOPE_META, **meta()}}
            )
    tools = body["result"]["tools"]
    names = sorted(tool["name"] for tool in tools)
    assert names == sorted([ENUMERATE, RESOLVE, DISCOVER, *GRAPH_TOOLS])
    for tool in tools:
        raw = json.dumps(tool)
        assert "../" not in raw and "aegis.io/contracts" not in raw


async def test_wire_missing_meta_is_minus_32602_with_input_invalid() -> None:
    service = make_service()
    async with serve(service) as url, httpx.AsyncClient(timeout=30.0) as http:
        async with wire_session(url, client=http) as session:
            body = await wire_request(
                http,
                session,
                "tools/call",
                {"name": ENUMERATE, "arguments": arguments(), "_meta": dict(ENVELOPE_META)},
            )
    assert "result" not in body
    error = body["error"]
    assert error["code"] == -32602
    assert error["data"]["code"] == "INPUT_INVALID"
    assert error["data"]["next_action"] == "FIX_INPUT"
    assert error["data"]["field"] == "/_meta/aegis.io~1trace_id"
    assert service.jobs.submissions == []  # type: ignore[attr-defined]


async def test_wire_call_returns_structured_content_and_replays_as_duplicate() -> None:
    service = make_service()
    async with serve(service) as url, httpx.AsyncClient(timeout=30.0) as http:
        async with wire_session(url, client=http) as session:
            first = await wire_request(
                http,
                session,
                "tools/call",
                {
                    "name": ENUMERATE,
                    "arguments": arguments(),
                    "_meta": {**ENVELOPE_META, **meta()},
                },
            )
            second = await wire_request(
                http,
                session,
                "tools/call",
                {
                    "name": ENUMERATE,
                    "arguments": arguments(),
                    "_meta": {**ENVELOPE_META, **meta()},
                },
                request_id=3,
            )
    for body in (first, second):
        assert body["result"]["isError"] is False
        assert (
            json.loads(body["result"]["content"][0]["text"]) == body["result"]["structuredContent"]
        )
    assert first["result"]["structuredContent"]["decision"] == "approved"
    assert second["result"]["structuredContent"]["decision"] == "duplicate"
    assert (
        second["result"]["structuredContent"]["job_id"]
        == first["result"]["structuredContent"]["job_id"]
    )
    assert len(service.jobs.submissions) == 1  # type: ignore[attr-defined]


async def test_wire_a_foreign_session_on_a_bound_connection_is_refused() -> None:
    service = make_service()
    async with serve(service) as url, httpx.AsyncClient(timeout=30.0) as http:
        async with wire_session(url, client=http) as session:
            await wire_request(
                http,
                session,
                "tools/list",
                {"_meta": {**ENVELOPE_META, **meta()}},
            )
            body = await wire_request(
                http,
                session,
                "tools/call",
                {
                    "name": ENUMERATE,
                    "arguments": arguments(),
                    "_meta": {
                        **ENVELOPE_META,
                        **meta(
                            **{"aegis.io/campaign_id": ("01934f6a-0000-7000-8000-000000000002")}
                        ),
                    },
                },
            )
    assert body["error"]["code"] == -32602
    assert body["error"]["data"]["field"] == "/_meta/aegis.io~1session_id"
    assert service.jobs.submissions == []  # type: ignore[attr-defined]


async def test_wire_tools_list_follows_the_transport_binding_without_aegis_meta() -> None:
    """The SDK sends only the envelope keys when it probes `tools/list`; the binding still filters.

    Before the transport is bound the catalogue is the admitted one (the probe arm). After a
    `tools/call` binds the transport, a `_meta`-less list is the campaign's list - omitting the
    `aegis.io/*` keys cannot widen it.
    """
    service = make_service(denylists={CAMPAIGN_ID: frozenset({RESOLVE})})
    async with serve(service) as url, httpx.AsyncClient(timeout=30.0) as http:
        async with wire_session(url, client=http) as session:
            unbound = await wire_request(
                http, session, "tools/list", {"_meta": dict(ENVELOPE_META)}
            )
            assert RESOLVE in [tool["name"] for tool in unbound["result"]["tools"]]

            await wire_request(
                http,
                session,
                "tools/call",
                {
                    "name": ENUMERATE,
                    "arguments": arguments(),
                    "_meta": {**ENVELOPE_META, **meta()},
                },
            )
            bound = await wire_request(
                http, session, "tools/list", {"_meta": dict(ENVELOPE_META)}, request_id=4
            )
    names = [tool["name"] for tool in bound["result"]["tools"]]
    assert RESOLVE not in names
    assert ENUMERATE in names
    assert len(service.jobs.submissions) == 1  # type: ignore[attr-defined]


async def test_the_sdk_client_drives_the_same_flow() -> None:
    service = make_service()
    async with serve(service) as url:
        async with connected(url) as session:
            listed = await session.list_tools(
                params=types.PaginatedRequestParams(_meta=cast(RequestParamsMeta, dict(meta())))
            )
            assert ENUMERATE in [tool.name for tool in listed.tools]
            result = await session.call_tool(
                ENUMERATE,
                dict(arguments()),
                meta=cast(RequestParamsMeta, dict(meta())),
            )
    assert isinstance(result, types.CallToolResult)
    assert result.is_error is False
    assert result.structured_content is not None
    assert result.structured_content["decision"] == "approved"


async def test_the_sdk_client_sees_a_protocol_error_for_a_bad_meta() -> None:
    service = make_service()
    async with serve(service) as url:
        async with connected(url) as session:
            with pytest.raises(MCPError) as caught:
                await session.call_tool(ENUMERATE, dict(arguments()))
    assert caught.value.code == INVALID_PARAMS
    assert isinstance(caught.value.data, dict)
    assert caught.value.data["code"] == "INPUT_INVALID"
    assert service.jobs.submissions == []  # type: ignore[attr-defined]
