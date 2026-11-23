"""Streamable HTTP MCP server for spike G0.3a."""

from __future__ import annotations

import argparse
import json
from typing import Any

import uvicorn
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.lowlevel.server import ServerRequestContext
from starlette.applications import Starlette

from .registry import FakeRegistry
from .service import McpToolService


def mcp_session_id(context: ServerRequestContext[Any, Any]) -> str | None:
    """Transport session id (the `Mcp-Session-Id` header the SDK assigns)."""
    request = getattr(context, "request", None)
    headers = getattr(request, "headers", None)
    if headers is None:
        return None
    return headers.get("mcp-session-id")


def build_server(service: McpToolService) -> Server:
    async def on_list_tools(
        context: ServerRequestContext[Any, Any], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        return types.ListToolsResult(tools=service.list_tools())

    async def on_call_tool(
        context: ServerRequestContext[Any, Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        return await service.call(
            tool_name=params.name,
            arguments=params.arguments,
            request_meta=params.meta,
            mcp_session_id=mcp_session_id(context),
        )

    return Server(
        "aegis-mcp-spike",
        version="0.1.0",
        instructions="Spike G0.3a: capability tools backed by a fake registry.",
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


def build_app(
    service: McpToolService, *, json_response: bool = True, stateless_http: bool = False
) -> Starlette:
    server = build_server(service)
    return server.streamable_http_app(
        json_response=json_response,
        stateless_http=stateless_http,
        host="127.0.0.1",
    )


def demo_service() -> McpToolService:
    """100 providers, one known campaign session, for manual runs."""
    from .registry import SessionContext

    registry = FakeRegistry.with_providers()
    registry.sessions.register(
        SessionContext(
            campaign_id="01934f6a-0000-7000-8000-000000000001",
            session_id="01934f6a-0000-7000-8000-000000000002",
            scan_cycle="01934f6a-0000-7000-8000-000000000003",
        )
    )
    return McpToolService(registry=registry)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="AEGIS MCP spike server (G0.3a)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8931)
    parser.add_argument("--sse", action="store_true", help="stream responses as SSE instead of JSON")
    args = parser.parse_args(argv)
    service = demo_service()
    app = build_app(service, json_response=not args.sse)
    print(json.dumps({"tools": [tool.name for tool in service.list_tools()], "providers": len(service.registry.providers)}))
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
