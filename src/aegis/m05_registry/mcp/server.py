"""Streamable HTTP MCP server (the SDK line spike G0.3a verified: `mcp` 2.3.0, protocol 2025-11-25).

Thin by design: the lowlevel `Server` receives `tools/list`/`tools/call`, extracts the transport
session id (the `Mcp-Session-Id` header the SDK assigns) and hands everything to `McpToolService`,
which owns the contract checks. Nothing about jobs or policy lives here.

The transport stays in the control network (`contracts/mcp/README.md:2`); the Web UI uses M26 REST.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette

from aegis.m05_registry.mcp.service import McpToolService

__all__ = ["build_app", "build_server", "transport_session_id"]

MCP_PATH = "/mcp"
INSTRUCTIONS = (
    "AEGIS control plane. Capability tools submit jobs through M05 and return immediately; "
    "graph.* tools read the campaign's knowledge within the server's limits. Every call carries "
    "aegis.io/* keys in params._meta; the server checks them against the session it bound."
)


def transport_session_id(context: Any) -> str | None:
    """The `Mcp-Session-Id` the SDK assigned to this connection (None for stateless transport)."""
    request = getattr(context, "request", None)
    headers = getattr(request, "headers", None)
    if headers is None:
        return None
    value = headers.get("mcp-session-id")
    return None if value is None else str(value)


def build_server(service: McpToolService) -> Server:
    """The lowlevel server whose two handlers are the tool service."""

    async def on_list_tools(
        context: Any,
        params: types.PaginatedRequestParams | None,
    ) -> types.ListToolsResult:
        return service.list_tools(
            request_meta=None if params is None else params.meta,
            mcp_session_id=transport_session_id(context),
        )

    async def on_call_tool(
        context: Any,
        params: types.CallToolRequestParams,
    ) -> types.CallToolResult:
        return service.call(
            tool_name=params.name,
            arguments=params.arguments,
            request_meta=params.meta,
            mcp_session_id=transport_session_id(context),
        )

    return Server(
        "aegis",
        version="2",
        instructions=INSTRUCTIONS,
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


def build_app(
    service: McpToolService,
    *,
    json_response: bool = True,
    stateless_http: bool = False,
    host: str = "127.0.0.1",
    allowed_hosts: Sequence[str] | None = None,
) -> Starlette:
    """The Streamable HTTP ASGI app.

    `host`/`allowed_hosts` drive the SDK's DNS-rebinding guard: for a loopback host it is enabled
    with the loopback names, and a deployment behind another name must list it in
    `allowed_hosts` rather than switch the guard off.
    """
    security = None
    if allowed_hosts:
        security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(allowed_hosts),
        )
    return build_server(service).streamable_http_app(
        streamable_http_path=MCP_PATH,
        json_response=json_response,
        stateless_http=stateless_http,
        host=host,
        transport_security=security,
    )
