"""Client + raw wire helpers (SDK client for tool calls, httpx2 for the wire)."""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, AsyncIterator, Mapping

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

PROTOCOL_VERSION = "2025-11-25"


@asynccontextmanager
async def connected(url: str) -> AsyncIterator[ClientSession]:
    async with streamable_http_client(url) as streams:
        async with ClientSession(streams[0], streams[1]) as session:
            await session.initialize()
            yield session


async def call_capability(
    session: ClientSession,
    capability: str,
    arguments: Mapping[str, Any],
    meta: Mapping[str, Any],
) -> Any:
    return await session.call_tool(capability, dict(arguments), meta=dict(meta))


@dataclass
class WireSession:
    url: str
    session_id: str
    protocol_version: str = PROTOCOL_VERSION

    def post(self, payload: dict[str, Any], *, request_id: int = 2) -> dict[str, Any]:
        body = {"jsonrpc": "2.0", "id": request_id, **payload}
        return body

    @property
    def headers(self) -> dict[str, str]:
        return {
            "content-type": "application/json",
            "accept": "application/json, text/event-stream",
            "mcp-session-id": self.session_id,
            "mcp-protocol-version": self.protocol_version,
        }


@asynccontextmanager
async def wire_session(url: str, *, client: httpx2.AsyncClient | None = None) -> AsyncIterator[WireSession]:
    """Open a real MCP session by hand so tests can assert the raw JSON-RPC body."""
    owned = client is None
    http = client or httpx2.AsyncClient(timeout=30.0)
    try:
        response = await http.post(
            url,
            headers={"content-type": "application/json", "accept": "application/json, text/event-stream"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "g0.3a-spike", "version": "0.1.0"},
                },
            },
        )
        response.raise_for_status()
        session_id = response.headers.get("mcp-session-id")
        if session_id is None:  # pragma: no cover - transport regression
            raise RuntimeError("server did not return an Mcp-Session-Id header")
        await http.post(
            url,
            headers={
                "content-type": "application/json",
                "accept": "application/json, text/event-stream",
                "mcp-session-id": session_id,
                "mcp-protocol-version": PROTOCOL_VERSION,
            },
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        )
        yield WireSession(url=url, session_id=session_id)
    finally:
        if owned:
            await http.aclose()


async def wire_tools_call(
    http: httpx2.AsyncClient,
    session: WireSession,
    capability: str,
    arguments: Mapping[str, Any],
    meta: Mapping[str, Any] | None,
    *,
    request_id: int = 2,
) -> dict[str, Any]:
    params: dict[str, Any] = {"name": capability, "arguments": dict(arguments)}
    if meta is not None:
        params["_meta"] = dict(meta)
    response = await http.post(
        session.url,
        headers=session.headers,
        json={"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": params},
    )
    response.raise_for_status()
    return response.json()


def parse_sse(text: str) -> dict[str, Any]:
    """Take the JSON-RPC message out of an SSE response body."""
    for block in text.split("\n\n"):
        data = [line[len("data:") :].strip() for line in block.splitlines() if line.startswith("data:")]
        if data:
            return json.loads("\n".join(data))
    raise AssertionError(f"no SSE data frame in response: {text[:200]!r}")
