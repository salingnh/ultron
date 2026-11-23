"""Shared test support: constants, a throwaway server, and a fake service."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator

import uvicorn

from aegis_mcp.registry import FakeRegistry, SessionContext
from aegis_mcp.server import build_app
from aegis_mcp.service import McpToolService

CAMPAIGN_ID = "01934f6a-0000-7000-8000-000000000001"
SESSION_ID = "01934f6a-0000-7000-8000-000000000002"
OTHER_SESSION_ID = "01934f6a-0000-7000-8000-000000000003"
OTHER_CAMPAIGN_ID = "01934f6a-0000-7000-8000-000000000004"
SCAN_CYCLE = "01934f6a-0000-7000-8000-000000000005"
TRACE_ID = "0123456789abcdef0123456789abcdef"

ENUMERATE = "dns.enumerate_subdomains"


def make_service(**kwargs) -> McpToolService:
    registry = FakeRegistry.with_providers()
    registry.sessions.register(SessionContext(CAMPAIGN_ID, SESSION_ID, SCAN_CYCLE))
    registry.sessions.register(SessionContext(CAMPAIGN_ID, OTHER_SESSION_ID, SCAN_CYCLE))
    registry.sessions.register(SessionContext(OTHER_CAMPAIGN_ID, OTHER_SESSION_ID, SCAN_CYCLE))
    return McpToolService(registry=registry, **kwargs)


def meta(**overrides: str) -> dict[str, str]:
    value = {
        "aegis.io/trace_id": TRACE_ID,
        "aegis.io/campaign_id": CAMPAIGN_ID,
        "aegis.io/session_id": SESSION_ID,
        "aegis.io/idempotency_key": f"{SESSION_ID}:step:1",
    }
    value.update(overrides)
    return value


def enumerate_request(**overrides):
    value = {
        "input": {"targets": ["example.test"]},
        "rationale": "Spike fixture: enumerate subdomains for the lab domain",
        "objective_id": "01934f6a-0000-7000-8000-000000000006",
    }
    value.update(overrides)
    return value


@asynccontextmanager
async def serve(service: McpToolService, *, json_response: bool = True) -> AsyncIterator[str]:
    config = uvicorn.Config(
        build_app(service, json_response=json_response),
        host="127.0.0.1",
        port=0,
        log_level="warning",
        lifespan="on",
    )
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    try:
        while not server.started:
            if task.done():
                await task
                raise RuntimeError("uvicorn exited before startup")
            await asyncio.sleep(0.01)
        port = server.servers[0].sockets[0].getsockname()[1]
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        server.should_exit = True
        await task
