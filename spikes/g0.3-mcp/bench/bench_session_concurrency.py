"""Does one MCP session carry concurrent tools/call, or serialise it?

Measured over the raw Streamable HTTP wire (httpx2, no SDK client), because the
answer decides whether the idempotency race can be reached through the
transport or only from separate connections.

Run: .venv/bin/python -m bench.bench_session_concurrency
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx2

from aegis_mcp.client import wire_session
from aegis_mcp.registry import FakeRegistry, SessionContext
from aegis_mcp.server import build_app
from aegis_mcp.service import McpToolService

from .bench_latency import stats_ms

CAMPAIGN_ID = "01934f6a-0000-7000-8000-000000000001"
SESSION_ID = "01934f6a-0000-7000-8000-000000000002"
SCAN_CYCLE = "01934f6a-0000-7000-8000-000000000005"
TRACE_ID = "0123456789abcdef0123456789abcdef"
ENUMERATE = "dns.enumerate_subdomains"


def meta_for(step: int, prefix: str = "conc") -> dict[str, str]:
    return {
        "aegis.io/trace_id": TRACE_ID,
        "aegis.io/campaign_id": CAMPAIGN_ID,
        "aegis.io/session_id": SESSION_ID,
        "aegis.io/idempotency_key": f"{SESSION_ID}:{prefix}:{step}",
    }


def arguments() -> dict[str, Any]:
    return {
        "input": {"targets": ["example.test"]},
        "rationale": "G0.3a concurrency run: enumerate subdomains for the lab domain",
        "objective_id": "01934f6a-0000-7000-8000-000000000006",
    }


@dataclass
class Phase:
    name: str
    description: str
    wall_s: float
    stats: dict[str, float]


async def post(http: httpx2.AsyncClient, session, step: int, *, prefix: str) -> float:
    start = time.perf_counter()
    response = await http.post(
        session.url,
        headers=session.headers,
        json={
            "jsonrpc": "2.0",
            "id": step + 10,
            "method": "tools/call",
            "params": {"name": ENUMERATE, "arguments": arguments(), "_meta": meta_for(step, prefix)},
        },
    )
    response.raise_for_status()
    body = response.json()
    assert "error" not in body, body
    return time.perf_counter() - start


async def run(iterations: int, concurrency: int, *, stateless: bool = False) -> dict[str, Any]:
    service = McpToolService(registry=FakeRegistry.with_providers())
    service.registry.sessions.register(SessionContext(CAMPAIGN_ID, SESSION_ID, SCAN_CYCLE))
    import uvicorn

    app = build_app(service, json_response=True, stateless_http=stateless)
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning", lifespan="on")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.01)
    port = server.servers[0].sockets[0].getsockname()[1]
    url = f"http://127.0.0.1:{port}/mcp"
    phases: list[Phase] = []
    try:
        async with httpx2.AsyncClient(timeout=120.0) as http:
            if stateless:
                headers = {
                    "content-type": "application/json",
                    "accept": "application/json, text/event-stream",
                    "mcp-protocol-version": "2025-11-25",
                }

                async def post_stateless(step: int, prefix: str) -> float:
                    start = time.perf_counter()
                    response = await http.post(
                        url,
                        headers=headers,
                        json={
                            "jsonrpc": "2.0",
                            "id": step + 10,
                            "method": "tools/call",
                            "params": {
                                "name": ENUMERATE,
                                "arguments": arguments(),
                                "_meta": meta_for(step, prefix),
                            },
                        },
                    )
                    response.raise_for_status()
                    assert "error" not in response.json(), response.text
                    return time.perf_counter() - start

                semaphore = asyncio.Semaphore(concurrency)

                async def one_stateless(step: int) -> float:
                    async with semaphore:
                        return await post_stateless(step, "stateless")

                start = time.perf_counter()
                samples = await asyncio.gather(*(one_stateless(step) for step in range(iterations)))
                wall = time.perf_counter() - start
                phases.append(
                    Phase(
                        "stateless_concurrent",
                        f"stateless Streamable HTTP (no session), {concurrency} concurrent POSTs",
                        round(wall, 3),
                        stats_ms(list(samples)),
                    )
                )
                server.should_exit = True
                await task
                return {
                    "requests": iterations,
                    "concurrency": concurrency,
                    "stateless": True,
                    "phases": [
                        {
                            "name": phase.name,
                            "description": phase.description,
                            "wall_s": phase.wall_s,
                            "requests_per_s": round(iterations / phase.wall_s, 1),
                            "stats": phase.stats,
                        }
                        for phase in phases
                    ],
                    "jobs_created": len(service.registry.jobs),
                }
            async with wire_session(url, client=http) as session:
                for step in range(20):
                    await post(http, session, step, prefix="warm")
                samples = []
                start = time.perf_counter()
                for step in range(iterations):
                    samples.append(await post(http, session, step, prefix="seq"))
                wall = time.perf_counter() - start
                phases.append(
                    Phase(
                        "one_session_sequential",
                        "one MCP session, requests sent one at a time",
                        round(wall, 3),
                        stats_ms(samples),
                    )
                )

                semaphore = asyncio.Semaphore(concurrency)
                samples = []

                async def one(step: int) -> float:
                    async with semaphore:
                        return await post(http, session, step, prefix="par")

                start = time.perf_counter()
                samples = await asyncio.gather(*(one(step) for step in range(iterations)))
                wall = time.perf_counter() - start
                phases.append(
                    Phase(
                        "one_session_concurrent",
                        f"one MCP session, {concurrency} concurrent POSTs",
                        round(wall, 3),
                        stats_ms(list(samples)),
                    )
                )

            # separate connections: the shape a retry/duplicate caller really has
            samples = []
            semaphore = asyncio.Semaphore(concurrency)

            async def one_connection(step: int) -> float:
                async with semaphore:
                    async with wire_session(url, client=http) as fresh:
                        return await post(http, fresh, step, prefix=f"fresh{step}")

            start = time.perf_counter()
            samples = await asyncio.gather(*(one_connection(step) for step in range(iterations)))
            wall = time.perf_counter() - start
            phases.append(
                Phase(
                    "many_sessions_concurrent",
                    f"{iterations} separate MCP sessions, {concurrency} concurrent",
                    round(wall, 3),
                    stats_ms(list(samples)),
                )
            )
    finally:
        server.should_exit = True
        await task

    return {
        "requests": iterations,
        "concurrency": concurrency,
        "phases": [
            {
                "name": phase.name,
                "description": phase.description,
                "wall_s": phase.wall_s,
                "requests_per_s": round(iterations / phase.wall_s, 1),
                "stats": phase.stats,
            }
            for phase in phases
        ],
        "jobs_created": len(service.registry.jobs),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=50)
    parser.add_argument("--stateless", action="store_true", help="probe stateless transport instead (no MCP session)")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()
    payload = asyncio.run(run(args.iterations, args.concurrency, stateless=args.stateless))
    text = json.dumps(payload, indent=2, sort_keys=True)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text + "\n", encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(text)


if __name__ == "__main__":
    main()
