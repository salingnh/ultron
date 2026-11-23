"""NFR-04 latency measurement for G0.3a (registry P95 < 300 ms @ 100 providers).

Measures the code path the MCP boundary will own in G1.2b:

* ``tools/list``             - schema wrapping for 3 capabilities x 100 providers
* ``tools/call`` handler     - contract validation + session check + registry
                               lookup + idempotent job create (no transport)
* ``tools/call`` HTTP (json) - the same path over Streamable HTTP, JSON responses
* ``tools/call`` HTTP (SSE)  - same, SSE framed responses
* same-key burst             - 100 concurrent identical calls, wall time, jobs=1

Run: .venv/bin/python -m bench.bench_latency [--out benchmarks/latency.json]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import platform
import statistics
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable

import uvicorn

from aegis_mcp import contracts
from aegis_mcp.client import call_capability, connected
from aegis_mcp.registry import FakeRegistry, SessionContext
from aegis_mcp.server import build_app
from aegis_mcp.service import McpToolService

CAMPAIGN_ID = "01934f6a-0000-7000-8000-000000000001"
SESSION_ID = "01934f6a-0000-7000-8000-000000000002"
SCAN_CYCLE = "01934f6a-0000-7000-8000-000000000005"
TRACE_ID = "0123456789abcdef0123456789abcdef"
ENUMERATE = "dns.enumerate_subdomains"

NFR04_TARGET_MS = 300.0
RESULT_OUT = Path(__file__).resolve().parents[1] / "benchmarks" / "latency.json"


def percentile(samples: list[float], fraction: float) -> float:
    ordered = sorted(samples)
    index = min(len(ordered) - 1, max(0, round(fraction * (len(ordered) - 1))))
    return ordered[index]


def stats_ms(samples_s: list[float]) -> dict[str, float]:
    values = [value * 1000.0 for value in samples_s]
    return {
        "n": len(values),
        "mean_ms": round(statistics.fmean(values), 3),
        "p50_ms": round(percentile(values, 0.50), 3),
        "p90_ms": round(percentile(values, 0.90), 3),
        "p95_ms": round(percentile(values, 0.95), 3),
        "p99_ms": round(percentile(values, 0.99), 3),
        "max_ms": round(max(values), 3),
    }


def meta_for(step: int, prefix: str = "step") -> dict[str, str]:
    return {
        "aegis.io/trace_id": TRACE_ID,
        "aegis.io/campaign_id": CAMPAIGN_ID,
        "aegis.io/session_id": SESSION_ID,
        "aegis.io/idempotency_key": f"{SESSION_ID}:{prefix}:{step}",
    }


def arguments() -> dict[str, Any]:
    return {
        "input": {"targets": ["example.test", "dns:sub.example.test"]},
        "rationale": "G0.3a latency run: enumerate subdomains for the lab domain",
        "objective_id": "01934f6a-0000-7000-8000-000000000006",
    }


@dataclass
class Result:
    name: str
    description: str
    stats: dict[str, float]
    extra: dict[str, Any] = field(default_factory=dict)

    def passes_target(self, target_ms: float = NFR04_TARGET_MS) -> bool:
        return self.stats["p95_ms"] < target_ms


async def with_server(service: McpToolService, body: Callable[[str], Awaitable[None]], *, json_response: bool = True, path: str = ""):
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
        await body(f"http://127.0.0.1:{port}/mcp")
    finally:
        server.should_exit = True
        await task


async def scenario_tools_list(url: str, iterations: int) -> Result:
    async with connected(url) as session:
        for _ in range(20):
            await session.list_tools()
        samples = []
        for _ in range(iterations):
            start = time.perf_counter()
            await session.list_tools()
            samples.append(time.perf_counter() - start)
    return Result(
        name="tools/list_http_json",
        description="tools/list over Streamable HTTP (JSON), 3 wrapped capability tools",
        stats=stats_ms(samples),
    )


async def scenario_call_http(url: str, iterations: int) -> Result:
    samples = []
    async with connected(url) as session:
        for step in range(20):
            await call_capability(session, ENUMERATE, arguments(), meta_for(step, prefix="warm"))
        for step in range(iterations):
            start = time.perf_counter()
            await call_capability(session, ENUMERATE, arguments(), meta_for(step, prefix="http"))
            samples.append(time.perf_counter() - start)
    return Result(
        name="tools/call_http_json",
        description="tools/call over Streamable HTTP (JSON): schema+_meta validation, session check, registry, job create",
        stats=stats_ms(samples),
    )


async def scenario_call_http_concurrent(url: str, calls: int, concurrency: int) -> Result:
    semaphore = asyncio.Semaphore(concurrency)

    async def one(session, step: int) -> float:
        async with semaphore:
            start = time.perf_counter()
            await call_capability(session, ENUMERATE, arguments(), meta_for(step, prefix="conc"))
            return time.perf_counter() - start

    async with connected(url) as session:
        wall_start = time.perf_counter()
        samples = await asyncio.gather(*(one(session, step) for step in range(calls)))
        wall = time.perf_counter() - wall_start
    result = Result(
        name="tools/call_http_json_concurrent",
        description=f"tools/call over Streamable HTTP, {concurrency} concurrent callers, distinct keys",
        stats=stats_ms(list(samples)),
    )
    result.extra = {
        "concurrency": concurrency,
        "wall_s": round(wall, 3),
        "calls_per_s": round(calls / wall, 1),
    }
    return result


async def scenario_handler(
    service: McpToolService, iterations: int, *, write_latency: float = 0.0, prefix: str = "handler"
) -> Result:
    service.registry.write_latency = write_latency
    for step in range(50):
        await service.call(
            tool_name=ENUMERATE,
            arguments=arguments(),
            request_meta=meta_for(step, prefix=f"{prefix}-warm"),
            mcp_session_id="bench-handler",
        )
    samples = []
    for step in range(iterations):
        start = time.perf_counter()
        await service.call(
            tool_name=ENUMERATE,
            arguments=arguments(),
            request_meta=meta_for(step, prefix=prefix),
            mcp_session_id="bench-handler",
        )
        samples.append(time.perf_counter() - start)
    service.registry.write_latency = 0.0
    label = "tools/call_handler" + (f"_plus_{round(write_latency * 1000)}ms_registry_write" if write_latency else "")
    return Result(
        name=label,
        description=(
            "tools/call handler only (no HTTP): contract validation + _meta/session + registry select + "
            + (f"simulated {round(write_latency * 1000)} ms registry write" if write_latency else "in-memory job create")
        ),
        stats=stats_ms(samples),
    )


async def scenario_same_key_burst(service: McpToolService) -> Result:
    async def burst() -> dict[str, Any]:
        start = time.perf_counter()
        results = await asyncio.gather(
            *(
                service.call(
                    tool_name=ENUMERATE,
                    arguments=arguments(),
                    request_meta=meta_for(0, prefix="burst"),
                    mcp_session_id="bench-burst",
                )
                for _ in range(100)
            )
        )
        wall = time.perf_counter() - start
        jobs = {result.structured_content["job_id"] for result in results}
        decisions = sorted(result.structured_content["decision"] for result in results)
        return {
            "calls": len(results),
            "distinct_job_ids": len(jobs),
            "approved": decisions.count("approved"),
            "duplicate": decisions.count("duplicate"),
            "wall_ms": round(wall * 1000, 2),
            "jobs_in_registry": len(service.registry.jobs),
        }

    extra = await burst()
    return Result(
        name="same_idempotency_key_burst_100",
        description="100 concurrent tools/call with one idempotency_key (NFR-02 case, fake registry)",
        stats={},
        extra=extra,
    )


async def scenario_sse(url: str, iterations: int) -> Result:
    samples = []
    async with connected(url) as session:
        for step in range(20):
            await call_capability(session, ENUMERATE, arguments(), meta_for(step, prefix="sse-warm"))
        for step in range(iterations):
            start = time.perf_counter()
            await call_capability(session, ENUMERATE, arguments(), meta_for(step, prefix="sse"))
            samples.append(time.perf_counter() - start)
    return Result(
        name="tools/call_http_sse",
        description="tools/call over Streamable HTTP with SSE framed responses",
        stats=stats_ms(samples),
    )


def environment() -> dict[str, Any]:
    import importlib.metadata as metadata

    def version(name: str) -> str:
        try:
            return metadata.version(name)
        except metadata.PackageNotFoundError:  # pragma: no cover
            return "not-installed"

    cpu = "unknown"
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:  # pragma: no cover
        pass
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "host": platform.node(),
        "platform": platform.platform(),
        "cpu": cpu,
        "cpu_count": os_cpu_count(),
        "python": sys.version.split()[0],
        "packages": {
            name: version(name)
            for name in ("mcp", "mcp-types", "jsonschema", "uvicorn", "starlette", "httpx2", "anyio")
        },
        "providers": 100,
        "capabilities": sorted(contracts.CAPABILITY_SCHEMAS),
        "transport": "Streamable HTTP, stateful session, localhost",
    }


def os_cpu_count() -> int:
    import os

    return os.cpu_count() or 0


async def run(iterations: int, concurrent_calls: int, concurrency: int) -> dict[str, Any]:
    registry = FakeRegistry.with_providers()
    registry.sessions.register(SessionContext(CAMPAIGN_ID, SESSION_ID, SCAN_CYCLE))
    mcp = McpToolService(registry=registry)

    results: list[Result] = []
    results.append(await _run_http(mcp, scenario_tools_list, iterations))
    results.append(await _run_http(mcp, scenario_call_http, iterations))
    results.append(await _run_http(mcp, scenario_call_http_concurrent, concurrent_calls, concurrency))
    results.append(await _run_http(mcp, scenario_sse, iterations, json_response=False))
    results.append(await scenario_handler(mcp, iterations * 10, prefix="handler"))
    results.append(await scenario_handler(mcp, iterations * 10, write_latency=0.005, prefix="handler-write"))
    results.append(await scenario_same_key_burst(mcp))

    for result in results:
        print(
            f"{result.name:52s} "
            + (
                f"p50={result.stats['p50_ms']:7.3f}ms p95={result.stats['p95_ms']:7.3f}ms "
                f"p99={result.stats['p99_ms']:7.3f}ms max={result.stats['max_ms']:8.3f}ms n={result.stats['n']}"
                if result.stats
                else json.dumps(result.extra)
            )
        )

    return {
        "environment": environment(),
        "nfr_04_target": {
            "metric": "registry P95 < 300 ms with 100 providers",
            "target_p95_ms": NFR04_TARGET_MS,
            "note": "fake in-memory registry; no PostgreSQL, no network to data services",
        },
        "results": [
            {
                "name": result.name,
                "description": result.description,
                "stats": result.stats,
                "extra": result.extra,
                "passes_target": result.passes_target() if result.stats else None,
            }
            for result in results
        ],
    }


async def _run_http(service: McpToolService, scenario, *args, json_response: bool = True) -> Result:
    box: dict[str, Result] = {}

    async def body(url: str) -> None:
        box["result"] = await scenario(url, *args)

    await with_server(service, body, json_response=json_response)
    return box["result"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=500)
    parser.add_argument("--concurrent-calls", type=int, default=500)
    parser.add_argument("--concurrency", type=int, default=16)
    parser.add_argument("--out", type=Path, default=RESULT_OUT)
    args = parser.parse_args()
    payload = asyncio.run(run(args.iterations, args.concurrent_calls, args.concurrency))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
