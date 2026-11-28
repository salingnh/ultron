"""Shared support for the MCP boundary tests (G1.2b): fakes, fixtures and a throwaway server.

The transport tests drive the real Streamable HTTP app over loopback (uvicorn on port 0); the
service tests drive `McpToolService` directly. Both use the same fakes here, so a transport test
never depends on PostgreSQL and a database test never depends on uvicorn.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import LATEST_PROTOCOL_VERSION
from pydantic import RootModel

from aegis.contracts_gen.capability.job_submit_v2_schema import JobSubmit
from aegis.m05_registry.errors import M05Error
from aegis.m05_registry.mcp.campaign import InMemoryCampaignPolicies
from aegis.m05_registry.mcp.graph import GraphLimits, GraphQueryResult, GraphQueryService
from aegis.m05_registry.mcp.server import build_app
from aegis.m05_registry.mcp.service import McpToolService
from aegis.m05_registry.mcp.session import InMemorySessionDirectory, SessionContext
from aegis.m05_registry.registry import InMemoryManifestRegistry
from aegis.m05_registry.service import TERMINAL_STATUSES, JobPage
from tests.support import REPO_ROOT

CAMPAIGN_ID = "01934f6a-0000-7000-8000-000000000001"
OTHER_CAMPAIGN_ID = "01934f6a-0000-7000-8000-000000000002"
SESSION_ID = "01934f6a-0000-7000-8000-000000000003"
OTHER_SESSION_ID = "01934f6a-0000-7000-8000-000000000004"
OBJECTIVE_ID = "01934f6a-0000-7000-8000-000000000005"
FOREIGN_SESSION_ID = "01934f6a-0000-7000-8000-000000000006"
OTHER_OBJECTIVE_ID = "01934f6a-0000-7000-8000-000000000007"
TRACE_ID = "0123456789abcdef0123456789abcdef"
# The campaign run's operator (what M05 derives as `requested_by` for an agent-proposed job).
RUN_OPERATOR: dict[str, str] = {"kind": "operator", "id": "op-g12b"}

# The SDK's own reserved `_meta` keys: the 2.3.0 server refuses a request `_meta` without them, so
# a hand-rolled wire request must send them next to the `aegis.io/*` keys.
ENVELOPE_META: dict[str, Any] = {
    "io.modelcontextprotocol/protocolVersion": LATEST_PROTOCOL_VERSION,
    "io.modelcontextprotocol/clientCapabilities": {},
}

ENUMERATE = "dns.enumerate_subdomains"
RESOLVE = "dns.resolve"
DISCOVER = "network.discover_services"
GRAPH_TOOLS = (
    "graph.get_asset_neighbors",
    "graph.get_evidence_excerpt",
    "graph.get_package_cve_matches",
    "graph.get_recent_observations",
    "graph.get_unverified_hypotheses",
    "graph.summarize_campaign_delta",
)

MANIFESTS = (
    "manifest.subfinder.yaml",
    "manifest.dnsx.yaml",
    "manifest.naabu.yaml",
    "manifest.fingerprintx.yaml",
    "manifest.httpx.yaml",
    "manifest.trivy.yaml",
    "manifest.syft.yaml",
    "manifest.grype.yaml",
)
PROVIDERS = {
    ENUMERATE: "subfinder",
    RESOLVE: "dnsx",
    DISCOVER: "naabu",
    "service.fingerprint": "fingerprintx",
    "web.probe_http": "httpx",
    "vuln.scan_artifact": "trivy",
    "sbom.generate": "syft",
}


def manifest_bytes() -> list[bytes]:
    return [(REPO_ROOT / "contracts/fixtures/valid" / name).read_bytes() for name in MANIFESTS]


def plain(value: Any) -> Any:
    """Unwrap generated `RootModel` ids into the plain JSON values (as M05 does)."""
    if isinstance(value, RootModel):
        return plain(value.root)
    if isinstance(value, (list, tuple)):
        return [plain(item) for item in value]
    if isinstance(value, dict):
        return {key: plain(item) for key, item in value.items()}
    return value


def meta(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "aegis.io/trace_id": TRACE_ID,
        "aegis.io/campaign_id": CAMPAIGN_ID,
        "aegis.io/session_id": SESSION_ID,
        "aegis.io/idempotency_key": f"{SESSION_ID}:step:1",
    }
    value.update(overrides)
    return value


def arguments(**overrides: Any) -> dict[str, Any]:
    """Valid `capability-request.v2` arguments for `dns.enumerate_subdomains`."""
    value: dict[str, Any] = {
        "input": {"targets": ["internal.example"]},
        "rationale": "Enumerate the lab domain's subdomains for the campaign objective",
        "objective_id": OBJECTIVE_ID,
    }
    value.update(overrides)
    return value


def graph_arguments(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {"campaign_id": CAMPAIGN_ID}
    value.update(overrides)
    return value


@dataclass
class FakeJobService:
    """The `JobService` seam with M05's idempotence and E-4 rules, without a database."""

    refusals: dict[str, M05Error] = field(default_factory=dict)
    run_initiator: Mapping[str, str] = field(default_factory=lambda: dict(RUN_OPERATOR))
    jobs: dict[str, dict[str, Any]] = field(default_factory=dict)
    submissions: list[dict[str, Any]] = field(default_factory=list)
    _by_key: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)

    def submit(
        self,
        request: JobSubmit,
        *,
        requested_by: Mapping[str, str] | None,
        idempotency_key: str,
        proposed_by: Mapping[str, str] | None = None,
        trace_id: str | None = None,
    ) -> Any:
        from aegis.m05_registry.service import SubmitOutcome

        capability = str(plain(request.capability))
        provider = (
            PROVIDERS[capability] if request.provider is None else str(plain(request.provider))
        )
        campaign = str(plain(request.campaign_id))
        actor = dict(self.run_initiator) if requested_by is None else dict(requested_by)
        body_hash = hashlib.sha256(
            json.dumps(
                plain(request.model_dump(mode="json", exclude_none=True)), sort_keys=True
            ).encode()
        ).hexdigest()
        key = (campaign, idempotency_key)
        stored = self._by_key.get(key)
        if stored is not None:
            if stored["session"] != (None if proposed_by is None else proposed_by["id"]):
                raise M05Error.idempotency_conflict(
                    "Idempotency-Key belongs to another session; a key is not transferable"
                )
            if stored["body_hash"] != body_hash:
                raise M05Error.idempotency_conflict(
                    "Idempotency-Key was first used for a different request body"
                )
            return SubmitOutcome(job=stored["job"], replayed=True, decision_id=stored["decision"])
        refusal = self.refusals.get(capability)
        if refusal is not None:
            raise refusal
        job_id = f"01934f6a-0000-7000-8000-{len(self.jobs) + 100:012d}"
        job: dict[str, Any] = {
            "job_id": job_id,
            "campaign_id": campaign,
            "capability": capability,
            "provider": provider,
            "status": "QUEUED",
            "policy_version": "roe-1",
            "requested_by": actor,
            "proposed_by": None if proposed_by is None else dict(proposed_by),
            "priority": 50,
            "depends_on": [],
        }
        self.jobs[job_id] = job
        self._by_key[key] = {
            "body_hash": body_hash,
            "job": job,
            "decision": f"01934f6a-0000-7000-8000-{len(self.jobs) + 900:012d}",
            "session": None if proposed_by is None else proposed_by["id"],
        }
        self.submissions.append(
            {
                "campaign_id": campaign,
                "capability": capability,
                "provider": provider,
                "idempotency_key": idempotency_key,
                "requested_by": actor,
                "proposed_by": None if proposed_by is None else dict(proposed_by),
                "trace_id": trace_id,
            }
        )
        return SubmitOutcome(job=job, replayed=False, decision_id=self._by_key[key]["decision"])

    def get_job(self, job_id: str) -> dict[str, Any]:
        try:
            return self.jobs[job_id]
        except KeyError as error:
            raise M05Error.not_found(f"job {job_id} does not exist") from error

    def list_jobs(
        self,
        *,
        campaign_id: str,
        status: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> JobPage:
        items = tuple(job for job in self.jobs.values() if job["status"] not in TERMINAL_STATUSES)
        return JobPage(items=items, next_cursor=None)

    def cancel(
        self, job_id: str, *, requested_by: Mapping[str, str], reason: str | None = None
    ) -> dict[str, Any]:
        return self.get_job(job_id)


@dataclass
class FakeGraphQueries:
    """A projection stand-in: returns fixed data and records the limits it was handed."""

    answers: dict[str, tuple[Mapping[str, Any], bool]] = field(default_factory=dict)
    calls: list[dict[str, Any]] = field(default_factory=list)

    def run(
        self,
        query: str,
        inputs: Mapping[str, Any],
        *,
        campaign_id: str,
        limits: GraphLimits,
    ) -> GraphQueryResult:
        self.calls.append({"query": query, "inputs": dict(inputs), "limits": limits.as_json()})
        data, truncated = self.answers.get(query, ({}, False))
        return GraphQueryResult(data=data, truncated=truncated)


def registry() -> InMemoryManifestRegistry:
    value = InMemoryManifestRegistry()
    for raw in manifest_bytes():
        value.register(raw, registered_by={"kind": "module", "id": "M05"})
    return value


def sessions() -> InMemorySessionDirectory:
    directory = InMemorySessionDirectory()
    for campaign_id, session_id, objective in (
        (CAMPAIGN_ID, SESSION_ID, OBJECTIVE_ID),
        (CAMPAIGN_ID, OTHER_SESSION_ID, OTHER_OBJECTIVE_ID),
        (OTHER_CAMPAIGN_ID, FOREIGN_SESSION_ID, OTHER_OBJECTIVE_ID),
    ):
        directory.register(
            SessionContext(
                campaign_id=campaign_id,
                session_id=session_id,
                scan_cycle=session_id,
                objective_id=objective,
            )
        )
    return directory


def make_service(
    *,
    denylists: Mapping[str, frozenset[str]] | None = None,
    graph: GraphQueryService | None = None,
    jobs: FakeJobService | None = None,
    manifest_registry: InMemoryManifestRegistry | None = None,
) -> McpToolService:
    return McpToolService(
        registry=manifest_registry if manifest_registry is not None else registry(),
        jobs=jobs or FakeJobService(),
        sessions=sessions(),
        policies=InMemoryCampaignPolicies(denylists or {}),
        graph=graph or FakeGraphQueries(),
    )


@asynccontextmanager
async def serve(service: McpToolService, *, json_response: bool = True) -> AsyncIterator[str]:
    """Run the Streamable HTTP app on a loopback port and yield its `/mcp` URL."""
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
        for _ in range(1000):
            if server.started:
                break
            if task.done():
                await task
                raise RuntimeError("uvicorn exited before startup")
            await asyncio.sleep(0.01)
        else:  # pragma: no cover - startup regression
            raise RuntimeError("uvicorn did not start")
        sockets = server.servers[0].sockets
        port = sockets[0].getsockname()[1]
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        server.should_exit = True
        await task


@asynccontextmanager
async def connected(url: str) -> AsyncIterator[ClientSession]:
    """An SDK client session (the real client an agent uses)."""
    async with streamable_http_client(url) as streams:
        async with ClientSession(streams[0], streams[1]) as session:
            await session.initialize()
            yield session


@dataclass(frozen=True)
class WireSession:
    """A hand-rolled MCP session so a test can assert the raw JSON-RPC body/headers."""

    url: str
    session_id: str

    @property
    def headers(self) -> dict[str, str]:
        return {
            "content-type": "application/json",
            "accept": "application/json, text/event-stream",
            "mcp-session-id": self.session_id,
            "mcp-protocol-version": LATEST_PROTOCOL_VERSION,
        }


@asynccontextmanager
async def wire_session(url: str, *, client: Any) -> AsyncIterator[WireSession]:
    response = await client.post(
        url,
        headers={
            "content-type": "application/json",
            "accept": "application/json, text/event-stream",
        },
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": LATEST_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "g1.2b-tests", "version": "0.1.0"},
            },
        },
    )
    response.raise_for_status()
    session_id = response.headers.get("mcp-session-id")
    if session_id is None:  # pragma: no cover - transport regression
        raise RuntimeError("server did not return an Mcp-Session-Id header")
    session = WireSession(url=url, session_id=session_id)
    await client.post(
        url,
        headers=session.headers,
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
    )
    yield session


def wire_headers(session: WireSession, method: str, params: Mapping[str, Any]) -> dict[str, str]:
    """Session headers plus the per-message headers protocol 2026-07-28 requires."""
    headers = dict(session.headers)
    headers["mcp-method"] = method
    name = params.get("name")
    if isinstance(name, str):
        headers["mcp-name"] = name
    return headers


async def wire_request(
    client: Any,
    session: WireSession,
    method: str,
    params: Mapping[str, Any],
    *,
    request_id: int = 2,
) -> dict[str, Any]:
    response = await client.post(
        session.url,
        headers=wire_headers(session, method, params),
        json={"jsonrpc": "2.0", "id": request_id, "method": method, "params": dict(params)},
    )
    # The 2.3.0 transport answers a JSON-RPC error with HTTP 400; both are protocol answers.
    assert response.status_code in {200, 400}, response.text
    body: dict[str, Any] = response.json()
    return body


def seed_agent_session(
    dsn: str,
    campaign_id: str,
    session_id: str,
    *,
    policy_version: str,
    objective_id: str | None = None,
    status: str = "RUNNING",
) -> None:
    """Insert one `agent_session` row (the authority `PostgresSessionDirectory` reads)."""
    import psycopg
    from psycopg.types.json import Jsonb

    with psycopg.connect(dsn) as conn, conn.transaction():
        if objective_id is not None:
            # `agent_session.objective_id` is a foreign key: the objective must be a real row.
            conn.execute(
                "INSERT INTO objective (objective_id, campaign_id, text, created_by) "
                "VALUES (%s, %s, %s, %s) ON CONFLICT (objective_id) DO NOTHING",
                (
                    objective_id,
                    campaign_id,
                    "prove the MCP boundary",
                    Jsonb({"kind": "operator", "id": "op-g12b"}),
                ),
            )
        conn.execute(
            "INSERT INTO agent_session (session_id, campaign_id, objective_id, policy_version, "
            "revision_from, status) VALUES (%s, %s, %s, %s, 0, %s)",
            (session_id, campaign_id, objective_id, policy_version, status),
        )
