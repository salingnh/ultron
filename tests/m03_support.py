"""Shared support for the M03 (G1.2c) tests: the seams, with the real M05 boundary behind them.

Two kinds of double, and the difference matters for what the tests prove:

* **The tool client double is only a transport double.** `InProcessToolClient` drives the real
  `McpToolService` (the same catalogue, the same `tools/list` filtering, the same acceptance path,
  the same idempotency rules) and interprets its answers with the same parsers the HTTP client uses.
  So a session test exercises M03's real MCP interaction, not a hand-written fake of it.
* **The rest are in-memory ports**: the agent_session store, the ledger, the context read model and
  the model client. They are small because their real implementations are exercised by the
  PostgreSQL/MCP integration module.

The scripted model answers are contract `model-response.v2` payloads, so the loop validates them the
way it validates a provider answer (M04's `FakeModelClient` does the budget/usage/contract work).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, cast

from langgraph.checkpoint.memory import InMemorySaver
from mcp.shared.exceptions import MCPError

from aegis.common.ports import ToolInfo
from aegis.contracts_gen.agent.model_response_v2_schema import FinishReason, ModelResponse
from aegis.m02_orchestrator.types import SessionRequest
from aegis.m03_agent.config import SessionConfig
from aegis.m03_agent.context import CampaignContext
from aegis.m03_agent.mcp import (
    CallMeta,
    ToolClient,
    ToolOutcome,
    parse_capability_result,
    parse_graph_result,
)
from aegis.m03_agent.session import SessionDeps
from aegis.m03_agent.store import SessionRef
from aegis.m05_registry.mcp.service import McpToolService
from aegis.m05_registry.mcp.session import SessionContext, SessionDirectory
from tests.mcp_support import (
    CAMPAIGN_ID,
    ENUMERATE,
    OBJECTIVE_ID,
    RESOLVE,
    FakeGraphQueries,
    FakeJobService,
    registry,
)

__all__ = [
    "CAMPAIGN_ID",
    "ENUMERATE",
    "OBJECTIVE_ID",
    "RESOLVE",
    "FakeContext",
    "InMemoryLedger",
    "InMemoryStore",
    "InProcessToolClient",
    "PermissiveSessions",
    "decision_response",
    "deps_for",
    "fake_model",
    "graph_answers",
    "job_store",
    "scripted_model",
    "session_request",
    "tool_call_response",
]

SESSION_LABEL = f"{CAMPAIGN_ID}:cycle-0"
SESSION_ID = "01934f6a-0000-7000-8000-0000000000aa"
OTHER_SESSION_ID = "01934f6a-0000-7000-8000-0000000000ab"
TRACE_ID = "0123456789abcdef0123456789abcdef"


def session_request(
    *,
    campaign_id: str = CAMPAIGN_ID,
    session_id: str = SESSION_LABEL,
    cycle: int = 0,
    cursor: int = 0,
    objective: str = "Discover the lab domain's subdomains and resolve them",
) -> SessionRequest:
    return SessionRequest(
        campaign_id=campaign_id,
        session_id=session_id,
        cycle=cycle,
        cursor=cursor,
        objective=objective,
    )


class PermissiveSessions(SessionDirectory):
    """Accepts any `(campaign, session)` the test opened, with the objective it was told about."""

    def __init__(self, objective_id: str = OBJECTIVE_ID) -> None:
        self.objective_id = objective_id
        self.resolved: list[SessionContext] = []

    def resolve(
        self, transport_session_id: str | None, *, campaign_id: str, session_id: str
    ) -> tuple[SessionContext | None, str | None]:
        del transport_session_id
        context = SessionContext(
            campaign_id=campaign_id,
            session_id=session_id,
            scan_cycle=session_id,
            objective_id=self.objective_id,
        )
        self.resolved.append(context)
        return context, None

    def bound(self, transport_session_id: str | None) -> SessionContext | None:
        del transport_session_id
        return None


def graph_answers(
    *, observations: Sequence[Mapping[str, Any]] = (), revision: int = 0
) -> FakeGraphQueries:
    """A projection stand-in that answers the one query `build_context` asks."""
    return FakeGraphQueries(
        answers={
            "get_recent_observations": (
                {"observations": [dict(item) for item in observations], "revision": revision},
                False,
            )
        }
    )


def service(
    *,
    graph: Any | None = None,
    jobs: FakeJobService | None = None,
    sessions: SessionDirectory | None = None,
    denylists: Mapping[str, frozenset[str]] | None = None,
) -> McpToolService:
    """The real M05 MCP boundary with in-memory job/session/policy sources."""
    from aegis.m05_registry.mcp.campaign import InMemoryCampaignPolicies

    return McpToolService(
        registry=registry(),
        jobs=jobs or FakeJobService(),
        sessions=sessions or PermissiveSessions(),
        policies=InMemoryCampaignPolicies(denylists or {}),
        graph=graph if graph is not None else graph_answers(),
    )


class InProcessToolClient:
    """`ToolClient` over the real `McpToolService`; only the HTTP transport is left out."""

    def __init__(
        self,
        tool_service: McpToolService,
        *,
        fail_on_call: int | None = None,
        fail_after_call: int | None = None,
        fail_on_close: bool = False,
        error: BaseException | None = None,
    ) -> None:
        self.service = tool_service
        self.calls: list[tuple[str, Mapping[str, Any], CallMeta]] = []
        self.graph_calls: list[tuple[str, Mapping[str, Any], CallMeta]] = []
        self.closed = False
        self._fail_on_call = fail_on_call
        self._fail_after_call = fail_after_call
        self._fail_on_close = fail_on_close
        self._error = error or RuntimeError("simulated worker part-way through the session")

    async def list_tools(self, meta: CallMeta) -> list[ToolInfo]:
        # the server's own `tools/list` arm: the campaign's denylist and the session binding apply
        listed = self.service.list_tools(request_meta=meta.as_meta(), mcp_session_id=None)
        return [
            ToolInfo(
                name=tool.name,
                description=tool.description or "",
                input_schema=dict(tool.input_schema or {}),
            )
            for tool in listed.tools
        ]

    async def call_capability(
        self, tool: str, arguments: Mapping[str, Any], *, meta: CallMeta
    ) -> ToolOutcome:
        self.calls.append((tool, dict(arguments), meta))
        if self._fail_on_call is not None and len(self.calls) == self._fail_on_call:
            raise self._error
        try:
            result = self.service.call(
                tool_name=tool,
                arguments=dict(arguments),
                request_meta=meta.as_meta(),
                mcp_session_id=None,
            )
        except MCPError as error:
            data = error.data if isinstance(error.data, dict) else {}
            return ToolOutcome(
                tool=tool,
                error_code=str(data.get("code") or "INPUT_INVALID"),
                detail=str(data.get("message") or error.message),
                text=error.message,
                request_refused=True,
            )
        if self._fail_after_call is not None and len(self.calls) == self._fail_after_call:
            # the server accepted the call, the answer never arrived (a lost response, a killed
            # worker): only the idempotency key can keep this to one job
            raise self._error
        return parse_capability_result(tool, result)

    async def query_graph(
        self, query: str, inputs: Mapping[str, Any], *, meta: CallMeta
    ) -> ToolOutcome:
        name = query if query.startswith("graph.") else f"graph.{query}"
        self.graph_calls.append((name, dict(inputs), meta))
        result = self.service.call(
            tool_name=name,
            arguments=dict(inputs),
            request_meta=meta.as_meta(),
            mcp_session_id=None,
        )
        return parse_graph_result(name, result)

    async def aclose(self) -> None:
        self.closed = True
        if self._fail_on_close:
            # the graph finished but the activity died before the result was written
            raise self._error

    # helpers the tests read
    @property
    def job_store(self) -> FakeJobService:
        return cast(FakeJobService, self.service.jobs)


def fake_model(deps: SessionDeps) -> Any:
    """The scripted M04 client a test built (its `calls`/`usage` are the record of what it saw)."""
    from aegis.m04_model.fake import FakeModelClient

    return cast(FakeModelClient, deps.model)


def job_store(service_: McpToolService) -> FakeJobService:
    """The in-memory M05 job store behind a `McpToolService` (a `JobService` at the seam)."""
    return cast(FakeJobService, service_.jobs)


def tool_client(
    client: InProcessToolClient,
) -> Callable[[], AbstractAsyncContextManager[ToolClient]]:
    @asynccontextmanager
    async def _open() -> AsyncIterator[ToolClient]:
        try:
            yield client
        finally:
            await client.aclose()

    return _open


class InMemoryLedger:
    """`campaign_ledger` in a list, with the same newest-first `find` semantics."""

    def __init__(self) -> None:
        self.entries_by_campaign: dict[str, list[dict[str, Any]]] = {}
        self.seq = 0

    def append(self, campaign_id: str, kind: str, payload: Mapping[str, Any]) -> int:
        self.seq += 1
        self.entries_by_campaign.setdefault(campaign_id, []).append(
            {"seq": self.seq, "kind": kind, "payload": dict(payload)}
        )
        return self.seq

    def find(
        self, campaign_id: str, kind: str, *, match: Mapping[str, Any]
    ) -> dict[str, Any] | None:
        for entry in reversed(self.entries_by_campaign.get(campaign_id, [])):
            if entry["kind"] != kind:
                continue
            if all(entry["payload"].get(key) == value for key, value in match.items()):
                return entry
        return None

    def entries(
        self, campaign_id: str, *, kinds: tuple[str, ...], limit: int = 20
    ) -> list[dict[str, Any]]:
        selected = [
            entry
            for entry in self.entries_by_campaign.get(campaign_id, [])
            if entry["kind"] in kinds
        ]
        return selected[-limit:]

    def kinds(self, campaign_id: str) -> list[str]:
        return [entry["kind"] for entry in self.entries_by_campaign.get(campaign_id, [])]


class InMemoryStore:
    """`agent_session` + its ledger link, with the idempotency the real store gets from it."""

    def __init__(self, ledger: InMemoryLedger) -> None:
        self.ledger = ledger
        self.rows: dict[str, dict[str, Any]] = {}
        self.opened = 0
        self.session_id = ""

    def _next_session_id(self) -> str:
        """A fresh UUIDv7-shaped id per session label (the real store mints one per cycle)."""
        return f"01934f6a-0000-7000-8000-{0xAA + len(self.rows):012d}"

    def open(
        self, request: SessionRequest, *, revision_from: int, max_sessions: int | None = None
    ) -> SessionRef:
        del max_sessions
        found = self.ledger.find(
            request.campaign_id, "cycle_started", match={"workflow_session": request.session_id}
        )
        if found is not None:
            session_id = str(found["payload"]["session_id"])
            row = self.rows[session_id]
            return SessionRef(
                session_id=session_id,
                campaign_id=request.campaign_id,
                objective_id=row["objective_id"],
                policy_version=row["policy_version"],
                cycle=request.cycle,
                status=row["status"],
                created=False,
                workflow_session=request.session_id,
            )
        self.opened += 1
        session_id = self._next_session_id()
        self.session_id = session_id
        row = {
            "session_id": session_id,
            "campaign_id": request.campaign_id,
            "objective_id": OBJECTIVE_ID,
            "policy_version": "roe-10",
            "status": "RUNNING",
            "decision": None,
            "stop_reason": None,
            "steps_used": 0,
            "result": None,
            "revision_from": revision_from,
        }
        self.rows[session_id] = row
        self.ledger.append(
            request.campaign_id,
            "cycle_started",
            {
                "workflow_session": request.session_id,
                "session_id": session_id,
                "cycle": request.cycle,
            },
        )
        return SessionRef(
            session_id=session_id,
            campaign_id=request.campaign_id,
            objective_id=OBJECTIVE_ID,
            policy_version="roe-10",
            cycle=request.cycle,
            status="RUNNING",
            created=True,
            workflow_session=request.session_id,
        )

    def finish(
        self,
        ref: SessionRef,
        *,
        status: str,
        decision: str,
        stop_reason: str | None,
        steps_used: int,
        result: Mapping[str, Any],
        cursor: int = 0,
        idle: bool = False,
        detail: str | None = None,
    ) -> bool:
        row = self.rows[ref.session_id]
        if row["status"] != "RUNNING":
            return False
        row.update(
            {
                "status": status,
                "decision": decision,
                "stop_reason": stop_reason,
                "steps_used": steps_used,
                "result": dict(result),
            }
        )
        self.ledger.append(
            ref.campaign_id,
            "cycle_finished",
            {
                "workflow_session": ref.workflow_session,
                "session_id": ref.session_id,
                "cycle": ref.cycle,
                "status": status,
                "decision": decision,
                "stop_reason": stop_reason,
                "steps_used": steps_used,
                "cursor": cursor,
                "idle": idle,
                "detail": detail,
                "requested_jobs": list(result.get("requested_jobs") or []),
                "denied": list(result.get("denied") or []),
                "usage": dict(result.get("usage") or {}),
            },
        )
        ref.status = status
        return True

    def finished_outcome(self, ref: SessionRef) -> dict[str, Any] | None:
        found = self.ledger.find(
            ref.campaign_id, "cycle_finished", match={"session_id": ref.session_id}
        )
        return None if found is None else dict(found["payload"])


class FakeContext:
    """`ContextSource` over a dict; `load` records the cursor it was asked for."""

    def __init__(
        self,
        *,
        observations: Sequence[Mapping[str, Any]] = (),
        jobs: Sequence[Mapping[str, Any]] = (),
        targets: Sequence[Mapping[str, Any]] = (),
        policy: Mapping[str, Any] | None = None,
        spent_tokens: int = 0,
        spent_cost_usd: float = 0.0,
        graph_revision: int = 0,
        campaign_id: str = CAMPAIGN_ID,
        objective_text: str = "Discover the lab domain's subdomains and resolve them",
    ) -> None:
        self.campaign_id = campaign_id
        self.objective_text = objective_text
        self.observations = tuple(observations)
        self.jobs = tuple(jobs)
        self.targets = tuple(targets)
        self.policy = dict(
            policy
            or {
                "budget": {"max_llm_tokens": 100000, "max_llm_cost_usd": 5.0},
                "max_parallel_jobs": 2,
                "rate_limits": {"jobs_per_minute": 30},
            }
        )
        self.spent_tokens = spent_tokens
        self.spent_cost_usd = spent_cost_usd
        self.graph_revision = graph_revision
        self.cursors: list[int] = []

    def load(self, campaign_id: str, *, cursor: int) -> CampaignContext:
        self.cursors.append(cursor)
        return CampaignContext(
            campaign_id=campaign_id,
            objective_text=self.objective_text,
            policy_version="roe-10",
            policy=self.policy,
            graph_revision=self.graph_revision,
            targets=self.targets,
            observations=self.observations,
            jobs=self.jobs,
            spent_tokens=self.spent_tokens,
            spent_cost_usd=self.spent_cost_usd,
            idle_cycles=0,
        )


@dataclass
class Deps:
    """What `deps_for` built, for assertions."""

    deps: SessionDeps
    store: InMemoryStore
    ledger: InMemoryLedger
    client: InProcessToolClient
    context: FakeContext
    saver: InMemorySaver = field(default_factory=InMemorySaver)


def deps_for(
    *,
    responses: Sequence[ModelResponse] = (),
    context: FakeContext | None = None,
    tool_service: McpToolService | None = None,
    fail_on_call: int | None = None,
    config: SessionConfig | None = None,
    store: InMemoryStore | None = None,
    ledger: InMemoryLedger | None = None,
    model: Any | None = None,
) -> Deps:
    """A `SessionDeps` whose only real parts are the M05 boundary and the loop itself."""
    from aegis.m04_model.fake import FakeModelClient

    resolved_ledger = ledger or InMemoryLedger()
    resolved_store = store or InMemoryStore(resolved_ledger)
    client = InProcessToolClient(tool_service or service(), fail_on_call=fail_on_call)
    resolved_context = context or FakeContext()
    saver = InMemorySaver()

    @asynccontextmanager
    async def _checkpointer() -> AsyncIterator[Any]:
        yield saver

    resolved_model = model or FakeModelClient(responses=list(responses))
    deps = SessionDeps(
        config=config
        or SessionConfig(model="scripted-test", max_steps=6, in_session_idle_rounds=2),
        dsn="postgresql://unused/unused",
        context=resolved_context,
        tools=tool_client(client),
        model=resolved_model,
        store=resolved_store,
        ledger=resolved_ledger,
        checkpointer=_checkpointer,
    )
    return Deps(
        deps=deps,
        store=resolved_store,
        ledger=resolved_ledger,
        client=client,
        context=resolved_context,
        saver=saver,
    )


def tool_call_response(
    tool: str,
    arguments: Mapping[str, Any],
    *,
    call_id: str = "call-0001",
    text: str = "proposing a capability",
) -> ModelResponse:
    """A valid `model-response.v2` answer that proposes one capability call."""
    return ModelResponse.model_validate(
        {
            "provider": "openai",
            "model": "scripted-test",
            "message": {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": text},
                    {
                        "type": "tool_call",
                        "call": {
                            "id": call_id,
                            "name": tool,
                            "arguments": dict(arguments),
                            "arguments_raw": "{}",
                        },
                    },
                ],
            },
            "finish_reason": FinishReason.tool_calls,
            "provider_meta": {
                "provider": "openai",
                "response_id": "resp-1",
                "raw_finish_reason": "tool_calls",
            },
            "usage": {"input_tokens": 10, "output_tokens": 20, "cost_usd": 0.001, "latency_ms": 3},
        }
    )


def decision_response(
    decision: str = "stop", summary: str = "objective met", *, cost_usd: float = 0.001
) -> ModelResponse:
    """A valid `model-response.v2` answer that answers with the plan decision object."""
    return ModelResponse.model_validate(
        {
            "provider": "openai",
            "model": "scripted-test",
            "message": {
                "role": "assistant",
                "content": [{"type": "text", "text": summary}],
            },
            "parsed": {"decision": decision, "summary": summary},
            "finish_reason": FinishReason.completed,
            "provider_meta": {
                "provider": "openai",
                "response_id": "resp-decision",
                "raw_finish_reason": "stop",
            },
            "usage": {
                "input_tokens": 5,
                "output_tokens": 7,
                "cost_usd": cost_usd,
                "latency_ms": 2,
            },
        }
    )


def scripted_model(responses: Sequence[ModelResponse]) -> Callable[[], Any]:
    """A factory of a fresh `FakeModelClient` per test (its script is a fixed sequence)."""
    from aegis.m04_model.fake import FakeModelClient

    return lambda: FakeModelClient(responses=list(responses))


def capability_arguments(**overrides: Any) -> dict[str, Any]:
    """Valid `capability-request.v2` arguments for `dns.enumerate_subdomains`."""
    value: dict[str, Any] = {
        "input": {"targets": ["internal.example"]},
        "rationale": "Enumerate the lab domain's subdomains for the campaign objective",
    }
    value.update(overrides)
    return value


def run(coroutine: Any) -> Any:
    """Drive one async call from a sync test (the gate runs tests without an async plugin)."""
    return asyncio.run(coroutine)
