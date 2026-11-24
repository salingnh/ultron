"""One `run_agent_session` call: open the session row, run the graph, record the contract result.

This is the temporal-free half of the activity (the activity in `activities.py` only adds heartbeat
and Configuration). The order is the card's acceptance:

1. **Open (or find) the session row** - `agent_session` is what the MCP server checks, so it exists
   and is `RUNNING` before any tool call. The mapping from M02's label to that row lives in the
   ledger, so a retried activity call resumes the same LangGraph thread instead of opening a second
   session (`store.py` for the reasoning).
2. **Resume from the checkpoint when there is one** - `graph.aget_state(thread_id).next` means a
   worker died inside the graph; `ainvoke(None)` continues at the next node with the state the
   previous attempt committed. A finished checkpoint (state present, nothing next) is the "crashed
   after the last node, before the result was written" case and is recorded, not re-run.
3. **Finish once** - `agent_session.result` gets the contract `session-result.v2`,
   `steps_used`/`decision`/`stop_reason` are the row's status columns, and the ledger gets
   `cycle_finished` (the outcome a retried call is answered from), `idle_cycle` (so M02's pause
   threshold sees it), `stop_condition` and `budget`.
4. **Cancel** - the campaign's cancel signal cancels this activity; the session row is finalised
   `CANCELLED`/`stop_reason=operator` from the last committed node state before the failure
   propagates (M02 waits for exactly that: `WAIT_CANCELLATION_COMPLETED`).

`AgentSessionResult.requested_jobs` only ever holds the MCP job ids this session received - M03 has
no fallback dispatch path, so there is nothing else it could report.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import psycopg
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from aegis import validation
from aegis.common.ports import ModelClient
from aegis.contracts_gen.agent.session_result_v2_schema import (
    Decision,
    SessionResult,
    StopReason,
)
from aegis.m02_orchestrator.types import SessionOutcome, SessionRequest
from aegis.m03_agent.config import SessionConfig
from aegis.m03_agent.context import ContextSource
from aegis.m03_agent.ledger import CampaignLedger
from aegis.m03_agent.ledger import connect as ledger_connect
from aegis.m03_agent.mcp import ToolClient
from aegis.m03_agent.nodes import (
    RESULT_SCHEMA,
    SessionNodes,
    build_graph,
)
from aegis.m03_agent.state import initial_state
from aegis.m03_agent.store import AgentSessionStore, SessionRef

__all__ = [
    "CHECKPOINT_SCHEMA",
    "SessionDeps",
    "SessionRun",
    "SessionStateError",
    "checkpoint_dsn",
    "ensure_checkpoint_schema",
    "run_session",
]

CHECKPOINT_SCHEMA = "langgraph"


class SessionStateError(RuntimeError):
    """A session row is final but the ledger outcome it should be answered from is missing."""


@dataclass(frozen=True, slots=True)
class SessionDeps:
    """Everything one session needs; the activity's `configure()` builds this once per worker."""

    config: SessionConfig
    dsn: str
    context: ContextSource
    tools: Callable[[], AbstractAsyncContextManager[ToolClient]]
    model: ModelClient
    store: AgentSessionStore
    ledger: CampaignLedger
    #: The LangGraph checkpointer, one per session run. The default is PostgreSQL (`langgraph`
    #: schema); tests inject `MemorySaver` so the loop can be driven without a database.
    checkpointer: Callable[[], AbstractAsyncContextManager[Any]] | None = None


@dataclass(frozen=True, slots=True)
class SessionRun:
    """What the activity returns plus the evidence a test wants to look at."""

    outcome: SessionOutcome
    ref: SessionRef
    result: Mapping[str, Any] | None = None
    resumed: bool = False
    state: Mapping[str, Any] = field(default_factory=dict)


def _postgres_checkpointer(dsn: str) -> Callable[[], AbstractAsyncContextManager[Any]]:
    """The production checkpointer factory: `langgraph` schema, tables created by the library."""

    @asynccontextmanager
    async def _open() -> AsyncIterator[Any]:
        await asyncio.to_thread(ensure_checkpoint_schema, dsn)
        async with AsyncPostgresSaver.from_conn_string(checkpoint_dsn(dsn)) as saver:
            yield saver

    return _open


def checkpoint_dsn(dsn: str) -> str:
    """The DSN that puts the checkpointer's tables in `langgraph` instead of `public` (0001:14).

    Without it the library creates its tables in the first schema of the search path (public), which
    0001:14 explicitly does not want. The DSN may be a URI or the libpq keyword form (the test
    harnesses hand out the latter), so the option is merged instead of appended.
    """
    parameters = conninfo_to_dict(dsn)
    options = parameters.get("options", "")
    parameters["options"] = (
        f"{options} -c search_path={CHECKPOINT_SCHEMA}"
        if options
        else f"-c search_path={CHECKPOINT_SCHEMA}"
    )
    return str(make_conninfo("", **parameters))


def ensure_checkpoint_schema(dsn: str) -> None:
    """Create the checkpointer's schema (0001 says the library owns the tables, not the schema)."""
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(f"CREATE SCHEMA IF NOT EXISTS {CHECKPOINT_SCHEMA}")


async def run_session(
    request: SessionRequest,
    deps: SessionDeps,
    *,
    beat: Callable[[str, Mapping[str, Any]], None] | None = None,
) -> SessionRun:
    """Run (or resume) one session and record its result; never dispatches outside MCP."""
    ref = await asyncio.to_thread(deps.store.open, request, revision_from=request.cursor)
    if ref.status != "RUNNING":
        return _already_finished(deps, ref)
    open_checkpointer = deps.checkpointer or _postgres_checkpointer(deps.dsn)
    async with deps.tools() as tools:
        nodes = SessionNodes(
            request=request,
            ref=ref,
            config=deps.config,
            context=deps.context,
            tools=tools,
            model=deps.model,
            ledger=deps.ledger,
            beat=beat,
            heartbeat_seconds=deps.config.heartbeat_seconds,
        )
        start = initial_state(
            cycle=request.cycle,
            cursor=request.cursor,
            objective_id=ref.objective_id,
            objective_text=request.objective,
            policy_version=ref.policy_version,
            graph_revision=request.cursor,
            budget={"max_steps": deps.config.max_steps, "calls_made": 0},
        )
        try:
            async with open_checkpointer() as saver:
                setup = getattr(saver, "setup", None)
                if setup is not None:
                    await setup()
                graph = build_graph(nodes, saver)
                config = {"configurable": {"thread_id": ref.thread_id}}
                snapshot = await graph.aget_state(config)
                resumed = bool(snapshot.next) or bool(snapshot.values)
                if snapshot.next:
                    state = dict(await graph.ainvoke(None, config))
                elif snapshot.values:
                    state = dict(snapshot.values)
                else:
                    state = dict(await graph.ainvoke(start, config))
        except asyncio.CancelledError:
            # Blocking on purpose: a cleanup that awaits could be cancelled again and the campaign
            # would lose the stop reason (this is why 02-nen-tang pins WAIT_CANCELLATION_COMPLETED).
            _finish_cancelled(deps, ref, nodes.last_state)
            raise
    outcome, result = await asyncio.to_thread(_record, deps, request, ref, state)
    return SessionRun(outcome=outcome, ref=ref, result=result, resumed=resumed, state=state)


def _already_finished(deps: SessionDeps, ref: SessionRef) -> SessionRun:
    payload = deps.store.finished_outcome(ref)
    if payload is None:
        raise SessionStateError(
            f"agent_session {ref.session_id} is {ref.status} without a cycle_finished entry; "
            "the session outcome cannot be reconstructed"
        )
    return SessionRun(outcome=_outcome_from_payload(payload), ref=ref, resumed=True)


def _outcome_from_payload(payload: Mapping[str, Any]) -> SessionOutcome:
    return SessionOutcome(
        cursor=int(payload.get("cursor") or 0),
        cycle=int(payload.get("cycle") or 0) if payload.get("cycle") is not None else 0,
        job_ids=tuple(str(job) for job in payload.get("requested_jobs") or ()),
        stop_reason=None if payload.get("stop_reason") is None else str(payload["stop_reason"]),
        idle=bool(payload.get("idle")),
        detail=None if payload.get("detail") is None else str(payload["detail"]),
    )


def _session_result(
    ref: SessionRef,
    state: Mapping[str, Any],
    *,
    decision: str,
    stop_reason: str | None,
    steps_used: int,
    summary: str,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "session_id": ref.session_id,
        "decision": Decision(decision),
        "steps_used": max(0, min(30, int(steps_used))),
        "requested_jobs": [str(job) for job in state.get("jobs") or []],
        "denied": [dict(item) for item in state.get("denied") or []],
        "hypothesis_updates": [],
        "usage": dict(state.get("usage") or {}),
    }
    if stop_reason is not None:
        payload["stop_reason"] = StopReason(stop_reason)
    if summary:
        payload["summary"] = summary[:4000]
    result = SessionResult.model_validate(payload)
    validation.validate_model(RESULT_SCHEMA, result)
    return result.model_dump(mode="json", exclude_none=True)


def _final_state(state: Mapping[str, Any]) -> tuple[str, str | None, int, str]:
    decision = str(state.get("decision") or "wait")
    if decision == "continue":  # pragma: no cover - the graph only ends on stop/wait
        decision = "wait"
    stop_reason = None if state.get("stop_reason") is None else str(state["stop_reason"])
    steps = int(state.get("step") or 0)
    summary = str(state.get("summary") or "")
    return decision, stop_reason, steps, summary


def _record(
    deps: SessionDeps,
    request: SessionRequest,
    ref: SessionRef,
    state: Mapping[str, Any],
) -> tuple[SessionOutcome, Mapping[str, Any]]:
    decision, stop_reason, steps, summary = _final_state(state)
    jobs = tuple(str(job) for job in state.get("jobs") or ())
    idle = decision == "wait" and not jobs
    cursor = int(state.get("graph_revision") or request.cursor)
    result = _session_result(
        ref, state, decision=decision, stop_reason=stop_reason, steps_used=steps, summary=summary
    )
    deps.store.finish(
        ref,
        status="SUCCEEDED",
        decision=decision,
        stop_reason=stop_reason,
        steps_used=steps,
        result=result,
        cursor=cursor,
        idle=idle,
        detail=summary or None,
    )
    usage = dict(state.get("usage") or {})
    deps.ledger.append(
        request.campaign_id,
        "budget",
        {
            "session_id": ref.session_id,
            "sent_tokens": int(usage.get("input_tokens") or 0)
            + int(usage.get("output_tokens") or 0),
            "sent_cost_usd": float(usage.get("cost_usd") or 0.0),
            "remaining_tokens": (state.get("budget") or {}).get("tokens_remaining"),
            "remaining_cost_usd": (state.get("budget") or {}).get("cost_remaining"),
            "models": list(usage.get("models") or []),
        },
    )
    if idle:
        deps.ledger.append(
            request.campaign_id,
            "idle_cycle",
            {"session_id": ref.session_id, "cycle": request.cycle, "detail": summary or None},
        )
    if stop_reason is not None:
        deps.ledger.append(
            request.campaign_id,
            "stop_condition",
            {"session_id": ref.session_id, "stop_reason": stop_reason, "detail": summary or None},
        )
    outcome = SessionOutcome(
        cursor=cursor,
        cycle=request.cycle,
        job_ids=jobs,
        stop_reason=stop_reason,
        idle=idle,
        detail=summary or None,
    )
    return outcome, result


def _finish_cancelled(deps: SessionDeps, ref: SessionRef, state: Mapping[str, Any]) -> None:
    """Record the cancel with what the last completed node committed (no await: not cancellable)."""
    _decision, _ignored, steps, summary = _final_state(state)
    jobs = tuple(str(job) for job in state.get("jobs") or ())
    result = _session_result(
        ref,
        state,
        decision="stop",
        stop_reason="operator",
        steps_used=steps,
        summary=summary or "session cancelled by the campaign cancel signal",
    )
    deps.store.finish(
        ref,
        status="CANCELLED",
        decision="stop",
        stop_reason="operator",
        steps_used=steps,
        result=result,
        cursor=int(state.get("graph_revision") or 0),
        idle=False,
        detail=f"cancelled after step {steps}; jobs proposed before the cancel: {list(jobs)}",
    )
    deps.ledger.append(
        ref.campaign_id,
        "stop_condition",
        {
            "session_id": ref.session_id,
            "stop_reason": "operator",
            "detail": f"cancel signal; steps committed: {steps}",
        },
    )


def build_deps(
    *,
    config: SessionConfig,
    dsn: str,
    tools: Callable[[], AbstractAsyncContextManager[ToolClient]],
    model: ModelClient,
) -> SessionDeps:
    """The production composition root: PostgreSQL read model/ledger/store, MCP tool client."""
    from aegis.m03_agent.context import PostgresContextSource
    from aegis.m03_agent.ledger import PostgresCampaignLedger
    from aegis.m03_agent.store import PostgresAgentSessionStore

    connect = lambda: ledger_connect(dsn)  # noqa: E731 - one short connection per call
    return SessionDeps(
        config=config,
        dsn=dsn,
        context=PostgresContextSource(connect),
        tools=tools,
        model=model,
        store=PostgresAgentSessionStore(connect),
        ledger=PostgresCampaignLedger(connect),
    )
