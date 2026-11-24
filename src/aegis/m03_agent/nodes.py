"""The agent loop: BuildContext -> Plan -> SelectTool -> Dispatch -> AwaitResult -> Analyze ->
DecideNext.

One node, one decision, one checkpoint (G0.1 nesting decision). What that buys, and what the tests
assert:

* **Resume without duplicate work.** `dispatch` returns only after MCP answered, so its node state
  (the call and its idempotency key) is committed before `await_result` runs. A worker killed after
  that resumes at `await_result` with the answer already in the checkpoint: one MCP call, one job.
* **One job per logical request even when the checkpoint is lost.** The idempotency key is
  `<session_id>:step:<n>:<digest of tool+arguments>`, so re-running a step after a lost checkpoint
  replays the same key and M05 answers `duplicate` with the same job id.
* **The model cannot widen its own powers.** `Plan` only proposes; `SelectTool` checks the proposal
  against the catalogue the server published for this session and refuses anything else (an unknown
  tool, a foreign `objective_id`, arguments that fail the published schema) with an `error.v2` code
  - and the refusal is a tool result, not a dispatch.
* **Budget and steps stop it, not the prompt.** `DecideNext` reads the remaining budget it has
  accumulated, the step counter and the tool-call ceiling; M04 refuses the call before the provider
  when the campaign budget is spent (`BudgetExceeded`), and both paths end the session with a
  contract stop reason.
* **Idle is a decision, not an error.** A session with no job and no new evidence answers `wait`;
  it returns `idle=True` so M02's own `idle_cycles_before_pause` counter can pause the campaign with
  a reason (the session never pauses a campaign itself).

`AwaitResult` semantics in G1 (G1.2b is asynchronous acceptance): a capability call returns a job
id, not the job's output. The node collects the MCP answer, and the *job's* result arrives in a
later session - M02 waits for `job_completed` and starts the next cycle. If a send was checkpointed
without its answer (only possible if a future dispatch runs concurrently), the node re-sends with
the same key instead of guessing.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import AsyncIterator, Callable, Collection, Mapping, Sequence
from contextlib import asynccontextmanager
from hashlib import sha256
from typing import Any

from langgraph.graph import END, START, StateGraph

from aegis import validation
from aegis.common.ports import Budget, BudgetExceeded, ModelClient
from aegis.contracts_gen.agent.context_bundle_v2_schema import (
    Capability,
    ContextBundle,
)
from aegis.contracts_gen.agent.model_request_v2_schema import ModelRequest, Provider, ToolSpec
from aegis.contracts_gen.agent.model_response_v2_schema import FinishReason
from aegis.m02_orchestrator.types import SessionRequest
from aegis.m03_agent import prompt
from aegis.m03_agent.config import MAX_STEPS, SessionConfig
from aegis.m03_agent.context import (
    MAX_OBSERVATIONS,
    UNBOUNDED,
    CampaignContext,
    ContextSource,
)
from aegis.m03_agent.ledger import CampaignLedger
from aegis.m03_agent.mcp import GRAPH_PREFIX, CallMeta, ToolClient, ToolOutcome
from aegis.m03_agent.state import SessionState, add_usage
from aegis.m03_agent.store import SessionRef
from aegis.m03_agent.trace import new_trace_id
from aegis.m03_agent.wire import blocks as wire_blocks

__all__ = [
    "NODES",
    "SessionNodes",
    "build_graph",
    "initial_budget",
    "outcome_from_state",
    "outcome_to_state",
]

#: Node order of the loop (`02-nen-tang` §Phiên agent); also the ledger/heartbeat stage names.
NODES = (
    "build_context",
    "plan",
    "select_tool",
    "dispatch",
    "await_result",
    "analyze",
    "decide_next",
)
CONTEXT_SCHEMA = "agent/context-bundle.v2.schema.json"
RESULT_SCHEMA = "agent/session-result.v2.schema.json"


def outcome_to_state(outcome: ToolOutcome) -> dict[str, Any]:
    """A `ToolOutcome` as a checkpointable dict (the checkpointer stores JSON values)."""
    return {
        "response": None if outcome.response is None else dict(outcome.response),
        "text": outcome.text,
        "error_code": outcome.error_code,
        "detail": outcome.detail,
        "request_refused": outcome.request_refused,
        "graph": outcome.graph,
    }


def outcome_from_state(tool: str, data: Mapping[str, Any]) -> ToolOutcome:
    response = data.get("response")
    return ToolOutcome(
        tool=tool,
        response=None if response is None else dict(response),
        text=str(data.get("text") or ""),
        error_code=None if data.get("error_code") is None else str(data["error_code"]),
        detail=None if data.get("detail") is None else str(data["detail"]),
        request_refused=bool(data.get("request_refused")),
        graph=bool(data.get("graph")),
    )


def initial_budget(config: SessionConfig, loaded: CampaignContext) -> dict[str, Any]:
    """The session's budget view: the campaign's ceiling minus what the campaign already spent."""
    max_tokens = loaded.budget_item("max_llm_tokens")
    max_cost = loaded.budget_item("max_llm_cost_usd")
    return {
        "tokens_remaining": None
        if max_tokens is None
        else max(0, int(max_tokens) - loaded.spent_tokens),
        "cost_remaining": None
        if max_cost is None
        else max(0.0, float(max_cost) - loaded.spent_cost_usd),
        "spent_tokens": loaded.spent_tokens,
        "spent_cost": loaded.spent_cost_usd,
        "max_steps": min(config.max_steps, MAX_STEPS),
        "max_tool_calls": None,
        "calls_made": 0,
    }


def _spent(budget: Mapping[str, Any], *, tokens: int, cost: float) -> dict[str, Any]:
    updated = dict(budget)
    tokens_left = updated.get("tokens_remaining")
    cost_left = updated.get("cost_remaining")
    updated["tokens_remaining"] = (
        None if tokens_left is None else max(0, int(tokens_left) - int(tokens))
    )
    updated["cost_remaining"] = (
        None if cost_left is None else max(0.0, float(cost_left) - float(cost))
    )
    updated["spent_tokens"] = int(updated.get("spent_tokens") or 0) + int(tokens)
    updated["spent_cost"] = round(float(updated.get("spent_cost") or 0.0) + float(cost), 6)
    return updated


def _budget_exhausted(budget: Mapping[str, Any]) -> bool:
    tokens_left = budget.get("tokens_remaining")
    cost_left = budget.get("cost_remaining")
    return (tokens_left is not None and int(tokens_left) <= 0) or (
        cost_left is not None and float(cost_left) <= 0
    )


def _model_budget(budget: Mapping[str, Any], loaded: CampaignContext) -> Budget:
    tokens_left = budget.get("tokens_remaining")
    cost_left = budget.get("cost_remaining")
    policy_budget = None
    try:
        from aegis.contracts_gen.campaign.roe_policy_v2_schema import Budget as PolicyBudget

        policy_budget = PolicyBudget.model_validate(
            {key: value for key, value in (loaded.policy.get("budget") or {}).items()}
        )
    except Exception:  # pragma: no cover - a policy that does not parse is a context error
        policy_budget = None
    return Budget(
        remaining_tokens=UNBOUNDED if tokens_left is None else int(tokens_left),
        remaining_cost_usd=UNBOUNDED if cost_left is None else float(cost_left),
        policy=policy_budget,
    )


def _seed_observations(targets: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """The campaign's seed targets as bundle observations (the contract's place for raw targets).

    `context-bundle.v2` has no target list; its `Observation` is where a raw target string belongs
    (`untrusted`: "chuỗi lấy nguyên từ mục tiêu") and its `ref` may be a canonical key. So a session
    learns its seeds from the bundle, exactly like a real model does from its prompt, and nothing
    reads `campaign_target` behind the model's back.
    """
    items: list[dict[str, Any]] = []
    for target in targets:
        kind = str(target["kind"])
        raw = str(target["raw_value"])
        ref = target.get("canonical_key") or str(target["target_id"])
        items.append(
            _observation(
                ref=str(ref),
                summary=f"{prompt.SEED_SUMMARY_PREFIX} {kind}",
                untrusted=raw,
                confidence=1.0,
                evidence_uri=None,
            )
        )
    return items


def _observation(
    *,
    ref: str,
    summary: str,
    untrusted: str | None,
    confidence: float,
    evidence_uri: str | None,
) -> dict[str, Any]:
    """One `context-bundle.v2` observation; an absent optional value is omitted, never null."""
    item: dict[str, Any] = {
        "ref": ref[:200],
        "summary": summary[:1000],
        "confidence": max(0.0, min(1.0, confidence)),
    }
    if untrusted is not None:
        item["untrusted"] = untrusted[:2000]
    if evidence_uri is not None:
        item["evidence_uri"] = evidence_uri[:2048]
    return item


def _capability_summary(capability: Mapping[str, Any]) -> Capability:
    description = str(capability.get("description") or "").replace("\n", " ")[:500]
    return Capability.model_validate(
        {"capability": capability["name"], "accepts": [], "summary": description or None}
    )


class SessionNodes:
    """The seven node functions, bound to one session's dependencies."""

    def __init__(
        self,
        *,
        request: SessionRequest,
        ref: SessionRef,
        config: SessionConfig,
        context: ContextSource,
        tools: ToolClient,
        model: ModelClient,
        ledger: CampaignLedger,
        beat: Callable[[str, Mapping[str, Any]], None] | None = None,
        heartbeat_seconds: float = 1.0,
    ) -> None:
        self.request = request
        self.ref = ref
        self.config = config
        self.context = context
        self.tools = tools
        self.model = model
        self.ledger = ledger
        self._beat = beat or (lambda stage, fields: None)
        #: G1.1d schedules the activity with `heartbeat_timeout=3s`: a long model or MCP call has to
        #: keep beating, or Temporal would treat a slow provider as a dead worker.
        self.heartbeat_seconds = heartbeat_seconds
        self._loaded: CampaignContext | None = None
        #: Last state seen by a node: on cancellation the session row is finished from this
        #: snapshot without awaiting anything inside a cancelled task.
        self.last_state: dict[str, Any] = {}
        self.stage = "start"

    # --- helpers ----------------------------------------------------------------------------
    def _enter(self, stage: str, state: SessionState) -> None:
        self.stage = stage
        self.last_state = dict(state)
        self._beat(stage, {"step": int(state.get("step") or 0)})

    def _meta(self, state: SessionState, *, key: str) -> CallMeta:
        return CallMeta(
            trace_id=str(state.get("trace_id") or new_trace_id()),
            campaign_id=self.request.campaign_id,
            session_id=self.ref.session_id,
            idempotency_key=key,
        )

    @asynccontextmanager
    async def beating(self, stage: str) -> AsyncIterator[None]:
        """Beat every `heartbeat_seconds` while awaiting a call that can outlast the timeout."""

        async def loop() -> None:
            while True:
                await asyncio.sleep(self.heartbeat_seconds)
                self._beat(stage, {"step": int(self.last_state.get("step") or 0)})

        task = asyncio.create_task(loop())
        try:
            yield
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    def loaded(self) -> CampaignContext:
        if self._loaded is None:
            self._loaded = self.context.load(self.request.campaign_id, cursor=self.request.cursor)
        return self._loaded

    # --- 1. BuildContext --------------------------------------------------------------------
    async def build_context(self, state: SessionState) -> dict[str, Any]:
        self._enter("build_context", state)
        loaded = await asyncio.to_thread(
            self.context.load, self.request.campaign_id, cursor=self.request.cursor
        )
        self._loaded = loaded
        meta = self._meta(state, key=f"{self.ref.session_id}:context")
        catalogue = await self.tools.list_tools(meta)
        capabilities = [
            {"name": tool.name, "description": tool.description, "input_schema": tool.input_schema}
            for tool in catalogue
            if not tool.name.startswith(GRAPH_PREFIX)
        ]
        observations, graph_revision, graph_detail = await self._observations(loaded, meta)
        budget = initial_budget(self.config, loaded)
        terminal = {"SUCCEEDED", "FAILED", "CANCELLED"}
        pending = [str(job["job_id"]) for job in loaded.jobs if str(job["status"]) not in terminal]
        # The campaign's history as the model may use it: one code-generated line per finished job,
        # so a session knows what was already proposed without reading a table itself.
        completed = [
            f"{job['capability']} {job['job_id']} {job['status']}"
            for job in loaded.jobs
            if str(job["status"]) in terminal
        ]
        observations = (_seed_observations(loaded.targets) + observations)[:MAX_OBSERVATIONS]
        bundle = ContextBundle.model_validate(
            {
                "campaign_id": self.request.campaign_id,
                "session_id": self.ref.session_id,
                "objective": {
                    "objective_id": self.ref.objective_id,
                    "text": loaded.objective_text[:4000],
                },
                "policy_version": self.ref.policy_version,
                "policy_summary": {
                    "budget": dict(loaded.policy.get("budget") or {}),
                    "max_parallel_jobs": loaded.policy.get("max_parallel_jobs"),
                    "rate_limits": dict(loaded.policy.get("rate_limits") or {}),
                    "allowed_windows": len(loaded.policy.get("allowed_windows") or []),
                    "blackout_windows": len(loaded.policy.get("blackout_windows") or []),
                    "spent_tokens": loaded.spent_tokens,
                    "spent_cost_usd": loaded.spent_cost_usd,
                },
                "graph_revision": graph_revision,
                "previous_revision": int(state.get("cursor") or 0),
                "observations": observations,
                "ledger": {
                    "completed_objectives": completed[:200],
                    "blockers": [] if graph_detail is None else [graph_detail],
                    "pending_job_ids": pending[:200],
                    "idle_cycles": loaded.idle_cycles,
                },
                "capabilities": [
                    _capability_summary(item).model_dump(mode="json") for item in capabilities
                ],
                "budget": {
                    "max_steps": budget["max_steps"],
                    "llm_tokens_remaining": budget["tokens_remaining"],
                    "llm_cost_usd_remaining": budget["cost_remaining"],
                },
            }
        )
        validation.validate_model(CONTEXT_SCHEMA, bundle)
        messages = [
            prompt.system_message(),
            prompt.context_message(
                objective_text=loaded.objective_text,
                cycle=self.request.cycle,
                budget=budget,
                capabilities=capabilities,
                observations=[dict(item) for item in observations],
                pending_job_ids=pending,
                completed_objectives=completed,
                idle_cycles=loaded.idle_cycles,
            ),
        ]
        # A model stand-in that has no prompt (the scripted G1 policy) is given the same bundle the
        # prompt was built from; a real client ignores this hook and reads the prompt.
        observe = getattr(self.model, "observe_context", None)
        if callable(observe):
            observe(bundle)
        self.ledger.append(
            self.request.campaign_id,
            "cursor",
            {
                "session_id": self.ref.session_id,
                "previous_revision": int(state.get("cursor") or 0),
                "graph_revision": graph_revision,
                "capabilities": [item["name"] for item in capabilities],
                "graph_source": "m23" if graph_detail is None else "postgres",
            },
        )
        return {
            "objective_id": self.ref.objective_id,
            "objective_text": loaded.objective_text,
            "policy_version": self.ref.policy_version,
            "graph_revision": graph_revision,
            "budget": budget,
            "capabilities": capabilities,
            "messages": messages,
        }

    async def _observations(
        self, loaded: CampaignContext, meta: CallMeta
    ) -> tuple[list[dict[str, Any]], int, str | None]:
        """M23's projection first; the same M27 rows from PostgreSQL when it is not wired."""
        outcome = await self.tools.query_graph(
            "get_recent_observations",
            {
                "campaign_id": self.request.campaign_id,
                "since_revision": max(0, int(self.request.cursor)),
                "limit": 20,
            },
            meta=meta,
        )
        if outcome.ok and outcome.response is not None:
            rows = outcome.response.get("observations") or []
            revision = int(outcome.response.get("revision") or 0)
            return (
                [
                    _observation(
                        ref=str(row["subject"]),
                        # typed fields only: a value is untrusted text, so it stays in `untrusted`
                        summary=f"{row.get('predicate')} on {row.get('subject')}",
                        untrusted=row.get("value_summary"),
                        confidence=float(row.get("confidence") or 1.0),
                        evidence_uri=(
                            None
                            if row.get("evidence_id") is None
                            else f"evidence:{row['evidence_id']}"
                        ),
                    )
                    for row in rows
                ],
                max(revision, loaded.graph_revision),
                None,
            )
        detail = (
            f"graph.get_recent_observations unavailable ({outcome.error_code}"
            f"{': ' + outcome.detail if outcome.detail else ''}); context read from M27 rows"
        )
        self.ledger.append(
            self.request.campaign_id,
            "blocker",
            {
                "session_id": self.ref.session_id,
                "code": outcome.error_code or "DEPENDENCY_MISSING",
                "context": "context graph",
                "detail": detail[:1000],
            },
        )
        return (
            [
                _observation(
                    ref=str(row["subject"]),
                    summary=f"{row['predicate']} on {row['subject']}",
                    untrusted=(
                        None
                        if row.get("value") is None
                        else json.dumps(row["value"], sort_keys=True)
                    ),
                    confidence=float(row.get("confidence") or 1.0),
                    evidence_uri=None,
                )
                for row in loaded.observations
            ],
            loaded.graph_revision,
            detail,
        )

    # --- 2. Plan ----------------------------------------------------------------------------
    async def plan(self, state: SessionState) -> dict[str, Any]:
        self._enter("plan", state)
        step = int(state.get("step") or 0) + 1
        trace_id = new_trace_id()
        budget = dict(state.get("budget") or {})
        if step > int(budget.get("max_steps") or MAX_STEPS):
            return {
                "step": step - 1,
                "trace_id": trace_id,
                "decision": "stop",
                "stop_reason": "step_limit",
                "summary": f"step limit {budget.get('max_steps')} reached before planning",
            }
        tools = [
            ToolSpec(
                name=item["name"],
                description=item["description"][:8192] or item["name"],
                input_schema=dict(item["input_schema"]),
            ).model_dump(mode="json")
            for item in state.get("capabilities") or []
        ]
        payload: dict[str, Any] = {
            "provider": Provider(self.config.provider),
            "model": self.config.model,
            "messages": prompt.trim_messages(
                state.get("messages") or [], limit=self.config.max_history_messages
            ),
            "response_schema": prompt.PLAN_DECISION_SCHEMA,
            "campaign_id": self.request.campaign_id,
            "session_id": self.ref.session_id,
            "trace_id": trace_id,
            "max_output_tokens": self.config.max_output_tokens,
            "timeout_seconds": self.config.timeout_seconds,
        }
        if tools:
            payload["tools"] = tools
        request = ModelRequest.model_validate(payload)
        try:
            async with self.beating("plan"):
                answer = await self.model.complete(request, _model_budget(budget, self.loaded()))
        except BudgetExceeded as error:
            return {
                "step": step - 1,
                "trace_id": trace_id,
                "budget": budget,
                "decision": "stop",
                "stop_reason": "budget_exhausted",
                "summary": f"model budget refused the call before the provider: {error}"[:4000],
            }
        usage = add_usage(
            dict(state.get("usage") or {}),
            input_tokens=answer.usage.input_tokens,
            output_tokens=answer.usage.output_tokens,
            cost_usd=float(answer.usage.cost_usd),
            model=str(answer.model),
        )
        budget = _spent(
            budget,
            tokens=answer.usage.input_tokens + answer.usage.output_tokens,
            cost=float(answer.usage.cost_usd),
        )
        messages = list(state.get("messages") or [])
        if answer.message is not None:
            messages.append(answer.message.model_dump(mode="json"))
        update: dict[str, Any] = {
            "step": step,
            "trace_id": trace_id,
            "messages": messages,
            "usage": usage,
            "budget": budget,
            "proposal": None,
            "model_error": None,
        }
        if answer.finish_reason is FinishReason.tool_calls and answer.message is not None:
            update["proposal"] = self._proposal_from_tool_calls(answer.message)
        elif answer.finish_reason is FinishReason.completed:
            decided = prompt.decision_from_response(answer.parsed)
            if decided is None:
                update["model_error"] = "invalid_output: the decision object is not the plan schema"
            else:
                update["proposal"] = {
                    "kind": "decision",
                    "decision": decided[0],
                    "summary": decided[1],
                }
        else:
            code = answer.error.code if answer.error is not None else answer.finish_reason.value
            update["model_error"] = f"{answer.finish_reason.value}: {code}"
        return update

    def _proposal_from_tool_calls(self, message: Any) -> dict[str, Any]:
        calls = [
            block["call"] for block in wire_blocks(message) if block.get("type") == "tool_call"
        ]
        if not calls:  # pragma: no cover - the contract refuses tool_calls without a call
            return {"kind": "invalid", "detail": "finish_reason=tool_calls without a tool call"}
        first = calls[0]
        arguments = first.get("arguments")
        call_id = str(first["id"])
        if arguments is None:
            return {
                "kind": "invalid",
                "call_id": call_id,
                "detail": "the provider returned arguments_raw that do not parse as JSON",
            }
        proposal: dict[str, Any] = {
            "kind": "call",
            "call_id": call_id,
            "tool": str(first["name"]),
            "arguments": dict(arguments),
        }
        if len(calls) > 1:
            proposal["dropped_calls"] = [str(call["name"]) for call in calls[1:]]
        return proposal

    # --- 3. SelectTool ----------------------------------------------------------------------
    async def select_tool(self, state: SessionState) -> dict[str, Any]:
        self._enter("select_tool", state)
        proposal = state.get("proposal") or {}
        if proposal.get("kind") != "call":
            return {"selected": None, "refusal": None}
        tool = str(proposal["tool"])
        step = int(state.get("step") or 0)
        published = {item["name"]: item for item in state.get("capabilities") or []}
        refusal = self._refuse(tool, proposal, published.keys())
        if refusal is not None:
            return {"selected": None, "refusal": refusal}
        arguments = dict(proposal.get("arguments") or {})
        problems = prompt.schema_problems(
            published[tool]["input_schema"], {**arguments, "objective_id": self.ref.objective_id}
        )
        if problems:
            return {
                "selected": None,
                "refusal": {
                    "tool": tool,
                    "call_id": str(proposal.get("call_id") or ""),
                    "code": "INPUT_INVALID",
                    "detail": problems[0][:512],
                },
            }
        arguments["objective_id"] = self.ref.objective_id
        digest = sha256(
            json.dumps(
                {"tool": tool, "arguments": arguments}, sort_keys=True, separators=(",", ":")
            ).encode()
        ).hexdigest()[:16]
        return {
            "selected": {
                "tool": tool,
                "arguments": arguments,
                "call_id": str(proposal.get("call_id") or ""),
                "idempotency_key": f"{self.ref.session_id}:step:{step}:{digest}",
            },
            "refusal": None,
        }

    def _refuse(
        self, tool: str, proposal: Mapping[str, Any], published: Collection[str]
    ) -> dict[str, Any] | None:
        if tool not in published:
            return {
                "tool": tool,
                "call_id": str(proposal.get("call_id") or ""),
                "code": "INPUT_INVALID",
                "detail": (
                    f"{tool!r} is not published for this session: the catalogue is tools/list "
                    "(nothing in tool output can add a tool)"
                ),
            }
        arguments = proposal.get("arguments") or {}
        objective = arguments.get("objective_id") if isinstance(arguments, Mapping) else None
        if objective is not None and str(objective) != self.ref.objective_id:
            return {
                "tool": tool,
                "call_id": str(proposal.get("call_id") or ""),
                "code": "INPUT_INVALID",
                "detail": (
                    "objective_id is assigned by the session; a call cannot pick another objective"
                ),
            }
        return None

    # --- 4. Dispatch ------------------------------------------------------------------------
    async def dispatch(self, state: SessionState) -> dict[str, Any]:
        self._enter("dispatch", state)
        selected = state.get("selected")
        if not selected:
            return {}
        budget = dict(state.get("budget") or {})
        calls_made = int(budget.get("calls_made") or 0)
        ceiling = budget.get("max_tool_calls")
        if ceiling is not None and calls_made >= int(ceiling):
            return {
                "selected": None,
                "decision": "stop",
                "stop_reason": "budget_exhausted",
                "summary": f"tool-call budget {ceiling} reached; the call was not sent",
            }
        meta = self._meta(state, key=str(selected["idempotency_key"]))
        async with self.beating("dispatch"):
            outcome = await self.tools.call_capability(
                str(selected["tool"]), selected["arguments"], meta=meta
            )
        budget["calls_made"] = calls_made + 1
        entry = {
            "tool": str(selected["tool"]),
            "call_id": str(selected["call_id"]),
            "idempotency_key": str(selected["idempotency_key"]),
            "arguments": dict(selected["arguments"]),
            "outcome": outcome_to_state(outcome),
        }
        return {
            "dispatched": [*(state.get("dispatched") or []), entry],
            "budget": budget,
            "selected": None,
        }

    # --- 5. AwaitResult ---------------------------------------------------------------------
    async def await_result(self, state: SessionState) -> dict[str, Any]:
        self._enter("await_result", state)
        entries = list(state.get("dispatched") or [])
        if not entries:
            return {}
        outcomes: list[dict[str, Any]] = []
        for entry in entries:
            data = entry.get("outcome")
            if data is None:  # a send checkpointed without its answer: same key, still one job
                async with self.beating("await_result"):
                    redone = await self.tools.call_capability(
                        str(entry["tool"]),
                        entry["arguments"],
                        meta=self._meta(state, key=str(entry["idempotency_key"])),
                    )
                data = outcome_to_state(redone)
            outcomes.append({"tool": str(entry["tool"]), "call_id": str(entry["call_id"]), **data})
        return {"outcomes": outcomes}

    # --- 6. Analyze -------------------------------------------------------------------------
    async def analyze(self, state: SessionState) -> dict[str, Any]:
        self._enter("analyze", state)
        messages = list(state.get("messages") or [])
        jobs = list(state.get("jobs") or [])
        denied = list(state.get("denied") or [])
        novel = False
        for item in state.get("outcomes") or []:
            outcome = outcome_from_state(str(item["tool"]), item)
            messages.append(
                prompt.tool_result_message(
                    call_id=str(item["call_id"]),
                    name=outcome.tool,
                    outcome=outcome,
                    is_error=outcome.error_code is not None,
                )
            )
            if outcome.job_id is not None and outcome.job_id not in jobs:
                jobs.append(outcome.job_id)
                novel = True
            if outcome.error_code is not None and not outcome.graph:
                denied = _deny(denied, outcome.tool, outcome.error_code)
            if outcome.graph and outcome.ok:
                records = len((outcome.response or {}).get("observations") or [])
                novel = novel or records > 0
        refusal = state.get("refusal")
        if refusal is not None:
            outcome = ToolOutcome(
                tool=str(refusal["tool"]),
                error_code=str(refusal["code"]),
                detail=str(refusal.get("detail") or ""),
                request_refused=True,
            )
            messages.append(
                prompt.tool_result_message(
                    call_id=str(refusal.get("call_id") or ""),
                    name=outcome.tool,
                    outcome=outcome,
                    is_error=True,
                )
            )
            denied = _deny(denied, outcome.tool, str(refusal["code"]))
        idle_rounds = 0 if novel else int(state.get("idle_rounds") or 0) + 1
        return {
            "messages": messages,
            "jobs": jobs,
            "denied": denied,
            "novel": novel,
            "idle_rounds": idle_rounds,
            "round": int(state.get("round") or 0) + 1,
            "dispatched": [],
            "outcomes": [],
            "refusal": None,
        }

    # --- 7. DecideNext ----------------------------------------------------------------------
    async def decide_next(self, state: SessionState) -> dict[str, Any]:
        self._enter("decide_next", state)
        budget = dict(state.get("budget") or {})
        if state.get("stop_reason"):
            return {"decision": "stop"}
        if _budget_exhausted(budget):
            return {
                "decision": "stop",
                "stop_reason": "budget_exhausted",
                "summary": "campaign model budget is spent; the session stopped",
            }
        ceiling = budget.get("max_tool_calls")
        if ceiling is not None and int(budget.get("calls_made") or 0) >= int(ceiling):
            return {
                "decision": "stop",
                "stop_reason": "budget_exhausted",
                "summary": f"tool-call budget {ceiling} spent",
            }
        if int(state.get("step") or 0) >= int(budget.get("max_steps") or MAX_STEPS):
            return {
                "decision": "stop",
                "stop_reason": "step_limit",
                "summary": f"step limit {budget.get('max_steps')} reached",
            }
        proposal = state.get("proposal") or {}
        if proposal.get("kind") == "decision":
            if proposal.get("decision") == "stop":
                return {
                    "decision": "stop",
                    "stop_reason": "objective_met",
                    "summary": str(
                        proposal.get("summary") or "the planner reports the objective met"
                    ),
                }
            return {"decision": "wait", "summary": str(proposal.get("summary") or "")}
        if state.get("model_error"):
            return {"decision": "wait", "summary": f"model answer unusable: {state['model_error']}"}
        if state.get("jobs"):
            return {
                "decision": "wait",
                "summary": "job(s) proposed; the workflow waits for job_completed and opens the "
                "next session",
            }
        if int(state.get("idle_rounds") or 0) >= self.config.in_session_idle_rounds:
            return {
                "decision": "wait",
                "summary": f"no new evidence in {state.get('idle_rounds')} round(s)",
            }
        return {"decision": "continue"}


def _deny(denied: Sequence[Mapping[str, Any]], capability: str, code: str) -> list[dict[str, Any]]:
    items = [dict(item) for item in denied]
    for item in items:
        if item.get("capability") == capability and item.get("code") == code:
            return items
    items.append({"capability": capability, "code": code})
    return items


def build_graph(nodes: SessionNodes, checkpointer: Any) -> Any:
    """Compile the seven-node loop; the only branch is DecideNext's continue/stop."""
    graph: StateGraph[SessionState] = StateGraph(SessionState)
    graph.add_node("build_context", nodes.build_context)
    graph.add_node("plan", nodes.plan)
    graph.add_node("select_tool", nodes.select_tool)
    graph.add_node("dispatch", nodes.dispatch)
    graph.add_node("await_result", nodes.await_result)
    graph.add_node("analyze", nodes.analyze)
    graph.add_node("decide_next", nodes.decide_next)
    graph.add_edge(START, "build_context")
    graph.add_edge("build_context", "plan")
    graph.add_edge("plan", "select_tool")
    graph.add_edge("select_tool", "dispatch")
    graph.add_edge("dispatch", "await_result")
    graph.add_edge("await_result", "analyze")
    graph.add_edge("analyze", "decide_next")
    graph.add_conditional_edges(
        "decide_next",
        lambda state: "continue" if state.get("decision") == "continue" else "end",
        {"continue": "plan", "end": END},
    )
    return graph.compile(checkpointer=checkpointer)
