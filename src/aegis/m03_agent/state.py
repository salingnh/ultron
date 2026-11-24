"""The checkpointed state of one agent session (plain JSON values only).

LangGraph persists this state with the PostgreSQL checkpointer, so every value is a JSON value:
contract payloads are stored as `model_dump(mode="json")` dicts and nothing here re-declares a
contract shape. The state is the resume boundary the card's acceptance rests on - a worker killed
between two nodes continues at the next node with everything the earlier nodes already decided
(the same `step`, the same idempotency key, the same dispatched calls).

Sections:
    * fixed inputs written once by `build_context` (objective, budget, catalogue, messages);
    * the loop position (`step`, `round`, `trace_id`) and the current proposal/selection;
    * what was dispatched and what came back (`dispatched`, `outcomes`, `jobs`, `denied`);
    * the budget the session spent (`usage`) and the pending decision (`decision`, `stop_reason`).
"""

from __future__ import annotations

from typing import Any, TypedDict

__all__ = ["SessionState", "add_usage", "empty_usage", "initial_state"]

DECISIONS = ("continue", "wait", "stop")


class SessionState(TypedDict, total=False):
    """One session's working state; every key is optional so a partial update can be returned."""

    cycle: int
    cursor: int
    objective_id: str
    objective_text: str
    policy_version: str
    graph_revision: int
    previous_revision: int
    #: {"tokens_remaining", "cost_remaining", "spent_tokens", "spent_cost", "max_steps",
    #: "max_tool_calls"} - the campaign budget as this session sees it.
    budget: dict[str, Any]
    #: The MCP catalogue published for this session: [{"name", "description", "input_schema"}].
    capabilities: list[dict[str, Any]]
    #: The model conversation (bounded by SessionConfig.max_history_messages).
    messages: list[dict[str, Any]]
    step: int
    round: int
    trace_id: str
    #: {"kind": "call"|"decision", ...} - what the model asked for in this round.
    proposal: dict[str, Any] | None
    #: The validated call M03 will send: {"tool", "arguments", "idempotency_key", "call_id"}.
    selected: dict[str, Any] | None
    #: A call the model asked for that M03 refused before dispatch (error.v2 code + detail).
    refusal: dict[str, Any] | None
    dispatched: list[dict[str, Any]]
    outcomes: list[dict[str, Any]]
    jobs: list[str]
    denied: list[dict[str, Any]]
    usage: dict[str, Any]
    novel: bool
    idle_rounds: int
    decision: str
    stop_reason: str | None
    summary: str
    model_error: str | None


def empty_usage() -> dict[str, Any]:
    """The `usage` member of `session-result.v2`, zeroed."""
    return {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0, "models": []}


def add_usage(
    usage: dict[str, Any], *, input_tokens: int, output_tokens: int, cost_usd: float, model: str
) -> dict[str, Any]:
    """Accumulate one model answer into the session's usage (the call already wrote its row)."""
    models = list(usage.get("models") or [])
    if model not in models:
        models.append(model)
    return {
        "input_tokens": int(usage.get("input_tokens") or 0) + int(input_tokens),
        "output_tokens": int(usage.get("output_tokens") or 0) + int(output_tokens),
        "cost_usd": round(float(usage.get("cost_usd") or 0.0) + float(cost_usd), 6),
        "models": models,
    }


def initial_state(
    *,
    cycle: int,
    cursor: int,
    objective_id: str,
    objective_text: str,
    policy_version: str,
    graph_revision: int,
    budget: dict[str, Any],
) -> SessionState:
    """The state a fresh session starts from; `build_context` fills the catalogue and messages."""
    return SessionState(
        cycle=cycle,
        cursor=cursor,
        objective_id=objective_id,
        objective_text=objective_text,
        policy_version=policy_version,
        graph_revision=graph_revision,
        previous_revision=cursor,
        budget=budget,
        capabilities=[],
        messages=[],
        step=0,
        round=0,
        proposal=None,
        selected=None,
        refusal=None,
        dispatched=[],
        outcomes=[],
        jobs=[],
        denied=[],
        usage=empty_usage(),
        novel=False,
        idle_rounds=0,
        decision="continue",
        stop_reason=None,
        summary="",
        model_error=None,
    )
