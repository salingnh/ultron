"""G1.6: the live M04 client drives the real agent loop, for both provider standards.

Nothing here opens a socket: the provider answers are recorded bodies (`tests/fixtures/m04/`)
played back by the HTTP boundary `HttpTransport` already accepts, so the test proves the whole
chain - `SessionNodes.plan` builds the request from the MCP catalogue, the provider driver writes
the wire form, the answer is normalized, the model's tool call is validated against the published
schema, dispatched through the real M05 boundary, and the tool result returns to the next provider
request inside `UNTRUSTED_TOOL_OUTPUT`. One `aegis.model_usage` row per attempt is recorded with the
deployment's prices, and the session's budget ledger carries the same cost.

The scripted policy keeps its own coverage in `tests/test_m03_loop.py`; this module is the live
selection (`AEGIS_SESSION_LIVE_MODEL=1`) end to end.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import pytest

from aegis.contracts_gen.agent.model_request_v2_schema import Provider
from aegis.contracts_gen.agent.model_response_v2_schema import FinishReason
from aegis.m03_agent import prompt
from aegis.m03_agent.config import SessionConfig
from aegis.m03_agent.session import SessionRun, run_session
from aegis.m04_model import deployment
from aegis.m04_model.deployment import ModelDeployment
from aegis.m04_model.raw import usage_tokens
from aegis.m04_model.tool_names import PORTABLE_NAME, provider_tool_name
from aegis.m04_model.transport import HttpAnswer
from aegis.m04_model.usage import InMemoryUsageSink, ModelUsage
from tests.m03_support import (
    ENUMERATE,
    Deps,
    deps_for,
    job_store,
    service,
    session_request,
)
from tests.m04_support import recorded
from tests.mcp_support import OBJECTIVE_ID

SECRET = "sk-g16-loop-secret"
MODELS = {
    Provider.openai: "gpt-5-mini-2026-01-01",
    Provider.anthropic: "claude-sonnet-4-5-20260201",
}
PRICES = {Provider.openai: (2.0, 8.0), Provider.anthropic: (3.0, 15.0)}
RATIONALES = (
    "Enumerate the lab domain's subdomains for the campaign objective",
    "Enumerate the seed domain to find new surface before resolving it",
)
VARIABLES = (
    deployment.LIVE_MODEL_ENV,
    deployment.PROVIDER_ENV,
    deployment.MODEL_NAME_ENV,
    deployment.BASE_URL_ENV,
    deployment.API_KEY_ENV,
    deployment.INPUT_PRICE_ENV,
    deployment.OUTPUT_PRICE_ENV,
    deployment.TIMEOUT_SECONDS_ENV,
    deployment.MAX_OUTPUT_TOKENS_ENV,
)


def configure_live(monkeypatch: pytest.MonkeyPatch, provider: Provider) -> ModelDeployment:
    """The deployment the worker would build from a complete live environment."""
    for name in VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(deployment.LIVE_MODEL_ENV, "1")
    monkeypatch.setenv(deployment.PROVIDER_ENV, provider.value)
    monkeypatch.setenv(deployment.MODEL_NAME_ENV, MODELS[provider])
    monkeypatch.setenv(deployment.API_KEY_ENV, SECRET)
    monkeypatch.setenv(deployment.INPUT_PRICE_ENV, str(PRICES[provider][0]))
    monkeypatch.setenv(deployment.OUTPUT_PRICE_ENV, str(PRICES[provider][1]))
    return ModelDeployment.from_env()


@dataclass
class RecordedHttp:
    """The injected HTTP boundary: plays recorded bodies and keeps every request it saw."""

    bodies: list[dict[str, Any]]
    calls: list[dict[str, Any]]

    def __init__(self, bodies: Sequence[dict[str, Any]]) -> None:
        self.bodies = list(bodies)
        self.calls = []

    def __call__(
        self, url: str, headers: dict[str, str], body: bytes, timeout: float
    ) -> HttpAnswer:
        wire: Any = json.loads(body)
        assert isinstance(wire, dict), "the driver must send a JSON object"
        self.calls.append({"url": url, "headers": dict(headers), "wire": wire, "timeout": timeout})
        assert self.bodies, "the loop sent more provider requests than the recording has answers"
        return HttpAnswer(200, json.dumps(self.bodies.pop(0)).encode())


def tool_call_body(provider: Provider, arguments: Mapping[str, Any]) -> dict[str, Any]:
    """The recorded tool-call answer with the arguments a test wants the model to have produced.

    The name is the one the provider was given: a provider echoes the wire name it was sent, which
    is the capability id only when that id is already inside the function-name grammar
    (`dns.enumerate_subdomains` is not - it is published as `dns__enumerate_subdomains`). Answering
    with the wire name is what makes this test prove the round trip back to the capability id.
    """
    name = "openai-plan-tool-call" if provider is Provider.openai else "anthropic-plan-tool-use"
    raw = recorded(name)
    wire_name = provider_tool_name(ENUMERATE)
    if provider is Provider.openai:
        function = raw["choices"][0]["message"]["tool_calls"][0]["function"]
        function["name"] = wire_name
        function["arguments"] = json.dumps(dict(arguments), sort_keys=True)
    else:
        block = next(item for item in raw["content"] if item["type"] == "tool_use")
        block["name"] = wire_name
        block["input"] = dict(arguments)
    return raw


def decision_body(provider: Provider) -> dict[str, Any]:
    name = "openai-plan-decision" if provider is Provider.openai else "anthropic-plan-decision"
    return recorded(name)


def run_live_loop(
    monkeypatch: pytest.MonkeyPatch,
    provider: Provider,
    bodies: Sequence[dict[str, Any]],
) -> tuple[ModelDeployment, RecordedHttp, InMemoryUsageSink, Deps, SessionRun]:
    """One session whose plan calls go through the live client and a recorded HTTP boundary."""
    live = configure_live(monkeypatch, provider)
    http = RecordedHttp(bodies)
    sink = InMemoryUsageSink()
    client = live.client(sink, post=http)
    job_service = service()
    deps = deps_for(
        model=client,
        tool_service=job_service,
        config=SessionConfig.from_env(),
    )
    run = asyncio.run(run_session(session_request(), deps.deps))
    return live, http, sink, deps, run


def wire_tool_names(provider: Provider, wire: Mapping[str, Any]) -> set[str]:
    """Every function name the provider will see in the tool catalogue."""
    catalog = wire.get("tools") or []
    if provider is Provider.openai:
        return {str(tool["function"]["name"]) for tool in catalog}
    return {str(tool["name"]) for tool in catalog}


def tool_result_text(provider: Provider, wire: Mapping[str, Any], call_id: str) -> str:
    """The text of the tool-result turn that answers `call_id`, in each provider's own shape."""
    messages = wire["messages"]
    if provider is Provider.openai:
        [answer] = [message for message in messages if message["role"] == "tool"]
        assert answer["tool_call_id"] == call_id
        return str(answer["content"])
    users = [
        message
        for message in messages
        if message["role"] == "user"
        and isinstance(message["content"], list)
        and any(block.get("type") == "tool_result" for block in message["content"])
    ]
    [block] = [item for item in users[-1]["content"] if item.get("type") == "tool_result"]
    assert block["tool_use_id"] == call_id
    return str(block["content"])


def expected_cost(provider: Provider, body: Mapping[str, Any]) -> float:
    input_tokens, output_tokens = usage_tokens(provider, body)
    price_in, price_out = PRICES[provider]
    return round((input_tokens * price_in + output_tokens * price_out) / 1_000_000, 6)


def budget_entry(deps: Deps) -> Mapping[str, Any]:
    from tests.m03_support import CAMPAIGN_ID

    entries = [
        entry for entry in deps.ledger.entries_by_campaign[CAMPAIGN_ID] if entry["kind"] == "budget"
    ]
    assert entries, "the session must record what it spent"
    return dict(entries[-1]["payload"])


@pytest.mark.parametrize("provider", [Provider.openai, Provider.anthropic])
def test_the_live_client_drives_the_mcp_tool_loop(
    monkeypatch: pytest.MonkeyPatch, provider: Provider
) -> None:
    # 1st answer: a call M03 must refuse (the contract requires `rationale`), so the loop continues
    # and the refusal comes back to the model; 2nd answer: the same capability, now valid.
    refused = tool_call_body(provider, {"input": {"targets": ["internal.example"]}})
    accepted = tool_call_body(
        provider,
        {"input": {"targets": ["internal.example"]}, "rationale": RATIONALES[0]},
    )
    live, http, sink, deps, run = run_live_loop(monkeypatch, provider, [refused, accepted])
    assert len(http.calls) == 2, "one refused call and one dispatched call"
    assert run.outcome.job_ids, "the accepted call must become an MCP job"

    first = http.calls[0]
    if provider is Provider.openai:
        assert first["url"] == "https://api.openai.com/v1/chat/completions"
        assert first["headers"]["authorization"] == f"Bearer {SECRET}"
        assert first["wire"]["response_format"]["json_schema"]["schema"] == (
            prompt.PLAN_DECISION_SCHEMA
        )
        assert first["wire"]["response_format"]["json_schema"]["strict"] is True
    else:
        assert first["url"] == "https://api.anthropic.com/v1/messages"
        assert first["headers"]["x-api-key"] == SECRET
        assert "authorization" not in first["headers"]
        assert first["wire"]["system"].startswith("You are the planner of one AEGIS agent session")
        assert "response_format" not in first["wire"]
    # The catalogue came from MCP `tools/list`, not from anything the model said - in the provider's
    # own function-name grammar, which every OpenAI-compatible provider validates (`dns.resolve` is
    # refused there; the capability id is what the caller sees, below).
    published = wire_tool_names(provider, first["wire"])
    assert {provider_tool_name(ENUMERATE), provider_tool_name("dns.resolve")} <= published
    for name in published:
        assert PORTABLE_NAME.fullmatch(name), name
    assert first["timeout"] == 120.0

    # The refusal reached the next provider request as untrusted data, not as an instruction.
    refusal = tool_result_text(provider, http.calls[1]["wire"], call_id=first_call_id(provider))
    assert '<UNTRUSTED_TOOL_OUTPUT source="dns.enumerate_subdomains">' in refusal
    assert "</UNTRUSTED_TOOL_OUTPUT>" in refusal
    assert "INPUT_INVALID" in refusal
    assert "rationale" in refusal

    # The model's accepted call was dispatched through the real M05 boundary with its arguments.
    assert [call[0] for call in deps.client.calls] == [ENUMERATE]
    arguments = deps.client.calls[0][1]
    assert arguments["input"]["targets"] == ["internal.example"]
    assert arguments["rationale"] == RATIONALES[0]
    assert arguments["objective_id"] == OBJECTIVE_ID
    submissions = job_store(deps.client.service).submissions
    assert [item["capability"] for item in submissions] == [ENUMERATE]
    assert run.result is not None
    assert list(run.outcome.job_ids) == [run.result["requested_jobs"][0]]

    # One usage row per attempt, priced by the deployment's own prices.
    assert [row.status for row in sink.rows] == ["ok", "ok"]
    assert [row.cost_usd for row in sink.rows] == [
        pytest.approx(expected_cost(provider, refused)),
        pytest.approx(expected_cost(provider, accepted)),
    ]
    for row in sink.rows:
        assert (row.provider, row.model) == (provider, live.model)
        assert row.campaign_id == "01934f6a-0000-7000-8000-000000000001"
        assert row.session_id == run.ref.session_id
        assert row.trace_id and len(row.trace_id) == 32
        assert row.error_code is None

    # The session's budget ledger carries the same money the usage rows recorded.
    budget = budget_entry(deps)
    spent = sum(row.cost_usd for row in sink.rows)
    assert budget["sent_cost_usd"] == pytest.approx(spent)
    assert budget["sent_tokens"] == sum(row.input_tokens + row.output_tokens for row in sink.rows)
    assert budget["models"] == [live.model]
    assert run.result is not None
    assert run.result["usage"]["cost_usd"] == pytest.approx(spent)
    assert run.result["decision"] == "wait"
    assert run.outcome.stop_reason is None


def first_call_id(provider: Provider) -> str:
    body = recorded(
        "openai-plan-tool-call" if provider is Provider.openai else "anthropic-plan-tool-use"
    )
    if provider is Provider.openai:
        return str(body["choices"][0]["message"]["tool_calls"][0]["id"])
    block = next(item for item in body["content"] if item["type"] == "tool_use")
    return str(block["id"])


@pytest.mark.parametrize("provider", [Provider.openai, Provider.anthropic])
def test_the_live_client_ends_a_session_on_a_valid_decision(
    monkeypatch: pytest.MonkeyPatch, provider: Provider
) -> None:
    body = decision_body(provider)
    live, http, sink, _deps, run = run_live_loop(monkeypatch, provider, [body])
    assert len(http.calls) == 1
    assert run.result is not None
    assert run.result["decision"] == "stop"
    assert run.result["stop_reason"] == "objective_met"
    assert "objective is met" in str(run.result.get("summary"))
    assert [row.status for row in sink.rows] == ["ok"]
    assert sink.rows[0].cost_usd == pytest.approx(expected_cost(provider, body))
    assert sink.rows[0].model == live.model


@pytest.mark.parametrize("provider", [Provider.openai, Provider.anthropic])
def test_a_provider_failure_ends_the_session_without_leaking_the_key(
    monkeypatch: pytest.MonkeyPatch, provider: Provider
) -> None:
    live = configure_live(monkeypatch, provider)
    seen: list[dict[str, str]] = []

    def post(url: str, headers: dict[str, str], body: bytes, timeout: float) -> HttpAnswer:
        seen.append(headers)
        echoed = headers.get("authorization") or headers.get("x-api-key") or ""
        return HttpAnswer(401, json.dumps({"error": f"invalid api key {echoed}"}).encode())

    sink = InMemoryUsageSink()
    deps = deps_for(
        model=live.client(sink, post=post),
        tool_service=service(),
        config=SessionConfig.from_env(),
    )
    run = asyncio.run(run_session(session_request(), deps.deps))
    assert seen, "the provider was called"
    assert [row.status for row in sink.rows] == ["error"]
    assert run.result is not None
    assert run.result["decision"] == "wait"
    assert run.outcome.stop_reason is None
    assert "provider_error" in str(run.result.get("summary"))
    recorded_surfaces = json.dumps(
        {"result": run.result, "state": dict(run.state), "rows": [_row_json(r) for r in sink.rows]}
    )
    assert SECRET not in recorded_surfaces


def _row_json(row: ModelUsage) -> dict[str, Any]:
    return {
        "usage_id": row.usage_id,
        "status": row.status,
        "error_code": None if row.error_code is None else row.error_code.value,
        "model": row.model,
        "cost_usd": row.cost_usd,
    }


def test_the_plan_decision_schema_is_inside_openais_strict_subset() -> None:
    """`strict: true` accepts only a narrow JSON Schema subset; the plan schema must stay in it."""
    unsupported = {
        "$schema",
        "pattern",
        "format",
        "maxLength",
        "minLength",
        "maxItems",
        "minItems",
        "uniqueItems",
        "minimum",
        "maximum",
        "multipleOf",
        "maxProperties",
        "minProperties",
        "propertyNames",
        "patternProperties",
        "not",
        "if",
        "then",
        "else",
        "allOf",
        "oneOf",
    }

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for keyword, value in node.items():
                assert keyword not in unsupported, f"{keyword} is not in OpenAI's strict subset"
                walk(value)
            properties = node.get("properties")
            if node.get("type") == "object" and isinstance(properties, dict):
                assert node.get("additionalProperties") is False
                assert set(properties) == set(node.get("required") or ())
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(prompt.PLAN_DECISION_SCHEMA)
    assert prompt.decision_from_response({"decision": "wait", "summary": "still running"}) == (
        "wait",
        "still running",
    )
    assert prompt.decision_from_response({"decision": "wait"}) is None


def test_the_recorded_finish_reasons_are_the_ones_the_loop_expects() -> None:
    """Guard on the fixtures: a re-recording must still produce the two contract answers."""
    from aegis.contracts_gen.agent.model_message_v2_schema import ToolCallBlock
    from aegis.m04_model.client import output_validator
    from aegis.m04_model.drivers import DEFAULT_DRIVERS

    drivers = {driver.provider: driver for driver in DEFAULT_DRIVERS}
    validate = output_validator(prompt.PLAN_DECISION_SCHEMA)
    for provider in (Provider.openai, Provider.anthropic):
        calls = drivers[provider].normalize(
            tool_call_body(
                provider,
                {"input": {"targets": ["internal.example"]}, "rationale": RATIONALES[0]},
            ),
            model=MODELS[provider],
        )
        assert calls.finish_reason is FinishReason.tool_calls
        assert calls.message is not None
        assert any(isinstance(block.root, ToolCallBlock) for block in calls.message.content)
        decision = drivers[provider].normalize(
            decision_body(provider), model=MODELS[provider], validate=validate
        )
        assert decision.finish_reason is FinishReason.completed
        assert decision.parsed is not None and decision.parsed["decision"] == "stop"
