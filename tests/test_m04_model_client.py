"""ModelClient execution: budget before any call, bounded fallback, usage rows, transport."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any

import pytest

from aegis import validation
from aegis.common.ports import Budget, BudgetExceeded
from aegis.common.ports import ModelClient as ModelClientPort
from aegis.contracts_gen.agent.model_request_v2_schema import Provider
from aegis.contracts_gen.agent.model_response_v2_schema import FinishReason, ModelResponse
from aegis.contracts_gen.common.error_v2_schema import ErrorCode, NextAction
from aegis.m04_model import (
    FakeModelClient,
    HttpAnswer,
    HttpTransport,
    InMemoryUsageSink,
    MissingEndpoint,
    ModelClient,
    ModelConfig,
    Price,
    PricingUnknown,
    ProviderSpec,
    TransportError,
)
from tests.m04_support import (
    MODEL_OUTPUT_SCHEMA,
    ScriptedTransport,
    Step,
    budget,
    recorded,
    request,
)
from tests.support import load_fixture


def run(call: Any) -> Any:
    return asyncio.run(call)


def openai_invalid_output() -> dict[str, Any]:
    raw = recorded("openai-completed")
    return {
        **raw,
        "choices": [{"finish_reason": "stop", "message": {"content": '{"severity": "BANANA"}'}}],
    }


def test_every_attempt_records_one_usage_row_and_budget_denial_calls_nothing() -> None:
    sink = InMemoryUsageSink()
    transport = ScriptedTransport(
        [Step(raw=recorded("openai-completed"), latency_ms=700, cost_usd=0.0002)]
    )
    client = ModelClient(transport, sink)

    response = run(client.complete(request(), budget()))
    assert response.finish_reason is FinishReason.completed
    assert len(sink.rows) == 1
    row = sink.rows[0]
    assert row.status == "ok" and row.error_code is None
    assert (row.provider, row.model) == (Provider.openai, "configured-model")
    assert (row.input_tokens, row.output_tokens, row.cost_usd, row.latency_ms) == (
        180,
        9,
        0.0002,
        700,
    )
    assert row.campaign_id == "01934f6a-0000-7000-8000-000000000001"
    assert row.trace_id == "0123456789abcdef0123456789abcdef"

    with pytest.raises(BudgetExceeded):
        run(client.complete(request(), Budget(remaining_tokens=0, remaining_cost_usd=1.0)))
    assert len(transport.calls) == 1
    denied = sink.rows[1]
    assert denied.status == "budget_denied"
    assert denied.error_code is ErrorCode.POLICY_DENIED
    assert (denied.input_tokens, denied.output_tokens, denied.cost_usd) == (0, 0, 0.0)


@pytest.mark.parametrize(
    "spent",
    [
        Budget(remaining_tokens=0, remaining_cost_usd=1.0),
        Budget(remaining_tokens=10_000, remaining_cost_usd=0.0),
    ],
)
def test_budget_is_denied_when_either_dimension_is_spent(spent: Budget) -> None:
    transport = ScriptedTransport([])
    client = ModelClient(transport, InMemoryUsageSink())
    with pytest.raises(BudgetExceeded):
        run(client.complete(request(), spent))
    assert transport.calls == []


def test_provider_error_then_configured_fallback() -> None:
    config = ModelConfig(
        fallback=(ProviderSpec(Provider.anthropic, "fallback-model"),),
        allow_fallback=True,
        max_attempts=2,
    )
    sink = InMemoryUsageSink()
    transport = ScriptedTransport(
        [
            Step(error=TransportError(ErrorCode.NETWORK_TIMEOUT, "primary unreachable")),
            Step(raw=recorded("anthropic-completed"), latency_ms=1200, cost_usd=0.0011),
        ]
    )
    client = ModelClient(transport, sink, config)

    response = run(client.complete(request(), budget()))
    assert response.finish_reason is FinishReason.completed
    assert response.provider is Provider.anthropic
    assert [call["provider"] for call in transport.calls] == [
        Provider.openai,
        Provider.anthropic,
    ]
    assert [row.status for row in sink.rows] == ["error", "fallback"]
    assert sink.rows[0].error_code is ErrorCode.NETWORK_TIMEOUT
    assert sink.rows[0].latency_ms >= 0
    assert sink.rows[1].model == "fallback-model"
    assert sink.rows[1].error_code is None


def test_invalid_output_is_not_hidden_by_fallback() -> None:
    config = ModelConfig(
        fallback=(ProviderSpec(Provider.anthropic, "fallback-model"),),
        allow_fallback=True,
        max_attempts=2,
    )
    sink = InMemoryUsageSink()
    transport = ScriptedTransport(
        [
            Step(raw=openai_invalid_output()),
            Step(raw=recorded("anthropic-completed")),
        ]
    )
    client = ModelClient(transport, sink, config)
    req = request()
    req.response_schema = MODEL_OUTPUT_SCHEMA

    response = run(client.complete(req, budget()))
    assert response.finish_reason is FinishReason.invalid_output
    assert len(transport.calls) == 1
    assert [row.status for row in sink.rows] == ["ok"]


def test_fallback_attempts_are_capped_by_config() -> None:
    config = ModelConfig(
        fallback=(
            ProviderSpec(Provider.anthropic, "fallback-1"),
            ProviderSpec(Provider.openai, "fallback-2"),
        ),
        allow_fallback=True,
        max_attempts=2,
    )
    sink = InMemoryUsageSink()
    transport = ScriptedTransport(
        [
            Step(error=TransportError(ErrorCode.NETWORK_TIMEOUT, "primary")),
            Step(error=TransportError(ErrorCode.NETWORK_TIMEOUT, "fallback-1")),
            Step(raw=recorded("openai-completed")),
        ]
    )
    client = ModelClient(transport, sink, config)

    response = run(client.complete(request(), budget()))
    assert response.finish_reason is FinishReason.provider_error
    assert response.error is not None
    assert response.error.next_action is NextAction.RETRY
    assert len(transport.calls) == 2
    assert [row.status for row in sink.rows] == ["error", "error"]


def test_fallback_is_off_unless_the_policy_opt_in_is_set() -> None:
    config = ModelConfig(fallback=(ProviderSpec(Provider.anthropic, "x"),))
    sink = InMemoryUsageSink()
    transport = ScriptedTransport(
        [
            Step(error=TransportError(ErrorCode.RATE_LIMITED, "slow down")),
            Step(raw=recorded("anthropic-completed")),
        ]
    )
    client = ModelClient(transport, sink, config)

    response = run(client.complete(request(), budget()))
    assert response.finish_reason is FinishReason.provider_error
    assert response.error is not None and response.error.code is ErrorCode.RATE_LIMITED
    assert response.error.next_action is NextAction.RETRY_LATER
    assert len(transport.calls) == 1


def test_invalid_request_is_refused_before_any_call() -> None:
    sink = InMemoryUsageSink()
    transport = ScriptedTransport([])
    client = ModelClient(transport, sink)
    req = request()
    req.trace_id = "not-a-trace"

    with pytest.raises(validation.ContractViolation):
        run(client.complete(req, budget()))
    assert transport.calls == [] and sink.rows == []


def test_usage_rows_are_validated_contract_payloads() -> None:
    sink = InMemoryUsageSink()
    transport = ScriptedTransport(
        [Step(raw=recorded("anthropic-tool-use"), latency_ms=10, cost_usd=0.0001)]
    )
    client = ModelClient(transport, sink)
    response = run(client.complete(request(Provider.anthropic), budget()))
    assert response.finish_reason is FinishReason.tool_calls
    validation.validate_model("agent/model-response.v2.schema.json", response)
    assert len(sink.rows) == 1 and sink.rows[0].status == "ok"


def test_fake_driver_is_a_first_class_model_client() -> None:
    scripted = ModelResponse.model_validate(
        load_fixture("valid/model-response.tool-calls.openai.json")
    )
    sink = InMemoryUsageSink()
    client = FakeModelClient([scripted], usage=sink)
    assert isinstance(client, ModelClientPort)

    result = run(client.complete(request(), budget()))
    assert result == scripted
    assert client.calls == [request()]
    assert [row.status for row in sink.rows] == ["ok"]
    assert sink.rows[0].error_code is None

    with pytest.raises(BudgetExceeded):
        run(client.complete(request(), Budget(remaining_tokens=0, remaining_cost_usd=0.0)))
    assert sink.rows[-1].status == "budget_denied"
    assert sink.rows[-1].error_code is ErrorCode.POLICY_DENIED


# ---------------------------------------------------------------------------
# HttpTransport: offline, through an injected HTTP boundary
# ---------------------------------------------------------------------------


def http_transport(
    post: Callable[[str, dict[str, str], bytes, float], HttpAnswer],
    *,
    model: str = "configured-model",
) -> HttpTransport:
    return HttpTransport(
        endpoints={
            Provider.openai: "https://api.test/v1/chat/completions",
            Provider.anthropic: "https://api.test/v1/messages",
        },
        api_keys={Provider.openai: "test-key", Provider.anthropic: "test-key"},
        pricing={
            (Provider.openai, model): Price(input_usd_per_million=2.0, output_usd_per_million=8.0)
        },
        post=post,
    )


def test_http_transport_posts_and_prices_the_answer() -> None:
    raw = recorded("openai-completed")
    seen: list[dict[str, Any]] = []

    def post(url: str, headers: dict[str, str], body: bytes, timeout: float) -> HttpAnswer:
        seen.append({"url": url, "headers": headers, "body": json.loads(body), "timeout": timeout})
        return HttpAnswer(200, json.dumps(raw).encode())

    answer = run(
        http_transport(post).send(
            Provider.openai, "configured-model", {"model": "configured-model"}, timeout_seconds=30
        )
    )
    assert answer.raw == raw
    assert seen[0]["url"] == "https://api.test/v1/chat/completions"
    assert seen[0]["headers"]["authorization"] == "Bearer test-key"
    assert seen[0]["timeout"] == 30
    # 180 input tokens at $2/M + 9 output at $8/M.
    assert answer.cost_usd == pytest.approx(0.000432)
    assert answer.latency_ms >= 0


def test_http_transport_uses_anthropic_headers() -> None:
    seen: list[dict[str, str]] = []

    def post(url: str, headers: dict[str, str], body: bytes, timeout: float) -> HttpAnswer:
        seen.append(headers)
        return HttpAnswer(200, json.dumps(recorded("anthropic-completed")).encode())

    transport = HttpTransport(
        endpoints={Provider.anthropic: "https://api.test/v1/messages"},
        api_keys={Provider.anthropic: "test-key"},
        pricing={(Provider.anthropic, "configured-model"): Price(1.0, 3.0)},
        post=post,
    )
    run(
        transport.send(
            Provider.anthropic, "configured-model", {"model": "configured-model"}, timeout_seconds=5
        )
    )
    assert seen[0]["x-api-key"] == "test-key"
    assert seen[0]["anthropic-version"] == "2023-06-01"
    assert "authorization" not in seen[0]


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (429, ErrorCode.RATE_LIMITED),
        # 402 Payment Required is "out of credits" (the owner's live OpenCode answer): the same
        # exhausted-quota class as 429, so the ledger and the campaign budget see one failure kind.
        (402, ErrorCode.RATE_LIMITED),
        (500, ErrorCode.INTERNAL_ERROR),
        (401, ErrorCode.INTERNAL_ERROR),
        (400, ErrorCode.INPUT_INVALID),
        (408, ErrorCode.NETWORK_TIMEOUT),
    ],
)
def test_http_transport_maps_error_statuses(status: int, code: ErrorCode) -> None:
    def post(url: str, headers: dict[str, str], body: bytes, timeout: float) -> HttpAnswer:
        return HttpAnswer(status, b'{"error": {"message": "provider says no"}}')

    with pytest.raises(TransportError) as caught:
        run(
            http_transport(post).send(
                Provider.openai,
                "configured-model",
                {"model": "configured-model"},
                timeout_seconds=5,
            )
        )
    assert caught.value.code is code
    assert str(status) in caught.value.message


def test_http_transport_maps_timeout_and_garbage_to_transport_errors() -> None:
    def timeout(url: str, headers: dict[str, str], body: bytes, wait: float) -> HttpAnswer:
        raise TimeoutError

    with pytest.raises(TransportError) as caught:
        run(
            http_transport(timeout).send(
                Provider.openai,
                "configured-model",
                {"model": "configured-model"},
                timeout_seconds=1,
            )
        )
    assert caught.value.code is ErrorCode.NETWORK_TIMEOUT

    def garbage(url: str, headers: dict[str, str], body: bytes, wait: float) -> HttpAnswer:
        return HttpAnswer(200, b"<html>not json</html>")

    with pytest.raises(TransportError) as caught:
        run(
            http_transport(garbage).send(
                Provider.openai,
                "configured-model",
                {"model": "configured-model"},
                timeout_seconds=1,
            )
        )
    assert caught.value.code is ErrorCode.INTERNAL_ERROR


def test_http_transport_refuses_missing_configuration_loudly() -> None:
    def post(url: str, headers: dict[str, str], body: bytes, timeout: float) -> HttpAnswer:
        return HttpAnswer(200, b"{}")

    transport = http_transport(post)
    with pytest.raises(PricingUnknown):
        run(
            transport.send(
                Provider.openai, "unknown-model", {"model": "unknown-model"}, timeout_seconds=1
            )
        )
    with pytest.raises(MissingEndpoint):
        run(
            HttpTransport(endpoints={Provider.openai: "https://x"}, api_keys={}, pricing={}).send(
                Provider.openai, "configured-model", {"model": "x"}, timeout_seconds=1
            )
        )
    with pytest.raises(MissingEndpoint):
        run(
            HttpTransport(endpoints={}, api_keys={}, pricing={}, post=post).send(
                Provider.openai, "configured-model", {"model": "x"}, timeout_seconds=1
            )
        )
