"""An upstream that is out of credits (HTTP 402) rotates instead of failing the group (item 62).

The owner's live run: one endpoint's account answered

    HTTP 402 Payment Required
    {"error": {"type": "invalid_request_error", "message": "Insufficient balance. ..."}}

LiteLLM classifies that as a bad request (the body says `invalid_request_error`), and a group that
does not advance on a 4xx-class answer hands the 402 to the agent while a healthy endpoint sits next
to it. Being out of credits is an exhausted quota, like a 429: serve the call from the next endpoint
and cool this one down.

This module boots its own gateway (a separate compose-free container with two fake upstreams, one
answering 402) so it does not inherit the cooldowns of the rotation module's gateway.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator

import pytest

from aegis.common.ports import Budget
from aegis.contracts_gen.agent.model_request_v2_schema import ModelRequest, Provider
from aegis.contracts_gen.agent.model_response_v2_schema import FinishReason, ModelResponse
from aegis.m04_model.deployment import ModelDeployment
from aegis.m04_model.usage import InMemoryUsageSink
from tests.llm_gateway_support import (
    PAYMENT_MESSAGE,
    FakeUpstream,
    GatewayProcess,
    gateway_config,
    gateway_env,
)

CAMPAIGN_ID = "01934f6a-0000-7000-8000-000000000001"
SESSION_ID = "01934f6a-0000-7000-8000-000000000002"
MODEL_GROUP = "aegis-smart"


@pytest.fixture(scope="module")
def upstreams() -> Iterator[list[FakeUpstream]]:
    started = [FakeUpstream().start(), FakeUpstream().start()]
    try:
        yield started
    finally:
        for upstream in started:
            upstream.stop()


@pytest.fixture(scope="module")
def gateway(upstreams: list[FakeUpstream]) -> Iterator[GatewayProcess]:
    process = GatewayProcess.spawn(gateway_config(upstreams), name="llm-gateway-payment").start()
    try:
        yield process
    finally:
        process.stop()


def complete(
    gateway: GatewayProcess, monkeypatch: pytest.MonkeyPatch
) -> tuple[ModelResponse, InMemoryUsageSink]:
    for name, value in gateway_env(f"{gateway.base_url}/v1", MODEL_GROUP).items():
        monkeypatch.setenv(name, value)
    deployment = ModelDeployment.from_env()
    request = ModelRequest.model_validate(
        {
            "provider": Provider.openai.value,
            "model": MODEL_GROUP,
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "ping"}]},
            ],
            "campaign_id": CAMPAIGN_ID,
            "session_id": SESSION_ID,
            "trace_id": "0123456789abcdef0123456789abcdef",
            "max_output_tokens": 64,
            "timeout_seconds": 60,
        }
    )
    sink = InMemoryUsageSink()
    response = asyncio.run(
        deployment.client(sink).complete(
            request, Budget(remaining_tokens=100_000, remaining_cost_usd=5.0)
        )
    )
    return response, sink


def test_an_endpoint_out_of_credits_rotates_and_cools_down(
    gateway: GatewayProcess,
    upstreams: list[FakeUpstream],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exhausted, healthy = upstreams
    exhausted.mode, healthy.mode = "payment", "ok"

    answer, sink = complete(gateway, monkeypatch)
    assert answer.finish_reason is FinishReason.completed, (
        f"the 402 must rotate to the next endpoint:\n{gateway.logs()}"
    )
    assert exhausted.paths() == ["/v1/chat/completions"], "the exhausted endpoint is tried once"
    assert healthy.paths() == ["/v1/chat/completions"], "and the next endpoint serves the call"
    assert sink.rows[-1].status == "ok"
    assert PAYMENT_MESSAGE.split(".")[0] not in repr(sink.rows[-1]), (
        "an upstream's billing text is not copied into the ledger row of a successful call"
    )

    # The exhausted endpoint is cooling down: the next request does not spend a call on it.
    second, _ = complete(gateway, monkeypatch)
    assert second.finish_reason is FinishReason.completed
    assert exhausted.paths() == ["/v1/chat/completions"], "a 402 puts the endpoint in cooldown"
    assert healthy.paths() == ["/v1/chat/completions"] * 2

    table = gateway.status_table()
    cooling = next(line for line in table.splitlines() if "fake-endpoint-a" in line)
    serving = next(line for line in table.splitlines() if "fake-endpoint-b" in line)
    assert "cooling down" in cooling, table
    assert "cooling down" not in serving, table
