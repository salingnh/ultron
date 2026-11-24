"""The S1.4 offline suite replayed against the product OpenAI/Anthropic drivers (C07).

Wire bodies and normalized payloads are compared byte-for-byte with
`contracts/tests/model_client_ref.py` on recorded provider answers, so G1.2a proves the drivers
implement the locked contract, not a look-alike. Every returned DTO is also checked against
`model-response.v2` through `aegis.validation`.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from aegis import validation
from aegis.contracts_gen.agent.model_message_v2_schema import TextBlock, ToolCallBlock
from aegis.contracts_gen.agent.model_request_v2_schema import ModelRequest, Provider
from aegis.contracts_gen.agent.model_response_v2_schema import FinishReason, ModelResponse
from aegis.m04_model.client import output_validator
from aegis.m04_model.drivers import AnthropicMessagesDriver, OpenAIChatDriver, ProviderDriver
from tests.m04_support import (
    MODEL_OUTPUT_SCHEMA,
    recorded,
    reference_normalize,
    reference_to_wire,
)
from tests.support import load_fixture

DRIVERS: dict[Provider, ProviderDriver] = {
    Provider.openai: OpenAIChatDriver(),
    Provider.anthropic: AnthropicMessagesDriver(),
}

RESPONSE_SCHEMA = "agent/model-response.v2.schema.json"


def payload(response: ModelResponse) -> dict[str, Any]:
    return response.model_dump(mode="json", exclude_unset=True)


def assert_valid(response: ModelResponse) -> None:
    validation.validate_model(RESPONSE_SCHEMA, response)


def with_choices(raw: dict[str, Any], choice: dict[str, Any]) -> dict[str, Any]:
    return {**raw, "choices": [choice]}


def test_finish_reasons_are_the_locked_six() -> None:
    schema = validation.document(RESPONSE_SCHEMA)
    assert tuple(schema["$defs"]["FinishReason"]["enum"]) == (
        "completed",
        "tool_calls",
        "truncated",
        "refused",
        "invalid_output",
        "provider_error",
    )


@pytest.mark.parametrize(
    ("provider", "raw", "expected"),
    [
        (Provider.openai, recorded("openai-completed"), FinishReason.completed),
        (
            Provider.openai,
            with_choices(
                recorded("openai-completed"),
                {"finish_reason": "length", "message": {"content": '{"sev'}},
            ),
            FinishReason.truncated,
        ),
        (
            Provider.openai,
            with_choices(
                recorded("openai-completed"),
                {"finish_reason": "content_filter", "message": {"content": None}},
            ),
            FinishReason.refused,
        ),
        (Provider.anthropic, recorded("anthropic-completed"), FinishReason.completed),
        (
            Provider.anthropic,
            {**recorded("anthropic-completed"), "stop_reason": "max_tokens"},
            FinishReason.truncated,
        ),
        (
            Provider.anthropic,
            {**recorded("anthropic-completed"), "stop_reason": "refusal", "content": []},
            FinishReason.refused,
        ),
    ],
)
def test_provider_finish_reasons_map_to_the_six_normalized_values(
    provider: Provider, raw: dict[str, Any], expected: FinishReason
) -> None:
    response = DRIVERS[provider].normalize(raw, model="configured-model")
    assert response.finish_reason is expected
    assert response.parsed is None
    assert (response.message is not None) is (expected is not FinishReason.provider_error)
    assert_valid(response)


@pytest.mark.parametrize("provider", list(DRIVERS))
def test_wire_form_and_round_trip_match_the_s1_4_reference(provider: Provider) -> None:
    fixture: dict[str, Any] = load_fixture("valid/model-request.agent-turn.json")
    fixture = {**fixture, "provider": provider.value}
    request = ModelRequest.model_validate(fixture)

    ours = DRIVERS[provider].to_wire(request, model=request.model)
    assert ours == reference_to_wire(provider, fixture)

    # Two rounds must keep the provider-issued id, name and raw arguments verbatim.
    assistant = next(message for message in ours["messages"] if message["role"] == "assistant")
    if provider is Provider.openai:
        call = assistant["tool_calls"][0]
        assert call["id"] == "call_01934f6a0000700080000000a0000001"
        assert call["function"]["name"] == "dns/enumerate-subdomains"
        assert call["function"]["arguments"] == '{"targets":["example.test"]}'
        tool = next(message for message in ours["messages"] if message["role"] == "tool")
        assert tool["tool_call_id"] == call["id"]
    else:
        use = next(block for block in assistant["content"] if block["type"] == "tool_use")
        assert use["id"] == "call_01934f6a0000700080000000a0000001"
        assert use["name"] == "dns/enumerate-subdomains"
        assert use["input"] == {"targets": ["example.test"]}
        result = next(
            block
            for message in ours["messages"]
            if message["role"] == "user"
            for block in message["content"]
            if block["type"] == "tool_result"
        )
        assert result["tool_use_id"] == use["id"]


@pytest.mark.parametrize(
    ("provider", "name"),
    [
        (Provider.openai, "openai-tool-calls"),
        (Provider.openai, "openai-completed"),
        (Provider.anthropic, "anthropic-tool-use"),
        (Provider.anthropic, "anthropic-completed"),
    ],
)
def test_normalization_matches_the_s1_4_reference(provider: Provider, name: str) -> None:
    raw = recorded(name)
    latency_ms, cost_usd = 850, 0.00042
    ours = payload(
        DRIVERS[provider].normalize(
            raw, model="configured-model", latency_ms=latency_ms, cost_usd=cost_usd
        )
    )
    theirs = reference_normalize(provider, raw, latency_ms=latency_ms, cost_usd=cost_usd)
    assert ours == theirs
    assert_valid(ModelResponse.model_validate(ours))


def test_structured_output_matches_the_reference_and_is_parsed() -> None:
    raw = recorded("openai-assessment")
    validator = output_validator(MODEL_OUTPUT_SCHEMA)
    response = DRIVERS[Provider.openai].normalize(
        raw, model="configured-model", validate=validator, latency_ms=900, cost_usd=0.001
    )
    assert response.finish_reason is FinishReason.completed
    assert response.parsed is not None and response.parsed["severity"] == "HIGH"
    assert payload(response) == reference_normalize(
        Provider.openai, raw, validate=validator, latency_ms=900, cost_usd=0.001
    )
    assert_valid(response)


def test_invalid_and_truncated_output_keep_raw_text() -> None:
    validator = output_validator(MODEL_OUTPUT_SCHEMA)
    bad_schema = with_choices(
        recorded("openai-completed"),
        {"finish_reason": "stop", "message": {"content": '{"severity": "BANANA", "reasons": []}'}},
    )
    response = DRIVERS[Provider.openai].normalize(bad_schema, model="m", validate=validator)
    assert response.finish_reason is FinishReason.invalid_output
    assert response.parsed is None
    assert response.message is not None
    block = response.message.content[0].root
    assert isinstance(block, TextBlock) and "BANANA" in block.text
    assert_valid(response)

    truncated = DRIVERS[Provider.openai].normalize(
        with_choices(
            recorded("openai-completed"),
            {"finish_reason": "length", "message": {"content": '{"severity": "HI'}},
        ),
        model="m",
        validate=validator,
    )
    assert truncated.finish_reason is FinishReason.truncated
    assert truncated.parsed is None
    assert truncated.message is not None
    block = truncated.message.content[0].root
    assert isinstance(block, TextBlock) and block.text == '{"severity": "HI'
    assert_valid(truncated)


def test_refusal_keeps_provider_text_and_has_no_parsed() -> None:
    raw = with_choices(
        recorded("openai-completed"),
        {"finish_reason": "stop", "message": {"content": None, "refusal": "Tôi không thể hỗ trợ."}},
    )
    response = DRIVERS[Provider.openai].normalize(raw, model="m")
    assert response.finish_reason is FinishReason.refused
    assert response.parsed is None
    assert response.message is not None
    block = response.message.content[0].root
    assert isinstance(block, TextBlock) and "không thể" in block.text
    assert_valid(response)

    empty_refusal = DRIVERS[Provider.anthropic].normalize(
        {**recorded("anthropic-completed"), "stop_reason": "refusal", "content": []},
        model="m",
    )
    assert empty_refusal.finish_reason is FinishReason.refused
    assert empty_refusal.message is not None and empty_refusal.message.content == []
    assert empty_refusal.parsed is None
    assert_valid(empty_refusal)


def test_unknown_finish_keeps_content_as_invalid_output() -> None:
    raw = with_choices(
        recorded("openai-completed"),
        {"finish_reason": "banana", "message": {"content": "lạ"}},
    )
    response = DRIVERS[Provider.openai].normalize(raw, model="m")
    assert response.finish_reason is FinishReason.invalid_output
    assert response.message is not None
    block = response.message.content[0].root
    assert isinstance(block, TextBlock) and block.text == "lạ"
    assert_valid(response)


def test_empty_provider_response_is_provider_error() -> None:
    response = DRIVERS[Provider.anthropic].normalize(
        {"id": "msg_x", "stop_reason": "end_turn", "content": []}, model="m"
    )
    assert response.finish_reason is FinishReason.provider_error
    assert response.error is not None and response.error.code == "INTERNAL_ERROR"
    assert response.message is None
    assert response.provider_meta.response_id == "msg_x"
    assert_valid(response)


def test_completed_with_a_tool_call_is_invalid_output() -> None:
    raw = with_choices(
        recorded("openai-completed"),
        {
            "finish_reason": "stop",
            "message": {
                "content": "xong",
                "tool_calls": [
                    {
                        "id": "call_1",
                        "function": {"name": "dns/resolve", "arguments": "{}"},
                    }
                ],
            },
        },
    )
    response = DRIVERS[Provider.openai].normalize(raw, model="m")
    assert response.finish_reason is FinishReason.invalid_output
    assert_valid(response)


def test_tool_calls_without_a_tool_call_is_invalid_output() -> None:
    response = DRIVERS[Provider.anthropic].normalize(
        {**recorded("anthropic-completed"), "stop_reason": "tool_use"}, model="m"
    )
    assert response.finish_reason is FinishReason.invalid_output
    assert_valid(response)


def test_unparsable_tool_arguments_keep_the_raw_string() -> None:
    raw = with_choices(
        recorded("openai-tool-calls"),
        {
            "finish_reason": "tool_calls",
            "message": {
                "tool_calls": [
                    {
                        "id": "call_1",
                        "function": {"name": "dns/resolve", "arguments": '{"targets":'},
                    }
                ]
            },
        },
    )
    response = DRIVERS[Provider.openai].normalize(raw, model="m")
    assert response.finish_reason is FinishReason.invalid_output
    assert response.message is not None
    block = response.message.content[0].root
    assert isinstance(block, ToolCallBlock)
    call = block.call.root
    assert call.arguments is None
    assert call.arguments_raw == '{"targets":'
    assert_valid(response)


def test_unsupported_anthropic_block_type_is_invalid_output_not_dropped_silently() -> None:
    raw = {
        **recorded("anthropic-completed"),
        "content": [
            {"type": "text", "text": "có suy nghĩ"},
            {"type": "thinking", "thinking": "..."},
        ],
    }
    response = DRIVERS[Provider.anthropic].normalize(raw, model="m")
    assert response.finish_reason is FinishReason.invalid_output
    assert response.message is not None
    assert len(response.message.content) == 1
    assert_valid(response)


def test_response_schema_rejects_non_object_output() -> None:
    raw = with_choices(
        recorded("openai-completed"),
        {"finish_reason": "stop", "message": {"content": json.dumps([1, 2, 3])}},
    )
    response = DRIVERS[Provider.openai].normalize(
        raw, model="m", validate=output_validator({"type": "array"})
    )
    assert response.finish_reason is FinishReason.invalid_output
    assert response.parsed is None
    assert_valid(response)
