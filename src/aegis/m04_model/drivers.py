"""OpenAI Chat Completions and Anthropic Messages drivers (C07).

Each driver has two halves and no I/O of its own:

* `to_wire` maps `model-request.v2` to the provider's request body, keeping every tool call's id,
  name and raw arguments so a second (and later) round trip sends back exactly what the provider
  issued;
* `normalize` maps the provider's JSON answer back to `model-response.v2`: the six normalized
  finish reasons, provider metadata, typed content blocks, and `provider_error` without a message.

Behaviour follows the S1.4 reference (`contracts/tests/model_client_ref.py`); the tests compare
both halves byte-for-byte with it on recorded payloads. Provider output is untrusted input, so a
malformed shape becomes `invalid_output` (raw text kept) or `provider_error`; it never raises and
is never silently repaired. Two contract rules the reference leaves to the caller are enforced
here: `completed` carries no tool call and `tool_calls` carries at least one.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from aegis.contracts_gen.agent.model_message_v2_schema import (
    ContentBlock,
    Role,
    TextBlock,
    ToolCallBlock,
    ToolResultBlock,
)
from aegis.contracts_gen.agent.model_request_v2_schema import ModelRequest, Provider
from aegis.contracts_gen.agent.model_response_v2_schema import FinishReason, ModelResponse
from aegis.contracts_gen.common.error_v2_schema import ErrorCode, NextAction
from aegis.m04_model.raw import as_dict, usage_tokens
from aegis.m04_model.transport import TransportError

OutputValidator = Callable[[Any], list[str]]

#: `model-message.v2` patterns; a provider value outside them cannot become a contract block.
_CALL_ID = re.compile(r"^[A-Za-z0-9_-]{1,200}$")
_TOOL_NAME = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")

_TEXT_LIMIT = 100_000
_ERROR_MESSAGE_LIMIT = 2_000

RAW_FINISH: dict[Provider, dict[str, FinishReason]] = {
    Provider.openai: {
        "stop": FinishReason.completed,
        "tool_calls": FinishReason.tool_calls,
        "length": FinishReason.truncated,
        "content_filter": FinishReason.refused,
    },
    Provider.anthropic: {
        "end_turn": FinishReason.completed,
        "tool_use": FinishReason.tool_calls,
        "max_tokens": FinishReason.truncated,
        "refusal": FinishReason.refused,
    },
}

_NEXT_ACTION: dict[ErrorCode, NextAction] = {
    ErrorCode.RATE_LIMITED: NextAction.RETRY_LATER,
    ErrorCode.NETWORK_TIMEOUT: NextAction.RETRY,
    ErrorCode.EXECUTION_TIMEOUT: NextAction.RETRY_LATER,
    ErrorCode.POLICY_DENIED: NextAction.NONE,
}


def next_action(code: ErrorCode) -> NextAction:
    """The `next_action` error.v2 pairs with a provider/transport failure code."""
    return _NEXT_ACTION.get(code, NextAction.CHECK_PROVIDER)


class ProviderDriver(Protocol):
    """One provider dialect: request wire form and response normalization."""

    provider: Provider

    def to_wire(self, request: ModelRequest, *, model: str) -> dict[str, Any]: ...

    def normalize(
        self,
        raw: Mapping[str, Any],
        *,
        model: str,
        validate: OutputValidator | None = None,
        latency_ms: int = 0,
        cost_usd: float = 0.0,
    ) -> ModelResponse: ...


@dataclass(frozen=True, slots=True)
class _Parsed:
    """Provider-specific reading of one response, before the shared finish/parsed rules."""

    blocks: list[dict[str, Any]]
    finish: FinishReason | None
    input_tokens: int
    output_tokens: int
    provider_meta: dict[str, Any]
    protocol_error: str | None
    model_version: str | None


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _clamp(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[:limit]


def _text_of(blocks: Sequence[ContentBlock]) -> str:
    return "\n".join(block.root.text for block in blocks if isinstance(block.root, TextBlock))


def _text_of_text(blocks: Sequence[TextBlock]) -> str:
    return "\n".join(block.text for block in blocks)


def _tool_call_wire(call: ToolCallBlock, provider: Provider) -> dict[str, Any]:
    """One assistant tool call in provider form; raw arguments kept when the provider sent them."""
    inner = call.call.root
    if provider is Provider.openai:
        arguments = inner.arguments_raw or json.dumps(
            inner.arguments if inner.arguments is not None else {},
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return {
            "id": inner.id,
            "type": "function",
            "function": {"name": inner.name, "arguments": arguments},
        }
    if inner.arguments is None:
        raise ValueError(
            f"tool_call {inner.id} has no parsed arguments; refusing to send a fabricated input"
        )
    return {"type": "tool_use", "id": inner.id, "name": inner.name, "input": inner.arguments}


def provider_error_response(
    provider: Provider,
    model: str,
    error: TransportError,
    *,
    latency_ms: int = 0,
) -> ModelResponse:
    """`model-response.v2` for a failed provider call: `provider_error`, no message, no parsed."""
    error_payload: dict[str, Any] = {
        "code": error.code.value,
        "message": _clamp(error.message, _ERROR_MESSAGE_LIMIT),
        "next_action": next_action(error.code).value,
    }
    if error.retry_after_seconds is not None:
        error_payload["retry_after_seconds"] = error.retry_after_seconds
    return ModelResponse.model_validate(
        {
            "provider": provider.value,
            "model": _clamp(model, 200),
            "finish_reason": FinishReason.provider_error.value,
            "provider_meta": {"provider": provider.value},
            "usage": {
                "input_tokens": 0,
                "output_tokens": 0,
                "cost_usd": 0.0,
                "latency_ms": max(0, latency_ms),
            },
            "error": error_payload,
        }
    )


def _build_response(
    provider: Provider,
    model: str,
    parsed: _Parsed,
    *,
    validate: OutputValidator | None,
    latency_ms: int,
    cost_usd: float,
) -> ModelResponse:
    finish = parsed.finish
    if parsed.protocol_error is not None:
        finish = FinishReason.invalid_output
    elif finish is None and parsed.blocks:
        finish = FinishReason.invalid_output
    if not parsed.blocks and finish is not FinishReason.refused:
        finish = FinishReason.provider_error

    has_tool_call = any(block.get("type") == "tool_call" for block in parsed.blocks)
    if finish is FinishReason.completed and has_tool_call:
        finish = FinishReason.invalid_output
        parsed = _Parsed(
            parsed.blocks,
            finish,
            parsed.input_tokens,
            parsed.output_tokens,
            parsed.provider_meta,
            "completed response carries a tool call",
            parsed.model_version,
        )
    elif finish is FinishReason.tool_calls and not has_tool_call:
        finish = FinishReason.invalid_output
        parsed = _Parsed(
            parsed.blocks,
            finish,
            parsed.input_tokens,
            parsed.output_tokens,
            parsed.provider_meta,
            "tool_calls response carries no tool call",
            parsed.model_version,
        )

    parsed_output: dict[str, Any] | None = None
    if finish is FinishReason.completed and validate is not None:
        text = "\n".join(block["text"] for block in parsed.blocks if block.get("type") == "text")
        try:
            candidate: Any = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            finish = FinishReason.invalid_output
        else:
            if not isinstance(candidate, dict) or list(validate(candidate)):
                finish = FinishReason.invalid_output
            else:
                parsed_output = candidate

    assert finish is not None  # every branch above selects a normalized value
    payload: dict[str, Any] = {
        "provider": provider.value,
        "model": _clamp(parsed.model_version or model, 200),
        "finish_reason": finish.value,
        "provider_meta": parsed.provider_meta,
        "usage": {
            "input_tokens": parsed.input_tokens,
            "output_tokens": parsed.output_tokens,
            "cost_usd": float(cost_usd),
            "latency_ms": max(0, latency_ms),
        },
    }
    if finish is FinishReason.provider_error:
        payload["error"] = {
            "code": ErrorCode.INTERNAL_ERROR.value,
            "message": _clamp(
                parsed.protocol_error or "provider returned no usable content",
                _ERROR_MESSAGE_LIMIT,
            ),
            "next_action": NextAction.CHECK_PROVIDER.value,
        }
    else:
        payload["message"] = {"role": "assistant", "content": parsed.blocks}
    if parsed_output is not None:
        payload["parsed"] = parsed_output
    return ModelResponse.model_validate(payload)


def _meta(provider: Provider, raw: Mapping[str, Any]) -> tuple[dict[str, Any], str | None]:
    meta: dict[str, Any] = {"provider": provider.value}
    response_id = raw.get("id")
    if isinstance(response_id, str) and response_id:
        meta["response_id"] = _clamp(response_id, 200)
    model_version = raw.get("model")
    if isinstance(model_version, str) and model_version:
        meta["model_version"] = _clamp(model_version, 200)
        return meta, model_version
    return meta, None


# ---------------------------------------------------------------------------
# OpenAI Chat Completions
# ---------------------------------------------------------------------------


class OpenAIChatDriver:
    """Chat Completions wire form (`messages`, `tool_calls`, `response_format`)."""

    provider = Provider.openai

    def to_wire(self, request: ModelRequest, *, model: str) -> dict[str, Any]:
        messages: list[dict[str, Any]] = []
        for message in request.messages:
            role = message.role.value
            if role == Role.tool.value:
                for block in message.content:
                    if isinstance(block.root, ToolResultBlock):
                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": block.root.result.call_id,
                                "content": _text_of_text(block.root.result.content),
                            }
                        )
                continue
            if role == Role.assistant.value:
                calls = [
                    _tool_call_wire(block.root, self.provider)
                    for block in message.content
                    if isinstance(block.root, ToolCallBlock)
                ]
                outgoing: dict[str, Any] = {
                    "role": "assistant",
                    "content": _text_of(message.content) or None,
                }
                if calls:
                    outgoing["tool_calls"] = calls
                messages.append(outgoing)
                continue
            messages.append({"role": role, "content": _text_of(message.content)})

        wire: dict[str, Any] = {
            "model": model,
            "max_tokens": request.max_output_tokens,
            "messages": messages,
        }
        if request.tools:
            wire["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": tool.input_schema,
                    },
                }
                for tool in request.tools
            ]
        if request.response_schema is not None:
            wire["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "response",
                    "schema": request.response_schema,
                    "strict": True,
                },
            }
        return wire

    def normalize(
        self,
        raw: Mapping[str, Any],
        *,
        model: str,
        validate: OutputValidator | None = None,
        latency_ms: int = 0,
        cost_usd: float = 0.0,
    ) -> ModelResponse:
        return _build_response(
            self.provider,
            model,
            self._parse(raw),
            validate=validate,
            latency_ms=latency_ms,
            cost_usd=cost_usd,
        )

    def _parse(self, raw: Mapping[str, Any]) -> _Parsed:
        provider_meta, model_version = _meta(self.provider, raw)
        choices = raw.get("choices")
        if not isinstance(choices, list) or not choices:
            return _Parsed(
                [], None, 0, 0, provider_meta, "provider response has no choices", model_version
            )
        choice = as_dict(choices[0])
        message = as_dict(choice.get("message"))
        raw_finish = choice.get("finish_reason")
        raw_finish = raw_finish if isinstance(raw_finish, str) and raw_finish else None
        if raw_finish is not None:
            provider_meta["raw_finish_reason"] = _clamp(raw_finish, 100)

        blocks: list[dict[str, Any]] = []
        protocol_error: str | None = None
        content = message.get("content")
        if isinstance(content, str) and content:
            blocks.append({"type": "text", "text": _clamp(content, _TEXT_LIMIT)})
        elif content is not None and not isinstance(content, str):
            protocol_error = "message content is not a string"
        refusal = message.get("refusal")
        if isinstance(refusal, str) and refusal:
            blocks.append({"type": "text", "text": _clamp(refusal, _TEXT_LIMIT)})
        elif refusal is not None and not isinstance(refusal, str):
            protocol_error = "message refusal is not a string"
        is_refusal = bool(isinstance(refusal, str) and refusal) or raw_finish == "content_filter"

        tool_calls = message.get("tool_calls")
        if tool_calls is not None and not isinstance(tool_calls, list):
            protocol_error = "message tool_calls is not a list"
        for item in tool_calls if isinstance(tool_calls, list) else []:
            item = as_dict(item)
            function = as_dict(item.get("function"))
            call_id = item.get("id")
            name = function.get("name")
            if not (isinstance(call_id, str) and _CALL_ID.fullmatch(call_id)):
                protocol_error = "tool call id does not match model-message.v2"
                continue
            if not (isinstance(name, str) and _TOOL_NAME.fullmatch(name)):
                protocol_error = "tool call name does not match model-message.v2"
                continue
            call: dict[str, Any] = {"id": call_id, "name": name}
            raw_arguments = function.get("arguments")
            if isinstance(raw_arguments, str):
                call["arguments_raw"] = _clamp(raw_arguments, _TEXT_LIMIT)
                try:
                    arguments: Any = json.loads(raw_arguments)
                except json.JSONDecodeError:
                    protocol_error = "tool call arguments are not valid JSON"
                else:
                    if isinstance(arguments, dict):
                        call["arguments"] = arguments
                    else:
                        protocol_error = "tool call arguments are not a JSON object"
            elif raw_arguments is None:
                call["arguments"] = {}
            else:
                protocol_error = "tool call arguments are not a string"
            blocks.append({"type": "tool_call", "call": call})

        input_tokens, output_tokens = usage_tokens(self.provider, raw)
        finish = RAW_FINISH[self.provider].get(raw_finish) if raw_finish else None
        if is_refusal:
            finish = FinishReason.refused
        return _Parsed(
            blocks,
            finish,
            input_tokens,
            output_tokens,
            provider_meta,
            protocol_error,
            model_version,
        )


# ---------------------------------------------------------------------------
# Anthropic Messages
# ---------------------------------------------------------------------------


class AnthropicMessagesDriver:
    """Messages wire form (`system`, typed content blocks, `tool_use`/`tool_result`)."""

    provider = Provider.anthropic

    def to_wire(self, request: ModelRequest, *, model: str) -> dict[str, Any]:
        system = "\n\n".join(
            _text_of(message.content) for message in request.messages if message.role is Role.system
        )
        messages: list[dict[str, Any]] = []
        for message in request.messages:
            role = message.role.value
            if role == Role.system.value:
                continue
            if role == Role.tool.value:
                results = [
                    {
                        "type": "tool_result",
                        "tool_use_id": block.root.result.call_id,
                        "content": _text_of_text(block.root.result.content),
                        "is_error": bool(block.root.result.is_error),
                    }
                    for block in message.content
                    if isinstance(block.root, ToolResultBlock)
                ]
                messages.append({"role": "user", "content": results})
                continue
            if role == Role.assistant.value:
                blocks: list[dict[str, Any]] = []
                for block in message.content:
                    if isinstance(block.root, TextBlock):
                        blocks.append({"type": "text", "text": block.root.text})
                    elif isinstance(block.root, ToolCallBlock):
                        blocks.append(_tool_call_wire(block.root, self.provider))
                messages.append({"role": "assistant", "content": blocks})
                continue
            messages.append(
                {"role": "user", "content": [{"type": "text", "text": _text_of(message.content)}]}
            )

        wire: dict[str, Any] = {
            "model": model,
            "max_tokens": request.max_output_tokens,
            "messages": messages,
        }
        if system:
            wire["system"] = system
        if request.tools:
            wire["tools"] = [
                {
                    "name": tool.name,
                    "description": tool.description,
                    "input_schema": tool.input_schema,
                }
                for tool in request.tools
            ]
        return wire

    def normalize(
        self,
        raw: Mapping[str, Any],
        *,
        model: str,
        validate: OutputValidator | None = None,
        latency_ms: int = 0,
        cost_usd: float = 0.0,
    ) -> ModelResponse:
        return _build_response(
            self.provider,
            model,
            self._parse(raw),
            validate=validate,
            latency_ms=latency_ms,
            cost_usd=cost_usd,
        )

    def _parse(self, raw: Mapping[str, Any]) -> _Parsed:
        provider_meta, model_version = _meta(self.provider, raw)
        content = raw.get("content")
        protocol_error: str | None = None
        if content is None:
            content = []
        if not isinstance(content, list):
            protocol_error = "content is not a list"
            content = []

        blocks: list[dict[str, Any]] = []
        for block in content:
            block = as_dict(block)
            block_type = block.get("type")
            if block_type == "text":
                text = block.get("text")
                if isinstance(text, str):
                    blocks.append({"type": "text", "text": _clamp(text, _TEXT_LIMIT)})
                else:
                    protocol_error = "text block has no string text"
            elif block_type == "tool_use":
                call_id = block.get("id")
                name = block.get("name")
                arguments = block.get("input")
                if not (isinstance(call_id, str) and _CALL_ID.fullmatch(call_id)):
                    protocol_error = "tool_use id does not match model-message.v2"
                    continue
                if not (isinstance(name, str) and _TOOL_NAME.fullmatch(name)):
                    protocol_error = "tool_use name does not match model-message.v2"
                    continue
                if not isinstance(arguments, dict):
                    protocol_error = "tool_use input is not an object"
                    arguments = {}
                blocks.append(
                    {
                        "type": "tool_call",
                        "call": {"id": call_id, "name": name, "arguments": arguments},
                    }
                )
            else:
                # Never drop an unknown block silently: thinking/signature blocks cannot round-trip
                # through model-message.v2, so the answer is unusable as structured output.
                protocol_error = f"unsupported content block type {block_type!r}"

        raw_finish = raw.get("stop_reason")
        raw_finish = raw_finish if isinstance(raw_finish, str) and raw_finish else None
        if raw_finish is not None:
            provider_meta["raw_finish_reason"] = _clamp(raw_finish, 100)
        input_tokens, output_tokens = usage_tokens(self.provider, raw)
        finish = RAW_FINISH[self.provider].get(raw_finish) if raw_finish else None
        if is_refusal(raw_finish):
            finish = FinishReason.refused
        return _Parsed(
            blocks,
            finish,
            input_tokens,
            output_tokens,
            provider_meta,
            protocol_error,
            model_version,
        )


def is_refusal(raw_finish: str | None) -> bool:
    """A stop reason the provider itself labels a refusal (Anthropic `refusal`)."""
    return raw_finish == "refusal"


#: The drivers a client has by default; both are stateless and safe to share.
DEFAULT_DRIVERS: tuple[OpenAIChatDriver | AnthropicMessagesDriver, ...] = (
    OpenAIChatDriver(),
    AnthropicMessagesDriver(),
)
