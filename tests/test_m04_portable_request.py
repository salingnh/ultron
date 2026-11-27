"""A model request is portable to any OpenAI-compatible provider, and names its session (item 62).

Two findings from the owner's live run against a real upstream (OpenRouter in front of Nvidia):

* a capability id is not a provider function name. Our tools are `dns.resolve`; the OpenAI
  function-name grammar is `^[a-zA-Z0-9_-]{1,64}$`, and the provider answered

      Validation: Function at index 0 has an invalid name: "dns.resolve"

  which is a 400 for the whole request - no model ever sees it. M04 now publishes the provider form
  (`dns__resolve`) and reverses it on the answer, for both standards, so `model-request.v2` /
  `model-response.v2` and every MCP name stay unchanged;
* the OpenCode Go provider refuses a request with no session identity. Behind the gateway every call
  carries `x-litellm-session-id` = the agent session id (LiteLLM forwards it as
  `x-opencode-session`), and every call carries the product user agent `aegis-ultron/<version>`.

No test here opens a socket: the provider boundary is an injected `post`, and the gateway is a
deployment built from environment variables.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import pytest

from aegis import validation
from aegis.common.ports import Budget
from aegis.contracts_gen.agent.model_message_v2_schema import ToolCallBlock
from aegis.contracts_gen.agent.model_request_v2_schema import ModelRequest, Provider
from aegis.contracts_gen.agent.model_response_v2_schema import FinishReason
from aegis.m04_model.deployment import ModelDeployment
from aegis.m04_model.tool_names import (
    PORTABLE_MAX_LENGTH,
    PORTABLE_NAME,
    ToolNameNotPortable,
    portable_request,
    provider_tool_name,
    request_tool_names,
    restore_tool_names,
    wire_tool_names,
)
from aegis.m04_model.usage import InMemoryUsageSink
from tests.m04_support import CAMPAIGN_ID, SESSION_ID, TRACE_ID

SECRET = "sk-portable-not-a-real-key"
MODEL = "aegis-smart"

CAPABILITY = "dns.resolve"


def tool(name: str = CAPABILITY) -> dict[str, Any]:
    return {
        "name": name,
        "description": "Resolve a name on the authorized target.",
        "input_schema": {"type": "object", "properties": {"name": {"type": "string"}}},
    }


def request_with_tools(
    provider: Provider = Provider.openai, session_id: str = SESSION_ID
) -> ModelRequest:
    """A request with a published tool and one earlier round trip that used it."""
    return ModelRequest.model_validate(
        {
            "provider": provider.value,
            "model": MODEL,
            "messages": [
                {
                    "role": "user",
                    "content": [{"type": "text", "text": "Mục tiêu: lab.aegis.test"}],
                },
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_call",
                            "call": {
                                "id": "call_1",
                                "name": CAPABILITY,
                                "arguments_raw": '{"name":"lab.aegis.test"}',
                                "arguments": {"name": "lab.aegis.test"},
                            },
                        }
                    ],
                },
                {
                    "role": "tool",
                    "content": [
                        {
                            "type": "tool_result",
                            "result": {
                                "call_id": "call_1",
                                "name": CAPABILITY,
                                "content": [{"type": "text", "text": "10.114.53.10"}],
                            },
                        }
                    ],
                },
            ],
            "tools": [tool()],
            "campaign_id": CAMPAIGN_ID,
            "session_id": session_id,
            "trace_id": TRACE_ID,
            "max_output_tokens": 128,
            "timeout_seconds": 30,
        }
    )


def openai_tool_call(name: str) -> dict[str, Any]:
    return {
        "id": "chatcmpl-fake",
        "object": "chat.completion",
        "created": 1,
        "model": MODEL,
        "choices": [
            {
                "index": 0,
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "call_2",
                            "type": "function",
                            "function": {"name": name, "arguments": '{"name":"a.test"}'},
                        }
                    ],
                },
            }
        ],
        "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
    }


def anthropic_tool_call(name: str) -> dict[str, Any]:
    return {
        "id": "msg_fake",
        "type": "message",
        "role": "assistant",
        "model": MODEL,
        "content": [
            {"type": "tool_use", "id": "call_2", "name": name, "input": {"name": "a.test"}}
        ],
        "stop_reason": "tool_use",
        "usage": {"input_tokens": 5, "output_tokens": 2},
    }


class CapturedTransport:
    """Records what the client would put on the wire; answers with one canned body."""

    def __init__(self, raw: dict[str, Any]) -> None:
        self.raw = raw
        self.calls: list[dict[str, Any]] = []

    async def send(
        self,
        provider: Provider,
        model: str,
        wire: Mapping[str, Any],
        *,
        timeout_seconds: float,
        headers: Mapping[str, str] | None = None,
    ) -> Any:
        from aegis.m04_model.transport import TransportResponse

        self.calls.append(
            {"wire": dict(wire), "headers": dict(headers or {}), "provider": provider}
        )
        return TransportResponse(raw=self.raw, latency_ms=1, cost_usd=0.0001)


def gateway_deployment(**overrides: str) -> ModelDeployment:
    environment = {
        "AEGIS_SESSION_LIVE_MODEL": "1",
        "AEGIS_MODEL_GATEWAY": "1",
        "AEGIS_MODEL_PROVIDER": "openai",
        "AEGIS_MODEL_NAME": MODEL,
        "AEGIS_MODEL_BASE_URL": "http://127.0.0.1:14000/v1",
        "AEGIS_MODEL_API_KEY": SECRET,
        "AEGIS_MODEL_PRICE_INPUT_PER_MTOK": "1.0",
        "AEGIS_MODEL_PRICE_OUTPUT_PER_MTOK": "2.0",
        **overrides,
    }
    return ModelDeployment.from_env(environment)


# ---------------------------------------------------------------------------
# the mapping itself
# ---------------------------------------------------------------------------


def test_a_capability_id_becomes_a_provider_function_name() -> None:
    assert provider_tool_name("dns.resolve") == "dns__resolve"
    assert provider_tool_name("web/probe") == "web_slash_probe"
    assert provider_tool_name("web_probe_http") == "web_probe_http", "a portable name is untouched"
    assert PORTABLE_NAME.fullmatch(provider_tool_name("web.probe_http")), (
        "every published name matches the provider grammar"
    )


def test_the_mapping_reverses_every_name_it_publishes() -> None:
    names = ["dns.resolve", "web_probe_http", "graph.neighbors", "graph/neighbors"]
    mapping = wire_tool_names(names)
    reverse = {wire: capability for capability, wire in mapping.items()}
    assert sorted(reverse[wire] for wire in mapping.values()) == sorted(names)
    for capability, wire in mapping.items():
        assert PORTABLE_NAME.fullmatch(wire), (capability, wire)
        assert reverse[wire] == capability


def test_two_ids_that_would_share_a_wire_name_are_refused() -> None:
    with pytest.raises(ToolNameNotPortable) as refusal:
        wire_tool_names(["dns.resolve", "dns__resolve"])
    message = str(refusal.value)
    assert "dns.resolve" in message and "dns__resolve" in message, message
    assert "rename one" in message


def test_a_name_longer_than_the_provider_limit_is_refused() -> None:
    long_id = "a" * (PORTABLE_MAX_LENGTH - 1) + ".b"
    with pytest.raises(ToolNameNotPortable) as refusal:
        provider_tool_name(long_id)
    assert f"{PORTABLE_MAX_LENGTH}-character" in str(refusal.value)
    assert long_id in str(refusal.value), "the refusal names the capability id to rename"


def test_the_same_id_twice_in_one_request_is_refused() -> None:
    with pytest.raises(ToolNameNotPortable):
        wire_tool_names(["dns.resolve", "dns.resolve"])


def test_the_request_names_include_tools_and_history() -> None:
    assert request_tool_names(request_with_tools()) == [CAPABILITY]


# ---------------------------------------------------------------------------
# the wire body and the normalized answer
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("provider", "raw"),
    [
        (Provider.openai, openai_tool_call("dns__resolve")),
        (Provider.anthropic, anthropic_tool_call("dns__resolve")),
    ],
)
def test_the_provider_sees_a_portable_name_and_the_agent_sees_the_capability_id(
    provider: Provider, raw: dict[str, Any]
) -> None:
    client_request = request_with_tools(provider)
    transport = CapturedTransport(raw)
    deployment = gateway_deployment(
        AEGIS_MODEL_PROVIDER=provider.value, AEGIS_MODEL_NAME=client_request.model
    )
    from aegis.m04_model.client import ModelClient

    client = ModelClient(
        transport, InMemoryUsageSink(), deployment.client(InMemoryUsageSink()).config
    )
    response = __import__("asyncio").run(
        client.complete(client_request, Budget(remaining_tokens=10_000, remaining_cost_usd=1.0))
    )

    wire = transport.calls[0]["wire"]
    if provider is Provider.openai:
        published = [entry["function"]["name"] for entry in wire["tools"]]
        assistant = next(message for message in wire["messages"] if message["role"] == "assistant")
        history_name = assistant["tool_calls"][0]["function"]["name"]
    else:
        published = [entry["name"] for entry in wire["tools"]]
        assistant = next(message for message in wire["messages"] if message["role"] == "assistant")
        history_name = next(
            block["name"] for block in assistant["content"] if block["type"] == "tool_use"
        )
    assert published == ["dns__resolve"], published
    for name in published:
        assert PORTABLE_NAME.fullmatch(name), name
    # The history replays the earlier call under the same provider name, or the provider would see
    # a tool call it never issued.
    assert history_name == "dns__resolve", assistant

    assert response.finish_reason is FinishReason.tool_calls, response
    assert response.message is not None
    calls = [block for block in response.message.content if isinstance(block.root, ToolCallBlock)]
    assert len(calls) == 1
    assert calls[0].root.call.root.name == CAPABILITY, "the agent gets the capability id back"
    validation.validate_model("agent/model-response.v2.schema.json", response)


def test_a_provider_name_we_never_published_keeps_its_own_name() -> None:
    """A hallucinated tool call is the caller's to reject; it must not be silently renamed."""
    client_request = request_with_tools()
    mapping = {
        name: wire for name, wire in wire_tool_names(request_tool_names(client_request)).items()
    }
    portable = portable_request(client_request, mapping)
    assert portable.tools is not None and portable.tools[0].name == "dns__resolve"

    from aegis.m04_model.drivers import OpenAIChatDriver

    response = OpenAIChatDriver().normalize(openai_tool_call("invented_tool"), model=MODEL)
    restored = restore_tool_names(response, {"dns__resolve": CAPABILITY})
    assert restored.message is not None
    name = next(
        block.root.call.root.name
        for block in restored.message.content
        if isinstance(block.root, ToolCallBlock)
    )
    assert name == "invented_tool"


# ---------------------------------------------------------------------------
# the call itself: session identity and product user agent
# ---------------------------------------------------------------------------


def headers_of(deployment: ModelDeployment, request: ModelRequest) -> dict[str, str]:
    seen: list[dict[str, str]] = []

    def post(url: str, headers: dict[str, str], body: bytes, timeout: float) -> Any:
        from aegis.m04_model.transport import HttpAnswer

        seen.append(dict(headers))
        return HttpAnswer(
            200,
            json.dumps(openai_tool_call("dns__resolve")).encode(),
            {"x-litellm-response-cost": "0.000002", "content-type": "application/json"},
        )

    import asyncio

    client = deployment.client(InMemoryUsageSink(), post=post)
    asyncio.run(client.complete(request, Budget(remaining_tokens=10_000, remaining_cost_usd=1.0)))
    assert len(seen) == 1
    return seen[0]


def test_a_gateway_call_names_its_session_and_the_product() -> None:
    request = request_with_tools()
    headers = headers_of(gateway_deployment(), request)
    assert headers["x-litellm-session-id"] == SESSION_ID, headers
    assert headers["user-agent"].startswith("aegis-ultron/"), headers
    assert headers["authorization"] == f"Bearer {SECRET}"

    # The same session sends the same id (a gateway's affinity/session forwarding relies on it),
    # a new session a different one, and nothing in it is personal data.
    again = headers_of(gateway_deployment(), request)
    assert again["x-litellm-session-id"] == headers["x-litellm-session-id"]
    other = headers_of(
        gateway_deployment(), request_with_tools(session_id="01934f6a-0000-7000-8000-0000000000ff")
    )
    assert other["x-litellm-session-id"] != headers["x-litellm-session-id"]


def test_a_direct_provider_call_sends_no_gateway_session_header() -> None:
    deployment = gateway_deployment(
        AEGIS_MODEL_GATEWAY="0", AEGIS_MODEL_BASE_URL="https://api.test/v1"
    )
    headers = headers_of(deployment, request_with_tools())
    assert "x-litellm-session-id" not in headers, (
        "the header is the gateway's contract, not a provider's"
    )
    assert headers["user-agent"].startswith("aegis-ultron/"), headers
