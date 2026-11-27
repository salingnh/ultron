"""Provider-safe function names for the tools a request publishes (item 62, live-run defect 3).

A capability id is an MCP name: `model-request.v2` allows `[A-Za-z0-9._/-]{1,200}`, so our tools are
called `dns.resolve`, `web.probe_http`, ... The OpenAI function-name grammar (and every
OpenAI-compatible provider that validates it, e.g. OpenRouter in front of Nvidia) is
`^[a-zA-Z0-9_-]{1,64}$`: a dot is refused with

    Validation: Function at index 0 has an invalid name: "dns.resolve"

which is a 400 for the whole request - no model ever sees it.

So the wire name is a *provider* name, not a capability id: this module maps one to the other for
both standards (OpenAI Chat Completions and Anthropic Messages share the grammar), and the client
reverses it on the answer, so `model-response.v2` still carries the capability id M05/M03 dispatch
on. Nothing in the contract changes, and no name is invented at random:

* the mapping is deterministic - a name keeps every portable character, `.` becomes `__` (the
  namespace separator), `/` becomes `_slash_`;
* it is reversible *for one request*: `wire_tool_names` returns the table the caller reverses with,
  so a provider echoing our name cannot be misread;
* it refuses instead of guessing: a request whose names cannot be mapped without ambiguity (two
  capability ids landing on the same wire name) or that would exceed the provider's 64-character
  limit is a configuration error, raised before any provider call.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from aegis.contracts_gen.agent.model_request_v2_schema import ModelRequest
from aegis.contracts_gen.agent.model_response_v2_schema import ModelResponse

#: What an OpenAI-compatible or Anthropic provider accepts as a function name.
PORTABLE_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
PORTABLE_MAX_LENGTH = 64

#: Characters a provider refuses, in the form that stays inside its grammar. `.` is the MCP
#: namespace separator and the only one our capability ids use in practice.
_REPLACEMENTS = ((".", "__"), ("/", "_slash_"))


class ToolNameNotPortable(ValueError):
    """A capability id cannot become a provider function name; the message names it and why."""


def provider_tool_name(capability_id: str) -> str:
    """The deterministic wire form of one capability id (still a valid contract name)."""
    name = capability_id
    for character, replacement in _REPLACEMENTS:
        name = name.replace(character, replacement)
    if not name:
        raise ToolNameNotPortable(f"capability id {capability_id!r} is empty")
    if len(name) > PORTABLE_MAX_LENGTH:
        raise ToolNameNotPortable(
            f"capability id {capability_id!r} becomes {name!r}, longer than the provider's "
            f"{PORTABLE_MAX_LENGTH}-character function-name limit"
        )
    if not PORTABLE_NAME.fullmatch(name):
        raise ToolNameNotPortable(
            f"capability id {capability_id!r} becomes {name!r}, which is outside the provider "
            f"function-name grammar {PORTABLE_NAME.pattern}"
        )
    return name


def wire_tool_names(capability_ids: Iterable[str]) -> dict[str, str]:
    """`{capability id: wire name}` for one request, or a refusal that names the clash.

    Ambiguity is refused, never papered over with a suffix: a suffix would make the same capability
    id mean different things in different requests, and the reversed name (which M03 dispatches on)
    is the one thing that must never shift.
    """
    mapping: dict[str, str] = {}
    claimed: dict[str, str] = {}
    for capability_id in capability_ids:
        wire = provider_tool_name(capability_id)
        if capability_id in mapping:
            raise ToolNameNotPortable(
                f"capability id {capability_id!r} is published twice in one request"
            )
        previous = claimed.get(wire)
        if previous is not None:
            raise ToolNameNotPortable(
                f"capability ids {previous!r} and {capability_id!r} both map to the provider name "
                f"{wire!r}; rename one of them (the wire name must map back to exactly one tool)"
            )
        mapping[capability_id] = wire
        claimed[wire] = capability_id
    return mapping


def request_tool_names(request: ModelRequest) -> list[str]:
    """Every capability id the request mentions: published tools and its own tool-call history."""
    names: list[str] = [tool.name for tool in request.tools or ()]
    for message in request.messages:
        for block in message.content:
            root: Any = block.root
            if getattr(root, "type", None) == "tool_call":
                # `call` is the contract's ToolCall root model over the two argument forms.
                names.append(root.call.root.name)
            elif getattr(root, "type", None) == "tool_result":
                names.append(root.result.name)
    return list(dict.fromkeys(names))


def portable_request(request: ModelRequest, mapping: Mapping[str, str]) -> ModelRequest:
    """The same request with every tool name in its wire form (revalidated against the contract)."""
    payload = request.model_dump(mode="json", exclude_unset=True)
    for tool in payload.get("tools") or []:
        tool["name"] = mapping.get(tool["name"], tool["name"])
    for message in payload.get("messages") or []:
        for block in message.get("content") or []:
            holder = block.get("call") if block.get("type") == "tool_call" else block.get("result")
            if isinstance(holder, dict) and isinstance(holder.get("name"), str):
                holder["name"] = mapping.get(holder["name"], holder["name"])
    return ModelRequest.model_validate(payload)


def restore_tool_names(response: ModelResponse, reverse: Mapping[str, str]) -> ModelResponse:
    """The answer with every wire tool name back to its capability id (still contract-valid).

    Only names this request published are reversed: a provider naming something we never sent keeps
    its own name, which the contract validates and the caller's tool dispatch reports as unknown.
    """
    if response.message is None or not reverse:
        return response
    payload = response.model_dump(mode="json", exclude_unset=True)
    message = payload.get("message") or {}
    for block in message.get("content") or []:
        holder = block.get("call")
        if block.get("type") == "tool_call" and isinstance(holder, dict):
            name = holder.get("name")
            if isinstance(name, str) and name in reverse:
                holder["name"] = reverse[name]
    return ModelResponse.model_validate(payload)


__all__ = [
    "PORTABLE_MAX_LENGTH",
    "PORTABLE_NAME",
    "ToolNameNotPortable",
    "portable_request",
    "provider_tool_name",
    "request_tool_names",
    "restore_tool_names",
    "wire_tool_names",
]
