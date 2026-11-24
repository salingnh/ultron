"""Readers for untrusted raw provider JSON (shared by the drivers and the live transport).

Provider bodies are data from outside the process: a field may be missing, null or of the wrong
type. These readers never raise; they return a safe value so normalization can mark the answer
`invalid_output` instead of crashing the agent session.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from aegis.contracts_gen.agent.model_request_v2_schema import Provider


def as_dict(value: Any) -> dict[str, Any]:
    """`value` when it is a JSON object, else an empty object."""
    return value if isinstance(value, dict) else {}


def as_non_negative_int(value: Any) -> int:
    """A token count; provider booleans/floats/negatives are not counts."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return int(value)


def usage_tokens(provider: Provider, raw: Mapping[str, Any]) -> tuple[int, int]:
    """`(input_tokens, output_tokens)` of a raw response; 0 when the provider omitted them."""
    usage = as_dict(raw.get("usage"))
    if provider is Provider.openai:
        return as_non_negative_int(usage.get("prompt_tokens")), as_non_negative_int(
            usage.get("completion_tokens")
        )
    return as_non_negative_int(usage.get("input_tokens")), as_non_negative_int(
        usage.get("output_tokens")
    )
