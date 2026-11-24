"""Offline support for the M04 tests: recorded payloads, a scripted transport, the S1.4 reference.

No test in this module (or the ones importing it) opens a socket: the recorded provider bodies are
the same ones the contract suite uses, and `ScriptedTransport` plays them back in order.
"""

from __future__ import annotations

import json
import runpy
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from aegis.common.ports import Budget
from aegis.common.repo import repository_root
from aegis.contracts_gen.agent.model_request_v2_schema import ModelRequest, Provider
from aegis.m04_model.transport import TransportError, TransportResponse

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "m04"
CONTRACTS = repository_root() / "contracts"

CAMPAIGN_ID = "01934f6a-0000-7000-8000-000000000001"
SESSION_ID = "01934f6a-0000-7000-8000-000000000002"
TRACE_ID = "0123456789abcdef0123456789abcdef"
EVIDENCE_ID = "01934f6a-0000-7000-8000-0000000e0001"

MODEL_OUTPUT_SCHEMA: dict[str, Any] = {
    "$ref": "https://aegis.io/contracts/finding/severity-assessment.v2.schema.json#/$defs/ModelOutput"
}


def recorded(name: str) -> dict[str, Any]:
    """One recorded provider response body (`tests/fixtures/m04/<name>.json`)."""
    payload: object = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    assert isinstance(payload, dict), f"{name} must be a JSON object"
    return cast(dict[str, Any], payload)


def request(provider: Provider = Provider.openai, model: str = "configured-model") -> ModelRequest:
    return ModelRequest.model_validate(
        {
            "provider": provider.value,
            "model": model,
            "messages": [
                {
                    "role": "user",
                    "content": [{"type": "text", "text": "Mục tiêu: kiểm example.test"}],
                }
            ],
            "campaign_id": CAMPAIGN_ID,
            "session_id": SESSION_ID,
            "trace_id": TRACE_ID,
            "max_output_tokens": 512,
            "timeout_seconds": 60,
        }
    )


def budget(tokens: int = 100_000, cost_usd: float = 1.0) -> Budget:
    return Budget(remaining_tokens=tokens, remaining_cost_usd=cost_usd)


@dataclass(frozen=True, slots=True)
class Step:
    """One scripted provider answer: a raw body or a transport failure."""

    raw: dict[str, Any] | None = None
    error: TransportError | None = None
    latency_ms: int = 0
    cost_usd: float = 0.0


@dataclass
class ScriptedTransport:
    """Plays the steps in order and records every call; never touches the network."""

    steps: Sequence[Step] = field(default_factory=tuple)
    calls: list[dict[str, Any]] = field(default_factory=list)
    _pending: list[Step] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        self._pending = list(self.steps)

    async def send(
        self,
        provider: Provider,
        model: str,
        wire: Mapping[str, Any],
        *,
        timeout_seconds: float,
    ) -> TransportResponse:
        self.calls.append(
            {
                "provider": provider,
                "model": model,
                "wire": dict(wire),
                "timeout_seconds": timeout_seconds,
            }
        )
        if not self._pending:
            raise AssertionError("ScriptedTransport has no step left for this call")
        step = self._pending.pop(0)
        if step.error is not None:
            raise step.error
        if step.raw is None:
            raise AssertionError("a ScriptedTransport step needs raw or error")
        return TransportResponse(raw=step.raw, latency_ms=step.latency_ms, cost_usd=step.cost_usd)


_REFERENCE: dict[str, Any] | None = None


def reference() -> dict[str, Any]:
    """The S1.4 reference behaviour, loaded by path (test-only; never imported as product)."""
    global _REFERENCE
    if _REFERENCE is None:
        _REFERENCE = runpy.run_path(str(CONTRACTS / "tests/model_client_ref.py"))
    return _REFERENCE


def reference_to_wire(provider: Provider, payload: Mapping[str, Any]) -> dict[str, Any]:
    wire: Any = reference()["to_wire"](provider.value, dict(payload))
    return cast(dict[str, Any], wire)


def reference_normalize(
    provider: Provider,
    raw: Mapping[str, Any],
    *,
    validate: Any = None,
    latency_ms: int = 0,
    cost_usd: float = 0.0,
) -> dict[str, Any]:
    result: Any = reference()["normalize_response"](
        provider.value,
        dict(raw),
        validate=validate,
        latency_ms=latency_ms,
        cost_usd=cost_usd,
    )
    return cast(dict[str, Any], result)
