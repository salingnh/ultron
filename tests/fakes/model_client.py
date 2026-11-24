"""Fake M04 ModelClient: scripted contract responses, no provider and no network."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from aegis.common.ports import Budget, BudgetExceeded, ModelClient
from aegis.contracts_gen.agent.model_request_v2_schema import ModelRequest
from aegis.contracts_gen.agent.model_response_v2_schema import ModelResponse


@dataclass
class FakeModelClient(ModelClient):
    """Returns the scripted `model-response.v2` payloads in order and records every call.

    The budget check happens before the response is handed out, which is the interface promise
    ("BudgetExceeded khi ngân sách chiến dịch hết trước lời gọi; không gọi model"): an exhausted
    budget raises and `calls` shows the attempt for the ledger.
    """

    responses: Sequence[ModelResponse]
    calls: list[ModelRequest] = field(default_factory=list, init=False)
    _next: int = field(default=0, init=False)

    async def complete(self, req: ModelRequest, budget: Budget) -> ModelResponse:
        self.calls.append(req)
        if budget.remaining_tokens <= 0:
            raise BudgetExceeded(
                f"campaign budget exhausted: remaining_tokens={budget.remaining_tokens}"
            )
        if self._next >= len(self.responses):
            raise RuntimeError("FakeModelClient has no scripted response left")
        response = self.responses[self._next]
        self._next += 1
        return response
