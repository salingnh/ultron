"""First-class fake M04 driver for G1 (leader decision: the model is fake unless a live flag is on).

It implements the same port and the same rules as `ModelClient` - request/response contract
validation, budget pre-check before handing out a scripted answer, one usage row per attempt - but
plays back scripted `model-response.v2` payloads instead of reaching a provider. Agent-session
tests and the G1 demo therefore exercise the real caller path (budget, usage, finish handling)
while sending nothing.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from aegis import validation
from aegis.common.ports import Budget, BudgetExceeded
from aegis.contracts_gen.agent.model_request_v2_schema import ModelRequest
from aegis.contracts_gen.agent.model_response_v2_schema import FinishReason, ModelResponse
from aegis.contracts_gen.common.error_v2_schema import ErrorCode
from aegis.m04_model.client import REQUEST_SCHEMA, RESPONSE_SCHEMA
from aegis.m04_model.config import ProviderSpec
from aegis.m04_model.usage import InMemoryUsageSink, UsageSink, model_usage_row


@dataclass
class FakeModelClient:
    """Scripted answers in order, with the production budget/usage behaviour around them."""

    responses: Sequence[ModelResponse]
    usage: UsageSink = field(default_factory=InMemoryUsageSink)
    calls: list[ModelRequest] = field(default_factory=list, init=False)
    _next: int = field(default=0, init=False)

    async def complete(self, request: ModelRequest, budget: Budget) -> ModelResponse:
        self.calls.append(request)
        validation.validate_model(REQUEST_SCHEMA, request)

        if budget.remaining_tokens <= 0 or budget.remaining_cost_usd <= 0:
            await self.usage.record(
                model_usage_row(
                    request,
                    ProviderSpec(request.provider, request.model),
                    None,
                    status="budget_denied",
                    error_code=ErrorCode.POLICY_DENIED,
                )
            )
            raise BudgetExceeded(
                "campaign budget exhausted: remaining_tokens="
                f"{budget.remaining_tokens}, remaining_cost_usd={budget.remaining_cost_usd}"
            )

        if self._next >= len(self.responses):
            raise RuntimeError("FakeModelClient has no scripted response left")
        response = self.responses[self._next]
        self._next += 1
        validation.validate_model(RESPONSE_SCHEMA, response)
        error = response.finish_reason is FinishReason.provider_error
        await self.usage.record(
            model_usage_row(
                request,
                ProviderSpec(response.provider, response.model),
                response,
                status="error" if error else "ok",
                error_code=response.error.code if response.error is not None else None,
            )
        )
        return response
