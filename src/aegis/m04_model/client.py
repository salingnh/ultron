"""M04 ModelClient: budget pre-check, bounded fallback, one usage row per attempt (C07).

`complete` is the only entry point. It validates the request against `model-request.v2`, refuses a
spent campaign budget *before* any provider call (`BudgetExceeded` plus a `budget_denied` usage
row), sends the bounded attempt chain from `ModelConfig`, normalizes each answer with the provider
driver, validates it against `model-response.v2`, records one usage row per attempt, and only lets
a `provider_error` advance to the next configured provider. Refusal/invalid/truncated output is
returned to M03 as-is, never hidden by a second provider.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from functools import cache
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from aegis import validation
from aegis.common.ports import Budget, BudgetExceeded
from aegis.contracts_gen.agent.model_request_v2_schema import ModelRequest, Provider
from aegis.contracts_gen.agent.model_response_v2_schema import FinishReason, ModelResponse
from aegis.contracts_gen.common.error_v2_schema import ErrorCode
from aegis.m04_model.config import ModelConfig, ProviderSpec
from aegis.m04_model.drivers import (
    DEFAULT_DRIVERS,
    OutputValidator,
    ProviderDriver,
    provider_error_response,
)
from aegis.m04_model.transport import ProviderTransport, TransportError
from aegis.m04_model.usage import UsageSink, UsageStatus, model_usage_row

REQUEST_SCHEMA = "agent/model-request.v2.schema.json"
RESPONSE_SCHEMA = "agent/model-response.v2.schema.json"


@cache
def _contract_registry() -> Registry:
    """The contract registry, so a `response_schema` may `$ref` any contract `$id`."""
    return Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema)) for schema in validation.schemas().values()
    )


def output_validator(schema: Mapping[str, Any]) -> OutputValidator:
    """Validate a parsed model output against the caller's `response_schema`."""
    validator = Draft202012Validator(
        dict(schema),
        registry=_contract_registry(),
        format_checker=validation.format_checker(),
    )

    def check(candidate: Any) -> list[str]:
        return sorted(str(error.message) for error in validator.iter_errors(candidate))

    return check


def _spent(budget: Budget) -> bool:
    return budget.remaining_tokens <= 0 or budget.remaining_cost_usd <= 0


class ModelClient:
    """Contract-following M04 client over a provider transport."""

    def __init__(
        self,
        transport: ProviderTransport,
        usage: UsageSink,
        config: ModelConfig | None = None,
        drivers: Mapping[Provider, ProviderDriver] | None = None,
    ) -> None:
        self.transport = transport
        self.usage = usage
        self.config = config or ModelConfig()
        self.drivers: Mapping[Provider, ProviderDriver] = drivers or {
            driver.provider: driver for driver in DEFAULT_DRIVERS
        }

    async def complete(self, request: ModelRequest, budget: Budget) -> ModelResponse:
        validation.validate_model(REQUEST_SCHEMA, request)

        if _spent(budget):
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
                "campaign budget exhausted before model call: "
                f"remaining_tokens={budget.remaining_tokens}, "
                f"remaining_cost_usd={budget.remaining_cost_usd}"
            )

        validate = output_validator(request.response_schema) if request.response_schema else None
        response: ModelResponse | None = None
        for index, spec in enumerate(self.config.attempts(request)):
            driver = self.drivers[spec.provider]
            wire = driver.to_wire(request, model=spec.model)
            status: UsageStatus
            error_code: ErrorCode | None
            started = time.perf_counter()
            try:
                answer = await self.transport.send(
                    spec.provider,
                    spec.model,
                    wire,
                    timeout_seconds=float(request.timeout_seconds or 120),
                )
            except TransportError as error:
                latency_ms = int((time.perf_counter() - started) * 1000)
                response = provider_error_response(
                    spec.provider, spec.model, error, latency_ms=latency_ms
                )
                status, error_code = "error", error.code
            else:
                response = driver.normalize(
                    answer.raw,
                    model=spec.model,
                    validate=validate,
                    latency_ms=answer.latency_ms,
                    cost_usd=answer.cost_usd,
                )
                status = "fallback" if index > 0 else "ok"
                error_code = response.error.code if response.error is not None else None
                if response.finish_reason is FinishReason.provider_error:
                    status = "error"

            validation.validate_model(RESPONSE_SCHEMA, response)
            await self.usage.record(
                model_usage_row(request, spec, response, status=status, error_code=error_code)
            )
            if response.finish_reason is not FinishReason.provider_error:
                break

        if response is None:  # the attempt chain always starts with the primary call
            raise RuntimeError("ModelClient attempt chain is empty")
        return response


__all__ = ["ModelClient", "REQUEST_SCHEMA", "RESPONSE_SCHEMA", "output_validator"]
