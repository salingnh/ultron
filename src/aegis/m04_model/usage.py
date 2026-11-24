"""`aegis.model_usage`: one append-only row per model call (C07).

The table is DDL 0001 as amended by 0002 (`profile` dropped with the v1 impact taxonomy) and 0004
(non-negative counters). Every attempt reaches a sink exactly once: `ok`, `error`, `fallback` or
`budget_denied`, with provider/model, tokens, cost, latency, trace and the error code when the
attempt failed. `PostgresUsageSink` writes with its own connection per row, so a call path never
holds a transaction while waiting on a provider.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Literal, Protocol, runtime_checkable

import psycopg

from aegis.contracts_gen.agent.model_request_v2_schema import ModelRequest, Provider
from aegis.contracts_gen.agent.model_response_v2_schema import ModelResponse
from aegis.contracts_gen.common.error_v2_schema import ErrorCode
from aegis.m04_model.config import ProviderSpec

UsageStatus = Literal["ok", "error", "fallback", "budget_denied"]


@dataclass(frozen=True, slots=True)
class ModelUsage:
    """One row of `aegis.model_usage` (no `created_at`: the database default records it)."""

    usage_id: str
    campaign_id: str
    session_id: str
    provider: Provider
    model: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    latency_ms: int
    status: UsageStatus
    error_code: ErrorCode | None
    trace_id: str


def model_usage_row(
    request: ModelRequest,
    spec: ProviderSpec,
    response: ModelResponse | None,
    *,
    status: UsageStatus,
    error_code: ErrorCode | None = None,
) -> ModelUsage:
    """Build the row of one attempt; `response=None` is the budget denial (no provider call)."""
    if response is None:
        input_tokens = output_tokens = latency_ms = 0
        cost_usd = 0.0
    else:
        usage = response.usage
        input_tokens = usage.input_tokens
        output_tokens = usage.output_tokens
        cost_usd = usage.cost_usd
        latency_ms = usage.latency_ms
    return ModelUsage(
        usage_id=str(uuid.uuid4()),
        campaign_id=str(request.campaign_id.root),
        session_id=str(request.session_id.root),
        provider=spec.provider,
        model=spec.model,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cost_usd=cost_usd,
        latency_ms=latency_ms,
        status=status,
        error_code=error_code,
        trace_id=request.trace_id,
    )


@runtime_checkable
class UsageSink(Protocol):
    """Destination of usage rows (in-memory in tests, PostgreSQL in a deployment)."""

    async def record(self, row: ModelUsage) -> None: ...


@dataclass
class InMemoryUsageSink:
    """Deterministic sink for tests and the G1 fake driver."""

    rows: list[ModelUsage] = field(default_factory=list)

    async def record(self, row: ModelUsage) -> None:
        self.rows.append(row)


class PostgresUsageSink:
    """Append-only insert into `aegis.model_usage`; one short connection per row."""

    INSERT = """
        INSERT INTO aegis.model_usage (
            usage_id, campaign_id, session_id, provider, model,
            input_tokens, output_tokens, cost_usd, latency_ms, status, error_code, trace_id
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn

    async def record(self, row: ModelUsage) -> None:
        connection = await psycopg.AsyncConnection.connect(self._dsn)
        try:
            await connection.execute(
                self.INSERT,
                (
                    row.usage_id,
                    row.campaign_id,
                    row.session_id,
                    row.provider.value,
                    row.model,
                    row.input_tokens,
                    row.output_tokens,
                    row.cost_usd,
                    row.latency_ms,
                    row.status,
                    row.error_code.value if row.error_code is not None else None,
                    row.trace_id,
                ),
            )
            await connection.commit()
        finally:
            await connection.close()
