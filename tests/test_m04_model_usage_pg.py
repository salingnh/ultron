"""`PostgresUsageSink` writes the contract's one-row-per-attempt against the real DDL (C07)."""

from __future__ import annotations

import asyncio
import json

import psycopg
import pytest

from aegis.common.ports import Budget, BudgetExceeded
from aegis.contracts_gen.agent.model_request_v2_schema import Provider
from aegis.contracts_gen.common.error_v2_schema import ErrorCode
from aegis.m04_model import (
    ModelClient,
    ModelConfig,
    PostgresUsageSink,
    ProviderSpec,
    TransportError,
)
from aegis.migrations import apply_contract_migrations
from tests.m04_support import (
    CAMPAIGN_ID,
    SESSION_ID,
    TRACE_ID,
    ScriptedTransport,
    Step,
    budget,
    recorded,
    request,
)
from tests.pg import requires_postgres, throwaway_database


def seed_campaign(dsn: str) -> None:
    """The parent rows `model_usage` references.

    `campaign.current_policy_version` and `policy_snapshot.campaign_id` reference each other, both
    `DEFERRABLE INITIALLY DEFERRED` (0001:121, :138), so the snapshot and the campaign are inserted
    in one transaction and the foreign keys are checked at commit.
    """
    actor = json.dumps({"kind": "operator", "operator_id": "g1.2a"}, sort_keys=True)
    # 0009 requires a roe-policy.v2 shape for a new snapshot; these are the mandatory limits.
    policy = json.dumps({"max_parallel_jobs": 1, "max_duration_hours": 1}, sort_keys=True)
    scope_id = "01934f6a-0000-7000-8000-000000000004"
    with psycopg.connect(dsn) as connection:
        connection.execute(
            """
            INSERT INTO aegis.scope_snapshot (scope_id, campaign_id, targets)
            VALUES (%s, %s, %s::jsonb)
            """,
            (scope_id, CAMPAIGN_ID, json.dumps({"domains": ["example.test"]})),
        )
        connection.execute(
            """
            INSERT INTO aegis.policy_snapshot
                (policy_version, campaign_id, policy, policy_hash, created_by)
            VALUES ('roe-1', %s, %s::jsonb, aegis.policy_hash(%s::jsonb), %s::jsonb)
            """,
            (CAMPAIGN_ID, policy, policy, actor),
        )
        connection.execute(
            """
            INSERT INTO aegis.campaign
                (campaign_id, name, objective, current_policy_version, scope_id, created_by)
            VALUES (%s, 'g1.2a usage', 'usage sink contract test', 'roe-1', %s, %s::jsonb)
            """,
            (CAMPAIGN_ID, scope_id, actor),
        )
        connection.execute(
            """
            INSERT INTO aegis.agent_session
                (session_id, campaign_id, policy_version, revision_from, status)
            VALUES (%s, %s, 'roe-1', 0, 'RUNNING')
            """,
            (SESSION_ID, CAMPAIGN_ID),
        )


@requires_postgres
def test_one_usage_row_per_attempt_lands_in_model_usage() -> None:
    with throwaway_database() as dsn, psycopg.connect(dsn, autocommit=True) as connection:
        apply_contract_migrations(connection)
        seed_campaign(dsn)

        sink = PostgresUsageSink(dsn)
        config = ModelConfig(
            fallback=(ProviderSpec(Provider.anthropic, "fallback-model"),),
            allow_fallback=True,
            max_attempts=2,
        )
        transport = ScriptedTransport(
            [
                Step(error=TransportError(ErrorCode.NETWORK_TIMEOUT, "primary unreachable")),
                Step(raw=recorded("anthropic-completed"), latency_ms=1200, cost_usd=0.0011),
            ]
        )
        client = ModelClient(transport, sink, config)

        response = asyncio.run(client.complete(request(), budget()))
        assert response.provider is Provider.anthropic

        rows = connection.execute(
            """
            SELECT status, provider, model, input_tokens, output_tokens, cost_usd,
                   latency_ms, error_code, campaign_id::text, session_id::text, trace_id
            FROM aegis.model_usage
            """
        ).fetchall()
        by_status = {str(row[0]): row for row in rows}
        assert len(rows) == 2

        error = by_status["error"]
        assert (error[1], error[2]) == ("openai", "configured-model")
        assert error[3:5] == (0, 0)
        assert error[7] == "NETWORK_TIMEOUT"

        fallback = by_status["fallback"]
        assert (fallback[1], fallback[2]) == ("anthropic", "fallback-model")
        assert (fallback[3], fallback[4], fallback[6]) == (240, 20, 1200)
        assert float(fallback[5]) == pytest.approx(0.0011)
        assert fallback[7] is None

        for row in rows:
            assert str(row[8]) == CAMPAIGN_ID
            assert str(row[9]) == SESSION_ID
            assert row[10] == TRACE_ID

        # A spent budget writes its own row and never reaches the provider.
        with pytest.raises(BudgetExceeded):
            asyncio.run(
                client.complete(request(), Budget(remaining_tokens=0, remaining_cost_usd=0.0))
            )
        denied = connection.execute(
            """
            SELECT input_tokens, output_tokens, cost_usd, latency_ms, error_code
            FROM aegis.model_usage WHERE status = 'budget_denied'
            """
        ).fetchall()
        assert len(denied) == 1
        assert (denied[0][0], denied[0][1], denied[0][3]) == (0, 0, 0)
        assert float(denied[0][2]) == 0.0
        assert denied[0][4] == "POLICY_DENIED"
        assert len(transport.calls) == 2
