"""Optional live call behind `AEGIS_MODEL_LIVE=1`; nothing here is defined or called otherwise.

No provider is contacted in CI or by `make test`: the test is only *defined* when the live flag is
on, so `AEGIS_NO_SKIPS=1` never sees a skip and the suite cannot spend a token by accident. The
manual equivalent (env file loading, the real plan prompt and a printed summary) is
`make llm-smoke`; both paths read one configuration (`aegis.m04_model.deployment`).

Environment (names only, never values): `AEGIS_SESSION_LIVE_MODEL=1` plus the `AEGIS_MODEL_*`
variables documented in `.env.example` (provider, model, base URL, key, both prices).
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

from aegis.common.ports import Budget
from aegis.contracts_gen.agent.model_request_v2_schema import ModelRequest
from aegis.m04_model import InMemoryUsageSink, ModelDeployment
from tests.m04_support import CAMPAIGN_ID, SESSION_ID, TRACE_ID

if os.environ.get("AEGIS_MODEL_LIVE") == "1":

    def test_a_live_call_is_normalized_and_recorded() -> None:
        deployment = ModelDeployment.from_env()
        sink = InMemoryUsageSink()
        request: Any = ModelRequest.model_validate(
            {
                "provider": deployment.provider.value,
                "model": deployment.model,
                "messages": [
                    {
                        "role": "user",
                        "content": [{"type": "text", "text": "Trả lời đúng một từ: ok"}],
                    }
                ],
                "campaign_id": CAMPAIGN_ID,
                "session_id": SESSION_ID,
                "trace_id": TRACE_ID,
                "max_output_tokens": 16,
                "timeout_seconds": deployment.timeout_seconds,
            }
        )
        response = asyncio.run(
            deployment.client(sink).complete(
                request,
                Budget(
                    remaining_tokens=int(os.environ.get("AEGIS_MODEL_BUDGET_TOKENS", "2000")),
                    remaining_cost_usd=float(os.environ.get("AEGIS_MODEL_BUDGET_USD", "0.05")),
                ),
            )
        )
        assert response.finish_reason in {"completed", "refused"}
        assert len(sink.rows) == 1
        assert sink.rows[0].status == "ok"
