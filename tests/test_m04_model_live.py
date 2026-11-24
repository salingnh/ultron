"""Optional live smoke behind `AEGIS_MODEL_LIVE=1`; nothing here is defined or called otherwise.

No provider is contacted in CI or by `make test`: the tests are only *defined* when the live flag
is on, so `AEGIS_NO_SKIPS=1` never sees a skip and the suite cannot spend a token by accident.
Leader decision: G1 runs the fake driver; this path is opt-in. OD-2 (provider/model/endpoint) is
still open, so it has not been executed yet.

Environment (names only, never values):
  AEGIS_MODEL_PROVIDER=openai|anthropic   AEGIS_MODEL_NAME=<model>
  AEGIS_MODEL_INPUT_PRICE / AEGIS_MODEL_OUTPUT_PRICE  (USD per million tokens)
  AEGIS_OPENAI_API_KEY / AEGIS_ANTHROPIC_API_KEY
  AEGIS_OPENAI_ENDPOINT / AEGIS_ANTHROPIC_ENDPOINT
  AEGIS_MODEL_BUDGET_TOKENS (default 2000), AEGIS_MODEL_BUDGET_USD (default 0.05)
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

from aegis.common.ports import Budget
from aegis.contracts_gen.agent.model_request_v2_schema import ModelRequest, Provider
from aegis.m04_model import HttpTransport, InMemoryUsageSink, ModelClient, Price
from tests.m04_support import CAMPAIGN_ID, SESSION_ID, TRACE_ID

KEY_ENV = {"openai": "AEGIS_OPENAI_API_KEY", "anthropic": "AEGIS_ANTHROPIC_API_KEY"}
ENDPOINT_ENV = {"openai": "AEGIS_OPENAI_ENDPOINT", "anthropic": "AEGIS_ANTHROPIC_ENDPOINT"}


if os.environ.get("AEGIS_MODEL_LIVE") == "1":

    def test_live_call_is_normalized_and_recorded() -> None:
        provider = Provider(os.environ.get("AEGIS_MODEL_PROVIDER", "openai"))
        model = os.environ["AEGIS_MODEL_NAME"]
        transport = HttpTransport(
            endpoints={provider: os.environ[ENDPOINT_ENV[provider.value]]},
            api_keys={provider: os.environ[KEY_ENV[provider.value]]},
            pricing={
                (provider, model): Price(
                    input_usd_per_million=float(os.environ["AEGIS_MODEL_INPUT_PRICE"]),
                    output_usd_per_million=float(os.environ["AEGIS_MODEL_OUTPUT_PRICE"]),
                )
            },
        )
        sink = InMemoryUsageSink()
        request: Any = ModelRequest.model_validate(
            {
                "provider": provider.value,
                "model": model,
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
                "timeout_seconds": 60,
            }
        )
        response = asyncio.run(
            ModelClient(transport, sink).complete(
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
