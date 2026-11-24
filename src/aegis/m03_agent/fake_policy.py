"""The G1 stand-in for the model: a scripted lab policy wrapped in M04's budget and usage rules.

Leader decision for G1: the model is fake unless a live provider is configured (G1.2a). This is that
fake for the *session*, and it is a policy, not a model: it reads the campaign's own job list and
asset inventory and answers with the next contract-valid `model-response.v2` - no provider is
contacted, no prompt is interpreted.

The demo it drives (card G1.2c, G1.5c):

1. seed domain -> `dns.enumerate_subdomains` on the campaign's domain seeds (Subfinder);
2. discovered names -> `dns.resolve` on the domain assets M27 recorded, with
   `depends_on = [<the enumerate job id>]` (DNSx after Subfinder);
3. nothing left -> `{"decision": "stop"}` with the objective met.

Why it reads the database and not just the prompt: a real model infers "which names were discovered"
from the observations in its context. Until G1.4b/M23 serves those observations the scripted policy
asks the same question of the inventory (`LabCatalog`), which keeps the demo deterministic while the
prompt path stays the production one. `ScriptedLabPolicy` is only constructed when the deployment
has
no live model (the default), so it can never shadow a real provider by accident.

Every answer goes through `FakeModelClient` (M04), so the budget pre-check, the one-usage-row-per-
attempt rule and the response contract validation are exactly the production ones.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from aegis.common.ports import Budget
from aegis.contracts_gen.agent.model_request_v2_schema import ModelRequest
from aegis.contracts_gen.agent.model_response_v2_schema import FinishReason, ModelResponse
from aegis.m03_agent.wire import blocks as wire_blocks
from aegis.m04_model.fake import FakeModelClient
from aegis.m04_model.usage import InMemoryUsageSink, UsageSink

__all__ = [
    "ENUMERATE",
    "RESOLVE",
    "LabCatalog",
    "PostgresLabCatalog",
    "ScriptedLabPolicy",
]

ENUMERATE = "dns.enumerate_subdomains"
RESOLVE = "dns.resolve"
ENUMERATE_RATIONALE = (
    "Enumerate the subdomains of the campaign's authorized domain seeds to find more surface "
    "before resolving them"
)
RESOLVE_RATIONALE = (
    "Resolve the domain names the enumeration job discovered, so the campaign learns their "
    "addresses "
    "before the next step"
)
#: Characters per token approximation used for the fake usage numbers (no provider is called).
CHARS_PER_TOKEN = 4
OUTPUT_TOKENS = 96


class LabCatalog(Protocol):
    """The read-only questions the scripted policy asks about a campaign (the demo's inventory)."""

    def seed_domains(self, campaign_id: str) -> list[str]: ...

    def discovered_domains(self, campaign_id: str) -> list[str]: ...

    def jobs(self, campaign_id: str) -> list[tuple[str, str, str]]:
        """`(job_id, capability, status)` for the campaign, oldest first."""
        ...


def _plain(value: Any) -> Any:
    return getattr(value, "root", value)


@dataclass
class ScriptedLabPolicy:
    """The lab demo's decisions, as contract `ModelResponse` payloads (never a provider call)."""

    catalog: LabCatalog
    provider: str = "openai"
    model: str = "scripted-lab"
    usage: UsageSink = field(default_factory=InMemoryUsageSink)
    calls: list[ModelRequest] = field(default_factory=list, init=False)
    responses: list[ModelResponse] = field(default_factory=list, init=False)

    async def complete(self, request: ModelRequest, budget: Budget) -> ModelResponse:
        self.calls.append(request)
        response = self.decide(request)
        self.responses.append(response)
        # The budget pre-check, the usage row and the contract validation are M04's, not a copy.
        return await FakeModelClient(responses=[response], usage=self.usage).complete(
            request, budget
        )

    # --- the script ---------------------------------------------------------------------------
    def decide(self, request: ModelRequest) -> ModelResponse:
        campaign_id = str(_plain(request.campaign_id))
        jobs = self.catalog.jobs(campaign_id)
        enumerated = [job for job in jobs if job[1] == ENUMERATE]
        resolved = [job for job in jobs if job[1] == RESOLVE]
        if not enumerated:
            seeds = self.catalog.seed_domains(campaign_id)
            if not seeds:
                return self._decision(
                    request,
                    "wait",
                    "no domain seed on the campaign scope, so no enumeration target exists",
                )
            return self._tool_call(
                request,
                ENUMERATE,
                {"tags": ["subdomain-enum"]},
                {
                    "input": {"targets": seeds[:100]},
                    "rationale": ENUMERATE_RATIONALE,
                    "expected_signal": "new subdomains of the seed domains",
                    "priority": 80,
                },
            )
        if not resolved:
            names = self.catalog.discovered_domains(campaign_id)
            if not names:
                return self._decision(
                    request,
                    "wait",
                    f"{ENUMERATE} {enumerated[-1][0]} has not produced new domain names yet",
                )
            return self._tool_call(
                request,
                RESOLVE,
                {"tags": ["dns-resolve"]},
                {
                    "input": {"targets": names[:100]},
                    "rationale": RESOLVE_RATIONALE,
                    "expected_signal": "A/AAAA/CNAME records for the enumerated names",
                    "depends_on": [enumerated[-1][0]],
                    "priority": 70,
                },
            )
        return self._decision(
            request,
            "stop",
            "enumeration and resolution are both proposed; the campaign objective is met",
        )

    # --- response builders --------------------------------------------------------------------
    def _tool_call(
        self,
        request: ModelRequest,
        tool: str,
        tags: Mapping[str, Any],
        arguments: Mapping[str, Any],
    ) -> ModelResponse:
        call_id = f"call-{uuid.uuid4().hex[:16]}"
        message = {
            "role": "assistant",
            "content": [
                {"type": "text", "text": f"Next step: {tool} ({', '.join(tags.get('tags', []))})."},
                {
                    "type": "tool_call",
                    "call": {
                        "id": call_id,
                        "name": tool,
                        "arguments": dict(arguments),
                        "arguments_raw": json.dumps(dict(arguments), sort_keys=True),
                    },
                },
            ],
        }
        return self._response(request, FinishReason.tool_calls, message=message)

    def _decision(self, request: ModelRequest, decision: str, summary: str) -> ModelResponse:
        parsed = {"decision": decision, "summary": summary}
        return self._response(
            request,
            FinishReason.completed,
            message={"role": "assistant", "content": [{"type": "text", "text": summary}]},
            parsed=parsed,
        )

    def _response(
        self,
        request: ModelRequest,
        finish: FinishReason,
        *,
        message: Mapping[str, Any] | None = None,
        parsed: Mapping[str, Any] | None = None,
    ) -> ModelResponse:
        prompt_chars = sum(
            len(str(block.get("text") or ""))
            for item in request.messages
            for block in wire_blocks(item)
        )
        payload: dict[str, Any] = {
            "provider": self.provider,
            "model": self.model,
            "finish_reason": finish,
            "provider_meta": {
                "provider": self.provider,
                "response_id": f"scripted-{uuid.uuid4().hex[:16]}",
                "model_version": "scripted-lab/1",
                "raw_finish_reason": finish.value,
            },
            "usage": {
                "input_tokens": max(1, prompt_chars // CHARS_PER_TOKEN),
                "output_tokens": OUTPUT_TOKENS,
                "cost_usd": 0.0,
                "latency_ms": 1,
            },
        }
        # `model-response.v2` forbids `parsed`/`error` for a `tool_calls` answer (and requires
        # `parsed` for `completed`): an absent key, never an explicit null.
        if message is not None:
            payload["message"] = dict(message)
        if parsed is not None:
            payload["parsed"] = dict(parsed)
        return ModelResponse.model_validate(payload)


class PostgresLabCatalog:
    """The demo's inventory: M01 seed targets, M27 domain assets and M05 job status, read only."""

    def __init__(self, connect: Callable[[], Any]) -> None:
        self._connect = connect

    def seed_domains(self, campaign_id: str) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT t.raw_value
                  FROM campaign c JOIN campaign_target t ON t.scope_id = c.scope_id
                 WHERE c.campaign_id = %s AND t.kind = 'domain'
                 ORDER BY t.created_at, t.target_id
                """,
                (campaign_id,),
            ).fetchall()
        return [str(row["raw_value"]) for row in rows]

    def discovered_domains(self, campaign_id: str) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT a.canonical_key
                  FROM asset a JOIN asset_campaign ac ON ac.asset_id = a.asset_id
                 WHERE ac.campaign_id = %s AND a.kind = 'domain'
                 ORDER BY a.first_seen, a.canonical_key
                """,
                (campaign_id,),
            ).fetchall()
        return [str(row["canonical_key"]) for row in rows]

    def jobs(self, campaign_id: str) -> list[tuple[str, str, str]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT job_id, capability, status FROM scan_job
                 WHERE campaign_id = %s ORDER BY created_at, job_id
                """,
                (campaign_id,),
            ).fetchall()
        return [(str(row["job_id"]), str(row["capability"]), str(row["status"])) for row in rows]


def jobs_of(
    catalog: LabCatalog, campaign_id: str, capability: str
) -> Sequence[tuple[str, str, str]]:
    """Jobs of one capability (small helper the tests and the demo read the catalog through)."""
    return [job for job in catalog.jobs(campaign_id) if job[1] == capability]
