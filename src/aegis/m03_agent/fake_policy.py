"""The G1 stand-in for the model: a scripted lab policy wrapped in M04's budget and usage rules.

Leader decision for G1: the model is fake unless a live provider is configured (G1.2a). This is
that fake for the *session*, and it is a policy, not a model: it has no provider, no prompt
interpretation and **no database access**. It answers with the next contract-valid
`model-response.v2` from the same `ContextBundle` the prompt is rendered from
(`observe_context`, called by `nodes.build_context`).

Why the bundle and not the campaign's tables: the demo must prove the data path
**M06 (Subfinder) → M27 ingestion → `build_context` → context → M03's decision (DNSx)**, not the lab
inventory. A policy that read `scan_job`/`asset` directly would pass even if ingestion and the
context builder were broken; reading the bundle means the DNSx targets can only come from
observations M27 recorded (now from the M27 rows, after G1.4b from M23's projection). Everything the
policy decides from is in the bundle:

* the campaign's seed targets arrive as observations (`summary` = `campaign seed target ...`,
  `ref` = the seed's canonical key, raw value in `untrusted`) - the contract's own place for raw
  target text;
* what was already proposed arrives in `ledger.completed_objectives`, one code-generated line per
  finished job (`<capability> <job_id> <status>`), and in `ledger.pending_job_ids`;
* the names to resolve arrive as observations whose `ref` is their canonical key.

The demo it drives (card G1.2c, G1.5c):

1. seed domain -> `dns.enumerate_subdomains` on the seed observations (Subfinder);
2. after M27 recorded domain observations -> `dns.resolve` on them, with
   `depends_on = [<the enumerate job id>]` (DNSx after Subfinder);
3. enumeration finished with no new names -> `{"decision": "wait"}` (nothing to resolve, and
   nothing is invented); both capabilities proposed -> `{"decision": "stop"}`.

Every answer goes through `FakeModelClient` (M04), so the budget pre-check, the one-usage-row-
per-attempt rule and the response contract validation are exactly the production ones.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol

from aegis.common.ports import Budget
from aegis.contracts_gen.agent.context_bundle_v2_schema import ContextBundle
from aegis.contracts_gen.agent.model_request_v2_schema import ModelRequest
from aegis.contracts_gen.agent.model_response_v2_schema import FinishReason, ModelResponse
from aegis.m03_agent.prompt import SEED_SUMMARY_PREFIX
from aegis.m03_agent.wire import plain
from aegis.m04_model.fake import FakeModelClient
from aegis.m04_model.usage import InMemoryUsageSink, UsageSink

__all__ = [
    "ENUMERATE",
    "RESOLVE",
    "SEED_SUMMARY_PREFIX",
    "ContextObserver",
    "ScriptedLabPolicy",
    "job_lines",
]

ENUMERATE = "dns.enumerate_subdomains"
RESOLVE = "dns.resolve"
ENUMERATE_RATIONALE = (
    "Enumerate the subdomains of the campaign's authorized domain seeds to find more surface "
    "before resolving them"
)
RESOLVE_RATIONALE = (
    "Resolve the domain names the enumeration job discovered, so the campaign learns their "
    "addresses before the next step"
)
#: Characters per token approximation used for the fake usage numbers (no provider is called).
CHARS_PER_TOKEN = 4
OUTPUT_TOKENS = 96
#: Sessions whose bundle is remembered (a worker may run several activities at once).
MAX_REMEMBERED_BUNDLES = 256


class ContextObserver(Protocol):
    """A model stand-in that needs the session's bundle: the same data the prompt is built from."""

    def observe_context(self, bundle: ContextBundle) -> None: ...


def job_lines(bundle: ContextBundle) -> list[tuple[str, str, str]]:
    """The `ledger.completed_objectives` lines as `(capability, job_id, status)`.

    `build_context` writes them as `<capability> <job_id> <status>` from the campaign's job rows, so
    a reader (this policy, or a live model reading the prompt) gets the campaign's history from the
    bundle instead of from the database. A line that does not have that shape is ignored, never
    guessed at.
    """
    lines: list[tuple[str, str, str]] = []
    for line in (bundle.ledger.completed_objectives if bundle.ledger is not None else None) or ():
        parts = str(line).split()
        if len(parts) == 3:
            lines.append((parts[0], parts[1], parts[2]))
    return lines


@dataclass
class ScriptedLabPolicy:
    """The lab demo's decisions, from the session's bundle (never a provider or a database)."""

    provider: str = "openai"
    model: str = "scripted-lab"
    usage: UsageSink = field(default_factory=InMemoryUsageSink)
    calls: list[ModelRequest] = field(default_factory=list, init=False)
    responses: list[ModelResponse] = field(default_factory=list, init=False)
    bundles: dict[str, ContextBundle] = field(default_factory=dict, init=False)

    def observe_context(self, bundle: ContextBundle) -> None:
        """The session's bundle, keyed by session id (one worker may run several sessions)."""
        session_id = str(plain(bundle.session_id))
        self.bundles[session_id] = bundle
        while len(self.bundles) > MAX_REMEMBERED_BUNDLES:
            self.bundles.pop(next(iter(self.bundles)))

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
        bundle = self.bundles.get(str(plain(request.session_id)))
        if bundle is None:
            raise RuntimeError(
                "ScriptedLabPolicy has no ContextBundle for session "
                f"{plain(request.session_id)}: the session must call observe_context() before the "
                "first plan call"
            )
        jobs = job_lines(bundle)
        enumerated = [job for job in jobs if job[0] == ENUMERATE]
        resolved = [job for job in jobs if job[0] == RESOLVE]
        pending = [
            str(plain(item))
            for item in (bundle.ledger.pending_job_ids if bundle.ledger is not None else None) or []
        ]
        seeds = _refs(bundle, seed=True)
        # the seed itself may also be recorded as an observation once M27 knows the asset; it is not
        # a name the enumeration discovered
        discovered = [ref for ref in _refs(bundle, seed=False) if ref not in seeds]

        if pending:
            return self._decision(
                request,
                "wait",
                f"{len(pending)} job(s) still in flight; their results arrive in a later session",
            )
        if not enumerated:
            if not seeds:
                return self._decision(
                    request,
                    "wait",
                    "the context bundle carries no domain seed target, so there is nothing to "
                    "enumerate",
                )
            return self._tool_call(
                request,
                ENUMERATE,
                ["subdomain-enum"],
                {
                    "input": {"targets": seeds[:100]},
                    "rationale": ENUMERATE_RATIONALE,
                    "expected_signal": "new subdomains of the seed domains",
                    "priority": 80,
                },
            )
        if not resolved:
            if not discovered:
                return self._decision(
                    request,
                    "wait",
                    f"{ENUMERATE} {enumerated[0][1]} produced no new domain name in the context "
                    "bundle, so there is nothing to resolve",
                )
            return self._tool_call(
                request,
                RESOLVE,
                ["dns-resolve"],
                {
                    "input": {"targets": discovered[:100]},
                    "rationale": RESOLVE_RATIONALE,
                    "expected_signal": "A/AAAA/CNAME records for the enumerated names",
                    "depends_on": [enumerated[0][1]],
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
        tags: list[str],
        arguments: dict[str, Any],
    ) -> ModelResponse:
        call_id = f"call-{uuid.uuid4().hex[:16]}"
        message = {
            "role": "assistant",
            "content": [
                {"type": "text", "text": f"Next step: {tool} ({', '.join(tags)})."},
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
        message: dict[str, Any] | None = None,
        parsed: dict[str, Any] | None = None,
    ) -> ModelResponse:
        prompt_chars = sum(
            len(str(block.get("text") or ""))
            for item in request.messages
            for block in _blocks(item)
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


def _blocks(message: Any) -> list[dict[str, Any]]:
    from aegis.m03_agent.wire import blocks

    return blocks(message)


def _refs(bundle: ContextBundle, *, seed: bool) -> list[str]:
    """Domain refs of the bundle's observations, split into seed targets and discovered names."""
    refs: list[str] = []
    for observation in bundle.observations:
        ref = str(plain(observation.ref))
        if not ref.startswith("dns:"):
            continue
        is_seed = str(plain(observation.summary)).startswith(SEED_SUMMARY_PREFIX)
        if is_seed is seed and ref not in refs:
            refs.append(ref)
    return refs
