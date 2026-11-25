#!/usr/bin/env python3
"""G1.6 live smoke: ONE real provider call with the owner's key (manual only, never in CI).

    make llm-smoke

What it does, in order:

1. reads the live settings from the environment and, when they are not exported, from the
   repository's git-ignored `.env` (`make run-local` sources the same file);
2. validates them with the same reader the worker uses (`aegis.m04_model.deployment`), so a missing
   key, price or provider stops here with the variable's name - nothing is sent;
3. sends one real plan call through the real M04 client (`HttpTransport` + the provider driver):
   the platform's system prompt, the campaign-context turn and the capability catalogue M05
   publishes from the adapter manifests, with the plan decision schema - the same request shape a
   session sends, and nothing else;
4. prints the provider's answer, the normalized finish reason, tokens and the cost the deployment's
   prices produce. The credential is never printed and provider text is passed through the
   deployment's redaction first.

It sends exactly one request, costs a fraction of a cent and writes nothing to the database
(`InMemoryUsageSink`), so it can be repeated. It refuses to run on a CI host.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = ROOT / ".env"


def load_env_file(path: Path) -> None:
    """Source `KEY=VALUE` pairs from `.env` without overriding what is already exported."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _tool_catalogue() -> list[dict[str, Any]]:
    """The capability tools M05 publishes, built from the adapter manifests (no database)."""
    from aegis.m05_registry.manifest import ManifestRecord, parse_document, schema_reference_path
    from aegis.m05_registry.mcp import schemas

    tools: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in sorted((ROOT / "adapters").glob("**/manifest.yaml")):
        data = raw.read_bytes()
        record = ManifestRecord(sha256="", raw=data, document=parse_document(data))
        capability = record.capability
        path = schema_reference_path(record.input_schema_ref)
        if capability in seen or path is None:
            continue
        seen.add(capability)
        tools.append(
            {
                "name": capability,
                "description": (
                    f"Request one {capability} job through M05 (provider {record.provider}); "
                    "returns a job id immediately, results arrive later as knowledge."
                ),
                "input_schema": schemas.capability_request_schema(path).schema,
            }
        )
    return tools


def _request(deployment: Any, tools: list[dict[str, Any]]) -> Any:
    """A plan request shaped exactly like `aegis.m03_agent.nodes.SessionNodes.plan`."""
    from aegis.contracts_gen.agent.model_request_v2_schema import ModelRequest
    from aegis.m03_agent import prompt

    capabilities = [
        {
            "name": tool["name"],
            "description": tool["description"],
            "input_schema": tool["input_schema"],
        }
        for tool in tools
    ]
    messages = [
        prompt.system_message(),
        prompt.context_message(
            objective_text=(
                "G1.6 smoke: decide the next capability for the lab domain internal.example, or "
                "answer wait when this session cannot make progress"
            ),
            cycle=0,
            budget={"max_steps": 30, "tokens_remaining": None, "cost_remaining": None},
            capabilities=capabilities,
            observations=[],
            pending_job_ids=[],
            completed_objectives=[],
            idle_cycles=0,
        ),
    ]
    payload: dict[str, Any] = {
        "provider": deployment.provider.value,
        "model": deployment.model,
        "messages": messages,
        "response_schema": prompt.PLAN_DECISION_SCHEMA,
        "campaign_id": "01934f6a-0000-7000-8000-000000000001",
        "session_id": "01934f6a-0000-7000-8000-000000000002",
        "trace_id": uuid.uuid4().hex,
        "max_output_tokens": min(deployment.max_output_tokens, 512),
        "timeout_seconds": deployment.timeout_seconds,
    }
    if tools:
        payload["tools"] = tools
    return ModelRequest.model_validate(payload)


def _describe_answer(deployment: Any, answer: Any) -> list[str]:
    """The lines worth printing: finish reason, tokens, cost and the answer's own content."""
    from aegis.contracts_gen.agent.model_message_v2_schema import TextBlock, ToolCallBlock

    redact = deployment.redacted
    usage = answer.usage
    lines = [
        f"finish_reason : {answer.finish_reason.value}",
        f"provider      : {answer.provider.value} (model reported: {answer.model})",
        f"response id   : {answer.provider_meta.response_id}",
        f"tokens        : {usage.input_tokens} in / {usage.output_tokens} out",
        f"cost          : ${usage.cost_usd:.6f} (latency {usage.latency_ms} ms)",
    ]
    if answer.error is not None:
        lines.append(f"error         : {answer.error.code.value}: {redact(answer.error.message)}")
        lines.append(f"next action   : {answer.error.next_action.value}")
    if answer.message is not None:
        for block in answer.message.content:
            body = block.root
            if isinstance(body, TextBlock):
                lines.append(f"text          : {redact(body.text)[:1200]}")
            elif isinstance(body, ToolCallBlock):
                call = body.call.root
                arguments = getattr(call, "arguments", None)
                rendered = "" if arguments is None else json.dumps(arguments, sort_keys=True)
                lines.append(
                    f"tool call     : {call.name} id={call.id} arguments={redact(rendered)[:600]}"
                )
    if answer.parsed is not None:
        lines.append(f"parsed        : {redact(json.dumps(answer.parsed, sort_keys=True))[:600]}")
    return lines


async def smoke() -> int:
    from aegis.common.ports import Budget, BudgetExceeded
    from aegis.m04_model.deployment import (
        API_KEY_ENV,
        INPUT_PRICE_ENV,
        MODEL_NAME_ENV,
        OUTPUT_PRICE_ENV,
        PROVIDER_ENV,
        LIVE_MODEL_ENV,
        ModelDeployment,
        ModelDeploymentError,
        live_model_enabled,
    )
    from aegis.m04_model.usage import InMemoryUsageSink

    if os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"):
        print("llm-smoke: refusing to run on a CI host (it sends a real, paid request)", file=sys.stderr)
        return 2
    try:
        if not live_model_enabled():
            print(
                "llm-smoke: nothing to do - the scripted policy is selected.\n"
                f"  set {LIVE_MODEL_ENV}=1 and {PROVIDER_ENV}, {MODEL_NAME_ENV}, {API_KEY_ENV},\n"
                f"  {INPUT_PRICE_ENV}, {OUTPUT_PRICE_ENV} in .env (see .env.example)",
                file=sys.stderr,
            )
            return 2
        deployment = ModelDeployment.from_env()
    except ModelDeploymentError as error:
        print(f"llm-smoke: configuration error, nothing was sent: {error}", file=sys.stderr)
        return 2

    tools = _tool_catalogue()
    request = _request(deployment, tools)
    print("llm-smoke: live provider call (one request, nothing written to the database)")
    for key, value in deployment.describe().items():
        print(f"  {key:28}: {value}")
    print(f"  tools published             : {', '.join(tool['name'] for tool in tools) or 'none'}")
    print()

    usage = InMemoryUsageSink()
    client = deployment.client(usage)
    try:
        answer = await client.complete(request, Budget(remaining_tokens=100_000, remaining_cost_usd=5.0))
    except BudgetExceeded as error:  # pragma: no cover - this budget is never exhausted in one call
        print(f"llm-smoke: the fake budget refused the call: {error}", file=sys.stderr)
        return 2
    for line in _describe_answer(deployment, answer):
        print(line)
    print()
    rows = len(usage.rows)
    print(f"usage rows    : {rows} (in memory only; a session writes them to aegis.model_usage)")
    if rows:
        row = usage.rows[-1]
        print(
            f"would record  : status={row.status} {row.provider.value}/{row.model} "
            f"tokens={row.input_tokens}/{row.output_tokens} cost=${row.cost_usd:.6f}"
        )
    if answer.finish_reason.value == "provider_error":
        print("\nllm-smoke: FAILED - the provider answered with an error (see above)", file=sys.stderr)
        return 1
    if answer.usage.cost_usd <= 0:
        print(
            "\nllm-smoke: WARNING - the recorded cost is 0; check the price variables",
            file=sys.stderr,
        )
    print("\nllm-smoke: OK - the provider answered and the client normalized it")
    return 0


def main() -> int:
    load_env_file(ENV_FILE)
    return asyncio.run(smoke())


if __name__ == "__main__":
    sys.exit(main())
