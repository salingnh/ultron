"""MCP tool service for spike G0.3a: tools/list + idempotent tools/call.

Transport free on purpose: the same service is driven by the Streamable HTTP
server and by the latency benchmark, so "handler latency" is measured on the
code path the real M05 MCP boundary will run (contract validation, session
check, registry lookup, idempotent job create), not on uvicorn.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from typing import Any, Mapping

from mcp import types
from mcp.shared.exceptions import MCPError
from mcp.types import INVALID_PARAMS

from . import contracts, meta as meta_contract
from .registry import (
    FakeRegistry,
    IdempotencyConflict,
    Job,
    Provider,
    SchedulingConflict,
    SessionContext,
)

POLICY_VERSION = "roe-1"
DEFAULT_PRIORITY = 50


def error_object(
    *,
    code: str,
    message: str,
    field: str | None = None,
    trace_id: str | None = None,
    next_action: str = "FIX_INPUT",
) -> dict[str, Any]:
    value: dict[str, Any] = {"code": code, "message": message, "next_action": next_action}
    if field is not None:
        value["field"] = field
    if trace_id is not None:
        value["trace_id"] = trace_id
    problems = contracts.errors_for(contracts.error_schema(), value)
    if problems:  # pragma: no cover - would be a spike bug
        raise RuntimeError(f"error.v2 violation: {problems}")
    return value


def invalid_params(*, field: str, message: str, trace_id: str | None = None) -> MCPError:
    """-32602 carrying an error.v2 object with code INPUT_INVALID."""
    return MCPError(
        code=INVALID_PARAMS,
        message=f"INPUT_INVALID: {message}",
        data=error_object(code="INPUT_INVALID", message=message, field=field, trace_id=trace_id),
    )


def apply_defaults(schema: Mapping[str, Any], value: Any) -> Any:
    """Merge schema defaults before validation (README: inputDefaults then validate)."""
    if isinstance(value, dict):
        result = dict(value)
        for name, subschema in (schema.get("properties") or {}).items():
            if isinstance(subschema, Mapping) and "default" in subschema:
                if name not in result:
                    result[name] = copy.deepcopy(subschema["default"])
            if name in result:
                result[name] = apply_defaults(subschema, result[name])
        return result
    if isinstance(value, list) and "items" in schema:
        return [apply_defaults(schema["items"], item) for item in value]
    return value


@dataclass(frozen=True)
class ToolSpec:
    capability: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]


@dataclass
class McpToolService:
    registry: FakeRegistry
    denied_capabilities: frozenset[str] = frozenset()
    campaign_capabilities: frozenset[str] | None = None
    called: int = field(default=0)

    # -- tools/list ---------------------------------------------------------
    def tool_specs(self) -> list[ToolSpec]:
        specs = []
        for capability in sorted(contracts.CAPABILITY_SCHEMAS):
            if capability in self.denied_capabilities:
                continue
            if self.campaign_capabilities is not None and capability not in self.campaign_capabilities:
                continue
            specs.append(
                ToolSpec(
                    capability=capability,
                    description=f"Submit a {capability} job through M05 (spike fake registry).",
                    input_schema=contracts.tool_input_schema(capability),
                    output_schema=contracts.response_schema(),
                )
            )
        return specs

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name=spec.capability,
                description=spec.description,
                input_schema=spec.input_schema,
                output_schema=spec.output_schema,
            )
            for spec in self.tool_specs()
        ]

    # -- tools/call ---------------------------------------------------------
    async def call(
        self,
        *,
        tool_name: str,
        arguments: Mapping[str, Any] | None,
        request_meta: Mapping[str, Any] | None,
        mcp_session_id: str | None,
    ) -> types.CallToolResult:
        self.called += 1
        meta, meta_errors = meta_contract.parse_meta(request_meta)
        if meta_errors:
            first = meta_errors[0]
            raise invalid_params(
                field=first.pointer,
                message="; ".join(f"{error.pointer}: {error.message}" for error in meta_errors),
            )
        assert meta is not None

        context, session_problem = self.registry.sessions.resolve(
            mcp_session_id, meta.campaign_id, meta.session_id
        )
        if context is None:
            raise invalid_params(
                field=meta_contract.json_pointer(meta_contract.SESSION_ID),
                message=(
                    f"campaign_id/session_id do not match the server-side session ({session_problem})"
                ),
                trace_id=meta.trace_id,
            )

        spec = next((item for item in self.tool_specs() if item.capability == tool_name), None)
        if spec is None:
            raise invalid_params(
                field="/name",
                message=f"capability {tool_name!r} is not published for this campaign/session",
                trace_id=meta.trace_id,
            )

        payload = apply_defaults(spec.input_schema, dict(arguments or {}))
        problems = contracts.errors_for(spec.input_schema, payload)
        if problems:
            raise invalid_params(
                field="/arguments" + problems[0][0],
                message=problems[0][1],
                trace_id=meta.trace_id,
            )

        return await self._submit(spec=spec, payload=payload, meta=meta, context=context)

    async def _submit(
        self,
        *,
        spec: ToolSpec,
        payload: dict[str, Any],
        meta: meta_contract.Meta,
        context: SessionContext,
    ) -> types.CallToolResult:
        provider = self.registry.choose_provider(spec.capability)
        if provider is None:
            return self._result(
                {
                    "decision": "denied",
                    "error": error_object(
                        code="TOOL_UNAVAILABLE",
                        message=f"no healthy provider registered for {spec.capability}",
                        next_action="CHECK_PROVIDER",
                        trace_id=meta.trace_id,
                    ),
                },
                is_error=True,
            )

        try:
            submitted = await self.registry.submit(
                campaign_id=meta.campaign_id,
                session_id=meta.session_id,
                idempotency_key=meta.idempotency_key,
                capability=spec.capability,
                provider=provider,
                input=payload["input"],
                priority=payload["priority"],
                depends_on=payload["depends_on"],
                scan_cycle=context.scan_cycle,
            )
        except IdempotencyConflict:
            return self._result(
                {
                    "decision": "denied",
                    "error": error_object(
                        code="INPUT_INVALID",
                        message=(
                            "idempotency_key was already used for a different scan "
                            "(campaign/provider pin/input/scan_cycle differ); use a new key"
                        ),
                        field=meta_contract.json_pointer(meta_contract.IDEMPOTENCY_KEY),
                        trace_id=meta.trace_id,
                    ),
                },
                is_error=True,
            )
        except SchedulingConflict:
            return self._result(
                {
                    "decision": "denied",
                    "error": error_object(
                        code="INPUT_INVALID",
                        message=(
                            "idempotency_key was already used with a different priority/"
                            "depends_on; scheduling does not identify a scan"
                        ),
                        field=meta_contract.json_pointer(meta_contract.IDEMPOTENCY_KEY),
                        trace_id=meta.trace_id,
                    ),
                },
                is_error=True,
            )

        return self._result(self._job_response(submitted.decision, submitted.job))

    def _job_response(self, decision: str, job: Job) -> dict[str, Any]:
        return {
            "decision": decision,
            "job_id": job.job_id,
            "job_status": "QUEUED",
            "provider": job.provider.name,
            "policy_version": POLICY_VERSION,
        }

    def _result(self, structured: dict[str, Any], *, is_error: bool = False) -> types.CallToolResult:
        problems = contracts.errors_for(contracts.response_schema(), structured)
        if problems:  # pragma: no cover - would be a spike bug
            raise RuntimeError(f"capability-response.v2 violation: {problems}")
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps(structured, sort_keys=True))],
            structured_content=structured,
            is_error=is_error,
        )


def session_for(campaign_id: str, session_id: str, scan_cycle: str) -> SessionContext:
    return SessionContext(campaign_id=campaign_id, session_id=session_id, scan_cycle=scan_cycle)


__all__ = [
    "DEFAULT_PRIORITY",
    "McpToolService",
    "POLICY_VERSION",
    "Provider",
    "ToolSpec",
    "apply_defaults",
    "error_object",
    "invalid_params",
    "session_for",
]
