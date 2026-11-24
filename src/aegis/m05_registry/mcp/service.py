"""Transport-free MCP tool service: `tools/list` and `tools/call` on top of M05.

The same service is driven by the Streamable HTTP server (`server`) and by the tests, so what a test
asserts is the code path a real client runs - contract validation, `_meta`, session authority,
M05 acceptance - not uvicorn.

Contract points implemented here (contracts/mcp/README.md):

* a capability tool is a job **request**: name = capability id, arguments = capability-request.v2;
  `tools/call` returns immediately with `capability-response.v2` (approved/duplicate) - results come
  later through query tools;
* the list is filtered by the campaign's `capability_denylist` and by what the registry can actually
  serve; a capability with no admitted manifest is not published;
* `_meta` is checked against the server-bound session (G0.3a): a wrong, missing or foreign value is
  `-32602` carrying `error.v2`, never a job;
* identity never comes from the request: the proposing session is the bound one, the initiator is
  this module (C05), and the `Idempotency-Key` is bound to that session by M05 (E-4);
* a policy refusal is `isError=true` with a full `capability-response.v2` (`decision=denied`) and a
  contract `error.v2`; `field` appears only on `INPUT_INVALID` (mcp/README.md).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from mcp import types
from mcp.shared.exceptions import MCPError
from mcp.types import INVALID_PARAMS

from aegis import validation
from aegis.contracts_gen.capability.job_submit_v2_schema import JobSubmit
from aegis.m05_registry.errors import M05Error
from aegis.m05_registry.manifest import ManifestRecord, schema_reference_path
from aegis.m05_registry.registry import ManifestRegistry
from aegis.m05_registry.service import JobService

from . import graph as graph_contract
from . import meta as meta_contract
from . import schemas
from .campaign import PolicySource
from .graph import GraphQueryService, GraphUnavailable, UnavailableGraphQueries
from .session import SessionContext, SessionDirectory

__all__ = [
    "DEFAULT_PRIORITY",
    "GRAPH_PREFIX",
    "REQUESTED_BY",
    "McpToolService",
    "ToolSpec",
    "invalid_params",
]

# C05: an agent session cannot be the initiator of a job, only its proposer. The MCP server is the
# module that turns an agent request into an M05 submission (requested_by stays server-derived).
REQUESTED_BY: Mapping[str, str] = {"kind": "module", "id": "M05"}
DEFAULT_PRIORITY = 50
GRAPH_PREFIX = "graph."
OBJECTIVE_POINTER = "/arguments/objective_id"


def error_object(
    *,
    code: str,
    message: str,
    next_action: str = "FIX_INPUT",
    field: str | None = None,
    trace_id: str | None = None,
) -> dict[str, Any]:
    """One `error.v2` value, validated before it reaches a client."""
    value: dict[str, Any] = {"code": code, "message": message, "next_action": next_action}
    if field is not None:
        value["field"] = field
    if trace_id is not None:
        value["trace_id"] = trace_id
    problems = schemas.error_schema().problems(value)
    if problems:  # pragma: no cover - a schema/code mismatch is a bug, not a caller error
        raise RuntimeError(f"error.v2 violation: {problems}")
    return value


def invalid_params(*, field: str, message: str, trace_id: str | None = None) -> MCPError:
    """`-32602` carrying `error.v2` with `INPUT_INVALID` (the contract's metadata error)."""
    return MCPError(
        code=INVALID_PARAMS,
        message=f"INPUT_INVALID: {message}",
        data=error_object(
            code="INPUT_INVALID",
            message=message,
            next_action="FIX_INPUT",
            field=field,
            trace_id=trace_id,
        ),
    )


def _trace_hint(meta: Mapping[str, Any] | None) -> str | None:
    """The trace id to echo in an error whose `_meta` did not validate as a whole."""
    if not isinstance(meta, Mapping):
        return None
    value = meta.get(meta_contract.TRACE_ID)
    if isinstance(value, str) and len(value) == 32 and all(c in "0123456789abcdef" for c in value):
        return value
    return None


def _merge_input_defaults(record: ManifestRecord, submitted: Mapping[str, Any]) -> dict[str, Any]:
    """`inputDefaults` under the submitted input, exactly like `m05_registry.caps.merge_input`.

    M05 merges the same defaults again when it accepts the request; doing it here first means the
    body the client's schema validated is the body M05 approves, stores and the runner executes.
    """
    defaults = record.spec.get("inputDefaults") or {}
    if not isinstance(defaults, Mapping):
        raise validation.ContractUnavailable(
            f"{record.provider}: manifest inputDefaults is not an object"
        )
    merged: dict[str, Any] = {str(key): value for key, value in defaults.items()}
    merged.update({str(key): value for key, value in submitted.items()})
    return merged


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """One published tool: a capability request or a `graph.*` query, with its wire schemas."""

    name: str
    description: str
    input_schema: Mapping[str, Any]
    output_schema: Mapping[str, Any]
    kind: Literal["capability", "graph"]
    capability: str | None = None
    query: str | None = None


@dataclass
class McpToolService:
    """`tools/list` + `tools/call`; every dependency is a seam so tests need no database."""

    registry: ManifestRegistry
    jobs: JobService
    sessions: SessionDirectory
    policies: PolicySource
    graph: GraphQueryService = field(default_factory=UnavailableGraphQueries)

    # --- tools/list -------------------------------------------------------------------------
    def tool_specs(self, denied: frozenset[str]) -> list[ToolSpec]:
        """What this campaign may see: served capabilities minus its denylist, plus graph.*."""
        specs: list[ToolSpec] = []
        seen: set[str] = set()
        for record in sorted(self.registry.all(), key=lambda item: item.capability):
            capability = record.capability
            if capability in seen or capability in denied:
                continue
            path = schema_reference_path(record.input_schema_ref)
            if path is None:  # pragma: no cover - admission already refuses this
                continue
            seen.add(capability)
            specs.append(
                ToolSpec(
                    name=capability,
                    description=(
                        f"Request one {capability} job through M05 (provider {record.provider}); "
                        "returns a job id immediately, results arrive later as knowledge."
                    ),
                    input_schema=schemas.capability_request_schema(path).schema,
                    output_schema=schemas.capability_response_schema().schema,
                    kind="capability",
                    capability=capability,
                )
            )
        for query in schemas.graph_query_names():
            specs.append(
                ToolSpec(
                    name=GRAPH_PREFIX + query,
                    description=schemas.graph_tool_description(query),
                    input_schema=schemas.graph_input_schema(query).schema,
                    output_schema=schemas.graph_output_schema(query).schema,
                    kind="graph",
                    query=query,
                )
            )
        return specs

    def list_tools(
        self, *, request_meta: Mapping[str, Any] | None, mcp_session_id: str | None
    ) -> types.ListToolsResult:
        """The catalogue: campaign-filtered when a session `_meta` is sent, admitted otherwise.

        A client that sends no `aegis.io/*` key has not identified a campaign, so there is no
        policy to apply and no session to bind: it gets the registry's admitted capabilities. This
        arm exists for the protocol itself - an SDK client probes `tools/list` without `_meta` to
        validate a tool's `outputSchema` before it returns a result - and such a client still
        cannot call a tool it was not granted. A `_meta` that names the namespace but is
        incomplete or wrong is refused, not tolerated.
        """
        meta_keys = () if request_meta is None else tuple(str(key) for key in request_meta)
        if not any(key.startswith(meta_contract.NAMESPACE) for key in meta_keys):
            return self._list(frozenset())
        _, context = self.context(request_meta=request_meta, mcp_session_id=mcp_session_id)
        return self._list(self.policies.capability_denylist(context.campaign_id))

    def _list(self, denied: frozenset[str]) -> types.ListToolsResult:
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name=spec.name,
                    description=spec.description,
                    input_schema=dict(spec.input_schema),
                    output_schema=dict(spec.output_schema),
                )
                for spec in self.tool_specs(denied)
            ]
        )

    # --- tools/call -------------------------------------------------------------------------
    def call(
        self,
        *,
        tool_name: str,
        arguments: Mapping[str, Any] | None,
        request_meta: Mapping[str, Any] | None,
        mcp_session_id: str | None,
    ) -> types.CallToolResult:
        meta, context = self.context(request_meta=request_meta, mcp_session_id=mcp_session_id)
        if tool_name.startswith(GRAPH_PREFIX):
            return self._call_graph(meta, context, tool_name.removeprefix(GRAPH_PREFIX), arguments)
        return self._call_capability(meta, context, tool_name, arguments)

    def context(
        self, *, request_meta: Mapping[str, Any] | None, mcp_session_id: str | None
    ) -> tuple[meta_contract.Meta, SessionContext]:
        """Parse `_meta` and check it against the session the server bound to this transport."""
        meta, problems = meta_contract.parse_meta(request_meta)
        if problems:
            raise invalid_params(
                field=problems[0].pointer,
                message="; ".join(f"{problem.pointer}: {problem.message}" for problem in problems),
                trace_id=_trace_hint(request_meta),
            )
        assert meta is not None
        context, reason = self.sessions.resolve(
            mcp_session_id, campaign_id=meta.campaign_id, session_id=meta.session_id
        )
        if context is None:
            raise invalid_params(
                field=meta_contract.json_pointer(meta_contract.SESSION_ID),
                message=(
                    "campaign_id/session_id do not match the server-side session "
                    f"({reason}); _meta never grants access"
                ),
                trace_id=meta.trace_id,
            )
        return meta, context

    def _published(self, context: SessionContext, tool_name: str) -> ManifestRecord:
        denied = self.policies.capability_denylist(context.campaign_id)
        for record in self.registry.all():
            if record.capability == tool_name and tool_name not in denied:
                return record
        raise invalid_params(
            field="/name",
            message=(
                f"capability {tool_name!r} is not published for this campaign/session; "
                "call tools/list for the capabilities this session may request"
            ),
        )

    def _call_capability(
        self,
        meta: meta_contract.Meta,
        context: SessionContext,
        tool_name: str,
        arguments: Mapping[str, Any] | None,
    ) -> types.CallToolResult:
        record = self._published(context, tool_name)
        path = schema_reference_path(record.input_schema_ref)
        if path is None:  # pragma: no cover - admission already refuses this
            raise invalid_params(
                field="/name",
                message=f"capability {tool_name!r} has no resolvable input schema",
                trace_id=meta.trace_id,
            )
        if arguments is not None and not isinstance(arguments, Mapping):
            raise invalid_params(
                field="/arguments",
                message="arguments must be a JSON object",
                trace_id=meta.trace_id,
            )
        schema = schemas.capability_request_schema(path)
        # Only the wrapper's own defaults (priority, depends_on) are defaulted here; the capability
        # input is defaulted by the manifest/M05 so there is one merge, not two.
        payload = schemas.apply_defaults(schema.schema, dict(arguments or {}), nested=False)
        submitted_input = payload.get("input")
        if isinstance(submitted_input, Mapping):
            payload["input"] = _merge_input_defaults(record, submitted_input)
        problems = schema.problems(payload)
        if problems:
            pointer, message = problems[0]
            raise invalid_params(
                field="/arguments" + pointer, message=message, trace_id=meta.trace_id
            )

        objective = payload.get("objective_id")
        if context.objective_id is not None and objective != context.objective_id:
            raise invalid_params(
                field=OBJECTIVE_POINTER,
                message=(
                    "objective_id must be the bound session's objective; the server does not "
                    "accept an objective the session was not opened for"
                ),
                trace_id=meta.trace_id,
            )

        request = JobSubmit.model_validate(
            {
                "campaign_id": context.campaign_id,
                "capability": record.capability,
                "input": payload["input"],
                "rationale": payload["rationale"],
                "priority": payload.get("priority", DEFAULT_PRIORITY),
                "depends_on": payload.get("depends_on", []),
                # The scan cycle belongs to the session, not to the model's arguments: a retry in
                # the same session must land on the same scan (and the same job), and a *new* scan
                # is a new agent session until the contract adds a key for it (mcp/README.md).
                "scan_cycle": context.scan_cycle,
            }
        )
        try:
            outcome = self.jobs.submit(
                request,
                requested_by=REQUESTED_BY,
                proposed_by={"kind": "agent", "id": context.session_id},
                idempotency_key=meta.idempotency_key,
                trace_id=meta.trace_id,
            )
        except M05Error as error:
            return self._denied(error, trace_id=meta.trace_id)
        response: dict[str, Any] = {
            "decision": "duplicate" if outcome.replayed else "approved",
            "job_id": outcome.job["job_id"],
            "job_status": outcome.job["status"],
            "provider": outcome.job["provider"],
            "policy_version": outcome.job["policy_version"],
        }
        return self._structured(response, is_error=False)

    def _denied(self, error: M05Error, *, trace_id: str) -> types.CallToolResult:
        refusal = error.refusal
        value = refusal.body(trace_id)
        if str(refusal.code) != "INPUT_INVALID":
            # mcp/README.md: `field` is INPUT_INVALID-only; other codes carry the detail in message.
            value.pop("field", None)
        return self._structured({"decision": "denied", "error": value}, is_error=True)

    def _call_graph(
        self,
        meta: meta_contract.Meta,
        context: SessionContext,
        query: str,
        arguments: Mapping[str, Any] | None,
    ) -> types.CallToolResult:
        if query not in schemas.graph_query_names():
            raise invalid_params(
                field="/name",
                message=f"query {GRAPH_PREFIX}{query!r} is not one of the contract's graph tools",
                trace_id=meta.trace_id,
            )
        input_schema = schemas.graph_input_schema(query)
        inputs = schemas.apply_defaults(input_schema.schema, dict(arguments or {}))
        problems = input_schema.problems(inputs)
        if problems:
            pointer, message = problems[0]
            raise invalid_params(
                field="/arguments" + pointer, message=message, trace_id=meta.trace_id
            )
        if inputs.get("campaign_id") != context.campaign_id:
            raise invalid_params(
                field="/arguments/campaign_id",
                message=(
                    "campaign_id must be the campaign this session is bound to; a query never "
                    "reads another campaign"
                ),
                trace_id=meta.trace_id,
            )
        limits = graph_contract.limits_for(query, inputs)
        try:
            result = self.graph.run(query, inputs, campaign_id=context.campaign_id, limits=limits)
        except GraphUnavailable as error:
            return self._graph_error(
                error_object(
                    code="DEPENDENCY_MISSING",
                    message=str(error),
                    next_action="ESCALATE",
                    trace_id=meta.trace_id,
                )
            )
        output: dict[str, Any] = dict(result.data)
        output["truncated"] = bool(result.truncated)
        output["limits_applied"] = limits.as_json()
        found = schemas.graph_output_schema(query).problems(output)
        if found:  # pragma: no cover - a projection bug, not a caller error
            raise RuntimeError(
                f"graph.{query} produced an invalid graph-queries.v2 output: {found}"
            )
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps(output, sort_keys=True))],
            structured_content=output,
        )

    # --- result helpers ---------------------------------------------------------------------
    def _structured(self, value: Mapping[str, Any], *, is_error: bool) -> types.CallToolResult:
        payload = dict(value)
        found = schemas.capability_response_schema().problems(payload)
        if found:  # pragma: no cover - a service bug; the contract shape is built above
            raise RuntimeError(f"capability-response.v2 violation: {found}")
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps(payload, sort_keys=True))],
            structured_content=payload,
            is_error=is_error,
        )

    def _graph_error(self, value: Mapping[str, Any]) -> types.CallToolResult:
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps(value, sort_keys=True))],
            is_error=True,
        )
