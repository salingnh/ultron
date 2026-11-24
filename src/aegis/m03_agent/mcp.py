"""The MCP client M03 is allowed to use - the only way a session starts a job (G1.2b boundary).

`tools/call` on the Streamable HTTP MCP server is the single dispatch path: M05 owns acceptance
(idempotency, policy, signing) and this module never imports or calls it. The client sends the four
`aegis.io/*` keys of `contracts/mcp/README.md` in `params._meta`, so the server can bind the call to
the `agent_session` row M03 created, and it parses the answer with the contract's own schemas:

* a capability answer is `capability-response.v2` (`approved`/`duplicate` with a job id, or `denied`
  with an `error.v2`);
* a `graph.*` answer is the query's `graph-queries.v2` output (`data` + `truncated` +
  `limits_applied`);
* a protocol error (`-32602`, a bad `_meta`, an unknown tool) and a transport failure are outcomes
  too, not exceptions the loop has to guess about.

`ToolOutcome.text` keeps the provider's text verbatim: it is data for the prompt, never an
instruction (`prompt.wrap_untrusted` is the only way it reaches the model).
"""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import Any, Protocol, cast

import httpx
from mcp import ClientSession, types
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import MCPError
from mcp.types import RequestParamsMeta

from aegis import validation
from aegis.common.ports import ToolInfo
from aegis.m03_agent.wire import plain
from aegis.m05_registry.mcp import meta as meta_contract

__all__ = [
    "GRAPH_PREFIX",
    "CallMeta",
    "McpToolClient",
    "ToolClient",
    "ToolClientError",
    "ToolOutcome",
    "capability_response_problems",
    "graph_output_reference",
    "parse_capability_result",
    "parse_graph_result",
]

GRAPH_PREFIX = "graph."
CAPABILITY_RESPONSE_SCHEMA = "mcp/capability-response.v2.schema.json"
GRAPH_SCHEMA = "mcp/graph-queries.v2.schema.json"


class ToolClientError(RuntimeError):
    """The MCP transport could not be reached at all (no answer to interpret)."""


def capability_response_problems(response: Mapping[str, Any]) -> list[str]:
    return validation.errors(CAPABILITY_RESPONSE_SCHEMA, dict(response))


def graph_output_reference(query: str) -> str:
    """The contract reference of one query's output (`graph-queries.v2` `$defs/<query>`)."""
    return f"{GRAPH_SCHEMA}#/$defs/{query}/properties/output"


@dataclass(frozen=True, slots=True)
class CallMeta:
    """The `_meta` a call carries; `session_id` must be the `RUNNING` agent_session row (G1.2b)."""

    trace_id: str
    campaign_id: str
    session_id: str
    idempotency_key: str

    def as_meta(self) -> dict[str, str]:
        return {
            meta_contract.TRACE_ID: self.trace_id,
            meta_contract.CAMPAIGN_ID: self.campaign_id,
            meta_contract.SESSION_ID: self.session_id,
            meta_contract.IDEMPOTENCY_KEY: self.idempotency_key,
        }


@dataclass(frozen=True, slots=True)
class ToolOutcome:
    """One `tools/call` answer, already parsed with the contract schema that defines it."""

    tool: str
    #: `capability-response.v2` or the graph query output, when the call returned a structured one.
    response: Mapping[str, Any] | None = None
    #: The provider text verbatim (untrusted data; wrapped before it reaches a prompt).
    text: str = ""
    #: error.v2 code of a refusal/protocol error; None when the call produced a result.
    error_code: str | None = None
    detail: str | None = None
    #: True when the request never reached the tool (`-32602`, transport failure).
    request_refused: bool = False
    #: True for a `graph.*` answer (its `data` is the query output, not an acceptance).
    graph: bool = False

    @property
    def decision(self) -> str | None:
        if self.response is None or self.graph:
            return None
        value = self.response.get("decision")
        return None if value is None else str(value)

    @property
    def job_id(self) -> str | None:
        if self.response is None or self.graph:
            return None
        value = self.response.get("job_id")
        return None if value is None else str(value)

    @property
    def job_status(self) -> str | None:
        if self.response is None or self.graph:
            return None
        value = self.response.get("job_status")
        return None if value is None else str(value)

    @property
    def ok(self) -> bool:
        return self.error_code is None and self.response is not None


class ToolClient(Protocol):
    """The MCP surface M03 needs (one implementation over the SDK, one scripted in tests)."""

    async def list_tools(self, meta: CallMeta) -> list[ToolInfo]: ...

    async def call_capability(
        self, tool: str, arguments: Mapping[str, Any], *, meta: CallMeta
    ) -> ToolOutcome: ...

    async def query_graph(
        self, query: str, inputs: Mapping[str, Any], *, meta: CallMeta
    ) -> ToolOutcome: ...

    async def aclose(self) -> None: ...


class McpToolClient:
    """The SDK client of the M05 MCP boundary (Streamable HTTP, JSON responses)."""

    def __init__(self, url: str, *, timeout_seconds: float = 30.0) -> None:
        self.url = url
        self.timeout_seconds = timeout_seconds
        self._stack: AsyncExitStack | None = None
        self._session: ClientSession | None = None

    async def __aenter__(self) -> McpToolClient:
        await self.connect()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def connect(self) -> None:
        stack = AsyncExitStack()
        streams = await stack.enter_async_context(streamable_http_client(self.url))
        session = await stack.enter_async_context(ClientSession(streams[0], streams[1]))
        await session.initialize()
        self._stack = stack
        self._session = session

    async def aclose(self) -> None:
        stack, self._stack = self._stack, None
        self._session = None
        if stack is not None:
            await stack.aclose()

    def _client(self) -> ClientSession:
        if self._session is None:
            raise ToolClientError(
                "the MCP client is not connected; call connect()/aclose() around it"
            )
        return self._session

    async def list_tools(self, meta: CallMeta) -> list[ToolInfo]:
        session = self._client()
        try:
            listed = await session.list_tools(
                params=types.PaginatedRequestParams(_meta=cast(RequestParamsMeta, meta.as_meta()))
            )
        except MCPError as error:
            raise ToolClientError(
                f"tools/list was refused by the MCP server: {error.message}"
            ) from error
        except (httpx.HTTPError, OSError) as error:
            raise ToolClientError(
                f"the MCP server is unreachable at {self.url}: {error}"
            ) from error
        return [
            ToolInfo(
                name=tool.name,
                description=tool.description or "",
                input_schema=dict(tool.input_schema or {}),
            )
            for tool in listed.tools
        ]

    async def call_capability(
        self, tool: str, arguments: Mapping[str, Any], *, meta: CallMeta
    ) -> ToolOutcome:
        return parse_capability_result(tool, await self._call(tool, arguments, meta))

    async def query_graph(
        self, query: str, inputs: Mapping[str, Any], *, meta: CallMeta
    ) -> ToolOutcome:
        name = query if query.startswith(GRAPH_PREFIX) else f"{GRAPH_PREFIX}{query}"
        return parse_graph_result(name, await self._call(name, inputs, meta))

    async def _call(
        self, name: str, arguments: Mapping[str, Any], meta: CallMeta
    ) -> types.CallToolResult | ToolOutcome:
        session = self._client()
        try:
            result = await session.call_tool(
                name,
                dict(arguments),
                meta=cast(RequestParamsMeta, meta.as_meta()),
                read_timeout_seconds=self.timeout_seconds,
            )
        except MCPError as error:
            data = error.data if isinstance(error.data, dict) else {}
            return ToolOutcome(
                tool=name,
                error_code=str(data.get("code") or "INPUT_INVALID"),
                detail=str(data.get("message") or error.message)[:512],
                text=error.message,
                request_refused=True,
            )
        except (httpx.HTTPError, OSError) as error:
            return ToolOutcome(
                tool=name,
                error_code="INTERNAL_ERROR",
                detail=f"the MCP transport failed: {error}"[:512],
                request_refused=True,
            )
        if not isinstance(result, types.CallToolResult):
            return ToolOutcome(
                tool=name,
                error_code="OUTPUT_INVALID",
                detail=f"unexpected tools/call result type {type(result).__name__}",
                request_refused=True,
            )
        return result


def parse_capability_result(tool: str, result: types.CallToolResult | ToolOutcome) -> ToolOutcome:
    """Interpret a `tools/call` answer as `capability-response.v2` (or say why it is not one)."""
    if isinstance(result, ToolOutcome):
        return result
    payload = dict(result.structured_content or {})
    text = _text(result)
    if not payload:
        return ToolOutcome(
            tool=tool,
            text=text,
            error_code="OUTPUT_INVALID",
            detail="tools/call returned no structuredContent (capability-response.v2 missing)",
        )
    payload = plain(payload)
    problems = capability_response_problems(payload)
    if problems:
        return ToolOutcome(
            tool=tool,
            text=text,
            error_code="OUTPUT_INVALID",
            detail=("tools/call answer is not capability-response.v2: " + "; ".join(problems[:4])),
        )
    if payload.get("decision") == "denied" or result.is_error:
        error = payload.get("error") or {}
        return ToolOutcome(
            tool=tool,
            response=payload,
            text=text,
            error_code=str(error.get("code") or "POLICY_DENIED"),
            detail=str(error.get("message") or "the tool refused the request")[:512],
        )
    return ToolOutcome(tool=tool, response=payload, text=text)


def parse_graph_result(name: str, result: types.CallToolResult | ToolOutcome) -> ToolOutcome:
    """Interpret a `tools/call` answer of a `graph.*` query against its contract output schema."""
    bare = name.removeprefix(GRAPH_PREFIX)
    if isinstance(result, ToolOutcome):
        return result
    text = _text(result)
    payload = plain(dict(result.structured_content or {}))
    if result.is_error or not payload:
        # graph.py answers DEPENDENCY_MISSING/ESCALATE as an error.v2 body without a schema
        # (the projection is not wired yet); keep the code, never invent data.
        return ToolOutcome(
            tool=name,
            response=payload or None,
            text=text,
            error_code=str(payload.get("code") or "DEPENDENCY_MISSING"),
            detail=str(payload.get("message") or "the graph query is unavailable")[:512],
            graph=True,
        )
    problems = validation.errors(graph_output_reference(bare), payload)
    if problems:
        return ToolOutcome(
            tool=name,
            text=text,
            error_code="OUTPUT_INVALID",
            detail=(
                "graph answer is not the query's graph-queries.v2 output: "
                + "; ".join(problems[:4])
            ),
            graph=True,
        )
    return ToolOutcome(tool=name, response=payload, text=text, graph=True)


def _text(result: types.CallToolResult) -> str:
    parts = [block.text for block in result.content if isinstance(block, types.TextContent)]
    return "\n".join(parts)
