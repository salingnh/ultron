"""Fake MCP/registry client: `tools/list` and `tools/call` from scripted contract payloads."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from aegis.common.ports import RegistryClient, ToolInfo
from aegis.contracts_gen.mcp.capability_request_v2_schema import CapabilityRequest
from aegis.contracts_gen.mcp.capability_response_v2_schema import CapabilityResponse


@dataclass
class FakeRegistryClient(RegistryClient):
    """Serves the given tool catalogue and one scripted `capability-response.v2` per tool."""

    tools: Sequence[ToolInfo]
    responses: dict[str, CapabilityResponse]
    calls: list[tuple[str, CapabilityRequest]] = field(default_factory=list, init=False)

    def list_tools(self) -> tuple[ToolInfo, ...]:
        return tuple(self.tools)

    def call(self, tool: str, request: CapabilityRequest) -> CapabilityResponse:
        if tool not in self.responses:
            raise KeyError(f"unknown tool {tool!r}")
        self.calls.append((tool, request))
        return self.responses[tool]
