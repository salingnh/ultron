"""The MCP boundary (G1.2b): tools/list and tools/call as the contract defines them.

Entry points:

* `aegis.m05_registry.mcp.service.McpToolService` - transport-free; what tests drive;
* `aegis.m05_registry.mcp.server` - the Streamable HTTP app;
* `aegis.m05_registry.mcp.main` - `uvicorn aegis.m05_registry.mcp.main:app`.
"""

from __future__ import annotations

from aegis.m05_registry.mcp.campaign import (
    InMemoryCampaignPolicies,
    PolicySource,
    PostgresCampaignPolicies,
)
from aegis.m05_registry.mcp.graph import (
    GraphLimits,
    GraphQueryResult,
    GraphQueryService,
    GraphUnavailable,
    UnavailableGraphQueries,
)
from aegis.m05_registry.mcp.server import build_app, build_server
from aegis.m05_registry.mcp.service import REQUESTED_BY, McpToolService, ToolSpec
from aegis.m05_registry.mcp.session import (
    InMemorySessionDirectory,
    PostgresSessionDirectory,
    SessionContext,
    SessionDirectory,
)

__all__ = [
    "REQUESTED_BY",
    "GraphLimits",
    "GraphQueryResult",
    "GraphQueryService",
    "GraphUnavailable",
    "InMemoryCampaignPolicies",
    "InMemorySessionDirectory",
    "McpToolService",
    "PolicySource",
    "PostgresCampaignPolicies",
    "PostgresSessionDirectory",
    "SessionContext",
    "SessionDirectory",
    "ToolSpec",
    "UnavailableGraphQueries",
    "build_app",
    "build_server",
]
