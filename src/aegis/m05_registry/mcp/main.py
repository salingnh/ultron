"""Production entrypoint of the MCP server: `uvicorn aegis.m05_registry.mcp.main:app`.

Settings come from the environment and nowhere else:

* `AEGIS_PG_DSN` - PostgreSQL DSN (the same variable the API and the migration runner use);
* the signing key ring of `aegis.m05_registry.signing` (job tasks are signed, never unsigned);
* `AEGIS_ADAPTER_MANIFESTS` - optional manifest directory (default `adapters/`);
* `AEGIS_MCP_HOST` / `AEGIS_MCP_ALLOWED_HOSTS` - the DNS-rebinding guard's host names.

A missing DSN, signing key or admitted manifest aborts start-up with the error that names it: a
server that cannot sign, or that silently drops a provider, must not come up looking healthy.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

import psycopg
from starlette.applications import Starlette

from aegis.m05_registry.mcp.campaign import PostgresCampaignPolicies
from aegis.m05_registry.mcp.graph import GraphQueryService, UnavailableGraphQueries
from aegis.m05_registry.mcp.server import build_app
from aegis.m05_registry.mcp.service import McpToolService
from aegis.m05_registry.mcp.session import PostgresSessionDirectory
from aegis.m05_registry.registry import PostgresManifestRegistry
from aegis.m05_registry.service import PostgresJobService
from aegis.m05_registry.signing import KeyRing
from aegis.m26_api.manifests import adapter_manifests

__all__ = [
    "ALLOWED_HOSTS_ENV",
    "HOST_ENV",
    "PG_DSN_ENV",
    "build_service",
    "create_production_app",
]

PG_DSN_ENV = "AEGIS_PG_DSN"
HOST_ENV = "AEGIS_MCP_HOST"
ALLOWED_HOSTS_ENV = "AEGIS_MCP_ALLOWED_HOSTS"


def build_service(
    dsn: str | None = None,
    *,
    connect: Callable[[], Any] | None = None,
    graph: GraphQueryService | None = None,
) -> McpToolService:
    """M05 (registry, signing ring) + the session/policy readers + the graph provider seam."""
    resolved = dsn or os.environ.get(PG_DSN_ENV)
    if not resolved:
        raise RuntimeError(f"{PG_DSN_ENV} is required to run the MCP server")
    opener: Callable[[], Any] = connect or (lambda: psycopg.connect(resolved))
    registry = PostgresManifestRegistry(opener)
    manifests = adapter_manifests()
    for raw in manifests:
        registry.register(raw, registered_by={"kind": "module", "id": "M05"})
    if not manifests and os.environ.get("AEGIS_ADAPTER_MANIFESTS"):
        # An explicitly configured directory that yields nothing is a deployment error, not the
        # pre-G1.3b state; without the setting an empty registry just publishes no capability tool.
        raise RuntimeError("AEGIS_ADAPTER_MANIFESTS is set but no manifest.yaml was found under it")
    jobs = PostgresJobService(opener, registry=registry, key_ring=KeyRing.from_env())
    return McpToolService(
        registry=registry,
        jobs=jobs,
        sessions=PostgresSessionDirectory(opener),
        policies=PostgresCampaignPolicies(opener),
        graph=graph or UnavailableGraphQueries(),
    )


def create_production_app() -> Starlette:
    """Build the transport app from the environment (raises when a setting is missing)."""
    service = build_service()
    allowed = [
        host.strip() for host in os.environ.get(ALLOWED_HOSTS_ENV, "").split(",") if host.strip()
    ]
    return build_app(
        service,
        host=os.environ.get(HOST_ENV, "127.0.0.1"),
        allowed_hosts=allowed or None,
    )


app = create_production_app()
