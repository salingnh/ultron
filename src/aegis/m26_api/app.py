"""FastAPI app factory for M26, built from the router registry.

Nothing here knows a business route: G1.1b registers campaigns, G1.1c jobs and G1.5a events/flow
in their own modules. The factory only mounts what is registered, exposes the OpenAPI document at
the versioned path the contract uses (`/api/v2/openapi.json`) and answers a liveness probe.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI

from aegis.m26_api.operator import OperatorAuthenticator
from aegis.m26_api.registry import RouterRegistry

__all__ = ["API_PREFIX", "OPENAPI_PATH", "create_app"]

API_PREFIX = "/api/v2"
OPENAPI_PATH = f"{API_PREFIX}/openapi.json"


def create_app(
    registry: RouterRegistry | None = None,
    *,
    operator_authenticator: OperatorAuthenticator | None = None,
) -> FastAPI:
    """Build the API app from `registry` (empty by default until G1.1b registers routers)."""
    routers = registry if registry is not None else RouterRegistry()
    app = FastAPI(
        title="AEGIS–Vanguard",
        version="2",
        openapi_url=OPENAPI_PATH,
        docs_url=None,
        redoc_url=None,
    )
    app.state.router_registry = routers
    app.state.operator_authenticator = operator_authenticator

    @app.get("/healthz", tags=["ops"], operation_id="healthz", include_in_schema=False)
    def healthz() -> dict[str, Any]:
        """Liveness only: the process is up; dependencies are reported by readiness checks."""
        return {"status": "ok"}

    routers.include_all(app)
    return app
