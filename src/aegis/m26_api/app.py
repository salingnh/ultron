"""FastAPI app factory for M26, built from the router registry.

Nothing here knows a business route: G1.1b registers campaigns, G1.1c jobs and G1.5a events/flow
in their own modules. The factory only mounts what is registered, exposes the OpenAPI document at
the versioned path the contract uses (`/api/v2/openapi.json`) and answers a liveness probe.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import FastAPI

from aegis.m26_api.errors import install_error_handlers
from aegis.m26_api.operator import OperatorAuthenticator
from aegis.m26_api.registry import RouterRegistry

__all__ = ["API_PREFIX", "OPENAPI_PATH", "create_app"]

API_PREFIX = "/api/v2"
OPENAPI_PATH = f"{API_PREFIX}/openapi.json"


def _drop_default_422(app: FastAPI) -> None:
    """Remove FastAPI's automatic 422 from the served OpenAPI.

    FastAPI documents a 422 for every operation with a body or a constrained
    parameter. This service never answers 422: `install_error_handlers` maps those
    failures to the contract's 400 `INPUT_INVALID`, and the contract documents no 422
    on any endpoint. Leaving the entry in the spec would advertise a response the
    server does not send.
    """
    generate: Callable[[], dict[str, Any]] = app.openapi

    def openapi() -> dict[str, Any]:
        schema = generate()
        for path_item in schema.get("paths", {}).values():
            for operation in path_item.values():
                if isinstance(operation, dict):
                    operation.get("responses", {}).pop("422", None)
        return schema

    app.openapi = openapi  # type: ignore[method-assign]


def create_app(
    registry: RouterRegistry | None = None,
    *,
    operator_authenticator: OperatorAuthenticator | None = None,
    database_dsn: str | None = None,
) -> FastAPI:
    """Build the API app from `registry` (empty by default until a card registers routers).

    `database_dsn` is the PostgreSQL DSN the request dependency opens a transaction
    on; it is `None` by default so an app without routes needs no database, and the
    dependency fails loudly when a route needs one. `operator_authenticator` stays
    fail-closed: without it every operator call is refused. The error handlers of
    `error.v2` are installed here so no route can answer with FastAPI's `detail` shape.
    """
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
    app.state.database_dsn = database_dsn
    install_error_handlers(app)
    _drop_default_422(app)

    @app.get("/healthz", tags=["ops"], operation_id="healthz", include_in_schema=False)
    def healthz() -> dict[str, Any]:
        """Liveness only: the process is up; dependencies are reported by readiness checks."""
        return {"status": "ok"}

    routers.include_all(app)
    return app
