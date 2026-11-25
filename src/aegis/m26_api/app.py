"""FastAPI app factory for M26, built from the router registry.

Nothing here knows a business route: G1.1b registers campaigns, G1.1c jobs and G1.5a events/flow
in their own modules. The factory only mounts what is registered, exposes the OpenAPI document at
the versioned path the contract uses (`/api/v2/openapi.json`) and answers a liveness probe.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from aegis.m04_model.deployment import model_status
from aegis.m26_api.errors import install_error_handlers
from aegis.m26_api.operator import OperatorAuthenticator
from aegis.m26_api.registry import RouterRegistry

__all__ = [
    "API_PREFIX",
    "CORS_HEADERS",
    "CORS_ORIGINS_ENV",
    "OPENAPI_PATH",
    "cors_origins_from_env",
    "create_app",
]

API_PREFIX = "/api/v2"
OPENAPI_PATH = f"{API_PREFIX}/openapi.json"

#: Origins allowed to call the API from a browser (comma-separated, empty = no CORS at all).
CORS_ORIGINS_ENV = "AEGIS_CORS_ORIGINS"
#: Request headers the browser client sends (operator token, idempotent writes, SSE resume, trace).
CORS_HEADERS = ("Authorization", "Content-Type", "Idempotency-Key", "Last-Event-ID", "traceparent")
#: Response headers a browser client may read (trace id, replay marker, stream generation, retry).
CORS_EXPOSE_HEADERS = ("traceparent", "Idempotent-Replayed", "X-Aegis-Consumer", "Retry-After")


def cors_origins_from_env(environ: Mapping[str, str] | None = None) -> list[str]:
    """The browser origins from `AEGIS_CORS_ORIGINS`; unset means "no cross-origin access"."""
    source = os.environ if environ is None else environ
    raw = (source.get(CORS_ORIGINS_ENV) or "").strip()
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


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
    cors_origins: Sequence[str] | None = None,
    graph_driver: Any | None = None,
) -> FastAPI:
    """Build the API app from `registry` (empty by default until a card registers routers).

    `database_dsn` is the PostgreSQL DSN the request dependency opens a transaction
    on; it is `None` by default so an app without routes needs no database, and the
    dependency fails loudly when a route needs one. `operator_authenticator` stays
    fail-closed: without it every operator call is refused. The error handlers of
    `error.v2` are installed here so no route can answer with FastAPI's `detail` shape.
    `graph_driver` is the Neo4j driver the graph read routes (G1.4b) use; the graph route
    fails loudly on a missing one, like the database dependency does.
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
    app.state.graph_driver = graph_driver
    install_error_handlers(app)
    _drop_default_422(app)
    if cors_origins:
        # An explicit allowlist, never "*": the operator token travels in a header, so a browser
        # origin that is not named here must not be able to read a response or send a preflight.
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(cors_origins),
            allow_methods=["GET", "POST"],
            allow_headers=list(CORS_HEADERS),
            expose_headers=list(CORS_EXPOSE_HEADERS),
            max_age=600,
        )

    @app.get("/healthz", tags=["ops"], operation_id="healthz", include_in_schema=False)
    def healthz() -> dict[str, Any]:
        """Liveness, plus the model mode this deployment's environment selects (G1.6).

        The model block is configuration, not a probe: the API process reads the same environment
        the workers inherit, so an operator can tell scripted from live without a database call.
        It never carries the credential (`aegis.m04_model.deployment.model_status`).
        """
        return {"status": "ok", "model": model_status()}

    routers.include_all(app)
    return app
