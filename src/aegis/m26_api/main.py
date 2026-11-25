"""Production entrypoint of the M26 API: `uvicorn aegis.m26_api.main:app`.

Three settings come from the environment and from nowhere else:

* `AEGIS_PG_DSN` - the PostgreSQL DSN the request dependency opens a transaction on
  (the same variable `python -m aegis.migrations` uses);
* `AEGIS_OPERATOR_TOKENS_FILE` - the JSON operator token store (sha256 digests; see
  `aegis.m26_api.operator`);
* `AEGIS_CORS_ORIGINS` (optional) - comma-separated browser origins allowed to call the
  API, e.g. the Vite dev server behind `make run-local`. Unset means no CORS at all.

A missing or invalid setting aborts start-up with the error that names it: an app
that cannot verify operators must not come up accepting nobody *silently*, and an
app without a database must not come up only to fail on the first call.
"""

from __future__ import annotations

import os

from fastapi import FastAPI

from aegis.m26_api import (
    activity,
    assets,
    capabilities,
    events,
    flow,
    jobs,
    vulnerabilities,
)
from aegis.m26_api.app import CORS_ORIGINS_ENV, cors_origins_from_env, create_app
from aegis.m26_api.campaigns import register
from aegis.m26_api.operator import (
    OPERATOR_TOKENS_FILE,
    OperatorTokens,
    TokenAuthenticator,
)
from aegis.m26_api.registry import RouterRegistry
from aegis.m27_ingestion.router import register as register_ingestion
from aegis.m27_ingestion.service import IngestionService

__all__ = ["CORS_ORIGINS_ENV", "PG_DSN_ENV", "build_registry", "create_production_app"]

PG_DSN_ENV = "AEGIS_PG_DSN"


def build_registry() -> RouterRegistry:
    """Every router this service mounts: campaigns (G1.1b), jobs (G1.1c), flow/events/capabilities
    (G1.5a), the activity timeline (G1.6), assets (G1.4b), candidate vulnerabilities (G1.6 slice C)
    and the ingestion endpoint M27 owns (G1.4a/G1.5c)."""
    registry = RouterRegistry()
    register(registry)
    jobs.register(registry)
    flow.register(registry)
    activity.register(registry)
    events.register(registry)
    capabilities.register(registry)
    assets.register(registry)
    vulnerabilities.register(registry)
    register_ingestion(registry)
    return registry


def create_production_app() -> FastAPI:
    """Build the app from the environment; raises when a required setting is missing."""
    dsn = os.environ.get(PG_DSN_ENV)
    if not dsn:
        raise RuntimeError(f"{PG_DSN_ENV} is required to run the API")
    tokens_path = os.environ.get(OPERATOR_TOKENS_FILE)
    if not tokens_path:
        raise RuntimeError(f"{OPERATOR_TOKENS_FILE} is required to verify operator tokens")
    tokens = OperatorTokens.from_file(tokens_path)
    app = create_app(
        build_registry(),
        operator_authenticator=TokenAuthenticator(tokens),
        database_dsn=dsn,
        cors_origins=cors_origins_from_env() or None,
    )
    # M05 needs its own configured objects (manifest registry, signing ring); a manifest or key
    # problem aborts start-up instead of surfacing as an "unknown capability" on the first job.
    jobs.install_job_service(app, jobs.build_job_service(dsn))
    # M27's endpoint is served by this app (contracts/api/openapi.v2.yaml, tag `ingestion`): the
    # service token is read from AEGIS_SERVICE_TOKEN by the route, and an unconfigured token fails
    # closed with 401 rather than accepting anonymous submissions.
    app.state.ingestion = IngestionService.from_dsn(dsn)
    return app


app = create_production_app()
