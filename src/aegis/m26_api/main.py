"""Production entrypoint of the M26 API: `uvicorn aegis.m26_api.main:app`.

Two settings come from the environment and from nowhere else:

* `AEGIS_PG_DSN` - the PostgreSQL DSN the request dependency opens a transaction on
  (the same variable `python -m aegis.migrations` uses);
* `AEGIS_OPERATOR_TOKENS_FILE` - the JSON operator token store (sha256 digests; see
  `aegis.m26_api.operator`).

A missing or invalid setting aborts start-up with the error that names it: an app
that cannot verify operators must not come up accepting nobody *silently*, and an
app without a database must not come up only to fail on the first call.
"""

from __future__ import annotations

import os

from fastapi import FastAPI

from aegis.m26_api import events, flow, jobs
from aegis.m26_api.app import create_app
from aegis.m26_api.campaigns import register
from aegis.m26_api.operator import (
    OPERATOR_TOKENS_FILE,
    OperatorTokens,
    TokenAuthenticator,
)
from aegis.m26_api.registry import RouterRegistry

__all__ = ["PG_DSN_ENV", "build_registry", "create_production_app"]

PG_DSN_ENV = "AEGIS_PG_DSN"


def build_registry() -> RouterRegistry:
    """Every router this service mounts: campaigns (G1.1b), jobs (G1.1c), flow/events (G1.5a)."""
    registry = RouterRegistry()
    register(registry)
    jobs.register(registry)
    flow.register(registry)
    events.register(registry)
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
    )
    # M05 needs its own configured objects (manifest registry, signing ring); a manifest or key
    # problem aborts start-up instead of surfacing as an "unknown capability" on the first job.
    jobs.install_job_service(app, jobs.build_job_service(dsn))
    return app


app = create_production_app()
