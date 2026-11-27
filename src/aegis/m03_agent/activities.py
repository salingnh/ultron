"""`run_agent_session` - the M03 activity M02's worker registers on the `aegis-agent` queue.

The seam is M02's (`SessionRequest` → `SessionOutcome`, `m02_orchestrator/types.py`), the work is
`session.run_session`, and this module adds only what an activity needs:

* **a heartbeat**, because G1.1d schedules the activity with `heartbeat_timeout=3s` and
  `WAIT_CANCELLATION_COMPLETED`; a session that stops beating is a dead worker, and a cancel has to
  reach the session's cleanup (G0.1 memo);
* **cancellation**, which arrives as `asyncio.CancelledError` inside the activity and is re-raised
  after the session row is finalised `CANCELLED` (the workflow waits for exactly that);
* **one composition root**: `configure()` builds the PostgreSQL read model, the ledger/store and the
  MCP tool client once per worker from the environment. Nothing is constructed at import time, so a
  test can point the activity at a throwaway database and a loopback MCP server.

The model is the scripted G1 policy unless `AEGIS_SESSION_LIVE_MODEL=1` (G1.6): the live branch
builds the M04 `ModelClient` over `HttpTransport` from the `AEGIS_MODEL_*` deployment settings, with
one `aegis.model_usage` row per attempt. `build_model()` is that one switch and it never falls back
silently in either direction - a live deployment that is missing its key or prices refuses to start.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any

from temporalio import activity
from temporalio.exceptions import ApplicationError

from aegis.common.ports import ModelClient
from aegis.m02_orchestrator.types import SESSION_REFUSED_ERROR, SessionOutcome, SessionRequest
from aegis.m03_agent import config as config_module
from aegis.m03_agent import session as session_module
from aegis.m03_agent.mcp import McpToolClient, ToolClient
from aegis.m03_agent.store import SessionRefused

__all__ = [
    "ACTIVITIES",
    "SESSION_REFUSED_ERROR",
    "build_model",
    "configure",
    "configure_from_env",
    "run_agent_session",
]

#: `SESSION_REFUSED_ERROR` (imported from the M02/M03 seam) is the `ApplicationError.type` of a
#: business refusal: M02 reads `details[0].code` to decide what it means; retrying can only
#: refuse again (D4, item 61 trial).

#: Records the selected model mode once per worker process (never the credential: see G1.6).
logger = logging.getLogger(__name__)

#: Set by `configure()` (the worker entry point) or by a test before it starts a worker.
_deps: session_module.SessionDeps | None = None


def _deps_or_fail() -> session_module.SessionDeps:
    if _deps is None:
        raise RuntimeError(
            "M03 is not configured: start the worker with "
            "`python -m aegis.m02_orchestrator.worker --session-module "
            "aegis.m03_agent.activities` (it reads AEGIS_PG_DSN and AEGIS_MCP_URL), or call "
            "aegis.m03_agent.activities.configure(...) first"
        )
    return _deps


def build_model(config: config_module.SessionConfig, *, dsn: str | None = None) -> ModelClient:
    """The scripted G1 policy by default; the live M04 client only when the deployment says so.

    The live branch is one provider, one model and one price pair from the environment; it refuses
    to start when anything it needs is missing (a zero or guessed price would make the campaign
    budget and the `model_usage` rows dishonest). Nothing here logs the credential.
    """
    from aegis.m03_agent.fake_policy import ScriptedLabPolicy

    if not config.live_model:
        # No database, no provider: the policy decides from the ContextBundle the session hands it
        # (`observe_context`), so the demo proves the M27 -> context -> decision path.
        logger.info(
            "model: scripted policy (AEGIS_SESSION_LIVE_MODEL is off) provider=%s model=%s",
            config.provider,
            config.model,
        )
        return ScriptedLabPolicy(provider=config.provider, model=config.model)

    from aegis.m04_model.deployment import ModelDeployment
    from aegis.m04_model.usage import PostgresUsageSink

    deployment = ModelDeployment.from_env()
    if (deployment.provider.value, deployment.model) != (config.provider, config.model):
        raise config_module.SessionConfigError(
            "the live deployment and the session config disagree: "
            f"AEGIS_MODEL_PROVIDER/AEGIS_MODEL_NAME select "
            f"{deployment.provider.value}/{deployment.model}, the session asks for "
            f"{config.provider}/{config.model} (SessionConfig.from_env reads the same variables)"
        )
    # One usage row per attempt is the deployment's ledger obligation; without a database the live
    # client would spend money and leave no record, so a missing DSN is an error, not a fallback.
    usage_dsn = dsn or config_module.dsn_from_env()
    logger.info("model: live %s", deployment.describe())
    return deployment.client(PostgresUsageSink(usage_dsn))


def configure(
    *,
    dsn: str | None = None,
    mcp_url: str | None = None,
    session_config: config_module.SessionConfig | None = None,
    model: ModelClient | None = None,
    tool_client: Callable[[], AbstractAsyncContextManager[ToolClient]] | None = None,
    deps: session_module.SessionDeps | None = None,
) -> session_module.SessionDeps:
    """Point the activity at its dependencies; tests pass the seams, a worker passes the env."""
    global _deps
    if deps is not None:
        _deps = deps
        return deps
    resolved_dsn = dsn or config_module.dsn_from_env()
    config = session_config or config_module.SessionConfig.from_env()

    resolved_model = model or build_model(config, dsn=resolved_dsn)
    if tool_client is None:
        url = mcp_url or config_module.mcp_url_from_env()

        @asynccontextmanager
        async def _client() -> Any:  # one transport session per agent session (server binding)
            client = McpToolClient(url)
            await client.connect()
            try:
                yield client
            finally:
                await client.aclose()

        resolved_tools: Callable[[], AbstractAsyncContextManager[ToolClient]] = _client
    else:
        resolved_tools = tool_client
    _deps = session_module.build_deps(
        config=config,
        dsn=resolved_dsn,
        tools=resolved_tools,
        model=resolved_model,
    )
    return _deps


def configure_from_env() -> session_module.SessionDeps:
    """The composition root `python -m aegis.m02_orchestrator.worker` runs before it starts.

    The worker hosts this module's activity; it does not know what a session needs. Reading the
    environment here keeps that knowledge in M03 and makes a misconfigured worker fail at start-up
    instead of on the first activity (see `aegis.m02_orchestrator.worker._configure_from_env`).
    """
    return configure()


def _heartbeat(stage: str, fields: Mapping[str, Any]) -> None:
    if activity.in_activity():
        activity.heartbeat({"stage": stage, **dict(fields)})


@activity.defn(name="run_agent_session")
async def run_agent_session(request: SessionRequest) -> SessionOutcome:
    """M02's session seam: one campaign cycle, hosted here (G0.1 decision).

    A `SessionRefused` is a campaign decision (budget spent, campaign not RUNNING), not a
    transport failure: it becomes a non-retryable `ApplicationError` of type `SessionRefused`
    carrying its `code`, so M02 can terminalise the campaign instead of retrying the activity.
    """
    deps = _deps_or_fail()
    try:
        run = await session_module.run_session(request, deps, beat=_heartbeat)
    except SessionRefused as refusal:
        raise ApplicationError(
            str(refusal),
            {"code": refusal.code},
            type=SESSION_REFUSED_ERROR,
            non_retryable=True,
        ) from None
    return run.outcome


#: The activities `m02_orchestrator.worker --session-module aegis.m03_agent.activities` registers.
ACTIVITIES: list[Any] = [run_agent_session]
