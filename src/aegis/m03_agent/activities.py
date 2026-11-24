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

The model is the scripted G1 policy unless `AEGIS_SESSION_LIVE_MODEL=1` (OD-2 is still open, so the
live branch is reachable only by explicit configuration) - `build_model()` is that one switch.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any

from temporalio import activity

from aegis.common.ports import ModelClient
from aegis.m02_orchestrator.types import SessionOutcome, SessionRequest
from aegis.m03_agent import config as config_module
from aegis.m03_agent import session as session_module
from aegis.m03_agent.mcp import McpToolClient, ToolClient

__all__ = ["ACTIVITIES", "build_model", "configure", "run_agent_session"]

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


def build_model(config: config_module.SessionConfig) -> ModelClient:
    """The scripted G1 policy by default; the live M04 client only when the deployment says so."""
    from aegis.m03_agent.fake_policy import ScriptedLabPolicy

    if not config.live_model:
        # No database, no provider: the policy decides from the ContextBundle the session hands it
        # (`observe_context`), so the demo proves the M27 -> context -> decision path.
        return ScriptedLabPolicy(provider=config.provider, model=config.model)
    # The live branch needs OD-2 (provider, endpoint, key, price table) and must never run by
    # accident in the gate, so it refuses loudly instead of guessing a configuration.
    raise config_module.SessionConfigError(
        "AEGIS_SESSION_LIVE_MODEL=1 needs the OD-2 provider endpoint, credentials and price table; "
        "G1 ships the scripted policy only (card G1.2c: 'Fake model in G1')"
    )


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

    resolved_model = model or build_model(config)
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


def _heartbeat(stage: str, fields: Mapping[str, Any]) -> None:
    if activity.in_activity():
        activity.heartbeat({"stage": stage, **dict(fields)})


@activity.defn(name="run_agent_session")
async def run_agent_session(request: SessionRequest) -> SessionOutcome:
    """M02's session seam: one campaign cycle, hosted here (G0.1 decision)."""
    deps = _deps_or_fail()
    run = await session_module.run_session(request, deps, beat=_heartbeat)
    return run.outcome


#: The activities `m02_orchestrator.worker --session-module aegis.m03_agent.activities` registers.
ACTIVITIES: list[Any] = [run_agent_session]
