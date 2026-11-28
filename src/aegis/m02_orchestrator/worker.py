"""Temporal worker of M02 (and, once G1.2c lands, of the M03 session activity).

Two task queues, as the interface fixes them:

* `aegis-orchestrator`: `CampaignWorkflow` plus the M02 activities (load/dispatch/cancel/finish);
* `aegis-agent`: the session activities. `run_agent_session` belongs to M03 (G1.2c); the worker
  fails loudly when no session module is available instead of running campaigns that can never
  start a session. `--without-sessions` is the explicit opt-out for a dispatch-only deployment.

Usage:
    AEGIS_PG_DSN=... python -m aegis.m02_orchestrator.worker --address 127.0.0.1:7233 \
        --session-module aegis.m03_agent.activities
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
from typing import Any

from temporalio.client import Client
from temporalio.worker import Worker

from .activities import ACTIVITIES, configure
from .db import dsn_from_env
from .intel import IntelSyncWorkflow, run_intel_sync
from .types import AGENT_QUEUE, ORCHESTRATOR_QUEUE
from .workflow import CampaignWorkflow

__all__ = ["main", "run_worker"]

DEFAULT_SESSION_MODULE = "aegis.m03_agent.activities"


def _session_module(module_name: str) -> Any:
    try:
        return importlib.import_module(module_name)
    except ImportError as error:
        raise SystemExit(
            f"cannot import the session activity module {module_name!r}: {error}. "
            "G1.2c provides it; pass --without-sessions for a dispatch-only worker."
        ) from error


def _activities_from(module: Any, module_name: str) -> list[object]:
    activities = getattr(module, "ACTIVITIES", None)
    if activities is None:
        raise SystemExit(
            f"{module_name!r} must expose an ACTIVITIES list (the activities to register)"
        )
    return list(activities)


def _configure_from_env(module: Any, module_name: str) -> None:
    """Run the session module's composition root before any activity can be scheduled.

    The activity module owns its dependencies (M03 builds the PostgreSQL read model, the ledger and
    the MCP client from the environment); the worker only hosts it. A module without the hook is
    loaded as-is - the tests' scripted activity module has no environment of its own.
    """
    hook = getattr(module, "configure_from_env", None)
    if hook is None:
        return
    try:
        hook()
    except Exception as error:  # fail loudly: a worker that cannot configure must not start
        raise SystemExit(f"cannot configure the session module {module_name!r}: {error}") from error


async def run_worker(
    *,
    address: str,
    namespace: str,
    dsn: str | None,
    session_modules: list[str],
    run_without_sessions: bool,
) -> None:
    configure(dsn=dsn or dsn_from_env())
    client = await Client.connect(address, namespace=namespace)
    orchestrator = Worker(
        client,
        task_queue=ORCHESTRATOR_QUEUE,
        workflows=[CampaignWorkflow, IntelSyncWorkflow],
        activities=[*ACTIVITIES, run_intel_sync],
    )
    workers = [orchestrator.run()]
    if session_modules:
        session_activities: list[object] = []
        for module_name in session_modules:
            module = _session_module(module_name)
            _configure_from_env(module, module_name)
            session_activities.extend(_activities_from(module, module_name))
        workers.append(
            __import__("temporalio.worker", fromlist=["Worker"])
            .Worker(client, task_queue=AGENT_QUEUE, activities=session_activities)
            .run()
        )
    elif not run_without_sessions:
        raise SystemExit(
            "no session activity module given: pass --session-module (G1.2c) or --without-sessions"
        )
    await asyncio.gather(*workers)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="M02 Temporal worker")
    parser.add_argument("--address", default="127.0.0.1:7233")
    parser.add_argument("--namespace", default="default")
    parser.add_argument("--dsn", default=None, help="PostgreSQL DSN (default: $AEGIS_PG_DSN)")
    parser.add_argument(
        "--session-module",
        action="append",
        default=None,
        help=f"module exposing ACTIVITIES for {AGENT_QUEUE} (default: {DEFAULT_SESSION_MODULE})",
    )
    parser.add_argument("--without-sessions", action="store_true")
    args = parser.parse_args(argv)
    session_modules = args.session_module
    if session_modules is None:
        session_modules = [] if args.without_sessions else [DEFAULT_SESSION_MODULE]
    asyncio.run(
        run_worker(
            address=args.address,
            namespace=args.namespace,
            dsn=args.dsn,
            session_modules=session_modules,
            run_without_sessions=args.without_sessions,
        )
    )


if __name__ == "__main__":  # pragma: no cover - process entry point
    main()
