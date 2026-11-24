"""M02 dispatcher process: outbox events -> signals, campaign rows -> start/signals.

Both loops are idempotent and safe to run beside a second copy: the outbox lease has a fencing
token, and the campaign watcher only signals the current status of a row.

Usage:
    AEGIS_PG_DSN=... python -m aegis.m02_orchestrator.dispatcher --address 127.0.0.1:7233
"""

from __future__ import annotations

import argparse
import asyncio

from temporalio.client import Client

from .campaign_state import CampaignStateWatcher
from .db import connect
from .outbox import OutboxDispatcher
from .signals import TemporalSignals

__all__ = ["main", "run"]


async def run(
    *,
    address: str,
    namespace: str,
    interval_seconds: float = 1.0,
    once: bool = False,
) -> None:
    client = await Client.connect(address, namespace=namespace)
    signals = TemporalSignals(client)
    dispatcher = OutboxDispatcher(connect, signals)
    watcher = CampaignStateWatcher(connect, signals)
    while True:
        await watcher.run_once()
        outcome = await dispatcher.run_once()
        if outcome.error is not None:
            print(f"m02 dispatch error: {outcome.error}", flush=True)
        if once:
            return
        await asyncio.sleep(interval_seconds)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="M02 outbox/campaign dispatcher")
    parser.add_argument("--address", default="127.0.0.1:7233")
    parser.add_argument("--namespace", default="default")
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    asyncio.run(
        run(
            address=args.address,
            namespace=args.namespace,
            interval_seconds=args.interval,
            once=args.once,
        )
    )


if __name__ == "__main__":  # pragma: no cover - process entry point
    main()
