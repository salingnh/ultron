"""The scheduled intel refresh: `IntelSyncWorkflow`, its activity, and the Temporal schedule.

The M18 CLI can refresh NVD/EPSS/KEV, but a command is only daily if something runs it. This module
is that "something" and the **single** mechanism: a Temporal schedule on the M02 orchestrator task
queue starts `IntelSyncWorkflow` once a day; the workflow runs one `run_intel_sync` activity, which
calls the same `aegis.m18_intel.runs.recorded_refresh` the CLI calls, so the scheduled and manual
paths cannot drift.

* The activity is long (a full NVD corpus is ~30 min) and idempotent/resumable (M18's NVD
  checkpoint), so it runs with a two-hour timeout and one retry; each attempt opens its own
  `intel_sync_run` row, so a retry is a second auditable attempt, not an overwrite.
* A failed refresh is an **activity result with `ok: false`** as well as a `FAILED` ledger row:
  the workflow only returns it and Temporal shows the run, while `GET /intel/status` shows the
  failed leg to an operator who does not read the Temporal UI.
* `install` uses `create_schedule`, and updates an existing schedule in place (deploying a new
  version must not fail because the schedule already exists). Overlap is `SKIP`: one refresh at a
  time, never two NVD syncs against the same checkpoint.

Usage (from `make intel-schedule` / documented in the report):
    AEGIS_PG_DSN=... python -m aegis.m02_orchestrator.intel install --address 127.0.0.1:7233
    python -m aegis.m02_orchestrator.intel show
    python -m aegis.m02_orchestrator.intel run-now
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Literal, cast

from temporalio import activity, workflow
from temporalio.client import (
    Client,
    Schedule,
    ScheduleActionStartWorkflow,
    ScheduleAlreadyRunningError,
    ScheduleOverlapPolicy,
    SchedulePolicy,
    ScheduleSpec,
    ScheduleState,
    ScheduleUpdate,
)
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from aegis.m02_orchestrator.types import ORCHESTRATOR_QUEUE

__all__ = [
    "INTEL_CRON",
    "INTEL_SCHEDULE_ID",
    "INTEL_TIME_ZONE",
    "IntelSyncRequest",
    "IntelSyncWorkflow",
    "build_schedule",
    "install_schedule",
    "main",
    "run_intel_sync",
]

#: One schedule on one queue, named so an operator can find it in the Temporal UI.
INTEL_SCHEDULE_ID = "intel-sync-daily"
#: 03:00 UTC daily: after the NVD day boundary and before a working day starts in UTC+7.
INTEL_CRON = "0 3 * * *"
INTEL_TIME_ZONE = "UTC"
NVD_MODES = ("auto", "full", "incremental")


@dataclass(frozen=True, slots=True)
class IntelSyncRequest:
    """One scheduled attempt; `schedule` is the schedule, `manual` a `run-now`/activity test."""

    trigger: str = "schedule"


def _options() -> Any:
    """The M18 refresh options of a scheduled run (feed sources from the environment)."""
    from aegis.m18_intel.refresh import RefreshOptions

    mode = os.environ.get("AEGIS_INTEL_NVD_MODE", "auto").strip() or "auto"
    if mode not in NVD_MODES:
        raise ValueError(f"AEGIS_INTEL_NVD_MODE={mode!r} is not one of {', '.join(NVD_MODES)}")
    return RefreshOptions(
        nvd_mode=cast(Literal["auto", "full", "incremental"], mode),
        epss_source=os.environ.get("AEGIS_EPSS_SOURCE"),
        epss_version=os.environ.get("AEGIS_EPSS_VERSION"),
        source_file=os.environ.get("AEGIS_KEV_SOURCE_FILE"),
        distro_source_file=os.environ.get("AEGIS_DISTRO_SOURCE_FILE"),
    )


@activity.defn(name="run_intel_sync")
async def run_intel_sync(request: IntelSyncRequest) -> dict[str, Any]:
    """Refresh every feed and persist the attempt; the CLI's offline path is not used here."""
    from aegis.m18_intel.runs import recorded_refresh

    return await asyncio.to_thread(
        recorded_refresh, request.trigger, _options(), require_database=True
    )


@workflow.defn(name="IntelSyncWorkflow")
class IntelSyncWorkflow:
    """One daily refresh; a failure is returned and recorded, never retried into a loop."""

    @workflow.run
    async def run(self, request: IntelSyncRequest) -> dict[str, Any]:
        return await workflow.execute_activity(
            run_intel_sync,
            request,
            start_to_close_timeout=timedelta(hours=2),
            retry_policy=RetryPolicy(maximum_attempts=2),
        )


def build_schedule(cron: str = INTEL_CRON) -> Schedule:
    """The one schedule document; `install` and the tests inspect the same object."""
    return Schedule(
        action=ScheduleActionStartWorkflow(
            IntelSyncWorkflow.run,
            IntelSyncRequest(trigger="schedule"),
            id=f"{INTEL_SCHEDULE_ID}-workflow",
            task_queue=ORCHESTRATOR_QUEUE,
        ),
        spec=ScheduleSpec(cron_expressions=[cron], time_zone_name=INTEL_TIME_ZONE),
        policy=SchedulePolicy(overlap=ScheduleOverlapPolicy.SKIP),
        state=ScheduleState(note="M18 intel refresh (NVD, EPSS when configured, KEV)"),
    )


async def install_schedule(
    client: Client, *, cron: str = INTEL_CRON, schedule_id: str = INTEL_SCHEDULE_ID
) -> Schedule:
    """Create the schedule, or update it in place when this deployment already has it."""
    schedule = build_schedule(cron)
    try:
        await client.create_schedule(schedule_id, schedule)
    except ScheduleAlreadyRunningError:
        handle = client.get_schedule_handle(schedule_id)
        await handle.update(lambda _: ScheduleUpdate(schedule=schedule))
    return schedule


async def _install(args: argparse.Namespace) -> None:
    client = await Client.connect(args.address, namespace=args.namespace)
    schedule = await install_schedule(client, cron=args.cron, schedule_id=args.schedule_id)
    print(
        json.dumps(
            {
                "schedule_id": args.schedule_id,
                "cron": args.cron,
                "time_zone": INTEL_TIME_ZONE,
                "workflow": "IntelSyncWorkflow",
                "task_queue": ORCHESTRATOR_QUEUE,
                "overlap": schedule.policy.overlap.name,
                "installed": True,
            },
            indent=2,
        )
    )


async def _show(args: argparse.Namespace) -> None:
    client = await Client.connect(args.address, namespace=args.namespace)
    from google.protobuf.json_format import MessageToDict

    description = await client.get_schedule_handle(args.schedule_id).describe()
    print(json.dumps({"schedule": MessageToDict(description.raw_description)}, indent=2))


async def _run_now(args: argparse.Namespace) -> None:
    client = await Client.connect(args.address, namespace=args.namespace)
    await client.get_schedule_handle(args.schedule_id).trigger()
    print(json.dumps({"schedule_id": args.schedule_id, "triggered": True}, indent=2))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m aegis.m02_orchestrator.intel")
    parser.add_argument("--address", default="127.0.0.1:7233")
    parser.add_argument("--namespace", default="default")
    parser.add_argument("--schedule-id", default=INTEL_SCHEDULE_ID)
    sub = parser.add_subparsers(dest="command", required=True)
    install = sub.add_parser("install", help="create or update the daily intel refresh schedule")
    install.add_argument(
        "--cron", default=INTEL_CRON, help=f"cron expression (default {INTEL_CRON})"
    )
    install.add_argument("--schedule-id", default=INTEL_SCHEDULE_ID)
    show = sub.add_parser("show", help="describe the installed schedule")
    show.add_argument("--schedule-id", default=INTEL_SCHEDULE_ID)
    run_now = sub.add_parser("run-now", help="trigger the schedule once")
    run_now.add_argument("--schedule-id", default=INTEL_SCHEDULE_ID)
    args = parser.parse_args(argv)
    if args.command == "install":
        asyncio.run(_install(args))
    elif args.command == "show":
        asyncio.run(_show(args))
    else:
        asyncio.run(_run_now(args))


if __name__ == "__main__":  # pragma: no cover - process entry point
    main()
