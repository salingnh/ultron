"""The M06 runner process: claim `VALIDATING` jobs, run them, record the one terminal result.

M02 leaves a dispatched job in `VALIDATING`; M06 is the component that runs it and the only writer
of `SUCCEEDED`/`FAILED`/`CANCELLED` (`lifecycle.py`). Until now that was a library plus tests, so a
deployment had no process to start: this module is the missing composition root (G1.5c).

One loop, one host, one runner directory (`LoopConfig.base_dir`), in this order per tick:

1. **reconcile** - adopt the containers of jobs that are still running and remove the ones whose
   job is terminal or gone (`PodmanRunner.reconcile`). The database is the truth: a container of a
   finished job is never left behind, and the output directory stays for the collector.
2. **resume** - a job this runner already started (its container carries this runner's owner label)
   but whose process died (`SIGKILL`, OOM) is adopted, waited for, collected and submitted exactly
   once (`JobRunner.resume`). This is the G1.5c recovery evidence, not a special case.
3. **run** - `VALIDATING` jobs, oldest first: `JobRunner.execute` claims each one (`VALIDATING ->
   DISPATCHED`) and terminalizes it. Sequential by design: the campaign's `max_parallel_jobs` and
   the host's capacity are M02's and the deployment's business, and one runner that starts every
   container at once would only move the queue.

Every dependency comes from the environment, and a missing one aborts start-up instead of surfacing
as a failed job later: `AEGIS_PG_DSN`, `AEGIS_API_URL` (the ingestion endpoint lives on the API),
`AEGIS_SERVICE_TOKEN` (the internal service token), the S3 settings of `S3EvidenceStore` and,
optionally, `AEGIS_M06_LAB_PROFILE` (the authorized lab, `lab.py`) and `AEGIS_M06_BROKER_IMAGE`.
"""

from __future__ import annotations

import argparse
import os
import signal as signal_module
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import FrameType
from typing import Any

import psycopg

from aegis.common.repo import repository_root
from aegis.contracts_gen.capability.approved_task_v2_schema import ApprovedTask
from aegis.contracts_gen.capability.provider_manifest_v2_schema import ProviderManifest
from aegis.contracts_gen.common.ids_v2_schema import Classification
from aegis.m05_registry.manifest import ManifestRecord
from aegis.m05_registry.registry import PostgresManifestRegistry
from aegis.m05_registry.signing import KeyRing
from aegis.m06_runner import envelope as envelopes
from aegis.m06_runner.job import JobOutcome, JobPlan, JobRunner
from aegis.m06_runner.lab import LabProfile
from aegis.m06_runner.lifecycle import TERMINAL_DB_STATUSES, JobClaim, JobLifecycle, connect
from aegis.m06_runner.podman import PodmanRunner
from aegis.m28_evidence.catalog import EvidenceCatalog
from aegis.m28_evidence.store import S3EvidenceStore

__all__ = [
    "DSN_ENV",
    "LoopConfig",
    "LoopTick",
    "RUNNABLE_STATUSES",
    "SERVICE_TOKEN_ENV",
    "ServiceTokenMissing",
    "api_url_from_env",
    "main",
    "plan_for",
    "run",
    "run_once",
    "statuses_named",
]

DSN_ENV = "AEGIS_PG_DSN"
API_URL_ENV = "AEGIS_API_URL"
SERVICE_TOKEN_ENV = "AEGIS_SERVICE_TOKEN"
BROKER_IMAGE_ENV = "AEGIS_M06_BROKER_IMAGE"
BASE_DIR_ENV = "AEGIS_M06_BASE_DIR"
POLL_ENV = "AEGIS_M06_POLL_SECONDS"
INGESTION_PATH = "/api/v2/ingestion/results"
#: A job whose container may still exist on this host: the runner reconciles and may adopt it.
RUNNABLE_STATUSES = ("DISPATCHED", "RUNNING", "COLLECTING")
DEFAULT_API_URL = "http://127.0.0.1:8000"
DEFAULT_POLL_SECONDS = 1.0
TERMINAL_STATUSES = tuple(sorted(TERMINAL_DB_STATUSES))


class ServiceTokenMissing(RuntimeError):
    """The ingestion endpoint needs the internal service token; without it M06 cannot report."""


@dataclass(frozen=True, slots=True)
class LoopConfig:
    """Everything one runner process needs; built from the environment in `from_env`."""

    dsn: str
    base_dir: Path
    api_url: str = DEFAULT_API_URL
    service_token: str = ""
    broker_image: str | None = None
    lab: LabProfile | None = None
    poll_seconds: float = DEFAULT_POLL_SECONDS
    platform_cidrs: tuple[str, ...] = ()
    parser_python_path: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> LoopConfig:
        source = os.environ if env is None else env
        dsn = source.get(DSN_ENV, "").strip()
        if not dsn:
            raise SystemExit(f"{DSN_ENV} is required: the runner records job state in PostgreSQL")
        base_dir = source.get(BASE_DIR_ENV, "").strip()
        poll = source.get(POLL_ENV, "").strip()
        return cls(
            dsn=dsn,
            base_dir=Path(base_dir) if base_dir else repository_root() / ".local" / "m06",
            api_url=source.get(API_URL_ENV, DEFAULT_API_URL).rstrip("/"),
            service_token=source.get(SERVICE_TOKEN_ENV, "").strip(),
            broker_image=source.get(BROKER_IMAGE_ENV) or None,
            lab=LabProfile.from_env(source),
            poll_seconds=float(poll) if poll else DEFAULT_POLL_SECONDS,
            platform_cidrs=tuple(
                item.strip()
                for item in source.get("AEGIS_M06_PLATFORM_CIDRS", "").split(",")
                if item.strip()
            ),
            parser_python_path=(str(repository_root()),),
        )


@dataclass(frozen=True, slots=True)
class LoopTick:
    """What one tick did, for the log and the recovery evidence."""

    resumed: tuple[str, ...] = ()
    ran: tuple[str, ...] = ()
    failed: tuple[str, ...] = ()
    reconciled_removed: tuple[str, ...] = ()


def _field(row: Mapping[str, Any] | tuple[Any, ...], name: str, index: int) -> Any:
    """One column of a row: by name on a dict-row connection, by position on a tuple one.

    `lifecycle.connect` hands out tuple rows (its own statements read positionally); the tests and
    the demo read with `dict_row`. Reading both keeps one implementation of the plan query.
    """
    return row[name] if isinstance(row, Mapping) else row[index]


def plan_for(
    conn: psycopg.Connection[Any], job_id: str, registry: PostgresManifestRegistry
) -> JobPlan:
    """The plan of one job from its own row: signed task, pinned manifest, merged input.

    Everything comes from `scan_job` and the immutable manifest registry, so a resumed job is the
    same job: no re-resolution and no "latest manifest" (interfaces §2, OI-12). A row that did not
    come through M05 (fixtures, history) has no `approved_task` and cannot be run.
    """
    row = conn.execute(
        """
        SELECT campaign_id, manifest_sha256, input, approved_task
          FROM scan_job
         WHERE job_id = %s
        """,
        (job_id,),
    ).fetchone()
    if row is None:
        raise LookupError(f"job {job_id} does not exist")
    campaign_id = _field(row, "campaign_id", 0)
    manifest_sha256 = _field(row, "manifest_sha256", 1)
    input_values = _field(row, "input", 2)
    approved = _field(row, "approved_task", 3)
    if approved is None:
        raise ValueError(f"job {job_id} has no approved task (it did not come through M05)")
    record: ManifestRecord = registry.get(str(manifest_sha256 or approved.get("manifest_sha256")))
    denylist = _target_denylist(conn, str(campaign_id))
    return JobPlan(
        job_id=job_id,
        task=ApprovedTask.model_validate(approved),
        manifest=ProviderManifest.model_validate(dict(record.document)),
        input=dict(input_values or {}),
        manifest_bytes=record.raw,
        task_body=dict(approved),
        target_denylist=denylist,
        classification=_classification(record.document),
    )


def _classification(document: Mapping[str, Any]) -> Classification:
    """The job's classification from the manifest; a provider that states none is INTERNAL."""
    raw = document.get("spec", {}).get("classification") if isinstance(document, Mapping) else None
    try:
        return Classification(str(raw)) if raw else Classification.INTERNAL
    except ValueError:
        return Classification.INTERNAL


def _target_denylist(conn: psycopg.Connection[Any], campaign_id: str) -> tuple[str, ...]:
    row = conn.execute(
        """
        SELECT p.policy -> 'target_denylist' AS denylist
          FROM campaign c JOIN policy_snapshot p
            ON p.policy_version = c.current_policy_version
         WHERE c.campaign_id = %s
        """,
        (campaign_id,),
    ).fetchone()
    values = (_field(row, "denylist", 0) if row is not None else None) or []
    return tuple(str(item) for item in values)


def statuses_named(conn: psycopg.Connection[Any], statuses: Sequence[str]) -> list[str]:
    """Job ids at one of these statuses, oldest first (a queue, not a set)."""
    rows = conn.execute(
        "SELECT job_id FROM scan_job WHERE status = ANY(%s) ORDER BY created_at, job_id",
        (list(statuses),),
    ).fetchall()
    return [str(_field(row, "job_id", 0)) for row in rows]


def claim_of(conn: psycopg.Connection[Any], job_id: str) -> JobClaim | None:
    """The fence of a job already in flight, or None when it is not claimable any more."""
    row = conn.execute(
        "SELECT generation, attempt FROM scan_job WHERE job_id = %s AND status = ANY(%s)",
        (job_id, list(RUNNABLE_STATUSES)),
    ).fetchone()
    if row is None:
        return None
    return JobClaim(
        job_id=job_id,
        generation=int(_field(row, "generation", 0)),
        attempt=int(_field(row, "attempt", 1)),
    )


def runner_for(config: LoopConfig, lifecycle: JobLifecycle) -> tuple[PodmanRunner, JobRunner]:
    """The one composition root of this process: podman, evidence store, ingestion, parsers."""
    if not config.service_token:
        raise ServiceTokenMissing(
            f"{SERVICE_TOKEN_ENV} is required: M06 submits envelopes to {config.api_url}"
            f"{INGESTION_PATH} with the internal service token"
        )
    podman = PodmanRunner(
        base_dir=config.base_dir,
        broker_image=config.broker_image,
        lab=config.lab,
    )
    job_runner = JobRunner(
        podman,
        S3EvidenceStore.from_env(),
        key_ring=KeyRing.from_env(),
        ingestion=envelopes.HttpIngestionClient(config.api_url, config.service_token),
        extra_parser_prefixes=("adapters.",),
        extra_parser_python_path=list(config.parser_python_path),
        lifecycle=lifecycle,
        catalog=EvidenceCatalog.from_dsn(config.dsn),
    )
    return podman, job_runner


def run_once(
    config: LoopConfig,
    *,
    podman: PodmanRunner,
    job_runner: JobRunner,
    registry: PostgresManifestRegistry,
    reconcile: bool = True,
    log: Callable[[str], None] = print,
) -> LoopTick:
    """One tick of the loop: reconcile, resume what this runner already started, run the queue."""
    with connect(config.dsn) as conn:
        live = statuses_named(conn, RUNNABLE_STATUSES)
        removed: tuple[str, ...] = ()
        if reconcile:
            report = podman.reconcile(live)
            removed = report.removed
            if report.removed:
                log(f"reconcile: removed containers of finished jobs {list(report.removed)}")

        # A job this runner already began: its container is ours (owner label) or its job directory
        # is (killed before the container existed). Anything else live belongs to another runner.
        ours = set(podman.owned_jobs()) | {job_id for job_id in live if podman.started(job_id)}
        resumed: list[str] = []
        for job_id in sorted(set(live) & ours):
            claim = claim_of(conn, job_id)
            if claim is None:
                continue
            plan = plan_for(conn, job_id, registry)
            log(f"resume: job {job_id} (adopting the container this runner already started)")
            outcome = job_runner.resume(plan, claim)
            resumed.append(job_id)
            _log_outcome(job_id, outcome, log)

        ran: list[str] = []
        failed: list[str] = []
        for job_id in statuses_named(conn, ("VALIDATING",)):
            if job_id in resumed:
                continue
            try:
                plan = plan_for(conn, job_id, registry)
            except (LookupError, ValueError) as error:
                log(f"skip: job {job_id} cannot be planned: {error}")
                failed.append(job_id)
                continue
            outcome = job_runner.execute(plan)
            if outcome.status == "skipped":
                continue
            ran.append(job_id)
            _log_outcome(job_id, outcome, log)
            if outcome.status in ("failed", "cancelled"):
                failed.append(job_id)
    return LoopTick(
        resumed=tuple(resumed),
        ran=tuple(ran),
        failed=tuple(failed),
        reconciled_removed=removed,
    )


def _log_outcome(job_id: str, outcome: JobOutcome, log: Callable[[str], None]) -> None:
    detail = outcome.error or ""
    if outcome.receipt is not None:
        detail = f"accepted={outcome.receipt.accepted} duplicate={outcome.receipt.duplicate}"
    log(f"job {job_id}: {outcome.status} {detail}".rstrip())


def run(config: LoopConfig, *, once: bool = False, ticks: int | None = None) -> int:
    """The loop; `once`/`ticks` exist for the tests and the demo, never for a service."""
    lifecycle = JobLifecycle.from_dsn(config.dsn)
    registry = PostgresManifestRegistry(lambda: psycopg.connect(config.dsn))
    podman, job_runner = runner_for(config, lifecycle)
    stopping = {"asked": False}

    def _stop(signum: int, frame: FrameType | None) -> None:
        del signum, frame
        stopping["asked"] = True

    previous = signal_module.signal(signal_module.SIGTERM, _stop)
    completed = 0
    try:
        while not stopping["asked"]:
            # The first tick always reconciles: a container of a job that ended while this process
            # was down (or a job another runner finished) must not stay on the host. Later ticks
            # only need it when a job is live.
            with connect(config.dsn) as conn:
                live = statuses_named(conn, RUNNABLE_STATUSES)
            tick = run_once(
                config,
                podman=podman,
                job_runner=job_runner,
                registry=registry,
                reconcile=completed == 0 or bool(live),
            )
            completed += 1
            if once or (ticks is not None and completed >= ticks):
                return 0
            if not (tick.ran or tick.resumed):
                _sleep(config.poll_seconds, stopping)
        return 0
    finally:
        signal_module.signal(signal_module.SIGTERM, previous)


def _sleep(seconds: float, stopping: Mapping[str, bool]) -> None:
    """Sleep in short steps so SIGTERM is acted on promptly (a job in flight is not interrupted)."""
    deadline = seconds
    while deadline > 0 and not stopping["asked"]:
        step = min(0.2, deadline)
        time.sleep(step)
        deadline -= step


def api_url_from_env(env: Mapping[str, str] | None = None) -> str:
    source = os.environ if env is None else env
    return source.get(API_URL_ENV, DEFAULT_API_URL).rstrip("/")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="M06 runner loop (claim, run, collect, submit)")
    parser.add_argument("--once", action="store_true", help="one tick, then exit (demo/tests)")
    parser.add_argument("--ticks", type=int, default=None, help="stop after N ticks")
    parser.add_argument("--poll-seconds", type=float, default=None)
    parser.add_argument(
        "--base-dir", default=None, help="runner directory (default: env or .local)"
    )
    args = parser.parse_args(argv)
    config = LoopConfig.from_env()
    if args.base_dir or args.poll_seconds is not None:
        config = LoopConfig(
            dsn=config.dsn,
            base_dir=Path(args.base_dir) if args.base_dir else config.base_dir,
            api_url=config.api_url,
            service_token=config.service_token,
            broker_image=config.broker_image,
            lab=config.lab,
            poll_seconds=args.poll_seconds
            if args.poll_seconds is not None
            else config.poll_seconds,
            platform_cidrs=config.platform_cidrs,
            parser_python_path=config.parser_python_path,
        )
    return run(config, once=args.once, ticks=args.ticks)


if __name__ == "__main__":  # pragma: no cover - process entry point
    sys.exit(main())
