"""The M06 runner loop (G1.5c): plan a job from its own row, and the order of a tick.

The loop is the process a deployment starts (`python -m aegis.m06_runner`). Its two jobs are
reading a runnable plan out of the database - never a second resolution of the manifest - and
adopting what this runner already started before it takes new work. Both are checked here against
a migrated database; the containers themselves are the `podman` suites' business.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from psycopg.rows import dict_row

from aegis.contracts_gen.capability.approved_task_v2_schema import ApprovedTask
from aegis.m05_registry.manifest import parse_document
from aegis.m05_registry.registry import PostgresManifestRegistry
from aegis.m06_runner import loop
from aegis.m06_runner.lifecycle import JobClaim
from aegis.m06_runner.values import text
from tests.db_support import migrated_database, requires_postgres, seed_campaign
from tests.m02_support import accept_job, run_job, scheduler_for, service

pytestmark = requires_postgres


@pytest.fixture()
def database() -> Iterator[str]:
    with migrated_database() as dsn:
        yield dsn


def _validating(dsn: str) -> tuple[str, str]:
    campaign = seed_campaign(dsn)
    with service(dsn) as jobs:
        job_id = accept_job(jobs, campaign)
    with scheduler_for(dsn) as scheduler:
        assert scheduler.dispatch(campaign.campaign_id).claimed == (job_id,)
    return campaign.campaign_id, job_id


def _registry(dsn: str) -> PostgresManifestRegistry:
    """The registry reads its own rows positionally, exactly as the loop builds it in `run()`."""
    import psycopg

    return PostgresManifestRegistry(lambda: psycopg.connect(dsn))


def dict_connection(dsn: str) -> Any:
    connection = __import__("psycopg").connect(dsn, autocommit=True, row_factory=dict_row)
    connection.execute("SET search_path = aegis, public")
    return connection


def test_a_plan_comes_from_the_job_row_and_the_pinned_manifest(database: str) -> None:
    _, job_id = _validating(database)
    with dict_connection(database) as connection:
        plan = loop.plan_for(connection, job_id, _registry(database))
        row = connection.execute(
            "SELECT approved_task FROM scan_job WHERE job_id = %s", (job_id,)
        ).fetchone()
    assert row is not None
    approved = ApprovedTask.model_validate(row["approved_task"])
    assert plan.job_id == job_id
    assert plan.task == approved
    digest = text(approved.manifest_sha256)
    assert hashlib.sha256(plan.manifest_bytes or b"").hexdigest() == digest
    assert dict(plan.input) == dict(approved.input)
    document = parse_document(plan.manifest_bytes or b"")
    assert document["spec"]["capability"] == text(approved.capability)
    assert plan.task_body is not None and "signature" in plan.task_body


def test_a_job_that_did_not_come_through_m05_has_no_plan(database: str) -> None:
    with dict_connection(database) as connection:
        with pytest.raises(LookupError):
            loop.plan_for(connection, str(uuid.uuid4()), _registry(database))


def test_the_queue_and_the_fence_of_a_job(database: str) -> None:
    _, job_id = _validating(database)
    with dict_connection(database) as connection:
        assert loop.statuses_named(connection, ("VALIDATING",)) == [job_id]
        assert loop.statuses_named(connection, ("RUNNING",)) == []
        # `VALIDATING` is M06's to claim, not to resume: no fence is handed out for it.
        assert loop.claim_of(connection, job_id) is None
        run_job(database, job_id)
        # A job in flight keeps its fence: the runner adopts it with the same (generation, attempt).
        assert loop.claim_of(connection, job_id) == JobClaim(job_id=job_id, generation=1, attempt=1)


def test_a_tick_adopts_this_runners_job_before_it_takes_new_work(database: str) -> None:
    """Order matters: the adopted job keeps one container, a new claim would start a second."""
    _, job_id = _validating(database)
    run_job(database, job_id)
    calls: list[tuple[str, str]] = []
    runner = _Runner(job_id, calls)
    tick = loop.run_once(
        _config(database),
        podman=_Podman(owned=(job_id,)),  # type: ignore[arg-type]
        job_runner=runner,  # type: ignore[arg-type]
        registry=_registry(database),
        log=_quiet,
    )
    assert calls == [("resume", job_id)]
    assert tick.resumed == (job_id,)
    assert tick.ran == ()


def test_a_tick_runs_a_queued_job_it_does_not_own(database: str) -> None:
    _, job_id = _validating(database)
    calls: list[tuple[str, str]] = []
    runner = _Runner(job_id, calls)
    tick = loop.run_once(
        _config(database),
        podman=_Podman(),  # type: ignore[arg-type]
        job_runner=runner,  # type: ignore[arg-type]
        registry=_registry(database),
        log=_quiet,
    )
    assert calls == [("execute", job_id)]
    assert tick.ran == (job_id,)
    assert tick.resumed == ()


def test_a_tick_with_nothing_to_do_changes_nothing(database: str) -> None:
    calls: list[tuple[str, str]] = []
    tick = loop.run_once(
        _config(database),
        podman=_Podman(),  # type: ignore[arg-type]
        job_runner=_Runner("", calls),  # type: ignore[arg-type]
        registry=_registry(database),
        log=_quiet,
    )
    assert tick == loop.LoopTick()
    assert calls == []


def _quiet(message: str) -> None:
    del message


def _config(dsn: str) -> loop.LoopConfig:
    return loop.LoopConfig(dsn=dsn, base_dir=Path("/tmp/aegis-m06-loop-test"), service_token="t")


class _Podman:
    def __init__(self, *, owned: tuple[str, ...] = (), live: tuple[str, ...] = ()) -> None:
        self._owned = owned
        self._live = set(live)
        self.reconciled: list[tuple[str, ...]] = []

    def reconcile(self, live: Any) -> Any:
        self.reconciled.append(tuple(live))
        return _Report()

    def owned_jobs(self) -> tuple[str, ...]:
        return self._owned

    def started(self, job_id: str) -> bool:
        return job_id in self._live


class _Report:
    removed: tuple[str, ...] = ()


class _Runner:
    def __init__(self, job_id: str, calls: list[tuple[str, str]]) -> None:
        self._job_id = job_id
        self._calls = calls

    def execute(self, plan: Any) -> Any:
        self._calls.append(("execute", plan.job_id))
        return _Outcome(plan.job_id, "succeeded")

    def resume(self, plan: Any, claim: Any) -> Any:
        assert claim == JobClaim(job_id=self._job_id, generation=1, attempt=1)
        self._calls.append(("resume", plan.job_id))
        return _Outcome(plan.job_id, "succeeded")


class _Outcome:
    def __init__(self, job_id: str, status: str) -> None:
        self.job_id = job_id
        self.status = status
        self.error = None
        self.errors: list[dict[str, Any]] = []
        self.receipt = None
