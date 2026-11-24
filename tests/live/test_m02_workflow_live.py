"""Live CampaignWorkflow tests against a throwaway Temporal dev server and PostgreSQL.

Not part of the default gate (tests/conftest.py ignores `tests/live` unless
`AEGIS_TEMPORAL_TARGET` is set): the CI `python` job has no Temporal server. Run it with
`scripts/temporal/run-live.sh`, which starts both throwaways and writes the replay fixture the
default gate uses.

The scenarios prove the card's Temporal acceptance on a real server: dispatch order and
dependency, pause/resume through the campaign watcher, cancel propagation into a running session,
Continue-As-New, and a deterministic replay of a real history.
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from temporalio.client import Client, WorkflowHandle
from temporalio.worker import Replayer, Worker

from aegis.m02_orchestrator import db
from aegis.m02_orchestrator.activities import ACTIVITIES, configure
from aegis.m02_orchestrator.campaign_state import CampaignStateWatcher
from aegis.m02_orchestrator.outbox import OutboxDispatcher
from aegis.m02_orchestrator.signals import TemporalSignals
from aegis.m02_orchestrator.types import (
    AGENT_QUEUE,
    ORCHESTRATOR_QUEUE,
    CampaignRunInput,
    SessionOutcome,
    workflow_id,
)
from aegis.m02_orchestrator.workflow import CampaignWorkflow
from tests.db_support import connect, migrated_database, policy_document, seed_campaign
from tests.live.session_activities import ACTIVITIES as SESSION_ACTIVITIES
from tests.live.session_activities import SessionScript
from tests.live.session_activities import configure as configure_script
from tests.m02_support import (
    accept_job,
    complete_job,
    insert_outbox_event,
    run_job,
    service,
)

REPO = Path(__file__).resolve().parents[2]
REPLAY_FIXTURE = REPO / "tests/fixtures/temporal/campaign_workflow_history.json"


@pytest.fixture(scope="module")
def temporal_target() -> str:
    target = os.environ.get("AEGIS_TEMPORAL_TARGET")
    if not target:
        pytest.skip("AEGIS_TEMPORAL_TARGET is not set")
    return target


@pytest.fixture()
def dsn() -> Iterator[str]:
    with migrated_database() as database:
        yield database


@asynccontextmanager
async def running(client: Client, dsn: str, stop: asyncio.Event) -> AsyncIterator[None]:
    """Worker (both queues) and the dispatchers, exactly as the process entry points run them."""
    configure(connect=lambda: db.connect(dsn))
    signals = TemporalSignals(client)
    outbox = OutboxDispatcher(lambda: db.connect(dsn), signals)
    watcher = CampaignStateWatcher(lambda: db.connect(dsn), signals)

    async def dispatch_forever() -> None:
        while not stop.is_set():
            await watcher.run_once()
            await outbox.run_once()
            await asyncio.sleep(0.05)

    dispatcher = asyncio.create_task(dispatch_forever())
    async with (
        Worker(
            client,
            task_queue=ORCHESTRATOR_QUEUE,
            workflows=[CampaignWorkflow],
            activities=list(ACTIVITIES),
        ),
        Worker(client, task_queue=AGENT_QUEUE, activities=list(SESSION_ACTIVITIES)),
    ):
        try:
            yield
        finally:
            stop.set()
            dispatcher.cancel()
            await asyncio.gather(dispatcher, return_exceptions=True)


async def _wait_for(check: Callable[[], Any], timeout: float = 20.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if check():
            return
        await asyncio.sleep(0.05)
    raise AssertionError("condition not met before the timeout")


async def _wait_state(
    handle: WorkflowHandle[Any, Any], expected: str, timeout: float = 20.0
) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        view = await handle.query(CampaignWorkflow.status)
        if view.state == expected:
            return
        await asyncio.sleep(0.05)
    raise AssertionError(f"workflow state is not {expected!r} before the timeout")


def _job_status(dsn: str, job_id: str) -> str:
    with connect(dsn) as conn:
        row = conn.execute("SELECT status FROM scan_job WHERE job_id = %s", (job_id,)).fetchone()
    assert row is not None
    return str(row[0])


def _campaign_status(dsn: str, campaign_id: str) -> str:
    with connect(dsn) as conn:
        row = conn.execute(
            "SELECT status FROM campaign WHERE campaign_id = %s", (campaign_id,)
        ).fetchone()
    assert row is not None
    return str(row[0])


def _completed_event(campaign_id: str, job_id: str, status: str = "SUCCEEDED") -> dict[str, Any]:
    return {
        "job_id": job_id,
        "campaign_id": campaign_id,
        "status": status,
        "evidence_refs": [],
        "finished_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "attempt": 1,
        "generation": 1,
    }


def test_dispatch_dependency_completion_and_replay_fixture(temporal_target: str, dsn: str) -> None:
    campaign = seed_campaign(dsn, policy=policy_document(max_parallel_jobs=1))
    with service(dsn) as jobs:
        parent = accept_job(jobs, campaign, priority=10)
        child = accept_job(jobs, campaign, priority=90, depends_on=[parent])
    script = configure_script(
        campaign.campaign_id,
        SessionScript(outcomes=[SessionOutcome(cursor=1, cycle=0, stop_reason="objective_done")]),
    )

    async def scenario() -> None:
        client = await Client.connect(temporal_target)
        stop = asyncio.Event()
        handle = await client.start_workflow(
            CampaignWorkflow.run,
            CampaignRunInput(campaign_id=campaign.campaign_id, tick_seconds=0.1),
            id=workflow_id(campaign.campaign_id),
            task_queue=ORCHESTRATOR_QUEUE,
        )
        async with running(client, dsn, stop):
            await _wait_for(lambda: _job_status(dsn, parent) == "VALIDATING")
            assert _job_status(dsn, child) == "QUEUED", "a dependency must not be overtaken"

            run_job(dsn, parent)
            assert complete_job(dsn, parent) == "terminalized"
            insert_outbox_event(
                dsn,
                event_type="job.completed.v2",
                campaign_id=campaign.campaign_id,
                dedup_key=parent,
                payload=_completed_event(campaign.campaign_id, parent),
            )
            await _wait_for(lambda: _job_status(dsn, child) == "VALIDATING")

            run_job(dsn, child)
            assert complete_job(dsn, child) == "terminalized"
            insert_outbox_event(
                dsn,
                event_type="job.completed.v2",
                campaign_id=campaign.campaign_id,
                dedup_key=child,
                payload=_completed_event(campaign.campaign_id, child),
            )
            result = await asyncio.wait_for(handle.result(), timeout=30)
            assert result.status == "COMPLETED" and result.stop_reason == "objective_done"
            assert _campaign_status(dsn, campaign.campaign_id) == "COMPLETED"
            assert [request.cycle for request in script.requests] == [0]
            history = await handle.fetch_history()
            replayed = await Replayer(
                workflows=[CampaignWorkflow], namespace=client.namespace
            ).replay_workflow(history)
            assert replayed.replay_failure is None
            REPLAY_FIXTURE.parent.mkdir(parents=True, exist_ok=True)
            REPLAY_FIXTURE.write_text(
                json.dumps({"workflow_id": handle.id, "history": json.loads(history.to_json())})
                + "\n"
            )
            from temporalio.api.enums.v1 import EventType

            REPLAY_FIXTURE.with_name("campaign_workflow_history.events.json").write_text(
                json.dumps([EventType.Name(event.event_type) for event in history.events], indent=1)
                + "\n"
            )

    asyncio.run(scenario())


def test_pause_and_resume_arrive_through_the_campaign_watcher(
    temporal_target: str, dsn: str
) -> None:
    campaign = seed_campaign(dsn, status="PAUSED", policy=policy_document(max_parallel_jobs=1))
    with service(dsn) as jobs:
        job = accept_job(jobs, campaign)
    configure_script(campaign.campaign_id, SessionScript())

    async def scenario() -> None:
        client = await Client.connect(temporal_target)
        stop = asyncio.Event()
        handle = await client.start_workflow(
            CampaignWorkflow.run,
            CampaignRunInput(campaign_id=campaign.campaign_id, tick_seconds=0.1),
            id=workflow_id(campaign.campaign_id),
            task_queue=ORCHESTRATOR_QUEUE,
        )
        async with running(client, dsn, stop):
            await _wait_state(handle, "PAUSED")
            assert _job_status(dsn, job) == "QUEUED"

            with connect(dsn) as conn, conn.transaction():
                conn.execute(
                    "UPDATE campaign SET status = 'RUNNING' WHERE campaign_id = %s",
                    (campaign.campaign_id,),
                )
            await _wait_state(handle, "RUNNING")
            await _wait_for(lambda: _job_status(dsn, job) == "VALIDATING")

            with connect(dsn) as conn, conn.transaction():
                conn.execute(
                    "UPDATE campaign SET status = 'PAUSED', status_reason = 'operator pause' "
                    "WHERE campaign_id = %s",
                    (campaign.campaign_id,),
                )
            await _wait_state(handle, "PAUSED")
            assert _job_status(dsn, job) == "VALIDATING", (
                "pause stops new dispatches; a started job keeps its state"
            )
            await handle.cancel()

    asyncio.run(scenario())


def test_cancel_stops_a_running_session_and_writes_the_campaign_state(
    temporal_target: str, dsn: str
) -> None:
    campaign = seed_campaign(dsn, policy=policy_document(max_parallel_jobs=1))
    script = configure_script(
        campaign.campaign_id,
        SessionScript(outcomes=[SessionOutcome(cursor=0, cycle=0)], delay_seconds=60),
    )

    async def scenario() -> None:
        client = await Client.connect(temporal_target)
        stop = asyncio.Event()
        handle = await client.start_workflow(
            CampaignWorkflow.run,
            CampaignRunInput(campaign_id=campaign.campaign_id, tick_seconds=0.1),
            id=workflow_id(campaign.campaign_id),
            task_queue=ORCHESTRATOR_QUEUE,
        )
        async with running(client, dsn, stop):
            await _wait_for(lambda: script.started.is_set())
            with connect(dsn) as conn, conn.transaction():
                conn.execute(
                    "UPDATE campaign SET status = 'CANCELLED' WHERE campaign_id = %s",
                    (campaign.campaign_id,),
                )
            result = await asyncio.wait_for(handle.result(), timeout=20)
            assert result.status == "CANCELLED"
            assert script.cancelled, (
                "the in-flight session activity must be cancelled, not abandoned"
            )

    asyncio.run(scenario())


def test_an_idle_session_pauses_the_campaign_with_a_reason(temporal_target: str, dsn: str) -> None:
    """G1.2c acceptance: the idle threshold pauses the campaign, and the reason is recorded.

    M03 owns "is this cycle idle" (`SessionOutcome.idle`); M02 owns the threshold
    (`budget.idle_cycles_before_pause`) and the pause. This drives the real workflow with a session
    activity that reports idle every time, so the boundary between the two is what is proven.
    """
    campaign = seed_campaign(
        dsn,
        policy=policy_document(
            max_parallel_jobs=1,
            budget={
                "max_jobs": 50,
                "max_llm_tokens": 100000,
                "max_llm_cost_usd": 5,
                "idle_cycles_before_pause": 3,
            },
        ),
    )
    script = configure_script(
        campaign.campaign_id,
        SessionScript(outcomes=[]),  # the fake's default answer is `idle=True`, no stop reason
    )

    async def scenario() -> None:
        client = await Client.connect(temporal_target)
        stop = asyncio.Event()
        handle = await client.start_workflow(
            CampaignWorkflow.run,
            CampaignRunInput(campaign_id=campaign.campaign_id, tick_seconds=0.1),
            id=workflow_id(campaign.campaign_id),
            task_queue=ORCHESTRATOR_QUEUE,
        )
        async with running(client, dsn, stop):
            await _wait_state(handle, "PAUSED", timeout=30)
            view = await handle.query(CampaignWorkflow.status)
            assert view.idle_cycles >= 3
            assert view.paused is True
            assert view.stop_reason is None  # a pause, not a terminal stop
            with connect(dsn) as conn:
                row = conn.execute(
                    "SELECT status, status_reason FROM campaign WHERE campaign_id = %s",
                    (campaign.campaign_id,),
                ).fetchone()
            assert row is not None
            assert row[0] == "PAUSED"
            assert row[1] == f"no progress for {view.idle_cycles} session(s)"
            assert len(script.finished) >= 3
        with suppress(Exception):
            await handle.cancel()

    asyncio.run(scenario())


def test_continue_as_new_carries_the_cycle_and_cursor(temporal_target: str, dsn: str) -> None:
    campaign = seed_campaign(dsn, policy=policy_document(max_parallel_jobs=1))
    script = configure_script(
        campaign.campaign_id,
        SessionScript(
            outcomes=[
                SessionOutcome(cursor=1, cycle=0),
                SessionOutcome(cursor=2, cycle=0),
                SessionOutcome(cursor=3, cycle=0),
                SessionOutcome(cursor=4, cycle=0, stop_reason="objective_done"),
            ]
        ),
    )

    async def scenario() -> None:
        client = await Client.connect(temporal_target)
        stop = asyncio.Event()
        handle = await client.start_workflow(
            CampaignWorkflow.run,
            CampaignRunInput(
                campaign_id=campaign.campaign_id,
                tick_seconds=0.05,
                continue_after_cycles=2,
            ),
            id=workflow_id(campaign.campaign_id),
            task_queue=ORCHESTRATOR_QUEUE,
        )
        async with running(client, dsn, stop):
            result = await asyncio.wait_for(handle.result(), timeout=40)
            runs = [
                workflow
                async for workflow in client.list_workflows(
                    f'WorkflowId = "{workflow_id(campaign.campaign_id)}"'
                )
            ]
        assert result.status == "COMPLETED"
        # Two Temporal runs prove Continue-As-New; the carried cycle shows in the session requests.
        assert len(runs) == 2, [run.run_id for run in runs]
        assert [request.cycle for request in script.requests] == [0, 1, 2, 3]

    asyncio.run(scenario())


def test_already_terminal_campaign_ends_immediately(temporal_target: str, dsn: str) -> None:
    campaign = seed_campaign(dsn, status="CANCELLED", policy=policy_document(max_parallel_jobs=1))
    configure_script(campaign.campaign_id, SessionScript())

    async def scenario() -> None:
        client = await Client.connect(temporal_target)
        stop = asyncio.Event()
        async with running(client, dsn, stop):
            handle = await client.start_workflow(
                CampaignWorkflow.run,
                CampaignRunInput(campaign_id=campaign.campaign_id, tick_seconds=0.1),
                id=workflow_id(campaign.campaign_id),
                task_queue=ORCHESTRATOR_QUEUE,
            )
            result = await asyncio.wait_for(handle.result(), timeout=20)
        assert result.status == "CANCELLED"
        assert result.stop_reason == "campaign_cancelled"

    asyncio.run(scenario())
