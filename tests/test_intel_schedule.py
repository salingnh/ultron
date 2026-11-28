"""The daily intel schedule: one Temporal schedule, one workflow, one activity (item 80).

These are process tests with a fake Temporal client: CI has no Temporal server, and the schedule's
*shape* (cron, queue, workflow, overlap, idempotent install) is exactly what a deployment bug would
change. The activity is called directly with the real refresh substituted, because M18's sync has
its own database suite.
"""

from __future__ import annotations

import asyncio
from typing import Any, cast

import pytest
from temporalio.client import (
    Client,
    ScheduleActionStartWorkflow,
    ScheduleAlreadyRunningError,
    ScheduleUpdate,
)

from aegis.m02_orchestrator import intel
from aegis.m02_orchestrator.types import ORCHESTRATOR_QUEUE


class FakeHandle:
    def __init__(self) -> None:
        self.update_calls = 0
        self.updated: ScheduleUpdate | None = None

    async def update(self, updater: Any) -> None:
        self.update_calls += 1
        self.updated = updater(None)


class FakeClient:
    def __init__(self, *, exists: bool = False) -> None:
        self.exists = exists
        self.created: tuple[str, Any] | None = None
        self.handle = FakeHandle()

    async def create_schedule(self, schedule_id: str, schedule: Any) -> Any:
        if self.exists:
            raise ScheduleAlreadyRunningError()
        self.created = (schedule_id, schedule)
        return self.handle

    def get_schedule_handle(self, schedule_id: str) -> FakeHandle:
        assert schedule_id == intel.INTEL_SCHEDULE_ID
        return self.handle


def test_the_schedule_is_daily_on_the_orchestrator_queue() -> None:
    schedule = intel.build_schedule()
    assert schedule.spec.cron_expressions == ["0 3 * * *"]
    assert schedule.spec.time_zone_name == "UTC"
    assert isinstance(schedule.action, ScheduleActionStartWorkflow)
    assert schedule.action.task_queue == ORCHESTRATOR_QUEUE
    assert schedule.policy.overlap.name == "SKIP"
    assert "intel" in (schedule.state.note or "")


def test_install_creates_the_schedule_once() -> None:
    client = FakeClient()
    asyncio.run(intel.install_schedule(cast(Client, client)))
    assert client.created is not None
    schedule_id, schedule = client.created
    assert schedule_id == intel.INTEL_SCHEDULE_ID
    assert schedule.spec.cron_expressions == [intel.INTEL_CRON]
    assert client.handle.update_calls == 0


def test_install_updates_an_existing_schedule_in_place() -> None:
    client = FakeClient(exists=True)
    asyncio.run(intel.install_schedule(cast(Client, client)))
    assert client.handle.update_calls == 1
    assert client.handle.updated is not None
    assert client.handle.updated.schedule.spec.cron_expressions == [intel.INTEL_CRON]


def test_the_activity_calls_the_recorded_refresh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[tuple[str, Any, bool]] = []

    def fake_recorded_refresh(
        trigger: str, options: Any, *, require_database: bool
    ) -> dict[str, Any]:
        seen.append((trigger, options, require_database))
        return {"ok": True, "legs": {}, "run_id": "run-1", "recorded": True}

    monkeypatch.setattr("aegis.m18_intel.runs.recorded_refresh", fake_recorded_refresh)
    result = asyncio.run(intel.run_intel_sync(intel.IntelSyncRequest(trigger="schedule")))
    assert result["ok"] is True
    assert seen and seen[0][0] == "schedule" and seen[0][2] is True


def test_an_unknown_nvd_mode_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_INTEL_NVD_MODE", "sometimes")
    with pytest.raises(ValueError, match="AEGIS_INTEL_NVD_MODE"):
        intel._options()


def test_the_workflow_and_activity_names_are_stable() -> None:
    workflow_definition = getattr(intel.IntelSyncWorkflow, "__temporal_workflow_definition")
    activity_definition = getattr(intel.run_intel_sync, "__temporal_activity_definition")
    assert workflow_definition.name == "IntelSyncWorkflow"
    assert activity_definition.name == "run_intel_sync"
