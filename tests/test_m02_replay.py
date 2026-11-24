"""Replay gate: the committed CampaignWorkflow history must replay deterministically.

The fixture is produced by `tests/live/test_m02_workflow_live.py` on a throwaway Temporal server
(`scripts/temporal/run-live.sh`) and committed, so this check runs in CI without a server. The
negative control proves the gate can fail.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from temporalio.client import WorkflowHistory
from temporalio.worker import Replayer

from aegis.m02_orchestrator.workflow import CampaignWorkflow
from tests.m02_changed_workflow import ChangedCampaignWorkflow

FIXTURE = Path(__file__).resolve().parent / "fixtures/temporal/campaign_workflow_history.json"
EVENT_TYPES = FIXTURE.with_name("campaign_workflow_history.events.json")


def _history() -> WorkflowHistory:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return WorkflowHistory.from_json(str(document["workflow_id"]), document["history"])


def test_the_committed_history_replays_without_a_nondeterminism_error() -> None:
    history = _history()
    replayed = asyncio.run(Replayer(workflows=[CampaignWorkflow]).replay_workflow(history))
    assert replayed.replay_failure is None
    events = json.loads(EVENT_TYPES.read_text(encoding="utf-8"))
    assert len(events) == len(history.events)
    assert "EVENT_TYPE_ACTIVITY_TASK_COMPLETED" in events
    assert "EVENT_TYPE_WORKFLOW_EXECUTION_COMPLETED" in events


def test_a_changed_command_sequence_is_rejected() -> None:
    """If this stops failing, the replay gate is not checking anything."""
    with pytest.raises(Exception) as caught:
        asyncio.run(Replayer(workflows=[ChangedCampaignWorkflow]).replay_workflow(_history()))
    message = str(caught.value).lower()
    assert "nondeterministic" in message or "does not match" in message, message
