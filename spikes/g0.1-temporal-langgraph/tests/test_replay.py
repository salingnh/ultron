"""Acceptance: recorded history replays deterministically, and the replay test can fail."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from temporalio.worker import Replayer

from aegis_spike import config
from aegis_spike.changed_workflow import ChangedCampaignWorkflow
from aegis_spike.workflows import CampaignWorkflow

from .conftest import start_campaign

EVIDENCE = Path(__file__).resolve().parents[1] / "evidence"


async def test_replay_is_deterministic(temporal, worker_factory, campaign_id: str):
    worker_factory()
    handle, _ = await start_campaign(temporal, campaign_id, max_cycles=1, fake_job_delay_seconds=0.2)
    result = await handle.result()
    assert result.status == "COMPLETED"

    history = await handle.fetch_history()
    replayed = await Replayer(workflows=[CampaignWorkflow], namespace=config.TEMPORAL_NAMESPACE).replay_workflow(
        history
    )
    assert replayed.replay_failure is None

    history_json = history.to_json()
    EVIDENCE.mkdir(exist_ok=True)
    (EVIDENCE / "replay.json").write_text(
        json.dumps(
            {
                "workflow_id": handle.id,
                "run_id": handle.result_run_id,
                "history_events": len(history.events),
                "history_bytes": len(history_json.encode()),
                "replay_failure": None,
                "event_types": [type(e).__name__ for e in history.events],
            },
            indent=2,
        )
    )


async def test_incompatible_code_change_is_rejected_by_replay(temporal, worker_factory, campaign_id: str):
    """Negative control: the replay gate must fail on a changed command sequence."""
    worker_factory()
    handle, _ = await start_campaign(temporal, campaign_id, max_cycles=1, fake_job_delay_seconds=0.2)
    assert (await asyncio.wait_for(handle.result(), timeout=120)).status == "COMPLETED"
    history = await handle.fetch_history()

    with pytest.raises(Exception) as excinfo:
        # Same workflow type, different first command: replaying the recorded history
        # with this code must be rejected as nondeterministic.
        await Replayer(workflows=[ChangedCampaignWorkflow], namespace=config.TEMPORAL_NAMESPACE).replay_workflow(
            history
        )
    message = str(excinfo.value).lower()
    assert "nondeterministic" in message or "does not match" in message, message

    EVIDENCE.mkdir(exist_ok=True)
    (EVIDENCE / "replay-negative.json").write_text(
        json.dumps(
            {
                "workflow_id": handle.id,
                "control": "ChangedCampaignWorkflow (same workflow type, different command sequence)",
                "rejected": True,
                "error": str(excinfo.value).splitlines()[0],
            },
            indent=2,
        )
    )
