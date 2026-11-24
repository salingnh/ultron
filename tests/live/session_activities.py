"""Fake `run_agent_session` activity for M02's live workflow tests (G1: no LLM, no MCP).

G1.2c replaces this with the real M03 activity on the `aegis-agent` queue. The fake is scripted per
campaign so a test can decide what each session returns, how long it runs (cancel propagation) and
whether it heartbeats (the interface requires a finite heartbeat timeout).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from temporalio import activity

from aegis.m02_orchestrator.types import SessionOutcome, SessionRequest

__all__ = ["ACTIVITIES", "SessionScript", "configure", "run_agent_session", "script_for"]


@dataclass
class SessionScript:
    """Scripted outcomes for one campaign, plus what actually happened in the activity."""

    outcomes: list[SessionOutcome] = field(default_factory=list)
    delay_seconds: float = 0.0
    requests: list[SessionRequest] = field(default_factory=list)
    finished: list[SessionOutcome] = field(default_factory=list)
    cancelled: list[str] = field(default_factory=list)
    started: asyncio.Event = field(default_factory=asyncio.Event)

    def next(self, request: SessionRequest) -> SessionOutcome:
        self.requests.append(request)
        if self.outcomes:
            return self.outcomes.pop(0)
        return SessionOutcome(cursor=request.cursor, cycle=request.cycle, idle=True)


_SCRIPTS: dict[str, SessionScript] = {}


def configure(campaign_id: str, script: SessionScript) -> SessionScript:
    _SCRIPTS[campaign_id] = script
    return script


def script_for(campaign_id: str) -> SessionScript | None:
    return _SCRIPTS.get(campaign_id)


@activity.defn(name="run_agent_session")
async def run_agent_session(request: SessionRequest) -> SessionOutcome:
    script = _SCRIPTS.get(request.campaign_id)
    if script is None:
        raise RuntimeError(f"no session script for campaign {request.campaign_id}")
    outcome = script.next(request)
    script.started.set()
    try:
        if script.delay_seconds:
            loop = asyncio.get_running_loop()
            deadline = loop.time() + script.delay_seconds
            while loop.time() < deadline:
                activity.heartbeat(request.session_id)
                await asyncio.sleep(0.05)
    except asyncio.CancelledError:
        script.cancelled.append(request.session_id)
        raise
    script.finished.append(outcome)
    return outcome


ACTIVITIES = [run_agent_session]
