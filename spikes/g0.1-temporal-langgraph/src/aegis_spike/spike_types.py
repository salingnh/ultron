"""Dataclasses crossing Temporal activity/workflow boundaries.

Kept free of LangGraph/psycopg imports so the workflow sandbox can import them cheaply.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CampaignInput:
    campaign_id: str
    cursor: int = 0
    cycle: int = 0
    max_cycles: int = 1
    continue_as_new_after_cycles: int = 0  # 0 = never (spike keeps it explicit)
    fake_job_delay_seconds: float = 3.0


@dataclass
class FetchDeltaInput:
    campaign_id: str
    cursor: int


@dataclass
class ContextBundle:
    campaign_id: str
    cursor_in: int
    cursor_out: int
    objective: str
    observations: list[str] = field(default_factory=list)
    pending_jobs: list[str] = field(default_factory=list)


@dataclass
class SessionInput:
    campaign_id: str
    session_id: str
    cursor_in: int
    cursor_out: int
    objective: str
    max_steps: int = 30
    fake_job_delay_seconds: float = 3.0


@dataclass
class SessionResult:
    session_id: str
    status: str  # completed | canceled
    stop_reason: str | None
    steps: int
    cursor: int
    job_id: str | None
    resumed: bool
    attempt: int


@dataclass
class RunRecord:
    workflow_id: str
    run_id: str
    first_run_id: str
    continued_from_run_id: str | None
    cursor_in: int
    cycle_in: int


@dataclass
class CampaignStatusView:
    state: str
    cycle: int
    cursor: int
    pending_jobs: list[str]
    last_revision: int
    idle_cycles: int
    paused: bool
    cancel_requested: bool


@dataclass
class CampaignOutcome:
    status: str
    stop_reason: str | None
    cursor: int
    cycle: int
    canceled_job_ids: list[str] = field(default_factory=list)
    jobs: list[str] = field(default_factory=list)
    snapshot: dict = field(default_factory=dict)


@dataclass
class NodeInput:
    """Variant B (workflow-per-session): one graph node per activity."""

    campaign_id: str
    session_id: str
    node: str
    state: dict
    objective: str
    fake_job_delay_seconds: float = 3.0
