"""M02 value types shared by the CampaignWorkflow, its activities and the dispatchers.

Temporal's default data converter serializes dataclasses, so these are the payload types of the
workflow boundary. They are internal interface values with no JSON Schema: contract shapes
(campaign.v2, job.v2, AgentSessionResult) are generated DTOs and must not be re-declared here.

`SessionRequest`/`SessionOutcome` are the seam to G1.2c: M03 implements the `run_agent_session`
activity on the `aegis-agent` queue with this input, and this workflow only consumes the outcome.
The session graph, the LangGraph checkpoint and the MCP calls live in M03; M02 never reads model
output directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = [
    "BlockedJob",
    "CampaignOutcome",
    "CampaignRunInput",
    "CampaignSnapshot",
    "CampaignStatusView",
    "CancelOutcome",
    "DispatchPlan",
    "FinalCampaign",
    "SESSION_REFUSED_ERROR",
    "SessionOutcome",
    "SessionRequest",
    "REFUSAL_BUDGET_EXHAUSTED",
    "REFUSAL_CAMPAIGN_MISSING",
    "REFUSAL_INCONSISTENT",
    "REFUSAL_NOT_RUNNING",
]

#: The Temporal task queues of the interface (contracts/interfaces/README.md §7).
ORCHESTRATOR_QUEUE = "aegis-orchestrator"
AGENT_QUEUE = "aegis-agent"
#: Workflow id of a campaign, as the interface fixes it.
WORKFLOW_ID_PREFIX = "campaign-"

#: `ApplicationError.type` of a refused `run_agent_session`, and the `details[0].code` values: the
#: seam between M03 (which refuses) and M02 (which decides what the refusal means). They live here
#: because both sides must agree on them and the workflow may not import M03's store (which owns a
#: database driver). A refusal is a campaign decision, never an activity to retry.
SESSION_REFUSED_ERROR = "SessionRefused"
REFUSAL_BUDGET_EXHAUSTED = "session_budget_exhausted"
REFUSAL_NOT_RUNNING = "campaign_not_running"
REFUSAL_CAMPAIGN_MISSING = "campaign_missing"
REFUSAL_INCONSISTENT = "session_inconsistent"


def workflow_id(campaign_id: str) -> str:
    return f"{WORKFLOW_ID_PREFIX}{campaign_id}"


@dataclass(frozen=True, slots=True)
class CampaignRunInput:
    """Input of `CampaignWorkflow` (and of its Continue-As-New run)."""

    campaign_id: str
    #: Sessions completed so far. A Continue-As-New run starts from the carried value.
    cycle: int = 0
    #: Ingested-knowledge cursor carried across Continue-As-New.
    cursor: int = 0
    idle_cycles: int = 0
    last_revision: int = 0
    #: Timer that re-evaluates the scheduling gates when no signal arrives (window opening,
    #: rate-limit window sliding, a job accepted by M05 outside the workflow).
    tick_seconds: float = 5.0
    continue_after_cycles: int = 500
    continue_after_history_events: int = 10_000
    #: Safety stop for a campaign that would otherwise keep running forever (tests set it small).
    max_cycles: int = 10_000


@dataclass(frozen=True, slots=True)
class CampaignStatusView:
    """Answer of the `status` query (interfaces/README.md §7)."""

    state: str
    cycle: int
    cursor: int
    pending_jobs: tuple[str, ...] = ()
    queued_jobs: int = 0
    in_flight_jobs: int = 0
    last_revision: int = 0
    idle_cycles: int = 0
    paused: bool = False
    cancel_requested: bool = False
    stop_reason: str | None = None


@dataclass(frozen=True, slots=True)
class CampaignOutcome:
    """Result of the workflow; its `status` is written to `campaign.status` when it changes."""

    campaign_id: str
    status: str
    stop_reason: str
    cycle: int = 0
    cursor: int = 0
    canceled_job_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CampaignSnapshot:
    """What the workflow needs from the campaign row at start-up (`load_campaign`)."""

    campaign_id: str
    status: str
    objective: str
    max_parallel_jobs: int
    idle_cycles_before_pause: int = 3
    pending_job_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class BlockedJob:
    """A QUEUED job and the reason it was not dispatched in this tick."""

    job_id: str
    code: str
    detail: str
    blocking_job_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DispatchPlan:
    """One scheduling decision for a campaign, already committed by the activity."""

    campaign_id: str
    status: str
    paused: bool = False
    #: Jobs moved QUEUED -> VALIDATING in this tick, in priority order.
    claimed: tuple[str, ...] = ()
    #: Every non-terminal job of the campaign after this tick (QUEUED or in flight). The workflow
    #: waits on these instead of remembering signals: a signal that arrives while the campaign is
    #: between ticks would otherwise leave the loop waiting for an event that already happened.
    pending: tuple[str, ...] = ()
    #: Jobs left QUEUED with a committed `wait_reason`.
    waiting: tuple[BlockedJob, ...] = ()
    queued: int = 0
    in_flight: int = 0
    #: Set when the workflow must stop: campaign terminal, duration budget, ...
    stop: str | None = None


@dataclass(frozen=True, slots=True)
class CancelOutcome:
    """Result of `cancel_jobs`: jobs terminalised now and jobs that only got the intent."""

    canceled_job_ids: tuple[str, ...] = ()
    cancel_requested_job_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class FinalCampaign:
    """The verified reason a completed campaign ends with (`finalize_campaign`).

    `reason` is what `finish_campaign` records on the campaign row (`status_reason`), so it is the
    operator-facing answer to "did this campaign actually cover the surface?". It is the session's
    proposed stop reason only when matching ran and every job's coverage was complete.
    """

    reason: str
    #: Campaign jobs whose current result reports `coverage.complete = false`, with their codes.
    incomplete_jobs: tuple[str, ...] = ()
    #: `EGRESS_PACED`, `EGRESS_CAPPED`, ... that made those jobs incomplete.
    limitation_codes: tuple[str, ...] = ()
    #: Candidates the matcher produced or retracted for this campaign, and why it failed.
    matches: int = 0
    retractions: int = 0
    matching_error: str | None = None


@dataclass(frozen=True, slots=True)
class SessionRequest:
    """Input of the `run_agent_session` activity (M03, G1.2c)."""

    campaign_id: str
    session_id: str
    cycle: int
    cursor: int
    objective: str


@dataclass(frozen=True, slots=True)
class SessionOutcome:
    """What one agent session did: jobs it proposed, the new cursor, why it stopped."""

    cursor: int
    cycle: int
    job_ids: tuple[str, ...] = ()
    #: None means "the session made progress and another round is allowed".
    stop_reason: str | None = None
    #: True when the session produced no useful new evidence/job (feeds the idle threshold).
    idle: bool = False
    detail: str | None = field(default=None, compare=False)
