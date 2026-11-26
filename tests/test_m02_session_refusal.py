"""The M02/M03 refusal seam (D4, item 61 trial): a refusal is a campaign decision, not a retry.

`agent_session` refused another session (budget spent, campaign no longer RUNNING) used to surface
as an ordinary activity failure: Temporal retried it and, when the retries ran out, the workflow
task failed and replayed, so one campaign produced 926 activity attempts and stayed RUNNING with
`status_reason = NULL` forever.

The seam now carries a machine-readable reason: M03 raises a non-retryable `ApplicationError` of
type `SessionRefused` whose `details[0].code` M02 interprets. These tests pin both halves without a
Temporal server; the live suite (`tests/live/test_m02_workflow_live.py`) proves the workflow turns
it into `COMPLETED`/`budget_exhausted`.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any, cast

import pytest
from temporalio.exceptions import ActivityError, ApplicationError

from aegis.m02_orchestrator.types import (
    REFUSAL_BUDGET_EXHAUSTED,
    REFUSAL_INCONSISTENT,
    REFUSAL_NOT_RUNNING,
    SESSION_REFUSED_ERROR,
    SessionRequest,
)
from aegis.m02_orchestrator.workflow import SessionRefusal, session_refusal
from aegis.m03_agent import activities as m03_activities
from aegis.m03_agent.session import SessionDeps
from aegis.m03_agent.store import SessionRefused

REQUEST = SessionRequest(
    campaign_id="01900000-0000-7000-8000-0000000c0001",
    session_id="01900000-0000-7000-8000-0000000c0001:cycle-5",
    cycle=5,
    cursor=0,
    objective="finish the chain",
)


class RefusingStore:
    """The one seam `run_session` touches before doing any work."""

    def __init__(self, code: str) -> None:
        self.code = code

    def open(self, request: SessionRequest, *, revision_from: int, **_: Any) -> Any:
        raise SessionRefused(
            f"campaign {request.campaign_id} already used 5 of its 5 agent sessions",
            code=self.code,
        )


def _deps(code: str) -> SessionDeps:
    # `run_session` opens the store before it touches any other dependency, so the store is the
    # only member this test needs (the rest would be a database, a model and an MCP server).
    return cast(SessionDeps, SimpleNamespace(store=RefusingStore(code)))


def _failure() -> ApplicationError:
    """What Temporal hands the workflow when the M03 activity refuses."""

    try:
        asyncio.run(m03_activities.run_agent_session(REQUEST))
    except ApplicationError as error:  # the activity raises it; the workflow sees it as a cause
        return error
    raise AssertionError("the activity did not refuse")


def _failure_for(code: str) -> ApplicationError:
    """Run the real M03 activity once against a store that refuses with `code`."""

    m03_activities.configure(deps=_deps(code))
    try:
        return _failure()
    finally:
        m03_activities._deps = None


def test_the_activity_turns_a_refusal_into_a_non_retryable_typed_failure() -> None:
    failure = _failure_for(SessionRefused.BUDGET_EXHAUSTED)
    assert failure.type == SESSION_REFUSED_ERROR
    assert failure.non_retryable is True
    assert tuple(failure.details) == ({"code": REFUSAL_BUDGET_EXHAUSTED},)


@pytest.mark.parametrize(
    "code", [REFUSAL_BUDGET_EXHAUSTED, REFUSAL_NOT_RUNNING, REFUSAL_INCONSISTENT]
)
def test_the_workflow_reads_the_code_from_the_activity_failure(code: str) -> None:
    cause = _failure_for(code)
    error = ActivityError(
        "activity failed",
        scheduled_event_id=1,
        started_event_id=2,
        identity="worker",
        activity_type="run_agent_session",
        activity_id="3",
        retry_state=None,
    )
    error.__cause__ = cause
    assert error.cause is cause
    assert session_refusal(error) == SessionRefusal(code=code, message=cause.message)


def test_a_failure_that_is_not_a_refusal_is_left_alone() -> None:
    error = ActivityError(
        "boom",
        scheduled_event_id=1,
        started_event_id=2,
        identity="worker",
        activity_type="run_agent_session",
        activity_id="3",
        retry_state=None,
    )
    error.__cause__ = RuntimeError("database went away")
    assert session_refusal(error) is None
    error.__cause__ = ApplicationError("other", type="SomethingElse", non_retryable=True)
    assert session_refusal(error) is None
    assert session_refusal(RuntimeError("not an activity failure")) is None
