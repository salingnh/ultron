"""The seams the G1.5c demo closed, each one a bug the joined system showed.

Four regressions, one test each:

* the worker never configured the session module it hosts (`run_worker` imported it and started it,
  so the first activity failed with "M03 is not configured" instead of the worker refusing to
  start);
* a campaign paused after `idle_cycles_before_pause` sessions while its own job was running, because
  the workflow decided "pending" from signals instead of the committed rows;
* a parser's `coverage_subjects` never became the envelope's `coverage`, and its `raw` evidence ref
  never named the file the envelope carries, so ingestion quarantined every record (G3);
* a policy that sets no LLM ceiling produced `null` in a bundle field the contract has no null for.
"""

from __future__ import annotations

import importlib
from typing import Any

import pytest

from aegis.m02_orchestrator import worker as worker_module
from aegis.m03_agent import activities as activity_module


class _Module:
    def __init__(self, *, fail: bool = False) -> None:
        self.called = 0
        self.fail = fail

    def configure_from_env(self) -> None:
        self.called += 1
        if self.fail:
            raise RuntimeError("no database")

    ACTIVITIES: list[Any] = []


def test_the_worker_configures_the_session_module_before_it_starts(monkeypatch: Any) -> None:
    module = _Module()

    def _import(name: str) -> Any:
        assert name == "example.sessions"
        return module

    monkeypatch.setattr(importlib, "import_module", _import)
    worker_module._configure_from_env(module, "example.sessions")
    assert module.called == 1


def test_a_session_module_without_the_hook_is_used_as_is(monkeypatch: Any) -> None:
    class _Plain:
        ACTIVITIES: list[Any] = []

    worker_module._configure_from_env(_Plain(), "tests.live.session_activities")


def test_a_session_module_that_cannot_configure_stops_the_worker() -> None:
    with pytest.raises(SystemExit, match="cannot configure the session module"):
        worker_module._configure_from_env(_Module(fail=True), "example.sessions")


def test_the_m03_module_exposes_the_hook_the_worker_calls(monkeypatch: Any) -> None:
    """`aegis.m03_agent.activities` is the module the default worker imports: it must have one."""
    assert callable(activity_module.configure_from_env)
    configured: dict[str, Any] = {}

    def _configure() -> Any:
        configured["called"] = True
        return object()

    monkeypatch.setattr(activity_module, "configure", _configure)
    activity_module.configure_from_env()
    assert configured["called"] is True


# --- the bundle budget: a ceiling nobody set is absent, never null ----------------------------

BUNDLE_SCHEMA = "agent/context-bundle.v2.schema.json"


def _bundle_budget(**budget: Any) -> dict[str, Any]:
    from aegis.m03_agent.nodes import _bundle_budget as build

    return build({"max_steps": 30, **budget})


def test_a_policy_without_llm_ceilings_produces_no_null_in_the_bundle() -> None:
    from aegis import validation

    budget = _bundle_budget(tokens_remaining=None, cost_remaining=None)
    assert budget == {"max_steps": 30}
    document = {
        "campaign_id": "01a20c00-0000-7000-8000-000000000001",
        "session_id": "01a20c00-0000-7000-8000-000000000002",
        "objective": {"objective_id": "01a20c00-0000-7000-8000-000000000003", "text": "lab"},
        "policy_version": "roe-1",
        "policy_summary": {"budget": {}},
        "graph_revision": 0,
        "previous_revision": 0,
        "observations": [],
        "ledger": {"completed_objectives": [], "blockers": [], "pending_job_ids": []},
        "capabilities": [],
        "budget": budget,
    }
    validation.validate(BUNDLE_SCHEMA, document)


def test_a_policy_with_ceilings_carries_them() -> None:
    budget = _bundle_budget(tokens_remaining=10, cost_remaining=2.5)

    assert budget == {"max_steps": 30, "llm_tokens_remaining": 10, "llm_cost_usd_remaining": 2.5}


def test_a_null_ceiling_is_what_the_bundle_schema_forbids() -> None:
    """The regression the fix removes: `null` is not a number, and the bundle has no null for it."""
    import pytest

    from aegis import validation
    from aegis.validation import ContractViolation

    document = {
        "campaign_id": "01a20c00-0000-7000-8000-000000000001",
        "session_id": "01a20c00-0000-7000-8000-000000000002",
        "objective": {"objective_id": "01a20c00-0000-7000-8000-000000000003", "text": "lab"},
        "policy_version": "roe-1",
        "policy_summary": {"budget": {}},
        "graph_revision": 0,
        "previous_revision": 0,
        "observations": [],
        "ledger": {"completed_objectives": [], "blockers": [], "pending_job_ids": []},
        "capabilities": [],
        "budget": {"max_steps": 30, "llm_tokens_remaining": None},
    }
    with pytest.raises(ContractViolation):
        validation.validate(BUNDLE_SCHEMA, document)
