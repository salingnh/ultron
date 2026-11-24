"""The scripted lab demo the card asks for: seed domain -> Subfinder -> DNSx on discovered names.

`ScriptedLabPolicy` is the G1 stand-in for the model (leader decision: the model is fake in G1). It
reads the campaign's inventory instead of a provider and answers with contract `model-response.v2`
payloads, so the demo exercises the production loop - M04's budget/usage rules, M03's validation and
the real M05 MCP boundary - while sending nothing.

The chain is three campaigns cycles, which is how it will run for real: a session proposes one job
and ends with `wait`; M02 waits for `job_completed`; M27 records the discovered names; the next
session's context contains them and the policy proposes DNSx with `depends_on`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aegis.m03_agent.config import SessionConfig
from aegis.m03_agent.fake_policy import ENUMERATE, RESOLVE, ScriptedLabPolicy, jobs_of
from aegis.m03_agent.session import run_session
from aegis.m04_model.usage import InMemoryUsageSink
from tests.m03_support import (
    InMemoryLedger,
    InMemoryStore,
    deps_for,
    job_store,
    run,
    service,
    session_request,
)


@dataclass
class FakeCatalog:
    """The demo's inventory: seeds, discovered names and jobs, updated between cycles."""

    seeds: list[str] = field(default_factory=lambda: ["internal.example"])
    discovered: list[str] = field(default_factory=list)
    job_rows: list[tuple[str, str, str]] = field(default_factory=list)

    def seed_domains(self, campaign_id: str) -> list[str]:
        del campaign_id
        return list(self.seeds)

    def discovered_domains(self, campaign_id: str) -> list[str]:
        del campaign_id
        return list(self.discovered)

    def jobs(self, campaign_id: str) -> list[tuple[str, str, str]]:
        del campaign_id
        return list(self.job_rows)


def _config() -> SessionConfig:
    return SessionConfig(model="scripted-lab", max_steps=4, in_session_idle_rounds=2)


def _label(cycle: int) -> str:
    return f"01934f6a-0000-7000-8000-000000000001:cycle-{cycle}"


def test_the_lab_demo_chain_proposes_subfinder_then_dnsx_with_a_dependency() -> None:
    catalog = FakeCatalog()
    policy = ScriptedLabPolicy(catalog=catalog, usage=InMemoryUsageSink())
    job_service = service()
    ledger = InMemoryLedger()
    store = InMemoryStore(ledger)

    def session(cycle: int) -> Any:
        deps = deps_for(
            model=policy,
            tool_service=job_service,
            store=store,
            ledger=ledger,
            config=_config(),
        )
        return run(run_session(session_request(session_id=_label(cycle), cycle=cycle), deps.deps))

    # cycle 1: the seed domain is enumerated (Subfinder)
    first = session(0)
    assert len(first.outcome.job_ids) == 1
    enumerate_job = first.outcome.job_ids[0]
    assert policy.responses[-1].finish_reason.value == "tool_calls"
    assert _call(policy.responses[-1])["name"] == ENUMERATE
    assert _call(policy.responses[-1])["arguments"]["input"]["targets"] == ["internal.example"]

    # M06 runs Subfinder, M27 records the names it found (the demo's stand-in) and M02 signals
    catalog.job_rows = [(enumerate_job, ENUMERATE, "SUCCEEDED")]
    catalog.discovered = ["dns:www.internal.example", "dns:mail.internal.example"]

    # cycle 2: DNSx resolves the discovered names and depends on the enumeration job
    second = session(1)
    assert len(second.outcome.job_ids) == 1
    resolve_job = second.outcome.job_ids[0]
    resolve_call = _call(policy.responses[-1])
    assert resolve_call["name"] == RESOLVE
    assert resolve_call["arguments"]["input"]["targets"] == catalog.discovered
    assert resolve_call["arguments"]["depends_on"] == [enumerate_job]

    # cycle 3: both jobs exist, so the planner reports the objective met and the campaign completes
    catalog.job_rows = [
        (enumerate_job, ENUMERATE, "SUCCEEDED"),
        (resolve_job, RESOLVE, "SUCCEEDED"),
    ]
    third = session(2)
    assert third.outcome.stop_reason == "objective_met"
    assert third.outcome.job_ids == ()
    assert third.result is not None
    assert third.result["decision"] == "stop"

    # every answer the policy produced is a valid model-response.v2 (FakeModelClient validated it)
    assert len(policy.responses) == 3
    assert len(policy.calls) == 3
    # the M05 boundary accepted exactly the two proposed jobs, both proposed by an agent session
    jobs = list(job_store(job_service).jobs.values())
    assert [job["capability"] for job in jobs] == [ENUMERATE, RESOLVE]
    assert all(job["proposed_by"]["kind"] == "agent" for job in jobs)


def test_the_policy_waits_instead_of_inventing_a_target() -> None:
    catalog = FakeCatalog(seeds=[])
    policy = ScriptedLabPolicy(catalog=catalog, usage=InMemoryUsageSink())
    deps = deps_for(model=policy, config=_config())

    session = run(run_session(session_request(), deps.deps))

    assert session.outcome.idle is True
    assert session.outcome.stop_reason is None
    assert session.outcome.job_ids == ()
    assert policy.responses[-1].finish_reason.value == "completed"
    assert (policy.responses[-1].parsed or {})["decision"] == "wait"


def test_the_policy_reports_the_jobs_it_asked_for() -> None:
    catalog = FakeCatalog()
    policy = ScriptedLabPolicy(catalog=catalog, usage=InMemoryUsageSink())
    deps = deps_for(model=policy, config=_config())

    run(run_session(session_request(), deps.deps))

    assert len(jobs_of(catalog, "01934f6a-0000-7000-8000-000000000001", ENUMERATE)) == 0
    assert len(policy.calls) == 1
    assert policy.calls[0].response_schema is not None  # the plan decision schema travels with it


def _call(response: Any) -> dict[str, Any]:
    from aegis.m03_agent.wire import blocks

    return next(block["call"] for block in blocks(response.message) if block["type"] == "tool_call")
