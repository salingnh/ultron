"""The scripted lab demo the card asks for: seed domain -> Subfinder -> M27 -> context -> DNSx.

`ScriptedLabPolicy` is the G1 stand-in for the model (leader decision: the model is fake in G1). It
has no provider and **no database access**: it decides from the `ContextBundle` the session builds
and hands it (`observe_context`), so this suite proves the data path the demo exists for - a
capability's targets can only come from what the context carries:

* the seed targets arrive as bundle observations (`campaign seed target ...`, raw value in
  `untrusted`), which is where the contract puts campaign target text;
* the names DNSx resolves arrive as observations M27 recorded (here: the fixture stands in for
  M27; with the projection wired it is M23's `get_recent_observations` output);
* what was already proposed arrives in `ledger.completed_objectives` / `pending_job_ids`.

The chain is three campaign cycles, which is how it will run for real: a session proposes one job
and ends with `wait`; M02 waits for `job_completed`; M27 records the discovered names; the next
session's bundle contains them and the policy proposes DNSx with `depends_on`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from aegis.m03_agent.config import SessionConfig
from aegis.m03_agent.fake_policy import ENUMERATE, RESOLVE, ScriptedLabPolicy, job_lines
from aegis.m03_agent.session import run_session
from aegis.m04_model.usage import InMemoryUsageSink
from aegis.m05_registry.mcp.graph import UnavailableGraphQueries
from tests.m03_support import (
    InMemoryLedger,
    InMemoryStore,
    deps_for,
    run,
    service,
    session_request,
)

SEED = "internal.example"


@dataclass
class Demo:
    """The demo's stand-ins for M06/M27: the jobs M05 accepted and the observations M27 recorded."""

    policy: ScriptedLabPolicy = field(
        default_factory=lambda: ScriptedLabPolicy(usage=InMemoryUsageSink())
    )
    ledger: InMemoryLedger = field(default_factory=InMemoryLedger)
    store: InMemoryStore = field(init=False)
    #: The M23 projection is not wired yet (G1.4b), so `build_context` reads the M27 rows - the
    #: production path today. The fixture's `observations` stand in for what M27 ingested.
    job_service: Any = field(default_factory=lambda: service(graph=UnavailableGraphQueries()))
    observations: list[Mapping[str, Any]] = field(default_factory=list)
    #: The objective text the bundle carries; the policy reads it to decide how far to go.
    objective: str = "Discover the lab domain's subdomains and resolve them"
    bundles: list[Any] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        self.store = InMemoryStore(self.ledger)

    def context(self) -> Any:
        """What `build_context` reads: the campaign's jobs (M05) and the M27 rows."""
        from tests.m03_support import FakeContext

        jobs = [
            {"job_id": row["job_id"], "capability": row["capability"], "status": row["status"]}
            for row in _job_rows(self.job_service)
        ]
        return FakeContext(
            observations=self.observations,
            jobs=jobs,
            targets=[
                {
                    "target_id": "01934f6a-0000-7000-8000-0000000000e1",
                    "kind": "domain",
                    "raw_value": SEED,
                    "canonical_key": f"dns:{SEED}",
                }
            ],
            graph_revision=len(self.observations),
            objective_text=self.objective,
        )

    def session(self, cycle: int) -> Any:
        deps = deps_for(
            model=self.policy,
            tool_service=self.job_service,
            store=self.store,
            ledger=self.ledger,
            context=self.context(),
            config=_config(),
        )
        return run(run_session(session_request(session_id=_label(cycle), cycle=cycle), deps.deps))

    def record_discovered(self, *names: str) -> None:
        for index, name in enumerate(names):
            self.observations.append(
                {
                    "observation_id": f"01934f6a-0000-7000-8000-0000000000f{index}",
                    "subject": f"dns:{name}",
                    "predicate": "dns.record",
                    "value": {"type": "A", "value": f"10.114.53.{10 + index}"},
                    "revision": len(self.observations) + 1,
                    "confidence": 0.9,
                }
            )


def _job_rows(job_service: Any) -> list[dict[str, Any]]:
    return list(job_service.jobs.jobs.values())


def _config() -> SessionConfig:
    return SessionConfig(model="scripted-lab", max_steps=4, in_session_idle_rounds=2)


def _label(cycle: int) -> str:
    return f"01934f6a-0000-7000-8000-000000000001:cycle-{cycle}"


def test_the_lab_demo_chain_proposes_subfinder_then_dnsx_from_the_context() -> None:
    demo = Demo()

    # cycle 1: the seed target is in the bundle, so the policy enumerates it (Subfinder)
    first = demo.session(0)
    assert len(first.outcome.job_ids) == 1
    enumerate_job = first.outcome.job_ids[0]
    assert _call(demo.policy.responses[-1])["name"] == ENUMERATE
    assert _call(demo.policy.responses[-1])["arguments"]["input"]["targets"] == [f"dns:{SEED}"]

    # M06 runs Subfinder and M27 records the names it found; the bundle of the next cycle carries
    # them as observations (the fixture stands in for M27's rows)
    _complete(demo, enumerate_job, "SUCCEEDED")
    demo.record_discovered("www.internal.example", "mail.internal.example")

    # cycle 2: DNSx resolves exactly the names the context carries, depending on the enumeration job
    second = demo.session(1)
    assert len(second.outcome.job_ids) == 1
    resolve_job = second.outcome.job_ids[0]
    resolve_call = _call(demo.policy.responses[-1])
    assert resolve_call["name"] == RESOLVE
    assert resolve_call["arguments"]["input"]["targets"] == [
        "dns:www.internal.example",
        "dns:mail.internal.example",
    ]
    assert resolve_call["arguments"]["depends_on"] == [enumerate_job]

    # cycle 3: both capabilities are proposed, so the planner reports the objective met
    _complete(demo, resolve_job, "SUCCEEDED")
    third = demo.session(2)
    assert third.outcome.stop_reason == "objective_met"
    assert third.outcome.job_ids == ()
    assert third.result is not None
    assert third.result["decision"] == "stop"

    # every answer the policy produced is a valid model-response.v2 (FakeModelClient validated it)
    assert len(demo.policy.calls) == 3
    assert [job["capability"] for job in _job_rows(demo.job_service)] == [ENUMERATE, RESOLVE]
    assert all(job["proposed_by"]["kind"] == "agent" for job in _job_rows(demo.job_service))


def test_with_no_discovered_names_the_policy_proposes_no_dnsx_job() -> None:
    """Ingestion returned nothing: the policy must not invent a DNSx call (or a target)."""
    demo = Demo()
    first = demo.session(0)
    enumerate_job = first.outcome.job_ids[0]
    _complete(demo, enumerate_job, "SUCCEEDED")

    second = demo.session(1)

    assert second.outcome.job_ids == ()  # no DNSx job
    assert len(_job_rows(demo.job_service)) == 1  # only the Subfinder job
    assert second.result is not None
    assert second.result["decision"] == "wait"
    assert second.outcome.stop_reason is None
    assert second.outcome.idle is True  # M02's idle counter is what pauses the campaign
    response = demo.policy.responses[-1]
    assert response.finish_reason.value == "completed"
    assert (response.parsed or {})["decision"] == "wait"
    assert "no new domain name" in (response.parsed or {})["summary"]


def test_the_policy_waits_while_a_job_is_still_in_flight() -> None:
    demo = Demo()

    session = demo.session(0)

    # nothing proposed yet, so the first cycle enumerates; a second cycle with the job still QUEUED
    # does not propose it again - the bundle's pending ids say it is in flight
    assert session.outcome.job_ids
    assert demo.policy.bundles  # the session handed the policy its bundle
    _set_status(demo, session.outcome.job_ids[0], "QUEUED")

    second = demo.session(1)

    assert second.outcome.job_ids == ()
    assert (demo.policy.responses[-1].parsed or {})["decision"] == "wait"
    assert "in flight" in (demo.policy.responses[-1].parsed or {})["summary"]


def test_the_policy_refuses_to_decide_without_a_bundle() -> None:
    import pytest

    policy = ScriptedLabPolicy()
    deps = deps_for(model=policy, config=_config())
    # the session always hands the bundle over; a policy used outside a session must fail loudly
    from aegis.m03_agent.fake_policy import job_lines

    assert job_lines(_empty_bundle()) == []
    with pytest.raises(RuntimeError, match="no ContextBundle"):
        policy.decide(_first_request(deps))


def test_the_bundle_history_is_the_code_generated_job_lines() -> None:
    demo = Demo()
    first = demo.session(0)
    bundle = demo.policy.bundles[str(first.ref.session_id)]

    assert bundle.ledger is not None
    assert bundle.ledger.completed_objectives == []
    lines = job_lines(bundle)
    assert lines == []
    # a seed observation is marked by its summary prefix, and its raw value is untrusted text
    assert any(
        observation.summary.startswith("campaign seed target")
        for observation in bundle.observations
    )


def _complete(demo: Demo, job_id: str, status: str) -> None:
    _set_status(demo, job_id, status)


def _set_status(demo: Demo, job_id: str, status: str) -> None:
    job = demo.job_service.jobs.jobs[job_id]
    job["status"] = status


def _call(response: Any) -> dict[str, Any]:
    from aegis.m03_agent.wire import blocks

    return next(block["call"] for block in blocks(response.message) if block["type"] == "tool_call")


def _empty_bundle() -> Any:
    from aegis.contracts_gen.agent.context_bundle_v2_schema import ContextBundle

    return ContextBundle.model_validate(
        {
            "campaign_id": "01934f6a-0000-7000-8000-000000000001",
            "session_id": "01934f6a-0000-7000-8000-0000000000aa",
            "objective": {
                "objective_id": "01934f6a-0000-7000-8000-000000000005",
                "text": "demo",
            },
            "policy_version": "roe-10",
            "graph_revision": 0,
            "observations": [],
            "capabilities": [],
            "budget": {"max_steps": 4},
        }
    )


def _first_request(deps: Any) -> Any:
    """A `model-request.v2` naming a session the policy never saw."""
    from aegis.contracts_gen.agent.model_request_v2_schema import ModelRequest

    return ModelRequest.model_validate(
        {
            "provider": "openai",
            "model": "scripted-lab",
            "messages": [{"role": "user", "content": [{"type": "text", "text": "plan"}]}],
            "campaign_id": "01934f6a-0000-7000-8000-000000000001",
            "session_id": "01934f6a-0000-7000-8000-0000000000aa",
            "trace_id": "0123456789abcdef0123456789abcdef",
            "max_output_tokens": 256,
        }
    )


def test_a_services_objective_continues_to_the_port_scan_after_dnsx() -> None:
    """G1.6a: the policy reads the objective, then scans the addresses the resolution recorded.

    `make demo-discovery` states that it wants the services on the resolved addresses, so the same
    scripted policy adds one step after DNSx. The targets can only come from the bundle's `ip:`
    observations (M27's rows), never from the lab inventory - that is what the demo proves.
    """
    from aegis.m03_agent.fake_policy import DISCOVER, SERVICE_PORTS

    demo = Demo(
        objective=(
            "Enumerate the lab zone, resolve the names it found, then discover which ports and "
            "services those addresses expose"
        )
    )
    first = demo.session(0)
    assert _call(demo.policy.responses[-1])["name"] == ENUMERATE
    _complete(demo, first.outcome.job_ids[0], "SUCCEEDED")
    demo.record_discovered("www.internal.example")

    second = demo.session(1)
    resolve_call = _call(demo.policy.responses[-1])
    assert resolve_call["name"] == RESOLVE
    resolve_job = second.outcome.job_ids[0]
    _complete(demo, resolve_job, "SUCCEEDED")

    # M27 records the addresses the resolution found; the bundle carries them as `asset.seen` refs.
    for index, address in enumerate(("10.114.53.211", "10.114.53.212")):
        demo.observations.append(
            {
                "observation_id": f"01934f6a-0000-7000-8000-0000000000a{index}",
                "subject": f"ip:{address}",
                "predicate": "asset.seen",
                "value": True,
                "revision": len(demo.observations) + 1,
                "confidence": 1.0,
            }
        )

    third = demo.session(2)
    discover_call = _call(demo.policy.responses[-1])
    assert discover_call["name"] == DISCOVER
    assert discover_call["arguments"]["input"]["targets"] == [
        "ip:10.114.53.211",
        "ip:10.114.53.212",
    ]
    assert discover_call["arguments"]["input"]["ports"] == list(SERVICE_PORTS)
    assert discover_call["arguments"]["depends_on"] == [resolve_job]

    _complete(demo, third.outcome.job_ids[0], "SUCCEEDED")
    fourth = demo.session(3)
    assert fourth.outcome.stop_reason == "objective_met"
    assert "service discovery" in str(fourth.result["summary"])
    assert [job["capability"] for job in _job_rows(demo.job_service)] == [
        ENUMERATE,
        RESOLVE,
        DISCOVER,
    ]


def test_a_dns_only_objective_stops_before_the_port_scan() -> None:
    """`make demo-g1` keeps its two-job chain: its objective never asks for services or ports."""
    from aegis.m03_agent.fake_policy import DISCOVER

    demo = Demo()
    first = demo.session(0)
    _complete(demo, first.outcome.job_ids[0], "SUCCEEDED")
    demo.record_discovered("www.internal.example")
    second = demo.session(1)
    _complete(demo, second.outcome.job_ids[0], "SUCCEEDED")
    for index, address in enumerate(("10.114.53.211",)):
        demo.observations.append(
            {
                "observation_id": f"01934f6a-0000-7000-8000-0000000000b{index}",
                "subject": f"ip:{address}",
                "predicate": "asset.seen",
                "value": True,
                "revision": len(demo.observations) + 1,
                "confidence": 1.0,
            }
        )
    third = demo.session(2)
    assert third.outcome.stop_reason == "objective_met"
    assert DISCOVER not in [job["capability"] for job in _job_rows(demo.job_service)]
