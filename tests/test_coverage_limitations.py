"""Coverage limitations from the broker audit: a paced connection is unknown, never closed.

G1.6 Decision A says a scan that could not conclude a port must report incomplete coverage. The
broker's caps pace connections instead of refusing them (a refusal reads as "closed"), so the
failure mode the item 83 trial found is *silent*: the broker allows every CONNECT, the tool gives up
while it waits for a RoE slot, and nothing in the output or the audit says so. These tests pin the
two halves that close that gap:

* the audit carries `waited_ms`, the delay the connection paid for its slot;
* a wait longer than the job's declared `connectTimeoutMs` becomes one `EGRESS_PACED` limitation per
  address, naming the unprobed ports and the `ip:` subject, and makes `coverage.complete` false.
"""

from __future__ import annotations

from typing import Any

from aegis.m06_runner.job import _egress_limitations


def _allow(host: str = "171.244.52.17", port: int = 22, waited_ms: int = 1200) -> dict[str, Any]:
    return {
        "decision": "allow",
        "reason": "OK",
        "host": host,
        "port": port,
        "pinned": host,
        "waited_ms": waited_ms,
        "dial_ms": 3,
        "upstream": "open",
    }


def test_a_wait_inside_the_tool_budget_is_not_a_limitation() -> None:
    assert _egress_limitations([_allow(waited_ms=400)], 1000) == []


def test_a_paced_probe_past_the_budget_names_the_port_and_the_address() -> None:
    limitations = _egress_limitations(
        [
            _allow(port=22, waited_ms=1500),
            _allow(port=80, waited_ms=2100),
            _allow(port=443, waited_ms=100),  # admitted inside the budget: no claim about it
            _allow(host="171.244.52.15", port=80, waited_ms=1300),
        ],
        1000,
    )
    assert [item["code"] for item in limitations] == ["EGRESS_PACED", "EGRESS_PACED"]
    first = next(item for item in limitations if "171.244.52.17" in item["message"])
    assert "22" in first["message"] and "80" in first["message"]
    assert "443" not in first["message"]
    assert "unprobed, not closed" in first["message"]
    assert first["subjects"] == ["ip:171.244.52.17"]
    assert limitations[0]["subjects"] != limitations[1]["subjects"]


def test_without_a_declared_budget_the_broker_cannot_judge_the_wait() -> None:
    """A tool whose timeout the profile does not state gets no claim, not a guessed one."""
    assert _egress_limitations([_allow(waited_ms=9000)], None) == []


def test_a_paced_name_target_still_reports_but_invents_no_asset() -> None:
    record = {
        "decision": "allow",
        "reason": "OK",
        "host": "www.example.test",
        "port": 443,
        "pinned": "93.184.216.34",
        "waited_ms": 5000,
        "dial_ms": 2,
        "upstream": "open",
    }
    limitations = _egress_limitations([record], 1000)
    assert len(limitations) == 1
    # The dialled address is the limit's subject; the name stays in the message.
    assert limitations[0]["subjects"] == ["ip:93.184.216.34"]
    assert "www.example.test" in limitations[0]["message"]


def test_a_denied_and_a_paced_run_report_both_causes() -> None:
    denied = {
        "decision": "deny",
        "reason": "DENY_LOOPBACK",
        "host": "127.0.0.1",
        "port": 22,
        "waited_ms": 0,
    }
    limitations = _egress_limitations([denied, _allow(waited_ms=1800)], 1000)
    assert [item["code"] for item in limitations] == ["EGRESS_DENIED", "EGRESS_PACED"]


def test_many_paced_ports_are_listed_briefly() -> None:
    records = [_allow(port=port, waited_ms=2000) for port in range(1, 41)]
    limitations = _egress_limitations(records, 1000)
    assert len(limitations) == 1
    message = limitations[0]["message"]
    assert len(message) <= 1000
    assert "and 20 more" in message


def test_a_paced_job_envelope_reports_incomplete_coverage(tmp_path: Any) -> None:
    """The whole M06 side: a profile budget plus a paced audit record becomes `complete = false`.

    This is the wiring the item 83 trial was missing: `_build_and_submit` reads the job's declared
    connect budget, compares it with the audit's `waited_ms`, and the envelope's own coverage says
    the run was incomplete - which is what M02 reads before it may claim `objective_met`.
    """
    from pathlib import Path

    from aegis.m06_runner import envelope as envelopes
    from aegis.m06_runner.job import JobOutcome, JobPlan, JobRunner
    from aegis.m06_runner.podman import JobLayout
    from tests import m06_support
    from tests.fakes.evidence_store import FakeEvidenceStore

    image = "sha256:" + "ab" * 32
    manifest, raw = m06_support.probe_manifest(image, egress=True)
    binding = {
        "mode": "broker",
        "target_binding": "none",
        "entries": ["93.184.216.34:443"],
        "target_addresses": [],
    }
    values = {"targets": ["internal.example"], "max_results": 1}
    task = m06_support.task_for_manifest(
        manifest,
        raw,
        targets=[{"canonical_key": "dns:internal.example"}],
        input=values,
        egress_binding=binding,
        network_profile="internet",
    )
    plan = JobPlan(
        job_id=envelopes.new_id(),
        task=task,
        manifest=manifest,
        input=values,
        manifest_bytes=raw,
        task_body=m06_support.body_of(task),
        authorization=m06_support.AUTHORIZATION,
        per_host_rps=5.0,
        per_host_max_connections=2,
    )

    class AuditedRunner:
        connect_timeout_ms = 1000

        def profile_entry(self, kind: str, image_digest: str) -> Any:
            from aegis.m06_runner.profile import JobProfile

            assert kind == "internet" and image_digest == image
            return JobProfile(image_digest=image_digest, connect_timeout_ms=self.connect_timeout_ms)

        def audit_records(self, job_id: str) -> list[dict[str, Any]]:
            return [_allow(waited_ms=1800)]

    layout = JobLayout(Path(tmp_path) / "job").create()
    outcome = JobOutcome(
        job_id=plan.job_id,
        status="succeeded",
        parser=type(
            "Run",
            (),
            {
                "result": {
                    "assets": [],
                    "observations": [],
                    "relationships": [],
                    "findings": [],
                    "coverage_subjects": ["dns:internal.example"],
                }
            },
        )(),
    )
    runner = AuditedRunner()
    job_runner = JobRunner(runner, FakeEvidenceStore(), key_ring=m06_support.ANY_RING)
    job_runner._build_and_submit(plan, layout, outcome, "2026-11-28T00:00:00Z")

    assert outcome.envelope is not None
    coverage = outcome.envelope.coverage
    assert coverage.complete is False
    codes = [limitation.code for limitation in coverage.limitations or []]
    assert codes == ["EGRESS_PACED"]
    message = (coverage.limitations or [None])[0]
    assert "unprobed, not closed" in (message.message if message is not None else "")
    # The envelope snapshot on disk is what a later reader (or an evidence audit) sees.
    assert '"complete":false' in (layout.root / "envelope.json").read_text().replace(" ", "")
