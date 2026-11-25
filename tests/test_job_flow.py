"""The M06 job flow end to end on real containers (G1.3a acceptance).

Covers what the card names: a job runs and its output becomes evidence plus a submitted envelope
with `dedup_key = job:<id>:envelope`; timeout and cancel stop the container, still collect what it
wrote and remove it; a restarted runner reconciles the containers of live jobs without starting a
second one; and an egress job's only way out is the broker.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Iterator
from typing import Any

import pytest

from aegis.common.ports import ContainerSpec
from aegis.m05_registry.signing import KeyRing
from aegis.m06_runner import envelope as envelopes
from aegis.m06_runner.job import JobPlan, JobRunner
from aegis.m06_runner.lifecycle import JobClaim, JobLifecycle
from aegis.m06_runner.podman import PodmanRunner
from aegis.m06_runner.values import text
from tests.fakes.evidence_store import FakeEvidenceStore

from . import m06_support

pytestmark = [pytest.mark.podman]
if not m06_support.podman_available():
    pytestmark.append(pytest.mark.skip(reason="rootless podman is not installed on this host"))

MIB = 1024 * 1024


@pytest.fixture(scope="session")
def probe_image() -> str:
    m06_support.require_podman()
    return m06_support.build_probe_image()


@pytest.fixture()
def runner(tmp_path_factory: pytest.TempPathFactory, probe_image: str) -> Iterator[PodmanRunner]:
    instance = PodmanRunner(base_dir=tmp_path_factory.mktemp("flows"), broker_image=probe_image)
    try:
        yield instance
    finally:
        instance.reconcile([])
        m06_support.remove_tree(instance.base_dir)


@pytest.fixture()
def ingestion() -> Iterator[m06_support.FakeIngestion]:
    fake = m06_support.FakeIngestion().start()
    try:
        yield fake
    finally:
        fake.stop()


def _plan(
    image: str,
    *,
    job_id: str | None = None,
    input_values: dict[str, object] | None = None,
    timeout_seconds: int | None = None,
    args_template: list[str] | None = None,
    egress: bool = False,
    egress_sources: list[dict[str, Any]] | None = None,
    platform_cidrs: tuple[str, ...] = (),
    target_bound_ip: str | None = None,
) -> JobPlan:
    manifest, raw = m06_support.probe_manifest(
        image,
        timeout_seconds=timeout_seconds,
        args_template=args_template,
        egress=egress,
        egress_sources=egress_sources,
        target_bound=target_bound_ip is not None,
    )
    if target_bound_ip is not None:
        values = input_values or {
            "targets": [target_bound_ip],
            "ports": [8080],
            "max_results": 1,
        }
        binding = {
            "mode": "broker",
            "target_binding": "required",
            "entries": [f"{target_bound_ip}:8080"],
            "target_addresses": [target_bound_ip],
        }
        refs = [{"canonical_key": f"ip:{target_bound_ip}"}]
    else:
        values = input_values or {"targets": ["internal.example"], "max_results": 2}
        refs = [{"canonical_key": "dns:internal.example"}]
        if egress:
            binding = {
                "mode": "broker",
                "target_binding": "none",
                "entries": [
                    f"{source['hosts'][0]}:{source['ports'][0]}" for source in egress_sources or []
                ],
                "target_addresses": [],
            }
        else:
            binding = {
                "mode": "none",
                "target_binding": "none",
                "entries": [],
                "target_addresses": [],
            }
    task = m06_support.task_for_manifest(
        manifest,
        raw,
        targets=refs,
        input=values,
        egress_binding=binding,
        # An egress job on this test host runs on the internet profile (its own network plus the
        # broker on the uplink); the lab profile is the G1.5c deployment and is covered by
        # `tests/test_m06_profiles.py`.
        network_profile="internet" if egress else "lab",
    )
    return JobPlan(
        job_id=job_id or envelopes.new_id(),
        task=task,
        manifest=manifest,
        input=values,
        manifest_bytes=raw,
        task_body=m06_support.body_of(task),
        platform_cidrs=platform_cidrs,
        per_host_rps=5.0 if egress else None,
        per_host_max_connections=2 if egress else None,
    )


def _job_runner(
    runner: PodmanRunner,
    store: FakeEvidenceStore,
    ingestion_url: str | None,
    token: str = "token",
    *,
    lifecycle: JobLifecycle | None = None,
) -> JobRunner:
    ingestion = (
        envelopes.HttpIngestionClient(ingestion_url, token) if ingestion_url is not None else None
    )
    return JobRunner(
        runner,
        store,
        key_ring=KeyRing.dev(),
        ingestion=ingestion,
        extra_parser_python_path=[str(m06_support.CONTAINER_DIR)],
        lifecycle=lifecycle,
    )


class RecordingLifecycle(JobLifecycle):
    """A lifecycle double: records the calls, no database (the DB tests live elsewhere)."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    def claim(self, job_id: str) -> JobClaim | None:
        self.calls.append(("claim", job_id))
        return JobClaim(job_id=job_id, generation=1, attempt=1)

    def running(self, claim: JobClaim) -> bool:
        self.calls.append(("running", claim.job_id))
        return True

    def collecting(self, claim: JobClaim) -> bool:
        self.calls.append(("collecting", claim.job_id))
        return True

    def cancel_requested(self, job_id: str) -> bool:
        return False

    def finish(
        self,
        claim: JobClaim,
        status: str,
        *,
        envelope_event_id: str | None = None,
        error: object = None,
        evidence_refs: object = (),
    ) -> str:
        self.calls.append(("finish", (status, envelope_event_id)))
        return "terminalized"


def test_job_uploads_evidence_and_submits_one_envelope(
    runner: PodmanRunner, probe_image: str, ingestion: m06_support.FakeIngestion
) -> None:
    store = FakeEvidenceStore()
    plan = _plan(probe_image)
    job_runner = _job_runner(runner, store, ingestion.base_url, ingestion.service_token)
    outcome = job_runner.execute(plan)

    assert outcome.status == "succeeded", outcome.error
    assert outcome.wait is not None
    assert outcome.run is not None and outcome.run.status == "exited"
    assert outcome.collected is not None
    assert sorted(outcome.collected.local_refs) == ["result-jsonl", "targets-seen-txt"]
    assert len(outcome.evidence) == 2
    for stored in outcome.evidence:
        assert store.verify(stored.evidence_id) is True

    assert outcome.parser is not None and outcome.parser.ok
    assert outcome.envelope is not None
    assert str(outcome.envelope.dedup_key) == f"job:{plan.job_id}:envelope"
    assert outcome.envelope.status == "succeeded"
    assert outcome.receipt is not None and outcome.receipt.accepted is True

    assert len(ingestion.received) == 1
    body = ingestion.received[0].body
    assert body["dedup_key"] == f"job:{plan.job_id}:envelope"
    assert body["job_id"] == plan.job_id
    assert body["provenance"]["seed_targets"] == [
        reference.model_dump(mode="json") for reference in plan.task.targets
    ]
    assert body["provenance"]["input_fingerprint"] == envelopes.input_fingerprint(plan.input)
    assert body["coverage"]["subjects"] == ["dns:h0.internal.example", "dns:h1.internal.example"]
    assert {item["local_ref"] for item in body["evidence"]} == {"result-jsonl", "targets-seen-txt"}

    # The container is gone, the output stays for the record.
    assert runner.list_jobs() == ()
    assert (runner.layout(plan.job_id).output / "result.jsonl").exists()
    snapshot = runner.layout(plan.job_id).root / "envelope.json"
    assert json.loads(snapshot.read_text())["dedup_key"] == f"job:{plan.job_id}:envelope"


def test_the_lifecycle_seam_is_reported_in_order(
    runner: PodmanRunner, probe_image: str, ingestion: m06_support.FakeIngestion
) -> None:
    """M06 consumes VALIDATING: claim, RUNNING, COLLECTING, then SUCCEEDED with the receipt id."""
    lifecycle = RecordingLifecycle()
    plan = _plan(probe_image)
    job_runner = _job_runner(
        runner,
        FakeEvidenceStore(),
        ingestion.base_url,
        ingestion.service_token,
        lifecycle=lifecycle,
    )
    outcome = job_runner.execute(plan)
    assert outcome.status == "succeeded", outcome.error
    assert outcome.receipt is not None
    event_id = text(outcome.receipt.event_id)
    assert [name for name, _value in lifecycle.calls] == [
        "claim",
        "running",
        "collecting",
        "finish",
    ]
    assert lifecycle.calls[0] == ("claim", plan.job_id)
    assert lifecycle.calls[-1] == ("finish", ("SUCCEEDED", event_id))


def test_a_task_that_fails_signature_verification_never_starts_a_container(
    runner: PodmanRunner, probe_image: str
) -> None:
    plan = _plan(probe_image)
    tampered = dict(plan.task_body or {})
    tampered["priority"] = 99  # anything outside the signature makes the task inert
    job_runner = _job_runner(runner, FakeEvidenceStore(), None)
    outcome = job_runner.execute(
        JobPlan(
            job_id=plan.job_id,
            task=plan.task,
            manifest=plan.manifest,
            input=plan.input,
            manifest_bytes=plan.manifest_bytes,
            task_body=tampered,
        )
    )
    assert outcome.status == "failed"
    assert outcome.error is not None and "signature rejected" in outcome.error
    assert [error["code"] for error in outcome.errors] == ["POLICY_DENIED"]
    assert runner.list_jobs() == ()


def test_resubmit_sends_the_frozen_snapshot_again(
    runner: PodmanRunner, probe_image: str, ingestion: m06_support.FakeIngestion
) -> None:
    store = FakeEvidenceStore()
    plan = _plan(probe_image)
    job_runner = _job_runner(runner, store, ingestion.base_url, ingestion.service_token)
    assert job_runner.execute(plan).receipt is not None
    again = job_runner.resubmit(plan)
    assert again is not None
    assert again.duplicate is True
    assert len(ingestion.received) == 2
    assert ingestion.received[0].body == ingestion.received[1].body


def test_timeout_collects_output_then_removes_the_container(
    runner: PodmanRunner, probe_image: str, ingestion: m06_support.FakeIngestion
) -> None:
    store = FakeEvidenceStore()
    plan = _plan(
        probe_image,
        timeout_seconds=10,
        args_template=[
            "python3",
            "-m",
            "aegis_probe.tool",
            "--lines",
            "1",
            "--sleep",
            "60",
        ],
    )
    job_runner = _job_runner(runner, store, ingestion.base_url, ingestion.service_token)
    started = time.monotonic()
    outcome = job_runner.execute(plan)
    elapsed = time.monotonic() - started

    assert elapsed < 40
    assert outcome.status == "failed"
    assert outcome.wait is not None and outcome.wait.timed_out is True
    assert outcome.run is not None and outcome.run.status == "timeout"
    assert [error["code"] for error in outcome.errors] == ["EXECUTION_TIMEOUT"]
    assert outcome.collected is not None and outcome.collected.files
    assert outcome.evidence
    assert outcome.envelope is not None and outcome.envelope.status == "failed"
    assert outcome.envelope.errors[0].code == "EXECUTION_TIMEOUT"
    assert runner.list_jobs() == ()
    assert (runner.layout(plan.job_id).output / "result.jsonl").exists()


def test_a_job_over_its_output_cap_is_stopped_and_rejected(
    runner: PodmanRunner, probe_image: str, ingestion: m06_support.FakeIngestion
) -> None:
    manifest, raw = m06_support.probe_manifest(
        probe_image,
        args_template=["python3", "-m", "aegis_probe.tool", "--lines", "1", "--big-mb", "8"],
    )
    manifest.spec.budget.maxOutputMb = 1  # 1 MiB of output for a tool that writes 8 MiB
    task = m06_support.task_for_manifest(
        manifest,
        raw,
        targets=[{"canonical_key": "dns:internal.example"}],
        input={"targets": ["internal.example"], "max_results": 1},
        egress_binding={
            "mode": "none",
            "target_binding": "none",
            "entries": [],
            "target_addresses": [],
        },
    )
    plan = JobPlan(
        job_id=envelopes.new_id(),
        task=task,
        manifest=manifest,
        input={"targets": ["internal.example"], "max_results": 1},
        manifest_bytes=raw,
        task_body=m06_support.body_of(task),
    )
    job_runner = _job_runner(
        runner, FakeEvidenceStore(), ingestion.base_url, ingestion.service_token
    )
    outcome = job_runner.execute(plan)
    assert outcome.status == "failed"
    assert [error["code"] for error in outcome.errors] == ["OUTPUT_INVALID"]
    assert outcome.envelope is None and outcome.receipt is None
    assert ingestion.received == []
    assert runner.list_jobs() == ()
    assert runner.output_bytes(plan.job_id) <= 1 * MIB + 64 * 1024


def test_cancel_stops_collects_and_removes_without_an_envelope(
    runner: PodmanRunner, probe_image: str, ingestion: m06_support.FakeIngestion
) -> None:
    store = FakeEvidenceStore()
    plan = _plan(
        probe_image,
        args_template=[
            "python3",
            "-m",
            "aegis_probe.tool",
            "--lines",
            "1",
            "--sleep",
            "60",
        ],
    )
    job_runner = _job_runner(runner, store, ingestion.base_url, ingestion.service_token)
    deadline = time.monotonic() + 1.0
    outcome = job_runner.execute(plan, cancel=lambda: time.monotonic() > deadline)

    assert outcome.status == "cancelled"
    assert outcome.wait is not None and outcome.wait.cancelled is True
    assert outcome.collected is not None
    assert outcome.evidence
    assert outcome.envelope is None
    assert ingestion.received == []
    assert runner.list_jobs() == ()


def test_reconcile_adopts_live_jobs_and_never_duplicates_a_container(
    runner: PodmanRunner, probe_image: str
) -> None:
    job_id = m06_support.unique("reconcile")
    spec = _spec(probe_image, job_id)
    handle = runner.run(spec)
    try:
        restarted = PodmanRunner(base_dir=runner.base_dir, broker_image=probe_image)
        report = restarted.reconcile([job_id])
        assert report.adopted == (job_id,)
        assert report.removed == ()

        adopted = restarted.run(spec)
        assert adopted.container_id == handle.container_id
        assert restarted.list_jobs() == (job_id,)
        assert restarted.inspect(adopted).status in {"running", "created"}
    finally:
        runner.stop(handle)
    restarted = PodmanRunner(base_dir=runner.base_dir, broker_image=probe_image)
    report = restarted.reconcile([])
    assert report.removed == (job_id,)
    assert restarted.list_jobs() == ()
    assert restarted.inspect(handle).status == "missing"
    # Output is not deleted by reconcile: it is evidence until the collector uploads it.
    assert runner.layout(job_id).output.is_dir()


def test_a_second_runner_on_the_same_host_never_touches_this_runners_jobs(
    runner: PodmanRunner, probe_image: str
) -> None:
    """Two CI jobs (or a blue/green restart) share a host; reconcile() is owner-scoped.

    This is the regression test for a real failure: a concurrent suite's teardown called
    reconcile([]) and removed the containers of the other process.
    """
    job_id = m06_support.unique("owner")
    handle = runner.run(_spec(probe_image, job_id))
    try:
        other = PodmanRunner(base_dir=runner.base_dir / "other-runner", broker_image=probe_image)
        report = other.reconcile([])
        assert report.removed == ()
        assert report.adopted == ()
        assert runner.inspect(handle).status in {"running", "created"}
    finally:
        runner.stop(handle)
        runner.reconcile([])
    assert runner.inspect(handle).status == "missing"


def test_egress_job_reaches_only_its_broker(
    tmp_path_factory: pytest.TempPathFactory,
    probe_image: str,
    ingestion: m06_support.FakeIngestion,
) -> None:
    m06_support.require_podman()
    suffix = uuid.uuid4().hex[:6]
    uplink = m06_support.create_network(f"aegis-flow-up-{suffix}", internal=False)
    target_name = f"aegis-flow-target-{suffix}"
    runner = PodmanRunner(
        base_dir=tmp_path_factory.mktemp("egress-flow"),
        broker_image=probe_image,
        uplink_network=uplink,
    )
    job_id = envelopes.new_id()
    try:
        m06_support.run_detached(
            target_name,
            probe_image,
            ["python3", "-m", "aegis_probe.target", "8080"],
            networks=[uplink],
        )
        m06_support.wait_for_logs(target_name)
        target_ip = m06_support.container_ip(target_name, uplink)
        plan = _plan(
            probe_image,
            job_id=job_id,
            egress=True,
            # The internet profile (G1.6): the broker egresses through the uplink and the job may
            # reach exactly the address the campaign signed - a private lab-network address here,
            # which is reachable because it is the task's target (`private - signed targets`).
            target_bound_ip=target_ip,
            args_template=[
                "python3",
                "-m",
                "aegis_probe.tool",
                "--lines",
                "1",
                "--proxy-url",
                f"http://{target_ip}:8080/",
                "--proxy-url",
                "http://127.1/",
                "--proxy-url",
                "http://10.255.255.1:8080/",
            ],
        )
        job_runner = _job_runner(
            runner, FakeEvidenceStore(), ingestion.base_url, ingestion.service_token
        )
        outcome = job_runner.execute(plan)

        assert outcome.status == "succeeded", outcome.error
        assert outcome.collected is not None
        http_file = runner.layout(job_id).output / "http.json"
        fetches = json.loads(http_file.read_text())
        assert fetches[0]["status"] == 200
        assert fetches[1]["status"] == 403
        assert json.loads(fetches[1]["body"])["reason"] == "DENY_LOOPBACK"
        # A private address the campaign did not sign is refused on the internet profile.
        assert fetches[2]["status"] == 403
        assert json.loads(fetches[2]["body"])["reason"] == "DENY_PRIVATE"
        records = runner.audit_records(job_id)
        reasons = {str(record["reason"]) for record in records}
        assert {"OK", "DENY_LOOPBACK", "DENY_PRIVATE"} <= reasons
        assert {str(record["network_profile"]) for record in records} == {"internet"}
        assert runner.list_jobs() == ()
        assert runner.layout(job_id).audit.joinpath("egress.jsonl").exists()
    finally:
        m06_support.podman("rm", "-f", target_name, check=False)
        runner.reconcile([])
        m06_support.remove_tree(runner.base_dir)
        m06_support.remove_network(uplink)


def _spec(image: str, job_id: str) -> ContainerSpec:
    return ContainerSpec(
        job_id=job_id,
        image_digest=image,
        args=["python3", "-c", "import time; time.sleep(60)"],
        cpu=1.0,
        memory_mb=128,
        timeout_seconds=60,
        max_output_bytes=4 * MIB,
        network="none",
    )
