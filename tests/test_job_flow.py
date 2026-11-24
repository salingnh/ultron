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

import pytest

from aegis.common.ports import ContainerSpec
from aegis.m06_runner import envelope as envelopes
from aegis.m06_runner.job import JobPlan, JobRunner
from aegis.m06_runner.podman import PodmanRunner
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
    egress_sources: list[dict[str, object]] | None = None,
    platform_cidrs: tuple[str, ...] = (),
) -> JobPlan:
    manifest, raw = m06_support.probe_manifest(
        image,
        timeout_seconds=timeout_seconds,
        args_template=args_template,
        egress=egress,
        egress_sources=egress_sources,
    )
    values = input_values or {"targets": ["internal.example"], "max_results": 2}
    task = m06_support.task_for_manifest(
        manifest,
        raw,
        targets=[{"canonical_key": "dns:internal.example"}],
        input=values,
    )
    return JobPlan(
        job_id=job_id or envelopes.new_id(),
        task=task,
        manifest=manifest,
        input=values,
        manifest_bytes=raw,
        platform_cidrs=platform_cidrs,
    )


def _job_runner(
    runner: PodmanRunner, store: FakeEvidenceStore, ingestion_url: str | None, token: str = "token"
) -> JobRunner:
    ingestion = (
        envelopes.HttpIngestionClient(ingestion_url, token) if ingestion_url is not None else None
    )
    return JobRunner(
        runner,
        store,
        ingestion=ingestion,
        extra_parser_python_path=[str(m06_support.CONTAINER_DIR)],
    )


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
            egress_sources=[
                {"id": "target", "hosts": [target_ip], "ports": [8080], "protocol": "http"}
            ],
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
        reasons = {str(record["reason"]) for record in runner.audit_records(job_id)}
        assert {"OK", "DENY_LOOPBACK"} <= reasons
        assert runner.list_jobs() == ()
        assert runner.layout(job_id).audit.joinpath("egress.jsonl").exists()
    finally:
        m06_support.podman("rm", "-f", target_name, check=False)
        runner.reconcile([])
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
