"""M06 job lifecycle: the M02 → M06 seam, the status chain and the one terminal callback (C06).

The database tests run the real contract chain (`migrated_database`) and create jobs through M05 and
the M02 scheduler, so the row M06 consumes is the row the other modules actually produce.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from psycopg.types.json import Jsonb

from aegis.m05_registry.registry import PostgresManifestRegistry
from aegis.m05_registry.service import PostgresJobService
from aegis.m05_registry.signing import KeyRing
from aegis.m06_runner import envelope as envelopes
from aegis.m06_runner.job import JobPlan, JobRunner
from aegis.m06_runner.lifecycle import JobClaim, JobLifecycle, LifecycleError
from aegis.m06_runner.podman import PodmanRunner
from aegis.m06_runner.values import text
from aegis.m27_ingestion.service import IngestionService
from aegis.m28_evidence.catalog import EvidenceCatalog
from tests.db_support import (
    OPERATOR,
    SeededCampaign,
    connect,
    migrated_database,
    requires_postgres,
    seed_campaign,
)
from tests.fakes.evidence_store import FakeEvidenceStore
from tests.m02_support import accept_job, scheduler_for, service
from tests.test_m05_service import FakeBinder, body

from . import m06_support

pytestmark = requires_postgres


def _validating(dsn: str) -> tuple[SeededCampaign, str]:
    campaign = seed_campaign(dsn)
    with service(dsn) as jobs:
        job_id = accept_job(jobs, campaign)
    with scheduler_for(dsn) as scheduler:
        assert scheduler.dispatch(campaign.campaign_id).claimed == (job_id,)
    return campaign, job_id


def _status(dsn: str, job_id: str) -> str:
    with connect(dsn) as conn:
        row = conn.execute("SELECT status FROM scan_job WHERE job_id = %s", (job_id,)).fetchone()
    assert row is not None
    return str(row[0])


def _history(dsn: str, job_id: str) -> list[tuple[str, str]]:
    with connect(dsn) as conn:
        rows = conn.execute(
            "SELECT from_status, to_status FROM job_status_change WHERE job_id = %s ORDER BY seq",
            (job_id,),
        ).fetchall()
    return [(str(row[0]), str(row[1])) for row in rows]


def _job_row(dsn: str, job_id: str) -> dict[str, Any]:
    with connect(dsn) as conn:
        row = conn.execute(
            "SELECT status, started_at, finished_at, envelope_event_id, error, generation, attempt"
            " FROM scan_job WHERE job_id = %s",
            (job_id,),
        ).fetchone()
    assert row is not None
    return {
        "status": str(row[0]),
        "started_at": row[1],
        "finished_at": row[2],
        "envelope_event_id": None if row[3] is None else str(row[3]),
        "error": row[4],
        "generation": int(row[5]),
        "attempt": int(row[6]),
    }


def _inbox(dsn: str, job_id: str) -> str:
    """A committed inbox row, the way M27 writes it before the job callback runs."""
    from aegis.m05_registry.ids import uuid7

    event_id = uuid7()
    with connect(dsn) as conn, conn.transaction():
        conn.execute(
            "INSERT INTO ingestion_inbox (event_id, dedup_key, job_id, payload_hash, status,"
            " hash_version) VALUES (%s, %s, %s, %s, 'received', 'aegis-c14n/1')",
            (event_id, f"job:{job_id}:envelope", job_id, "0" * 64),
        )
    return str(event_id)


def _quarantine(dsn: str, job_id: str) -> list[dict[str, Any]]:
    with connect(dsn) as conn:
        rows = conn.execute(
            "SELECT reason, attempt FROM job_callback_quarantine WHERE job_id = %s ORDER BY reason",
            (job_id,),
        ).fetchall()
    return [{"reason": str(row[0]), "attempt": int(row[1])} for row in rows]


# --- transitions -----------------------------------------------------------------------------


def test_claim_takes_a_validating_job_exactly_once() -> None:
    with migrated_database() as dsn:
        _campaign, job_id = _validating(dsn)
        lifecycle = JobLifecycle.from_dsn(dsn)

        claim = lifecycle.claim(job_id)
        assert claim == JobClaim(job_id=job_id, generation=1, attempt=1)
        row = _job_row(dsn, job_id)
        assert row["status"] == "DISPATCHED"
        assert row["started_at"] is not None
        assert lifecycle.claim(job_id) is None  # not VALIDATING any more
        assert _history(dsn, job_id) == [
            ("QUEUED", "VALIDATING"),
            ("VALIDATING", "DISPATCHED"),
        ]


def test_running_and_collecting_are_fenced_by_the_claim() -> None:
    with migrated_database() as dsn:
        _campaign, job_id = _validating(dsn)
        lifecycle = JobLifecycle.from_dsn(dsn)
        claim = lifecycle.claim(job_id)
        assert claim is not None

        assert lifecycle.running(claim) is True
        assert _status(dsn, job_id) == "RUNNING"
        assert lifecycle.running(claim) is False  # already running
        assert lifecycle.collecting(claim) is True
        assert _status(dsn, job_id) == "COLLECTING"
        stale = JobClaim(job_id=job_id, generation=1, attempt=2)
        assert lifecycle.collecting(stale) is False
        assert _history(dsn, job_id) == [
            ("QUEUED", "VALIDATING"),
            ("VALIDATING", "DISPATCHED"),
            ("DISPATCHED", "RUNNING"),
            ("RUNNING", "COLLECTING"),
        ]


def test_finish_records_the_envelope_event_and_replays_idempotently() -> None:
    with migrated_database() as dsn:
        _campaign, job_id = _validating(dsn)
        lifecycle = JobLifecycle.from_dsn(dsn)
        claim = lifecycle.claim(job_id)
        assert claim is not None and lifecycle.running(claim) and lifecycle.collecting(claim)
        event_id = _inbox(dsn, job_id)

        verdict = lifecycle.finish(
            claim,
            "SUCCEEDED",
            envelope_event_id=event_id,
            evidence_refs=[{"evidence_id": "e-1", "sha256": "a" * 64}],
        )
        assert verdict == "terminalized"
        row = _job_row(dsn, job_id)
        assert row["status"] == "SUCCEEDED"
        assert row["envelope_event_id"] == event_id
        assert row["finished_at"] is not None
        assert row["error"] is None
        assert _history(dsn, job_id)[-1] == ("COLLECTING", "SUCCEEDED")

        assert lifecycle.finish(claim, "SUCCEEDED", envelope_event_id=event_id) == "duplicate"
        stale = JobClaim(job_id=job_id, generation=1, attempt=2)
        assert lifecycle.finish(stale, "SUCCEEDED") == "quarantined"
        assert _quarantine(dsn, job_id) == [{"reason": "attempt_not_started", "attempt": 2}]


def test_failed_needs_the_contract_error_object() -> None:
    with migrated_database() as dsn:
        _campaign, job_id = _validating(dsn)
        lifecycle = JobLifecycle.from_dsn(dsn)
        claim = lifecycle.claim(job_id)
        assert claim is not None
        with pytest.raises(LifecycleError, match="error object"):
            lifecycle.finish(claim, "FAILED")
        error = envelopes.error_object("EXECUTION_TIMEOUT", "the sandbox ran out of time")
        assert lifecycle.finish(claim, "FAILED", error=error) == "terminalized"
        row = _job_row(dsn, job_id)
        assert row["status"] == "FAILED"
        assert row["error"]["code"] == "EXECUTION_TIMEOUT"


def test_a_cancel_intent_before_the_run_blocks_the_claim() -> None:
    with migrated_database() as dsn:
        _campaign, job_id = _validating(dsn)
        lifecycle = JobLifecycle.from_dsn(dsn)
        with connect(dsn) as conn, conn.transaction():
            conn.execute(
                "SELECT aegis.request_job_cancel(%s, %s, 'test cancel')",
                (job_id, Jsonb({"kind": "operator", "id": op_id()})),
            )
        assert lifecycle.cancel_requested(job_id) is True
        assert lifecycle.claim(job_id) is None
        assert lifecycle.finish(JobClaim(job_id, 1, 1), "CANCELLED") == "terminalized"
        assert _status(dsn, job_id) == "CANCELLED"


def test_cancel_without_intent_is_quarantined() -> None:
    with migrated_database() as dsn:
        _campaign, job_id = _validating(dsn)
        lifecycle = JobLifecycle.from_dsn(dsn)
        claim = lifecycle.claim(job_id)
        assert claim is not None
        assert lifecycle.finish(claim, "CANCELLED") == "quarantined"
        assert _quarantine(dsn, job_id)[0]["reason"] == "cancel_not_requested"


def op_id() -> str:
    return f"op-{uuid.uuid4().hex[:8]}"


def test_a_tampered_task_is_terminalized_failed_without_a_container() -> None:
    if not m06_support.podman_available():
        pytest.skip("rootless podman is not installed on this host")
    image = m06_support.build_probe_image()
    manifest, raw = m06_support.probe_manifest(image)
    with migrated_database() as dsn:
        import tempfile
        from pathlib import Path as _Path

        campaign = seed_campaign(dsn)
        with _probe_service(dsn, raw) as jobs:
            outcome = jobs.submit(
                body(campaign, input={"targets": [campaign.seed_domain], "max_results": 1}),
                requested_by=OPERATOR,
                idempotency_key=f"m06-{uuid.uuid4()}",
            )
            job_id = str(outcome.job["job_id"])
        with scheduler_for(dsn) as scheduler:
            assert scheduler.dispatch(campaign.campaign_id).claimed == (job_id,)
        with connect(dsn) as conn:
            row = conn.execute(
                "SELECT approved_task FROM scan_job WHERE job_id = %s", (job_id,)
            ).fetchone()
        assert row is not None
        from aegis.contracts_gen.capability.approved_task_v2_schema import ApprovedTask

        task = ApprovedTask.model_validate(row[0])
        tampered = dict(row[0])
        tampered["priority"] = 99
        runner = PodmanRunner(base_dir=_Path(tempfile.mkdtemp()), broker_image=image)
        job_runner = JobRunner(
            runner,
            FakeEvidenceStore(),
            key_ring=m06_support.ANY_RING,
            extra_parser_python_path=[str(m06_support.CONTAINER_DIR)],
            lifecycle=JobLifecycle.from_dsn(dsn),
        )
        try:
            result = job_runner.execute(
                JobPlan(
                    job_id=job_id,
                    task=task,
                    manifest=manifest,
                    input=task.input,
                    manifest_bytes=raw,
                    task_body=tampered,
                )
            )
        finally:
            runner.reconcile([])
            m06_support.remove_tree(runner.base_dir)
        assert result.status == "failed"
        assert "signature rejected" in (result.error or "")
        assert runner.list_jobs() == ()
        row = _job_row(dsn, job_id)
        assert row["status"] == "FAILED"
        assert row["error"]["code"] == "POLICY_DENIED"
        assert _history(dsn, job_id)[-1] == ("DISPATCHED", "FAILED")


# --- the whole seam on a real container ------------------------------------------------------


@contextmanager
def _probe_service(dsn: str, raw: bytes) -> Iterator[PostgresJobService]:
    registry = PostgresManifestRegistry(lambda: connect(dsn))
    registry.register(raw, registered_by={"kind": "module", "id": "M05"})
    yield PostgresJobService(
        lambda: connect(dsn),
        registry=registry,
        key_ring=KeyRing.dev(),
        binder=FakeBinder(),
    )


def test_job_runner_reports_the_whole_lifecycle(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """Accept → schedule → M06 runs → callback: the database sees the full chain and the receipt."""
    if not m06_support.podman_available():
        pytest.skip("rootless podman is not installed on this host")
    image = m06_support.build_probe_image()
    manifest, raw = m06_support.probe_manifest(image)
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn)
        with _probe_service(dsn, raw) as jobs:
            outcome = jobs.submit(
                body(campaign, input={"targets": [campaign.seed_domain], "max_results": 2}),
                requested_by=OPERATOR,
                idempotency_key=f"m06-{uuid.uuid4()}",
            )
            job_id = str(outcome.job["job_id"])
        with scheduler_for(dsn) as scheduler:
            assert scheduler.dispatch(campaign.campaign_id).claimed == (job_id,)

        with connect(dsn) as conn:
            row = conn.execute(
                "SELECT approved_task FROM scan_job WHERE job_id = %s", (job_id,)
            ).fetchone()
        assert row is not None
        from aegis.contracts_gen.capability.approved_task_v2_schema import ApprovedTask

        task = ApprovedTask.model_validate(row[0])
        runner = PodmanRunner(base_dir=tmp_path_factory.mktemp("lifecycle"), broker_image=image)
        job_runner = JobRunner(
            runner,
            FakeEvidenceStore(),
            key_ring=m06_support.ANY_RING,
            ingestion=IngestionService.from_dsn(dsn),
            extra_parser_prefixes=("adapters.probe.",),
            extra_parser_python_path=[str(m06_support.CONTAINER_DIR)],
            lifecycle=JobLifecycle.from_dsn(dsn),
            catalog=EvidenceCatalog.from_dsn(dsn),
        )
        try:
            result = job_runner.execute(
                JobPlan(
                    job_id=job_id,
                    task=task,
                    manifest=manifest,
                    input=task.input,
                    manifest_bytes=raw,
                    task_body=row[0],
                )
            )
        finally:
            runner.reconcile([])
            m06_support.remove_tree(runner.base_dir)

        assert result.status == "succeeded", result.error
        assert result.receipt is not None and result.receipt.accepted is True
        assert result.receipt.quarantined == []
        event_id = text(result.receipt.event_id)

        row = _job_row(dsn, job_id)
        assert row["status"] == "SUCCEEDED"
        assert row["envelope_event_id"] == event_id
        assert _history(dsn, job_id) == [
            ("QUEUED", "VALIDATING"),
            ("VALIDATING", "DISPATCHED"),
            ("DISPATCHED", "RUNNING"),
            ("RUNNING", "COLLECTING"),
            ("COLLECTING", "SUCCEEDED"),
        ]
        with connect(dsn) as conn:
            inbox = conn.execute(
                "SELECT dedup_key, job_id FROM ingestion_inbox WHERE event_id = %s", (event_id,)
            ).fetchone()
            evidence = conn.execute(
                "SELECT sha256, verified_at FROM evidence WHERE job_id = %s ORDER BY sha256",
                (job_id,),
            ).fetchall()
            observations = conn.execute(
                "SELECT count(*) FROM observation WHERE envelope_event_id = %s", (event_id,)
            ).fetchone()
        assert inbox is not None and inbox[0] == f"job:{job_id}:envelope"
        assert len(evidence) == len(result.collected.files if result.collected else [])
        assert all(entry[1] is not None for entry in evidence)
        assert observations is not None and int(observations[0]) == 2
