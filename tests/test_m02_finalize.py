"""M02 finishing a campaign: the matcher runs in the chain and coverage decides the reason.

Item 83 trial: the mandated 2 req/s active run found 4 services and 0 candidates, and the campaign
still said `objective_met`. Two defects, one test file:

* **the matcher never ran** - it was an operator step, so a campaign that had found a versioned
  service showed an empty vulnerability column until someone remembered the CLI. `finalize` now runs
  it for the campaign as the discovery chain's last step;
* **the scan's own coverage was ignored** - a paced probe the tool gave up on (`EGRESS_PACED`), a
  capped/denied connection or a partial run leaves `coverage.complete = false` on the job's current
  result, and the campaign must end `coverage_incomplete`, never `objective_met`.

Everything runs on the real contract chain, M27 ingestion and the M20 matcher; the intel is the
committed fixture slice (no network).
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, cast

import psycopg
import pytest
from psycopg.types.json import Jsonb

from aegis.m02_orchestrator.finalize import (
    COVERAGE_INCOMPLETE,
    MATCHING_FAILED,
    OBJECTIVE_MET,
    finalize,
    incomplete_jobs,
)
from aegis.m02_orchestrator.scheduler import PostgresScheduler
from aegis.m27_ingestion.service import IngestionService
from tests import g16c_support as fixtures
from tests import m23_support
from tests.db_support import requires_postgres
from tests.m02_support import complete_job, run_job
from tests.m23_support import CAMPAIGN_ID, connect, ingest, pipeline_database
from tests.support_ingestion import build_envelope, seed_evidence

pytestmark = requires_postgres

#: The paced probe M06 records: the broker allowed the connection, the tool had already given up.
PACED = {
    "subjects": ["ip:171.244.52.17"],
    "complete": False,
    "limitations": [
        {
            "code": "EGRESS_PACED",
            "message": (
                "1 port probe(s) on 171.244.52.17 waited longer than the tool's 1000 ms connect "
                "budget for an RoE slot and the tool had already given up; they are unprobed, not "
                "closed (ports 22)"
            ),
            "subjects": ["ip:171.244.52.17"],
        }
    ],
}


@pytest.fixture()
def database() -> Iterator[tuple[str, list[str]]]:
    with pipeline_database(jobs=2) as value:
        yield value


def _ingest_with_coverage(dsn: str, job_id: str, coverage: dict[str, Any]) -> Any:
    """One envelope whose coverage is the interesting part (the assets are the g16c fixtures)."""
    with connect(dsn) as connection:
        # The fixture's helper is typed for the tuple row factory M27 uses; the row factory is
        # irrelevant to this INSERT (tests/m23_support.ingest casts the same way).
        seed_evidence(
            cast(psycopg.Connection[tuple[object, ...]], connection),
            job_id,
            sha256=m23_support.EVIDENCE_SHA,
            size_bytes=1,
        )
    envelope = build_envelope(
        job_id,
        assets=fixtures.service_assets(),
        observations=fixtures.service_observations(),
        coverage=fixtures.coverage(),
        evidence=[m23_support.evidence_entry(job_id)],
    )
    envelope["coverage"] = coverage
    receipt = IngestionService.from_dsn(dsn).submit_payload(envelope)
    # The collector's callback is what links the job to the accepted result; M27 stores the
    # envelope and never terminalises a job itself (service.py:27).
    with connect(dsn) as connection, connection.transaction():
        connection.execute(
            "UPDATE scan_job SET envelope_event_id = %s, status = 'SUCCEEDED', finished_at = now()"
            " WHERE job_id = %s",
            (str(envelope["event_id"]), job_id),
        )
    return receipt


def _current_reason(dsn: str, campaign_id: str) -> tuple[str, str]:
    with connect(dsn) as connection:
        row = connection.execute(
            "SELECT status, status_reason FROM campaign WHERE campaign_id = %s", (campaign_id,)
        ).fetchone()
    assert row is not None
    return str(row["status"]), str(row["status_reason"])


def test_a_versioned_service_becomes_a_candidate_in_one_finalize(
    database: tuple[str, list[str]],
) -> None:
    """The chain's last step: no operator CLI, no empty vulnerability column on a finished run."""
    dsn, jobs = database
    fixtures.seed_intel(dsn)
    ingest(
        dsn,
        jobs[0],
        assets=fixtures.service_assets(),
        observations=fixtures.service_observations(),
        coverage=fixtures.coverage(),
    )
    with connect(dsn) as connection:
        result = finalize(connection, CAMPAIGN_ID, OBJECTIVE_MET)
        found = fixtures.matches(connection)

    assert result.reason == OBJECTIVE_MET
    assert result.matching_error is None
    assert result.matches == 3
    assert {row["vulnerability_id"] for row in found} == {
        "CVE-2021-41773",
        "CVE-2021-23017",
        "CVE-2022-22965",
    }


def test_a_paced_scan_ends_coverage_incomplete_not_objective_met(
    database: tuple[str, list[str]],
) -> None:
    """The item 83 test: a probe the tool gave up on is unknown, so the objective was not met."""
    dsn, jobs = database
    fixtures.seed_intel(dsn)
    receipt = _ingest_with_coverage(dsn, jobs[0], PACED)
    assert receipt.accepted is True
    with connect(dsn) as connection:
        pending = incomplete_jobs(connection, CAMPAIGN_ID)
        result = finalize(connection, CAMPAIGN_ID, OBJECTIVE_MET)
        PostgresScheduler(lambda: m23_support.connect(dsn)).finish(
            CAMPAIGN_ID, "complete", result.reason
        )

    assert [row["job_id"] for row in pending] == [jobs[0]]
    assert result.reason.startswith(f"{COVERAGE_INCOMPLETE}:")
    assert "EGRESS_PACED" in result.reason
    assert "the objective is not claimed" in result.reason
    assert result.incomplete_jobs == (jobs[0],)
    assert result.limitation_codes == ("EGRESS_PACED",)
    # The candidates are still recorded (the service was found): only the claim is withheld.
    assert result.matches == 3
    status, reason = _current_reason(dsn, CAMPAIGN_ID)
    assert status == "COMPLETED"
    assert reason.startswith(COVERAGE_INCOMPLETE)
    assert OBJECTIVE_MET not in reason
    assert result.reason == reason


def test_a_completed_job_does_not_block_the_objective(
    database: tuple[str, list[str]],
) -> None:
    dsn, jobs = database
    fixtures.seed_intel(dsn)
    receipt = _ingest_with_coverage(dsn, jobs[0], {"subjects": ["ip:192.0.2.10"], "complete": True})
    assert receipt.accepted is True
    with connect(dsn) as connection:
        result = finalize(connection, CAMPAIGN_ID, OBJECTIVE_MET)
    assert result.reason == OBJECTIVE_MET
    assert result.incomplete_jobs == ()


def test_a_matching_failure_is_reported_not_hidden(
    database: tuple[str, list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """No candidates and no signal is exactly the trial's bug: a failure has its own reason."""
    from aegis.m20_vuln.matching import Matcher

    def boom(self: Matcher, **_kwargs: Any) -> Any:
        raise psycopg.OperationalError("catalog connection lost")

    dsn, jobs = database
    ingest(dsn, jobs[0], assets=fixtures.service_assets(), coverage=fixtures.coverage())
    monkeypatch.setattr(Matcher, "run", boom)
    with connect(dsn) as connection:
        result = finalize(connection, CAMPAIGN_ID, OBJECTIVE_MET)
    assert result.reason.startswith(f"{MATCHING_FAILED}:")
    assert "OperationalError" in (result.matching_error or "")
    assert OBJECTIVE_MET not in result.reason


def test_another_stop_reason_keeps_its_name_and_carries_the_note(
    database: tuple[str, list[str]],
) -> None:
    """A campaign that stopped on its budget still says so; the coverage note is added."""
    dsn, jobs = database
    receipts = _ingest_with_coverage(dsn, jobs[0], PACED)
    assert receipts.accepted is True
    with connect(dsn) as connection:
        result = finalize(connection, CAMPAIGN_ID, "budget_exhausted")
    assert result.reason.startswith("budget_exhausted (")
    assert "EGRESS_PACED" in result.reason


# --- review round 1: a failed scan is a hole too -------------------------------------------------

TIMEOUT_ERROR = {
    "code": "EXECUTION_TIMEOUT",
    "message": "the sandbox ended the job with state timeout",
    "next_action": "RETRY",
    "retryable": True,
}


def _fail_job(dsn: str, job_id: str, error: dict[str, Any] | None = None) -> None:
    """Terminalise a job the way M06's callback would (FAILED needs an error.v2 object)."""
    run_job(dsn, job_id)  # a FAILED callback is only legal for a job the runner started
    assert (
        complete_job(dsn, job_id, status="FAILED", error=error or TIMEOUT_ERROR) == "terminalized"
    )


def _cancel_job(dsn: str, job_id: str) -> None:
    """An operator cancel of a queued job: intent, then the one terminal CAS (C06)."""
    with connect(dsn) as connection, connection.transaction():
        connection.execute(
            "SELECT aegis.request_job_cancel(%s, %s, %s)",
            (job_id, Jsonb({"kind": "operator", "id": "op-finalize"}), "test cancel"),
        )
    assert complete_job(dsn, job_id, status="CANCELLED") == "terminalized"


def _reopen_job(dsn: str, job_id: str) -> None:
    """Reopen a terminal job the way M06's re-execution does (generation+1, clean result)."""
    with connect(dsn) as connection, connection.transaction():
        connection.execute(
            "UPDATE scan_job SET status = 'QUEUED', generation = generation + 1, attempt = 1,"
            " started_at = NULL, finished_at = NULL, envelope_event_id = NULL, error = NULL"
            " WHERE job_id = %s",
            (job_id,),
        )


def test_a_failed_scan_job_ends_coverage_incomplete(database: tuple[str, list[str]]) -> None:
    """A scan that never produced a result is not "nothing found": it is an unknown surface.

    Review round 1 (item 83): the campaign could still end `objective_met` while its only port scan
    had failed - the model's stop proposal was never checked against the jobs that produced no
    result at all.
    """
    dsn, jobs = database
    fixtures.seed_intel(dsn)
    failure = {**TIMEOUT_ERROR, "code": "EXECUTION_TIMEOUT"}
    _fail_job(dsn, jobs[0], failure)
    with connect(dsn) as connection:
        pending = incomplete_jobs(connection, CAMPAIGN_ID)
        result = finalize(connection, CAMPAIGN_ID, OBJECTIVE_MET)
        PostgresScheduler(lambda: m23_support.connect(dsn)).finish(
            CAMPAIGN_ID, "complete", result.reason
        )

    assert [row["job_id"] for row in pending] == [jobs[0]]
    assert pending[0]["status"] == "FAILED"
    assert pending[0]["error_code"] == "EXECUTION_TIMEOUT"
    assert result.reason.startswith(f"{COVERAGE_INCOMPLETE}:")
    assert "1 job(s) did not complete" in result.reason
    assert "EXECUTION_TIMEOUT" in result.reason
    assert "the objective is not claimed" in result.reason
    assert result.incomplete_jobs == (jobs[0],)
    assert result.failure_codes == ("EXECUTION_TIMEOUT",)
    status, reason = _current_reason(dsn, CAMPAIGN_ID)
    assert status == "COMPLETED"
    assert reason.startswith(COVERAGE_INCOMPLETE)
    assert OBJECTIVE_MET not in reason


def test_a_cancelled_scan_job_ends_coverage_incomplete(
    database: tuple[str, list[str]],
) -> None:
    dsn, jobs = database
    _cancel_job(dsn, jobs[0])
    with connect(dsn) as connection:
        result = finalize(connection, CAMPAIGN_ID, OBJECTIVE_MET)
    assert result.reason.startswith(f"{COVERAGE_INCOMPLETE}:")
    assert "did not complete" in result.reason
    assert "CANCELLED" in result.reason
    assert result.failure_codes == ("CANCELLED",)


def test_a_job_that_failed_then_succeeded_does_not_block_objective_met(
    database: tuple[str, list[str]],
) -> None:
    """The verdict is the job's *current* state: a successful re-run replaces the failure."""
    dsn, jobs = database
    fixtures.seed_intel(dsn)
    _fail_job(dsn, jobs[0])
    _reopen_job(dsn, jobs[0])
    receipt = _ingest_with_coverage(dsn, jobs[0], {"subjects": ["ip:192.0.2.10"], "complete": True})
    assert receipt.accepted is True
    assert receipt.duplicate is False
    with connect(dsn) as connection:
        result = finalize(connection, CAMPAIGN_ID, OBJECTIVE_MET)
    assert result.reason == OBJECTIVE_MET
    assert result.incomplete_jobs == ()
    assert result.failure_codes == ()


def test_a_failed_job_and_a_paced_job_are_named_together(
    database: tuple[str, list[str]],
) -> None:
    """Two kinds of hole, one reason: the count, the capabilities and the codes, not a summary."""
    dsn, jobs = database
    fixtures.seed_intel(dsn)
    _fail_job(dsn, jobs[0])
    receipt = _ingest_with_coverage(dsn, jobs[1], PACED)
    assert receipt.accepted is True
    with connect(dsn) as connection:
        result = finalize(connection, CAMPAIGN_ID, OBJECTIVE_MET)
    assert result.reason.startswith(f"{COVERAGE_INCOMPLETE}:")
    assert "1 job(s) report incomplete scan coverage" in result.reason
    assert "EGRESS_PACED" in result.reason
    assert "1 job(s) did not complete" in result.reason
    assert "EXECUTION_TIMEOUT" in result.reason
    assert set(result.incomplete_jobs) == set(jobs)
    assert result.failure_codes == ("EXECUTION_TIMEOUT",)
    assert result.limitation_codes == ("EGRESS_PACED",)
