"""M20 intel-driven re-assessment (G2 slice C): one pass per feed revision, replay-safe.

The consumer is exercised with the real outbox machinery: its own dispatcher lease, the published
watermark it refreshes, `aegis.outbox_batch` and `aegis.consumer_advance`. The feed delta is a
**simulated** KEV catalog revision (`tests/severity_support.simulated_kev_added`), loaded through
the real M18 sync, so the `intel.revision.v2` event is the production one.

What these tests pin:

* a feed revision re-assesses exactly the findings whose CVEs it names, once, with
  `trigger=intel_revision` in the history - even though no `graph_revision` and no `scan_job` is
  created by the change;
* replaying the same events (the crash-before-checkpoint case: the cursor is moved back) adds no
  row and calls no model;
* a second live holder gets `leased=False` instead of processing the same events twice;
* the consumer checkpoints its own cursor, never M23's or M02's.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest

from aegis.m04_model.fake import FakeModelClient
from aegis.m20_vuln import cli, intel_reassess
from aegis.m20_vuln.findings import FindingsEngine
from aegis.m20_vuln.matching import Matcher
from tests import g16c_support as fixtures
from tests import severity_support as support
from tests.db_support import requires_postgres
from tests.m23_support import CAMPAIGN_ID, connect, ingest, pipeline_database

pytestmark = requires_postgres

KEV_ADDED_CVE = support.KEV_ADDED_CVE


@pytest.fixture()
def database() -> Iterator[tuple[str, list[str]]]:
    with pipeline_database(jobs=1) as (dsn, jobs):
        receipt = ingest(
            dsn,
            jobs[0],
            assets=fixtures.service_assets(),
            observations=list(fixtures.service_observations()),
            coverage=fixtures.coverage(),
        )
        assert receipt.accepted and not receipt.quarantined, receipt
        with connect(dsn) as connection:
            fixtures.seed_intel(dsn)
            Matcher(connection).run()
            FindingsEngine(connection).run(campaign_id=CAMPAIGN_ID, assess=False)
            # Drain the *initial* intel snapshot events: they describe the feed the findings were
            # raised from, not a change. Every finding gets its UNRATED record (no model here).
            intel_reassess.run_once(connection)
        yield dsn, jobs


def _counts(connection: Any) -> dict[str, int]:
    return {
        "assessments": int(
            connection.execute("SELECT count(*) AS n FROM severity_assessment").fetchone()["n"]
        ),
        "scan_jobs": int(connection.execute("SELECT count(*) AS n FROM scan_job").fetchone()["n"]),
        "graph_revisions": int(
            connection.execute("SELECT count(*) AS n FROM graph_revision").fetchone()["n"]
        ),
    }


def _records(connection: Any, finding_id: str) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in connection.execute(
            "SELECT trigger, severity, input_revision, assessment FROM severity_assessment"
            " WHERE finding_id = %s ORDER BY created_at, assessment_id",
            (finding_id,),
        ).fetchall()
    ]


def test_a_feed_revision_reassesses_only_its_finding_once(
    database: tuple[str, list[str]],
) -> None:
    dsn, _ = database
    with connect(dsn) as connection:
        before = _counts(connection)
        nginx = support.findings_by_cve(connection)[KEV_ADDED_CVE]
        finding_id = str(nginx["finding_id"])
        baseline = _records(connection, finding_id)
        assert len(baseline) == 1 and baseline[0]["severity"] == "UNRATED"
    support.sync_kev_added(dsn)
    with connect(dsn) as connection:
        fake = FakeModelClient(
            [support.completed_response(support.evidence_of(connection, finding_id))]
        )
        report = intel_reassess.run_once(
            connection, model=fake, provider="anthropic", model_name="configured-model"
        )
        after = _counts(connection)
        records = _records(connection, finding_id)
        current = connection.execute(
            "SELECT severity FROM finding WHERE finding_id = %s", (finding_id,)
        ).fetchone()
        other = support.findings_by_cve(connection)["CVE-2021-41773"]
        other_records = _records(connection, str(other["finding_id"]))
        cursor = connection.execute(
            "SELECT last_seq FROM consumer_cursor WHERE consumer = %s",
            (intel_reassess.CONSUMER,),
        ).fetchone()
        newest = connection.execute("SELECT max(seq) AS n FROM outbox_event").fetchone()
        assert newest is not None
        newest_seq = newest["n"]
    assert report.leased is True
    assert report.intel_events == 1
    # A KEV catalog revision rewrites every entry's catalog_version, so the event names all four
    # CVEs of the fixture; only the finding whose material signal changed is queued.
    assert report.impacted_cves == 4
    assert report.candidates == 1
    assert report.created == 1 and report.assessed == 1 and report.model_calls == 1
    assert len(fake.calls) == 1
    assert after["assessments"] == before["assessments"] + 1
    assert after["scan_jobs"] == before["scan_jobs"], "a feed change must not create a scan job"
    assert after["graph_revisions"] == before["graph_revisions"]
    assert len(records) == 2
    assert records[-1]["trigger"] == "intel_revision"
    assert records[-1]["severity"] == "MEDIUM"
    assert records[-1]["input_revision"] != baseline[0]["input_revision"]
    assert current is not None and str(current["severity"]) == "MEDIUM"
    # Selective: the finding of another CVE keeps its one record.
    assert len(other_records) == 1
    assert report.checkpoint == int(newest_seq)
    assert cursor is not None and int(cursor["last_seq"]) == report.checkpoint


def test_a_replayed_batch_adds_no_row_and_calls_no_model(
    database: tuple[str, list[str]],
) -> None:
    dsn, _ = database
    support.sync_kev_added(dsn)
    with connect(dsn) as connection:
        nginx = support.findings_by_cve(connection)[KEV_ADDED_CVE]
        finding_id = str(nginx["finding_id"])
        before_cursor = connection.execute(
            "SELECT last_seq FROM consumer_cursor WHERE consumer = %s",
            (intel_reassess.CONSUMER,),
        ).fetchone()
        assert before_cursor is not None
        checkpoint = int(before_cursor["last_seq"])
        fake = FakeModelClient(
            [support.completed_response(support.evidence_of(connection, finding_id))]
        )
        first = intel_reassess.run_once(
            connection, model=fake, provider="anthropic", model_name="configured-model"
        )
        # A crash after the writes but before the checkpoint: the same events are replayed.
        connection.execute(
            "UPDATE consumer_cursor SET last_seq = %s WHERE consumer = %s",
            (checkpoint, intel_reassess.CONSUMER),
        )
        replay = intel_reassess.run_once(
            connection, model=fake, provider="anthropic", model_name="configured-model"
        )
        rows = _records(connection, finding_id)
    assert first.created == 1 and len(fake.calls) == 1
    assert replay.leased is True and replay.intel_events == 1
    assert replay.created == 0 and replay.assessed == 0 and replay.candidates == 0
    assert replay.model_calls == 0
    assert len(fake.calls) == 1
    assert len(rows) == 2


def test_a_second_live_holder_is_refused_by_the_lease(
    database: tuple[str, list[str]],
) -> None:
    dsn, _ = database
    support.sync_kev_added(dsn)
    with connect(dsn) as connection:
        # Another live holder owns the lease: run_once must not process the same events.
        connection.execute(
            "SELECT aegis.outbox_dispatch_lease(%s, 'worker-b', %s)",
            (intel_reassess.DISPATCHER, 60),
        )
        refused = intel_reassess.IntelReassessor(connection, holder="worker-a").run_once()
        # The same holder renews its own lease and finishes.
        ran = intel_reassess.IntelReassessor(connection, holder="worker-b").run_once()
    assert refused.leased is False
    assert refused.events == 0 and refused.assessed == 0
    assert ran.leased is True and ran.events >= 1


def test_an_empty_outbox_is_a_quiet_pass(database: tuple[str, list[str]]) -> None:
    dsn, _ = database
    with connect(dsn) as connection:
        report = intel_reassess.run_once(connection)
    assert report.leased is True
    assert report.events == 0 and report.assessed == 0 and report.checkpoint is None


def test_the_consumer_never_touches_another_consumer_cursor(
    database: tuple[str, list[str]],
) -> None:
    dsn, _ = database
    support.sync_kev_added(dsn)
    with connect(dsn) as connection:
        connection.execute(
            "INSERT INTO consumer_cursor (consumer, last_seq) VALUES ('m23-projector#g1', 0)"
            " ON CONFLICT (consumer) DO NOTHING"
        )
        report: intel_reassess.ReassessReport = intel_reassess.run_once(connection)
        rows = {
            str(row["consumer"]): int(row["last_seq"])
            for row in connection.execute(
                "SELECT consumer, last_seq FROM consumer_cursor"
            ).fetchall()
        }
    assert rows["m23-projector#g1"] == 0
    assert rows[intel_reassess.CONSUMER] == report.checkpoint


def test_the_model_is_optional_and_a_scripted_deployment_still_records_the_change(
    database: tuple[str, list[str]],
) -> None:
    """No model configured: the new revision still gets an UNRATED record with its reason."""
    dsn, _ = database
    support.sync_kev_added(dsn)
    with connect(dsn) as connection:
        finding = support.findings_by_cve(connection)[KEV_ADDED_CVE]
        finding_id = str(finding["finding_id"])
        report = intel_reassess.run_once(connection)
        records = _records(connection, finding_id)
        before = report.assessed
    assert before == 1
    assert report.created == 1 and report.unrated == 1 and report.model_calls == 0
    record = dict(records[-1]["assessment"])
    assert record["severity"] == "UNRATED"
    assert record["trigger"] == "intel_revision"
    assert record["failure"]["code"] == "DEPENDENCY_MISSING"


def test_the_cli_prints_one_pass_as_json(
    database: tuple[str, list[str]], monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    """`python -m aegis.m20_vuln reassess` is the operator/automation entry point of the pass."""
    dsn, _ = database
    support.sync_kev_added(dsn)
    monkeypatch.setenv("AEGIS_PG_DSN", dsn)
    monkeypatch.delenv("AEGIS_SESSION_LIVE_MODEL", raising=False)
    assert cli.main(["reassess"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["leased"] is True
    assert document["created"] == 1
    assert document["model_calls"] == 0
    assert document["checkpoint"] is not None
