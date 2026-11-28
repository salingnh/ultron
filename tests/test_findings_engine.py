"""M20 finding producer (G2 slice A): candidates become findings with their run/source history.

The pipeline is the real one: M27 ingests the fingerprinted services, M18 loads the committed intel
slices, M20's matcher records the candidates, and `FindingsEngine` raises the findings. What these
tests pin:

* every current candidate raises exactly one finding per (asset, CVE), stable fingerprint, status
  CANDIDATE, with a `finding_run` (seen=true) and a `finding_source` for the covering scan, one
  initial transition and one `finding.changed.v2` event;
* a second run adds runs, not findings; a **rescan** that observes the same product outside the
  affected range is new remediation evidence and closes the finding (FIXED, `cause=scan`);
* a candidate retracted by an intel revision alone (0008) does **not** close the finding: an
  advisory change is not a remediation, so the status stays and the withdrawal remains in the match
  decision and its `vulnerability.matched.v2` event;
* a candidate that matches again moves FIXED to REGRESSED - never a stale CANDIDATE, never a delete;
* an operator decision (FALSE_POSITIVE) is not reopened by a re-run of the matcher.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from aegis import validation
from aegis.m18_intel.sync import FeedSync
from aegis.m20_vuln.findings import EVENT_SCHEMA, FindingsEngine, finding_fingerprint
from aegis.m20_vuln.matching import Matcher
from tests import g16c_support as fixtures
from tests.db_support import requires_postgres
from tests.m23_support import CAMPAIGN_ID, connect, ingest, pipeline_database

pytestmark = requires_postgres

FINDING_EVENT = "finding.changed.v2"
LATER = "2026-11-25T09:00:00Z"


@pytest.fixture()
def database() -> Iterator[tuple[str, list[str]]]:
    with pipeline_database(jobs=4) as (dsn, jobs):
        _ingest(dsn, jobs[0])
        with connect(dsn) as connection:
            fixtures.seed_intel(dsn)
            Matcher(connection).run()
        yield dsn, jobs


def _ingest(
    dsn: str,
    job_id: str,
    observations: list[dict[str, Any]] | None = None,
    *,
    assets: list[dict[str, Any]] | None = None,
) -> Any:
    # A rescan does not re-declare assets it already knows: M27 resolves the observation subject
    # from the database (an envelope that re-declares a known asset re-resolves its provenance
    # seed and G5 quarantines it - the observation-only envelope is the shape the runners post).
    receipt = ingest(
        dsn,
        job_id,
        assets=fixtures.service_assets() if assets is None else assets,
        observations=observations or list(fixtures.service_observations()),
        coverage=fixtures.coverage(),
    )
    assert receipt.accepted and not receipt.quarantined, receipt
    return receipt


PATCHED_CPE = "cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*"


def _httpd_at(version: str, cpe: str, observed_at: str) -> list[dict[str, Any]]:
    """The G1.6c observations with the httpd product/version pinned to one timestamp."""
    values = list(fixtures.service_observations())
    for item in values:
        if item["predicate"] == "service.product" and "httpd" in json.dumps(item["value"]):
            item["value"] = {"product": "Apache httpd", "version": version, "cpe": cpe}
            item["observed_at"] = observed_at
    return values


def _patched_httpd(observed_at: str = LATER) -> list[dict[str, Any]]:
    """The same service assets, with httpd at 2.4.51 (outside CVE-2021-41773's 2.4.49)."""
    return _httpd_at("2.4.51", PATCHED_CPE, observed_at)


def _vulnerable_again(observed_at: str = "2026-11-26T09:00:00Z") -> list[dict[str, Any]]:
    """A scan that reports httpd 2.4.49 again (the vulnerable version)."""
    return _httpd_at("2.4.49", fixtures.APACHE_CPE, observed_at)


def _findings(connection: Any, *, campaign_id: str = CAMPAIGN_ID) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in connection.execute(
            "SELECT f.*, a.canonical_key FROM finding f JOIN asset a ON a.asset_id = f.asset_id"
            "  JOIN asset_campaign ac ON ac.asset_id = a.asset_id AND ac.campaign_id = %s"
            " ORDER BY a.canonical_key, f.vulnerability_ids[1]",
            (campaign_id,),
        ).fetchall()
    ]


def _by_cve(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(row["vulnerability_ids"][0]): row for row in rows}


def _runs(connection: Any, finding_id: str) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in connection.execute(
            "SELECT * FROM finding_run WHERE finding_id = %s ORDER BY observed_at, scan_id",
            (finding_id,),
        ).fetchall()
    ]


def _transitions(connection: Any, finding_id: str) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in connection.execute(
            "SELECT * FROM finding_transition WHERE finding_id = %s ORDER BY seq", (finding_id,)
        ).fetchall()
    ]


def _events(connection: Any) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in connection.execute(
            "SELECT * FROM outbox_event WHERE type = %s ORDER BY seq", (FINDING_EVENT,)
        ).fetchall()
    ]


def test_every_candidate_becomes_a_candidate_finding(database: tuple[str, list[str]]) -> None:
    dsn, jobs = database
    with connect(dsn) as connection:
        report = FindingsEngine(connection).run(campaign_id=CAMPAIGN_ID, assess=False)
        rows = _findings(connection)
        runs = {str(row["finding_id"]): _runs(connection, str(row["finding_id"])) for row in rows}
        transitions = {
            str(row["finding_id"]): _transitions(connection, str(row["finding_id"])) for row in rows
        }
        events = _events(connection)
    assert report.pairs == 3
    assert report.findings_created == 3 and report.findings_existing == 0
    assert report.runs == 3 and report.sources == 3
    assert report.transitions == 3 and report.events == 3
    assert len(rows) == 3
    for row in rows:
        cve = str(row["vulnerability_ids"][0])
        assert row["status"] == "CANDIDATE"
        assert row["severity"] == "UNRATED"
        assert row["current_assessment"] is None
        assert row["category"] == "vulnerability"
        assert row["rule_id"] == f"cve:{cve}"
        assert row["match_method"] == "cpe_range"
        assert float(row["confidence"]) in {0.6, 0.7}
        assert row["location"] == {}
        assert row["transition_seq"] == 1
        assert len(str(row["fingerprint"])) == 64
        assert str(row["fingerprint"]) == finding_fingerprint(
            str(row["asset_id"]), f"cve:{cve}", {}
        )
        assert str(row["first_job_id"]) == jobs[0]
        assert str(row["first_campaign_id"]) == CAMPAIGN_ID
        assert row["first_seen"] == row["last_seen"]
        assert row["first_seen"] == datetime(2026, 11, 24, 10, 0, tzinfo=UTC)
        finding_runs = runs[str(row["finding_id"])]
        assert len(finding_runs) == 1
        assert finding_runs[0]["seen"] is True
        assert finding_runs[0]["status"] == "CANDIDATE"
        assert finding_runs[0]["severity"] == "UNRATED"
        assert finding_runs[0]["evidence_id"] is not None
        history = transitions[str(row["finding_id"])]
        assert len(history) == 1
        assert history[0]["seq"] == 1
        assert history[0]["from_status"] is None
        assert history[0]["to_status"] == "CANDIDATE"
        assert history[0]["cause"] == "scan"
        assert history[0]["actor"] == {"kind": "module", "id": "M20"}
        assert history[0]["evidence_id"] is not None
    payloads = [dict(event["payload"]) for event in events]
    assert len(payloads) == 3
    for payload in payloads:
        assert validation.problems(EVENT_SCHEMA, payload) == []
        assert payload["new_status"] == "CANDIDATE"
        assert payload["old_status"] is None
        assert payload["cause"] == "scan"
        assert payload["changed_by"] == {"kind": "module", "id": "M20"}
        assert payload["transition_seq"] == 1
    assert {(event["type"], event["producer"]) for event in events} == {(FINDING_EVENT, "M20")}


def test_a_second_run_adds_runs_not_findings(database: tuple[str, list[str]]) -> None:
    dsn, _ = database
    with connect(dsn) as connection:
        FindingsEngine(connection).run(campaign_id=CAMPAIGN_ID, assess=False)
        before = _findings(connection)
        second = FindingsEngine(connection).run(campaign_id=CAMPAIGN_ID, assess=False)
        after = _findings(connection)
        events = _events(connection)
        runs = sum(len(_runs(connection, str(row["finding_id"]))) for row in after)
    assert second.findings_created == 0 and second.findings_existing == 3
    assert second.runs == 0 and second.transitions == 0 and second.events == 0
    assert {str(row["finding_id"]) for row in before} == {str(row["finding_id"]) for row in after}
    assert {str(row["transition_seq"]) for row in after} == {"1"}
    assert len(events) == 3
    assert runs == 3


def test_a_rescan_outside_the_range_fixes_the_finding(
    database: tuple[str, list[str]],
) -> None:
    dsn, jobs = database
    with connect(dsn) as connection:
        FindingsEngine(connection).run(campaign_id=CAMPAIGN_ID, assess=False)
        httpd = _by_cve(_findings(connection))["CVE-2021-41773"]
    _ingest(dsn, jobs[1], _patched_httpd(), assets=[])
    with connect(dsn) as connection:
        report = FindingsEngine(connection).run(campaign_id=CAMPAIGN_ID, assess=False)
        httpd_after = _by_cve(_findings(connection))["CVE-2021-41773"]
        runs = _runs(connection, str(httpd["finding_id"]))
        transitions = _transitions(connection, str(httpd["finding_id"]))
        events = _events(connection)
        sources = [
            dict(row)
            for row in connection.execute(
                "SELECT scan_id, provider FROM finding_source WHERE finding_id = %s",
                (str(httpd["finding_id"]),),
            ).fetchall()
        ]
    assert report.findings_created == 0
    # Every finding got a run for the new scan: nginx/spring were seen again, httpd's 2.4.51 is
    # outside the CVE's range, so that one run is `seen = false` and no source is written for it.
    assert report.runs == 3
    assert report.sources == 2
    assert report.fixed_by_rescan == 1
    assert report.transitions == 1 and report.events == 1
    assert str(httpd_after["status"]) == "FIXED"
    assert int(httpd_after["transition_seq"]) == 2
    # `last_seen` is when the finding was last *seen*: an out-of-range scan does not move it.
    assert httpd_after["last_seen"] == datetime(2026, 11, 24, 10, 0, tzinfo=UTC)
    assert len(runs) == 2
    by_scan = {str(row["scan_id"]): row for row in runs}
    assert by_scan[jobs[0]]["seen"] is True
    assert by_scan[jobs[1]]["seen"] is False
    assert "outside the affected range" in str(by_scan[jobs[1]]["severity_reason"])
    assert "2.4.51" in str(by_scan[jobs[1]]["severity_reason"])
    assert by_scan[jobs[1]]["evidence_id"] is not None
    # The transition exists only because the rescan is new evidence; it names the version.
    assert [row["to_status"] for row in transitions] == ["CANDIDATE", "FIXED"]
    assert transitions[1]["cause"] == "scan"
    assert transitions[1]["evidence_id"] is not None
    assert "2.4.51" in str(transitions[1]["reason"])
    # A `seen = false` run is coverage, not a provider report: the finding keeps its source.
    assert {str(row["scan_id"]) for row in sources} == {jobs[0]}
    assert len(events) == 4
    # A re-run with no new scan is not new evidence: nothing else changes.
    with connect(dsn) as connection:
        again = FindingsEngine(connection).run(campaign_id=CAMPAIGN_ID, assess=False)
        after_again = _by_cve(_findings(connection))["CVE-2021-41773"]
    assert again.transitions == 0 and again.fixed_by_rescan == 0
    assert int(after_again["transition_seq"]) == 2


def test_an_intel_withdrawal_alone_does_not_fix_the_finding(
    database: tuple[str, list[str]],
) -> None:
    """An advisory that is withdrawn is not a remediation; FIXED needs new scan evidence.

    The withdrawal must not be lost either: it stays in the newest `package_vuln_match` decision
    (`matched = false`, `retraction_reason`, new `vuln_rev_id`) and in that decision's
    `vulnerability.matched.v2` event, both written by the matcher.
    """
    dsn, _ = database
    with connect(dsn) as connection:
        FindingsEngine(connection).run(campaign_id=CAMPAIGN_ID, assess=False)
        httpd = _by_cve(_findings(connection))["CVE-2021-41773"]
    FeedSync(fixtures.connector(dsn), fixtures.MemoryStore()).sync(
        "nvd",
        "2026-11-26",
        fixtures.nvd_with_rejected_cve(),
        source_uri="nvd-slice.json",
        snapshot_at=datetime(2026, 11, 26, 6, 0, tzinfo=UTC),
    )
    with connect(dsn) as connection:
        matcher = Matcher(connection).run()
        report = FindingsEngine(connection).run(campaign_id=CAMPAIGN_ID, assess=False)
        after = _by_cve(_findings(connection))["CVE-2021-41773"]
        transitions = _transitions(connection, str(httpd["finding_id"]))
        finding_events = connection.execute(
            "SELECT count(*) AS n FROM outbox_event WHERE type = %s"
            " AND payload->>'finding_id' = %s",
            (FINDING_EVENT, str(httpd["finding_id"])),
        ).fetchone()
        decision = connection.execute(
            "SELECT matched, retraction_reason, vuln_rev_id, match_id"
            " FROM package_vuln_match WHERE package_asset_id = %s"
            " AND vulnerability_id = 'CVE-2021-41773'"
            " ORDER BY created_at DESC, match_id DESC LIMIT 1",
            (str(httpd["asset_id"]),),
        ).fetchone()
        assert decision is not None
        decision_event = connection.execute(
            "SELECT count(*) AS n FROM outbox_event WHERE type = 'vulnerability.matched.v2'"
            " AND dedup_key = %s",
            (str(decision["match_id"]),),
        ).fetchone()
    assert matcher.retracted == 1
    assert report.withdrawals_kept_open == 1 and report.fixed_by_rescan == 0
    assert report.transitions == 0 and report.events == 0
    assert len(report.withdrawals) == 1
    assert report.withdrawals[0]["reason"] == "WITHDRAWN"
    assert after["status"] == "CANDIDATE"
    assert int(after["transition_seq"]) == 1
    assert [row["to_status"] for row in transitions] == ["CANDIDATE"]
    assert finding_events is not None and int(finding_events["n"]) == 1
    assert decision is not None
    assert decision["matched"] is False
    assert decision["retraction_reason"] == "WITHDRAWN"
    assert decision_event is not None and int(decision_event["n"]) == 1


def test_a_rematched_candidate_regresses_the_fixed_finding(
    database: tuple[str, list[str]],
) -> None:
    dsn, jobs = database
    with connect(dsn) as connection:
        FindingsEngine(connection).run(campaign_id=CAMPAIGN_ID, assess=False)
        httpd = _by_cve(_findings(connection))["CVE-2021-41773"]
    _ingest(dsn, jobs[1], _patched_httpd(), assets=[])
    with connect(dsn) as connection:
        fixed = FindingsEngine(connection).run(campaign_id=CAMPAIGN_ID, assess=False)
        assert _by_cve(_findings(connection))["CVE-2021-41773"]["status"] == "FIXED"
    assert fixed.fixed_by_rescan == 1
    _ingest(dsn, jobs[2], _vulnerable_again(), assets=[])
    with connect(dsn) as connection:
        report = FindingsEngine(connection).run(campaign_id=CAMPAIGN_ID, assess=False)
        after = _by_cve(_findings(connection))["CVE-2021-41773"]
        transitions = _transitions(connection, str(httpd["finding_id"]))
    assert report.reappeared == 1
    assert after["status"] == "REGRESSED"
    assert int(after["transition_seq"]) == 3
    assert [row["to_status"] for row in transitions] == ["CANDIDATE", "FIXED", "REGRESSED"]
    assert transitions[2]["cause"] == "scan"


def test_an_operator_decision_is_not_reopened(database: tuple[str, list[str]]) -> None:
    dsn, _ = database
    with connect(dsn) as connection:
        FindingsEngine(connection).run(campaign_id=CAMPAIGN_ID, assess=False)
        httpd = _by_cve(_findings(connection))["CVE-2021-41773"]
        finding_id = str(httpd["finding_id"])
        connection.execute(
            "INSERT INTO finding_transition (finding_id, seq, from_status, to_status, reason,"
            " evidence_id, actor, cause) VALUES (%s, 2, 'CANDIDATE', 'FALSE_POSITIVE', %s, %s,"
            " %s, 'operator')",
            (
                finding_id,
                "operator decided the banner is a proxy artefact",
                _runs(connection, finding_id)[0]["evidence_id"],
                json.dumps({"kind": "operator", "id": "op-soc-1"}),
            ),
        )
        connection.execute(
            "UPDATE finding SET status = 'FALSE_POSITIVE', transition_seq = 2"
            " WHERE finding_id = %s",
            (finding_id,),
        )
        report = FindingsEngine(connection).run(campaign_id=CAMPAIGN_ID, assess=False)
        after = _by_cve(_findings(connection))["CVE-2021-41773"]
        transitions = _transitions(connection, finding_id)
    assert report.suppressed == 1
    assert report.withdrawals_kept_open == 0 and report.reappeared == 0
    assert after["status"] == "FALSE_POSITIVE"
    assert int(after["transition_seq"]) == 2
    assert [row["to_status"] for row in transitions] == ["CANDIDATE", "FALSE_POSITIVE"]


def test_a_dry_run_reports_without_writing(database: tuple[str, list[str]]) -> None:
    dsn, _ = database
    with connect(dsn) as connection:
        report = FindingsEngine(connection).run(campaign_id=CAMPAIGN_ID, dry_run=True)
        findings = _findings(connection)
        events = _events(connection)
    assert report.dry_run is True
    assert len(report.findings) == 3
    assert findings == [] and events == []


def test_a_finding_without_evidence_is_not_raised() -> None:
    """A candidate whose observation carries no evidence cannot reach CANDIDATE (G3).

    An adapter that forgets `evidence_refs` still produces a candidate (matching does not need
    evidence), but raising it to a finding would attach no proof - the transition table requires
    evidence, so the engine counts it as blocked instead of writing a finding.
    """
    from tests.support_ingestion import observation

    with pipeline_database(jobs=1) as (dsn, jobs):
        bare = [
            observation(
                fixtures.SERVICE_KEY,
                "service.product",
                {"product": "Apache httpd", "version": "2.4.49", "cpe": fixtures.APACHE_CPE},
            ),
            observation(
                fixtures.NGINX_SERVICE_KEY,
                "service.product",
                {"product": "nginx", "version": "1.18.0", "cpe": fixtures.NGINX_CPE},
            ),
            observation(fixtures.APP_KEY, "http.technology", [fixtures.SPRING_CPE, "Spring Boot"]),
        ]
        _ingest(dsn, jobs[0], bare)
        with connect(dsn) as connection:
            fixtures.seed_intel(dsn)
            Matcher(connection).run()
            report = FindingsEngine(connection).run(campaign_id=CAMPAIGN_ID, assess=False)
            findings = _findings(connection)
    assert report.blocked_no_evidence == 3
    assert report.findings_created == 0
    assert findings == []


def test_late_historical_out_of_range_evidence_is_history_not_fixed(
    database: tuple[str, list[str]],
) -> None:
    """Review round 2: an archived rescan that arrives late is history, not remediation.

    The finding is raised from the affected observation at 2026-11-24T10:00Z; a different job's
    out-of-range observation was taken at 2026-11-23T09:00Z (before it). Ingesting it later must
    write its `finding_run` but must not close the finding on older evidence.
    """
    dsn, jobs = database
    with connect(dsn) as connection:
        FindingsEngine(connection).run(campaign_id=CAMPAIGN_ID, assess=False)
        httpd = _by_cve(_findings(connection))["CVE-2021-41773"]
    _ingest(dsn, jobs[1], _patched_httpd("2026-11-23T09:00:00Z"), assets=[])
    with connect(dsn) as connection:
        report = FindingsEngine(connection).run(campaign_id=CAMPAIGN_ID, assess=False)
        after = _by_cve(_findings(connection))["CVE-2021-41773"]
        runs = _runs(connection, str(httpd["finding_id"]))
        transitions = _transitions(connection, str(httpd["finding_id"]))
        events = _events(connection)
    assert report.fixed_by_rescan == 0 and report.transitions == 0 and report.events == 0
    assert after["status"] == "CANDIDATE" and int(after["transition_seq"]) == 1
    assert after["last_seen"] == datetime(2026, 11, 24, 10, 0, tzinfo=UTC)
    assert [row["to_status"] for row in transitions] == ["CANDIDATE"]
    # The older scan is kept as history, with its own observation time.
    assert len(runs) == 2
    by_scan = {str(row["scan_id"]): row for row in runs}
    assert by_scan[jobs[1]]["seen"] is False
    assert by_scan[jobs[1]]["observed_at"] == datetime(2026, 11, 23, 9, 0, tzinfo=UTC)
    assert len(events) == 3


def test_a_batch_with_a_newer_affected_observation_does_not_close_on_the_older_rescan(
    database: tuple[str, list[str]],
) -> None:
    """The same batch can carry both; the affected observation in it is the threshold."""
    dsn, jobs = database
    with connect(dsn) as connection:
        FindingsEngine(connection).run(campaign_id=CAMPAIGN_ID, assess=False)
        httpd = _by_cve(_findings(connection))["CVE-2021-41773"]
    _ingest(dsn, jobs[1], _patched_httpd("2026-11-23T09:00:00Z"), assets=[])
    _ingest(dsn, jobs[2], _vulnerable_again("2026-11-25T10:00:00Z"), assets=[])
    with connect(dsn) as connection:
        report = FindingsEngine(connection).run(campaign_id=CAMPAIGN_ID, assess=False)
        after = _by_cve(_findings(connection))["CVE-2021-41773"]
        runs = _runs(connection, str(httpd["finding_id"]))
    assert report.fixed_by_rescan == 0 and report.transitions == 0
    assert after["status"] == "CANDIDATE" and int(after["transition_seq"]) == 1
    # The newer affected observation moved `last_seen`; both scans are history.
    assert after["last_seen"] == datetime(2026, 11, 25, 10, 0, tzinfo=UTC)
    assert len(runs) == 3
    by_scan = {str(row["scan_id"]): row for row in runs}
    assert by_scan[jobs[1]]["seen"] is False
    assert by_scan[jobs[2]]["seen"] is True


def test_a_late_archived_positive_before_the_fix_is_not_a_regression(
    database: tuple[str, list[str]],
) -> None:
    """The inverse chronology: pre-remediation evidence that arrives late stays history."""
    dsn, jobs = database
    with connect(dsn) as connection:
        FindingsEngine(connection).run(campaign_id=CAMPAIGN_ID, assess=False)
        httpd = _by_cve(_findings(connection))["CVE-2021-41773"]
    _ingest(dsn, jobs[1], _patched_httpd(), assets=[])
    with connect(dsn) as connection:
        fixed = FindingsEngine(connection).run(campaign_id=CAMPAIGN_ID, assess=False)
        assert _by_cve(_findings(connection))["CVE-2021-41773"]["status"] == "FIXED"
    assert fixed.fixed_by_rescan == 1
    # Archived scan from before the remediation (but after the creation), ingested late.
    _ingest(dsn, jobs[2], _vulnerable_again("2026-11-24T12:00:00Z"), assets=[])
    with connect(dsn) as connection:
        stale = FindingsEngine(connection).run(campaign_id=CAMPAIGN_ID, assess=False)
        after_stale = _by_cve(_findings(connection))["CVE-2021-41773"]
        transitions = _transitions(connection, str(httpd["finding_id"]))
    assert stale.reappeared == 0 and stale.transitions == 0
    assert after_stale["status"] == "FIXED" and int(after_stale["transition_seq"]) == 2
    assert [row["to_status"] for row in transitions] == ["CANDIDATE", "FIXED"]
    # A scan observed after the remediation is a real regression.
    _ingest(dsn, jobs[3], _vulnerable_again(), assets=[])
    with connect(dsn) as connection:
        report = FindingsEngine(connection).run(campaign_id=CAMPAIGN_ID, assess=False)
        after = _by_cve(_findings(connection))["CVE-2021-41773"]
        transitions = _transitions(connection, str(httpd["finding_id"]))
    assert report.reappeared == 1
    assert after["status"] == "REGRESSED" and int(after["transition_seq"]) == 3
    assert [row["to_status"] for row in transitions] == ["CANDIDATE", "FIXED", "REGRESSED"]


def test_the_history_fixtures_match_their_openapi_shapes() -> None:
    """The page and history fixtures exist only inline in OpenAPI; both must validate."""
    from aegis.common.repo import contract_path

    page = json.loads(
        contract_path("fixtures", "valid", "findings.page.json").read_text(encoding="utf-8")
    )
    history = json.loads(
        contract_path("fixtures", "valid", "finding-history.json").read_text(encoding="utf-8")
    )
    page_validator = validation.openapi_response_validator("/findings")
    assert list(page_validator.iter_errors(page)) == []
    history_validator = validation.openapi_response_validator("/findings/{finding_id}/history")
    assert list(history_validator.iter_errors(history)) == []
    single = json.loads(
        contract_path("fixtures", "valid", "finding.json").read_text(encoding="utf-8")
    )
    assert validation.problems("finding/finding.v2.schema.json", single) == []


def test_raising_assesses_every_finding_even_without_a_model(
    database: tuple[str, list[str]],
) -> None:
    """The owner decision: severity is assessed for every finding, not only KEV/EPSS ones.

    A scripted deployment has no model, so each finding records UNRATED with the reason and the
    finding keeps the pointer to that record. The same input revision is not assessed twice.
    """
    dsn, _ = database
    with connect(dsn) as connection:
        report = FindingsEngine(connection).run(campaign_id=CAMPAIGN_ID)
        rows = _findings(connection)
        assessments = connection.execute(
            "SELECT kind, trigger, model, assessment FROM severity_assessment ORDER BY created_at"
        ).fetchall()
        second = FindingsEngine(connection).run(campaign_id=CAMPAIGN_ID)
        after = connection.execute("SELECT count(*) AS n FROM severity_assessment").fetchone()
    assert report.assessments == 3 and report.assessments_created == 3
    assert report.unrated == 3
    assert len(assessments) == 3
    for row in rows:
        assert row["severity"] == "UNRATED"
        assert row["current_assessment"] is not None
    for row in assessments:
        assert row["kind"] == "rule"
        assert row["trigger"] == "scan"
        assert row["model"] is None
        record = dict(row["assessment"])
        assert record["severity"] == "UNRATED"
        assert record["failure"]["code"] == "DEPENDENCY_MISSING"
        assert validation.problems("finding/severity-assessment.v2.schema.json", record) == []
    assert second.assessments == 3 and second.assessments_created == 0
    assert second.unrated == 3
    assert after is not None and int(after["n"]) == 3


def test_raising_assesses_with_the_model_when_one_is_configured(
    database: tuple[str, list[str]],
) -> None:
    """One agent record per finding, one model call per finding, and no second call on a re-run."""
    from aegis.contracts_gen.agent.model_response_v2_schema import ModelResponse
    from aegis.m04_model.fake import FakeModelClient

    dsn, _ = database
    template = json.loads(
        (
            Path(__file__).resolve().parent.parent
            / "contracts/fixtures/valid/model-response.completed.anthropic.json"
        ).read_text(encoding="utf-8")
    )
    responses: list[ModelResponse] = []
    for cve in ("CVE-2022-22965", "CVE-2021-41773", "CVE-2021-23017"):
        payload = json.loads(json.dumps(template))
        payload["parsed"]["source_refs"] = [{"kind": "intel", "ref": f"nvd:{cve}"}]
        payload["message"]["content"][0]["text"] = json.dumps(payload["parsed"])
        responses.append(ModelResponse.model_validate(payload))
    fake = FakeModelClient(list(reversed(responses)))
    with connect(dsn) as connection:
        report = FindingsEngine(connection).run(
            campaign_id=CAMPAIGN_ID,
            model=fake,
            provider="anthropic",
            model_name="configured-model",
        )
        rows = _findings(connection)
        second = FindingsEngine(connection).run(
            campaign_id=CAMPAIGN_ID,
            model=fake,
            provider="anthropic",
            model_name="configured-model",
        )
        assessments = connection.execute(
            "SELECT kind, assessment FROM severity_assessment"
        ).fetchall()
    assert report.assessments == 3 and report.assessments_created == 3
    assert len(fake.calls) == 3
    assert {row["severity"] for row in rows} == {"MEDIUM"}
    assert all(row["current_assessment"] is not None for row in rows)
    assert all(str(row["kind"]) == "agent" for row in assessments)
    for row in assessments:
        record = dict(row["assessment"])
        assert record["assessed_by"]["model"] == "configured-model"
        assert record["source_refs"][0]["kind"] == "intel"
    assert second.assessments_created == 0
    assert len(fake.calls) == 3
