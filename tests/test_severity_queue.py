"""C07 severity runtime (G2 slice C): the pending queue, the honest fallbacks and the revision.

What these tests pin (each acceptance bullet of the task, on the real runtime):

* every open finding is queued - including one that is not being raised by this pass - and the
  order is KEV, then EPSS, then recency. The order only decides who spends the campaign's LLM
  budget first: the scripted answer is the same for every finding, so KEV cannot change it;
* a capped budget, a truncated or refused answer, invalid model output and a citation that does not
  resolve all store an UNRATED record with the failure and keep the raw CVSS/KEV/EPSS inputs;
* one record per finding and input revision: a retry - with any trigger - adds no row and makes no
  model call, while a new evidence run or a new intel revision for the finding's CVE is a new
  revision and one new assessment;
* an intel revision of a different CVE leaves a finding's revision untouched (selective).

The intel deltas these tests load are **simulated** feed slices: `_kev_added` edits the committed
KEV fixture to add a CVE, which is the shape CISA publishes, labelled as a test document.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest

from aegis import validation
from aegis.m04_model.fake import FakeModelClient
from aegis.m20_vuln import severity
from aegis.m20_vuln.findings import FindingsEngine
from aegis.m20_vuln.matching import Matcher
from aegis.m27_ingestion.ids import uuid7
from tests import g16c_support as fixtures
from tests import severity_support as support
from tests.db_support import requires_postgres
from tests.m23_support import CAMPAIGN_ID, connect, ingest, pipeline_database

pytestmark = requires_postgres

SEVERITY_SCHEMA = "finding/severity-assessment.v2.schema.json"
KEV_ADDED_CVE = support.KEV_ADDED_CVE


@pytest.fixture()
def database() -> Iterator[tuple[str, list[str]]]:
    with pipeline_database(jobs=2) as (dsn, jobs):
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
        yield dsn, jobs


def _findings(connection: Any) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in connection.execute(
            "SELECT f.*, a.canonical_key, a.exposure, a.criticality"
            "  FROM finding f JOIN asset a ON a.asset_id = f.asset_id"
            "  JOIN asset_campaign ac ON ac.asset_id = a.asset_id AND ac.campaign_id = %s"
            " ORDER BY a.canonical_key",
            (CAMPAIGN_ID,),
        ).fetchall()
    ]


def _by_cve(connection: Any) -> dict[str, dict[str, Any]]:
    return {str(row["vulnerability_ids"][0]): row for row in _findings(connection)}


_assessment_rows = support.assessment_rows


_completed = support.completed_response
_without_result = support.refused_response
_evidence_of = support.evidence_of
_sync_kev_added = support.sync_kev_added
_simulated_kev_added = support.simulated_kev_added


def _prompt_finding(call: Any, finding_ids: dict[str, str]) -> str:
    text = json.dumps(call.model_dump(mode="json"))
    matches = [finding_id for finding_id, marker in finding_ids.items() if marker in text]
    assert len(matches) == 1, "the prompt should carry one finding"
    return matches[0]


def test_the_queue_orders_by_kev_then_epss_and_never_by_itself(
    database: tuple[str, list[str]],
) -> None:
    """KEV first, then EPSS: ordering only decides the budget order, not the answer."""
    dsn, _ = database
    with connect(dsn) as connection:
        by_cve = _by_cve(connection)
        pending = severity.pending_findings(connection, campaign_id=CAMPAIGN_ID)
        order = [
            next(cve for cve, row in by_cve.items() if str(row["finding_id"]) == item.finding_id)
            for item in pending
        ]
        assert order == ["CVE-2021-41773", "CVE-2022-22965", KEV_ADDED_CVE]
        assert [item.kev_listed for item in pending] == [True, True, False]
        assert pending[0].epss_score is not None and pending[1].epss_score is not None
        assert pending[0].epss_score > pending[1].epss_score
        assert pending[2].epss_score is not None and pending[2].epss_score < 0.1

        fake = FakeModelClient(
            [
                _completed(_evidence_of(connection, str(by_cve["CVE-2021-41773"]["finding_id"]))),
                _completed(_evidence_of(connection, str(by_cve["CVE-2022-22965"]["finding_id"]))),
                _completed(_evidence_of(connection, str(by_cve[KEV_ADDED_CVE]["finding_id"]))),
            ]
        )
        report = severity.assess_pending(
            connection,
            campaign_id=CAMPAIGN_ID,
            model=fake,
            provider="anthropic",
            model_name="configured-model",
        )
        called = [
            _prompt_finding(call, {item.finding_id: item.finding_id for item in pending})
            for call in fake.calls
        ]
        rows = _assessment_rows(connection)
    assert report.candidates == 3 and report.assessed == 3
    assert called == [item.finding_id for item in pending]
    # The same scripted answer for all three: KEV changed the order, not the severity.
    assert report.model_calls == 3
    assert {row["severity"] for row in rows} == {"MEDIUM"}
    assert all(row["trigger"] == "scan" for row in rows)


@pytest.mark.parametrize("finish_reason", ["truncated", "refused"])
def test_a_truncated_or_refused_answer_is_unrated_with_the_reason(
    database: tuple[str, list[str]], finish_reason: str
) -> None:
    dsn, _ = database
    with connect(dsn) as connection:
        by_cve = _by_cve(connection)
        finding_id = str(by_cve["CVE-2021-41773"]["finding_id"])
        fake = FakeModelClient([_without_result(finish_reason)])
        report = severity.assess_pending(
            connection,
            campaign_id=CAMPAIGN_ID,
            only_vulnerabilities=["CVE-2021-41773"],
            model=fake,
            provider="anthropic",
            model_name="configured-model",
        )
        rows = _assessment_rows(connection)
        finding = connection.execute(
            "SELECT severity, current_assessment FROM finding WHERE finding_id = %s",
            (finding_id,),
        ).fetchone()
    assert report.created == 1 and report.unrated == 1 and report.model_calls == 0
    assert len(rows) == 1
    record = dict(rows[0]["assessment"])
    assert validation.problems(SEVERITY_SCHEMA, record) == []
    assert record["severity"] == "UNRATED"
    assert record["failure"]["code"] == "OUTPUT_INVALID"
    assert record["failure"]["finish_reason"] == finish_reason
    assert record["failure"]["model"] == "configured-model"
    assert record["raw_signals"]
    # The raw signals survive the failure: CVSS from NVD, KEV membership and the EPSS score.
    assert record["inputs"]["cvss"]["base_score"] > 0
    assert record["inputs"]["kev"]["listed"] is True
    assert record["inputs"]["kev"]["date_added"] == "2021-11-03"
    assert record["inputs"]["kev"]["catalog_version"] == "2026.11.24"
    assert record["inputs"]["epss"]["score"] == pytest.approx(0.97431)
    assert finding is not None and finding["severity"] == "UNRATED"


def test_an_invalid_model_output_is_unrated_and_keeps_the_inputs(
    database: tuple[str, list[str]],
) -> None:
    dsn, _ = database
    with connect(dsn) as connection:
        fake = FakeModelClient([support.invalid_output_response()])
        severity.assess_pending(
            connection,
            campaign_id=CAMPAIGN_ID,
            only_vulnerabilities=["CVE-2021-41773"],
            model=fake,
            provider="openai",
            model_name="configured-model",
        )
        record = dict(_assessment_rows(connection)[0]["assessment"])
    assert record["severity"] == "UNRATED"
    assert record["failure"]["code"] == "OUTPUT_INVALID"
    assert "invalid_output" in record["failure"]["message"]
    assert record["inputs"]["kev"]["listed"] is True
    assert validation.problems(SEVERITY_SCHEMA, record) == []


def test_a_citation_that_does_not_resolve_is_rejected(database: tuple[str, list[str]]) -> None:
    dsn, _ = database
    with connect(dsn) as connection:
        by_cve = _by_cve(connection)
        fake = FakeModelClient(
            [
                _completed(
                    str(by_cve["CVE-2021-41773"]["finding_id"]),
                    kind="intel",
                    ref="nvd:CVE-0000-00000",
                )
            ]
        )
        severity.assess_pending(
            connection,
            campaign_id=CAMPAIGN_ID,
            only_vulnerabilities=["CVE-2021-41773"],
            model=fake,
            provider="anthropic",
            model_name="configured-model",
        )
        record = dict(_assessment_rows(connection)[0]["assessment"])
    assert record["severity"] == "UNRATED"
    assert record["failure"]["code"] == "OUTPUT_INVALID"
    assert "do not exist" in record["failure"]["message"]
    assert "source_refs" not in record


def test_an_exhausted_budget_is_unrated_without_a_call(
    database: tuple[str, list[str]],
) -> None:
    dsn, _ = database
    with connect(dsn) as connection:
        policy_row = connection.execute(
            "SELECT policy FROM policy_snapshot WHERE campaign_id = %s"
            " AND policy_version = (SELECT current_policy_version FROM campaign"
            "                        WHERE campaign_id = %s)",
            (CAMPAIGN_ID, CAMPAIGN_ID),
        ).fetchone()
        assert policy_row is not None
        policy = dict(policy_row["policy"])
        policy["budget"] = {"max_llm_tokens": 0, "max_llm_cost_usd": 0}
        connection.execute(
            "INSERT INTO policy_snapshot (policy_version, campaign_id, policy, policy_hash,"
            " created_by) VALUES ('roe-99', %s, %s, %s, %s)",
            (
                CAMPAIGN_ID,
                json.dumps(policy),
                "0" * 64,
                json.dumps({"kind": "operator", "id": "fixture"}),
            ),
        )
        connection.execute(
            "UPDATE campaign SET current_policy_version = 'roe-99' WHERE campaign_id = %s",
            (CAMPAIGN_ID,),
        )
        fake = FakeModelClient([])
        report = severity.assess_pending(
            connection,
            campaign_id=CAMPAIGN_ID,
            only_vulnerabilities=["CVE-2021-41773"],
            model=fake,
            provider="anthropic",
            model_name="configured-model",
        )
        record = dict(_assessment_rows(connection)[0]["assessment"])
    assert report.unrated == 1 and report.model_calls == 0
    assert fake.calls == []
    assert record["severity"] == "UNRATED"
    assert record["failure"]["code"] == "POLICY_DENIED"
    assert "budget" in record["failure"]["message"]
    assert record["inputs"]["cvss"]["base_score"] > 0


def test_one_record_per_input_revision_even_across_triggers(
    database: tuple[str, list[str]],
) -> None:
    dsn, _ = database
    with connect(dsn) as connection:
        by_cve = _by_cve(connection)
        finding_id = str(by_cve["CVE-2021-41773"]["finding_id"])
        fake = FakeModelClient([_completed(_evidence_of(connection, finding_id))])
        first = severity.assess_pending(
            connection,
            campaign_id=CAMPAIGN_ID,
            only_vulnerabilities=["CVE-2021-41773"],
            trigger="scan",
            model=fake,
            provider="anthropic",
            model_name="configured-model",
        )
        # A retry with another trigger is the same revision: the stored record, no second call.
        second = severity.assess_pending(
            connection,
            campaign_id=CAMPAIGN_ID,
            only_vulnerabilities=["CVE-2021-41773"],
            trigger="operator_request",
            model=fake,
            provider="anthropic",
            model_name="configured-model",
        )
        rows = _assessment_rows(connection)
        revision = int(rows[0]["input_revision"])
        dedup = str(rows[0]["dedup_key"])
    assert first.created == 1 and second.created == 0 and second.assessed == 0
    assert len(fake.calls) == 1
    assert len(rows) == 1
    assert rows[0]["trigger"] == "scan"
    assert dedup == f"severity:{finding_id}:{revision}"


def test_a_new_evidence_run_changes_the_revision_and_queues_one_assessment(
    database: tuple[str, list[str]],
) -> None:
    dsn, jobs = database
    with connect(dsn) as connection:
        by_cve = _by_cve(connection)
        finding_id = str(by_cve["CVE-2021-41773"]["finding_id"])
        before = severity.input_revision(connection, by_cve["CVE-2021-41773"])
        fake = FakeModelClient(
            [
                _completed(_evidence_of(connection, finding_id)),
                _completed(_evidence_of(connection, finding_id)),
            ]
        )
        severity.assess_pending(
            connection,
            campaign_id=CAMPAIGN_ID,
            only_vulnerabilities=["CVE-2021-41773"],
            model=fake,
            provider="anthropic",
            model_name="configured-model",
        )
        # A new covering run (the scan observed the product again) is new input.
        connection.execute(
            "INSERT INTO finding_run (finding_id, scan_id, seen, status, severity, observed_at)"
            " VALUES (%s, %s, false, 'CANDIDATE', 'UNRATED', now() + interval '1 minute')",
            (finding_id, jobs[1]),
        )
        after_run = severity.input_revision(connection, _by_cve(connection)["CVE-2021-41773"])
        again = severity.assess_pending(
            connection,
            campaign_id=CAMPAIGN_ID,
            only_vulnerabilities=["CVE-2021-41773"],
            model=fake,
            provider="anthropic",
            model_name="configured-model",
        )
        rows = _assessment_rows(connection)
    assert after_run != before
    assert again.created == 1
    assert len(fake.calls) == 2
    assert len(rows) == 2
    assert rows[0]["trigger"] == "scan" and rows[1]["trigger"] == "scan"


def test_an_intel_revision_queues_only_the_findings_of_that_cve(
    database: tuple[str, list[str]],
) -> None:
    dsn, _ = database
    with connect(dsn) as connection:
        by_cve = _by_cve(connection)
        apache = str(by_cve["CVE-2021-41773"]["finding_id"])
        before_apache = severity.input_revision(connection, by_cve["CVE-2021-41773"])
        before_nginx = severity.input_revision(connection, by_cve[KEV_ADDED_CVE])
    _sync_kev_added(dsn)
    with connect(dsn) as connection:
        by_cve = _by_cve(connection)
        after_apache = severity.input_revision(connection, by_cve["CVE-2021-41773"])
        after_nginx = severity.input_revision(connection, by_cve[KEV_ADDED_CVE])
        pending = severity.pending_findings(
            connection, campaign_id=CAMPAIGN_ID, only_vulnerabilities=[KEV_ADDED_CVE]
        )
        assert [item.finding_id for item in pending] == [str(by_cve[KEV_ADDED_CVE]["finding_id"])]
        # The KEV addition is visible to the assessment inputs of the nginx finding.
        context = severity.SeverityAssessor(connection).context(
            str(by_cve[KEV_ADDED_CVE]["finding_id"]), trigger="intel_revision"
        )
    assert after_apache == before_apache, "an unrelated CVE's feed revision changed the revision"
    assert after_nginx != before_nginx
    assert context.inputs["kev"]["listed"] is True
    assert context.inputs["kev"]["catalog_version"] == "2026-11-29"
    assert apache != str(by_cve[KEV_ADDED_CVE]["finding_id"])


def test_a_verified_finding_is_still_assessed(database: tuple[str, list[str]]) -> None:
    """VERIFIED is an open issue: the owner decision says every finding gets a severity."""
    dsn, _ = database
    with connect(dsn) as connection:
        finding = _by_cve(connection)["CVE-2021-41773"]
        connection.execute(
            "UPDATE finding SET status = 'VERIFIED', transition_seq = transition_seq + 1"
            " WHERE finding_id = %s",
            (finding["finding_id"],),
        )
        pending = severity.pending_findings(
            connection, campaign_id=CAMPAIGN_ID, only_vulnerabilities=["CVE-2021-41773"]
        )
    assert [item.finding_id for item in pending] == [str(finding["finding_id"])]


def test_a_closed_finding_is_not_queued(database: tuple[str, list[str]]) -> None:
    dsn, _ = database
    with connect(dsn) as connection:
        finding = _by_cve(connection)["CVE-2021-41773"]
        connection.execute(
            "UPDATE finding SET status = 'FALSE_POSITIVE', transition_seq = transition_seq + 1"
            " WHERE finding_id = %s",
            (finding["finding_id"],),
        )
        pending = severity.pending_findings(
            connection, campaign_id=CAMPAIGN_ID, only_vulnerabilities=["CVE-2021-41773"]
        )
    assert pending == []


def test_withdrawal_and_distro_retraction_are_material_intel_changes(
    database: tuple[str, list[str]],
) -> None:
    """The other two feed revisions of the task: a withdrawal and distro fix data.

    Both are read by the assessment (`inputs`, and the match decision the prompt names), so both
    must change the revision - and only for the finding they name.
    """
    dsn, _ = database
    with connect(dsn) as connection:
        by_cve = _by_cve(connection)
        apache = by_cve["CVE-2021-41773"]
        nginx = by_cve[KEV_ADDED_CVE]
        before_apache = severity.input_revision(connection, apache)
        before_nginx = severity.input_revision(connection, nginx)
        snapshot = connection.execute(
            "SELECT snapshot_id FROM intel_snapshot WHERE feed = 'nvd' ORDER BY fetched_at DESC"
            " LIMIT 1"
        ).fetchone()
        assert snapshot is not None
        # A newer NVD revision that withdraws the advisory (append-only history).
        connection.execute(
            "INSERT INTO vulnerability_revision (vuln_rev_id, vulnerability_id, source,"
            " snapshot_id, withdrawn, content_hash) VALUES (%s, 'CVE-2021-41773', 'nvd', %s, true,"
            " %s)",
            (str(uuid7()), snapshot["snapshot_id"], "d" * 64),
        )
        after_withdrawal = severity.input_revision(
            connection, _by_cve(connection)["CVE-2021-41773"]
        )
        # The matcher withdraws the pair with distro fix data.
        nvd_revision = connection.execute(
            "SELECT vuln_rev_id FROM vulnerability_current"
            " WHERE vulnerability_id = 'CVE-2021-41773' AND source = 'nvd'"
        ).fetchone()
        assert nvd_revision is not None
        connection.execute(
            "INSERT INTO package_vuln_match (match_id, package_asset_id, vulnerability_id,"
            " vuln_rev_id, match_method, affected_range, matched, retraction_reason)"
            " VALUES (%s, %s, %s, %s, 'cpe_range', '2.4.49', false, 'FIXED_BY_DISTRO')",
            (
                str(uuid7()),
                str(apache["asset_id"]),
                "CVE-2021-41773",
                str(nvd_revision["vuln_rev_id"]),
            ),
        )
        after_distro = severity.input_revision(connection, _by_cve(connection)["CVE-2021-41773"])
        after_nginx = severity.input_revision(connection, _by_cve(connection)[KEV_ADDED_CVE])
    assert after_withdrawal != before_apache
    assert after_distro != after_withdrawal
    assert after_nginx == before_nginx, "another CVE's intel changed this finding's revision"
