"""M26 report read model (G2 slice C): the JSON snapshot and the delta between two instants.

The report is read from append-only history: `finding_transition` gives the status an instant had,
`severity_assessment` the severity record current then, `finding_run`/`evidence` the evidence and
its SHA-256. What these tests pin:

* the snapshot validates against its OpenAPI schema, carries every finding of the campaign scope
  with its evidence hashes, and a past `as_of` shows the status/severity of that time;
* the delta compares two snapshots, so every finding is in exactly one list (fixed, regressed, new,
  changed) and each asset in at most one of new/gone - no duplicates;
* the window is validated (`from` before `to`, offsets present, valid campaign id) and the read
  model writes nothing;
* both operations are what the contract publishes (operation ids, security, responses).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest
import yaml
from fastapi.testclient import TestClient

from aegis import validation
from aegis.common.repo import repository_root
from aegis.m20_vuln import severity
from aegis.m20_vuln.findings import FindingsEngine
from aegis.m20_vuln.matching import Matcher
from aegis.m26_api import reports
from aegis.m26_api.app import API_PREFIX, create_app
from aegis.m26_api.operator import TokenAuthenticator
from aegis.m26_api.registry import RouterRegistry
from tests import campaign_support as support
from tests import g16c_support as fixtures
from tests.db_support import requires_postgres
from tests.m23_support import CAMPAIGN_ID, connect, ingest, pipeline_database

pytestmark = requires_postgres

METHODS = frozenset({"get", "post", "put", "patch", "delete"})
CONTRACT_PATHS = ("/reports/snapshot", "/reports/delta")
SEVERITY_SCHEMA = "finding/severity-assessment.v2.schema.json"


@pytest.fixture()
def database() -> Iterator[str]:
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
        yield dsn


def _client(dsn: str) -> TestClient:
    registry = RouterRegistry()
    reports.register(registry)
    app = create_app(
        registry,
        operator_authenticator=TokenAuthenticator(support.operator_tokens()),
        database_dsn=dsn,
    )
    return TestClient(app)


def _get(client: TestClient, path: str, **params: Any) -> Any:
    return client.get(f"{API_PREFIX}{path}", params=params, headers=support.auth())


def _stamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _clock(dsn: str) -> datetime:
    with connect(dsn) as connection:
        row = connection.execute("SELECT now() AS at").fetchone()
    assert row is not None
    return cast(datetime, row["at"])


def _created_at(dsn: str) -> datetime:
    """The newest transition the fixture wrote: every finding exists and is unchanged then."""
    with connect(dsn) as connection:
        row = connection.execute("SELECT max(created_at) AS at FROM finding_transition").fetchone()
    assert row is not None and row["at"] is not None
    return cast(datetime, row["at"])


def _findings(dsn: str) -> list[dict[str, Any]]:
    with connect(dsn) as connection:
        return [
            dict(row)
            for row in connection.execute(
                "SELECT f.*, a.canonical_key FROM finding f"
                "  JOIN asset a ON a.asset_id = f.asset_id"
                " ORDER BY a.canonical_key"
            ).fetchall()
        ]


def _by_cve(dsn: str) -> dict[str, dict[str, Any]]:
    return {str(row["vulnerability_ids"][0]): row for row in _findings(dsn)}


def _evidence_id(dsn: str, finding_id: str) -> str:
    with connect(dsn) as connection:
        row = connection.execute(
            "SELECT evidence_id FROM finding_run WHERE finding_id = %s AND evidence_id IS NOT NULL"
            " LIMIT 1",
            (finding_id,),
        ).fetchone()
    assert row is not None
    return str(row["evidence_id"])


def _close(dsn: str, finding_id: str, *, at: datetime) -> None:
    with connect(dsn) as connection:
        evidence_id = _evidence_id(dsn, finding_id)
        row = connection.execute(
            "SELECT transition_seq FROM finding WHERE finding_id = %s", (finding_id,)
        ).fetchone()
        assert row is not None
        seq = int(row["transition_seq"])
        connection.execute(
            "INSERT INTO finding_transition (finding_id, seq, from_status, to_status, reason,"
            " evidence_id, actor, cause, created_at)"
            " VALUES (%s, %s, 'CANDIDATE', 'FIXED', 'rescan outside the affected range', %s, %s,"
            " 'scan', %s)",
            (
                finding_id,
                seq + 1,
                evidence_id,
                json.dumps({"kind": "module", "id": "M20"}),
                at,
            ),
        )
        connection.execute(
            "UPDATE finding SET status = 'FIXED', transition_seq = %s WHERE finding_id = %s",
            (seq + 1, finding_id),
        )


def _severity_record(dsn: str, finding_id: str, *, rating: str) -> dict[str, Any]:
    """A contract-valid assessment row written the way the runtime writes one."""
    with connect(dsn) as connection:
        row = connection.execute(
            "SELECT f.*, a.exposure, a.criticality FROM finding f"
            "  JOIN asset a ON a.asset_id = f.asset_id WHERE f.finding_id = %s",
            (finding_id,),
        ).fetchone()
        assert row is not None
        finding = dict(row)
        revision = severity.input_revision(connection, finding)
    record: dict[str, Any] = {
        "severity": rating,
        "reasons": ["fixture: severity raised for the delta test"],
        "source_refs": [{"kind": "evidence", "ref": _evidence_id(dsn, finding_id)}],
        "uncertainty": [],
        "recommended_actions": [],
        "inputs": {"exposure": "unknown", "criticality": "unknown"},
        "trigger": "operator_request",
        "input_revision": revision,
        "dedup_key": f"severity:{finding_id}:{revision}",
        "assessed_by": {"kind": "rule"},
    }
    assert validation.problems(SEVERITY_SCHEMA, record) == []
    return record


def _raise_severity(dsn: str, finding_id: str, *, rating: str, at: datetime) -> None:
    with connect(dsn) as connection:
        record = _severity_record(dsn, finding_id, rating=rating)
        assessment_id = "01900000-0000-7000-8000-000000400001"
        connection.execute(
            "INSERT INTO severity_assessment (assessment_id, finding_id, severity, assessment,"
            " kind, trigger, created_at) VALUES (%s, %s, %s, %s, 'rule', 'operator_request', %s)",
            (assessment_id, finding_id, rating, json.dumps(record), at),
        )
        connection.execute(
            "UPDATE finding SET severity = %s, current_assessment = %s WHERE finding_id = %s",
            (rating, assessment_id, finding_id),
        )


def _table_counts(dsn: str) -> dict[str, int]:
    with connect(dsn) as connection:
        counts: dict[str, int] = {}
        for table in (
            "finding",
            "finding_transition",
            "severity_assessment",
            "outbox_event",
            "scan_job",
        ):
            row = connection.execute(f"SELECT count(*) AS n FROM {table}").fetchone()
            assert row is not None
            counts[table] = int(row["n"])
        return counts


def test_the_snapshot_carries_evidence_hashes_and_counts(database: str) -> None:
    client = _client(database)
    response = _get(client, "/reports/snapshot", campaign_id=CAMPAIGN_ID)
    assert response.status_code == 200, response.text
    document = response.json()
    validator = validation.openapi_response_validator("/reports/snapshot")
    assert list(validator.iter_errors(document)) == []
    assert document["campaign_id"] == CAMPAIGN_ID
    assert document["counts"]["findings"] == 3
    assert document["counts"]["assets"] == 3
    assert document["counts"]["by_status"] == {"CANDIDATE": 3}
    assert document["counts"]["by_severity"] == {"UNRATED": 3}
    for item in document["findings"]:
        assert item["status"] == "CANDIDATE"
        assert item["severity"] == "UNRATED"
        assert "severity_assessment" not in item, "no assessment has been written yet"
        assert item["evidence"], "a finding without evidence is not a finding"
        for evidence in item["evidence"]:
            assert len(evidence["sha256"]) == 64
        assert item["last_seen"] >= item["first_seen"]
    keys = {item["canonical_key"] for item in document["assets"]}
    assert keys == {fixtures.SERVICE_KEY, fixtures.NGINX_SERVICE_KEY, fixtures.APP_KEY}


def test_a_past_as_of_reconstructs_the_status_and_severity_of_that_instant(
    database: str,
) -> None:
    client = _client(database)
    by_cve = _by_cve(database)
    fixed = str(by_cve["CVE-2021-41773"]["finding_id"])
    raised = str(by_cve["CVE-2022-22965"]["finding_id"])
    base = _created_at(database) + timedelta(seconds=1)
    _close(database, fixed, at=base + timedelta(seconds=1))
    _raise_severity(database, raised, rating="HIGH", at=base + timedelta(seconds=2))

    before = _get(client, "/reports/snapshot", as_of=_stamp(base))
    after = _get(client, "/reports/snapshot", as_of=_stamp(base + timedelta(seconds=10)))
    assert before.status_code == 200 and after.status_code == 200
    old_items = {item["finding_id"]: item for item in before.json()["findings"]}
    new_items = {item["finding_id"]: item for item in after.json()["findings"]}
    assert old_items[fixed]["status"] == "CANDIDATE"
    assert new_items[fixed]["status"] == "FIXED"
    assert old_items[raised]["severity"] == "UNRATED"
    assert "severity_assessment" not in old_items[raised]
    assert new_items[raised]["severity"] == "HIGH"
    assert new_items[raised]["severity_assessment"]["severity"] == "HIGH"
    # The fixed finding's asset left the exposure inventory; the others stayed.
    assert len(before.json()["assets"]) == 3
    assert len(after.json()["assets"]) == 2


def test_the_delta_lists_each_finding_in_exactly_one_bucket(database: str) -> None:
    client = _client(database)
    by_cve = _by_cve(database)
    fixed = str(by_cve["CVE-2021-41773"]["finding_id"])
    changed = str(by_cve["CVE-2022-22965"]["finding_id"])
    stable = str(by_cve["CVE-2021-23017"]["finding_id"])
    base = _created_at(database) + timedelta(seconds=1)
    _close(database, fixed, at=base + timedelta(seconds=1))
    _raise_severity(database, changed, rating="HIGH", at=base + timedelta(seconds=2))

    response = _get(
        client,
        "/reports/delta",
        **{
            "from": _stamp(base),
            "to": _stamp(base + timedelta(seconds=10)),
            "campaign_id": CAMPAIGN_ID,
        },
    )
    assert response.status_code == 200, response.text
    document = response.json()
    validator = validation.openapi_response_validator("/reports/delta")
    assert list(validator.iter_errors(document)) == []
    identified = {
        "findings_new": {item["finding_id"] for item in document["findings_new"]},
        "findings_changed": {item["finding_id"] for item in document["findings_changed"]},
        "findings_fixed": {item["finding_id"] for item in document["findings_fixed"]},
        "findings_regressed": {item["finding_id"] for item in document["findings_regressed"]},
    }
    assert identified["findings_fixed"] == {fixed}
    assert identified["findings_changed"] == {changed}
    assert identified["findings_new"] == set()
    assert identified["findings_regressed"] == set()
    everything = [item["finding_id"] for name in identified for item in document[name]]
    assert len(everything) == len(set(everything)), "a finding appeared twice in one delta"
    assert stable not in everything
    # Assets: the fixed finding's asset left the inventory; nothing new started.
    gone = {item["canonical_key"] for item in document["assets_gone"]}
    assert gone == {fixtures.SERVICE_KEY}
    assert document["assets_new"] == []


def test_a_window_before_the_findings_reports_everything_as_new(database: str) -> None:
    client = _client(database)
    now = _clock(database)
    response = _get(
        client,
        "/reports/delta",
        **{
            "from": _stamp(now - timedelta(hours=1)),
            "to": _stamp(now + timedelta(hours=1)),
        },
    )
    assert response.status_code == 200, response.text
    document = response.json()
    assert len(document["findings_new"]) == 3
    assert document["findings_changed"] == []
    assert document["findings_fixed"] == []
    assert len(document["assets_new"]) == 3
    assert document["assets_gone"] == []
    for item in document["findings_new"]:
        assert item["evidence"] and item["evidence"][0]["sha256"]


def test_the_window_and_the_campaign_filter_are_validated(database: str) -> None:
    client = _client(database)
    now = _clock(database)
    equal = _get(
        client,
        "/reports/delta",
        **{"from": _stamp(now), "to": _stamp(now)},
    )
    assert equal.status_code == 400
    assert equal.json()["field"] == "/from"
    naive = _get(
        client,
        "/reports/delta",
        **{"from": "2026-11-28T00:00:00", "to": _stamp(now)},
    )
    assert naive.status_code == 400
    assert naive.json()["field"] == "/from"
    bad_campaign = _get(client, "/reports/snapshot", campaign_id="not-a-uuid")
    assert bad_campaign.status_code == 400
    assert bad_campaign.json()["field"] == "/campaign_id"
    unknown_campaign = _get(
        client, "/reports/snapshot", campaign_id="01900000-0000-7000-8000-0000000000ff"
    )
    assert unknown_campaign.status_code == 200
    assert unknown_campaign.json()["counts"]["findings"] == 0


def test_the_report_is_a_read_model_and_writes_nothing(database: str) -> None:
    client = _client(database)
    before = _table_counts(database)
    assert _get(client, "/reports/snapshot", campaign_id=CAMPAIGN_ID).status_code == 200
    now = _clock(database)
    assert (
        _get(
            client,
            "/reports/delta",
            **{"from": _stamp(now - timedelta(minutes=5)), "to": _stamp(now)},
        ).status_code
        == 200
    )
    assert _table_counts(database) == before


def test_the_report_operations_match_the_contract() -> None:
    registry = RouterRegistry()
    reports.register(registry)
    spec = create_app(registry).openapi()
    contract = yaml.safe_load(
        (repository_root() / "contracts/api/openapi.v2.yaml").read_text(encoding="utf-8")
    )
    served = {
        operation["operationId"]: (method, path, operation)
        for path, item in spec["paths"].items()
        for method, operation in item.items()
        if method in METHODS and path.startswith(API_PREFIX)
    }
    expected: dict[str, tuple[str, str, dict[str, Any]]] = {}
    for path in CONTRACT_PATHS:
        for method, operation in contract["paths"][path].items():
            if method in METHODS:
                expected[operation["operationId"]] = (method, path, operation)
    assert set(expected) == set(reports.REPORT_OPERATIONS)
    assert set(served) == set(reports.REPORT_OPERATIONS)
    for operation_id, (method, path, contract_operation) in expected.items():
        served_method, served_path, served_operation = served[operation_id]
        assert (served_method, served_path) == (method, f"{API_PREFIX}{path}")
        assert {int(code) for code in served_operation["responses"]} == {
            int(code) for code in contract_operation["responses"]
        }, operation_id
        assert contract_operation["security"] == [{"operatorToken": []}], operation_id
        assert served_operation["security"] == [{"operatorToken": []}], operation_id
        contract_names = {
            parameter.get("name")
            for parameter in contract_operation.get("parameters", [])
            if "$ref" not in parameter
        }
        served_names = {parameter["name"] for parameter in served_operation.get("parameters", [])}
        assert contract_names <= served_names, operation_id
