"""M26 findings API (G2 slice A): list/get/history/transition/assessment against PostgreSQL.

The findings are produced by the real path (`FindingsEngine` over M20's candidates), and every
response is validated against the contract (`finding/finding.v2.schema.json` and the inline
history/page shapes of `contracts/api/openapi.v2.yaml`), so a producer/API disagreement fails the
test instead of reaching the UI.

The conformance test reads the same contract file the app is built against and compares the five
operations it publishes: method, path, documented status codes, the operator bearer requirement and
the parameter names. The operator transition proves the server-assigned actor (the body carries
none) and the optimistic `expected_seq` (409 on a stale value).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

from aegis import validation
from aegis.common.repo import repository_root
from aegis.contracts_gen.agent.model_response_v2_schema import ModelResponse
from aegis.m04_model.fake import FakeModelClient
from aegis.m20_vuln.findings import FindingsEngine
from aegis.m20_vuln.matching import Matcher
from aegis.m26_api import findings as findings_module
from aegis.m26_api.app import API_PREFIX, create_app
from aegis.m26_api.operator import TokenAuthenticator
from aegis.m26_api.registry import RouterRegistry
from aegis.m27_ingestion.ids import uuid7
from tests import campaign_support as support
from tests import g16c_support as fixtures
from tests.db_support import requires_postgres
from tests.m23_support import CAMPAIGN_ID, connect, ingest, pipeline_database

pytestmark = requires_postgres

METHODS = frozenset({"get", "post", "put", "patch", "delete"})
CONTRACT_PATHS = (
    "/findings",
    "/findings/{finding_id}",
    "/findings/{finding_id}/transitions",
    "/findings/{finding_id}/history",
    "/findings/{finding_id}/assessment",
)


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
        yield dsn, jobs


def _client(dsn: str, *, severity_client: Any | None = None) -> TestClient:
    registry = RouterRegistry()
    findings_module.register(registry)
    app = create_app(
        registry,
        operator_authenticator=TokenAuthenticator(support.operator_tokens()),
        database_dsn=dsn,
        severity_client=severity_client,
    )
    return TestClient(app)


def _finding_rows(dsn: str) -> list[dict[str, Any]]:
    with connect(dsn) as connection:
        return [
            dict(row)
            for row in connection.execute(
                "SELECT f.*, a.canonical_key FROM finding f"
                "  JOIN asset a ON a.asset_id = f.asset_id"
                " ORDER BY a.canonical_key, f.vulnerability_ids[1]"
            ).fetchall()
        ]


def _by_cve(dsn: str) -> dict[str, dict[str, Any]]:
    return {str(row["vulnerability_ids"][0]): row for row in _finding_rows(dsn)}


def _get(client: TestClient, path: str, **params: Any) -> Any:
    return client.get(f"{API_PREFIX}{path}", params=params, headers=support.auth())


def test_list_findings_is_a_campaign_scoped_keyset_page(database: tuple[str, list[str]]) -> None:
    dsn, _ = database
    client = _client(dsn)
    response = _get(client, "/findings", campaign_id=CAMPAIGN_ID, limit=2)
    assert response.status_code == 200, response.text
    body = response.json()
    assert len(body["items"]) == 2
    assert "next_cursor" in body
    for item in body["items"]:
        assert validation.problems("finding/finding.v2.schema.json", item) == []
        assert item["status"] == "CANDIDATE"
        assert item["severity"] == "UNRATED"
        assert item["evidence"] and item["evidence"][0]["sha256"]
        assert item["rule_id"].startswith("cve:")
        assert item["providers"] == ["subfinder"]
    second = _get(client, "/findings", campaign_id=CAMPAIGN_ID, limit=2, cursor=body["next_cursor"])
    assert second.status_code == 200, second.text
    remaining = second.json()["items"]
    assert len(remaining) == 1 and "next_cursor" not in second.json()
    ids = {item["finding_id"] for item in body["items"] + remaining}
    assert ids == {str(row["finding_id"]) for row in _finding_rows(dsn)}


def test_list_findings_filters_by_campaign_status_severity_cve_and_kev(
    database: tuple[str, list[str]],
) -> None:
    dsn, _ = database
    client = _client(dsn)
    rows = _by_cve(dsn)
    assert _get(client, "/findings", campaign_id=CAMPAIGN_ID).json()["items"]
    assert _get(client, "/findings", campaign_id=str(uuid7())).json()["items"] == []
    assert (
        len(
            _get(client, "/findings", asset_id=str(rows["CVE-2021-41773"]["asset_id"])).json()[
                "items"
            ]
        )
        == 1
    )
    # Both the contract's `explode: false` form and repeated parameters are accepted.
    assert len(_get(client, "/findings", status="CANDIDATE,FIXED").json()["items"]) == 3
    assert len(_get(client, "/findings", status=["CANDIDATE", "FIXED"]).json()["items"]) == 3
    assert _get(client, "/findings", status="VERIFIED").json()["items"] == []
    assert len(_get(client, "/findings", severity="UNRATED").json()["items"]) == 3
    assert _get(client, "/findings", severity="HIGH").json()["items"] == []
    assert len(_get(client, "/findings", vulnerability_id="CVE-2021-41773").json()["items"]) == 1
    kev = _get(client, "/findings", kev=True).json()["items"]
    assert "CVE-2021-41773" in {item["vulnerability_ids"][0] for item in kev}
    assert _get(client, "/findings", kev=False).json()["items"]
    assert _get(client, "/findings", changed_since="2030-01-01T00:00:00Z").json()["items"] == []


def test_list_findings_refuses_a_bad_cursor_or_filter(database: tuple[str, list[str]]) -> None:
    dsn, _ = database
    client = _client(dsn)
    assert _get(client, "/findings", cursor="not-a-cursor").status_code == 400
    assert _get(client, "/findings", status="BANANA").status_code == 400
    assert _get(client, "/findings", severity="BANANA").status_code == 400
    assert _get(client, "/findings", campaign_id="not-an-id").status_code == 400
    assert _get(client, "/findings", format="sarif").status_code == 400
    assert client.get(f"{API_PREFIX}/findings").status_code == 401


def test_get_finding_and_history(database: tuple[str, list[str]]) -> None:
    dsn, _ = database
    client = _client(dsn)
    finding = _by_cve(dsn)["CVE-2021-41773"]
    response = _get(client, f"/findings/{finding['finding_id']}")
    assert response.status_code == 200, response.text
    body = response.json()
    assert validation.problems("finding/finding.v2.schema.json", body) == []
    assert body["finding_id"] == str(finding["finding_id"])
    assert body["vulnerability_ids"] == ["CVE-2021-41773"]
    assert body["asset_key"] == fixtures.SERVICE_KEY
    assert body["fingerprint"] == str(finding["fingerprint"])
    assert "severity_assessment" not in body
    assert _get(client, f"/findings/{uuid7()}").status_code == 404
    assert _get(client, "/findings/not-an-id").status_code == 404

    history = _get(client, f"/findings/{finding['finding_id']}/history")
    assert history.status_code == 200, history.text
    document = history.json()
    assert validation.openapi_response_validator("/findings/{finding_id}/history").is_valid(
        document
    )
    assert len(document["runs"]) == 1
    assert document["runs"][0]["seen"] is True
    assert document["runs"][0]["status"] == "CANDIDATE"
    assert document["runs"][0]["severity"] == "UNRATED"
    assert len(document["transitions"]) == 1
    assert document["transitions"][0]["from_status"] is None
    assert document["transitions"][0]["to_status"] == "CANDIDATE"
    assert document["transitions"][0]["actor"] == {"kind": "module", "id": "M20"}
    assert document["assessments"] == []
    assert _get(client, f"/findings/{uuid7()}/history").status_code == 404


def test_operator_transition_records_the_principal_and_the_optimistic_seq(
    database: tuple[str, list[str]],
) -> None:
    dsn, _ = database
    client = _client(dsn)
    finding = _by_cve(dsn)["CVE-2021-41773"]
    finding_id = str(finding["finding_id"])
    path = f"{API_PREFIX}/findings/{finding_id}/transitions"

    stale = client.post(
        path,
        json={"to": "FALSE_POSITIVE", "reason": "not the current seq", "expected_seq": 0},
        headers=support.auth(),
    )
    assert stale.status_code == 409, stale.text
    assert stale.json()["code"] == "IDEMPOTENCY_CONFLICT"

    refused = client.post(
        path,
        json={"to": "VERIFIED", "reason": "the operator cannot verify", "expected_seq": 1},
        headers=support.auth(),
    )
    assert refused.status_code == 409, refused.text

    body = {
        "to": "FALSE_POSITIVE",
        "reason": "the banner came from a proxy, not httpd on this port",
        "expected_seq": 1,
    }
    response = client.post(path, json=body, headers=support.auth("op-soc-1"))
    assert response.status_code == 200, response.text
    updated = response.json()
    assert validation.problems("finding/finding.v2.schema.json", updated) == []
    assert updated["status"] == "FALSE_POSITIVE"
    assert updated["severity"] == "UNRATED"
    assert updated["first_seen"] == finding["first_seen"].isoformat().replace("+00:00", "Z")

    history = _get(client, f"/findings/{finding_id}/history").json()
    assert [item["to_status"] for item in history["transitions"]] == [
        "CANDIDATE",
        "FALSE_POSITIVE",
    ]
    last = history["transitions"][-1]
    assert last["seq"] == 2
    assert last["actor"] == {"kind": "operator", "id": "op-soc-1"}
    assert last["cause"] == "operator"
    assert last["reason"] == body["reason"]

    with connect(dsn) as connection:
        row = connection.execute(
            "SELECT to_status, seq, actor, cause FROM finding_transition"
            " WHERE finding_id = %s ORDER BY seq DESC LIMIT 1",
            (finding_id,),
        ).fetchone()
        event = connection.execute(
            "SELECT producer, dedup_key, payload FROM outbox_event"
            " WHERE type = 'finding.changed.v2' AND payload->>'finding_id' = %s"
            "   AND payload->>'cause' = 'operator'",
            (finding_id,),
        ).fetchone()
        current = connection.execute(
            "SELECT status, transition_seq FROM finding WHERE finding_id = %s", (finding_id,)
        ).fetchone()
    assert row is not None and current is not None
    assert row["to_status"] == "FALSE_POSITIVE" and row["cause"] == "operator"
    assert int(row["seq"]) == 2
    assert dict(row["actor"]) == {"kind": "operator", "id": "op-soc-1"}
    assert event is not None
    assert event["producer"] == "M26"
    assert event["dedup_key"] == f"{finding_id}:2"
    payload = dict(event["payload"])
    assert validation.problems("events/finding.changed.v2.schema.json", payload) == []
    assert payload["changed_by"] == {"kind": "operator", "id": "op-soc-1"}
    assert payload["new_status"] == "FALSE_POSITIVE"
    assert current["status"] == "FALSE_POSITIVE" and int(current["transition_seq"]) == 2

    # The stale retry of the same request is a 409, not a second transition.
    again = client.post(path, json=body, headers=support.auth("op-soc-1"))
    assert again.status_code == 409, again.text


def test_transition_body_is_validated_against_the_contract(
    database: tuple[str, list[str]],
) -> None:
    dsn, _ = database
    client = _client(dsn)
    finding_id = str(_by_cve(dsn)["CVE-2021-41773"]["finding_id"])
    path = f"{API_PREFIX}/findings/{finding_id}/transitions"
    assert (
        client.post(
            path, json={"to": "FALSE_POSITIVE", "expected_seq": 1}, headers=support.auth()
        ).status_code
        == 400
    )
    assert (
        client.post(
            path,
            json={"to": "FALSE_POSITIVE", "reason": "x", "expected_seq": 1},
            headers=support.auth(),
        ).status_code
        == 400
    )
    assert (
        client.post(
            path,
            json={
                "to": "FALSE_POSITIVE",
                "reason": "long enough",
                "expected_seq": 1,
                "actor": {"kind": "operator", "id": "op-soc-2"},
            },
            headers=support.auth("op-soc-1"),
        ).status_code
        == 400
    )


def test_assessment_without_a_model_stores_unrated_with_the_reason(
    database: tuple[str, list[str]],
) -> None:
    dsn, _ = database
    client = _client(dsn)
    finding_id = str(_by_cve(dsn)["CVE-2021-41773"]["finding_id"])
    response = client.post(f"{API_PREFIX}/findings/{finding_id}/assessment", headers=support.auth())
    assert response.status_code == 200, response.text
    record = response.json()
    assert validation.problems("finding/severity-assessment.v2.schema.json", record) == []
    assert record["severity"] == "UNRATED"
    assert record["failure"]["code"] == "DEPENDENCY_MISSING"
    assert record["trigger"] == "operator_request"
    assert record["dedup_key"].startswith(f"severity:{finding_id}:")
    assert record["raw_signals"]
    with connect(dsn) as connection:
        assessment = connection.execute(
            "SELECT kind, trigger, session_id, model, assessment FROM severity_assessment"
            " WHERE finding_id = %s",
            (finding_id,),
        ).fetchall()
        finding = connection.execute(
            "SELECT severity, current_assessment FROM finding WHERE finding_id = %s",
            (finding_id,),
        ).fetchone()
    assert len(assessment) == 1
    assert finding is not None
    assert assessment[0]["kind"] == "rule"
    assert assessment[0]["trigger"] == "operator_request"
    assert assessment[0]["session_id"] is None
    assert dict(assessment[0]["assessment"])["failure"]["code"] == "DEPENDENCY_MISSING"
    assert finding["severity"] == "UNRATED"
    assert finding["current_assessment"] is not None
    # A second call is the stored record: same dedup key, one row, still no model.
    second = client.post(f"{API_PREFIX}/findings/{finding_id}/assessment", headers=support.auth())
    assert second.status_code == 200
    assert second.json()["dedup_key"] == record["dedup_key"]
    with connect(dsn) as connection:
        count = connection.execute(
            "SELECT count(*) AS n FROM severity_assessment WHERE finding_id = %s", (finding_id,)
        ).fetchone()
    assert count is not None and int(count["n"]) == 1


def _scripted_response(
    finding_id: str, evidence_id: str, *, ref: str | None = None
) -> ModelResponse:
    template = json.loads(
        (
            repository_root() / "contracts/fixtures/valid/model-response.completed.anthropic.json"
        ).read_text(encoding="utf-8")
    )
    template["parsed"]["source_refs"] = [{"kind": "evidence", "ref": ref or evidence_id}]
    template["parsed"]["reasons"] = [
        f"CVE on {finding_id} với bằng chứng {evidence_id} và chưa có đối chứng âm"
    ]
    template["message"]["content"][0]["text"] = json.dumps(template["parsed"])
    return ModelResponse.model_validate(template)


def test_assessment_with_a_model_is_agent_authored_and_idempotent(
    database: tuple[str, list[str]],
) -> None:
    dsn, _ = database
    finding = _by_cve(dsn)["CVE-2021-41773"]
    finding_id = str(finding["finding_id"])
    with connect(dsn) as connection:
        evidence_row = connection.execute(
            "SELECT evidence_id FROM finding_run WHERE finding_id = %s LIMIT 1",
            (finding_id,),
        ).fetchone()
    assert evidence_row is not None and evidence_row["evidence_id"] is not None
    evidence_id = str(evidence_row["evidence_id"])
    fake = FakeModelClient([_scripted_response(finding_id, evidence_id)])
    client = _client(dsn, severity_client=(fake, "anthropic", "configured-model"))
    response = client.post(f"{API_PREFIX}/findings/{finding_id}/assessment", headers=support.auth())
    assert response.status_code == 200, response.text
    record = response.json()
    assert validation.problems("finding/severity-assessment.v2.schema.json", record) == []
    assert record["severity"] == "MEDIUM"
    assert record["assessed_by"]["kind"] == "agent"
    assert record["assessed_by"]["model"] == "configured-model"
    assert record["assessed_by"]["prompt_version"] == "severity-v1"
    assert record["source_refs"] == [{"kind": "evidence", "ref": evidence_id}]
    assert len(fake.calls) == 1
    with connect(dsn) as connection:
        finding_row = connection.execute(
            "SELECT severity, current_assessment FROM finding WHERE finding_id = %s",
            (finding_id,),
        ).fetchone()
        session = connection.execute(
            "SELECT status, steps_used FROM agent_session WHERE session_id = %s",
            (record["assessed_by"]["session_id"],),
        ).fetchone()
    assert finding_row is not None and session is not None
    assert finding_row["severity"] == "MEDIUM"
    assert session["status"] == "SUCCEEDED" and int(session["steps_used"]) == 1

    # Same finding, same input revision: the stored record, no second model call.
    again = client.post(f"{API_PREFIX}/findings/{finding_id}/assessment", headers=support.auth())
    assert again.status_code == 200
    assert again.json()["dedup_key"] == record["dedup_key"]
    assert len(fake.calls) == 1


def test_a_model_that_cites_nothing_real_is_unrated(database: tuple[str, list[str]]) -> None:
    dsn, _ = database
    finding_id = str(_by_cve(dsn)["CVE-2021-41773"]["finding_id"])
    with connect(dsn) as connection:
        evidence_row = connection.execute(
            "SELECT evidence_id FROM finding_run WHERE finding_id = %s LIMIT 1",
            (finding_id,),
        ).fetchone()
    assert evidence_row is not None and evidence_row["evidence_id"] is not None
    evidence_id = str(evidence_row["evidence_id"])
    fake = FakeModelClient([_scripted_response(finding_id, evidence_id, ref=str(uuid7()))])
    client = _client(dsn, severity_client=(fake, "anthropic", "configured-model"))
    response = client.post(f"{API_PREFIX}/findings/{finding_id}/assessment", headers=support.auth())
    assert response.status_code == 200, response.text
    record = response.json()
    assert record["severity"] == "UNRATED"
    assert record["failure"]["code"] == "OUTPUT_INVALID"
    assert "do not exist" in record["failure"]["message"]
    with connect(dsn) as connection:
        session = connection.execute(
            "SELECT status, stop_reason FROM agent_session ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        severity_row = connection.execute(
            "SELECT severity FROM finding WHERE finding_id = %s", (finding_id,)
        ).fetchone()
    assert session is not None and severity_row is not None
    assert session["status"] == "FAILED" and session["stop_reason"] == "OUTPUT_INVALID"
    assert severity_row["severity"] == "UNRATED"


def test_an_exhausted_campaign_budget_keeps_the_finding_unrated(
    database: tuple[str, list[str]],
) -> None:
    dsn, _ = database
    finding_id = str(_by_cve(dsn)["CVE-2021-41773"]["finding_id"])
    policy = support.policy()
    policy["budget"] = {"max_llm_tokens": 0, "max_llm_cost_usd": 0}
    with connect(dsn) as connection:
        connection.execute(
            "INSERT INTO policy_snapshot (policy_version, campaign_id, policy, policy_hash,"
            " created_by) VALUES ('roe-2', %s, %s, %s, %s)",
            (
                CAMPAIGN_ID,
                json.dumps(policy),
                "2" * 64,
                json.dumps({"kind": "operator", "id": "op-soc-1"}),
            ),
        )
        connection.execute(
            "UPDATE campaign SET current_policy_version = 'roe-2' WHERE campaign_id = %s",
            (CAMPAIGN_ID,),
        )
    fake = FakeModelClient([])
    client = _client(dsn, severity_client=(fake, "anthropic", "configured-model"))
    response = client.post(f"{API_PREFIX}/findings/{finding_id}/assessment", headers=support.auth())
    assert response.status_code == 200, response.text
    record = response.json()
    assert record["severity"] == "UNRATED"
    assert record["failure"]["code"] == "POLICY_DENIED"
    assert "budget" in record["failure"]["message"]
    assert fake.calls == []


def test_served_openapi_matches_the_contract_for_the_findings_operations() -> None:
    registry = RouterRegistry()
    findings_module.register(registry)
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
    assert set(expected) == set(findings_module.FINDING_OPERATIONS)
    assert set(served) == set(findings_module.FINDING_OPERATIONS)
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
