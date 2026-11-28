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


def _transition(
    client: TestClient,
    path: str,
    body: dict[str, Any],
    *,
    key: str | None,
    principal: str = "op-soc-1",
) -> Any:
    headers = dict(support.auth(principal))
    if key is not None:
        headers["Idempotency-Key"] = key
    return client.post(path, json=body, headers=headers)


def _transition_counts(dsn: str, finding_id: str) -> tuple[int, int, int]:
    with connect(dsn) as connection:
        transitions = connection.execute(
            "SELECT count(*) AS n FROM finding_transition WHERE finding_id = %s", (finding_id,)
        ).fetchone()
        events = connection.execute(
            "SELECT count(*) AS n FROM outbox_event WHERE type = 'finding.changed.v2'"
            " AND payload->>'finding_id' = %s",
            (finding_id,),
        ).fetchone()
        records = connection.execute(
            "SELECT count(*) AS n FROM idempotency_record WHERE scope = %s",
            (f"POST /findings/{finding_id}/transitions",),
        ).fetchone()
    assert transitions is not None and events is not None and records is not None
    return int(transitions["n"]), int(events["n"]), int(records["n"])


def test_operator_transition_records_the_principal_and_the_optimistic_seq(
    database: tuple[str, list[str]],
) -> None:
    dsn, _ = database
    client = _client(dsn)
    finding = _by_cve(dsn)["CVE-2021-41773"]
    finding_id = str(finding["finding_id"])
    path = f"{API_PREFIX}/findings/{finding_id}/transitions"

    # A stale expected_seq is its own case: 409 with the field as the stable discriminator, not
    # the Idempotency-Key conflict code.
    stale = _transition(
        client,
        path,
        {"to": "FALSE_POSITIVE", "reason": "not the current seq", "expected_seq": 0},
        key="stale-seq-key-1",
    )
    assert stale.status_code == 409, stale.text
    assert stale.json()["code"] == "INPUT_INVALID"
    assert stale.json()["field"] == "/expected_seq"

    refused = _transition(
        client,
        path,
        {"to": "VERIFIED", "reason": "the operator cannot verify", "expected_seq": 1},
        key="invalid-transition-key-1",
    )
    assert refused.status_code == 409, refused.text
    assert refused.json()["code"] == "INPUT_INVALID"
    assert refused.json()["field"] == "/to"

    body = {
        "to": "FALSE_POSITIVE",
        "reason": "the banner came from a proxy, not httpd on this port",
        "expected_seq": 1,
    }
    key = "operator-transition-key-1"
    response = _transition(client, path, body, key=key)
    assert response.status_code == 200, response.text
    updated = response.json()
    assert validation.problems("finding/finding.v2.schema.json", updated) == []
    assert updated["status"] == "FALSE_POSITIVE"
    assert updated["severity"] == "UNRATED"
    assert updated["first_seen"] == finding["first_seen"].isoformat().replace("+00:00", "Z")
    assert "Idempotent-Replayed" not in response.headers

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

    # The contract's idempotency: same key + same body replays the stored response (header set)
    # and writes no second transition or event.
    replay = _transition(client, path, body, key=key)
    assert replay.status_code == 200, replay.text
    assert replay.headers["Idempotent-Replayed"] == "true"
    assert replay.json() == updated
    assert _transition_counts(dsn, finding_id) == (2, 2, 1)

    # A new key with the (now) stale seq is still the stale case, not a replay.
    stale_again = _transition(client, path, body, key="operator-transition-key-2")
    assert stale_again.status_code == 409, stale_again.text
    assert stale_again.json()["code"] == "INPUT_INVALID"
    assert stale_again.json()["field"] == "/expected_seq"


def test_transition_replay_survives_an_intervening_change(
    database: tuple[str, list[str]],
) -> None:
    """The stored response is returned even after another transition moved the finding on."""
    dsn, _ = database
    client = _client(dsn)
    finding_id = str(_by_cve(dsn)["CVE-2021-41773"]["finding_id"])
    path = f"{API_PREFIX}/findings/{finding_id}/transitions"
    first_body = {
        "to": "FALSE_POSITIVE",
        "reason": "first decision, before the operator changed their mind",
        "expected_seq": 1,
    }
    first = _transition(client, path, first_body, key="intervening-key-1")
    assert first.status_code == 200, first.text
    reopen = {
        "to": "CANDIDATE",
        "reason": "a second look found the banner was real after all",
        "expected_seq": 2,
    }
    second = _transition(client, path, reopen, key="intervening-key-2")
    assert second.status_code == 200, second.text
    assert second.json()["status"] == "CANDIDATE"
    assert _transition_counts(dsn, finding_id) == (3, 3, 2)

    replay = _transition(client, path, first_body, key="intervening-key-1")
    assert replay.status_code == 200, replay.text
    assert replay.headers["Idempotent-Replayed"] == "true"
    # The original response, not the finding's current state.
    assert replay.json() == first.json()
    assert replay.json()["status"] == "FALSE_POSITIVE"
    current = _get(client, f"/findings/{finding_id}").json()["status"]
    assert current == "CANDIDATE"
    # Nothing new was written by the replay.
    assert _transition_counts(dsn, finding_id) == (3, 3, 2)


def test_transition_same_key_with_a_different_body_is_a_conflict(
    database: tuple[str, list[str]],
) -> None:
    dsn, _ = database
    client = _client(dsn)
    rows = _by_cve(dsn)
    finding_id = str(rows["CVE-2021-41773"]["finding_id"])
    path = f"{API_PREFIX}/findings/{finding_id}/transitions"
    body = {
        "to": "FALSE_POSITIVE",
        "reason": "the first body of this key",
        "expected_seq": 1,
    }
    assert _transition(client, path, body, key="conflict-key-1").status_code == 200
    changed = {**body, "reason": "a different body under the same key"}
    conflict = _transition(client, path, changed, key="conflict-key-1")
    assert conflict.status_code == 409, conflict.text
    assert conflict.json()["code"] == "IDEMPOTENCY_CONFLICT"
    assert _transition_counts(dsn, finding_id) == (2, 2, 1)
    assert _get(client, f"/findings/{finding_id}").json()["status"] == "FALSE_POSITIVE"

    # The key is scoped by the finding: the same body on another finding is another write.
    other_id = str(rows["CVE-2021-23017"]["finding_id"])
    other_path = f"{API_PREFIX}/findings/{other_id}/transitions"
    other = _transition(client, other_path, body, key="conflict-key-1")
    assert other.status_code == 200, other.text
    assert other.json()["finding_id"] == other_id


def test_transition_requires_a_valid_idempotency_key(
    database: tuple[str, list[str]],
) -> None:
    dsn, _ = database
    client = _client(dsn)
    finding_id = str(_by_cve(dsn)["CVE-2021-41773"]["finding_id"])
    path = f"{API_PREFIX}/findings/{finding_id}/transitions"
    body = {"to": "FALSE_POSITIVE", "reason": "a valid reason", "expected_seq": 1}
    missing = _transition(client, path, body, key=None)
    assert missing.status_code == 400, missing.text
    assert missing.json()["code"] == "INPUT_INVALID"
    assert _transition(client, path, body, key="short").status_code == 400
    assert _transition(client, path, body, key="k" * 257).status_code == 400
    assert _transition_counts(dsn, finding_id) == (1, 1, 0)
    assert _get(client, f"/findings/{finding_id}").json()["status"] == "CANDIDATE"


def test_a_failed_transition_leaves_no_idempotency_record(
    database: tuple[str, list[str]],
) -> None:
    """The record and the effect commit together: a refused call leaves the key unused."""
    dsn, _ = database
    client = _client(dsn)
    finding_id = str(_by_cve(dsn)["CVE-2021-41773"]["finding_id"])
    path = f"{API_PREFIX}/findings/{finding_id}/transitions"
    key = "failed-then-corrected-key"
    stale = _transition(
        client,
        path,
        {"to": "FALSE_POSITIVE", "reason": "a stale attempt", "expected_seq": 0},
        key=key,
    )
    assert stale.status_code == 409, stale.text
    with connect(dsn) as connection:
        record = connection.execute(
            "SELECT * FROM idempotency_record WHERE scope = %s AND key = %s",
            (f"POST /findings/{finding_id}/transitions", key),
        ).fetchone()
    assert record is None
    assert _transition_counts(dsn, finding_id) == (1, 1, 0)

    corrected = _transition(
        client,
        path,
        {"to": "FALSE_POSITIVE", "reason": "the corrected attempt", "expected_seq": 1},
        key=key,
    )
    assert corrected.status_code == 200, corrected.text
    with connect(dsn) as connection:
        record = connection.execute(
            "SELECT status_code, response FROM idempotency_record WHERE scope = %s AND key = %s",
            (f"POST /findings/{finding_id}/transitions", key),
        ).fetchone()
    assert record is not None
    assert int(record["status_code"]) == 200
    assert dict(record["response"])["status"] == "FALSE_POSITIVE"
    assert _transition_counts(dsn, finding_id) == (2, 2, 1)


def test_transition_body_is_validated_against_the_contract(
    database: tuple[str, list[str]],
) -> None:
    dsn, _ = database
    client = _client(dsn)
    finding_id = str(_by_cve(dsn)["CVE-2021-41773"]["finding_id"])
    path = f"{API_PREFIX}/findings/{finding_id}/transitions"
    assert (
        _transition(
            client,
            path,
            {"to": "FALSE_POSITIVE", "expected_seq": 1},
            key="contract-body-key-1",
        ).status_code
        == 400
    )
    assert (
        _transition(
            client,
            path,
            {"to": "FALSE_POSITIVE", "reason": "x", "expected_seq": 1},
            key="contract-body-key-2",
        ).status_code
        == 400
    )
    assert (
        _transition(
            client,
            path,
            {
                "to": "FALSE_POSITIVE",
                "reason": "long enough",
                "expected_seq": 1,
                "actor": {"kind": "operator", "id": "op-soc-2"},
            },
            key="contract-body-key-3",
        ).status_code
        == 400
    )
    assert _transition_counts(dsn, finding_id) == (1, 1, 0)


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


def test_the_published_shape_carries_what_the_findings_screen_reads() -> None:
    """The exact fields the UI reads for severity are contract, not an implementation detail.

    The list carries `severity`; the detail carries the whole `severity_assessment` record
    (reasons, citations, uncertainty, inputs, failure for the UNRATED reason); the history carries
    every assessment. Pinned here so a later shape edit cannot silently drop one of them.
    """
    finding = json.loads(
        (repository_root() / "contracts/finding/finding.v2.schema.json").read_text(encoding="utf-8")
    )
    assert {"severity", "severity_assessment"} <= set(finding["properties"])
    assessment = json.loads(
        (repository_root() / "contracts/finding/severity-assessment.v2.schema.json").read_text(
            encoding="utf-8"
        )
    )
    required = {
        "severity",
        "reasons",
        "uncertainty",
        "recommended_actions",
        "assessed_by",
        "inputs",
        "trigger",
        "input_revision",
        "dedup_key",
    }
    assert required <= set(assessment["required"])
    assert {"source_refs", "raw_signals", "failure"} <= set(assessment["properties"])
    assert {"cvss", "kev", "epss"} <= set(assessment["properties"]["inputs"]["properties"])
    failure = assessment["$defs"]["Failure"]
    assert {"code", "message"} <= set(failure["required"])
    contract = yaml.safe_load(
        (repository_root() / "contracts/api/openapi.v2.yaml").read_text(encoding="utf-8")
    )
    history = contract["paths"]["/findings/{finding_id}/history"]["get"]["responses"]["200"][
        "content"
    ]["application/json"]["schema"]
    assert history["properties"]["assessments"]["items"]["$ref"].endswith(
        "severity-assessment.v2.schema.json"
    )
