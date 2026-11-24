"""The JSON encoding of `GET /campaigns/{id}/events` and the contract shape of both G1.5a endpoints.

The endpoint publishes one operation with two encodings; the JSON page is what a history view (or a
test) reads without a stream, and it follows the same 0008/0013 rules: only published events, in
publication order, never past the watermark. The SSE encoding has its own suite
(`test_events_stream.py`), because a stream needs a real socket.
"""

from __future__ import annotations

import importlib
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import psycopg
import pytest
import yaml
from fastapi.testclient import TestClient

from aegis import validation
from aegis.common.repo import repository_root
from aegis.m05_registry.ids import uuid7
from aegis.m26_api import events as events_module
from aegis.m26_api.app import API_PREFIX
from aegis.m26_api.app import create_app as create_test_app
from aegis.m26_api.errors import ERROR_CODES, NEXT_ACTIONS
from aegis.m26_api.operator import OPERATOR_TOKENS_FILE
from tests import campaign_support as support
from tests.db_support import migrated_database, requires_postgres
from tests.g15a_support import (
    accept_jobs,
    api_app,
    emit_event,
    job_completed_payload,
    job_started_payload,
    open_campaign,
)

pytestmark = requires_postgres

EVENTS_PATH = "/campaigns/{campaign_id}/events"
FLOW_PATH = "/campaigns/{campaign_id}/flow"


@pytest.fixture()
def dsn() -> Iterator[str]:
    with migrated_database() as value:
        yield value


@pytest.fixture()
def client(dsn: str) -> TestClient:
    return TestClient(api_app(dsn))


def _events(
    client: TestClient,
    campaign_id: str,
    *,
    headers: dict[str, str] | None = None,
    **params: Any,
) -> Any:
    return client.get(
        f"{API_PREFIX}/campaigns/{campaign_id}/events",
        params=params,
        headers=support.auth() if headers is None else headers,
    )


def _publish(dsn: str, campaign_id: str, jobs: list[dict[str, Any]]) -> list[int]:
    """Two job events per job, the way M06 publishes them; returns their publication seqs."""
    sequences = []
    for job in jobs:
        sequences.append(
            emit_event(
                dsn,
                campaign_id=campaign_id,
                event_type="job.started.v2",
                dedup_key=job["job_id"],
                payload=job_started_payload(job),
            )
        )
        sequences.append(
            emit_event(
                dsn,
                campaign_id=campaign_id,
                event_type="job.completed.v2",
                dedup_key=f"{job['job_id']}:1",
                payload=job_completed_payload(job, "SUCCEEDED"),
            )
        )
    return sequences


def test_the_json_page_returns_published_events_of_one_campaign_in_order(dsn: str) -> None:
    client = TestClient(api_app(dsn))
    campaign = open_campaign(dsn, name="events page")
    other = open_campaign(dsn, name="another campaign")
    jobs = accept_jobs(dsn, campaign, 2)
    mine = _publish(dsn, campaign.campaign_id, jobs)
    others = _publish(dsn, other.campaign_id, accept_jobs(dsn, other, 1))

    page = _events(client, campaign.campaign_id)
    assert page.status_code == 200, page.text
    body = page.json()
    assert "next_cursor" not in body
    assert [item["type"] for item in body["items"]] == [
        "job.started.v2",
        "job.completed.v2",
        "job.started.v2",
        "job.completed.v2",
    ]
    for item in body["items"]:
        validation.validate("events/event-envelope.v2.schema.json", item)
    assert min(mine) < min(others), "sequence numbers are shared by the whole outbox"

    # The page never exposes the other campaign's rows, whatever their sequence.
    published = [item["payload"]["job_id"] for item in body["items"]]
    assert published == [jobs[0]["job_id"], jobs[0]["job_id"], jobs[1]["job_id"], jobs[1]["job_id"]]


def test_paging_by_cursor_loses_nothing_and_repeats_nothing(dsn: str) -> None:
    client = TestClient(api_app(dsn))
    campaign = open_campaign(dsn, name="events cursor")
    _publish(dsn, campaign.campaign_id, accept_jobs(dsn, campaign, 3))

    seen: list[str] = []
    cursor: str | None = None
    while True:
        params: dict[str, Any] = {"limit": 2}
        if cursor is not None:
            params["cursor"] = cursor
        page = _events(client, campaign.campaign_id, **params).json()
        seen.extend(item["event_id"] for item in page["items"])
        cursor = page.get("next_cursor")
        if cursor is None:
            break
    assert len(seen) == 6
    assert len(set(seen)) == 6


def test_a_resume_point_beyond_the_published_head_is_refused(dsn: str) -> None:
    client = TestClient(api_app(dsn))
    campaign = open_campaign(dsn, name="events generation")
    sequence = _publish(dsn, campaign.campaign_id, accept_jobs(dsn, campaign, 1))[-1]

    accepted = _events(client, campaign.campaign_id, cursor=sequence)
    assert accepted.status_code == 200
    assert accepted.json()["items"] == []

    for cursor in (str(sequence + 1000), "-1", "not-a-number", "1.5"):
        refused = _events(client, campaign.campaign_id, cursor=cursor)
        assert refused.status_code == 400, cursor
        body = refused.json()
        assert body["code"] == "INPUT_INVALID"
        assert body["next_action"] == "FIX_INPUT"
        assert body["field"] == "/cursor"
        assert body["trace_id"]


def test_types_filters_the_page_and_an_unknown_type_is_a_400(dsn: str) -> None:
    client = TestClient(api_app(dsn))
    campaign = open_campaign(dsn, name="events types")
    _publish(dsn, campaign.campaign_id, accept_jobs(dsn, campaign, 2))

    only_completed = _events(
        client, campaign.campaign_id, types="job.completed.v2,job.completed.v2"
    ).json()
    assert [item["type"] for item in only_completed["items"]] == [
        "job.completed.v2",
        "job.completed.v2",
    ]

    unknown = _events(client, campaign.campaign_id, types="job.completed.v2,nope.v2")
    assert unknown.status_code == 400
    assert unknown.json()["field"] == "/types"
    assert "nope.v2" in unknown.json()["message"]


def test_an_unknown_campaign_is_404_and_an_uncommitted_event_is_not_served(dsn: str) -> None:
    client = TestClient(api_app(dsn))
    assert _events(client, uuid7()).status_code == 404
    assert _events(client, "not-a-uuid").status_code == 404

    campaign = open_campaign(dsn, name="events watermark")
    payload = job_started_payload(accept_jobs(dsn, campaign, 1)[0])
    with psycopg.connect(dsn) as producer, producer.transaction():
        emit_event(
            dsn,
            campaign_id=campaign.campaign_id,
            event_type="job.started.v2",
            dedup_key="pending-event",
            payload=payload,
            connection=producer,
        )
        assert _events(client, campaign.campaign_id).json()["items"] == []
    served = _events(client, campaign.campaign_id).json()["items"]
    assert [item["type"] for item in served] == ["job.started.v2"]


def test_a_database_role_without_the_dispatcher_grant_is_a_loud_503(
    dsn: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Streaming needs the 0008 dispatcher functions; a role without them must not look empty."""
    client = TestClient(api_app(dsn))
    campaign = open_campaign(dsn, name="events privilege")

    def deny(*_args: Any, **_kwargs: Any) -> None:
        raise psycopg.errors.InsufficientPrivilege("permission denied for function")

    monkeypatch.setattr(events_module, "_refresh_watermark", deny)
    refused = _events(client, campaign.campaign_id)
    assert refused.status_code == 503, refused.text
    body = refused.json()
    assert body["code"] == "DEPENDENCY_MISSING"
    assert body["next_action"] == "ESCALATE"
    assert "aegis_outbox_dispatcher" in body["message"]


def test_a_parameter_outside_the_contract_is_an_error_v2_400(dsn: str) -> None:
    client = TestClient(api_app(dsn))
    campaign = open_campaign(dsn, name="events error")
    refused = _events(client, campaign.campaign_id, limit=0)
    assert refused.status_code == 400, refused.text
    body = refused.json()
    assert body["code"] in ERROR_CODES
    assert body["next_action"] in NEXT_ACTIONS
    assert body["trace_id"]


# --------------------------------------------------------------------------- conformance


def _contract() -> dict[str, Any]:
    document = yaml.safe_load(
        (repository_root() / "contracts/api/openapi.v2.yaml").read_text(encoding="utf-8")
    )
    assert isinstance(document, dict)
    return document


def test_both_operations_expose_the_contracts_identifiers_and_parameters() -> None:
    contract = _contract()
    spec = api_app("postgresql://unused/unused").openapi()
    published = {
        "getCampaignFlow": FLOW_PATH,
        "streamCampaignEvents": EVENTS_PATH,
    }
    for operation_id, path in published.items():
        contract_operation = contract["paths"][path]["get"]
        app_operation = spec["paths"][f"{API_PREFIX}{path}"]["get"]
        assert contract_operation["operationId"] == operation_id
        assert app_operation["operationId"] == operation_id

        def parameters(
            document: dict[str, Any], path: str, operation: dict[str, Any]
        ) -> set[tuple[Any, Any]]:
            resolved: set[tuple[Any, Any]] = set()
            declared = document["paths"][path].get("parameters", []) + operation.get(
                "parameters", []
            )
            for node in declared:
                if "$ref" in node:
                    node = document["components"]["parameters"][node["$ref"].rsplit("/", 1)[1]]
                resolved.add((node["name"], node["in"]))
            return resolved

        assert parameters(spec, f"{API_PREFIX}{path}", app_operation) == parameters(
            contract, path, contract_operation
        )
        assert set(app_operation["responses"]) == {"200", "401"}, operation_id
        assert set(contract_operation["responses"]) == {"200", "401"}, operation_id
        assert (
            app_operation["security"] == contract_operation["security"] == [{"operatorToken": []}]
        ), operation_id
        # The shape is locked and this card is the one that locked it.
        # `x-aegis-status` absent means locked (the contract's own rule); flow names G1.5a.
        assert contract_operation.get("x-aegis-status", "locked") == "locked", operation_id

    events_parameters = {
        (node["name"], node["in"]): node
        for node in spec["paths"][f"{API_PREFIX}{EVENTS_PATH}"]["get"]["parameters"]
    }
    assert events_parameters[("limit", "query")]["schema"]["default"] == 50
    assert events_parameters[("limit", "query")]["schema"]["maximum"] == 200
    assert events_parameters[("Last-Event-ID", "header")]["in"] == "header"


def test_the_flow_response_schema_is_in_the_contracts_own_document() -> None:
    """The response the flow route returns is the inline schema the contract publishes for it."""
    contract = _contract()
    schema = contract["paths"][FLOW_PATH]["get"]["responses"]["200"]["content"]["application/json"][
        "schema"
    ]
    assert schema["required"] == ["nodes", "edges", "revision"]
    node = schema["properties"]["nodes"]["items"]
    wait_reason = node["properties"]["wait_reason"]["$ref"]
    assert wait_reason.endswith("job.v2.schema.json#/$defs/WaitReason")
    assert "attempt" in node["properties"] and "generation" in node["properties"]


def test_every_mounted_operation_requires_the_operator_token(
    dsn: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Both sides of the contract: the production app mounts only token-verified operations."""
    # `aegis.m26_api.main` builds the production app (and registers the adapter manifests) at
    # import time, so it needs a real database and its settings.
    monkeypatch.setenv("AEGIS_PG_DSN", dsn)
    monkeypatch.setenv(OPERATOR_TOKENS_FILE, support.write_token_file(tmp_path / "operators.json"))
    monkeypatch.setenv("AEGIS_ALLOW_DEV_SIGNING_KEY", "1")
    sys.modules.pop("aegis.m26_api.main", None)
    module = importlib.import_module("aegis.m26_api.main")
    sys.modules.pop("aegis.m26_api.main", None)

    contract = _contract()
    spec = create_test_app(module.build_registry()).openapi()
    contract_operations = {
        operation["operationId"]: (path, operation)
        for path, item in contract["paths"].items()
        for method, operation in item.items()
        if method in {"get", "post"} and isinstance(operation, dict) and "operationId" in operation
    }
    mounted = [
        operation
        for item in spec["paths"].values()
        for method, operation in item.items()
        if method in {"get", "post"} and isinstance(operation, dict) and "operationId" in operation
    ]
    assert {operation["operationId"] for operation in mounted} == {
        "createCampaign",
        "listCampaigns",
        "getCampaign",
        "updateCampaignPolicy",
        "pauseCampaign",
        "resumeCampaign",
        "cancelCampaign",
        "submitJob",
        "listJobs",
        "getJob",
        "cancelJob",
        "getCampaignFlow",
        "streamCampaignEvents",
        "listCapabilities",
        # G1.4b: the two locked graph reads. `openapi.v2` locks their shape but documents no
        # `security`/401 for them (reported as a contract gap); the app still requires the
        # operator token, so the invariant below asserts the app side and pins the gap.
        "getAssetGraph",
        "getAssetHistory",
    }
    graph_contract_gap = {"getAssetGraph", "getAssetHistory"}
    for operation in mounted:
        operation_id = operation["operationId"]
        assert operation["security"] == [{"operatorToken": []}], operation_id
        assert 401 in {int(code) for code in operation["responses"]}, operation_id
        if operation_id in graph_contract_gap:
            _, contract_operation = contract_operations[operation_id]
            assert "security" not in contract_operation, operation_id
            assert 401 not in {int(code) for code in contract_operation["responses"]}, operation_id
            continue
        _, contract_operation = contract_operations[operation_id]
        assert contract_operation.get("security") == [{"operatorToken": []}], operation_id
        assert 401 in {int(code) for code in contract_operation["responses"]}, operation_id
