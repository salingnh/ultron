"""`GET /campaigns/{id}/flow`: the React Flow read model over real M01/M05/M02 rows (G1.5a).

Every row here is produced the way production produces it: the campaign by M01's seed helper, the
jobs and their policy decisions by the real M05 acceptance path, the dispatch/terminal transitions
by 0007's `record_job_callback` / the M02 helpers. The one synthetic row is the **session-proposed
decision**: no module can write it yet (M03 sessions and the MCP proposer path are G1.2c/G1.2b), so
the test inserts the shape those modules will insert, to cover the `evaluates` edge.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

from aegis.common.repo import repository_root
from aegis.m01_campaign.campaigns import timestamp
from aegis.m05_registry.ids import uuid7
from aegis.m26_api import flow as flow_module
from aegis.m26_api.app import API_PREFIX, create_app
from aegis.m26_api.operator import TokenAuthenticator
from aegis.m26_api.registry import RouterRegistry
from tests import campaign_support as support
from tests.db_support import (
    OPERATOR,
    connect,
    migrated_database,
    requires_postgres,
    seed_campaign,
)
from tests.g15a_support import open_campaign, session_with_decision
from tests.m02_support import accept_job, complete_job, run_job
from tests.test_m05_service import service

pytestmark = requires_postgres

FLOW_PATH = "/campaigns/{campaign_id}/flow"


@pytest.fixture()
def dsn() -> Iterator[str]:
    with migrated_database() as value:
        yield value


def _client(dsn: str) -> TestClient:
    registry = RouterRegistry()
    flow_module.register(registry)
    app = create_app(
        registry,
        operator_authenticator=TokenAuthenticator(support.operator_tokens()),
        database_dsn=dsn,
    )
    return TestClient(app)


def _get(client: TestClient, campaign_id: str, *, headers: dict[str, str] | None = None) -> Any:
    return client.get(
        f"{API_PREFIX}/campaigns/{campaign_id}/flow",
        headers=support.auth() if headers is None else headers,
    )


def _wait_reason(dsn: str, job_id: str, blocking: str) -> None:
    reason = {
        "code": "DEPENDENCY_PENDING",
        "detail": "predecessor still running",
        "since": timestamp(datetime.now(UTC)),
        "blocking_job_ids": [blocking],
    }
    with connect(dsn) as conn, conn.transaction():
        conn.execute(
            "UPDATE scan_job SET wait_reason = %s WHERE job_id = %s", (Jsonb(reason), job_id)
        )


def _cancel(dsn: str, job_id: str) -> None:
    with connect(dsn) as conn, conn.transaction():
        conn.execute(
            "SELECT aegis.request_job_cancel(%s, %s, %s)",
            (job_id, Jsonb(OPERATOR), "operator stopped the scan"),
        )
    assert complete_job(dsn, job_id, "CANCELLED") == "terminalized"


FAILED_ERROR = {
    "code": "TOOL_UNAVAILABLE",
    "message": "the container exited before collecting",
    "next_action": "CHECK_PROVIDER",
    "trace_id": "0123456789abcdef0123456789abcdef",
}


def _graph(dsn: str) -> dict[str, Any]:
    """A campaign with a session decision and five jobs in every state the screen renders."""
    campaign = open_campaign(dsn, name="flow read model")
    session_id, decision_id = session_with_decision(dsn, campaign)
    with service(dsn) as jobs:
        first = accept_job(jobs, campaign, priority=60)
        second = accept_job(jobs, campaign, depends_on=[first])
        third = accept_job(jobs, campaign, depends_on=[second])
        cancelled = accept_job(jobs, campaign)
        failed = accept_job(jobs, campaign)
    run_job(dsn, first)
    assert complete_job(dsn, first, "SUCCEEDED") == "terminalized"
    run_job(dsn, second)
    _wait_reason(dsn, third, second)
    _cancel(dsn, cancelled)
    run_job(dsn, failed)
    assert complete_job(dsn, failed, "FAILED", error=FAILED_ERROR) == "terminalized"
    return {
        "campaign": campaign,
        "session": session_id,
        "session_decision": decision_id,
        "first": first,
        "second": second,
        "third": third,
        "cancelled": cancelled,
        "failed": failed,
    }


def _nodes(flow: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {node["id"]: node for node in flow["nodes"]}


def _edges(flow: dict[str, Any]) -> set[tuple[str, str, str]]:
    return {(edge["from"], edge["to"], edge["kind"]) for edge in flow["edges"]}


def test_the_flow_is_the_campaign_session_decisions_and_jobs_with_their_state() -> None:
    with migrated_database() as dsn:
        graph = _graph(dsn)
        client = _client(dsn)
        response = _get(client, graph["campaign"].campaign_id)
        assert response.status_code == 200, response.text
        flow = response.json()

        nodes = _nodes(flow)
        campaign_node = nodes[graph["campaign"].campaign_id]
        assert campaign_node["type"] == "campaign"
        assert campaign_node["status"] == "RUNNING"
        assert campaign_node["label"] == "flow read model"
        assert campaign_node["started_at"].endswith("Z")

        assert nodes[graph["session"]]["type"] == "session"
        assert nodes[graph["session"]]["status"] == "RUNNING"
        assert nodes[graph["session"]]["label"] == "M03 session: enumerate the lab zone"

        session_decision = nodes[graph["session_decision"]]
        assert session_decision["type"] == "decision"
        assert session_decision["status"] == "approved"

        first = nodes[graph["first"]]
        assert first["type"] == "job"
        assert first["status"] == "SUCCEEDED"
        assert (first["attempt"], first["generation"]) == (1, 1)
        assert first["label"].startswith("dns.enumerate_subdomains: internal.example")
        assert first["finished_at"].endswith("Z")

        second = nodes[graph["second"]]
        assert second["status"] == "RUNNING"
        assert "wait_reason" not in second  # the CHECK holds only for QUEUED jobs

        third = nodes[graph["third"]]
        assert third["status"] == "QUEUED"
        assert third["wait_reason"]["code"] == "DEPENDENCY_PENDING"
        assert third["wait_reason"]["blocking_job_ids"] == [graph["second"]]

        cancelled = nodes[graph["cancelled"]]
        assert cancelled["status"] == "CANCELLED"
        assert cancelled["cancel"]["reason"] == "operator stopped the scan"
        assert cancelled["cancel"]["requested_by"] == OPERATOR
        assert cancelled["cancel"]["requested_at"].endswith("Z")

        failed = nodes[graph["failed"]]
        assert failed["status"] == "FAILED"
        assert failed["error"]["code"] == "TOOL_UNAVAILABLE"

        decisions = {
            str(row["job_id"]): str(row["decision_id"])
            for row in support.fetch_all(
                dsn,
                "SELECT job_id, decision_id FROM scan_job WHERE campaign_id = %s",
                (graph["campaign"].campaign_id,),
            )
        }
        edges = _edges(flow)
        campaign_id = graph["campaign"].campaign_id
        assert (campaign_id, graph["session"], "initiates") in edges
        assert (graph["session"], graph["session_decision"], "evaluates") in edges
        # REST jobs have no agent session: their decision hangs off the campaign, then dispatches.
        assert (campaign_id, decisions[graph["first"]], "initiates") in edges
        assert (decisions[graph["first"]], graph["first"], "dispatches") in edges
        assert (graph["first"], graph["second"], "depends_on") in edges
        assert (graph["second"], graph["third"], "depends_on") in edges
        assert (graph["session"], graph["first"], "dispatches") not in edges


def test_only_job_nodes_carry_the_fencing_fields_and_the_response_satisfies_the_contract() -> None:
    with migrated_database() as dsn:
        graph = _graph(dsn)
        client = _client(dsn)
        flow = _get(client, graph["campaign"].campaign_id).json()

        contract = yaml.safe_load(
            (repository_root() / "contracts/api/openapi.v2.yaml").read_text(encoding="utf-8")
        )
        schema = contract["paths"][FLOW_PATH]["get"]["responses"]["200"]["content"][
            "application/json"
        ]["schema"]
        problems = list(support.validator(schema).iter_errors(flow))
        assert problems == [], f"flow must satisfy the contract: {problems[:2]}"

        for node in flow["nodes"]:
            if node["type"] == "job":
                assert {"attempt", "generation"} <= set(node)
            else:
                assert "attempt" not in node and "generation" not in node
                assert "wait_reason" not in node and "cancel" not in node


def test_the_revision_moves_only_when_something_the_flow_shows_changed() -> None:
    with migrated_database() as dsn:
        graph = _graph(dsn)
        client = _client(dsn)
        campaign = graph["campaign"]
        before = _get(client, campaign.campaign_id).json()["revision"]
        assert _get(client, campaign.campaign_id).json()["revision"] == before

        with service(dsn) as jobs:
            extra = accept_job(jobs, campaign)
        inserted = _get(client, campaign.campaign_id).json()["revision"]
        assert inserted > before

        run_job(dsn, extra)
        moved = _get(client, campaign.campaign_id).json()["revision"]
        assert moved > inserted


def test_a_campaign_without_activity_is_a_single_node() -> None:
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn, status="CREATED")
        client = _client(dsn)
        flow = _get(client, campaign.campaign_id).json()
        assert [node["type"] for node in flow["nodes"]] == ["campaign"]
        assert flow["edges"] == []
        assert isinstance(flow["revision"], int)


def test_another_campaigns_rows_are_never_mixed_in() -> None:
    with migrated_database() as dsn:
        mine = seed_campaign(dsn)
        theirs = _graph(dsn)
        flow = _get(_client(dsn), mine.campaign_id).json()
        assert {node["id"] for node in flow["nodes"]} == {mine.campaign_id}
        assert flow["edges"] == []
        assert theirs["campaign"].campaign_id not in {node["id"] for node in flow["nodes"]}


def test_an_unknown_or_malformed_campaign_is_404_in_error_v2() -> None:
    with migrated_database() as dsn:
        client = _client(dsn)
        for campaign_id in (uuid7(), "not-a-uuid"):
            response = _get(client, campaign_id)
            assert response.status_code == 404, campaign_id
            assert response.json()["code"] == "INPUT_INVALID"
            assert response.json()["next_action"] == "FIX_INPUT"
            assert response.json()["trace_id"]


def test_a_row_that_violates_the_contract_fails_loudly_instead_of_shipping() -> None:
    """A producer that stores a non-`error.v2` error must not be rendered as a valid 200."""
    with migrated_database() as dsn:
        campaign = open_campaign(dsn, name="bad producer")
        with service(dsn) as jobs:
            job = accept_job(jobs, campaign)
        run_job(dsn, job)
        assert (
            complete_job(
                dsn, job, "FAILED", error={"code": "TOOL_ERROR", "message": "not a contract error"}
            )
            == "terminalized"
        )
        response = _get(_client(dsn), campaign.campaign_id)
        assert response.status_code == 500, response.text
        assert response.json()["code"] == "INTERNAL_ERROR"
        assert "getCampaignFlow" in response.json()["message"]


def test_the_flow_requires_the_operator_token(dsn: str) -> None:
    campaign = open_campaign(dsn, name="flow auth")
    client = _client(dsn)
    for headers, expected in (
        ({}, 401),
        ({"authorization": "Bearer not-a-token"}, 401),
        (support.auth("op-soc-2"), 200),
    ):
        response = _get(client, campaign.campaign_id, headers=headers)
        assert response.status_code == expected, (headers, response.text)
        if expected == 401:
            assert response.json()["code"] == "INPUT_INVALID"
            assert response.headers["www-authenticate"] == "Bearer"
