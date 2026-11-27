"""`tools/call` through the real M05 acceptance path on PostgreSQL 18.

The card's signal is "the same acceptance path as POST /jobs": one decision, one signed task, one
job, the campaign's policy, and `IDEMPOTENCY_CONFLICT` semantics - with the one MCP difference that
the proposing agent session is server-derived (`proposed_by`) and the idempotency key is bound to
that session (E-4). This suite proves it against the contract schema, not against a fake.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from mcp.shared.exceptions import MCPError
from psycopg.types.json import Jsonb

from aegis.m05_registry.mcp.campaign import PostgresCampaignPolicies
from aegis.m05_registry.mcp.graph import UnavailableGraphQueries
from aegis.m05_registry.mcp.service import McpToolService
from aegis.m05_registry.mcp.session import PostgresSessionDirectory
from aegis.m05_registry.registry import PostgresManifestRegistry
from aegis.m05_registry.service import PostgresJobService
from aegis.m05_registry.signing import KeyRing
from tests.db_support import (
    OPERATOR,
    SeededCampaign,
    connect,
    migrated_database,
    policy_document,
    requires_postgres,
    seed_campaign,
)
from tests.mcp_support import (
    ENUMERATE,
    OBJECTIVE_ID,
    SESSION_ID,
    TRACE_ID,
    arguments,
    manifest_bytes,
    meta,
    seed_agent_session,
)

pytestmark = requires_postgres

SECOND_SESSION_ID = "01934f6a-0000-7000-8000-0000000000b1"


class FixedBinder:
    """Deterministic resolver; the subfinder fixture is targetBinding `none`, so it is unused."""

    def addresses(self, value: str) -> tuple[str, ...]:
        return ("198.51.100.10",)


@contextmanager
def service(dsn: str) -> Iterator[tuple[McpToolService, KeyRing]]:
    opener = lambda: connect(dsn)  # noqa: E731 - a lambda keeps the opener type simple
    registry = PostgresManifestRegistry(opener)
    for raw in manifest_bytes():
        registry.register(raw, registered_by={"kind": "module", "id": "M05"})
    ring = KeyRing.dev()
    yield (
        McpToolService(
            registry=registry,
            jobs=PostgresJobService(opener, registry=registry, key_ring=ring, binder=FixedBinder()),
            sessions=PostgresSessionDirectory(opener),
            policies=PostgresCampaignPolicies(opener),
            graph=UnavailableGraphQueries(),
        ),
        ring,
    )


def scalar(dsn: str, query: str, params: tuple[Any, ...] = ()) -> Any:
    with connect(dsn) as conn:
        row = conn.execute(query, params).fetchone()
    return None if row is None else row[0]


def call(
    service_: McpToolService,
    *,
    tool_name: str = ENUMERATE,
    call_arguments: dict[str, Any] | None = None,
    request_meta: dict[str, Any] | None = None,
    transport: str = "transport-1",
) -> dict[str, Any]:
    result = service_.call(
        tool_name=tool_name,
        arguments=arguments() if call_arguments is None else call_arguments,
        request_meta=meta() if request_meta is None else request_meta,
        mcp_session_id=transport,
    )
    assert result.structured_content is not None
    return dict(result.structured_content)


@pytest.fixture
def campaign() -> Iterator[tuple[str, SeededCampaign]]:
    with migrated_database() as dsn:
        seeded = seed_campaign(dsn)
        seed_agent_session(
            dsn,
            seeded.campaign_id,
            SESSION_ID,
            policy_version=seeded.policy_version,
            objective_id=OBJECTIVE_ID,
        )
        yield dsn, seeded


def test_a_tool_call_is_one_m05_decision_one_signed_task_one_job(
    campaign: tuple[str, SeededCampaign],
) -> None:
    dsn, seeded = campaign
    with service(dsn) as (mcp, ring):
        response = call(mcp, request_meta=meta(**{"aegis.io/campaign_id": seeded.campaign_id}))

    assert response["decision"] == "approved"
    assert response["job_status"] == "QUEUED"
    assert response["provider"] == "subfinder"
    assert scalar(dsn, "SELECT count(*) FROM policy_decision") == 1
    assert scalar(dsn, "SELECT count(*) FROM scan_job") == 1

    query = (
        "SELECT proposed_by, session_id, requested_by, idempotency_key, trace_id "
        "FROM policy_decision"
    )
    with connect(dsn) as conn:
        role = conn.execute(query).fetchone()
    assert role is not None
    proposed_by, session_id, requested_by, key, trace = role
    assert proposed_by == {"kind": "agent", "id": SESSION_ID}
    assert str(session_id) == SESSION_ID
    # OI-4: the initiator is the operator who started the campaign run, not M05.
    assert requested_by == OPERATOR
    assert key == meta()["aegis.io/idempotency_key"]
    assert trace == TRACE_ID

    task = scalar(
        dsn, "SELECT approved_task FROM scan_job WHERE job_id = %s", (response["job_id"],)
    )
    assert task["proposed_by"] == {"kind": "agent", "id": SESSION_ID}
    ring.verify(dict(task))  # the job the agent caused is the task M06 will run
    assert scalar(dsn, "SELECT status FROM scan_job") == "QUEUED"
    assert str(scalar(dsn, "SELECT scan_cycle FROM scan_job")) == SESSION_ID


def test_the_latest_running_transition_actor_is_the_initiator(
    campaign: tuple[str, SeededCampaign],
) -> None:
    dsn, seeded = campaign
    resumed = {"kind": "operator", "id": "op-resume"}
    with connect(dsn) as conn, conn.transaction():
        conn.execute(
            "INSERT INTO campaign_status_change (campaign_id, seq, from_status, to_status, "
            "actor, trace_id) VALUES (%s, 2, 'PAUSED', 'RUNNING', %s, %s)",
            (seeded.campaign_id, Jsonb(resumed), TRACE_ID),
        )
    with service(dsn) as (mcp, _):
        response = call(mcp, request_meta=meta(**{"aegis.io/campaign_id": seeded.campaign_id}))

    assert response["decision"] == "approved"
    assert scalar(dsn, "SELECT requested_by FROM scan_job") == resumed
    assert scalar(dsn, "SELECT requested_by FROM policy_decision") == resumed


def test_a_retry_with_the_same_key_replays_the_same_job(
    campaign: tuple[str, SeededCampaign],
) -> None:
    dsn, seeded = campaign
    with service(dsn) as (mcp, _):
        first = call(mcp, request_meta=meta(**{"aegis.io/campaign_id": seeded.campaign_id}))
        second = call(mcp, request_meta=meta(**{"aegis.io/campaign_id": seeded.campaign_id}))

    assert first["decision"] == "approved"
    assert second["decision"] == "duplicate"
    assert second["job_id"] == first["job_id"]
    assert scalar(dsn, "SELECT count(*) FROM scan_job") == 1


def test_one_hundred_calls_with_one_key_create_one_job(
    campaign: tuple[str, SeededCampaign],
) -> None:
    dsn, seeded = campaign
    with service(dsn) as (mcp, _):
        responses = [
            call(mcp, request_meta=meta(**{"aegis.io/campaign_id": seeded.campaign_id}))
            for _ in range(100)
        ]

    assert [item["decision"] for item in responses].count("approved") == 1
    assert [item["decision"] for item in responses].count("duplicate") == 99
    assert {item["job_id"] for item in responses} == {responses[0]["job_id"]}
    assert scalar(dsn, "SELECT count(*) FROM scan_job") == 1


def test_another_session_reusing_the_key_is_a_conflict_and_gets_no_job(
    campaign: tuple[str, SeededCampaign],
) -> None:
    dsn, seeded = campaign
    seed_agent_session(
        dsn,
        seeded.campaign_id,
        SECOND_SESSION_ID,
        policy_version=seeded.policy_version,
        objective_id=OBJECTIVE_ID,
    )
    with service(dsn) as (mcp, _):
        call(mcp, request_meta=meta(**{"aegis.io/campaign_id": seeded.campaign_id}))
        rejected = call(
            mcp,
            request_meta=meta(
                **{
                    "aegis.io/campaign_id": seeded.campaign_id,
                    "aegis.io/session_id": SECOND_SESSION_ID,
                }
            ),
            transport="transport-2",
        )

    assert rejected["decision"] == "denied"
    assert rejected["error"]["code"] == "IDEMPOTENCY_CONFLICT"
    assert "field" not in rejected["error"]
    assert scalar(dsn, "SELECT count(*) FROM scan_job") == 1
    assert scalar(dsn, "SELECT count(*) FROM policy_decision") == 1


def test_a_denylisted_capability_is_not_listed_and_its_call_is_refused() -> None:
    with migrated_database() as dsn:
        seeded = seed_campaign(dsn, policy=policy_document(capability_denylist=["dns.resolve"]))
        seed_agent_session(
            dsn,
            seeded.campaign_id,
            SESSION_ID,
            policy_version=seeded.policy_version,
            objective_id=OBJECTIVE_ID,
        )
        with service(dsn) as (mcp, _):
            tools = mcp.list_tools(
                request_meta=meta(**{"aegis.io/campaign_id": seeded.campaign_id}),
                mcp_session_id="transport-1",
            )
            names = [tool.name for tool in tools.tools]
            assert "dns.resolve" not in names
            assert ENUMERATE in names
            with pytest.raises(MCPError) as caught:
                mcp.call(
                    tool_name="dns.resolve",
                    arguments=arguments(input={"targets": ["internal.example"]}),
                    request_meta=meta(**{"aegis.io/campaign_id": seeded.campaign_id}),
                    mcp_session_id="transport-1",
                )
            assert caught.value.code == -32602
            assert scalar(dsn, "SELECT count(*) FROM scan_job") == 0


def test_a_policy_refusal_records_the_session_as_proposer() -> None:
    with migrated_database() as dsn:
        seeded = seed_campaign(dsn, policy=policy_document(target_denylist=["internal.example"]))
        seed_agent_session(
            dsn,
            seeded.campaign_id,
            SESSION_ID,
            policy_version=seeded.policy_version,
            objective_id=OBJECTIVE_ID,
        )
        with service(dsn) as (mcp, _):
            response = call(mcp, request_meta=meta(**{"aegis.io/campaign_id": seeded.campaign_id}))

        assert response["decision"] == "denied"
        assert response["error"]["code"] == "OUT_OF_SCOPE"
        decision = scalar(dsn, "SELECT proposed_by FROM policy_decision WHERE decision = 'denied'")
        assert decision == {"kind": "agent", "id": SESSION_ID}
        assert scalar(dsn, "SELECT count(*) FROM scan_job") == 0
        assert scalar(dsn, "SELECT count(*) FROM outbox_event WHERE type = 'policy.denied.v2'") == 1


def test_a_session_that_is_not_running_is_refused(campaign: tuple[str, SeededCampaign]) -> None:
    dsn, seeded = campaign
    with connect(dsn) as conn, conn.transaction():
        conn.execute(
            "UPDATE agent_session SET status = 'SUCCEEDED' WHERE session_id = %s",
            (SESSION_ID,),
        )
    with service(dsn) as (mcp, _):
        with pytest.raises(MCPError) as caught:
            call(mcp, request_meta=meta(**{"aegis.io/campaign_id": seeded.campaign_id}))

    assert "not RUNNING" in str(caught.value.data)
    assert scalar(dsn, "SELECT count(*) FROM scan_job") == 0
