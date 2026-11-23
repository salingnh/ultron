"""tools/call idempotency: same key x100 -> one job (NFR-02 case, fake registry)."""

from __future__ import annotations

import asyncio

import pytest
from mcp.shared.exceptions import MCPError

from aegis_mcp.client import call_capability, connected

from .support import (
    CAMPAIGN_ID,
    ENUMERATE,
    OTHER_CAMPAIGN_ID,
    OTHER_SESSION_ID,
    SESSION_ID,
    enumerate_request,
    make_service,
    meta,
    serve,
)

pytestmark = pytest.mark.anyio

BURST = 100


async def test_100_concurrent_identical_calls_create_one_job():
    service = make_service()
    async with serve(service) as url, connected(url) as session:
        results = await asyncio.gather(
            *(
                call_capability(session, ENUMERATE, enumerate_request(), meta())
                for _ in range(BURST)
            )
        )
    job_ids = {result.structured_content["job_id"] for result in results}
    assert len(job_ids) == 1
    assert len(service.registry.jobs) == 1
    assert all(result.is_error is False for result in results)
    decisions = [result.structured_content["decision"] for result in results]
    assert decisions.count("approved") == 1
    assert decisions.count("duplicate") == BURST - 1


async def test_handler_burst_is_race_safe():
    service = make_service()
    results = await asyncio.gather(
        *(
            service.call(
                tool_name=ENUMERATE,
                arguments=enumerate_request(),
                request_meta=meta(),
                mcp_session_id="handler-connection",
            )
            for _ in range(BURST)
        )
    )
    assert len({result.structured_content["job_id"] for result in results}) == 1
    assert len(service.registry.jobs) == 1


async def test_without_the_idempotency_lock_duplicates_appear():
    """Negative control: the burst test would catch a missing lock/unique index."""
    service = make_service()
    service.registry.lock_enabled = False
    service.registry.write_latency = 0.001
    await asyncio.gather(
        *(
            service.call(
                tool_name=ENUMERATE,
                arguments=enumerate_request(),
                request_meta=meta(),
                mcp_session_id="handler-connection",
            )
            for _ in range(BURST)
        )
    )
    assert len(service.registry.jobs) > 1


async def test_same_key_different_input_is_a_conflict():
    service = make_service()
    async with serve(service) as url, connected(url) as session:
        first = await call_capability(session, ENUMERATE, enumerate_request(), meta())
        assert first.structured_content["decision"] == "approved"
        conflict = await call_capability(
            session,
            ENUMERATE,
            enumerate_request(input={"targets": ["other.example.test"]}),
            meta(),
        )
    assert conflict.is_error is True
    assert conflict.structured_content["decision"] == "denied"
    assert conflict.structured_content["error"]["code"] == "INPUT_INVALID"
    assert conflict.structured_content["error"]["field"] == "/_meta/aegis.io~1idempotency_key"
    assert len(service.registry.jobs) == 1
    assert first.structured_content["job_id"] in service.registry.jobs


async def test_same_key_different_scheduling_is_a_conflict():
    service = make_service()
    async with serve(service) as url, connected(url) as session:
        await call_capability(session, ENUMERATE, enumerate_request(), meta())
        conflict = await call_capability(
            session, ENUMERATE, enumerate_request(priority=80), meta()
        )
    assert conflict.is_error is True
    assert conflict.structured_content["error"]["code"] == "INPUT_INVALID"
    assert "priority" in conflict.structured_content["error"]["message"]
    assert len(service.registry.jobs) == 1


async def test_different_keys_create_different_jobs():
    service = make_service()
    async with serve(service) as url, connected(url) as session:
        first = await call_capability(session, ENUMERATE, enumerate_request(), meta())
        second = await call_capability(
            session,
            ENUMERATE,
            enumerate_request(),
            meta(**{"aegis.io/idempotency_key": f"{SESSION_ID}:step:2"}),
        )
    assert first.structured_content["job_id"] != second.structured_content["job_id"]
    assert len(service.registry.jobs) == 2


async def test_retry_on_a_new_connection_returns_the_same_job():
    service = make_service()
    async with serve(service) as url:
        async with connected(url) as first:
            original = await call_capability(first, ENUMERATE, enumerate_request(), meta())
        async with connected(url) as retry:
            repeated = await call_capability(retry, ENUMERATE, enumerate_request(), meta())
    assert original.structured_content["job_id"] == repeated.structured_content["job_id"]
    assert repeated.structured_content["decision"] == "duplicate"
    assert len(service.registry.jobs) == 1


async def test_idempotency_key_is_scoped_per_campaign():
    service = make_service()
    key = f"{SESSION_ID}:step:1"
    async with serve(service) as url:
        async with connected(url) as first:
            job_a = await call_capability(first, ENUMERATE, enumerate_request(), meta())
        async with connected(url) as second:
            job_b = await call_capability(
                second,
                ENUMERATE,
                enumerate_request(),
                meta(
                    **{
                        "aegis.io/campaign_id": OTHER_CAMPAIGN_ID,
                        "aegis.io/session_id": OTHER_SESSION_ID,
                        "aegis.io/idempotency_key": key,
                    }
                ),
            )
    assert job_a.structured_content["decision"] == "approved"
    assert job_b.structured_content["decision"] == "approved"
    assert job_a.structured_content["job_id"] != job_b.structured_content["job_id"]
    assert {job.campaign_id for job in service.registry.jobs.values()} == {
        CAMPAIGN_ID,
        OTHER_CAMPAIGN_ID,
    }
