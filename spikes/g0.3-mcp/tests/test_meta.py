"""params._meta: required keys, formats, and session binding (G0.3a)."""

from __future__ import annotations

import anyio
import pytest
from mcp.shared.exceptions import MCPError

from aegis_mcp.client import call_capability, connected
from aegis_mcp.service import invalid_params

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


def _assert_invalid(error: MCPError, field: str) -> dict:
    assert error.code == -32602
    assert error.message.startswith("INPUT_INVALID")
    data = error.error.data
    assert data["code"] == "INPUT_INVALID"
    assert data["next_action"] == "FIX_INPUT"
    assert data["field"] == field
    return data


async def test_valid_meta_returns_capability_response_v2():
    service = make_service()
    async with serve(service) as url, connected(url) as session:
        result = await call_capability(session, ENUMERATE, enumerate_request(), meta())
    assert result.is_error is False
    assert result.structured_content["decision"] == "approved"
    assert result.structured_content["job_status"] == "QUEUED"
    assert result.structured_content["policy_version"] == "roe-1"
    assert result.structured_content["provider"].startswith("dns-enumerate_subdomains-")
    assert len(service.registry.jobs) == 1


async def test_absent_meta_is_input_invalid():
    service = make_service()
    async with serve(service) as url, connected(url) as session:
        with pytest.raises(MCPError) as raised:
            await session.call_tool(ENUMERATE, enumerate_request())
    data = _assert_invalid(raised.value, "/_meta/aegis.io~1trace_id")
    assert "missing" in data["message"]
    assert service.registry.jobs == {}


async def test_missing_single_key_names_that_key():
    service = make_service()
    bad = meta()
    del bad["aegis.io/idempotency_key"]
    async with serve(service) as url, connected(url) as session:
        with pytest.raises(MCPError) as raised:
            await call_capability(session, ENUMERATE, enumerate_request(), bad)
    data = _assert_invalid(raised.value, "/_meta/aegis.io~1idempotency_key")
    assert "idempotency_key" in data["message"]
    assert service.registry.jobs == {}


@pytest.mark.parametrize(
    ("key", "value", "field"),
    [
        ("aegis.io/trace_id", "not-hex", "/_meta/aegis.io~1trace_id"),
        ("aegis.io/trace_id", "A" * 32, "/_meta/aegis.io~1trace_id"),
        ("aegis.io/campaign_id", CAMPAIGN_ID.replace("-7000-", "-4000-"), "/_meta/aegis.io~1campaign_id"),
        ("aegis.io/session_id", "01934f6a-0000-7000-8000-00000000000Z", "/_meta/aegis.io~1session_id"),
        ("aegis.io/idempotency_key", "short", "/_meta/aegis.io~1idempotency_key"),
        ("aegis.io/idempotency_key", "has spaces in it", "/_meta/aegis.io~1idempotency_key"),
    ],
)
async def test_wrong_meta_value_is_input_invalid(key, value, field):
    service = make_service()
    async with serve(service) as url, connected(url) as session:
        with pytest.raises(MCPError) as raised:
            await call_capability(session, ENUMERATE, enumerate_request(), meta(**{key: value}))
    _assert_invalid(raised.value, field)
    assert service.registry.jobs == {}


async def test_unknown_namespaced_key_is_rejected_but_other_keys_pass():
    service = make_service()
    async with serve(service) as url, connected(url) as session:
        with pytest.raises(MCPError) as raised:
            await call_capability(
                session, ENUMERATE, enumerate_request(), meta(**{"aegis.io/trace-id": "typo"})
            )
    _assert_invalid(raised.value, "/_meta/aegis.io~1trace-id")

    async with serve(service) as url, connected(url) as session:
        ok = await call_capability(
            session, ENUMERATE, enumerate_request(), meta(progressToken="client-owned")
        )
    assert ok.structured_content["decision"] == "approved"


async def test_unknown_session_is_input_invalid():
    service = make_service()
    unknown = meta(**{"aegis.io/session_id": "01934f6a-0000-7000-8000-0000000000aa"})
    async with serve(service) as url, connected(url) as session:
        with pytest.raises(MCPError) as raised:
            await call_capability(session, ENUMERATE, enumerate_request(), unknown)
    data = _assert_invalid(raised.value, "/_meta/aegis.io~1session_id")
    assert "unknown" in data["message"]
    assert service.registry.jobs == {}


async def test_meta_cannot_switch_campaign_or_session_after_binding():
    service = make_service()
    async with serve(service) as url, connected(url) as session:
        first = await call_capability(session, ENUMERATE, enumerate_request(), meta())
        assert first.structured_content["decision"] == "approved"

        # same campaign, a different *known* agent session on the same MCP connection
        with pytest.raises(MCPError) as raised:
            await call_capability(
                session,
                ENUMERATE,
                enumerate_request(),
                meta(
                    **{
                        "aegis.io/session_id": OTHER_SESSION_ID,
                        "aegis.io/idempotency_key": f"{OTHER_SESSION_ID}:step:1",
                    }
                ),
            )
        _assert_invalid(raised.value, "/_meta/aegis.io~1session_id")
        assert "mismatch" in raised.value.error.data["message"]

        # a different campaign is refused the same way
        with pytest.raises(MCPError) as raised:
            await call_capability(
                session,
                ENUMERATE,
                enumerate_request(),
                meta(
                    **{
                        "aegis.io/campaign_id": OTHER_CAMPAIGN_ID,
                        "aegis.io/session_id": OTHER_SESSION_ID,
                        "aegis.io/idempotency_key": f"{OTHER_SESSION_ID}:step:2",
                    }
                ),
            )
        _assert_invalid(raised.value, "/_meta/aegis.io~1session_id")
    assert len(service.registry.jobs) == 1


async def test_two_connections_get_their_own_binding():
    service = make_service()
    async with serve(service) as url:
        async with connected(url) as first:
            await call_capability(first, ENUMERATE, enumerate_request(), meta())
        async with connected(url) as second:
            # a new MCP connection may bind to the other known campaign session
            result = await call_capability(
                second,
                ENUMERATE,
                enumerate_request(),
                meta(
                    **{
                        "aegis.io/campaign_id": OTHER_CAMPAIGN_ID,
                        "aegis.io/session_id": OTHER_SESSION_ID,
                        "aegis.io/idempotency_key": f"{OTHER_SESSION_ID}:step:1",
                    }
                ),
            )
    assert result.structured_content["decision"] == "approved"
    assert len(service.registry.jobs) == 2


def test_invalid_params_serialises_error_v2():
    error = invalid_params(field="/_meta/aegis.io~1trace_id", message="missing", trace_id="a" * 32)
    assert error.code == -32602
    assert error.error.data["field"] == "/_meta/aegis.io~1trace_id"
    assert error.error.data["trace_id"] == "a" * 32
