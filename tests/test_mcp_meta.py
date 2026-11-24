"""`params._meta`: the four contract keys, their formats, and `-32602` with `error.v2`.

G0.3a verified on the wire that the SDK hands `aegis.io/*` keys to the handler untouched. These
tests pin the server's side of the table: every required key, every format, the namespace rule, and
that a bad `_meta` creates no job.
"""

from __future__ import annotations

import pytest
from mcp.shared.exceptions import MCPError
from mcp.types import INVALID_PARAMS

from aegis.m05_registry.mcp import meta as meta_contract
from aegis.m05_registry.mcp.schemas import error_schema
from tests.mcp_support import ENUMERATE, FOREIGN_SESSION_ID, arguments, make_service, meta


def _data(error: MCPError) -> dict[str, object]:
    assert isinstance(error.data, dict)
    return error.data


def test_a_complete_meta_is_parsed() -> None:
    parsed, problems = meta_contract.parse_meta(meta())

    assert problems == []
    assert parsed is not None
    assert parsed.campaign_id == meta()["aegis.io/campaign_id"]
    assert parsed.session_id == meta()["aegis.io/session_id"]
    assert parsed.trace_id == meta()["aegis.io/trace_id"]


def test_absent_meta_reports_every_required_key() -> None:
    parsed, problems = meta_contract.parse_meta(None)

    assert parsed is None
    assert [problem.field for problem in problems] == list(meta_contract.REQUIRED_KEYS)
    assert [problem.pointer for problem in problems] == [
        "/_meta/aegis.io~1trace_id",
        "/_meta/aegis.io~1campaign_id",
        "/_meta/aegis.io~1session_id",
        "/_meta/aegis.io~1idempotency_key",
    ]


def test_a_missing_key_is_named_by_its_pointer() -> None:
    value = meta()
    del value["aegis.io/session_id"]
    parsed, problems = meta_contract.parse_meta(value)

    assert parsed is None
    assert [problem.pointer for problem in problems] == ["/_meta/aegis.io~1session_id"]
    assert problems[0].message == "required params._meta key is missing"


@pytest.mark.parametrize(
    ("key", "value", "pointer"),
    [
        ("aegis.io/trace_id", "0123456789ABCDEF0123456789ABCDEF", "/_meta/aegis.io~1trace_id"),
        ("aegis.io/campaign_id", "not-a-uuid", "/_meta/aegis.io~1campaign_id"),
        (
            "aegis.io/session_id",
            "01934f6a-0000-6000-8000-000000000003",
            "/_meta/aegis.io~1session_id",
        ),
        ("aegis.io/idempotency_key", "short", "/_meta/aegis.io~1idempotency_key"),
        ("aegis.io/idempotency_key", "has spaces or/slashes", "/_meta/aegis.io~1idempotency_key"),
    ],
)
def test_a_wrong_value_is_rejected_with_its_pointer(key: str, value: str, pointer: str) -> None:
    parsed, problems = meta_contract.parse_meta(meta(**{key: value}))

    assert parsed is None
    assert [problem.pointer for problem in problems] == [pointer]


def test_an_unknown_key_in_the_reserved_namespace_is_refused() -> None:
    parsed, problems = meta_contract.parse_meta(meta(**{"aegis.io/tenant": "x"}))

    assert parsed is None
    assert [problem.pointer for problem in problems] == ["/_meta/aegis.io~1tenant"]
    assert "reserved" in problems[0].message


def test_foreign_keys_outside_the_namespace_are_ignored() -> None:
    parsed, problems = meta_contract.parse_meta(meta(progressToken="p-1"))

    assert problems == []
    assert parsed is not None


def test_a_non_string_value_is_refused() -> None:
    parsed, problems = meta_contract.parse_meta(meta(**{"aegis.io/idempotency_key": 7}))

    assert parsed is None
    assert [problem.field for problem in problems] == ["aegis.io/idempotency_key"]
    assert problems[0].message == "value must be a string"


def test_call_without_meta_is_minus_32602_and_creates_no_job() -> None:
    service = make_service()
    with pytest.raises(MCPError) as caught:
        service.call(
            tool_name=ENUMERATE,
            arguments=arguments(),
            request_meta=None,
            mcp_session_id="transport-1",
        )

    error = caught.value
    assert error.code == INVALID_PARAMS
    data = _data(error)
    assert data["code"] == "INPUT_INVALID"
    assert data["next_action"] == "FIX_INPUT"
    assert data["field"] == "/_meta/aegis.io~1trace_id"
    assert "trace_id" not in data or data["trace_id"] is None
    # The data object is a contract error, not a free-form dict.
    assert error_schema().problems(data) == []
    assert service.jobs.submissions == []  # type: ignore[attr-defined]


def test_a_session_from_another_campaign_is_refused() -> None:
    service = make_service()
    foreign = FOREIGN_SESSION_ID  # exists, but in OTHER_CAMPAIGN_ID
    with pytest.raises(MCPError) as caught:
        service.call(
            tool_name=ENUMERATE,
            arguments=arguments(),
            request_meta=meta(**{"aegis.io/session_id": foreign}),
            mcp_session_id="transport-1",
        )

    data = _data(caught.value)
    assert caught.value.code == INVALID_PARAMS
    assert data["field"] == "/_meta/aegis.io~1session_id"
    assert data["code"] == "INPUT_INVALID"
    assert service.jobs.submissions == []  # type: ignore[attr-defined]


def test_an_unknown_session_is_refused() -> None:
    service = make_service()
    unknown = "01934f6a-0000-7000-8000-0000000000ff"
    with pytest.raises(MCPError) as caught:
        service.call(
            tool_name=ENUMERATE,
            arguments=arguments(),
            request_meta=meta(**{"aegis.io/session_id": unknown}),
            mcp_session_id="transport-1",
        )

    assert "no such agent session" in str(_data(caught.value)["message"])
    assert service.jobs.submissions == []  # type: ignore[attr-defined]


def test_tools_list_without_aegis_meta_is_the_admitted_catalogue() -> None:
    """No `aegis.io/*` key means no campaign: the SDK's own schema probe must still work."""
    service = make_service()

    tools = service.list_tools(request_meta=None, mcp_session_id="transport-1")

    assert any(tool.name == ENUMERATE for tool in tools.tools)
    filtered = service.list_tools(request_meta=meta(), mcp_session_id="transport-1")
    assert any(tool.name == ENUMERATE for tool in filtered.tools)


def test_tools_list_with_a_broken_aegis_meta_is_refused() -> None:
    service = make_service()
    with pytest.raises(MCPError) as caught:
        service.list_tools(
            request_meta={"aegis.io/campaign_id": meta()["aegis.io/campaign_id"]},
            mcp_session_id="transport-1",
        )

    assert caught.value.code == INVALID_PARAMS
    assert _data(caught.value)["code"] == "INPUT_INVALID"
    assert _data(caught.value)["field"] == "/_meta/aegis.io~1trace_id"
