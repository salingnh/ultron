"""`tools/call` on a capability: M05 accepted/duplicate, policy refusals, and the error channels.

The acceptance path is M05's (`PostgresJobService.submit`, proven against PostgreSQL in
`test_mcp_acceptance_pg.py`); this suite pins the MCP mapping around it with the `JobService` seam:

* approved -> `decision=approved` + the job's own status/provider/policy version;
* a replayed key -> `decision=duplicate`, same `job_id`, `isError=false`;
* a policy refusal -> `isError=true` and a **complete** `capability-response.v2` with `error.v2`
  inside; `field` only appears on `INPUT_INVALID` (mcp/README.md);
* a schema breach is a protocol `-32602`, not a job refusal: no job is created either way.
"""

from __future__ import annotations

from typing import Any

import pytest
from mcp import types
from mcp.shared.exceptions import MCPError
from mcp.types import INVALID_PARAMS

from aegis.m05_registry.errors import M05Error
from aegis.m05_registry.mcp.schemas import capability_response_schema, error_schema
from aegis.m05_registry.mcp.service import McpToolService
from tests.mcp_support import (
    CAMPAIGN_ID,
    ENUMERATE,
    OBJECTIVE_ID,
    OTHER_OBJECTIVE_ID,
    OTHER_SESSION_ID,
    RUN_OPERATOR,
    FakeJobService,
    arguments,
    make_service,
    meta,
)

TRANSPORT = "transport-1"


def call(
    service: McpToolService,
    *,
    tool_name: str = ENUMERATE,
    call_arguments: dict[str, Any] | None = None,
    request_meta: dict[str, Any] | None = None,
    transport: str = TRANSPORT,
) -> types.CallToolResult:
    return service.call(
        tool_name=tool_name,
        arguments=arguments() if call_arguments is None else call_arguments,
        request_meta=meta() if request_meta is None else request_meta,
        mcp_session_id=transport,
    )


def structured(result: types.CallToolResult) -> dict[str, Any]:
    value = result.structured_content
    assert value is not None
    return dict(value)


def data(error: MCPError) -> dict[str, Any]:
    assert isinstance(error.data, dict)
    return dict(error.data)


def test_an_approved_call_returns_the_job_identity_and_records_the_session() -> None:
    service = make_service()
    result = call(service)

    assert result.is_error is False
    value = structured(result)
    assert capability_response_schema().problems(value) == []
    assert value["decision"] == "approved"
    assert value["job_status"] == "QUEUED"
    assert value["provider"] == "subfinder"
    assert value["policy_version"] == "roe-1"

    submitted = service.jobs.submissions[0]  # type: ignore[attr-defined]
    # OI-4: the run's operator is the initiator; the agent session is only the proposer.
    assert submitted["requested_by"] == RUN_OPERATOR
    assert submitted["proposed_by"] == {"kind": "agent", "id": meta()["aegis.io/session_id"]}
    assert submitted["idempotency_key"] == meta()["aegis.io/idempotency_key"]
    assert submitted["trace_id"] == meta()["aegis.io/trace_id"]


def test_the_same_key_and_body_is_a_duplicate_of_the_same_job() -> None:
    service = make_service()
    first = structured(call(service))
    second_result = call(service)
    second = structured(second_result)

    assert first["decision"] == "approved"
    assert second_result.is_error is False
    assert second["decision"] == "duplicate"
    assert second["job_id"] == first["job_id"]
    assert len(service.jobs.submissions) == 1  # type: ignore[attr-defined]


def test_the_same_key_from_another_session_is_an_idempotency_conflict_without_a_field() -> None:
    service = make_service()
    call(service)
    result = call(
        service,
        request_meta=meta(**{"aegis.io/session_id": OTHER_SESSION_ID}),
        call_arguments=arguments(objective_id=OTHER_OBJECTIVE_ID),
        transport="transport-2",
    )

    assert result.is_error is True
    value = structured(result)
    assert value["decision"] == "denied"
    assert value["error"]["code"] == "IDEMPOTENCY_CONFLICT"
    assert "field" not in value["error"]
    assert error_schema().problems(value["error"]) == []
    assert len(service.jobs.submissions) == 1  # type: ignore[attr-defined]


def test_the_same_key_with_another_body_is_an_idempotency_conflict() -> None:
    service = make_service()
    call(service)
    changed = call(service, call_arguments=arguments(input={"targets": ["other.internal.example"]}))

    value = structured(changed)
    assert value["error"]["code"] == "IDEMPOTENCY_CONFLICT"
    assert "field" not in value["error"]


def test_a_policy_refusal_is_an_error_result_with_the_contract_shape() -> None:
    refusal = M05Error.policy_denied(
        "target_denylist", "the target is in the campaign's deny list", field="/input/targets"
    )
    service = make_service(jobs=FakeJobService(refusals={ENUMERATE: refusal}))
    result = call(service)

    assert result.is_error is True
    value = structured(result)
    assert capability_response_schema().problems(value) == []
    assert value["decision"] == "denied"
    assert value["error"]["code"] == "POLICY_DENIED"
    assert value["error"]["next_action"] == "FIX_INPUT"
    assert "field" not in value["error"]  # field is INPUT_INVALID-only on the wire
    assert value["error"]["trace_id"] == meta()["aegis.io/trace_id"]


def test_an_input_refusal_keeps_its_field() -> None:
    refusal = M05Error.input_invalid(
        "input does not satisfy the pinned schema", field="/input/targets/0"
    )
    service = make_service(jobs=FakeJobService(refusals={ENUMERATE: refusal}))
    value = structured(call(service))

    assert value["decision"] == "denied"
    assert value["error"]["code"] == "INPUT_INVALID"
    assert value["error"]["field"] == "/input/targets/0"


@pytest.mark.parametrize(
    ("bad", "pointer"),
    [
        (arguments(rationale="short"), "/arguments/rationale"),
        (arguments(input={"targets": "internal.example"}), "/arguments/input/targets"),
        (arguments(priority=101), "/arguments/priority"),
        (arguments(objective_id="not-a-uuid"), "/arguments/objective_id"),
        (arguments(input={"targets": []}), "/arguments/input/targets"),
    ],
)
def test_a_schema_breach_is_minus_32602_at_the_argument_pointer(
    bad: dict[str, Any], pointer: str
) -> None:
    service = make_service()
    with pytest.raises(MCPError) as caught:
        call(service, call_arguments=bad)

    assert caught.value.code == INVALID_PARAMS
    assert data(caught.value)["code"] == "INPUT_INVALID"
    assert str(data(caught.value)["field"]).startswith(pointer)
    assert service.jobs.submissions == []  # type: ignore[attr-defined]


def test_an_objective_that_is_not_the_sessions_is_refused() -> None:
    service = make_service()
    with pytest.raises(MCPError) as caught:
        call(service, call_arguments=arguments(objective_id=OTHER_OBJECTIVE_ID))

    assert data(caught.value)["field"] == "/arguments/objective_id"
    assert service.jobs.submissions == []  # type: ignore[attr-defined]


def test_an_unknown_capability_is_not_a_job_request() -> None:
    service = make_service()
    with pytest.raises(MCPError) as caught:
        call(service, tool_name="dns.not_a_capability")

    assert data(caught.value)["field"] == "/name"
    assert service.jobs.submissions == []  # type: ignore[attr-defined]


def test_a_denylisted_capability_cannot_be_called_even_though_it_exists() -> None:
    service = make_service(denylists={CAMPAIGN_ID: frozenset({ENUMERATE})})
    with pytest.raises(MCPError) as caught:
        call(service)

    assert data(caught.value)["code"] == "INPUT_INVALID"
    assert "not published" in str(data(caught.value)["message"])
    assert service.jobs.submissions == []  # type: ignore[attr-defined]


def test_wrapper_defaults_are_merged_before_submission() -> None:
    service = make_service()
    call(service)

    job = next(iter(service.jobs.jobs.values()))  # type: ignore[attr-defined]
    assert job["priority"] == 50
    assert job["depends_on"] == []


def _artifact_arguments(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "input": {"targets": ["sha256:" + "a" * 64]},
        "rationale": "Analyse one operator-supplied image digest",
        "objective_id": OBJECTIVE_ID,
    }
    value.update(overrides)
    return value


def test_a_shared_capability_can_name_its_provider() -> None:
    """G2-D: `vuln.scan_artifact` is served by two providers; the request chooses one.

    Without a name the registry default applies (the last registered, grype in this fixture set);
    naming a provider pins that manifest for the job. An unknown name is refused, never silently
    substituted with the default.
    """
    service = make_service()
    jobs = service.jobs
    assert isinstance(jobs, FakeJobService)

    default = structured(
        call(
            service,
            tool_name="vuln.scan_artifact",
            call_arguments=_artifact_arguments(),
            request_meta=meta(**{"aegis.io/idempotency_key": "artifact:default"}),
        )
    )
    assert default["provider"] == "grype"
    assert jobs.submissions[-1]["provider"] == "grype"

    trivy = structured(
        call(
            service,
            tool_name="vuln.scan_artifact",
            call_arguments=_artifact_arguments(provider="trivy"),
            request_meta=meta(**{"aegis.io/idempotency_key": "artifact:trivy"}),
        )
    )
    assert trivy["provider"] == "trivy"
    assert jobs.submissions[-1]["provider"] == "trivy"
    assert jobs.submissions[-1]["capability"] == "vuln.scan_artifact"

    with pytest.raises(MCPError) as refused:
        call(
            service,
            tool_name="vuln.scan_artifact",
            call_arguments=_artifact_arguments(provider="osv"),
            request_meta=meta(**{"aegis.io/idempotency_key": "artifact:osv"}),
        )
    data = refused.value.data if isinstance(refused.value.data, dict) else {}
    assert data.get("code") == "INPUT_INVALID"
    assert data.get("field") == "/arguments/provider"


def test_the_tool_description_lists_every_provider_of_a_capability() -> None:
    from tests.mcp_support import GRAPH_TOOLS  # noqa: F401 - the catalogue includes graph tools

    service = make_service()
    listed = service.list_tools(request_meta=meta(), mcp_session_id=TRANSPORT)
    tools = {tool.name: tool for tool in listed.tools}
    assert "providers: grype, trivy" in (tools["vuln.scan_artifact"].description or "")
    assert "providers: syft" in (tools["sbom.generate"].description or "")
