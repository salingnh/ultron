"""`graph.*`: the interface, the server caps, and the `truncated`/`limits_applied` obligation.

M23 owns the projection (G1.4b). Here the boundary is pinned:

* the six contract queries are published with the contract's own input/output schemas;
* the ceiling in `limits_applied` is the **server's**, taken from `graph-queries.v2` (two hops,
  200 records, 2 s, 8192 excerpt bytes), and a client asking for less gets what it asked for;
* `truncated` comes from the projection, and is always on the answer - a caller can tell a full
  answer from a cut one;
* a query can never read another campaign: `campaign_id` must be the bound session's;
* until G1.4b wires M23 the default service refuses with `DEPENDENCY_MISSING`, never an empty page.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp import types
from mcp.shared.exceptions import MCPError
from mcp.types import INVALID_PARAMS

from aegis.m05_registry.mcp.graph import CAPS, GraphLimits, UnavailableGraphQueries
from aegis.m05_registry.mcp.schemas import graph_output_schema
from aegis.m05_registry.mcp.service import McpToolService
from tests.mcp_support import (
    FakeGraphQueries,
    graph_arguments,
    make_service,
    meta,
)

TRANSPORT = "transport-1"

NODES = [
    {
        "asset_id": "01934f6a-0000-7000-8000-0000000000a1",
        "canonical_key": "dns:www.internal.example",
        "kind": "domain",
        "stale": False,
    }
]
EDGES = [
    {
        "type": "SUBDOMAIN_OF",
        "from": "dns:www.internal.example",
        "to": "dns:internal.example",
        "valid_from": "2026-11-24T00:00:00Z",
        "source_job_id": "01934f6a-0000-7000-8000-0000000000a2",
        "confidence": 0.9,
    }
]


def graph_call(
    service: McpToolService,
    tool: str,
    call_arguments: dict[str, Any],
    *,
    request_meta: dict[str, Any] | None = None,
    transport: str = TRANSPORT,
) -> types.CallToolResult:
    return service.call(
        tool_name=tool,
        arguments=call_arguments,
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


def test_neighbours_default_to_one_hop_and_fifty_records() -> None:
    graph = FakeGraphQueries(
        answers={"get_asset_neighbors": ({"nodes": NODES, "edges": EDGES}, False)}
    )
    service = make_service(graph=graph)
    value = structured(
        graph_call(
            service,
            "graph.get_asset_neighbors",
            graph_arguments(canonical_key="dns:internal.example"),
        )
    )

    assert value["limits_applied"] == {"max_hops": 1, "limit": 50, "timeout_ms": 2000}
    assert value["truncated"] is False
    assert graph.calls[0]["limits"] == value["limits_applied"]
    assert graph_output_schema("get_asset_neighbors").problems(value) == []


def test_a_smaller_client_limit_is_the_applied_one() -> None:
    graph = FakeGraphQueries(answers={"get_asset_neighbors": ({"nodes": [], "edges": []}, False)})
    service = make_service(graph=graph)
    value = structured(
        graph_call(
            service,
            "graph.get_asset_neighbors",
            graph_arguments(canonical_key="dns:internal.example", limit=10, max_hops=2),
        )
    )

    assert value["limits_applied"] == {"max_hops": 2, "limit": 10, "timeout_ms": 2000}


def test_a_truncated_projection_is_reported() -> None:
    graph = FakeGraphQueries(answers={"get_unverified_hypotheses": ({"hypotheses": []}, True)})
    service = make_service(graph=graph)
    value = structured(graph_call(service, "graph.get_unverified_hypotheses", graph_arguments()))

    assert value["truncated"] is True
    assert value["limits_applied"] == {"limit": 50, "timeout_ms": 2000}


def test_the_evidence_excerpt_caps_bytes_not_records() -> None:
    graph = FakeGraphQueries(
        answers={
            "get_evidence_excerpt": (
                {
                    "evidence_id": "01934f6a-0000-7000-8000-0000000000a3",
                    "sha256": "a" * 64,
                    "excerpt": "203.0.113.7 internal.example\n",
                    "total_bytes": 4000,
                },
                True,
            )
        }
    )
    service = make_service(graph=graph)
    value = structured(
        graph_call(
            service,
            "graph.get_evidence_excerpt",
            graph_arguments(evidence_id="01934f6a-0000-7000-8000-0000000000a3", max_bytes=2048),
        )
    )

    assert value["limits_applied"] == {"max_bytes": 2048, "timeout_ms": 2000}
    assert value["truncated"] is True
    assert graph_output_schema("get_evidence_excerpt").problems(value) == []


def test_a_query_never_reads_another_campaign() -> None:
    service = make_service()
    with pytest.raises(MCPError) as caught:
        graph_call(
            service,
            "graph.get_recent_observations",
            graph_arguments(campaign_id="01934f6a-0000-7000-8000-000000000002", since_revision=0),
        )

    assert caught.value.code == INVALID_PARAMS
    assert data(caught.value)["field"] == "/arguments/campaign_id"
    assert data(caught.value)["code"] == "INPUT_INVALID"


def test_a_breach_of_the_query_input_schema_is_minus_32602() -> None:
    service = make_service()
    with pytest.raises(MCPError) as caught:
        graph_call(
            service,
            "graph.get_asset_neighbors",
            graph_arguments(canonical_key="not-a-canonical-key"),
        )

    assert data(caught.value)["field"].startswith("/arguments/canonical_key")


def test_an_unknown_graph_query_is_minus_32602() -> None:
    service = make_service()
    with pytest.raises(MCPError) as caught:
        graph_call(service, "graph.delete_everything", graph_arguments())

    assert data(caught.value)["field"] == "/name"


def test_the_default_provider_refuses_instead_of_answering_empty() -> None:
    service = make_service(graph=UnavailableGraphQueries())
    result = graph_call(service, "graph.get_recent_observations", graph_arguments(since_revision=0))

    assert result.is_error is True
    assert result.structured_content is None
    body = result.content[0]
    assert isinstance(body, types.TextContent)
    assert '"code":"DEPENDENCY_MISSING"' in body.text.replace(" ", "")
    assert "G1.4b" in body.text


def test_the_limits_are_the_contract_caps() -> None:
    assert CAPS == {"max_hops": 2, "limit": 200, "timeout_ms": 2000, "max_bytes": 8192}
    limits = GraphLimits(applied={"limit": 10})
    assert limits.as_json() == {"limit": 10}


def test_m23_graph_queries_delegates_to_m23_and_pops_bookkeeping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from unittest.mock import MagicMock

    from aegis.m05_registry.mcp.graph import M23GraphQueries
    from aegis.m23_graph import queries as m23_queries

    fake_conn = MagicMock()
    ctx = MagicMock()
    ctx.__enter__.return_value = fake_conn
    ctx.__exit__.return_value = False

    recorded: dict[str, Any] = {}

    def fake_recent(conn: Any, **kwargs: Any) -> dict[str, Any]:
        recorded["conn"] = conn
        recorded["kwargs"] = kwargs
        return {
            "observations": [],
            "revision": 4,
            "truncated": True,
            "limits_applied": {"limit": 200, "timeout_ms": 2000},
        }

    monkeypatch.setattr(m23_queries, "get_recent_observations", fake_recent)
    service = make_service(graph=M23GraphQueries(lambda: ctx, driver=None))
    value = structured(
        graph_call(
            service,
            "graph.get_recent_observations",
            graph_arguments(since_revision=2, limit=15),
        )
    )

    assert recorded["conn"] is fake_conn
    assert recorded["kwargs"]["campaign_id"] == "01934f6a-0000-7000-8000-000000000001"
    assert recorded["kwargs"]["since_revision"] == 2
    assert recorded["kwargs"]["limit"] == 15
    assert value["revision"] == 4
    assert value["truncated"] is True
    assert value["limits_applied"] == {"limit": 15, "timeout_ms": 2000}


def test_m23_graph_queries_refuses_neighbors_when_neo4j_driver_absent() -> None:
    from aegis.m05_registry.mcp.graph import GraphUnavailable, M23GraphQueries

    queries_svc = M23GraphQueries(MagicMock(), driver=None)
    with pytest.raises(GraphUnavailable, match="AEGIS_NEO4J_PASSWORD"):
        queries_svc.run(
            "get_asset_neighbors",
            {"campaign_id": "01934f6a-0000-7000-8000-000000000001", "canonical_key": "dns:a.test"},
            campaign_id="01934f6a-0000-7000-8000-000000000001",
            limits=GraphLimits(applied={"max_hops": 1, "limit": 50, "timeout_ms": 2000}),
        )


def test_connect_from_env_requires_uri_and_password() -> None:
    from aegis.m23_graph import graph as m23_graph

    assert m23_graph.connect_from_env({}) is None
    with pytest.raises(RuntimeError, match=m23_graph.NEO4J_PASSWORD_ENV):
        m23_graph.connect_from_env({m23_graph.NEO4J_URI_ENV: "bolt://127.0.0.1:7687"})


def test_connect_from_env_builds_the_driver_from_complete_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aegis.m23_graph import graph as m23_graph

    opened: list[tuple[str, str, str]] = []

    def fake_connect(uri: str, user: str, password: str) -> object:
        opened.append((uri, user, password))
        return object()

    monkeypatch.setattr(m23_graph, "connect", fake_connect)
    driver = m23_graph.connect_from_env(
        {
            m23_graph.NEO4J_URI_ENV: "bolt://graph.internal:7687",
            m23_graph.NEO4J_USER_ENV: "aegis",
            m23_graph.NEO4J_PASSWORD_ENV: "secret",
        }
    )

    assert driver is not None
    assert opened == [("bolt://graph.internal:7687", "aegis", "secret")]


def test_a_missing_evidence_id_is_input_invalid() -> None:
    from aegis.m05_registry.mcp.graph import M23GraphQueries

    conn = MagicMock()
    conn.execute.return_value.fetchone.return_value = None
    opener = MagicMock()
    opener.__enter__.return_value = conn
    opener.__exit__.return_value = False
    service = make_service(graph=M23GraphQueries(lambda: opener, driver=None))

    result = graph_call(
        service,
        "graph.get_evidence_excerpt",
        graph_arguments(evidence_id="01934f6a-0000-7000-8000-0000000000b1"),
    )

    assert result.is_error is True
    body = result.content[0]
    assert isinstance(body, types.TextContent)
    assert json.loads(body.text)["code"] == "INPUT_INVALID"


def test_an_unreachable_neo4j_is_a_missing_dependency() -> None:
    from neo4j.exceptions import ServiceUnavailable

    from aegis.m05_registry.mcp.graph import M23GraphQueries

    driver = MagicMock()
    driver.session.side_effect = ServiceUnavailable("cannot reach bolt://graph.internal:7687")
    service = make_service(graph=M23GraphQueries(MagicMock(), driver=driver))

    result = graph_call(
        service,
        "graph.get_asset_neighbors",
        graph_arguments(canonical_key="dns:internal.example"),
    )

    assert result.is_error is True
    body = result.content[0]
    assert isinstance(body, types.TextContent)
    text = body.text.replace(" ", "")
    assert '"code":"DEPENDENCY_MISSING"' in text
    assert "cannot reach bolt://graph.internal:7687" in body.text
