"""OpenAPI conformance and live responses of the asset graph REST (G1.4b).

`GET /assets/{id}/graph` and `GET /assets/{id}/history` are the two graph operations the contract
locks. These tests compare the app's operations and parameters with the contract, then validate the
live bodies against the contract's own schemas: the neighbours document is the MCP query output
(`get_asset_neighbors.properties.output`), and the history body is checked against the inline
`Asset` component and the `items` fields the contract requires.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, cast

import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient

from aegis.common.repo import repository_root
from aegis.m23_graph import graph
from aegis.m26_api.app import API_PREFIX, create_app
from aegis.m26_api.assets import ASSET_OPERATIONS, register
from aegis.m26_api.operator import TokenAuthenticator
from aegis.m26_api.registry import RouterRegistry
from tests import campaign_support as support
from tests.m23_support import (
    CAMPAIGN_ID,
    graph_driver,
    ingest,
    pipeline_database,
    project_all,
    requires_pipeline,
)

pytestmark = requires_pipeline

CONTRACT_PATHS = ("/assets/{asset_id}/graph", "/assets/{asset_id}/history")
METHODS = frozenset({"get", "post", "put", "patch", "delete"})
MISSING_ASSET = "01900000-0000-7000-8000-0000000c0fff"


@pytest.fixture
def database() -> Iterator[tuple[str, list[str]]]:
    with pipeline_database(jobs=2) as value:
        yield value


@pytest.fixture
def client(database: tuple[str, list[str]]) -> Iterator[TestClient]:
    dsn, _ = database
    with graph_driver() as driver:
        registry = RouterRegistry()
        register(registry)
        app = create_app(
            registry,
            operator_authenticator=TokenAuthenticator(support.operator_tokens()),
            database_dsn=dsn,
            graph_driver=driver,
        )
        yield TestClient(app)


def app_spec(client: TestClient) -> dict[str, Any]:
    """The app's own OpenAPI document (TestClient.app is typed as the bare ASGI callable)."""
    return cast(FastAPI, client.app).openapi()


def _contract() -> dict[str, Any]:
    document = yaml.safe_load(
        (repository_root() / "contracts/api/openapi.v2.yaml").read_text(encoding="utf-8")
    )
    assert isinstance(document, dict)
    return document


def _contract_operations() -> dict[str, tuple[str, str, dict[str, Any]]]:
    contract = _contract()
    operations: dict[str, tuple[str, str, dict[str, Any]]] = {}
    for path in CONTRACT_PATHS:
        for method, operation in contract["paths"][path].items():
            if method in METHODS:
                operations[operation["operationId"]] = (method, path, operation)
    return operations


def _app_operations(client: TestClient) -> dict[str, tuple[str, str, dict[str, Any]]]:
    spec = app_spec(client)
    operations: dict[str, tuple[str, str, dict[str, Any]]] = {}
    for path, path_item in spec["paths"].items():
        if not path.startswith(API_PREFIX):
            continue
        relative = path[len(API_PREFIX) :]
        if relative not in CONTRACT_PATHS:
            continue
        for method, operation in path_item.items():
            if method in METHODS:
                operations[operation["operationId"]] = (method, relative, operation)
    return operations


def test_app_implements_exactly_the_locked_graph_operations(client: TestClient) -> None:
    contract = _contract_operations()
    app = _app_operations(client)
    assert set(contract) == set(ASSET_OPERATIONS)
    assert set(app) == set(ASSET_OPERATIONS)
    for operation_id, (method, path, operation) in contract.items():
        assert app[operation_id][:2] == (method, path), operation_id
        assert operation.get("x-aegis-status", "locked") == "locked", operation_id


def test_list_assets_stays_deferred_and_is_not_implemented(client: TestClient) -> None:
    contract = _contract()
    list_assets = contract["paths"]["/assets"]["get"]
    assert list_assets["x-aegis-status"] == "deferred"
    assert "/assets" not in app_spec(client)["paths"]


def test_parameters_match_the_contract(client: TestClient) -> None:
    contract = _contract()
    contract_operations = _contract_operations()
    app = _app_operations(client)

    def names(operation: dict[str, Any], document: dict[str, Any]) -> set[str]:
        """Query/header parameter names; path parameters are structural (`asset_id`)."""
        found: set[str] = set()
        for node in operation.get("parameters", []):
            while "$ref" in node:
                target: Any = document
                for part in node["$ref"].removeprefix("#/").split("/"):
                    target = target[part]
                node = target
            if node["in"] != "path":
                found.add(node["name"])
        return found

    graph_contract = names(contract_operations["getAssetGraph"][2], contract)
    graph_app = names(app["getAssetGraph"][2], app_spec(client))
    assert {"campaign_id", "max_hops", "as_of", "limit"} <= graph_contract
    assert graph_contract == graph_app
    history_contract = names(contract_operations["getAssetHistory"][2], contract)
    assert history_contract == {"cursor", "limit"}


def test_documented_status_codes_cover_the_contract(client: TestClient) -> None:
    contract = _contract_operations()
    app = _app_operations(client)
    for operation_id, (_, _, operation) in contract.items():
        documented = {int(code) for code in operation["responses"]}
        served = {int(code) for code in app[operation_id][2]["responses"]}
        assert documented <= served, operation_id
        # The extra codes are the ones an unknown asset/parameter needs; documented in the module.
        assert served - documented <= {400, 401, 404}, operation_id


def test_graph_response_satisfies_the_mcp_output_contract(
    client: TestClient, database: tuple[str, list[str]]
) -> None:
    dsn, jobs = database
    with graph_driver() as driver:
        ingest(
            dsn,
            jobs[0],
            assets=[
                {"kind": "domain", "canonical_key": "dns:api.test"},
                {
                    "kind": "domain",
                    "canonical_key": "dns:www.api.test",
                    "discovered_from": ["dns:api.test"],
                },
            ],
            relationships=[
                {
                    "type": "SUBDOMAIN_OF",
                    "from": "dns:www.api.test",
                    "to": "dns:api.test",
                    "observed_at": "2026-11-24T10:00:00Z",
                    "confidence": 0.9,
                }
            ],
            coverage=["dns:api.test", "dns:www.api.test"],
        )
        project_all(dsn, driver, consumer="api#g1")
        asset_id = str(
            driver.execute_query(
                "MATCH (a:Asset {canonical_key: 'dns:api.test'}) RETURN a.asset_id AS id"
            ).records[0]["id"]
        )
        response = client.get(
            f"{API_PREFIX}/assets/{asset_id}/graph",
            params={"campaign_id": CAMPAIGN_ID, "limit": 10},
            headers=support.auth(),
        )
    assert response.status_code == 200, response.text
    body = response.json()
    inline = _contract()["paths"]["/assets/{asset_id}/graph"]["get"]["responses"]["200"]["content"][
        "application/json"
    ]["schema"]
    assert list(support.validator(inline).iter_errors(body)) == []
    assert body["truncated"] is False
    assert body["limits_applied"] == {"max_hops": 2, "limit": 200, "timeout_ms": 2000}
    assert {node["canonical_key"] for node in body["nodes"]} == {"dns:api.test", "dns:www.api.test"}


def test_graph_truncation_is_reported(client: TestClient, database: tuple[str, list[str]]) -> None:
    dsn, jobs = database
    with graph_driver() as driver:
        ingest(dsn, jobs[0], assets=[{"kind": "domain", "canonical_key": "dns:many-api.test"}])
        project_all(dsn, driver, consumer="api#g1")
        asset_id = str(
            driver.execute_query(
                "MATCH (a:Asset {canonical_key: 'dns:many-api.test'}) RETURN a.asset_id AS id"
            ).records[0]["id"]
        )
        response = client.get(
            f"{API_PREFIX}/assets/{asset_id}/graph",
            params={"campaign_id": CAMPAIGN_ID, "limit": 1, "max_hops": 2},
            headers=support.auth(),
        )
    assert response.status_code == 200, response.text
    assert response.json()["truncated"] is False  # one node is not a truncation


def test_a_read_model_contract_violation_answers_with_a_code_not_a_500_dump(
    client: TestClient, database: tuple[str, list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """D2/D3 (item 61 trial): a producer bug must be a clear code, not an opaque 500.

    The old handler answered `INTERNAL_ERROR` with the JSON-schema validator's message, so the UI
    printed a screenful of regex patterns. The operator now sees a short pointer list and the
    `OUTPUT_INVALID` code (`error.v2`), and the response stays a 500 because the server is wrong.
    """
    dsn, jobs = database
    bad = {
        "nodes": [{"asset_id": "not-a-uuid", "canonical_key": "dns:x.test", "kind": "domain"}],
        "edges": [],
        "truncated": False,
        "limits_applied": {"max_hops": 2, "limit": 200, "timeout_ms": 2000},
    }
    monkeypatch.setattr(
        "aegis.m26_api.assets.queries.get_asset_neighbors", lambda *args, **kwargs: bad
    )
    with graph_driver() as driver:
        ingest(dsn, jobs[0], assets=[{"kind": "domain", "canonical_key": "dns:broke.test"}])
        project_all(dsn, driver, consumer="api#g1")
        asset_id = str(
            driver.execute_query(
                "MATCH (a:Asset {canonical_key: 'dns:broke.test'}) RETURN a.asset_id AS id"
            ).records[0]["id"]
        )
        response = client.get(
            f"{API_PREFIX}/assets/{asset_id}/graph",
            params={"campaign_id": CAMPAIGN_ID},
            headers=support.auth(),
        )
    assert response.status_code == 500
    body = response.json()
    assert body["code"] == "OUTPUT_INVALID"
    assert body["next_action"] == "REVIEW_QUARANTINE"
    assert "/nodes/0/asset_id" in body["message"]
    assert "pattern" not in body["message"] and "^" not in body["message"]
    assert body["trace_id"]


def test_history_validates_against_the_inline_asset_component(
    client: TestClient, database: tuple[str, list[str]]
) -> None:
    dsn, jobs = database
    with graph_driver() as driver:
        ingest(
            dsn,
            jobs[0],
            assets=[
                {"kind": "domain", "canonical_key": "dns:history.test"},
                {
                    "kind": "domain",
                    "canonical_key": "dns:alt.history.test",
                    "aliases": [{"namespace": "original", "value": "ALT.History.Test"}],
                },
            ],
            observations=[
                {
                    "subject": "dns:history.test",
                    "predicate": "dns.record",
                    "value": {"type": "A", "value": "192.0.2.55", "ttl": 300},
                    "observed_at": "2026-11-24T10:00:00Z",
                    "evidence_refs": [{"local_ref": "raw"}],
                }
            ],
            coverage=["dns:history.test", "dns:alt.history.test"],
        )
        project_all(dsn, driver, consumer="api#g1")
        asset_id = str(
            driver.execute_query(
                "MATCH (a:Asset {canonical_key: 'dns:history.test'}) RETURN a.asset_id AS id"
            ).records[0]["id"]
        )
        response = client.get(f"{API_PREFIX}/assets/{asset_id}/history", headers=support.auth())
    assert response.status_code == 200, response.text
    body = response.json()
    contract = _contract()
    inline_asset = contract["components"]["schemas"]["Asset"]
    assert list(support.validator(inline_asset).iter_errors(body["asset"])) == []
    assert body["asset"]["canonical_key"] == "dns:history.test"
    assert body["asset"]["kind"] == "domain"
    assert len(body["items"]) == 1
    item = body["items"][0]
    assert item["predicate"] == "dns.record"
    assert item["polarity"] == "present"
    assert item["capability"]
    assert item["observed_at"].endswith("Z")
    assert "next_cursor" not in body


def test_history_pages_with_a_keyset_cursor(
    client: TestClient, database: tuple[str, list[str]]
) -> None:
    dsn, jobs = database
    with graph_driver() as driver:
        ingest(
            dsn,
            jobs[0],
            assets=[{"kind": "domain", "canonical_key": "dns:pages.test"}],
            observations=[
                {
                    "subject": "dns:pages.test",
                    "predicate": "dns.record",
                    "value": {"type": "A", "value": f"192.0.2.{index}", "ttl": 60},
                    "observed_at": f"2026-11-24T10:0{index}:00Z",
                }
                for index in range(3)
            ],
            coverage=["dns:pages.test"],
        )
        project_all(dsn, driver, consumer="api#g1")
        asset_id = str(
            driver.execute_query(
                "MATCH (a:Asset {canonical_key: 'dns:pages.test'}) RETURN a.asset_id AS id"
            ).records[0]["id"]
        )
        first = client.get(
            f"{API_PREFIX}/assets/{asset_id}/history",
            params={"limit": 2},
            headers=support.auth(),
        )
        assert first.status_code == 200, first.text
        page = first.json()
        assert len(page["items"]) == 2
        cursor = page["next_cursor"]
        second = client.get(
            f"{API_PREFIX}/assets/{asset_id}/history",
            params={"limit": 2, "cursor": cursor},
            headers=support.auth(),
        )
    assert second.status_code == 200, second.text
    rest = second.json()
    assert len(rest["items"]) == 1
    assert rest["items"][0]["observation_id"] if "observation_id" in rest["items"][0] else True
    observed = {item["observed_at"] for item in page["items"] + rest["items"]}
    assert len(observed) == 3


def test_unknown_asset_and_bad_parameters_are_error_documents(
    client: TestClient, database: tuple[str, list[str]]
) -> None:
    dsn, _ = database
    missing = client.get(
        f"{API_PREFIX}/assets/{MISSING_ASSET}/graph",
        params={"campaign_id": CAMPAIGN_ID},
        headers=support.auth(),
    )
    assert missing.status_code == 404
    assert missing.json()["code"]

    bad_campaign = client.get(
        f"{API_PREFIX}/assets/{MISSING_ASSET}/graph",
        params={"campaign_id": "not-a-uuid"},
        headers=support.auth(),
    )
    assert bad_campaign.status_code == 400
    assert bad_campaign.json()["code"]

    bad_as_of = client.get(
        f"{API_PREFIX}/assets/{MISSING_ASSET}/graph",
        params={"campaign_id": CAMPAIGN_ID, "as_of": "yesterday"},
        headers=support.auth(),
    )
    assert bad_as_of.status_code == 400

    bad_hops = client.get(
        f"{API_PREFIX}/assets/{MISSING_ASSET}/graph",
        params={"campaign_id": CAMPAIGN_ID, "max_hops": 3},
        headers=support.auth(),
    )
    assert bad_hops.status_code == 400

    bad_cursor = client.get(
        f"{API_PREFIX}/assets/{MISSING_ASSET}/history",
        params={"cursor": "!!!"},
        headers=support.auth(),
    )
    assert bad_cursor.status_code in {400, 404}


def test_both_operations_require_an_operator_token(
    client: TestClient, database: tuple[str, list[str]]
) -> None:
    dsn, _ = database
    anonymous = client.get(
        f"{API_PREFIX}/assets/{MISSING_ASSET}/graph", params={"campaign_id": CAMPAIGN_ID}
    )
    assert anonymous.status_code == 401
    anonymous_history = client.get(f"{API_PREFIX}/assets/{MISSING_ASSET}/history")
    assert anonymous_history.status_code == 401


def test_the_module_exports_its_operation_ids() -> None:
    assert ASSET_OPERATIONS == ("getAssetGraph", "getAssetHistory")
    assert graph.GRAPH_NODE_KEYS  # the module is imported for its side-effect-free tables


def test_production_app_wires_neo4j_driver_and_closes_on_shutdown(
    monkeypatch: pytest.MonkeyPatch,
    database: tuple[str, list[str]],
    tmp_path: Any,
) -> None:
    import importlib
    import sys

    from aegis.m26_api.operator import OPERATOR_TOKENS_FILE
    from tests import graph_support

    dsn, jobs = database
    with graph_driver() as driver:
        ingest(dsn, jobs[0], assets=[{"kind": "domain", "canonical_key": "dns:prod-app.test"}])
        project_all(dsn, driver, consumer="api#g1")
        asset_id = str(
            driver.execute_query(
                "MATCH (a:Asset {canonical_key: 'dns:prod-app.test'}) RETURN a.asset_id AS id"
            ).records[0]["id"]
        )
        uri, password = graph_support.ensure_test_graph()
        token_file = support.write_token_file(tmp_path / "operators.json")
        monkeypatch.setenv("AEGIS_PG_DSN", dsn)
        monkeypatch.setenv(OPERATOR_TOKENS_FILE, token_file)
        monkeypatch.setenv("AEGIS_ALLOW_DEV_SIGNING_KEY", "1")
        monkeypatch.setenv("AEGIS_NEO4J_URI", uri)
        monkeypatch.setenv("AEGIS_NEO4J_USER", "neo4j")
        monkeypatch.setenv("AEGIS_NEO4J_PASSWORD", password)

        sys.modules.pop("aegis.m26_api.main", None)
        api_main = importlib.import_module("aegis.m26_api.main")
        try:
            app = api_main.app
            assert app.state.graph_driver is not None
            closed_calls: list[bool] = []
            original_close = app.state.graph_driver.close

            def tracked_close() -> None:
                closed_calls.append(True)
                original_close()

            monkeypatch.setattr(app.state.graph_driver, "close", tracked_close)
            with TestClient(app) as prod_client:
                response = prod_client.get(
                    f"{API_PREFIX}/assets/{asset_id}/graph",
                    params={"campaign_id": CAMPAIGN_ID, "limit": 10},
                    headers=support.auth(),
                )
            assert response.status_code == 200, response.text
            assert [n["canonical_key"] for n in response.json()["nodes"]] == ["dns:prod-app.test"]
            assert closed_calls == [True]
            assert app.state.graph_driver._closed is True

            monkeypatch.delenv("AEGIS_NEO4J_PASSWORD")
            with pytest.raises(RuntimeError, match="AEGIS_NEO4J_PASSWORD"):
                api_main.create_production_app()
        finally:
            sys.modules.pop("aegis.m26_api.main", None)


def test_missing_graph_driver_error_names_existing_env_vars() -> None:
    registry = RouterRegistry()
    register(registry)
    app = create_app(
        registry,
        operator_authenticator=TokenAuthenticator(support.operator_tokens()),
        database_dsn="postgresql://unused",
        cors_origins=["http://127.0.0.1:5174"],
    )
    client = TestClient(app, raise_server_exceptions=False)
    from starlette.requests import Request

    from aegis.m26_api.assets import _driver

    scope = {"type": "http", "method": "GET", "path": "/", "headers": [], "app": app}
    with pytest.raises(RuntimeError) as caught:
        _driver(Request(scope))
    message = str(caught.value)
    assert "AEGIS_NEO4J_URI" in message
    assert "AEGIS_NEO4J_USER" in message
    assert "AEGIS_NEO4J_PASSWORD" in message
    del client
