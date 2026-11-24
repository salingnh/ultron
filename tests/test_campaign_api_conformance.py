"""OpenAPI conformance of the campaign API against `contracts/api/openapi.v2.yaml`.

The contract bundle is the spec; the app's own OpenAPI document must not claim a
status code the contract does not document, a parameter it does not publish or a
route the contract does not have. Live responses are validated against the contract
schemas (including the inline 202 body and the policy response schema that only
exist inside the OpenAPI document).
"""

from __future__ import annotations

import importlib
import os
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

from aegis import validation
from aegis.common.repo import repository_root
from aegis.m26_api.app import API_PREFIX, create_app
from aegis.m26_api.campaigns import CAMPAIGN_OPERATIONS, register
from aegis.m26_api.operator import OPERATOR_TOKENS_FILE
from aegis.m26_api.registry import RouterRegistry

from . import campaign_support as support

requires_postgres = support.requires_postgres()
ERROR = "common/error.v2.schema.json"
CAMPAIGN_READ = "campaign/campaign.v2.schema.json"

CONTRACT_PATHS = (
    "/campaigns",
    "/campaigns/{campaign_id}",
    "/campaigns/{campaign_id}/policy",
    "/campaigns/{campaign_id}/pause",
    "/campaigns/{campaign_id}/resume",
    "/campaigns/{campaign_id}/cancel",
)
METHODS = frozenset({"get", "post", "put", "patch", "delete"})


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
            if method not in METHODS:
                continue
            operations[operation["operationId"]] = (method, path, operation)
    return operations


def _app_spec() -> dict[str, Any]:
    registry = RouterRegistry()
    register(registry)
    return create_app(registry).openapi()


def _app_operations(spec: dict[str, Any]) -> dict[str, tuple[str, str, dict[str, Any]]]:
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


def test_app_openapi_is_valid_openapi_31() -> None:
    spec = _app_spec()
    source = repository_root() / "contracts/api/app.openapi.json"
    assert validation.openapi_errors(spec, source) == []
    assert spec["openapi"].startswith("3.1")


def test_app_implements_exactly_the_campaign_operations() -> None:
    contract = _contract_operations()
    app = _app_operations(_app_spec())
    assert set(contract) == set(CAMPAIGN_OPERATIONS)
    assert set(app) == set(CAMPAIGN_OPERATIONS)
    for operation_id, (method, path, _) in contract.items():
        assert app[operation_id][:2] == (method, path), operation_id


def test_documented_status_codes_match_the_contract() -> None:
    contract = _contract_operations()
    app = _app_operations(_app_spec())
    for operation_id, (_, _, contract_operation) in contract.items():
        contract_codes = {int(code) for code in contract_operation["responses"]}
        app_codes = {int(code) for code in app[operation_id][2]["responses"]}
        assert app_codes == contract_codes, (
            f"{operation_id}: app documents {sorted(app_codes)}, contract {sorted(contract_codes)}"
        )
        # The shape is locked: no campaign endpoint may still be deferred.
        assert contract_operation.get("x-aegis-status", "locked") == "locked", operation_id


def test_operations_require_the_operator_bearer_scheme() -> None:
    contract = _contract_operations()
    spec = _app_spec()
    app = _app_operations(spec)
    scheme = spec["components"]["securitySchemes"]["operatorToken"]
    assert scheme["type"] == "http" and scheme["scheme"] == "bearer"
    for operation_id, (_, _, contract_operation) in contract.items():
        assert contract_operation["security"] == [{"operatorToken": []}], operation_id
        assert app[operation_id][2]["security"] == [{"operatorToken": []}], operation_id


def _resolve(document: dict[str, Any], node: dict[str, Any]) -> dict[str, Any]:
    while "$ref" in node:
        parts = node["$ref"].removeprefix("#/").split("/")
        target = document
        for part in parts:
            target = target[part]
        node = target
    return node


def _parameters(document: dict[str, Any], operation: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        parameter["name"]: parameter
        for parameter in (_resolve(document, node) for node in operation.get("parameters", []))
    }


def test_parameters_match_the_contract() -> None:
    document = _contract()
    contract = _contract_operations()
    spec = _app_spec()
    app = _app_operations(spec)
    for operation_id in ("createCampaign", "updateCampaignPolicy"):
        contract_parameter = _parameters(document, contract[operation_id][2])["Idempotency-Key"]
        app_parameter = _parameters(spec, app[operation_id][2])["Idempotency-Key"]
        assert contract_parameter["in"] == app_parameter["in"] == "header"
        assert contract_parameter["required"] is app_parameter["required"] is True
        assert app_parameter["schema"]["minLength"] == 8
        assert app_parameter["schema"]["maxLength"] == 256

    contract_list = _parameters(document, contract["listCampaigns"][2])
    app_list = _parameters(spec, app["listCampaigns"][2])
    assert set(contract_list) == set(app_list) == {"cursor", "limit", "status"}
    assert app_list["limit"]["schema"]["minimum"] == 1
    assert app_list["limit"]["schema"]["maximum"] == 200
    assert app_list["limit"]["schema"]["default"] == 50


# --------------------------------------------------------------------------- live payloads


@pytest.fixture(scope="module")
def dsn() -> Iterator[str]:
    if not os.environ.get(support.DSN_ENV):
        pytest.skip(f"set {support.DSN_ENV} to validate live campaign responses")
    with support.database() as value:
        yield value


@pytest.fixture(scope="module")
def client(dsn: str) -> TestClient:
    return support.build_app(dsn)[0]


@requires_postgres
def test_live_responses_satisfy_the_published_schemas(client: TestClient) -> None:
    contract = _contract()
    created = support.create_campaign(
        client, key="conformance-create", body=support.campaign_body(name="conformance")
    )
    assert created.status_code == 202, created.text

    inline_202 = contract["paths"]["/campaigns"]["post"]["responses"]["202"]["content"][
        "application/json"
    ]["schema"]
    assert list(support.validator(inline_202).iter_errors(created.json())) == []

    read = client.get(
        f"{support.API}/campaigns/{created.json()['campaign_id']}", headers=support.auth()
    )
    assert read.status_code == 200
    validation.validate(CAMPAIGN_READ, read.json())

    paused = client.post(
        f"{support.API}/campaigns/{created.json()['campaign_id']}/pause",
        json={"reason": "conformance pause"},
        headers=support.auth(),
    )
    assert paused.status_code == 200
    validation.validate(CAMPAIGN_READ, paused.json())

    policy_response = client.post(
        f"{support.API}/campaigns/{created.json()['campaign_id']}/policy",
        json={"policy": support.policy(), "reason": "conformance adopt"},
        headers={**support.auth(), "Idempotency-Key": "conformance-policy"},
    )
    assert policy_response.status_code == 200
    policy_operation = contract["paths"]["/campaigns/{campaign_id}/policy"]["post"]
    inline_policy = policy_operation["responses"]["200"]["content"]["application/json"]["schema"]
    assert list(support.validator(inline_policy).iter_errors(policy_response.json())) == []

    conflict = client.post(
        f"{support.API}/campaigns",
        json=support.campaign_body(name="other body"),
        headers={**support.auth(), "Idempotency-Key": "conformance-create"},
    )
    assert conflict.status_code == 409
    validation.validate(ERROR, conflict.json())


# --------------------------------------------------------------------------- entrypoint


def _import_main() -> ModuleType:
    sys.modules.pop("aegis.m26_api.main", None)
    return importlib.import_module("aegis.m26_api.main")


def test_production_entrypoint_requires_its_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AEGIS_PG_DSN", raising=False)
    monkeypatch.delenv(OPERATOR_TOKENS_FILE, raising=False)
    with pytest.raises(RuntimeError, match="AEGIS_PG_DSN"):
        _import_main()

    monkeypatch.setenv("AEGIS_PG_DSN", "postgresql://example/db")
    with pytest.raises(RuntimeError, match=OPERATOR_TOKENS_FILE):
        _import_main()


@requires_postgres
def test_production_entrypoint_builds_the_campaign_app(
    monkeypatch: pytest.MonkeyPatch, dsn: str, tmp_path: Path
) -> None:
    token_file = support.write_token_file(tmp_path / "operators.json")
    monkeypatch.setenv("AEGIS_PG_DSN", dsn)
    monkeypatch.setenv(OPERATOR_TOKENS_FILE, token_file)
    module = _import_main()

    client = TestClient(module.app)
    assert client.get(f"{API_PREFIX}/campaigns").status_code == 401
    listed = client.get(f"{API_PREFIX}/campaigns", headers=support.auth())
    assert listed.status_code == 200
    created = client.post(
        f"{API_PREFIX}/campaigns",
        json=support.campaign_body(name="entrypoint campaign"),
        headers={**support.auth(), "Idempotency-Key": f"entrypoint-{uuid.uuid4().hex}"},
    )
    assert created.status_code == 202, created.text
    sys.modules.pop("aegis.m26_api.main", None)
