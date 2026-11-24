"""`GET /capabilities`: the admitted M05 provider catalogue (G1.5a follow-up).

The rows under test are the ones M05 admission writes: the contract's own manifest fixtures,
registered through `PostgresManifestRegistry` (the same call start-up makes), so the catalogue is
tested against a real registry instead of a hand-built list.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import psycopg
import pytest
import yaml
from fastapi.testclient import TestClient
from psycopg.rows import dict_row

from aegis.common.repo import repository_root
from aegis.m01_campaign.campaigns import create_campaign
from aegis.m01_campaign.status import apply_workflow_action
from aegis.m05_registry.ids import uuid7
from aegis.m05_registry.registry import PostgresManifestRegistry
from aegis.m26_api import capabilities as capabilities_module
from aegis.m26_api.app import API_PREFIX, create_app
from aegis.m26_api.operator import TokenAuthenticator
from aegis.m26_api.registry import RouterRegistry
from tests import campaign_support as support
from tests.db_support import OPERATOR, connect, migrated_database, requires_postgres

pytestmark = requires_postgres

REPO = repository_root()
CAPABILITIES_PATH = "/capabilities"
SUBFINDER = (REPO / "contracts/fixtures/valid/manifest.subfinder.yaml").read_bytes()
DNSX = (REPO / "contracts/fixtures/valid/manifest.dnsx.yaml").read_bytes()


@pytest.fixture()
def dsn() -> Iterator[str]:
    with migrated_database() as value:
        yield value


def _registry() -> RouterRegistry:
    registry = RouterRegistry()
    capabilities_module.register(registry)
    return registry


def _client(dsn: str) -> TestClient:
    app = create_app(
        _registry(),
        operator_authenticator=TokenAuthenticator(support.operator_tokens()),
        database_dsn=dsn,
    )
    return TestClient(app)


def _register(dsn: str, *manifests: bytes) -> None:
    registry = PostgresManifestRegistry(lambda: connect(dsn))
    for raw in manifests:
        registry.register(raw, registered_by={"kind": "module", "id": "M05"})


def _get(client: TestClient, *, headers: dict[str, str] | None = None, **params: Any) -> Any:
    return client.get(
        f"{API_PREFIX}{CAPABILITIES_PATH}",
        params=params,
        headers=support.auth() if headers is None else headers,
    )


def _campaign_with_policy(dsn: str, policy: dict[str, Any]) -> str:
    """An M01 campaign whose current RoE is `policy` (created and started for real)."""
    with psycopg.connect(dsn, row_factory=dict_row) as conn, conn.transaction():
        created = create_campaign(
            conn,
            body=support.campaign_body(name="catalogue campaign", policy=policy),
            actor=OPERATOR,
            trace_id=uuid7().replace("-", "")[:32],
        ).as_response()
        apply_workflow_action(
            conn,
            campaign_id=created["campaign_id"],
            action="start",
            reason="capability catalogue test",
            actor={"kind": "module", "id": "M02"},
            trace_id=uuid7().replace("-", "")[:32],
        )
    return str(created["campaign_id"])


def _contract_schema() -> dict[str, Any]:
    contract: dict[str, Any] = yaml.safe_load(
        (REPO / "contracts/api/openapi.v2.yaml").read_text(encoding="utf-8")
    )
    schema: dict[str, Any] = contract["paths"]["/capabilities"]["get"]["responses"]["200"][
        "content"
    ]["application/json"]["schema"]
    return schema


def test_the_catalogue_lists_each_admitted_capability_with_its_providers(dsn: str) -> None:
    _register(dsn, SUBFINDER, DNSX)
    response = _get(_client(dsn))
    assert response.status_code == 200, response.text
    body = response.json()

    problems = list(support.validator(_contract_schema()).iter_errors(body))
    assert problems == [], problems[:2]

    items = {item["capability"]: item for item in body["items"]}
    assert set(items) == {"dns.enumerate_subdomains", "dns.resolve"}
    subfinder = items["dns.enumerate_subdomains"]
    assert subfinder["input_schema_ref"] == "schema://dns/enumerate-subdomains/v2"
    assert subfinder["providers"] == [
        {"name": "subfinder", "version": "v2.17.0", "module": "M08", "health": "healthy"}
    ]
    assert items["dns.resolve"]["providers"] == [
        {"name": "dnsx", "version": "v1.2.2", "module": "M08", "health": "healthy"}
    ]
    assert [item["capability"] for item in body["items"]] == sorted(items)


def test_the_newest_admitted_manifest_is_the_provider_that_is_listed(dsn: str) -> None:
    bumped = SUBFINDER.replace(b"version: 1.0.0", b"version: 1.1.0", 1).replace(
        b"providerVersion: v2.17.0", b"providerVersion: v2.18.0", 1
    )
    assert bumped != SUBFINDER
    _register(dsn, SUBFINDER)
    _register(dsn, bumped)

    body = _get(_client(dsn)).json()
    (item,) = body["items"]
    # The registry keeps both manifests (append-only), the catalogue lists the one a new job
    # would resolve, not two providers with one name.
    assert item["providers"] == [
        {"name": "subfinder", "version": "v2.18.0", "module": "M08", "health": "healthy"}
    ]


def test_a_campaigns_denylist_filters_the_catalogue(dsn: str) -> None:
    _register(dsn, SUBFINDER, DNSX)
    client = _client(dsn)
    denied = _campaign_with_policy(
        dsn, support.policy(capability_denylist=["dns.enumerate_subdomains"])
    )
    allowed = _campaign_with_policy(dsn, support.policy())

    filtered = _get(client, campaign_id=denied).json()
    assert [item["capability"] for item in filtered["items"]] == ["dns.resolve"]

    unfiltered = _get(client, campaign_id=allowed).json()
    assert [item["capability"] for item in unfiltered["items"]] == [
        "dns.enumerate_subdomains",
        "dns.resolve",
    ]


def test_the_catalogue_requires_the_operator_token(dsn: str) -> None:
    _register(dsn, SUBFINDER)
    client = _client(dsn)
    for headers, expected in (
        ({}, 401),
        ({"authorization": "Bearer not-a-token"}, 401),
        (support.auth("op-soc-2"), 200),
    ):
        response = _get(client, headers=headers)
        assert response.status_code == expected, (headers, response.text)
        if expected == 401:
            assert response.json()["code"] == "INPUT_INVALID"
            assert response.headers["www-authenticate"] == "Bearer"


def test_an_unknown_or_malformed_campaign_is_404(dsn: str) -> None:
    _register(dsn, SUBFINDER)
    client = _client(dsn)
    for campaign_id in (uuid7(), "not-a-uuid"):
        response = _get(client, campaign_id=campaign_id)
        assert response.status_code == 404, campaign_id
        assert response.json()["code"] == "INPUT_INVALID"
        assert response.json()["next_action"] == "FIX_INPUT"


def test_an_empty_registry_is_an_empty_catalogue(dsn: str) -> None:
    response = _get(_client(dsn))
    assert response.status_code == 200
    assert response.json() == {"items": []}


def test_a_catalogue_that_violates_the_contract_fails_loudly(
    dsn: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _register(dsn, SUBFINDER)
    monkeypatch.setattr(
        capabilities_module, "catalogue", lambda *_args, **_kwargs: [{"capability": "??"}]
    )
    response = _get(_client(dsn))
    assert response.status_code == 500, response.text
    assert response.json()["code"] == "INTERNAL_ERROR"
    assert "listCapabilities" in response.json()["message"]


def test_the_served_operation_matches_the_contract() -> None:
    contract = yaml.safe_load((REPO / "contracts/api/openapi.v2.yaml").read_text(encoding="utf-8"))
    contract_operation = contract["paths"]["/capabilities"]["get"]
    spec = create_app(_registry()).openapi()
    app_operation = spec["paths"][f"{API_PREFIX}{CAPABILITIES_PATH}"]["get"]

    assert contract_operation["operationId"] == app_operation["operationId"] == "listCapabilities"
    assert app_operation["security"] == contract_operation["security"] == [{"operatorToken": []}]
    assert (
        set(app_operation["responses"])
        == set(contract_operation["responses"])
        == {
            "200",
            "401",
            "404",
        }
    )
    assert [
        (parameter["name"], parameter["in"], parameter.get("required", False))
        for parameter in app_operation["parameters"]
    ] == [
        (parameter["name"], parameter["in"], parameter.get("required", False))
        for parameter in contract_operation["parameters"]
    ]
