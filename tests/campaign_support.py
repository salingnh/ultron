"""Shared helpers for the G1.1b campaign tests (throwaway database, app, tokens).

The database tests create their own database on the server named by
`AEGIS_TEST_PG_DSN`, apply the published migration chain and drop it again; they
never touch a shared schema or an existing campaign. Every campaign a test creates
is in that throwaway database, so the "no DELETE" rule of the contract needs no
cleanup between tests.
"""

from __future__ import annotations

import copy
import json
import os
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any, cast

import psycopg
import pytest
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg.rows import dict_row
from referencing import Registry, Resource

from aegis import validation
from aegis.common.repo import repository_root
from aegis.m26_api.app import create_app
from aegis.m26_api.campaigns import register
from aegis.m26_api.operator import OperatorTokens, TokenAuthenticator, token_digest
from aegis.m26_api.registry import RouterRegistry
from tests.pg import drop_throwaway_database

DSN_ENV = "AEGIS_TEST_PG_DSN"
API = "/api/v2"
CONTRACTS_BASE_URI = "https://aegis.io/contracts/"

#: Operators of the tests: opaque principal id -> token (the token store only has digests).
OPERATORS: dict[str, str] = {
    "op-soc-1": "token-of-soc-1-0123456789",
    "op-soc-2": "token-of-soc-2-0123456789",
}


def fixture(name: str) -> Any:
    """Load a JSON fixture from contracts/fixtures (the contract's own examples)."""
    path = repository_root() / "contracts" / "fixtures" / name
    return json.loads(path.read_text(encoding="utf-8"))


def campaign_body(**overrides: Any) -> dict[str, Any]:
    """A valid campaign-create body from the contract fixture, with optional overrides."""
    body: dict[str, Any] = copy.deepcopy(fixture("valid/campaign-create.json"))
    body.update(overrides)
    return body


def policy(**overrides: Any) -> dict[str, Any]:
    """A valid roe-policy.v2 object from the contract fixture."""
    body: dict[str, Any] = copy.deepcopy(fixture("valid/roe-policy.from-v1.json"))
    body.update(overrides)
    return body


def registry_documents() -> Registry:
    """A `referencing` registry of every contract schema, keyed by `$id`."""
    registry: Registry = Registry()
    for schema in validation.schemas().values():
        registry = registry.with_resource(str(schema["$id"]), Resource.from_contents(schema))
    return registry


def _absolute_refs(node: Any) -> Any:
    """Rewrite `../x/y.schema.json` refs to the contract's absolute `$id` URLs."""
    if isinstance(node, dict):
        rewritten = {key: _absolute_refs(value) for key, value in node.items()}
        reference = rewritten.get("$ref")
        if isinstance(reference, str) and reference.startswith("../"):
            rewritten["$ref"] = CONTRACTS_BASE_URI + reference.removeprefix("../")
        return rewritten
    if isinstance(node, list):
        return [_absolute_refs(item) for item in node]
    return node


def validator(document: Mapping[str, Any]) -> Draft202012Validator:
    """A JSON Schema validator for an inline contract schema (e.g. an OpenAPI response).

    Inline schemas of `openapi.v2.yaml` refer to sibling contract files with relative
    paths; they are rewritten to the contract `$id` URLs so the shared registry resolves
    them (the OpenAPI document is not fetched by URI).
    """
    return Draft202012Validator(
        _absolute_refs(dict(document)),
        registry=registry_documents(),
        format_checker=validation.format_checker(),
    )


def operator_tokens() -> OperatorTokens:
    return OperatorTokens.from_document(
        {
            "operators": [
                {"principal_id": principal, "token_sha256": token_digest(token)}
                for principal, token in OPERATORS.items()
            ]
        }
    )


def write_token_file(path: Any) -> str:
    """Write a token store in the documented file format; returns the path."""
    path.write_text(
        json.dumps(
            {
                "operators": [
                    {"principal_id": principal, "token_sha256": token_digest(token)}
                    for principal, token in OPERATORS.items()
                ]
            }
        ),
        encoding="utf-8",
    )
    return str(path)


def auth(principal: str = "op-soc-1") -> dict[str, str]:
    return {"authorization": f"Bearer {OPERATORS[principal]}"}


def build_app(dsn: str) -> tuple[TestClient, Any]:
    """The campaign app over a throwaway database and the test operator store."""
    registry = RouterRegistry()
    register(registry)
    app = create_app(
        registry,
        operator_authenticator=TokenAuthenticator(operator_tokens()),
        database_dsn=dsn,
    )
    return TestClient(app), app


@contextmanager
def database() -> Iterator[str]:
    """Create an empty database on the test server, apply the chain, drop it afterwards."""
    base_dsn = os.environ[DSN_ENV]
    name = f"aegis_g11b_{uuid.uuid4().hex[:12]}"
    parameters = conninfo_to_dict(base_dsn)
    parameters["dbname"] = "postgres"
    with psycopg.connect(make_conninfo("", **parameters), autocommit=True) as admin:
        admin.execute(f'CREATE DATABASE "{name}"')
    parameters["dbname"] = name
    dsn = make_conninfo("", **parameters)
    try:
        from aegis.migrations import apply_contract_migrations

        with psycopg.connect(dsn, autocommit=True) as connection:
            apply_contract_migrations(connection)
        yield dsn
    finally:
        with psycopg.connect(
            make_conninfo("", **{**parameters, "dbname": "postgres"}), autocommit=True
        ) as admin:
            drop_throwaway_database(admin, name)


def requires_postgres() -> pytest.MarkDecorator:
    return pytest.mark.skipif(
        not os.environ.get(DSN_ENV),
        reason=f"set {DSN_ENV} to a PostgreSQL 18 server to run the campaign database tests",
    )


@contextmanager
def query(dsn: str) -> Iterator[psycopg.Connection[Any]]:
    """A read connection with the contract search_path (autocommit, read-only assertions)."""
    with psycopg.connect(dsn, row_factory=dict_row, autocommit=True) as conn:
        conn.execute("SET search_path = aegis, public")
        conn.execute("SET TRANSACTION READ ONLY")
        yield conn


def fetch_one(dsn: str, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any]:
    with query(dsn) as conn:
        row = conn.execute(sql, params).fetchone()
    assert row is not None, f"query returned no row: {sql}"
    return cast(dict[str, Any], row)


def fetch_all(dsn: str, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with query(dsn) as conn:
        return cast(list[dict[str, Any]], conn.execute(sql, params).fetchall())


def count(dsn: str, table: str) -> int:
    row = fetch_one(dsn, f"SELECT count(*) AS n FROM aegis.{table}")
    return int(row["n"])


def create_campaign(client: TestClient, *, key: str, body: dict[str, Any]) -> Any:
    return client.post(f"{API}/campaigns", json=body, headers={**auth(), "Idempotency-Key": key})
