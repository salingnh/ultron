"""`GET /intel/status`: the scheduled refresh's outcome and feed freshness over HTTP (item 80)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import psycopg
import pytest
import yaml
from fastapi.testclient import TestClient

from aegis.common.repo import repository_root
from aegis.m18_intel import runs as runs_module
from aegis.m26_api import intel as api_intel
from aegis.m26_api.app import API_PREFIX, create_app
from aegis.m26_api.operator import TokenAuthenticator
from aegis.m26_api.registry import RouterRegistry
from tests import campaign_support as support
from tests.db_support import migrated_database, requires_postgres

pytestmark = requires_postgres

REPO = repository_root()
STATUS_PATH = "/intel/status"


@pytest.fixture()
def dsn() -> Iterator[str]:
    with migrated_database() as value:
        yield value


def _registry() -> RouterRegistry:
    registry = RouterRegistry()
    api_intel.register(registry)
    return registry


def _client(dsn: str) -> TestClient:
    app = create_app(
        _registry(),
        operator_authenticator=TokenAuthenticator(support.operator_tokens()),
        database_dsn=dsn,
    )
    return TestClient(app)


def _get(client: TestClient, *, headers: dict[str, str] | None = None) -> Any:
    return client.get(
        f"{API_PREFIX}{STATUS_PATH}",
        headers=support.auth() if headers is None else headers,
    )


def _seed(dsn: str) -> None:
    with psycopg.connect(dsn) as conn:
        conn.execute("SET search_path = aegis, public")
        conn.execute(
            "INSERT INTO intel_snapshot (snapshot_id, feed, version, snapshot_at, record_count,"
            " source_uri) VALUES (gen_random_uuid(), 'nvd', '2026-12-01', now(), 4, 'fixture')"
        )
        runs_module.record_start(
            conn, "schedule", started_at=datetime(2026, 12, 1, 3, 0, tzinfo=UTC)
        )
    with psycopg.connect(dsn) as conn:
        conn.execute("SET search_path = aegis, public")
        row = conn.execute("SELECT run_id FROM intel_sync_run LIMIT 1").fetchone()
        assert row is not None
        run_id = str(row[0])
        runs_module.record_finish(
            conn,
            run_id,
            ok=False,
            legs={"kev": {"error": "HTTP 503"}},
            error="kev: HTTP 503",
            finished_at=datetime(2026, 12, 1, 3, 10, tzinfo=UTC),
        )


def test_the_status_lists_every_feed_and_the_last_failed_run(dsn: str) -> None:
    _seed(dsn)
    response = _get(_client(dsn))
    assert response.status_code == 200, response.text
    body = response.json()
    assert [item["feed"] for item in body["feeds"]] == ["nvd", "epss", "kev"]
    assert body["stale_feeds"] == ["epss", "kev"]
    assert body["feeds"][0]["snapshot"]["version"] == "2026-12-01"
    assert body["last_run"]["status"] == "FAILED"
    assert body["last_run"]["error"] == "kev: HTTP 503"


def test_the_status_requires_the_operator_token(dsn: str) -> None:
    client = _client(dsn)
    for headers, expected in (
        ({}, 401),
        ({"authorization": "Bearer not-a-token"}, 401),
        (support.auth("op-soc-2"), 200),
    ):
        response = _get(client, headers=headers)
        assert response.status_code == expected, (headers, response.text)


def test_a_status_that_violates_the_contract_fails_loudly(
    dsn: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        runs_module,
        "feed_status",
        lambda *_args, **_kwargs: {"generated_at": "not-a-date"},
    )
    response = _get(_client(dsn))
    assert response.status_code == 500, response.text
    assert response.json()["code"] == "INTERNAL_ERROR"
    assert "getIntelStatus" in response.json()["message"]


def test_the_served_operation_matches_the_contract() -> None:
    contract = yaml.safe_load((REPO / "contracts/api/openapi.v2.yaml").read_text(encoding="utf-8"))
    contract_operation = contract["paths"][STATUS_PATH]["get"]
    spec = create_app(_registry()).openapi()
    app_operation = spec["paths"][f"{API_PREFIX}{STATUS_PATH}"]["get"]

    assert contract_operation["operationId"] == app_operation["operationId"] == "getIntelStatus"
    assert app_operation["security"] == contract_operation["security"] == [{"operatorToken": []}]
    assert set(app_operation["responses"]) == set(contract_operation["responses"]) == {"200", "401"}
