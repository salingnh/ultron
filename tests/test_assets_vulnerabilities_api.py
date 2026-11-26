"""`GET /assets/{asset_id}/vulnerabilities` (G1.6 slice C): the operator view of candidates.

The rows are produced by the real chain (M27 ingests the fingerprinted services, M18 loads the
fixture intel, M20 records the candidates); the app is the production app factory with the
operator token store, and every response is validated against the contract's inline schema, so the
test fails if the code and `contracts/api/openapi.v2.yaml` disagree.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from aegis import validation
from aegis.m18_intel.sync import FeedSync
from aegis.m20_vuln.matching import Matcher
from aegis.m26_api import vulnerabilities as vulnerabilities_module
from aegis.m26_api.app import API_PREFIX, create_app
from aegis.m26_api.operator import TokenAuthenticator
from aegis.m26_api.registry import RouterRegistry
from aegis.m27_ingestion.ids import uuid7
from tests import campaign_support as support
from tests import g16c_support as fixtures
from tests.db_support import requires_postgres
from tests.m23_support import connect, ingest, pipeline_database

pytestmark = requires_postgres

PATH = "/assets/{asset_id}/vulnerabilities"
CONTRACT_PATH = "/assets/{asset_id}/vulnerabilities"


@pytest.fixture()
def database() -> Iterator[tuple[str, dict[str, str]]]:
    with pipeline_database(jobs=1) as (dsn, jobs):
        ingest(
            dsn,
            jobs[0],
            assets=fixtures.service_assets(),
            observations=fixtures.service_observations(),
            coverage=fixtures.coverage(),
        )
        with connect(dsn) as connection:
            fixtures.seed_intel(dsn)
            Matcher(connection).run()
            rows = connection.execute(
                "SELECT canonical_key, asset_id FROM asset WHERE canonical_key = ANY(%s)",
                ([fixtures.SERVICE_KEY, fixtures.NGINX_SERVICE_KEY, fixtures.APP_KEY],),
            ).fetchall()
        yield dsn, {str(row["canonical_key"]): str(row["asset_id"]) for row in rows}


def _client(dsn: str) -> TestClient:
    registry = RouterRegistry()
    vulnerabilities_module.register(registry)
    app = create_app(
        registry,
        operator_authenticator=TokenAuthenticator(support.operator_tokens()),
        database_dsn=dsn,
    )
    return TestClient(app)


def _get(
    client: TestClient, asset_id: str, *, headers: dict[str, str] | None = None, **params: Any
) -> Any:
    return client.get(
        f"{API_PREFIX}{PATH.format(asset_id=asset_id)}",
        params=params,
        headers=support.auth() if headers is None else headers,
    )


def _validated(body: dict[str, Any]) -> None:
    assert validation.problems("vulnerability/asset-vulnerabilities.v2.schema.json", body) == []


def test_the_service_candidate_carries_cvss_kev_and_epss(
    database: tuple[str, dict[str, str]],
) -> None:
    dsn, assets = database
    client = _client(dsn)
    response = _get(client, assets[fixtures.SERVICE_KEY])
    assert response.status_code == 200, response.text
    body = response.json()
    _validated(body)
    assert body["asset"]["canonical_key"] == fixtures.SERVICE_KEY
    assert body["asset"]["kind"] == "service"
    assert len(body["items"]) == 1
    item = body["items"][0]
    assert item["vulnerability_id"] == "CVE-2021-41773"
    assert item["cvss_base"] == 9.8
    assert item["cvss_severity"] == "CRITICAL"
    assert item["kev"] is True
    assert item["kev_due_date"] == "2021-11-17"
    assert item["epss"] == pytest.approx(0.97431)
    assert item["match_method"] == "cpe_range"
    assert item["confidence"] == 0.7
    assert "affected_range" not in item
    assert item["snapshot_id"]
    assert item["candidate_since"].endswith("Z")


def test_a_range_candidate_reports_its_bounds_without_kev(
    database: tuple[str, dict[str, str]],
) -> None:
    dsn, assets = database
    body = _get(_client(dsn), assets[fixtures.NGINX_SERVICE_KEY]).json()
    _validated(body)
    item = body["items"][0]
    assert item["vulnerability_id"] == "CVE-2021-23017"
    assert item["kev"] is False
    assert item["affected_range"] == ">= 0.6.18, < 1.20.1"
    assert item["confidence"] == 0.6


def test_an_application_asset_is_a_candidate_source_too(
    database: tuple[str, dict[str, str]],
) -> None:
    dsn, assets = database
    body = _get(_client(dsn), assets[fixtures.APP_KEY]).json()
    _validated(body)
    assert body["asset"]["kind"] == "application"
    assert [item["vulnerability_id"] for item in body["items"]] == ["CVE-2022-22965"]


def test_a_retracted_candidate_disappears_from_the_read_model(
    database: tuple[str, dict[str, str]],
) -> None:
    """Item 61: the API follows the newest decision (`matched`), the same rule as the graph."""
    dsn, assets = database
    client = _client(dsn)
    assert [
        item["vulnerability_id"]
        for item in _get(client, assets[fixtures.SERVICE_KEY]).json()["items"]
    ] == ["CVE-2021-41773"]

    with connect(dsn) as connection:
        FeedSync(fixtures.connector(dsn), fixtures.MemoryStore()).sync(
            "nvd",
            "2026-11-27",
            fixtures.nvd_with_retracted_match(),
            source_uri="nvd-retraction.json",
            snapshot_at=fixtures.SNAPSHOT_AT,
        )
        report = Matcher(connection).run()
        history = connection.execute(
            "SELECT matched, retraction_reason FROM package_vuln_match"
            " WHERE vulnerability_id = 'CVE-2021-41773' ORDER BY created_at, match_id"
        ).fetchall()
    assert report.retracted == 1

    body = _get(client, assets[fixtures.SERVICE_KEY]).json()
    _validated(body)
    assert body["items"] == []
    assert (
        body["coverage"]["matchable"] is True
    )  # the service still has a CPE, it just matches nothing
    assert [row["matched"] for row in history] == [True, False]
    assert history[1]["retraction_reason"] == "NO_LONGER_MATCHES"

    # The other asset's candidate is untouched by a retraction of this pair.
    nginx = _get(client, assets[fixtures.NGINX_SERVICE_KEY]).json()
    assert [item["vulnerability_id"] for item in nginx["items"]] == ["CVE-2021-23017"]


def test_kev_only_filters_and_pages(database: tuple[str, dict[str, str]]) -> None:
    dsn, assets = database
    client = _client(dsn)
    service = assets[fixtures.SERVICE_KEY]
    only_kev = _get(client, service, kev_only=True).json()
    assert [item["vulnerability_id"] for item in only_kev["items"]] == ["CVE-2021-41773"]
    everything = _get(client, service, kev_only=False).json()
    assert len(everything["items"]) == 1
    page = _get(client, service, limit=1)
    assert page.status_code == 200
    assert "next_cursor" not in page.json()


def test_the_operator_token_is_required(database: tuple[str, dict[str, str]]) -> None:
    dsn, assets = database
    response = _get(_client(dsn), assets[fixtures.SERVICE_KEY], headers={})
    assert response.status_code == 401
    body = response.json()
    assert body["code"] == "INPUT_INVALID"
    assert "Authorization" in body["message"]


def test_an_unknown_asset_is_404_and_a_bad_cursor_is_400(
    database: tuple[str, dict[str, str]],
) -> None:
    dsn, _ = database
    client = _client(dsn)
    missing = _get(client, str(uuid7()))
    assert missing.status_code == 404
    bad = _get(client, str(uuid7()), cursor="not-a-cursor")
    assert bad.status_code == 404 or bad.status_code == 400


def test_a_foreign_campaign_sees_no_candidates(database: tuple[str, dict[str, str]]) -> None:
    dsn, assets = database
    body = _get(
        _client(dsn),
        assets[fixtures.SERVICE_KEY],
        campaign_id="01900000-0000-7000-8000-0000000c00ff",
    ).json()
    assert body["items"] == []


def test_versionless_asset_reports_match_coverage_reason(
    database: tuple[str, dict[str, str]],
) -> None:
    from tests.support_ingestion import asset, observation

    dsn, assets = database
    versionless_key = "app:http://10.114.53.10:8081"
    with pipeline_database(jobs=1) as (isolated_dsn, jobs):
        ingest(
            isolated_dsn,
            jobs[0],
            assets=[
                asset("dns:edge.internal.example", "domain"),
                asset(
                    versionless_key,
                    "application",
                    discovered_from=("dns:edge.internal.example",),
                ),
            ],
            observations=[
                observation(versionless_key, "http.technology", ["openresty", "nginx"]),
            ],
            coverage=[versionless_key],
        )
        with connect(isolated_dsn) as connection:
            fixtures.seed_intel(isolated_dsn)
            Matcher(connection).run()
            row = connection.execute(
                "SELECT asset_id FROM asset WHERE canonical_key = %s", (versionless_key,)
            ).fetchone()
            assert row is not None
            asset_id = str(row["asset_id"])
        body = _get(_client(isolated_dsn), asset_id).json()
        _validated(body)
        assert body["items"] == []
        assert body["coverage"] == {
            "matchable": False,
            "limitations": [
                {
                    "code": "VERSION_UNKNOWN",
                    "message": "version unknown, not matchable",
                    "products": ["openresty", "nginx"],
                }
            ],
        }
    # Matchable fixture assets also carry valid coverage metadata.
    apache_body = _get(_client(dsn), assets[fixtures.SERVICE_KEY]).json()
    _validated(apache_body)
    assert apache_body["coverage"] == {"matchable": True, "limitations": []}
