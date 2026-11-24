"""`/api/v2/jobs` over HTTP: auth, 202/200 replay, contract errors, read model, cancel, cursor."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient

from aegis import validation
from aegis.m05_registry.errors import M05Error
from aegis.m05_registry.registry import PostgresManifestRegistry
from aegis.m05_registry.service import PostgresJobService
from aegis.m05_registry.signing import KeyRing
from aegis.m26_api.app import API_PREFIX, create_app
from aegis.m26_api.jobs import install_job_service, router
from aegis.m26_api.operator import OperatorAuthenticationError, Principal
from aegis.m26_api.registry import RouterRegistry
from tests.db_support import connect, migrated_database, requires_postgres, seed_campaign

pytestmark = requires_postgres

AUTH = {"Authorization": "Bearer test-token"}
FIXTURES = Path(__file__).resolve().parents[1] / "contracts/fixtures/valid"


class AcceptingAuthenticator:
    def __init__(self, principal_id: str = "op-g11c") -> None:
        self.principal = Principal(id=principal_id)

    def authenticate(self, authorization: str | None) -> Principal:
        if authorization != AUTH["Authorization"]:
            raise OperatorAuthenticationError("unknown token")
        return self.principal


class FakeBinder:
    def addresses(self, value: str) -> tuple[str, ...]:
        return ("10.114.53.53",)


@contextmanager
def client(dsn: str) -> Iterator[TestClient]:
    registry = PostgresManifestRegistry(lambda: connect(dsn))
    registry.register(
        (FIXTURES / "manifest.subfinder.yaml").read_bytes(),
        registered_by={"kind": "module", "id": "M05"},
    )
    service = PostgresJobService(
        lambda: connect(dsn), registry=registry, key_ring=KeyRing.dev(), binder=FakeBinder()
    )
    routers = RouterRegistry()
    routers.register("jobs", router, prefix=API_PREFIX)
    app = create_app(routers, operator_authenticator=AcceptingAuthenticator())
    install_job_service(app, service)
    yield TestClient(app, raise_server_exceptions=False)


def payload(campaign: Any, **overrides: Any) -> dict[str, Any]:
    body = {
        "campaign_id": campaign.campaign_id,
        "capability": "dns.enumerate_subdomains",
        "input": {"targets": [campaign.seed_domain]},
        "rationale": "API acceptance test",
    }
    body.update(overrides)
    return body


def submit_headers(key: str = "idem-key-1", **extra: str) -> dict[str, str]:
    return {**AUTH, "Idempotency-Key": key, **extra}


def test_jobs_routes_require_a_verified_operator() -> None:
    with migrated_database() as dsn, client(dsn) as http:
        unauthorized = http.get(f"{API_PREFIX}/jobs", params={"campaign_id": "x"})
        assert unauthorized.status_code == 401
        assert unauthorized.headers["www-authenticate"] == "Bearer"


def test_submit_returns_202_then_200_on_replay() -> None:
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn)
        with client(dsn) as http:
            first = http.post(
                f"{API_PREFIX}/jobs",
                json=payload(campaign),
                headers=submit_headers(),
            )
            assert first.status_code == 202, first.text
            job = first.json()
            validation.validate("capability/job.v2.schema.json", job)
            trace = first.headers["traceparent"].split("-")[1]
            assert len(trace) == 32

            replay = http.post(
                f"{API_PREFIX}/jobs", json=payload(campaign), headers=submit_headers()
            )
            assert replay.status_code == 200
            assert replay.headers["idempotent-replayed"] == "true"
            assert replay.json()["job_id"] == job["job_id"]

            conflict = http.post(
                f"{API_PREFIX}/jobs", json=payload(campaign, priority=90), headers=submit_headers()
            )
            assert conflict.status_code == 409
            assert conflict.json()["code"] == "IDEMPOTENCY_CONFLICT"
            assert conflict.json()["next_action"] == "FIX_INPUT"

            read = http.get(f"{API_PREFIX}/jobs/{job['job_id']}", headers=AUTH)
            assert read.status_code == 200 and read.json()["job_id"] == job["job_id"]
            missing = http.get(
                f"{API_PREFIX}/jobs/{'0' * 8}-0000-7000-8000-{'0' * 12}", headers=AUTH
            )
            assert missing.status_code == 404
            assert missing.json()["code"] == "DEPENDENCY_MISSING"


def test_policy_denial_and_invalid_input_are_contract_errors() -> None:
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn)
        with client(dsn) as http:
            denied = http.post(
                f"{API_PREFIX}/jobs",
                json=payload(campaign, capability="dns.not_a_capability"),
                headers=submit_headers("idem-denied"),
            )
            assert denied.status_code == 403
            body = denied.json()
            assert body["code"] == "POLICY_DENIED"
            assert body["next_action"] == "CHECK_PROVIDER"
            assert body["trace_id"] == denied.headers["traceparent"].split("-")[1]

            invalid = http.post(
                f"{API_PREFIX}/jobs",
                json=payload(campaign, input={"targets": "internal.example"}),
                headers=submit_headers("idem-invalid"),
            )
            assert invalid.status_code == 400
            assert invalid.json()["code"] == "INPUT_INVALID"
            assert invalid.json()["field"].startswith("/input")
            assert invalid.json()["next_action"] == "FIX_INPUT"

            malformed = http.post(
                f"{API_PREFIX}/jobs",
                json={"campaign_id": campaign.campaign_id},
                headers=submit_headers("idem-malformed"),
            )
            assert malformed.status_code == 400
            assert malformed.json()["code"] == "INPUT_INVALID"
            assert malformed.json()["field"].startswith("/")

            no_key = http.post(f"{API_PREFIX}/jobs", json=payload(campaign), headers=dict(AUTH))
            assert no_key.status_code == 400
            assert no_key.json()["field"] == "/Idempotency-Key"


def test_list_jobs_uses_a_keyset_cursor_and_status_filter() -> None:
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn)
        with client(dsn) as http:
            for index in range(3):
                response = http.post(
                    f"{API_PREFIX}/jobs",
                    json=payload(campaign, rationale=f"scan number {index}"),
                    headers=submit_headers(f"idem-list-{index}"),
                )
                assert response.status_code == 202, response.text

            first_page = http.get(
                f"{API_PREFIX}/jobs",
                params={"campaign_id": campaign.campaign_id, "limit": 2},
                headers=AUTH,
            )
            assert first_page.status_code == 200
            page = first_page.json()
            assert len(page["items"]) == 2
            assert "next_cursor" in page

            second_page = http.get(
                f"{API_PREFIX}/jobs",
                params={
                    "campaign_id": campaign.campaign_id,
                    "limit": 2,
                    "cursor": page["next_cursor"],
                },
                headers=AUTH,
            )
            second = second_page.json()
            assert len(second["items"]) == 1
            assert "next_cursor" not in second
            ids = {item["job_id"] for item in page["items"]} | {
                item["job_id"] for item in second["items"]
            }
            assert len(ids) == 3

            filtered = http.get(
                f"{API_PREFIX}/jobs",
                params={"campaign_id": campaign.campaign_id, "status": "SUCCEEDED"},
                headers=AUTH,
            )
            assert filtered.json()["items"] == []


def test_cancel_records_intent_and_terminalises_a_queued_job() -> None:
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn)
        with client(dsn) as http:
            submitted = http.post(
                f"{API_PREFIX}/jobs", json=payload(campaign), headers=submit_headers("idem-cancel")
            ).json()
            cancelled = http.post(
                f"{API_PREFIX}/jobs/{submitted['job_id']}/cancel",
                json={"reason": "operator stopped the scan"},
                headers=AUTH,
            )
            assert cancelled.status_code == 200, cancelled.text
            body = cancelled.json()
            assert body["status"] == "CANCELLED"
            assert body["cancel"]["requested_by"] == {"kind": "operator", "id": "op-g11c"}
            assert body["cancel"]["reason"] == "operator stopped the scan"
            assert body["finished_at"]

            again = http.post(
                f"{API_PREFIX}/jobs/{submitted['job_id']}/cancel", json={}, headers=AUTH
            )
            assert again.status_code == 200 and again.json()["status"] == "CANCELLED"
            unknown = http.post(
                f"{API_PREFIX}/jobs/{'1' * 8}-0000-7000-8000-{'1' * 12}/cancel",
                headers=AUTH,
            )
            assert unknown.status_code == 404


def test_m05_refusal_reaches_the_client_with_its_status(monkeypatch: pytest.MonkeyPatch) -> None:
    """The route never invents a status: it answers what the refusal says."""
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn)
        with client(dsn) as http:
            service: PostgresJobService = cast(Any, http.app).state.job_service

            def boom(*args: Any, **kwargs: Any) -> Any:
                raise M05Error.rate_limited(
                    "rate_jobs_per_minute", "slow down", retry_after_seconds=7
                )

            monkeypatch.setattr(service, "submit", boom)
            limited = http.post(
                f"{API_PREFIX}/jobs", json=payload(campaign), headers=submit_headers("idem-429")
            )
            assert limited.status_code == 429
            assert limited.headers["retry-after"] == "7"
            assert limited.json()["code"] == "RATE_LIMITED"
            assert limited.json()["next_action"] == "RETRY_LATER"
