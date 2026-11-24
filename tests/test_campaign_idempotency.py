"""`Idempotency-Key` on campaign create/policy (NFR-02) against a real database."""

from __future__ import annotations

import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from fastapi.testclient import TestClient

from . import campaign_support as support

requires_postgres = support.requires_postgres()


@pytest.fixture(scope="module")
def dsn() -> Iterator[str]:
    if not os.environ.get(support.DSN_ENV):
        pytest.skip(f"set {support.DSN_ENV} to run the campaign idempotency tests")
    with support.database() as value:
        yield value


@pytest.fixture(scope="module")
def app(dsn: str) -> Any:
    return support.build_app(dsn)[1]


@pytest.fixture(scope="module")
def client(app: Any) -> TestClient:
    return TestClient(app)


def _post(client: TestClient, key: str, body: dict[str, Any]) -> Any:
    return support.create_campaign(client, key=key, body=body)


@requires_postgres
def test_same_key_same_body_replays_the_stored_response(dsn: str, client: TestClient) -> None:
    body = support.campaign_body(name="idempotent campaign")
    campaigns_before = support.count(dsn, "campaign")
    audit_before = support.count(dsn, "audit_log")
    first = _post(client, "idem-same-1", body)
    second = _post(client, "idem-same-1", body)

    assert first.status_code == second.status_code == 202
    assert second.json() == first.json()
    assert "Idempotent-Replayed" not in first.headers
    assert second.headers["Idempotent-Replayed"] == "true"
    assert support.count(dsn, "campaign") == campaigns_before + 1
    assert support.count(dsn, "audit_log") == audit_before + 1
    stored = support.fetch_one(
        dsn,
        "SELECT status_code, request_hash, response FROM aegis.idempotency_record"
        " WHERE scope = 'POST /campaigns' AND key = 'idem-same-1'",
    )
    assert stored["status_code"] == 202
    assert stored["response"] == first.json()
    assert len(stored["request_hash"]) == 64


@requires_postgres
def test_same_key_different_body_is_409_and_writes_nothing(dsn: str, client: TestClient) -> None:
    _post(client, "idem-conflict-1", support.campaign_body(name="first body"))
    before = support.count(dsn, "campaign")

    response = _post(client, "idem-conflict-1", support.campaign_body(name="second body"))
    assert response.status_code == 409, response.text
    payload = response.json()
    assert payload["code"] == "IDEMPOTENCY_CONFLICT"
    assert payload["next_action"] == "NONE"
    assert support.count(dsn, "campaign") == before


@requires_postgres
def test_one_hundred_calls_with_one_key_create_one_campaign(dsn: str, client: TestClient) -> None:
    """NFR-02: a client retrying a create a hundred times gets one campaign."""
    body = support.campaign_body(name="retry storm campaign")
    campaigns_before = support.count(dsn, "campaign")
    records_before = support.count(dsn, "idempotency_record")
    responses = [_post(client, "idem-storm-1", body) for _ in range(100)]

    assert {response.status_code for response in responses} == {202}
    ids = {response.json()["campaign_id"] for response in responses}
    assert len(ids) == 1
    replayed = [response for response in responses if response.headers.get("Idempotent-Replayed")]
    assert len(replayed) == 99
    assert support.count(dsn, "campaign") == campaigns_before + 1
    assert support.count(dsn, "idempotency_record") == records_before + 1


@requires_postgres
def test_concurrent_calls_with_one_key_create_one_campaign(app: Any, dsn: str) -> None:
    body = support.campaign_body(name="concurrent campaign")
    campaigns_before = support.count(dsn, "campaign")
    records_before = support.count(dsn, "idempotency_record")
    clients = [TestClient(app) for _ in range(12)]

    def call(client: TestClient) -> Any:
        return _post(client, "idem-concurrent-1", body)

    with ThreadPoolExecutor(max_workers=len(clients)) as pool:
        responses = list(pool.map(call, clients))

    assert {response.status_code for response in responses} == {202}, [r.text for r in responses]
    ids = {response.json()["campaign_id"] for response in responses}
    assert len(ids) == 1
    assert support.count(dsn, "campaign") == campaigns_before + 1
    assert support.count(dsn, "idempotency_record") == records_before + 1


@requires_postgres
def test_policy_adopt_is_idempotent_per_key(dsn: str, client: TestClient) -> None:
    created = _post(client, "idem-policy-create", support.campaign_body()).json()
    path = f"{support.API}/campaigns/{created['campaign_id']}/policy"
    request = {"policy": support.policy(max_parallel_jobs=9), "reason": "adopt once"}
    headers = {**support.auth(), "Idempotency-Key": "idem-policy-1"}

    first = client.post(path, json=request, headers=headers)
    second = client.post(path, json=request, headers=headers)
    assert first.status_code == second.status_code == 200, second.text
    assert second.json() == first.json()
    assert second.headers["Idempotent-Replayed"] == "true"
    assert len(first.json()["policy_version"]) > 4
    snapshots = support.fetch_all(
        dsn,
        "SELECT policy_version FROM aegis.policy_snapshot WHERE campaign_id = %s",
        (created["campaign_id"],),
    )
    assert len(snapshots) == 2, "the create snapshot plus exactly one adopted snapshot"

    changed = client.post(
        path,
        json={"policy": support.policy(max_parallel_jobs=11), "reason": "adopt once"},
        headers=headers,
    )
    assert changed.status_code == 409
    assert changed.json()["code"] == "IDEMPOTENCY_CONFLICT"
    assert (
        len(
            support.fetch_all(
                dsn,
                "SELECT policy_version FROM aegis.policy_snapshot WHERE campaign_id = %s",
                (created["campaign_id"],),
            )
        )
        == 2
    )


@requires_postgres
def test_keys_are_scoped_so_create_and_policy_may_share_one(client: TestClient) -> None:
    key = "shared-key-across-scopes"
    created = _post(client, key, support.campaign_body(name="scope key campaign"))
    assert created.status_code == 202
    response = client.post(
        f"{support.API}/campaigns/{created.json()['campaign_id']}/policy",
        json={"policy": support.policy(max_parallel_jobs=6), "reason": "same key, other scope"},
        headers={**support.auth(), "Idempotency-Key": key},
    )
    assert response.status_code == 200, response.text
    assert "Idempotent-Replayed" not in response.headers
