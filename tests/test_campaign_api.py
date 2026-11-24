"""Campaign REST over a real PostgreSQL 16 database (card G1.1b).

Every test runs against the full published migration chain in a throwaway database,
so the triggers of 0005/0009/0010/0011/0012/0014 are exercised on the rows the API
writes, not just the Python code.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

from aegis import validation
from aegis.m01_campaign.ids import uuid7

from . import campaign_support as support

ID_REFERENCE = "common/ids.v2.schema.json#/$defs/Id"
POLICY_VERSION_REFERENCE = "common/ids.v2.schema.json#/$defs/PolicyVersion"
CAMPAIGN_READ = "campaign/campaign.v2.schema.json"
ERROR = "common/error.v2.schema.json"

requires_postgres = support.requires_postgres()


@pytest.fixture(scope="module")
def dsn() -> Iterator[str]:
    if not os.environ.get(support.DSN_ENV):
        pytest.skip(f"set {support.DSN_ENV} to run the campaign API tests")
    with support.database() as value:
        yield value


@pytest.fixture(scope="module")
def client(dsn: str) -> TestClient:
    return support.build_app(dsn)[0]


def _assert_created(payload: dict[str, Any], *, status: str = "CREATED") -> None:
    assert set(payload) == {"campaign_id", "status", "policy_version", "scope_id"}
    assert payload["status"] == status
    validation.validate(ID_REFERENCE, payload["campaign_id"])
    validation.validate(ID_REFERENCE, payload["scope_id"])
    validation.validate(POLICY_VERSION_REFERENCE, payload["policy_version"])


def _assert_error(response: Any, status_code: int, code: str) -> dict[str, Any]:
    assert response.status_code == status_code, response.text
    payload: dict[str, Any] = response.json()
    validation.validate(ERROR, payload)
    assert payload["code"] == code
    assert payload["trace_id"]
    return payload


def _create(client: TestClient, key: str, **overrides: Any) -> dict[str, Any]:
    response = support.create_campaign(client, key=key, body=support.campaign_body(**overrides))
    assert response.status_code == 202, response.text
    payload: dict[str, Any] = response.json()
    _assert_created(payload)
    return payload


# --------------------------------------------------------------------------- create


@requires_postgres
def test_create_campaign_writes_the_whole_aggregate(dsn: str, client: TestClient) -> None:
    body = support.campaign_body()
    response = support.create_campaign(client, key="aggregate-1", body=body)

    assert response.status_code == 202, response.text
    payload = response.json()
    _assert_created(payload)
    campaign_id, scope_id = payload["campaign_id"], payload["scope_id"]

    campaign = support.fetch_one(
        dsn, "SELECT * FROM aegis.campaign WHERE campaign_id = %s", (campaign_id,)
    )
    assert campaign["name"] == body["name"]
    assert campaign["objective"] == body["objective"]
    assert campaign["status"] == "CREATED"
    assert campaign["current_policy_version"] == payload["policy_version"]
    assert campaign["created_by"] == {"kind": "operator", "id": "op-soc-1"}
    assert str(campaign["scope_id"]) == scope_id

    scope = support.fetch_one(
        dsn, "SELECT targets FROM aegis.scope_snapshot WHERE scope_id = %s", (scope_id,)
    )
    assert scope["targets"] == body["targets"], "the scope snapshot keeps the request verbatim"

    seeds = support.fetch_all(
        dsn,
        "SELECT kind, raw_value, canonical_key FROM aegis.campaign_target"
        " WHERE scope_id = %s ORDER BY kind, raw_value",
        (scope_id,),
    )
    assert seeds == [
        {"kind": "cidr", "raw_value": "10.20.0.0/24", "canonical_key": None},
        {
            "kind": "domain",
            "raw_value": "internal.example",
            "canonical_key": "dns:internal.example",
        },
        {"kind": "keyword", "raw_value": "acme corp", "canonical_key": None},
    ]

    snapshot = support.fetch_one(
        dsn,
        "SELECT policy, policy_hash, created_by FROM aegis.policy_snapshot"
        " WHERE policy_version = %s",
        (payload["policy_version"],),
    )
    assert snapshot["policy"] == body["policy"]
    assert snapshot["created_by"] == {"kind": "operator", "id": "op-soc-1"}
    expected_hash = support.fetch_one(
        dsn, "SELECT aegis.policy_hash(%s) AS h", (Jsonb(body["policy"]),)
    )["h"]
    assert snapshot["policy_hash"] == expected_hash

    history = support.fetch_all(
        dsn,
        "SELECT seq, from_status, to_status, reason, actor FROM aegis.campaign_status_change"
        " WHERE campaign_id = %s ORDER BY seq",
        (campaign_id,),
    )
    assert history == [
        {
            "seq": 1,
            "from_status": None,
            "to_status": "CREATED",
            "reason": None,
            "actor": {"kind": "operator", "id": "op-soc-1"},
        }
    ]

    audit = support.fetch_all(
        dsn,
        "SELECT action, actor, details FROM aegis.audit_log WHERE campaign_id = %s",
        (campaign_id,),
    )
    assert [row["action"] for row in audit] == ["campaign.create"]
    assert audit[0]["actor"] == {"kind": "operator", "id": "op-soc-1"}
    assert audit[0]["details"]["policy_version"] == payload["policy_version"]


@requires_postgres
def test_create_campaign_rejects_contract_violations(dsn: str, client: TestClient) -> None:
    before = support.count(dsn, "campaign")

    coerced = support.campaign_body()
    coerced["policy"]["max_parallel_jobs"] = "10"  # the contract says integer, not a string
    response = support.create_campaign(client, key="reject-coerced", body=coerced)
    payload = _assert_error(response, 400, "INPUT_INVALID")
    assert payload["next_action"] == "FIX_INPUT"
    assert payload["field"] == "/policy/max_parallel_jobs"

    unknown = support.campaign_body()
    unknown["unexpected"] = True
    _assert_error(
        support.create_campaign(client, key="reject-unknown", body=unknown), 400, "INPUT_INVALID"
    )

    bad_domain = support.campaign_body()
    bad_domain["targets"] = {"domains": ["-bad.example"]}
    _assert_error(
        support.create_campaign(client, key="reject-domain", body=bad_domain), 400, "INPUT_INVALID"
    )

    # The RoE time windows were dropped from the contract (owner decision 2026-11-24): a body that
    # still carries them is an unknown property of the policy, not a silently ignored setting.
    windows = support.campaign_body()
    windows["policy"]["allowed_windows"] = [
        {"days": ["mon"], "start": "08:00", "end": "18:00", "timezone": "Asia/Ho_Chi_Minh"}
    ]
    payload = _assert_error(
        support.create_campaign(client, key="reject-windows", body=windows), 400, "INPUT_INVALID"
    )
    assert payload["field"] is not None and payload["field"].startswith("/policy")

    malformed = client.post(
        f"{support.API}/campaigns",
        content="{not json",
        headers={
            **support.auth(),
            "Idempotency-Key": "malformed-1",
            "content-type": "application/json",
        },
    )
    _assert_error(malformed, 400, "INPUT_INVALID")

    assert support.count(dsn, "campaign") == before, "a rejected body must not write a campaign"


@requires_postgres
def test_idempotency_key_header_is_required_and_bounded(client: TestClient) -> None:
    body = support.campaign_body()
    missing = client.post(f"{support.API}/campaigns", json=body, headers=support.auth())
    _assert_error(missing, 400, "INPUT_INVALID")

    short = client.post(
        f"{support.API}/campaigns",
        json=body,
        headers={**support.auth(), "Idempotency-Key": "short"},
    )
    _assert_error(short, 400, "INPUT_INVALID")


@requires_postgres
def test_write_and_read_routes_require_a_verified_operator(client: TestClient) -> None:
    body = support.campaign_body()
    no_token = client.post(
        f"{support.API}/campaigns", json=body, headers={"Idempotency-Key": "no-token-1"}
    )
    payload = _assert_error(no_token, 401, "INPUT_INVALID")
    assert no_token.headers["www-authenticate"] == "Bearer"
    assert payload["next_action"] == "FIX_INPUT"

    wrong = client.post(
        f"{support.API}/campaigns",
        json=body,
        headers={"Idempotency-Key": "wrong-token-1", "authorization": "Bearer not-configured"},
    )
    _assert_error(wrong, 401, "INPUT_INVALID")

    for path in (f"{support.API}/campaigns", f"{support.API}/campaigns/{uuid7()}"):
        _assert_error(
            client.get(path, headers={"authorization": "Basic abc"}), 401, "INPUT_INVALID"
        )


@requires_postgres
def test_traceparent_is_echoed_and_recorded(client: TestClient, dsn: str) -> None:
    trace = uuid.uuid4().hex
    response = client.post(
        f"{support.API}/campaigns",
        json=support.campaign_body(name="traced campaign"),
        headers={
            **support.auth(),
            "Idempotency-Key": "traced-campaign-1",
            "traceparent": f"00-{trace}-{uuid.uuid4().hex[:16]}-01",
        },
    )
    assert response.status_code == 202, response.text
    assert response.headers["traceparent"].startswith(f"00-{trace}-")
    campaign_id = response.json()["campaign_id"]
    audit = support.fetch_one(
        dsn,
        "SELECT trace_id FROM aegis.audit_log"
        " WHERE campaign_id = %s AND action = 'campaign.create'",
        (campaign_id,),
    )
    assert audit["trace_id"] == trace

    generated = support.create_campaign(
        client, key="traced-campaign-2", body=support.campaign_body(name="generated trace")
    )
    assert len(generated.headers["traceparent"].split("-")[1]) == 32


# --------------------------------------------------------------------------- read


@requires_postgres
def test_get_campaign_returns_the_contract_read_model(client: TestClient) -> None:
    body = support.campaign_body(name="read model campaign")
    created = _create(client, "read-model-1", name=body["name"])

    response = client.get(
        f"{support.API}/campaigns/{created['campaign_id']}", headers=support.auth()
    )
    assert response.status_code == 200, response.text
    campaign = response.json()
    validation.validate(CAMPAIGN_READ, campaign)
    assert campaign["campaign_id"] == created["campaign_id"]
    assert campaign["policy_version"] == created["policy_version"]
    assert campaign["policy"] == body["policy"]
    assert campaign["targets"] == body["targets"]
    assert campaign["created_at"].endswith("Z")
    assert "started_at" not in campaign and "ended_at" not in campaign


@requires_postgres
def test_get_campaign_404_for_unknown_or_malformed_id(client: TestClient) -> None:
    for campaign_id in (str(uuid7()), "not-a-uuid", str(uuid.uuid4())):
        response = client.get(f"{support.API}/campaigns/{campaign_id}", headers=support.auth())
        _assert_error(response, 404, "INPUT_INVALID")


@requires_postgres
def test_list_campaigns_keyset_pagination_and_status_filter(client: TestClient) -> None:
    created = [
        _create(client, f"list-campaign-{index}", name=f"list campaign {index}")
        for index in range(3)
    ]
    created_ids = {item["campaign_id"] for item in created}

    seen: list[dict[str, Any]] = []
    cursor: str | None = None
    for _ in range(50):
        params: dict[str, Any] = {"limit": 2}
        if cursor:
            params["cursor"] = cursor
        response = client.get(f"{support.API}/campaigns", params=params, headers=support.auth())
        assert response.status_code == 200, response.text
        page = response.json()
        assert set(page) <= {"items", "next_cursor"}
        for item in page["items"]:
            validation.validate(CAMPAIGN_READ, item)
        seen.extend(page["items"])
        cursor = page.get("next_cursor")
        if not cursor:
            break
    assert cursor is None
    ids = [item["campaign_id"] for item in seen]
    assert len(ids) == len(set(ids)), "a keyset page must not repeat a campaign"
    assert created_ids <= set(ids)
    timestamps = [item["created_at"] for item in seen]
    assert timestamps == sorted(timestamps, reverse=True), "newest first"

    cancelled = client.get(
        f"{support.API}/campaigns",
        params={"status": "CANCELLED", "limit": 200},
        headers=support.auth(),
    )
    assert cancelled.status_code == 200
    assert all(item["status"] == "CANCELLED" for item in cancelled.json()["items"])

    invalid_status = client.get(
        f"{support.API}/campaigns", params={"status": "RUNNING_AWAY"}, headers=support.auth()
    )
    _assert_error(invalid_status, 400, "INPUT_INVALID")

    bad_cursor = client.get(
        f"{support.API}/campaigns", params={"cursor": "not-a-cursor"}, headers=support.auth()
    )
    _assert_error(bad_cursor, 400, "INPUT_INVALID")


# --------------------------------------------------------------------------- policy


@requires_postgres
def test_policy_adopt_appends_a_snapshot_and_keeps_the_old_one(
    dsn: str, client: TestClient
) -> None:
    original = support.campaign_body()
    created = _create(client, "policy-adopt-1")
    old_version = created["policy_version"]

    new_policy = support.policy(max_parallel_jobs=7)
    response = client.post(
        f"{support.API}/campaigns/{created['campaign_id']}/policy",
        json={"policy": new_policy, "reason": "raise parallelism for the window"},
        headers={**support.auth(), "Idempotency-Key": "policy-adopt-1"},
    )
    assert response.status_code == 200, response.text
    new_version = response.json()["policy_version"]
    assert new_version != old_version
    validation.validate(POLICY_VERSION_REFERENCE, new_version)

    campaign = client.get(
        f"{support.API}/campaigns/{created['campaign_id']}", headers=support.auth()
    ).json()
    assert campaign["policy_version"] == new_version
    assert campaign["policy"] == new_policy

    snapshots = support.fetch_all(
        dsn,
        "SELECT policy_version, policy FROM aegis.policy_snapshot WHERE campaign_id = %s"
        " ORDER BY policy_version",
        (created["campaign_id"],),
    )
    assert {row["policy_version"] for row in snapshots} == {old_version, new_version}
    old_row = next(row for row in snapshots if row["policy_version"] == old_version)
    assert old_row["policy"] == original["policy"], "the previous snapshot is append-only history"

    audit = support.fetch_one(
        dsn,
        "SELECT details FROM aegis.audit_log"
        " WHERE campaign_id = %s AND action = 'campaign.policy_adopt'",
        (created["campaign_id"],),
    )
    assert audit["details"]["reason"] == "raise parallelism for the window"
    assert audit["details"]["previous_policy_version"] == old_version


@requires_postgres
def test_policy_adopt_rejects_bad_bodies_and_ended_campaigns(dsn: str, client: TestClient) -> None:
    created = _create(client, "policy-errors-1")
    path = f"{support.API}/campaigns/{created['campaign_id']}/policy"

    unknown_field = client.post(
        path,
        json={"policy": {**support.policy(), "bogus": 1}, "reason": "invalid policy field"},
        headers={**support.auth(), "Idempotency-Key": "policy-errors-1"},
    )
    _assert_error(unknown_field, 400, "INPUT_INVALID")

    short_reason = client.post(
        path,
        json={"policy": support.policy(), "reason": "no"},
        headers={**support.auth(), "Idempotency-Key": "policy-errors-2"},
    )
    payload = _assert_error(short_reason, 400, "INPUT_INVALID")
    assert payload["field"] == "/reason"

    missing = client.post(
        path,
        json={"policy": support.policy(), "reason": "valid reason"},
        headers={**support.auth(), "Idempotency-Key": "policy-errors-3"},
    )
    assert missing.status_code == 200
    unknown_campaign = client.post(
        f"{support.API}/campaigns/{uuid7()}/policy",
        json={"policy": support.policy(), "reason": "valid reason"},
        headers={**support.auth(), "Idempotency-Key": "policy-errors-4"},
    )
    _assert_error(unknown_campaign, 404, "INPUT_INVALID")

    cancelled = _create(client, "policy-errors-5")
    client.post(
        f"{support.API}/campaigns/{cancelled['campaign_id']}/cancel",
        json={"reason": "stop the campaign"},
        headers=support.auth(),
    )
    response = client.post(
        f"{support.API}/campaigns/{cancelled['campaign_id']}/policy",
        json={"policy": support.policy(), "reason": "cannot adopt after the end"},
        headers={**support.auth(), "Idempotency-Key": "policy-errors-6"},
    )
    _assert_error(response, 409, "INPUT_INVALID")
    assert support.count(dsn, "policy_snapshot") >= 1


# --------------------------------------------------------------------------- status actions


@requires_postgres
def test_pause_resume_cancel_history_and_audit(dsn: str, client: TestClient) -> None:
    created = _create(client, "actions-1")
    base = f"{support.API}/campaigns/{created['campaign_id']}"

    paused = client.post(f"{base}/pause", json={"reason": "operator pause"}, headers=support.auth())
    assert paused.status_code == 200, paused.text
    campaign = paused.json()
    validation.validate(CAMPAIGN_READ, campaign)
    assert campaign["status"] == "PAUSED"
    assert campaign["status_reason"] == "operator pause"

    again = client.post(f"{base}/pause", json={"reason": "repeat"}, headers=support.auth())
    assert again.status_code == 200
    history = support.fetch_all(
        dsn,
        "SELECT seq, from_status, to_status, reason FROM aegis.campaign_status_change"
        " WHERE campaign_id = %s ORDER BY seq",
        (created["campaign_id"],),
    )
    assert [(row["from_status"], row["to_status"]) for row in history] == [
        (None, "CREATED"),
        ("CREATED", "PAUSED"),
    ], "a repeated action must not write a second history row"

    resumed = client.post(f"{base}/resume", json={"reason": "resume now"}, headers=support.auth())
    assert resumed.status_code == 200
    campaign = resumed.json()
    assert campaign["status"] == "RUNNING"
    assert "started_at" in campaign
    assert "status_reason" not in campaign, "resuming clears the pause reason"

    client.post(f"{base}/pause", json={"reason": "pause again"}, headers=support.auth())
    cancelled = client.post(f"{base}/cancel", json={"reason": "stop"}, headers=support.auth())
    assert cancelled.status_code == 200
    campaign = cancelled.json()
    assert campaign["status"] == "CANCELLED"
    assert campaign["status_reason"] == "stop"
    assert "ended_at" in campaign

    terminal_count = len(
        support.fetch_all(
            dsn,
            "SELECT seq FROM aegis.campaign_status_change WHERE campaign_id = %s",
            (created["campaign_id"],),
        )
    )
    repeat_cancel = client.post(f"{base}/cancel", json={"reason": "repeat"}, headers=support.auth())
    assert repeat_cancel.status_code == 200
    assert repeat_cancel.json()["status"] == "CANCELLED"
    assert (
        len(
            support.fetch_all(
                dsn,
                "SELECT seq FROM aegis.campaign_status_change WHERE campaign_id = %s",
                (created["campaign_id"],),
            )
        )
        == terminal_count
    )

    _assert_error(
        client.post(f"{base}/resume", json={"reason": "too late"}, headers=support.auth()),
        409,
        "INPUT_INVALID",
    )
    _assert_error(
        client.post(f"{base}/pause", json={"reason": "too late"}, headers=support.auth()),
        409,
        "INPUT_INVALID",
    )

    actions = [
        row["action"]
        for row in support.fetch_all(
            dsn,
            "SELECT action FROM aegis.audit_log WHERE campaign_id = %s ORDER BY audit_id",
            (created["campaign_id"],),
        )
    ]
    assert actions == [
        "campaign.create",
        "campaign.pause",
        "campaign.resume",
        "campaign.pause",
        "campaign.cancel",
    ], "one audit row per real transition, none for a repeated action"


@requires_postgres
def test_actions_require_a_reason_and_an_existing_campaign(client: TestClient) -> None:
    created = _create(client, "actions-errors-1")
    base = f"{support.API}/campaigns/{created['campaign_id']}"

    empty = client.post(f"{base}/pause", json={}, headers=support.auth())
    payload = _assert_error(empty, 400, "INPUT_INVALID")
    assert payload["field"] == "/reason"

    long_reason = client.post(f"{base}/pause", json={"reason": "x" * 2001}, headers=support.auth())
    _assert_error(long_reason, 400, "INPUT_INVALID")

    for action in ("pause", "resume", "cancel"):
        _assert_error(
            client.post(
                f"{support.API}/campaigns/{uuid7()}/{action}",
                json={"reason": "unknown campaign"},
                headers=support.auth(),
            ),
            404,
            "INPUT_INVALID",
        )


@requires_postgres
@pytest.mark.parametrize("field", ["actor", "requested_by", "proposed_by", "created_by"])
def test_a_body_cannot_declare_the_actor(dsn: str, client: TestClient, field: str) -> None:
    """C05/X-8: REST has no identity field; the server's principal is the only actor."""
    before = support.count(dsn, "campaign")
    body = support.campaign_body()
    body[field] = {"kind": "operator", "id": "somebody-else"}
    response = support.create_campaign(client, key=f"actor-field-{field}", body=body)
    payload = _assert_error(response, 400, "INPUT_INVALID")
    assert payload["field"] == f"/{field}" or payload["field"] == "/"
    assert support.count(dsn, "campaign") == before


@requires_postgres
def test_the_operator_token_is_never_stored(dsn: str, client: TestClient) -> None:
    created = _create(client, "token-leak-1")
    token = support.OPERATORS["op-soc-1"]

    campaign = support.fetch_one(
        dsn,
        "SELECT created_by::text AS created_by FROM aegis.campaign WHERE campaign_id = %s",
        (created["campaign_id"],),
    )
    audit = support.fetch_all(
        dsn,
        "SELECT actor::text AS actor, details::text AS details FROM aegis.audit_log"
        " WHERE campaign_id = %s",
        (created["campaign_id"],),
    )
    assert token not in campaign["created_by"]
    for row in audit:
        assert token not in row["actor"] and token not in row["details"]
    assert token not in str(created)


@requires_postgres
def test_the_seed_targets_become_assets(dsn: str, client: TestClient) -> None:
    """0001 gives `asset.first_job_id` the meaning "NULL = a seed target", so the seed is an asset.

    The G1.5c demo showed why it matters: M27 cannot resolve a coverage subject (or the parent of a
    `SUBDOMAIN_OF` edge) that is not an asset, and quarantines both. The seed becomes an asset in
    the same transaction that creates the campaign, and a second campaign reuses the row.
    """
    body = support.campaign_body(
        targets={"domains": ["seed-assets.example"], "ips": ["10.99.0.5"], "keywords": ["acme"]}
    )
    before = support.count(dsn, "asset")
    first = support.create_campaign(client, key="seed-assets-1", body=body)
    assert first.status_code == 202, first.text
    campaign_id = first.json()["campaign_id"]
    assert support.count(dsn, "asset") == before + 2, "a keyword seed has no identity and no asset"

    assets = support.fetch_all(
        dsn,
        "SELECT canonical_key, kind, first_job_id FROM aegis.asset"
        " WHERE canonical_key IN ('dns:seed-assets.example', 'ip:10.99.0.5') ORDER BY 1",
    )
    assert [row["canonical_key"] for row in assets] == ["dns:seed-assets.example", "ip:10.99.0.5"]
    assert [row["kind"] for row in assets] == ["domain", "ip"]
    assert all(row["first_job_id"] is None for row in assets), "a seed asset has no job yet"
    linked = support.fetch_all(
        dsn,
        "SELECT asset_id FROM aegis.asset_campaign WHERE campaign_id = %s",
        (campaign_id,),
    )
    assert len(linked) == 2, "the campaign must be linked to both seed assets"

    after = support.count(dsn, "asset")
    second = support.create_campaign(client, key="seed-assets-2", body=body)
    assert second.status_code == 202, second.text
    assert support.count(dsn, "asset") == after, "a second campaign must reuse the asset rows"
    campaign_two = support.fetch_all(
        dsn,
        "SELECT asset_id FROM aegis.asset_campaign WHERE campaign_id = %s",
        (second.json()["campaign_id"],),
    )
    assert len(campaign_two) == 2
