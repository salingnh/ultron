"""Every M05 refusal leaves an M25 trace - including the ones that cannot have a decision.

The leader decision (item #51, follow-up to #33): `policy_decision` stays decision-only and still
requires resolved TargetRefs (0012), so a `400 INPUT_INVALID` raised before any ref exists writes
no decision - but it must not be invisible either. Every refused submission therefore writes
exactly one `audit_log` row in the same transaction: the verified actor, the raw requested targets
as text, the capability, the error code/rule and the trace id.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from aegis.contracts_gen.capability.job_submit_v2_schema import JobSubmit
from aegis.m05_registry.errors import M05Error
from aegis.m05_registry.registry import PostgresManifestRegistry
from aegis.m05_registry.service import PostgresJobService
from aegis.m05_registry.signing import KeyRing
from tests.db_support import (
    OPERATOR,
    SeededCampaign,
    connect,
    migrated_database,
    requires_postgres,
    seed_campaign,
)

pytestmark = requires_postgres

FIXTURES = Path(__file__).resolve().parents[1] / "contracts/fixtures/valid"


class FakeBinder:
    def addresses(self, value: str) -> tuple[str, ...]:
        return ("10.114.53.53",)


def service(dsn: str) -> PostgresJobService:
    registry = PostgresManifestRegistry(lambda: connect(dsn))
    registry.register(
        (FIXTURES / "manifest.subfinder.yaml").read_bytes(),
        registered_by={"kind": "module", "id": "M05"},
    )
    return PostgresJobService(
        lambda: connect(dsn), registry=registry, key_ring=KeyRing.dev(), binder=FakeBinder()
    )


def body(campaign: SeededCampaign, **overrides: Any) -> JobSubmit:
    payload: dict[str, Any] = {
        "campaign_id": campaign.campaign_id,
        "capability": "dns.enumerate_subdomains",
        "input": {"targets": [campaign.seed_domain]},
        "rationale": "refusal audit test",
    }
    payload.update(overrides)
    return JobSubmit.model_validate(payload)


def audit_rows(dsn: str) -> list[dict[str, Any]]:
    with connect(dsn) as conn:
        rows = conn.execute(
            "SELECT actor, action, campaign_id::text, capability_id, targets, details, trace_id "
            "FROM audit_log ORDER BY audit_id"
        ).fetchall()
    return [
        {
            "actor": row[0],
            "action": row[1],
            "campaign_id": row[2],
            "capability_id": row[3],
            "targets": list(row[4]) if row[4] is not None else None,
            "details": row[5],
            "trace_id": row[6],
        }
        for row in rows
    ]


def test_invalid_input_writes_no_decision_but_one_audit_row() -> None:
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn)
        jobs = service(dsn)
        with pytest.raises(M05Error) as caught:
            jobs.submit(
                body(campaign, input={"targets": campaign.seed_domain}),  # not a list
                requested_by=OPERATOR,
                idempotency_key="audit-invalid-input",
                trace_id="a" * 32,
            )
        assert caught.value.refusal.code == "INPUT_INVALID"

        assert audit_rows(dsn) == [
            {
                "actor": OPERATOR,
                "action": "job.refuse",
                "campaign_id": campaign.campaign_id,
                "capability_id": "dns.enumerate_subdomains",
                "targets": [campaign.seed_domain],
                "details": audit_rows(dsn)[0]["details"],
                "trace_id": "a" * 32,
            }
        ]
        details = audit_rows(dsn)[0]["details"]
        assert details["code"] == "INPUT_INVALID"
        assert details["next_action"] == "FIX_INPUT"
        assert details["rule"] == "schema"
        assert details["field"].startswith("/input")

        # The leader's split holds: a 400 has no decision row (0012 needs resolved refs) ...
        with connect(dsn) as conn:
            assert conn.execute("SELECT count(*) FROM policy_decision").fetchone() == (0,)
            assert conn.execute("SELECT count(*) FROM outbox_event").fetchone() == (0,)


def test_an_unresolvable_target_is_audited_with_the_raw_value() -> None:
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn)
        jobs = service(dsn)
        with pytest.raises(M05Error) as caught:
            jobs.submit(
                body(campaign, input={"targets": ["dns:unknown.internal.example"]}),
                requested_by=OPERATOR,
                idempotency_key="audit-unknown-target",
                trace_id="b" * 32,
            )
        assert caught.value.refusal.code == "INPUT_INVALID"
        rows = audit_rows(dsn)
        assert len(rows) == 1
        assert rows[0]["targets"] == ["dns:unknown.internal.example"]
        assert rows[0]["details"]["field"] == "/input/targets/0"
        with connect(dsn) as conn:
            assert conn.execute("SELECT count(*) FROM policy_decision").fetchone() == (0,)


def test_a_policy_denial_has_a_decision_an_event_and_one_audit_row() -> None:
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn)
        jobs = service(dsn)
        with pytest.raises(M05Error) as caught:
            jobs.submit(
                body(campaign, capability="dns.not_a_capability"),
                requested_by=OPERATOR,
                idempotency_key="audit-denied",
                trace_id="c" * 32,
            )
        assert caught.value.refusal.code == "POLICY_DENIED"
        rows = audit_rows(dsn)
        assert len(rows) == 1
        assert rows[0]["details"]["code"] == "POLICY_DENIED"
        assert rows[0]["details"]["rule"] == "capability_unknown"
        assert rows[0]["trace_id"] == "c" * 32
        with connect(dsn) as conn:
            assert conn.execute("SELECT count(*) FROM policy_decision").fetchone() == (1,)
            assert conn.execute(
                "SELECT count(*) FROM outbox_event WHERE type = 'policy.denied.v2'"
            ).fetchone() == (1,)


def test_an_idempotency_conflict_is_audited_and_an_accepted_job_is_not() -> None:
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn)
        jobs = service(dsn)
        jobs.submit(body(campaign), requested_by=OPERATOR, idempotency_key="audit-accepted")
        assert audit_rows(dsn) == [], "a successful acceptance is not a refusal"

        with pytest.raises(M05Error) as caught:
            jobs.submit(
                body(campaign, priority=80),
                requested_by=OPERATOR,
                idempotency_key="audit-accepted",
                trace_id="d" * 32,
            )
        assert caught.value.refusal.code == "IDEMPOTENCY_CONFLICT"
        rows = audit_rows(dsn)
        assert len(rows) == 1
        assert rows[0]["details"]["code"] == "IDEMPOTENCY_CONFLICT"
        assert rows[0]["targets"] == [campaign.seed_domain]


def test_a_replayed_denial_is_audited_again_but_decided_once() -> None:
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn)
        jobs = service(dsn)
        request = body(campaign, capability="dns.not_a_capability")
        for attempt, trace in ((1, "e" * 32), (2, "f" * 32)):
            with pytest.raises(M05Error):
                jobs.submit(
                    request,
                    requested_by=OPERATOR,
                    idempotency_key="audit-denied-retry",
                    trace_id=trace,
                )
            assert len(audit_rows(dsn)) == attempt, "each refused request leaves its own row"
        with connect(dsn) as conn:
            assert conn.execute("SELECT count(*) FROM policy_decision").fetchone() == (1,)


def test_the_api_returns_400_and_writes_one_audit_row() -> None:
    from fastapi.testclient import TestClient

    from aegis.m26_api import jobs as jobs_api
    from aegis.m26_api.app import API_PREFIX, create_app
    from aegis.m26_api.operator import OperatorAuthenticationError, Principal
    from aegis.m26_api.registry import RouterRegistry

    class Authenticator:
        def authenticate(self, authorization: str | None) -> Principal:
            if authorization != "Bearer test-token":
                raise OperatorAuthenticationError("unknown token")
            return Principal(id=OPERATOR["id"])

    with migrated_database() as dsn:
        campaign = seed_campaign(dsn)
        routers = RouterRegistry()
        jobs_api.register(routers)
        app = create_app(routers, operator_authenticator=Authenticator())
        jobs_api.install_job_service(app, service(dsn))
        client = TestClient(app)

        response = client.post(
            f"{API_PREFIX}/jobs",
            json={
                "campaign_id": campaign.campaign_id,
                "capability": "dns.enumerate_subdomains",
                "input": {"targets": campaign.seed_domain},
                "rationale": "API refusal audit",
            },
            headers={"Authorization": "Bearer test-token", "Idempotency-Key": "audit-api-key"},
        )
        assert response.status_code == 400, response.text
        assert response.json()["code"] == "INPUT_INVALID"
        trace = response.headers["traceparent"].split("-")[1]
        rows = audit_rows(dsn)
        assert len(rows) == 1
        assert rows[0]["action"] == "job.refuse"
        assert rows[0]["trace_id"] == trace
        assert rows[0]["actor"] == {"kind": "operator", "id": OPERATOR["id"]}
        assert rows[0]["targets"] == [campaign.seed_domain]
