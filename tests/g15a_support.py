"""Shared G1.5a fixtures: a started campaign, its rows, outbox events and the app under test.

The campaign is created and started through M01's real write path (name, policy snapshot, seeds,
status history and `started_at` are the ones the API produces), and the jobs through M05's
acceptance path, so read-model and stream tests never run against hand-shaped rows.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import psycopg
from fastapi import FastAPI
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from aegis.m01_campaign.campaigns import create_campaign, timestamp
from aegis.m01_campaign.status import apply_workflow_action
from aegis.m05_registry.ids import uuid7
from aegis.m26_api import events, flow
from aegis.m26_api.app import create_app
from aegis.m26_api.campaigns import register as register_campaigns
from aegis.m26_api.jobs import register as register_jobs
from aegis.m26_api.operator import TokenAuthenticator
from aegis.m26_api.registry import RouterRegistry
from tests import campaign_support as support
from tests.db_support import OPERATOR, SeededCampaign
from tests.m02_support import accept_job
from tests.test_m05_service import service

__all__ = [
    "accept_jobs",
    "seed_events",
    "api_app",
    "emit_event",
    "job_started_payload",
    "job_completed_payload",
    "open_campaign",
    "session_with_decision",
]

MODULE_ACTOR = {"kind": "module", "id": "M02"}


def open_campaign(dsn: str, *, name: str = "G1.5a campaign") -> SeededCampaign:
    """M01 create + M02 start: the campaign row, snapshot, seeds and history the API makes."""
    with psycopg.connect(dsn, row_factory=dict_row) as conn, conn.transaction():
        created = create_campaign(
            conn,
            body=support.campaign_body(name=name),
            actor=OPERATOR,
            trace_id=uuid7().replace("-", "")[:32],
        ).as_response()
        apply_workflow_action(
            conn,
            campaign_id=created["campaign_id"],
            action="start",
            reason="G1.5a test campaign",
            actor=MODULE_ACTOR,
            trace_id=uuid7().replace("-", "")[:32],
        )
    return SeededCampaign(
        campaign_id=created["campaign_id"],
        policy_version=created["policy_version"],
        scope_id=created["scope_id"],
        seed_domain="internal.example",
        seed_ip="10.114.53.53",
        known_asset="",
    )


def seed_events(dsn: str, campaign_id: str) -> list[int]:
    """The publication sequence of the campaign's own seed events, in order.

    M01 publishes one `asset.discovered.v2` per identity-bearing seed target in the campaign
    transaction (`revision` 0), so a campaign's stream starts with those before any job event. A
    test that begins its own stream reads them first (`tests/test_events_stream.py`) instead of
    assuming an empty history.
    """
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        rows = conn.execute(
            "SELECT seq FROM aegis.outbox_event"
            " WHERE campaign_id = %s AND type = 'asset.discovered.v2'"
            "   AND coalesce((payload->>'revision')::bigint, 0) = 0"
            " ORDER BY seq",
            (campaign_id,),
        ).fetchall()
    return [int(row["seq"]) for row in rows]


def accept_jobs(dsn: str, campaign: SeededCampaign, count: int = 1) -> list[dict[str, Any]]:
    """Jobs accepted by the real M05 path; returns the job.v2 documents in creation order."""
    accepted: list[dict[str, Any]] = []
    with service(dsn) as jobs_service:
        for _ in range(count):
            job_id = accept_job(jobs_service, campaign)
            accepted.append(jobs_service.get_job(job_id))
    return accepted


def session_with_decision(dsn: str, campaign: SeededCampaign) -> tuple[str, str]:
    """An M03-style session and the decision it proposed (no module writes this shape yet)."""
    session_id, objective_id, decision_id = uuid7(), uuid7(), uuid7()
    with psycopg.connect(dsn, row_factory=dict_row) as conn, conn.transaction():
        seed = conn.execute(
            "SELECT target_id::text FROM campaign_target WHERE scope_id = %s AND raw_value = %s",
            (campaign.scope_id, campaign.seed_domain),
        ).fetchone()
        assert seed is not None
        conn.execute(
            "INSERT INTO objective (objective_id, campaign_id, text, created_by) "
            "VALUES (%s, %s, %s, %s)",
            (objective_id, campaign.campaign_id, "enumerate the lab zone", Jsonb(OPERATOR)),
        )
        conn.execute(
            "INSERT INTO agent_session (session_id, campaign_id, objective_id, policy_version, "
            "revision_from, status) VALUES (%s, %s, %s, %s, 0, 'RUNNING')",
            (session_id, campaign.campaign_id, objective_id, campaign.policy_version),
        )
        conn.execute(
            "INSERT INTO policy_decision (decision_id, campaign_id, session_id, capability, "
            "targets, target_refs, input, decision, rationale, requested_by, proposed_by, "
            "policy_version, scope_id, idempotency_key, trace_id) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, 'approved', %s, %s, %s, %s, %s, %s, %s)",
            (
                decision_id,
                campaign.campaign_id,
                session_id,
                "dns.enumerate_subdomains",
                [],
                Jsonb([{"seed_id": seed["target_id"]}]),
                Jsonb({"targets": [campaign.seed_domain]}),
                "the session proposed a subdomain enumeration",
                Jsonb(OPERATOR),
                Jsonb({"kind": "agent", "id": session_id}),
                campaign.policy_version,
                campaign.scope_id,
                f"session-{decision_id}",
                uuid7().replace("-", "")[:32],
            ),
        )
    return session_id, decision_id


def emit_event(
    dsn: str,
    *,
    campaign_id: str,
    event_type: str,
    dedup_key: str,
    payload: dict[str, Any],
    producer: str = "M06",
    connection: psycopg.Connection[Any] | None = None,
) -> int:
    """Write one outbox event the way a producer does (the seq comes from the 0008 trigger)."""
    trace = {"trace_id": uuid7().replace("-", "")[:32], "campaign_id": campaign_id}
    if connection is not None:
        return _insert_event(
            connection, campaign_id, event_type, dedup_key, payload, producer, trace
        )
    with psycopg.connect(dsn) as conn, conn.transaction():
        return _insert_event(conn, campaign_id, event_type, dedup_key, payload, producer, trace)


def _insert_event(
    conn: psycopg.Connection[Any],
    campaign_id: str,
    event_type: str,
    dedup_key: str,
    payload: dict[str, Any],
    producer: str,
    trace: dict[str, Any],
) -> int:
    row = conn.execute(
        "INSERT INTO outbox_event (event_id, type, producer, dedup_key, campaign_id, payload, "
        "trace) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING seq",
        (uuid7(), event_type, producer, dedup_key, campaign_id, Jsonb(payload), Jsonb(trace)),
    ).fetchone()
    assert row is not None
    return int(row[0])


def job_started_payload(job: dict[str, Any]) -> dict[str, Any]:
    """`job.started.v2` from a job.v2 document (M06 is the producer of this event)."""
    return {
        "job_id": job["job_id"],
        "campaign_id": job["campaign_id"],
        "capability": job["capability"],
        "provider": job["provider"],
        "provider_version": job["provider_version"],
        "policy_version": job["policy_version"],
        "scope_id": job["scope_id"],
        "started_at": timestamp(datetime.now(UTC)),
        "attempt": job["attempt"],
        "generation": job["generation"],
    }


def job_completed_payload(job: dict[str, Any], status: str) -> dict[str, Any]:
    """`job.completed.v2` from a job.v2 document and the terminal status M06 recorded."""
    return {
        "job_id": job["job_id"],
        "campaign_id": job["campaign_id"],
        "status": status,
        "evidence_refs": [],
        "finished_at": timestamp(datetime.now(UTC)),
        "attempt": job["attempt"],
        "generation": job["generation"],
    }


def api_app(dsn: str) -> FastAPI:
    """The M26 app with the campaign/jobs/flow/events routers, as `main.build_registry` mounts."""
    registry = RouterRegistry()
    register_campaigns(registry)
    register_jobs(registry)
    flow.register(registry)
    events.register(registry)
    app: FastAPI = create_app(
        registry,
        operator_authenticator=TokenAuthenticator(support.operator_tokens()),
        database_dsn=dsn,
    )
    return app
