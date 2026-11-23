"""Insert rows into the real contract schema (aegis.*) for the ready-job query tests."""

from __future__ import annotations

import uuid
from datetime import datetime

import psycopg


async def create_campaign(conn: psycopg.AsyncConnection) -> dict[str, str]:
    campaign_id = str(uuid.uuid4())
    scope_id = str(uuid.uuid4())
    async with conn.transaction():
        cur = await conn.execute("SELECT 'roe-' || nextval('aegis.policy_version_seq')")
        row = await cur.fetchone()
        assert row is not None
        policy_version = row[0]
        await conn.execute(
            """
            INSERT INTO aegis.campaign(campaign_id, name, objective, status, current_policy_version, scope_id, created_by)
            VALUES (%s, 'G0.1 ready-query fixture', 'scheduling spike', 'RUNNING', %s, %s,
                    '{"kind":"agent","id":"g01-spike"}')
            """,
            (campaign_id, policy_version, scope_id),
        )
        await conn.execute(
            """
            INSERT INTO aegis.policy_snapshot(policy_version, campaign_id, policy, policy_hash, created_by)
            VALUES (%s, %s, '{"max_parallel_jobs":4}', %s, '{"kind":"operator","id":"g01-spike"}')
            """,
            (policy_version, campaign_id, "a" * 64),
        )
        await conn.execute(
            """
            INSERT INTO aegis.scope_snapshot(scope_id, campaign_id, targets)
            VALUES (%s, %s, '{"domains":["internal.example"]}')
            """,
            (scope_id, campaign_id),
        )
    return {"campaign_id": campaign_id, "policy_version": policy_version, "scope_id": scope_id}


async def create_decision(conn: psycopg.AsyncConnection, campaign: dict[str, str], label: str) -> str:
    decision_id = str(uuid.uuid4())
    await conn.execute(
        """
        INSERT INTO aegis.policy_decision(decision_id, campaign_id, capability, provider, targets, input, decision,
                                          rationale, requested_by, policy_version, scope_id, idempotency_key, trace_id)
        VALUES (%s, %s, 'dns.enumerate_subdomains', 'subfinder', '{dns:internal.example}',
                '{"targets":["internal.example"]}', 'approved', 'g0.1 fixture',
                '{"kind":"agent","id":"g01-spike"}', %s, %s, %s, repeat('0', 32))
        """,
        (decision_id, campaign["campaign_id"], campaign["policy_version"], campaign["scope_id"], f"g01:{label}"),
    )
    return decision_id


async def create_job(
    conn: psycopg.AsyncConnection,
    campaign: dict[str, str],
    *,
    label: str,
    priority: int = 50,
    created_at: datetime | None = None,
    manifest_sha256: str | None = "b" * 64,
) -> str:
    job_id = str(uuid.uuid4())
    decision_id = await create_decision(conn, campaign, f"{label}:{job_id}")
    await conn.execute(
        """
        INSERT INTO aegis.scan_job(job_id, campaign_id, decision_id, capability, provider, provider_version,
                                   adapter_version, image_digest, manifest_sha256, scan_cycle, job_fingerprint,
                                   policy_version, scope_id, priority, input, targets, requested_by, rationale,
                                   trace_id, created_at)
        VALUES (%s, %s, %s, 'dns.enumerate_subdomains', 'subfinder', 'v2.6.6', '1.0.0',
                'sha256:' || repeat('a', 64), %s, %s, %s, %s, %s, %s, '{}', '{dns:internal.example}',
                '{"kind":"agent","id":"g01-spike"}', 'g0.1 fixture', repeat('0', 32),
                COALESCE(%s, now()))
        """,
        (
            job_id,
            campaign["campaign_id"],
            decision_id,
            manifest_sha256,
            str(uuid.uuid4()),
            "".join(ch for ch in job_id.replace("-", "")).ljust(64, "0")[:64],
            campaign["policy_version"],
            campaign["scope_id"],
            priority,
            created_at,
        ),
    )
    return job_id


async def add_dependency(conn: psycopg.AsyncConnection, campaign_id: str, job_id: str, depends_on_job_id: str) -> None:
    await conn.execute(
        "INSERT INTO aegis.job_dependency(campaign_id, job_id, depends_on_job_id) VALUES (%s, %s, %s)",
        (campaign_id, job_id, depends_on_job_id),
    )


async def set_job_status(conn: psycopg.AsyncConnection, job_id: str, status: str) -> None:
    # 0001: CHECK (status <> 'FAILED' OR error IS NOT NULL)
    error = '{"code": "G01_FIXTURE", "message": "fixture failure"}' if status == "FAILED" else None
    await conn.execute(
        "UPDATE aegis.scan_job SET status = %s, error = %s WHERE job_id = %s", (status, error, job_id)
    )
