"""Ready-job query prototype against the real contract DDL (aegis.scan_job/job_dependency)."""

from __future__ import annotations

import json
import statistics
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aegis_spike import ready

from . import fixtures

EVIDENCE = Path(__file__).resolve().parents[1] / "evidence"


async def test_ready_order_priority_dependency_and_failed_predecessor(db):
    campaign = await fixtures.create_campaign(db)
    cid = campaign["campaign_id"]
    t0 = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)

    pred = await fixtures.create_job(db, campaign, label="pred", priority=90, created_at=t0)
    blocked = await fixtures.create_job(db, campaign, label="blocked", priority=100, created_at=t0 + timedelta(seconds=1))
    await fixtures.add_dependency(db, cid, blocked, pred)
    low = await fixtures.create_job(db, campaign, label="low", priority=10, created_at=t0 + timedelta(seconds=2))
    mid = await fixtures.create_job(db, campaign, label="mid", priority=50, created_at=t0 + timedelta(seconds=3))
    high_later = await fixtures.create_job(
        db, campaign, label="high_later", priority=100, created_at=t0 + timedelta(seconds=4)
    )
    # same priority + same created_at: job_id ASC is the final tie-break
    tie_a = await fixtures.create_job(db, campaign, label="tie_a", priority=60, created_at=t0 + timedelta(seconds=5))
    tie_b = await fixtures.create_job(db, campaign, label="tie_b", priority=60, created_at=t0 + timedelta(seconds=5))

    ready_now = await ready.ready_jobs(db, cid)
    tie_first, tie_second = sorted([tie_a, tie_b])
    assert [r["job_id"] for r in ready_now] == [high_later, pred, tie_first, tie_second, mid, low], (
        "priority DESC, created_at ASC, job_id ASC; a QUEUED dependency blocks the higher-priority job"
    )
    assert blocked not in [r["job_id"] for r in ready_now]
    assert pred in [r["job_id"] for r in ready_now]

    waiting = {w["job_id"]: w["wait_reason"] for w in await ready.waiting_jobs(db, cid)}
    assert waiting[blocked] == "dependency_pending"

    # Only SUCCEEDED releases the dependent job; it then sorts first (priority 100, earliest created_at).
    await fixtures.set_job_status(db, pred, "SUCCEEDED")
    ready_after = [r["job_id"] for r in await ready.ready_jobs(db, cid)]
    # blocked (priority 100, created before high_later) is released and sorts first;
    # the SUCCEEDED predecessor leaves the ready set.
    assert ready_after[:2] == [blocked, high_later]
    assert pred not in ready_after
    assert blocked not in [w["job_id"] for w in await ready.waiting_jobs(db, cid)]

    # A failed predecessor leaves the dependent waiting with a reason, never dispatched.
    failed_pred = await fixtures.create_job(db, campaign, label="failed_pred", priority=100, created_at=t0)
    orphan = await fixtures.create_job(db, campaign, label="orphan", priority=100, created_at=t0 + timedelta(seconds=6))
    await fixtures.add_dependency(db, cid, orphan, failed_pred)
    await fixtures.set_job_status(db, failed_pred, "FAILED")
    canceled_pred = await fixtures.create_job(db, campaign, label="canceled_pred", priority=100, created_at=t0)
    canceled_child = await fixtures.create_job(
        db, campaign, label="canceled_child", priority=100, created_at=t0 + timedelta(seconds=7)
    )
    await fixtures.add_dependency(db, cid, canceled_child, canceled_pred)
    await fixtures.set_job_status(db, canceled_pred, "CANCELLED")

    waiting = {w["job_id"]: w["wait_reason"] for w in await ready.waiting_jobs(db, cid)}
    assert waiting[orphan] == "dependency_failed"
    assert waiting[canceled_child] == "dependency_cancelled"
    ready_ids = [r["job_id"] for r in await ready.ready_jobs(db, cid, limit=100)]
    assert orphan not in ready_ids and canceled_child not in ready_ids

    # Limit + ordering stay stable when the caller only asks for the next dispatch slots.
    assert [r["job_id"] for r in await ready.ready_jobs(db, cid, limit=2)] == ready_ids[:2]


async def test_ready_query_latency_with_backlog(db):
    """Scheduling-gate number: ready query on a campaign with a realistic backlog."""
    campaign = await fixtures.create_campaign(db)
    cid = campaign["campaign_id"]
    await db.execute(
        """
        INSERT INTO aegis.policy_decision(decision_id, campaign_id, capability, targets, input, decision, rationale,
                                          requested_by, policy_version, scope_id, idempotency_key, trace_id)
        SELECT gen_random_uuid(), %(cid)s, 'dns.enumerate_subdomains', '{dns:internal.example}', '{}', 'approved',
               'bulk seed', '{"kind":"agent","id":"g01-spike"}', %(pv)s, %(scope)s, 'bulk:' || g, repeat('0', 32)
        FROM generate_series(1, 5000) g
        """,
        {"cid": cid, "pv": campaign["policy_version"], "scope": campaign["scope_id"]},
    )
    await db.execute(
        """
        INSERT INTO aegis.scan_job(job_id, campaign_id, decision_id, capability, provider, provider_version,
                                   adapter_version, image_digest, manifest_sha256, scan_cycle, job_fingerprint,
                                   policy_version, scope_id, priority, input, targets, requested_by, rationale,
                                   trace_id, created_at)
        SELECT gen_random_uuid(), %(cid)s, d.decision_id, 'dns.enumerate_subdomains', 'subfinder', 'v2.6.6', '1.0.0',
               'sha256:' || repeat('a', 64), repeat('b', 64), gen_random_uuid(),
               md5(%(cid)s || ':' || g::text) || md5(%(cid)s || ':' || (g + 1)::text), %(pv)s, %(scope)s, (g %% 100), '{}', '{dns:internal.example}',
               '{"kind":"agent","id":"g01-spike"}', 'bulk seed', repeat('0', 32), now() - (g || ' seconds')::interval
        FROM generate_series(1, 5000) g
        JOIN aegis.policy_decision d ON d.campaign_id = %(cid)s AND d.idempotency_key = 'bulk:' || g
        """,
        {"cid": cid, "pv": campaign["policy_version"], "scope": campaign["scope_id"]},
    )
    # 10% of the backlog depends on the oldest job: 4500 dispatchable, 500 held by a dependency.
    await db.execute(
        """
        INSERT INTO aegis.job_dependency(campaign_id, job_id, depends_on_job_id)
        SELECT %(cid)s, j.job_id, p.job_id
        FROM (SELECT job_id, row_number() OVER (ORDER BY created_at) rn
              FROM aegis.scan_job WHERE campaign_id = %(cid)s) j
        JOIN (SELECT job_id FROM aegis.scan_job WHERE campaign_id = %(cid)s ORDER BY created_at ASC LIMIT 1) p ON true
        WHERE j.rn %% 10 = 0
        """,
        {"cid": cid},
    )
    await db.execute("ANALYZE aegis.scan_job")
    await db.execute("ANALYZE aegis.job_dependency")
    cur = await db.execute(
        "SELECT count(*) FROM aegis.scan_job WHERE campaign_id = %s AND status = 'QUEUED'", (cid,)
    )
    backlog = (await cur.fetchone())[0]
    assert backlog == 5000

    timings: list[float] = []
    rows: list[dict] = []
    for _ in range(40):
        started = time.perf_counter()
        rows = await ready.ready_jobs(db, cid, limit=32)
        timings.append((time.perf_counter() - started) * 1000)
    plan = await ready.explain_ready_jobs(db, cid, limit=32)
    plan_json = plan[0]["QUERY PLAN"][0]

    assert len(rows) == 32
    assert rows == sorted(rows, key=lambda r: (-r["priority"], r["created_at"], r["job_id"]))
    p50 = statistics.median(timings)
    p95 = sorted(timings)[int(len(timings) * 0.95) - 1]

    EVIDENCE.mkdir(exist_ok=True)
    (EVIDENCE / "ready-query.json").write_text(
        json.dumps(
            {
                "backlog_jobs": backlog,
                "limit": 32,
                "iterations": len(timings),
                "p50_ms": round(p50, 2),
                "p95_ms": round(p95, 2),
                "max_ms": round(max(timings), 2),
                "plan_node_types": list(_node_types(plan_json["Plan"])),
                "plan_execution_ms": round(plan_json["Execution Time"], 3),
                "index_scan_used": "scan_job_ready_order" in json.dumps(plan_json),
                "full_plan": plan_json["Plan"],
            },
            indent=2,
        )
    )
    assert p95 < 100, f"ready query p95 {p95:.1f} ms on a {backlog}-job backlog"


def _node_types(node: dict):
    yield node.get("Node Type")
    for child in node.get("Plans", []) or []:
        yield from _node_types(child)
