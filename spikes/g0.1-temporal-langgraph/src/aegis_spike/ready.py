"""Prototype of the M02 ready-job query (the G0 "scheduling" gate evidence).

Runs against the real contract migrations (aegis.scan_job, aegis.job_dependency from
0001/0002/0003), not a spike-only copy:

  * ready   = QUEUED, manifest pinned, every dependency SUCCEEDED
  * order   = priority DESC, created_at ASC, job_id ASC   (02-nen-tang.md §Điều phối)
  * waiting = jobs kept back, with a reason (contract gap X-4: "job wait reason")

Only SUCCEEDED releases a dependent job; FAILED/CANCELLED leave it waiting with a
reason instead of silently dropping the dependency.
"""

from __future__ import annotations

from typing import Any

import psycopg
from psycopg.rows import dict_row

READY_JOBS_SQL = """
SELECT j.job_id::text AS job_id,
       j.priority,
       j.created_at
FROM aegis.scan_job j
WHERE j.campaign_id = %(campaign_id)s
  AND j.status = 'QUEUED'
  AND j.manifest_sha256 IS NOT NULL
  AND NOT EXISTS (
      SELECT 1
      FROM aegis.job_dependency d
      JOIN aegis.scan_job p
        ON p.job_id = d.depends_on_job_id
       AND p.campaign_id = d.campaign_id
      WHERE d.job_id = j.job_id
        AND p.status <> 'SUCCEEDED'
  )
ORDER BY j.priority DESC, j.created_at ASC, j.job_id ASC
LIMIT %(limit)s
"""

WAITING_JOBS_SQL = """
WITH candidates AS (
SELECT j.job_id::text AS job_id,
       j.priority,
       j.created_at,
       CASE
         WHEN j.manifest_sha256 IS NULL THEN 'manifest_unpinned'
         WHEN EXISTS (
           SELECT 1 FROM aegis.job_dependency d
           JOIN aegis.scan_job p ON p.job_id = d.depends_on_job_id
           WHERE d.job_id = j.job_id AND p.status = 'FAILED'
         ) THEN 'dependency_failed'
         WHEN EXISTS (
           SELECT 1 FROM aegis.job_dependency d
           JOIN aegis.scan_job p ON p.job_id = d.depends_on_job_id
           WHERE d.job_id = j.job_id AND p.status = 'CANCELLED'
         ) THEN 'dependency_cancelled'
         WHEN EXISTS (
           SELECT 1 FROM aegis.job_dependency d
           JOIN aegis.scan_job p ON p.job_id = d.depends_on_job_id
           WHERE d.job_id = j.job_id
             AND p.status NOT IN ('SUCCEEDED', 'FAILED', 'CANCELLED')
         ) THEN 'dependency_pending'
         ELSE 'none'
       END AS wait_reason
FROM aegis.scan_job j
WHERE j.campaign_id = %(campaign_id)s
  AND j.status = 'QUEUED'
)
SELECT job_id, priority, created_at, wait_reason
FROM candidates
WHERE wait_reason <> 'none'
ORDER BY priority DESC, created_at ASC, job_id ASC
"""


async def ready_jobs(
    conn: psycopg.AsyncConnection, campaign_id: str, limit: int = 32
) -> list[dict[str, Any]]:
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(READY_JOBS_SQL, {"campaign_id": campaign_id, "limit": limit})
        return list(await cur.fetchall())


async def waiting_jobs(conn: psycopg.AsyncConnection, campaign_id: str) -> list[dict[str, Any]]:
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(WAITING_JOBS_SQL, {"campaign_id": campaign_id})
        return list(await cur.fetchall())


async def explain_ready_jobs(
    conn: psycopg.AsyncConnection, campaign_id: str, limit: int = 32
) -> list[dict[str, Any]]:
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(f"EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {READY_JOBS_SQL}", {"campaign_id": campaign_id, "limit": limit})
        return list(await cur.fetchall())
