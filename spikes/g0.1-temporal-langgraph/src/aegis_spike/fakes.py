"""Fakes for the two external boundaries the spike must not depend on.

FakeMcpRegistry stands in for M05/M06 dispatch: it persists jobs in PostgreSQL so a
worker kill cannot erase the evidence, and `idempotency_key` is UNIQUE so a repeated
dispatch of the same logical request returns the same job id (product rule: one job).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

import psycopg


def canonical_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class FakeMcpRegistry:
    def __init__(self, conn: psycopg.AsyncConnection) -> None:
        self._conn = conn

    async def submit(
        self,
        *,
        campaign_id: str,
        capability: str,
        payload: dict[str, Any],
        idempotency_key: str,
        delay_seconds: float,
    ) -> dict[str, Any]:
        input_hash = canonical_hash(payload)
        cur = await self._conn.execute(
            """
            INSERT INTO spike.mcp_job(job_id, campaign_id, idempotency_key, capability, input_hash,
                                      status, dispatch_calls, complete_at)
            VALUES (%s, %s, %s, %s, %s, 'RUNNING', 1, now() + make_interval(secs => %s))
            ON CONFLICT (idempotency_key) DO UPDATE SET
              dispatch_calls = spike.mcp_job.dispatch_calls + 1,
              last_dispatch_at = clock_timestamp()
            RETURNING job_id::text, dispatch_calls, status, input_hash
            """,
            (str(uuid.uuid4()), campaign_id, idempotency_key, capability, input_hash, delay_seconds),
        )
        row = await cur.fetchone()
        assert row is not None
        return {"job_id": row[0], "dispatch_calls": row[1], "status": row[2], "input_hash": row[3]}

    async def status_of(self, job_id: str) -> str | None:
        # The fake scanner "finishes" once its simulated runtime has elapsed.
        await self._conn.execute(
            """
            UPDATE spike.mcp_job SET status = 'SUCCEEDED', finished_at = clock_timestamp()
            WHERE job_id = %s AND status = 'RUNNING' AND complete_at <= now()
            """,
            (job_id,),
        )
        cur = await self._conn.execute("SELECT status FROM spike.mcp_job WHERE job_id = %s", (job_id,))
        row = await cur.fetchone()
        return None if row is None else row[0]

    async def cancel_campaign(self, campaign_id: str) -> list[str]:
        cur = await self._conn.execute(
            """
            UPDATE spike.mcp_job SET status = 'CANCELLED', finished_at = clock_timestamp()
            WHERE campaign_id = %s AND status IN ('QUEUED', 'RUNNING')
            RETURNING job_id::text
            """,
            (campaign_id,),
        )
        return [row[0] for row in await cur.fetchall()]


class FakeModelClient:
    """Deterministic stand-in for M04: no API key, no network, canned structured output."""

    def __init__(self, conn: psycopg.AsyncConnection, session_id: str, attempt: int) -> None:
        self._conn = conn
        self._session_id = session_id
        self._attempt = attempt

    async def complete(self, *, node: str, messages: list[dict[str, str]]) -> dict[str, Any]:
        from . import ledger

        if node == "plan":
            out = {
                "capability": "dns.enumerate_subdomains",
                "input": {"targets": ["internal.example"], "limits": {"max_results": 100}},
                "rationale": "spike: deterministic first discovery step",
            }
        elif node == "analyze":
            out = {"decision": "complete", "summary": "fake observation accepted; no extra step needed"}
        else:  # pragma: no cover - spike has two model nodes only
            raise ValueError(f"unexpected model node {node}")
        await ledger.log_model_call(self._conn, self._session_id, self._attempt, node, 128, 64)
        return out
