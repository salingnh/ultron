"""Append-only evidence tables for the spike (schema spike.*, see deploy/spike-schema.sql)."""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

import psycopg

from . import config


@asynccontextmanager
async def connect(dsn: str | None = None) -> AsyncIterator[psycopg.AsyncConnection]:
    conn = await psycopg.AsyncConnection.connect(dsn or config.DSN, autocommit=True)
    try:
        yield conn
    finally:
        await conn.close()


async def record_event(conn: psycopg.AsyncConnection, kind: str, payload: dict[str, Any]) -> None:
    await conn.execute(
        "INSERT INTO spike.event(kind, payload) VALUES (%s, %s::jsonb)",
        (kind, json.dumps(payload, sort_keys=True)),
    )


async def log_node(conn: psycopg.AsyncConnection, session_id: str, attempt: int, node: str) -> None:
    await conn.execute(
        "INSERT INTO spike.node_log(session_id, activity_attempt, node) VALUES (%s, %s, %s)",
        (session_id, attempt, node),
    )


async def log_model_call(
    conn: psycopg.AsyncConnection, session_id: str, attempt: int, node: str, tokens_in: int, tokens_out: int
) -> None:
    await conn.execute(
        "INSERT INTO spike.model_call(session_id, attempt, node, tokens_in, tokens_out) VALUES (%s, %s, %s, %s, %s)",
        (session_id, attempt, node, tokens_in, tokens_out),
    )


async def record_workflow_run(
    conn: psycopg.AsyncConnection,
    *,
    workflow_id: str,
    run_id: str,
    first_run_id: str,
    continued_from_run_id: str | None,
    cursor_in: int,
    cycle_in: int,
) -> None:
    await conn.execute(
        """
        INSERT INTO spike.workflow_run(workflow_id, run_id, first_run_id, continued_from_run_id, cursor_in, cycle_in)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (run_id) DO NOTHING
        """,
        (workflow_id, run_id, first_run_id, continued_from_run_id, cursor_in, cycle_in),
    )


async def save_session_state(
    conn: psycopg.AsyncConnection,
    *,
    session_id: str,
    campaign_id: str,
    status: str,
    stop_reason: str | None,
    steps: int,
    cursor: int,
    attempt: int,
    result: dict[str, Any],
) -> None:
    await conn.execute(
        """
        INSERT INTO spike.session_state(session_id, campaign_id, status, stop_reason, steps, cursor, attempts, result)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb)
        ON CONFLICT (session_id) DO UPDATE SET
          status = EXCLUDED.status,
          stop_reason = EXCLUDED.stop_reason,
          steps = EXCLUDED.steps,
          cursor = EXCLUDED.cursor,
          attempts = GREATEST(spike.session_state.attempts, EXCLUDED.attempts),
          result = EXCLUDED.result,
          updated_at = clock_timestamp()
        """,
        (session_id, campaign_id, status, stop_reason, steps, cursor, attempt, json.dumps(result, sort_keys=True)),
    )
