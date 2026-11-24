"""`/api/v2/campaigns/{campaign_id}/events` - the campaign event stream (G1.5a).

One operation, two encodings (contract `streamCampaignEvents`):

* `Accept: text/event-stream` -> Server-Sent Events. Every message is
  `id: <outbox seq>`, `event: <type>`, `data: <EventEnvelope v2 JSON>`; `event: heartbeat` every
  15 seconds; a client resumes with the `Last-Event-ID` header.
* anything else -> the same events as a JSON page `{items, next_cursor}`
  (`cursor`, `limit`, `types`).

Reading rules - the S1.3 publication algorithm (0008) with the 0013 refresh, not a second one:

1. this service is its own consumer, `m26-sse`, and its own dispatcher generation, `m26-sse#g1`
   (`consumer_name()`). It never shares `m02-campaign-signals` or `m23-projector`, and a rebuild
   starts a new generation instead of reusing one. The generation is taken by the stream from the
   resume point it validates: an `id` above the outbox's published head comes from another event
   log (a rebuilt or different database) and is refused, never silently honoured or skipped;
2. before reading, the dispatcher lease of this generation is taken/renewed and the publication
   watermark advanced with `aegis.outbox_watermark_refresh` (0013 waits for in-flight writers), in
   its own short statement, so no reader can cross a sequence that is still uncommitted (D25);
3. events are read strictly `seq > client checkpoint AND seq <= watermark`, in seq order, so a
   reconnect with `Last-Event-ID = n` sees every event after `n` exactly once: nothing is lost to a
   late commit and nothing is sent twice;
4. the endpoint never writes a cursor. A stream is a read: `consumer_cursor`/`consumer_inbox` belong
   to stateful consumers, and a shared cursor would make one UI client hide another's history.
   The client's `Last-Event-ID` is the position, which is why several clients can watch one
   campaign and a reconnecting one continues exactly where it stopped.

Latency: an idle poll is 250 ms and the watermark is refreshed every 500 ms, so a producer's
committed event reaches a connected client in well under 2 s (`POLL_SECONDS`, `REFRESH_SECONDS`).

Deployment note: `aegis.outbox_dispatch_lease`/`aegis.outbox_watermark_refresh` are granted to the
`aegis_outbox_dispatcher` group role, so the API's database user must hold it (or be the schema
owner, as in the dev stack and tests). Without it the endpoint answers 503 `DEPENDENCY_MISSING`
instead of streaming an empty history forever.

Authorisation: the contract publishes no `security` for this operation (unlike the seven G1.1b
campaign operations), so the route matches the contract and stays open inside the private
ingress/VPN perimeter; see `flow.py` and the G1.5a report for the contract gap.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import time
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from functools import partial
from typing import Annotated, Any

import psycopg
from anyio import to_thread
from fastapi import APIRouter, Header, Query, Request, Response
from fastapi.responses import StreamingResponse
from psycopg.rows import dict_row

from aegis import validation
from aegis.contracts_gen.events.event_envelope_v2_schema import Type as EventType
from aegis.m01_campaign.campaigns import timestamp
from aegis.m26_api.db import database_dsn_of
from aegis.m26_api.errors import INPUT_INVALID, ApiError
from aegis.m26_api.registry import RouterRegistry
from aegis.m26_api.tracing import TRACEPARENT_HEADER, current_trace_id, traceparent

__all__ = [
    "EVENTS_OPERATIONS",
    "HEARTBEAT_SECONDS",
    "POLL_SECONDS",
    "REFRESH_SECONDS",
    "STREAM_CONSUMER",
    "STREAM_GENERATION",
    "consumer_name",
    "register",
    "router",
]

#: Operations this router implements; the conformance test compares it with the contract.
EVENTS_OPERATIONS = ("streamCampaignEvents",)

API_PREFIX = "/api/v2"
ID_REFERENCE = "common/ids.v2.schema.json#/$defs/Id"

#: This service's own consumer identity; a rebuild bumps the generation instead of reusing a name.
STREAM_CONSUMER = "m26-sse"
STREAM_GENERATION = 1

#: Contract: `event: heartbeat` every 15 seconds (`HEARTBEAT_SECONDS` is that number, not a hint).
HEARTBEAT_SECONDS = 15.0
#: Idle poll and watermark refresh cadence; together they bound delivery latency below 1 s.
POLL_SECONDS = 0.25
REFRESH_SECONDS = 0.5
#: Lease bounds of this stream's dispatcher generation (`aegis.outbox_dispatch_lease`).
LEASE_TTL_SECONDS = 60
BATCH_SIZE = 200

EVENT_TYPES = frozenset(member.value for member in EventType)

_SSE = "text/event-stream"
_SSE_HEADERS = {
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    # nginx buffers a proxied response by default, which would hold events back.
    "X-Accel-Buffering": "no",
}

#: One holder per process: every stream of this process renews the same lease instead of queueing
#: behind its own previous holder for the whole TTL.
_HOLDER = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"

#: Refresh failures that mean "retry on a fresh transaction" (0013) rather than "deployment broken".
_REFRESH_RETRY = (
    psycopg.errors.LockNotAvailable,
    psycopg.errors.ObjectNotInPrerequisiteState,
)

router = APIRouter(tags=["campaigns"])


# --------------------------------------------------------------------------- helpers


def consumer_name(generation: int = STREAM_GENERATION) -> str:
    """The consumer/dispatcher generation of this stream (`m26-sse#g1`)."""
    return f"{STREAM_CONSUMER}#g{generation}"


def _is_id(value: str) -> bool:
    return not validation.errors(ID_REFERENCE, value)


def _trace(request: Request, response: Response) -> str:
    trace_id = current_trace_id(request)
    response.headers[TRACEPARENT_HEADER] = traceparent(trace_id)
    return trace_id


def _not_found(campaign_id: str) -> ApiError:
    return ApiError(
        404,
        INPUT_INVALID,
        f"campaign {campaign_id} does not exist",
        next_action="FIX_INPUT",
    )


def _bad(field: str, message: str) -> ApiError:
    return ApiError(400, INPUT_INVALID, message, next_action="FIX_INPUT", field=field)


def _connect(dsn: str) -> psycopg.Connection[Any]:
    """A connection for this stream: autocommit, contract search_path, dict rows."""
    connection = psycopg.connect(dsn, row_factory=dict_row, autocommit=True)
    connection.execute("SET search_path = aegis, public")
    return connection


# --------------------------------------------------------------------------- outbox reads


def _campaign_exists(connection: psycopg.Connection[Any], campaign_id: str) -> bool:
    row = connection.execute(
        "SELECT 1 AS present FROM aegis.campaign WHERE campaign_id = %s", (campaign_id,)
    ).fetchone()
    return row is not None


def _head(connection: psycopg.Connection[Any]) -> int:
    """Highest committed publication sequence: the generation a resume point must belong to."""
    row = connection.execute(
        "SELECT coalesce(max(seq), 0) AS head FROM aegis.outbox_event"
    ).fetchone()
    return 0 if row is None else int(row["head"])


def _watermark(connection: psycopg.Connection[Any]) -> int:
    row = connection.execute("SELECT published_upto FROM aegis.outbox_watermark").fetchone()
    return 0 if row is None else int(row["published_upto"])


def _refresh_watermark(
    connection: psycopg.Connection[Any], *, name: str, holder: str
) -> int | None:
    """Advance the publication watermark under this generation's lease; None when another holds it.

    Both calls are the 0008/0013 API and stay in their own short statements: the exclusive
    publication lock of the refresh is transaction-scoped and must not cover a read, a sleep or a
    client write.
    """
    row = connection.execute(
        "SELECT aegis.outbox_dispatch_lease(%s, %s, %s) AS fence",
        (name, holder, LEASE_TTL_SECONDS),
    ).fetchone()
    fence = None if row is None else row["fence"]
    if fence is None:
        return None
    connection.execute("SELECT aegis.outbox_watermark_refresh(%s, %s)", (name, int(fence)))
    return int(fence)


def _refresh_quietly(connection: psycopg.Connection[Any], *, name: str, holder: str) -> None:
    """Refresh from the stream loop: a contention timeout is retried on the next tick (0013)."""
    try:
        _refresh_watermark(connection, name=name, holder=holder)
    except _REFRESH_RETRY:
        return


def _events_after(
    connection: psycopg.Connection[Any],
    *,
    campaign_id: str,
    after: int,
    limit: int,
    types: tuple[str, ...] | None,
) -> list[dict[str, Any]]:
    """Published events of one campaign after `after`, never past the watermark (D25)."""
    rows = connection.execute(
        """
        SELECT seq, event_id, type, producer, dedup_key, campaign_id, payload, trace, occurred_at
          FROM aegis.outbox_event
         WHERE campaign_id = %(campaign)s
           AND seq > %(after)s
           AND seq <= %(watermark)s
           AND (%(types)s::text[] IS NULL OR type = ANY(%(types)s::text[]))
         ORDER BY seq
         LIMIT %(limit)s
        """,
        {
            "campaign": campaign_id,
            "after": after,
            "watermark": _watermark(connection),
            "types": None if types is None else list(types),
            "limit": limit,
        },
    ).fetchall()
    return [dict(row) for row in rows]


def _envelope(row: dict[str, Any]) -> dict[str, Any]:
    """EventEnvelope v2 exactly as `contracts/events/event-envelope.v2.schema.json` defines it."""
    return {
        "event_id": str(row["event_id"]),
        "type": row["type"],
        "occurred_at": timestamp(row["occurred_at"]),
        "producer": row["producer"],
        "dedup_key": row["dedup_key"],
        "trace": row["trace"],
        "payload": row["payload"],
    }


# --------------------------------------------------------------------------- request parsing


def _resume_point(value: str | None, *, field: str, head: int) -> int:
    """The client's publication checkpoint; a point this outbox cannot have is refused loudly."""
    if value is None or value.strip() == "":
        return 0
    text = value.strip()
    try:
        point = int(text)
    except ValueError as error:
        raise _bad(
            field, "a resume point must be the outbox sequence this stream published"
        ) from error
    if point < 0:
        raise _bad(field, "a resume point must not be negative")
    if point > head:
        raise _bad(
            field,
            f"resume point {point} is beyond this outbox's published head {head}: it belongs to "
            "another event-log generation, so it cannot be resumed; start a new stream",
        )
    return point


def _event_types(raw: str | None) -> tuple[str, ...] | None:
    """`types` is `style: form, explode: false` (one comma-separated parameter)."""
    if raw is None or raw.strip() == "":
        return None
    values: list[str] = []
    for value in raw.split(","):
        name = value.strip()
        if name and name not in values:
            values.append(name)
    unknown = sorted(set(values) - EVENT_TYPES)
    if unknown:
        raise _bad("/types", f"unknown event type(s): {', '.join(unknown)}")
    return tuple(values)


# --------------------------------------------------------------------------- SSE encoding


def _frame(seq: int, event_type: str, data: dict[str, Any]) -> str:
    body = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    return f"id: {seq}\nevent: {event_type}\ndata: {body}\n\n"


def _heartbeat() -> str:
    return f"event: heartbeat\ndata: {json.dumps({'at': timestamp(datetime.now(UTC))})}\n\n"


async def _stream(
    *,
    dsn: str,
    campaign_id: str,
    after: int,
    types: tuple[str, ...] | None,
    name: str,
    holder: str,
) -> AsyncIterator[str]:
    """Drain from `after` until the client goes away; every yield is one complete SSE message."""
    connection = await to_thread.run_sync(_connect, dsn)
    try:
        # A comment flushes the response head at once: the client sees the stream is open instead
        # of waiting for the first heartbeat, and the identity of the generation is visible.
        yield f": {name} ready\n\n"
        checkpoint = after
        next_refresh = time.monotonic() + REFRESH_SECONDS
        next_heartbeat = time.monotonic() + HEARTBEAT_SECONDS
        while True:
            now = time.monotonic()
            if now >= next_refresh:
                await to_thread.run_sync(
                    partial(_refresh_quietly, connection, name=name, holder=holder)
                )
                next_refresh = now + REFRESH_SECONDS
            rows = await to_thread.run_sync(
                partial(
                    _events_after,
                    connection,
                    campaign_id=campaign_id,
                    after=checkpoint,
                    limit=BATCH_SIZE,
                    types=types,
                )
            )
            for row in rows:
                checkpoint = int(row["seq"])
                yield _frame(checkpoint, str(row["type"]), _envelope(row))
            now = time.monotonic()
            if now >= next_heartbeat:
                yield _heartbeat()
                next_heartbeat = now + HEARTBEAT_SECONDS
            # A drained batch is followed by the next read at once; an idle one waits for a poll.
            await asyncio.sleep(0 if rows else POLL_SECONDS)
    finally:
        await to_thread.run_sync(connection.close)


# --------------------------------------------------------------------------- routes


@router.get(
    "/campaigns/{campaign_id}/events",
    operation_id="streamCampaignEvents",
    response_model=None,
    summary=(
        "Dòng thời gian; SSE khi Accept text/event-stream, JSON phân trang khi Accept "
        "application/json"
    ),
)
def stream_campaign_events(
    request: Request,
    response: Response,
    campaign_id: str,
    last_event_id: Annotated[str | None, Header(alias="Last-Event-ID")] = None,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    types: Annotated[str | None, Query()] = None,
) -> Response | dict[str, Any]:
    """The campaign's published events: SSE for a live view, a JSON page for a history read."""
    trace_id = _trace(request, response)
    selected = _event_types(types)
    name = consumer_name()
    dsn = database_dsn_of(request)
    sse = _SSE in (request.headers.get("accept") or "").lower()

    with _connect(dsn) as connection:
        if not _is_id(campaign_id) or not _campaign_exists(connection, campaign_id):
            raise _not_found(campaign_id)
        # SSE resumes from the header; the JSON page from `cursor` (the header is honoured there
        # too, because the contract documents it on the operation rather than per encoding).
        raw_point, field = (
            (last_event_id, "/Last-Event-ID")
            if sse or (cursor is None and last_event_id is not None)
            else (cursor, "/cursor")
        )
        point = _resume_point(raw_point, field=field, head=_head(connection))
        try:
            _refresh_watermark(connection, name=name, holder=_HOLDER)
        except _REFRESH_RETRY:
            pass  # 0013: the old watermark is safe; the stream loop retries on the next tick
        except psycopg.errors.InsufficientPrivilege as error:
            raise ApiError(
                503,
                "DEPENDENCY_MISSING",
                "the API database role cannot advance the outbox watermark: grant it "
                "aegis_outbox_dispatcher (0008)",
                next_action="ESCALATE",
            ) from error

        if not sse:
            rows = _events_after(
                connection,
                campaign_id=campaign_id,
                after=point,
                limit=limit + 1,
                types=selected,
            )
            page: dict[str, Any] = {"items": [_envelope(row) for row in rows[:limit]]}
            if len(rows) > limit:
                page["next_cursor"] = str(rows[limit - 1]["seq"])
            return page

    stream = _stream(
        dsn=dsn,
        campaign_id=campaign_id,
        after=point,
        types=selected,
        name=name,
        holder=_HOLDER,
    )
    return StreamingResponse(
        stream,
        media_type=_SSE,
        headers={
            **_SSE_HEADERS,
            TRACEPARENT_HEADER: traceparent(trace_id),
            "X-Aegis-Consumer": name,
        },
    )


def register(registry: RouterRegistry, *, prefix: str = "") -> Any:
    """Mount the events router on the app registry (called by `main.build_registry`)."""
    return registry.register("events", router, prefix=prefix or API_PREFIX)
