"""`GET /campaigns/{id}/events` as a real SSE stream over a real socket (G1.5a acceptance).

The acceptance criteria of the card live here: a job status change reaches a connected client
within two seconds, and a client that reconnects with `Last-Event-ID` sees every later event once -
nothing lost, nothing duplicated. The app runs under uvicorn on a loopback port (not `TestClient`),
because the behaviour under test is the stream itself: incremental writes, heartbeats, and the
client's disconnect.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncGenerator, Iterator
from contextlib import aclosing
from types import SimpleNamespace
from typing import Any, cast

import httpx
import psycopg
import pytest
from psycopg.rows import dict_row

from aegis.m26_api import events
from tests import campaign_support as support
from tests.db_support import migrated_database, requires_postgres
from tests.g15a_support import (
    accept_jobs,
    api_app,
    emit_event,
    job_completed_payload,
    job_started_payload,
    open_campaign,
    seed_events,
)
from tests.http_support import SseStream, open_sse, serve
from tests.m02_support import run_job

pytestmark = requires_postgres

SSE_ACCEPT = {"accept": "text/event-stream"}
AUTH = support.auth()


@pytest.fixture()
def dsn() -> Iterator[str]:
    with migrated_database() as value:
        yield value


@pytest.fixture()
def api(dsn: str) -> Iterator[str]:
    with serve(api_app(dsn)) as url:
        yield url


def _stream_url(api: str, campaign_id: str) -> str:
    return f"{api}/api/v2/campaigns/{campaign_id}/events"


def _open(url: str, **kwargs: Any) -> SseStream:
    return open_sse(url, extra_headers=AUTH, **kwargs)


def _consume_seed_events(stream: SseStream, seeds: list[int]) -> None:
    """Read the campaign's seed events, which every stream replays before the test's own events.

    M01 publishes one `asset.discovered.v2` per identity-bearing seed in the campaign transaction;
    a stream starts from the campaign's first event, so those frames arrive first and a test that
    begins its own stream must account for them (and can prove they are the seeds).
    """
    for sequence in seeds:
        message = stream.next()
        assert message.id == str(sequence), message.id
        assert message.event == "asset.discovered.v2", message.event


def _publish(dsn: str, campaign_id: str, jobs: list[dict[str, Any]]) -> list[int]:
    """One `job.started.v2` per job, committed as M06 publishes it; returns the seqs."""
    return [
        emit_event(
            dsn,
            campaign_id=campaign_id,
            event_type="job.started.v2",
            dedup_key=job["job_id"],
            payload=job_started_payload(job),
        )
        for job in jobs
    ]


def _complete_with_event(dsn: str, job: dict[str, Any]) -> int:
    """M06's commit: the terminal CAS and its `job.completed.v2` in one transaction."""
    with psycopg.connect(dsn) as conn, conn.transaction():
        row = conn.execute(
            "SELECT aegis.record_job_callback(%s, %s, %s, 'SUCCEEDED')",
            (job["job_id"], job["generation"], job["attempt"]),
        ).fetchone()
        assert row is not None and row[0] == "terminalized", row
        return emit_event(
            dsn,
            campaign_id=job["campaign_id"],
            event_type="job.completed.v2",
            dedup_key=job["job_id"],
            payload=job_completed_payload(job, "SUCCEEDED"),
            connection=conn,
        )


def _backends(dsn: str) -> int:
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        row = conn.execute(
            "SELECT count(*) AS n FROM pg_stat_activity WHERE datname = current_database()"
        ).fetchone()
    assert row is not None
    return int(row["n"])


def test_a_committed_job_status_change_reaches_a_connected_client(dsn: str, api: str) -> None:
    campaign = open_campaign(dsn, name="sse latency")
    (job,) = accept_jobs(dsn, campaign, 1)
    run_job(dsn, job["job_id"])

    with _open(_stream_url(api, campaign.campaign_id), read_timeout=5.0) as stream:
        _consume_seed_events(stream, seed_events(dsn, campaign.campaign_id))
        sequence = _complete_with_event(dsn, job)
        # How soon an open stream picks a commit up is checked on a controlled clock below.
        message = stream.next()

    assert message.id == str(sequence)
    assert message.event == "job.completed.v2"
    envelope = json.loads(message.data)
    assert envelope["payload"]["status"] == "SUCCEEDED"
    assert envelope["payload"]["job_id"] == job["job_id"]


def test_reconnect_with_last_event_id_loses_nothing_and_duplicates_nothing(
    dsn: str, api: str
) -> None:
    campaign = open_campaign(dsn, name="sse resume")
    jobs = accept_jobs(dsn, campaign, 2)
    first = _publish(dsn, campaign.campaign_id, jobs[:1])

    with _open(_stream_url(api, campaign.campaign_id), read_timeout=5.0) as stream:
        _consume_seed_events(stream, seed_events(dsn, campaign.campaign_id))
        checkpoint_message = stream.next()
    assert checkpoint_message.id == str(first[0])

    later = _publish(dsn, campaign.campaign_id, jobs[1:])
    with _open(
        _stream_url(api, campaign.campaign_id),
        last_event_id=checkpoint_message.id,
        read_timeout=5.0,
    ) as stream:
        resumed = stream.events(1)
        # Nothing after the published head may be sent again, so the client's read times out.
        with pytest.raises(httpx.ReadTimeout):
            stream.next()

    assert [message.id for message in resumed] == [str(sequence) for sequence in later]
    assert json.loads(resumed[0].data)["payload"]["job_id"] == jobs[1]["job_id"]
    assert resumed[0].event == "job.started.v2"


def test_a_resume_point_from_another_event_log_generation_is_refused(dsn: str, api: str) -> None:
    campaign = open_campaign(dsn, name="sse generation")
    response = httpx.get(
        _stream_url(api, campaign.campaign_id),
        headers={**SSE_ACCEPT, **AUTH, "last-event-id": "987654321"},
        timeout=5.0,
    )
    assert response.status_code == 400, response.text
    body = response.json()
    assert body["code"] == "INPUT_INVALID"
    assert body["field"] == "/Last-Event-ID"


def test_heartbeats_keep_an_idle_stream_alive(dsn: str, api: str, monkeypatch: Any) -> None:
    monkeypatch.setattr(events, "HEARTBEAT_SECONDS", 0.3)
    campaign = open_campaign(dsn, name="sse heartbeat")
    with _open(_stream_url(api, campaign.campaign_id), read_timeout=3.0) as stream:
        _consume_seed_events(stream, seed_events(dsn, campaign.campaign_id))
        # When it is sent is checked on a controlled clock below.
        heartbeat = stream.next()
    assert heartbeat.event == "heartbeat"
    assert heartbeat.id is None, "a heartbeat is not a resume point"
    assert json.loads(heartbeat.data)["at"].endswith("Z")


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.now += seconds


def test_an_idle_stream_sends_a_heartbeat_every_15_seconds(monkeypatch: Any) -> None:
    """The contract's interval, on a controlled clock: no socket, database or wall-clock time."""
    clock = _Clock()
    monkeypatch.setattr(events, "time", clock)
    monkeypatch.setattr(events, "asyncio", SimpleNamespace(sleep=clock.sleep))
    monkeypatch.setattr(events, "_connect", lambda _dsn: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(events, "_events_after", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(events, "_refresh_quietly", lambda *_args, **_kwargs: None)

    async def heartbeat_times(count: int) -> list[float]:
        stream = events._stream(
            dsn="unused", campaign_id="c", after=0, types=None, name="n", holder="h"
        )
        sent: list[float] = []
        async with aclosing(cast(AsyncGenerator[str], stream)) as frames:
            async for frame in frames:
                if frame.startswith("event: heartbeat\n"):
                    sent.append(clock.now)
                    if len(sent) == count:
                        break
        return sent

    first, second = asyncio.run(heartbeat_times(2))
    # Each is sent by the first poll at or after its due time.
    assert 15.0 <= first <= 15.0 + events.POLL_SECONDS
    assert 15.0 <= second - first <= 15.0 + events.POLL_SECONDS


def test_an_open_stream_sends_a_committed_event_at_its_next_poll(monkeypatch: Any) -> None:
    """The stream's share of "a status change reaches a client within 2 s" (G1.5a): its waiting."""
    clock = _Clock()
    committed_at = 3.1
    seq = 7

    def events_after(*_args: Any, after: int, **_kwargs: Any) -> list[dict[str, Any]]:
        due = clock.now >= committed_at and after < seq
        return [{"seq": seq, "type": "job.completed.v2"}] if due else []

    monkeypatch.setattr(events, "time", clock)
    monkeypatch.setattr(events, "asyncio", SimpleNamespace(sleep=clock.sleep))
    monkeypatch.setattr(events, "_connect", lambda _dsn: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(events, "_events_after", events_after)
    monkeypatch.setattr(events, "_refresh_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(events, "_envelope", lambda _row: {})

    async def sent_at() -> float:
        stream = events._stream(
            dsn="unused", campaign_id="c", after=0, types=None, name="n", holder="h"
        )
        async with aclosing(cast(AsyncGenerator[str], stream)) as frames:
            async for frame in frames:
                if frame.startswith("id: 7\n"):
                    break
        return clock.now

    delay = asyncio.run(sent_at()) - committed_at
    assert 0 <= delay <= events.POLL_SECONDS < 2.0


def test_a_stream_only_sees_its_own_campaign(dsn: str, api: str) -> None:
    mine = open_campaign(dsn, name="sse mine")
    theirs = open_campaign(dsn, name="sse theirs")
    _publish(dsn, theirs.campaign_id, accept_jobs(dsn, theirs, 1))
    with _open(_stream_url(api, mine.campaign_id), read_timeout=0.8) as stream:
        _consume_seed_events(stream, seed_events(dsn, mine.campaign_id))
        with pytest.raises(httpx.ReadTimeout):
            stream.next()


def test_the_response_identifies_the_stream_generation_and_forbids_buffering(
    dsn: str, api: str
) -> None:
    campaign = open_campaign(dsn, name="sse headers")
    with httpx.stream(
        "GET",
        _stream_url(api, campaign.campaign_id),
        headers={**SSE_ACCEPT, **AUTH},
        timeout=5.0,
    ) as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        assert response.headers["x-aegis-consumer"] == events.consumer_name() == "m26-sse#g1"
        assert response.headers["cache-control"] == "no-cache"
        assert response.headers["x-accel-buffering"] == "no"
        assert response.headers["traceparent"].startswith("00-")
        assert next(response.iter_lines()) == ": m26-sse#g1 ready"


def test_a_disconnected_client_releases_its_database_connection(dsn: str, api: str) -> None:
    campaign = open_campaign(dsn, name="sse disconnect")
    _publish(dsn, campaign.campaign_id, accept_jobs(dsn, campaign, 1))
    before = _backends(dsn)
    with _open(_stream_url(api, campaign.campaign_id), read_timeout=5.0) as stream:
        stream.next()
        assert _backends(dsn) > before, "the stream holds one connection while it is open"
    deadline = time.monotonic() + 5.0
    while _backends(dsn) > before and time.monotonic() < deadline:
        time.sleep(0.1)
    assert _backends(dsn) == before, "the stream must close its connection when the client leaves"


def test_the_stream_requires_the_operator_token(dsn: str, api: str) -> None:
    campaign = open_campaign(dsn, name="sse auth")
    url = _stream_url(api, campaign.campaign_id)
    for headers, expected in (
        (SSE_ACCEPT, 401),
        ({**SSE_ACCEPT, "authorization": "Bearer not-a-token"}, 401),
        ({**SSE_ACCEPT, **AUTH}, 200),
    ):
        with httpx.stream("GET", url, headers=headers, timeout=5.0) as response:
            assert response.status_code == expected
            if expected == 401:
                assert response.headers["www-authenticate"] == "Bearer"
                assert json.loads(response.read())["code"] == "INPUT_INVALID"
            else:
                assert response.headers["content-type"].startswith("text/event-stream")
                assert next(response.iter_lines()) == ": m26-sse#g1 ready"
