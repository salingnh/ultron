"""R-6 connection hardening and the M02 outbox/campaign dispatchers (PostgreSQL only)."""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Coroutine
from datetime import UTC, datetime
from typing import Any

import psycopg
import pytest

from aegis.m02_orchestrator import db
from aegis.m02_orchestrator.campaign_state import CampaignStateWatcher
from aegis.m02_orchestrator.outbox import CONSUMER, OutboxDispatcher
from tests.db_support import connect, migrated_database, requires_postgres, seed_campaign
from tests.m02_support import RecordingSignals, insert_outbox_event

pytestmark = requires_postgres


def _run[T](coroutine: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coroutine)


def test_dispatcher_connection_sets_statement_and_idle_timeouts() -> None:
    with migrated_database() as dsn:
        with db.connect(dsn, statement_timeout_ms=1500, idle_in_transaction_timeout_ms=900) as conn:
            assert conn.execute("SHOW statement_timeout").fetchone() == {
                "statement_timeout": "1500ms"
            }
            assert conn.execute("SHOW idle_in_transaction_session_timeout").fetchone() == {
                "idle_in_transaction_session_timeout": "900ms"
            }
            assert conn.autocommit is True
            assert conn.execute("SHOW search_path").fetchone() == {"search_path": "aegis, public"}
        with pytest.raises(ValueError):
            db.connect(dsn, statement_timeout_ms=0)


def test_a_long_statement_is_cancelled_by_statement_timeout() -> None:
    with migrated_database() as dsn:
        with db.connect(dsn, statement_timeout_ms=100, idle_in_transaction_timeout_ms=5000) as conn:
            with pytest.raises(psycopg.errors.QueryCanceled) as caught:
                conn.execute("SELECT pg_sleep(1)")
            assert caught.value.sqlstate == "57014"


def test_an_idle_transaction_is_terminated_so_the_publication_lock_cannot_leak() -> None:
    with migrated_database() as dsn:
        with db.connect(dsn, statement_timeout_ms=5000, idle_in_transaction_timeout_ms=200) as conn:
            with pytest.raises(psycopg.errors.IdleInTransactionSessionTimeout) as caught:
                with conn.transaction():
                    conn.execute(
                        "SELECT pg_advisory_xact_lock(aegis.outbox_publication_lock_key())"
                    )
                    time.sleep(0.6)
                    conn.execute("SELECT 1")
            assert caught.value.sqlstate == "25P03"  # idle_in_transaction_session_timeout


def test_the_watermark_refresh_releases_the_publication_lock_before_reading() -> None:
    """R-6: refresh is its own short transaction; a writer is never stuck behind it."""
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn)
        through = OutboxDispatcher(lambda: db.connect(dsn), RecordingSignals())
        with db.connect(dsn) as dispatcher:
            with dispatcher.transaction():
                leased = dispatcher.execute(
                    "SELECT aegis.outbox_dispatch_lease(%s, %s, %s) AS fence",
                    (through._dispatcher, "test-holder", 15),
                ).fetchone()
            assert leased is not None and leased["fence"] is not None
            fence = int(leased["fence"])
            with dispatcher.transaction():
                refreshed = dispatcher.execute(
                    "SELECT aegis.outbox_watermark_refresh(%s, %s) AS watermark",
                    (through._dispatcher, fence),
                ).fetchone()
            assert refreshed is not None
            watermark = int(refreshed["watermark"])
            assert watermark == 0
            assert dispatcher.info.transaction_status == psycopg.pq.TransactionStatus.IDLE
            # A writer must acquire the shared publication lock immediately: a leaked exclusive
            # lock from the refresh would block it until the statement timeout below.
            with db.connect(dsn) as writer, writer.transaction():
                writer.execute("SET LOCAL statement_timeout = '1s'")
                insert_outbox_event(
                    dsn,
                    event_type="asset.discovered.v2",
                    campaign_id=campaign.campaign_id,
                    payload={"asset_id": str(uuid.uuid4())},
                )
            assert dispatcher.info.transaction_status == psycopg.pq.TransactionStatus.IDLE


def test_outbox_dispatcher_delivers_job_completed_and_checkpoints() -> None:
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn)
        skipped = insert_outbox_event(
            dsn,
            event_type="asset.discovered.v2",
            campaign_id=campaign.campaign_id,
            payload={"asset_id": str(uuid.uuid4())},
        )
        job_id = str(uuid.uuid4())
        completed = insert_outbox_event(
            dsn,
            event_type="job.completed.v2",
            campaign_id=campaign.campaign_id,
            dedup_key=job_id,
            payload={
                "job_id": job_id,
                "campaign_id": campaign.campaign_id,
                "status": "SUCCEEDED",
                "evidence_refs": [],
                "finished_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "attempt": 1,
                "generation": 1,
            },
        )
        signals = RecordingSignals()
        signals.present.add(campaign.campaign_id)
        outcome = _run(OutboxDispatcher(lambda: db.connect(dsn), signals).run_once())
        assert outcome.leased is True and outcome.error is None
        assert outcome.delivered == 1 and outcome.checkpoint == completed
        assert signals.completed == [(campaign.campaign_id, job_id, "SUCCEEDED")]
        with connect(dsn) as conn:
            cursor = conn.execute(
                "SELECT last_seq FROM consumer_cursor WHERE consumer = %s", (CONSUMER,)
            ).fetchone()
        assert cursor is not None and int(cursor[0]) == max(skipped, completed)


def test_a_failed_signal_is_retried_and_does_not_advance_the_cursor() -> None:
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn)
        job_id = str(uuid.uuid4())
        insert_outbox_event(
            dsn,
            event_type="job.completed.v2",
            campaign_id=campaign.campaign_id,
            dedup_key=job_id,
            payload={
                "job_id": job_id,
                "campaign_id": campaign.campaign_id,
                "status": "FAILED",
                "evidence_refs": [],
                "finished_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "attempt": 1,
                "generation": 1,
            },
        )
        signals = RecordingSignals()
        signals.fail_with = RuntimeError("temporal unavailable")
        dispatcher = OutboxDispatcher(lambda: db.connect(dsn), signals)
        failed = _run(dispatcher.run_once())
        assert failed.delivered == 0 and failed.checkpoint is None
        assert failed.error is not None and "temporal unavailable" in failed.error
        with connect(dsn) as conn:
            assert conn.execute(
                "SELECT count(*) FROM consumer_cursor WHERE consumer = %s", (CONSUMER,)
            ).fetchone() == (0,)
        signals.fail_with = None
        retried = _run(dispatcher.run_once())
        assert retried.delivered == 1 and retried.checkpoint is not None
        assert signals.completed == [(campaign.campaign_id, job_id, "FAILED")]


def test_a_second_dispatcher_cannot_take_a_live_lease() -> None:
    with migrated_database() as dsn:
        first = OutboxDispatcher(lambda: db.connect(dsn), RecordingSignals(), holder="holder-a")
        second = OutboxDispatcher(lambda: db.connect(dsn), RecordingSignals(), holder="holder-b")
        assert _run(first.run_once()).leased is True
        assert _run(second.run_once()).leased is False


def test_campaign_watcher_starts_once_and_signals_each_status_change_once() -> None:
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn, status="RUNNING")
        signals = RecordingSignals()
        watcher = CampaignStateWatcher(lambda: db.connect(dsn), signals)
        first = _run(watcher.run_once())
        assert first.watched == 1 and first.started == 1 and first.signalled == 1
        assert signals.started == [campaign.campaign_id]
        assert signals.statuses == [(campaign.campaign_id, "RUNNING", None)]
        again = _run(watcher.run_once())
        assert again.signalled == 0 and len(signals.statuses) == 1
        with connect(dsn) as conn, conn.transaction():
            conn.execute(
                "UPDATE campaign SET status = 'PAUSED', status_reason = 'operator pause' "
                "WHERE campaign_id = %s",
                (campaign.campaign_id,),
            )
        paused = _run(watcher.run_once())
        assert paused.signalled == 1
        assert signals.statuses[-1] == (campaign.campaign_id, "PAUSED", "operator pause")
        with connect(dsn) as conn, conn.transaction():
            conn.execute(
                "UPDATE campaign SET status = 'CANCELLED' WHERE campaign_id = %s",
                (campaign.campaign_id,),
            )
        canceled = _run(watcher.run_once())
        assert canceled.signalled == 1
        last = signals.statuses[-1]
        assert last[1] == "CANCELLED"
        assert signals.started == [campaign.campaign_id, campaign.campaign_id, campaign.campaign_id]
