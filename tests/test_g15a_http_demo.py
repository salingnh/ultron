"""G1.5a acceptance demo: the flow document and the event stream over HTTP against a real API + DB.

`make demo-g15a` runs this file with `-s` and prints the evidence (flow JSON, SSE frames, latency,
resume result). It is a test so CI keeps it true, and a demo so the same steps read end to end:

1. start the app under uvicorn on a loopback port over a throwaway, fully migrated database;
2. create the campaign through `POST /api/v2/campaigns` as an operator (the real M01 write path);
3. accept two jobs through M05, the second depending on the first (the `/jobs` route needs
   registered adapters, which are G1.3b's; the demo calls the same acceptance service it calls);
4. `GET .../flow` - validated against the contract's inline response schema and printed;
5. open the SSE stream, terminalise a job exactly as M06 will (terminal CAS + `job.completed.v2` in
   one transaction) and time how long the client waits (acceptance: under two seconds);
6. reconnect with `Last-Event-ID` after another change: nothing lost, nothing duplicated.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import psycopg
import pytest
import yaml

from aegis.common.repo import repository_root
from tests import campaign_support as support
from tests.db_support import SeededCampaign, migrated_database, requires_postgres
from tests.g15a_support import api_app, emit_event, job_completed_payload, seed_events
from tests.http_support import open_sse, serve
from tests.m02_support import accept_job, run_job
from tests.test_m05_service import service

pytestmark = requires_postgres

API = "/api/v2"
EVIDENCE_ENV = "AEGIS_G15A_DEMO_OUT"
AUTH = support.auth()


@pytest.fixture()
def dsn() -> Iterator[str]:
    with migrated_database() as value:
        yield value


def _terminalise(dsn: str, job: dict[str, Any]) -> int:
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


def _flow_schema() -> dict[str, Any]:
    contract: dict[str, Any] = yaml.safe_load(
        (repository_root() / "contracts/api/openapi.v2.yaml").read_text(encoding="utf-8")
    )
    schema: dict[str, Any] = contract["paths"]["/campaigns/{campaign_id}/flow"]["get"]["responses"][
        "200"
    ]["content"]["application/json"]["schema"]
    return schema


def _print(title: str, body: Any) -> None:
    print(f"\n=== {title} ===")  # noqa: T201 - the demo's product is the printed evidence
    print(json.dumps(body, indent=2, ensure_ascii=False))  # noqa: T201


def test_the_flow_and_the_event_stream_over_http(dsn: str) -> None:
    evidence: dict[str, Any] = {
        "api": "uvicorn on 127.0.0.1",
        "database": "throwaway PostgreSQL 16",
    }
    authorization = f"Bearer {support.OPERATORS['op-soc-1']}"
    with (
        serve(api_app(dsn)) as base,
        httpx.Client(
            base_url=base, timeout=10.0, headers={"authorization": authorization}
        ) as client,
    ):
        created = client.post(
            f"{API}/campaigns",
            json=support.campaign_body(name="G1.5a demo"),
            headers={"Idempotency-Key": "g15a-demo-create"},
        )
        assert created.status_code == 202, created.text
        campaign = SeededCampaign(
            campaign_id=created.json()["campaign_id"],
            policy_version=created.json()["policy_version"],
            scope_id=created.json()["scope_id"],
            seed_domain="internal.example",
            seed_ip="10.114.53.53",
            known_asset="",
        )
        evidence["campaign"] = {"id": campaign.campaign_id, "created_by": "POST /campaigns"}

        with service(dsn) as jobs_service:
            first_id = accept_job(jobs_service, campaign)
            second_id = accept_job(jobs_service, campaign, depends_on=[first_id])
            first = jobs_service.get_job(first_id)
            second = jobs_service.get_job(second_id)
        run_job(dsn, first_id)
        run_job(dsn, second_id)

        flow = client.get(f"{API}/campaigns/{campaign.campaign_id}/flow")
        assert flow.status_code == 200, flow.text
        document = flow.json()
        problems = list(support.validator(_flow_schema()).iter_errors(document))
        assert problems == [], problems[:2]
        _print("GET /api/v2/campaigns/{id}/flow", document)
        evidence["flow"] = {
            "revision": document["revision"],
            "nodes": [(node["type"], node["status"]) for node in document["nodes"]],
            "edges": [(edge["from"], edge["to"], edge["kind"]) for edge in document["edges"]],
            "contract": "valid against openapi.v2 getCampaignFlow",
        }

        stream_url = f"{base}{API}/campaigns/{campaign.campaign_id}/events"
        started_at = time.monotonic()
        with open_sse(stream_url, read_timeout=5.0, extra_headers=AUTH) as stream:
            # A campaign's stream replays its own seed events first (M01 publishes one
            # `asset.discovered.v2` per identity-bearing seed in the campaign transaction).
            for _ in range(len(seed_events(dsn, campaign.campaign_id))):
                seed_frame = stream.next()
                assert seed_frame.event == "asset.discovered.v2", seed_frame.event
            sequence = _terminalise(dsn, first)
            message = stream.next()
            latency = time.monotonic() - started_at
        assert latency < 2.0, f"job status change took {latency:.2f}s"
        assert message.id == str(sequence)
        assert message.event == "job.completed.v2"
        _print(
            "SSE frame",
            {
                "id": message.id,
                "event": message.event,
                "data": json.loads(message.data),
                "latency_seconds": round(latency, 3),
            },
        )
        evidence["sse"] = {
            "first": {"id": message.id, "event": message.event},
            "job_status_change_latency_seconds": round(latency, 3),
            "under_two_seconds": latency < 2.0,
        }

        with open_sse(
            stream_url, last_event_id=message.id, read_timeout=5.0, extra_headers=AUTH
        ) as stream:
            later = _terminalise(dsn, second)
            resumed = stream.next()
        assert resumed.id == str(later), "the reconnect must continue exactly after the checkpoint"
        assert resumed.id != message.id, "the reconnect must not resend the checkpoint event"
        _print(
            "SSE after Last-Event-ID",
            {"last_event_id": message.id, "received": {"id": resumed.id, "event": resumed.event}},
        )
        evidence["resume"] = {
            "last_event_id": message.id,
            "received": {"id": resumed.id, "event": resumed.event},
            "lost": [],
            "duplicated": [],
        }

        after = client.get(f"{API}/campaigns/{campaign.campaign_id}/flow").json()
        assert after["revision"] > document["revision"]
        evidence["flow_after"] = {"revision": after["revision"]}

    if os.environ.get(EVIDENCE_ENV):
        Path(os.environ[EVIDENCE_ENV]).write_text(
            json.dumps(evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    _print("summary", evidence)
