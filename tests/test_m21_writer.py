"""M21's writer: one append-only run per job, one transition only when VERIFIED (G2-B, S2).

The decision table itself is replayed in `tests/test_m21_decision.py` without a database. This test
pins the writes:

* a replayed decision returns the committed row and adds no row, transition or event;
* VERIFIED writes `CANDIDATE -> VERIFIED` through the shared transition writer (actor M21, cause
  verification, the positive evidence) and publishes `finding.changed.v2`;
* a stale request sequence is INCONCLUSIVE and changes nothing;
* an operator decision (FALSE_POSITIVE) is not overridden;
* an already-VERIFIED finding at the requested sequence is recorded without a second transition;
* a job that is not a completed `verify.check` job is not decidable (None, no row).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import psycopg
import pytest
from psycopg.types.json import Jsonb

from aegis.m21_verify import controls as control_map
from aegis.m21_verify import writer
from aegis.m21_verify.evidence import MemoryEvidenceReader, evidence_from_row
from tests import db_support


def now() -> Any:
    from datetime import UTC, datetime

    return datetime.now(UTC)


pytestmark = db_support.requires_postgres

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "verify"
CHECK = "cve-2021-41773-traversal"
POSITIVE = "service:10.114.59.31:80/tcp"
TWIN = "service:10.114.59.32:80/tcp"
URI = "s3://evidence/test/pair.jsonl"


def _id() -> str:
    from aegis.m05_registry.ids import uuid7

    return str(uuid7())


@pytest.fixture()
def seeded() -> Iterator[dict[str, Any]]:
    with db_support.migrated_database() as dsn:
        campaign = db_support.seed_campaign(dsn)
        pair = (FIXTURES / "nuclei" / "pair.jsonl").read_bytes()
        sha = hashlib.sha256(pair).hexdigest()
        ids = {name: _id() for name in ("asset", "finding", "evidence")}
        with psycopg.connect(dsn) as conn, conn.transaction():
            conn.execute(
                "INSERT INTO asset (asset_id, canonical_key, kind, first_seen, last_seen,"
                " normalization_version) VALUES (%s, %s, 'service', now(), now(), 'aegis-norm/1')",
                (ids["asset"], POSITIVE),
            )
            conn.execute(
                "INSERT INTO asset_campaign (asset_id, campaign_id, first_seen)"
                " VALUES (%s, %s, now())",
                (ids["asset"], campaign.campaign_id),
            )
            base_task = {
                "network_profile": "lab",
                "capability": "verify.check",
                "provider": "nuclei-verify",
                "provider_version": "v3.11.1",
                "image_digest": "sha256:" + "5" * 64,
                "manifest_sha256": "6" * 64,
                "signature": "x",
                "signature_key_id": "k",
                "egress_binding": {},
                "input": {
                    "check_id": CHECK,
                    "check_pack_sha256": "0" * 64,
                    "request_cap": 4,
                    "expected_seq": 1,
                    "targets": [POSITIVE],
                    "controls": [{"role": "patched_twin", "target": TWIN}],
                    "benign_path": "/static/.%2e/.%2e/srv/canary/absent.txt",
                    "finding_id": ids["finding"],
                },
            }

            def add_job(
                key: str,
                *,
                status: str = "SUCCEEDED",
                capability: str = "verify.check",
                envelope: bool = True,
            ) -> str:
                decision = _id()
                conn.execute(
                    "INSERT INTO policy_decision (decision_id, campaign_id, capability, provider,"
                    " targets, input, decision, rationale, requested_by, target_refs,"
                    " policy_version, scope_id, idempotency_key, trace_id)"
                    " VALUES (%s, %s, %s, 'nuclei-verify', %s, %s, 'approved', 'test', %s, %s,"
                    " %s, %s, %s, %s)",
                    (
                        decision,
                        campaign.campaign_id,
                        capability,
                        [POSITIVE],
                        Jsonb({"check_id": CHECK}),
                        Jsonb(db_support.OPERATOR),
                        Jsonb([{"canonical_key": POSITIVE}]),
                        campaign.policy_version,
                        campaign.scope_id,
                        f"test-{key}",
                        "a" * 32,
                    ),
                )
                job = _id()
                conn.execute(
                    "INSERT INTO scan_job (job_id, campaign_id, decision_id, capability, provider,"
                    " provider_version, adapter_version, image_digest, manifest_sha256, scan_cycle,"
                    " job_fingerprint, policy_version, scope_id, input, targets, target_refs,"
                    " requested_by, rationale, trace_id, status, started_at, finished_at,"
                    " envelope_event_id, approved_task)"
                    " VALUES (%s, %s, %s, %s, 'nuclei-verify', 'v3.11.1', '1.0.0', %s, %s,"
                    " %s, %s, %s, %s, %s, %s, %s, %s, 'test', %s, %s, %s, %s, %s, %s)",
                    (
                        job,
                        campaign.campaign_id,
                        decision,
                        capability,
                        "sha256:" + "5" * 64,
                        "6" * 64,
                        _id(),
                        hashlib.sha256(key.encode()).hexdigest(),
                        campaign.policy_version,
                        campaign.scope_id,
                        Jsonb({"check_id": CHECK}),
                        [POSITIVE],
                        Jsonb([{"canonical_key": POSITIVE}]),
                        Jsonb(db_support.OPERATOR),
                        "b" * 32,
                        status,
                        now() if status == "SUCCEEDED" else None,
                        now() if status == "SUCCEEDED" else None,
                        _id() if envelope and status == "SUCCEEDED" else None,
                        Jsonb(base_task),
                    ),
                )
                return job

            ids["job"] = add_job("main")
            ids["queued"] = add_job("queued", status="QUEUED", envelope=False)
            ids["other"] = add_job("other", capability="network.discover_services")
            conn.execute(
                "INSERT INTO finding (finding_id, fingerprint, asset_id, rule_id, category, title,"
                " vulnerability_ids, status, first_seen, last_seen, first_job_id,"
                " first_campaign_id) VALUES (%s, %s, %s, 'cve:CVE-2021-41773', 'vulnerability',"
                " 'httpd traversal', '{CVE-2021-41773}', 'CANDIDATE', now(), now(), %s, %s)",
                (ids["finding"], "d" * 64, ids["asset"], ids["job"], campaign.campaign_id),
            )
            conn.execute(
                "INSERT INTO evidence (evidence_id, sha256, storage_uri, campaign_id, job_id,"
                " size_bytes, media_type, classification, source_tool, verified_at)"
                " VALUES (%s, %s, %s, %s, %s, %s, 'application/x-ndjson', 'INTERNAL',"
                " 'nuclei-verify', now())",
                (
                    ids["evidence"],
                    sha,
                    URI,
                    campaign.campaign_id,
                    ids["job"],
                    len(pair),
                ),
            )
            # The lab map of the recorded run: the capture's addresses and canary.
            mapping = control_map.load_controls(FIXTURES / "controls.json")
        yield {
            "dsn": dsn,
            "campaign": campaign,
            "ids": ids,
            "pair": pair,
            "controls": mapping,
        }


def _reader(seeded: dict[str, Any]) -> MemoryEvidenceReader:
    return MemoryEvidenceReader({URI: seeded["pair"]})


def _connect(seeded: dict[str, Any]) -> psycopg.Connection[Any]:
    connection = psycopg.connect(seeded["dsn"], autocommit=True, row_factory=psycopg.rows.dict_row)
    connection.execute("SET search_path = aegis, public")
    return connection


def _count(connection: psycopg.Connection[Any], table: str) -> int:
    row = connection.execute(f"SELECT count(*) AS n FROM {table}").fetchone()
    assert row is not None
    return int(row["n"])


def test_verified_writes_one_run_one_transition_one_event(seeded: dict[str, Any]) -> None:
    connection = _connect(seeded)
    try:
        record = writer.decide_job(
            connection, seeded["ids"]["job"], reader=_reader(seeded), controls=seeded["controls"]
        )
        assert record is not None
        assert record.outcome == "VERIFIED"
        assert record.written is True
        assert record.transition_seq == 2
        run = connection.execute("SELECT * FROM verification_run").fetchone()
        assert run is not None
        assert run["outcome"] == "VERIFIED"
        assert run["network_profile"] == "lab"
        assert run["requests_sent"] == 4
        assert run["transition_seq"] == 2
        assert run["matched"]["positive"] is True
        assert run["matched"]["control_a"] is False
        finding = connection.execute("SELECT * FROM finding").fetchone()
        assert finding is not None
        assert finding["status"] == "VERIFIED"
        assert finding["transition_seq"] == 2
        transition = connection.execute("SELECT * FROM finding_transition").fetchone()
        assert transition is not None
        assert transition["from_status"] == "CANDIDATE"
        assert transition["to_status"] == "VERIFIED"
        assert transition["cause"] == "verification"
        assert transition["actor"] == {"kind": "module", "id": "M21"}
        events = connection.execute(
            "SELECT * FROM outbox_event WHERE type = 'finding.changed.v2'"
        ).fetchall()
        assert len(events) == 1
        assert events[0]["producer"] == "M21"
        assert events[0]["payload"]["changed_by"] == {"kind": "module", "id": "M21"}
    finally:
        connection.close()


def test_a_replay_writes_nothing(seeded: dict[str, Any]) -> None:
    connection = _connect(seeded)
    try:
        first = writer.decide_job(
            connection, seeded["ids"]["job"], reader=_reader(seeded), controls=seeded["controls"]
        )
        second = writer.decide_job(
            connection, seeded["ids"]["job"], reader=_reader(seeded), controls=seeded["controls"]
        )
        assert first is not None and second is not None
        assert second.written is False
        assert second.verification_id == first.verification_id
        assert _count(connection, "verification_run") == 1
        assert _count(connection, "finding_transition") == 1
        assert _count(connection, "outbox_event") == 1
    finally:
        connection.close()


def test_a_stale_request_sequence_is_inconclusive(seeded: dict[str, Any]) -> None:
    connection = _connect(seeded)
    try:
        connection.execute(
            "INSERT INTO finding_transition (finding_id, seq, from_status, to_status, reason,"
            " evidence_id, actor, cause) VALUES (%s, 2, 'CANDIDATE', 'CORROBORATED',"
            " 'second source', %s, %s, 'scan')",
            (
                seeded["ids"]["finding"],
                seeded["ids"]["evidence"],
                Jsonb({"kind": "module", "id": "M20"}),
            ),
        )
        connection.execute(
            "UPDATE finding SET status = 'CORROBORATED', transition_seq = 2 WHERE finding_id = %s",
            (seeded["ids"]["finding"],),
        )
        record = writer.decide_job(
            connection, seeded["ids"]["job"], reader=_reader(seeded), controls=seeded["controls"]
        )
        assert record is not None
        assert record.outcome == "INCONCLUSIVE"
        assert "stale" in record.reason
        assert record.transition_seq is None
        finding = connection.execute("SELECT * FROM finding").fetchone()
        assert finding is not None and finding["status"] == "CORROBORATED"
        run = connection.execute("SELECT * FROM verification_run").fetchone()
        assert run is not None and run["transition_seq"] is None
    finally:
        connection.close()


def test_an_operator_decision_is_not_overridden(seeded: dict[str, Any]) -> None:
    connection = _connect(seeded)
    try:
        connection.execute(
            "UPDATE finding SET status = 'FALSE_POSITIVE' WHERE finding_id = %s",
            (seeded["ids"]["finding"],),
        )
        record = writer.decide_job(
            connection, seeded["ids"]["job"], reader=_reader(seeded), controls=seeded["controls"]
        )
        assert record is not None
        assert record.outcome == "INCONCLUSIVE"
        assert "operator decision" in record.reason or "FALSE_POSITIVE" in record.reason
        finding = connection.execute("SELECT * FROM finding").fetchone()
        assert finding is not None and finding["status"] == "FALSE_POSITIVE"
    finally:
        connection.close()


def test_an_already_verified_finding_gets_no_second_transition(seeded: dict[str, Any]) -> None:
    connection = _connect(seeded)
    try:
        connection.execute(
            "UPDATE finding SET status = 'VERIFIED' WHERE finding_id = %s",
            (seeded["ids"]["finding"],),
        )
        record = writer.decide_job(
            connection, seeded["ids"]["job"], reader=_reader(seeded), controls=seeded["controls"]
        )
        assert record is not None
        assert record.outcome == "VERIFIED"
        assert record.transition_seq == 1
        assert _count(connection, "finding_transition") == 0
    finally:
        connection.close()


def test_a_job_that_is_not_done_is_not_decidable(seeded: dict[str, Any]) -> None:
    connection = _connect(seeded)
    try:
        assert (
            writer.decide_job(
                connection,
                seeded["ids"]["queued"],
                reader=_reader(seeded),
                controls=seeded["controls"],
            )
            is None
        )
        assert _count(connection, "verification_run") == 0
    finally:
        connection.close()


def test_a_job_of_another_capability_is_refused(seeded: dict[str, Any]) -> None:
    connection = _connect(seeded)
    try:
        with pytest.raises(writer.VerificationError, match="not a verify.check job"):
            writer.decide_job(
                connection,
                seeded["ids"]["other"],
                reader=_reader(seeded),
                controls=seeded["controls"],
            )
    finally:
        connection.close()


def test_a_campaign_pass_decides_only_completed_undecided_jobs(seeded: dict[str, Any]) -> None:
    connection = _connect(seeded)
    try:
        decided = writer.decide_campaign(
            connection,
            seeded["campaign"].campaign_id,
            reader=_reader(seeded),
            controls=seeded["controls"],
        )
        assert [record.outcome for record in decided] == ["VERIFIED"]
        assert writer.open_runs(connection, seeded["campaign"].campaign_id) == []
    finally:
        connection.close()


def test_the_evidence_row_reader_names_the_object() -> None:
    row = evidence_from_row(
        {
            "evidence_id": "e",
            "storage_uri": "s3://evidence/a/b/c",
            "sha256": "f" * 64,
            "media_type": "application/x-ndjson",
            "size_bytes": 1,
        }
    )
    assert row.uri == "s3://evidence/a/b/c"


def test_the_record_is_json_ready(seeded: dict[str, Any]) -> None:
    connection = _connect(seeded)
    try:
        record = writer.decide_job(
            connection, seeded["ids"]["job"], reader=_reader(seeded), controls=seeded["controls"]
        )
        assert record is not None
        assert json.loads(json.dumps(record.as_dict()))["outcome"] == "VERIFIED"
    finally:
        connection.close()
