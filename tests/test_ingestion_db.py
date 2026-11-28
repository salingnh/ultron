"""M27 ingestion against PostgreSQL 18: gates, C03 receipt, outbox, concurrency and P95 (G1.4a).

These tests apply the real contract chain to a throwaway database, build the campaign/decision/job
rows the owning modules would write, and then drive `IngestionService`. They never touch a shared
schema: `throwaway_database` creates and drops its own database.
"""

from __future__ import annotations

import hashlib
import json
import math
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, cast

import psycopg
import pytest

from aegis import validation
from aegis.m27_ingestion import canonical
from aegis.m27_ingestion.errors import EnvelopeRejected, IdempotencyConflict
from aegis.m27_ingestion.ids import uuid7
from aegis.m27_ingestion.service import IngestionService
from tests.pg import requires_postgres, throwaway_database
from tests.support_ingestion import (
    CAMPAIGN_ID,
    FINISHED_AT,
    IMAGE_DIGEST,
    POLICY_VERSION,
    PROVIDER,
    PROVIDER_VERSION,
    SCOPE_ID,
    SEED_ASSET_KEY,
    SEED_ID,
    asset,
    build_envelope,
    finding,
    observation,
    relationship,
    seed_campaign,
    seed_evidence,
    seed_job,
    seed_jobs,
)

RAW_EVIDENCE = b'{"A": "192.0.2.10"}\n'
EVIDENCE_SHA = hashlib.sha256(RAW_EVIDENCE).hexdigest()


def _migrate(dsn: str) -> None:
    from aegis.migrations import apply_contract_migrations

    with psycopg.connect(dsn, autocommit=True) as connection:
        apply_contract_migrations(connection)


def _connect(dsn: str) -> psycopg.Connection[tuple[object, ...]]:
    connection: psycopg.Connection[tuple[object, ...]] = psycopg.connect(dsn, autocommit=True)
    connection.execute("SET search_path = aegis, public")
    return connection


def _count(
    connection: psycopg.Connection[tuple[object, ...]], sql: str, params: tuple[Any, ...] = ()
) -> int:
    row = connection.execute(sql, params).fetchone()
    assert row is not None
    return int(cast(int, row[0]))


def _one(
    connection: psycopg.Connection[tuple[object, ...]], sql: str, params: tuple[Any, ...] = ()
) -> tuple[Any, ...]:
    """One row, typed as Any so the test can assert on individual columns."""
    row = connection.execute(sql, params).fetchone()
    assert row is not None
    return cast(tuple[Any, ...], row)


def _evidence_entry(job_id: str) -> dict[str, Any]:
    return {
        "local_ref": "raw",
        "sha256": EVIDENCE_SHA,
        "uri": f"s3://evidence/{CAMPAIGN_ID}/{job_id}/{EVIDENCE_SHA}",
        "size_bytes": len(RAW_EVIDENCE),
        "media_type": "application/json",
        "classification": "INTERNAL",
        "kind": "raw_output",
    }


def _baseline_envelope(job_id: str, *, event_id: str | None = None) -> dict[str, Any]:
    return build_envelope(
        job_id,
        event_id=event_id,
        assets=[
            asset(SEED_ASSET_KEY, "domain"),
            asset(
                "dns:www.internal.example",
                "domain",
                aliases=[{"namespace": "original", "value": "WWW.Internal.Example"}],
            ),
            asset("ip:192.0.2.10", "ip"),
            asset("service:192.0.2.10:443/tcp", "service"),
        ],
        observations=[
            observation(
                "dns:www.internal.example",
                "dns.record",
                {"type": "A", "value": "192.0.2.10", "ttl": 300},
                evidence_refs=[{"local_ref": "raw"}],
            ),
            observation("ip:192.0.2.10", "net.asn", {"asn": 64500, "org": "fixture"}),
            observation("service:192.0.2.10:443/tcp", "service.product", {"product": "nginx"}),
        ],
        relationships=[
            relationship("SUBDOMAIN_OF", "dns:www.internal.example", SEED_ASSET_KEY),
            relationship("RESOLVES_TO", "dns:www.internal.example", "ip:192.0.2.10"),
            relationship("EXPOSES", "ip:192.0.2.10", "service:192.0.2.10:443/tcp"),
        ],
        coverage=[
            "dns:www.internal.example",
            "ip:192.0.2.10",
            "service:192.0.2.10:443/tcp",
        ],
        evidence=[_evidence_entry(job_id)],
    )


@requires_postgres
def test_first_submission_ingests_the_whole_graph_and_emits_events() -> None:
    with throwaway_database() as dsn:
        _migrate(dsn)
        with _connect(dsn) as connection:
            seed_campaign(connection)
            job_id = seed_job(connection, "g14a:first")
            seed_evidence(connection, job_id, sha256=EVIDENCE_SHA, size_bytes=len(RAW_EVIDENCE))
        service = IngestionService.from_dsn(dsn)
        envelope = _baseline_envelope(job_id)
        payload_hash = canonical.payload_hash(envelope)

        receipt = service.submit_payload(envelope)

        assert receipt.accepted is True
        assert receipt.duplicate is False
        assert receipt.quarantined == []
        assert receipt.payload_hash.root == payload_hash
        assert receipt.hash_version == "aegis-c14n/1"
        assert receipt.event_id.root == envelope["event_id"]

        with _connect(dsn) as connection:
            status, stored_receipt, revision, stored_hash, stored_version = _one(
                connection,
                "SELECT status, receipt, revision, payload_hash, hash_version FROM ingestion_inbox",
            )
            assert status == "accepted"
            assert int(revision) == receipt.revision
            assert str(stored_hash) == payload_hash
            assert str(stored_version) == "aegis-c14n/1"
            validation.validate("ingestion/ingest-receipt.v2.schema.json", stored_receipt)
            assert stored_receipt["duplicate"] is False

            assert _count(connection, "SELECT count(*) FROM graph_revision") == 1
            assert (
                _count(
                    connection,
                    "SELECT count(*) FROM graph_revision WHERE envelope_event_id = %s"
                    " AND causal_job_id = %s",
                    (envelope["event_id"], job_id),
                )
                == 1
            )
            assert _count(connection, "SELECT count(*) FROM ingestion_attempt") == 1
            assert (
                _count(
                    connection,
                    "SELECT count(*) FROM ingestion_attempt WHERE outcome = 'first'"
                    " AND inbox_event_id = event_id",
                )
                == 1
            )

            # Assets, detail rows, aliases and campaign membership.
            assert _count(connection, "SELECT count(*) FROM asset") == 4
            assert (
                _count(
                    connection,
                    "SELECT count(*) FROM asset WHERE normalization_version = 'aegis-norm/1'",
                )
                == 4
            )
            assert _count(connection, "SELECT count(*) FROM asset_campaign") == 4
            service_row = _one(
                connection,
                "SELECT s.ip, s.port, s.transport FROM asset_service s"
                " JOIN asset a ON a.asset_id = s.asset_id"
                " WHERE a.canonical_key = 'service:192.0.2.10:443/tcp'",
            )
            assert (str(service_row[0]), int(service_row[1]), str(service_row[2])) == (
                "192.0.2.10",
                443,
                "tcp",
            )
            alias = _one(
                connection,
                "SELECT al.namespace, al.alias_value FROM asset_alias al"
                " JOIN asset a ON a.asset_id = al.asset_id"
                " WHERE a.canonical_key = 'dns:www.internal.example'",
            )
            assert (str(alias[0]), str(alias[1])) == (
                "original",
                "WWW.Internal.Example",
            )

            # G5: every asset traces to the job's seed, by target id (the seed has no asset row).
            assert _count(connection, "SELECT count(*) FROM asset_provenance") == 4
            assert (
                _count(
                    connection,
                    "SELECT count(*) FROM asset_provenance WHERE from_target_id = %s"
                    " AND source_job_id = %s AND provider = %s",
                    (SEED_ID, job_id, PROVIDER),
                )
                == 4
            )

            # Observations and relationships (open interval + sighting).
            assert _count(connection, "SELECT count(*) FROM observation") == 3
            assert _count(connection, "SELECT count(*) FROM relationship") == 3
            assert _count(connection, "SELECT count(*) FROM relationship_sighting") == 3
            record = _one(
                connection,
                "SELECT value_hash, evidence_ids, polarity FROM observation"
                " WHERE predicate = 'dns.record'",
            )
            expected_value = {"ttl": 300, "type": "A", "value": "192.0.2.10"}
            assert str(record[0]) == canonical.sha256_hex(expected_value)
            assert len(record[1]) == 1

            # Outbox: one asset.discovered per asset, one observation.changed per observation.
            events = connection.execute(
                "SELECT type, payload, producer FROM outbox_event ORDER BY type"
            ).fetchall()
            asset_events = [row for row in events if row[0] == "asset.discovered.v2"]
            observation_events = [row for row in events if row[0] == "observation.changed.v2"]
            assert len(asset_events) == 4
            assert len(observation_events) == 3
            assert {str(row[2]) for row in events} == {"M27"}
            for _type, payload, _producer in events:
                schema = str(_type).replace(".v2", ".v2.schema.json")
                validation.validate(f"events/{schema}", payload)
            asset_payload = cast(dict[str, Any], asset_events[0][1])
            assert int(asset_payload["revision"]) == receipt.revision

            # M27 does not terminalize the job; the collector owns the C06 callback.
            job = _one(
                connection,
                "SELECT status, envelope_event_id FROM scan_job WHERE job_id = %s",
                (job_id,),
            )
            assert str(job[0]) == "QUEUED" and job[1] is None


@requires_postgres
def test_the_accepted_envelope_coverage_is_stored_verbatim() -> None:
    """0009: the accepted result keeps its own coverage, so a reader can tell a complete run.

    The campaign's final reason is computed from this column (M02 `finalize_campaign`): a job that
    reports `complete = false` may not end its campaign as `objective_met`.
    """
    with throwaway_database() as dsn:
        _migrate(dsn)
        with _connect(dsn) as connection:
            seed_campaign(connection)
            job_id = seed_job(connection, "g14a:coverage")
            seed_evidence(connection, job_id, sha256=EVIDENCE_SHA, size_bytes=len(RAW_EVIDENCE))
        service = IngestionService.from_dsn(dsn)
        envelope = _baseline_envelope(job_id)
        envelope["coverage"] = {
            "subjects": ["dns:www.internal.example"],
            "complete": False,
            "limitations": [
                {
                    "code": "EGRESS_PACED",
                    "message": "1 port probe waited past the tool's connect budget",
                    "subjects": ["ip:192.0.2.10"],
                }
            ],
        }
        receipt = service.submit_payload(envelope)
        assert receipt.accepted is True

        with _connect(dsn) as connection:
            stored = _one(connection, "SELECT coverage FROM ingestion_inbox")
        assert stored[0] == envelope["coverage"]

        # A replay never rewrites the stored coverage: the row is append-only.
        replay = service.submit_payload(
            {**_baseline_envelope(job_id, event_id=str(uuid7())), "coverage": envelope["coverage"]}
        )
        assert replay.duplicate is True
        with _connect(dsn) as connection:
            assert _one(connection, "SELECT coverage FROM ingestion_inbox")[0] == stored[0]


def test_replay_returns_the_first_receipt_and_a_conflict_changes_nothing() -> None:
    with throwaway_database() as dsn:
        _migrate(dsn)
        with _connect(dsn) as connection:
            seed_campaign(connection)
            job_id = seed_job(connection, "g14a:replay")
            seed_evidence(connection, job_id, sha256=EVIDENCE_SHA, size_bytes=len(RAW_EVIDENCE))
        service = IngestionService.from_dsn(dsn)
        envelope = _baseline_envelope(job_id)
        first = service.submit_payload(envelope)

        replay_envelope = _baseline_envelope(job_id, event_id=str(uuid7()))
        replay = service.submit_payload(replay_envelope)
        assert replay.duplicate is True
        assert replay.event_id == first.event_id
        assert replay.revision == first.revision
        assert replay.quarantined == first.quarantined
        validation.validate(
            "ingestion/ingest-receipt.v2.schema.json", replay.model_dump(mode="json")
        )

        # A crash-retry that resends the very same event_id is still a duplicate, not an error.
        same_event = service.submit_payload(
            _baseline_envelope(job_id, event_id=first.event_id.root)
        )
        assert same_event.duplicate is True
        assert same_event.event_id == first.event_id

        with _connect(dsn) as connection:
            assert _count(connection, "SELECT count(*) FROM ingestion_inbox") == 1
            attempts: dict[str, int] = {
                str(row[0]): int(cast(int, row[1]))
                for row in connection.execute(
                    "SELECT outcome, count(*) FROM ingestion_attempt GROUP BY outcome"
                ).fetchall()
            }
            assert attempts == {"first": 1, "duplicate": 1}
            tables = ("asset", "observation", "relationship", "graph_revision", "outbox_event")
            counts = {
                table: _count(connection, f"SELECT count(*) FROM {table}") for table in tables
            }

        # The same event_id may not be reused for another logical result.
        with _connect(dsn) as connection:
            other_job = seed_job(connection, "g14a:reused-event")
        reused = _baseline_envelope(other_job, event_id=first.event_id.root)
        with pytest.raises(EnvelopeRejected) as reuse:
            service.submit_payload(reused)
        assert reuse.value.field == "/event_id"

        conflicting = _baseline_envelope(job_id, event_id=str(uuid7()))
        conflicting["results"]["observations"][0]["value"] = {"type": "A", "value": "192.0.2.99"}
        with pytest.raises(IdempotencyConflict) as conflict:
            service.submit_payload(conflicting)
        assert conflict.value.reason == "hash_mismatch"

        with _connect(dsn) as connection:
            assert {
                table: _count(connection, f"SELECT count(*) FROM {table}") for table in tables
            } == counts, "a conflict must not change accepted data, revisions or events"
            stored = _one(connection, "SELECT receipt FROM ingestion_inbox")
            assert stored[0]["event_id"] == first.event_id.root
            conflict_row = _one(
                connection, "SELECT detail FROM ingestion_attempt WHERE outcome = 'conflict'"
            )
            assert conflict_row[0]["reason"] == "hash_mismatch"
            assert conflict_row[0]["existing_payload_hash"] == first.payload_hash.root


@requires_postgres
def test_each_gate_quarantines_only_its_record() -> None:
    with throwaway_database() as dsn:
        _migrate(dsn)
        with _connect(dsn) as connection:
            seed_campaign(connection)
            job_id = seed_job(connection, "g14a:gates")
        service = IngestionService.from_dsn(dsn)
        envelope = build_envelope(
            job_id,
            assets=[
                asset("dns:www.internal.example", "domain"),
                # A key shape aegis-norm/1 has no rule for: quarantined, not invented (G1).
                asset("cloud:aws:ec2:us-east-1:123456789012/i-0123456789abcdef0", "cloud_resource"),
                # Key namespace and declared kind disagree (G1).
                asset("ip:192.0.2.55", "domain"),
                asset("ip:192.0.2.56", "ip"),
            ],
            observations=[
                observation("dns:www.internal.example", "asset.seen", True),
                observation("dns:www.internal.example", "dns.not_registered", True),
                observation("dns:ghost.internal.example", "asset.seen", True),
                observation(
                    "dns:www.internal.example",
                    "dns.record",
                    "not an object",
                ),
                observation(
                    "dns:www.internal.example",
                    "asset.seen",
                    True,
                    evidence_refs=[{"local_ref": "missing"}],
                ),
            ],
            relationships=[
                relationship(
                    "SUBDOMAIN_OF", "dns:www.internal.example", "dns:ghost.internal.example"
                ),
                relationship("ALIAS_OF", "dns:www.internal.example", "dns:www.internal.example"),
            ],
            findings=[finding("dns:www.internal.example", evidence_refs=[{"local_ref": "raw"}])],
            coverage=["dns:ghost.internal.example", "dns:www.internal.example"],
        )

        receipt = service.submit_payload(envelope)

        reasons = {(item.gate.value, item.reason, item.pointer) for item in receipt.quarantined}
        expected = {
            ("G1", "kind_not_supported", "/results/assets/1"),
            ("G1", "canonical_key_kind_mismatch", "/results/assets/2"),
            ("G4", "unknown_predicate", "/results/observations/1"),
            ("G5", "unknown_subject_asset", "/results/observations/2"),
            ("G4", "predicate_value_type_mismatch", "/results/observations/3"),
            ("G3", "evidence_reference_not_stored", "/results/observations/4"),
            ("G5", "unknown_relationship_endpoint", "/results/relationships/0"),
            ("G4", "self_relationship", "/results/relationships/1"),
            ("G4", "finding_candidates_deferred_to_m20", "/results/findings/0"),
            ("G5", "unknown_subject_asset", "/coverage/subjects/0"),
        }
        assert reasons == expected

        with _connect(dsn) as connection:
            assert _count(
                connection,
                "SELECT count(*) FROM quarantine_record WHERE event_id = %s",
                (envelope["event_id"],),
            ) == len(expected)
            inbox_status = _one(connection, "SELECT status FROM ingestion_inbox")
            assert str(inbox_status[0]) == "partially_quarantined"
            # The valid records of the same envelope are still accepted.
            assert _count(connection, "SELECT count(*) FROM asset") == 2
            assert _count(connection, "SELECT count(*) FROM observation") == 1
            assert _count(connection, "SELECT count(*) FROM relationship") == 0
            quarantined = connection.execute(
                "SELECT gate, reason FROM quarantine_record ORDER BY record_pointer"
            ).fetchall()
            assert ("G1", "kind_not_supported") in [(str(g), str(r)) for g, r in quarantined]


@requires_postgres
def test_a_refused_envelope_is_dead_lettered_and_never_accepted() -> None:
    with throwaway_database() as dsn:
        _migrate(dsn)
        with _connect(dsn) as connection:
            seed_campaign(connection)
            job_id = seed_job(connection, "g14a:rejected")
        service = IngestionService.from_dsn(dsn)

        wrong_key = _baseline_envelope(job_id, event_id=str(uuid7()))
        wrong_key["dedup_key"] = "job:00000000-0000-0000-0000-000000000000:envelope"
        with pytest.raises(EnvelopeRejected) as rejected:
            service.submit_payload(wrong_key)
        assert rejected.value.field == "/dedup_key"

        wrong_pin = _baseline_envelope(job_id, event_id=str(uuid7()))
        wrong_pin["provider"]["version"] = "v9.9.9"
        with pytest.raises(EnvelopeRejected) as pinned:
            service.submit_payload(wrong_pin)
        assert pinned.value.field == "/provider/version"

        missing_field = _baseline_envelope(job_id, event_id=str(uuid7()))
        del missing_field["policy_version"]
        with pytest.raises(EnvelopeRejected) as invalid:
            service.submit_payload(missing_field)
        assert invalid.value.code == "INPUT_INVALID"

        # The shared semantic validator refuses a key its rules cannot reproduce, so the whole
        # envelope is dead-lettered instead of storing a second spelling of one asset.
        non_canonical = build_envelope(
            job_id,
            assets=[asset("ip:0:0:0:0:0:0:0:1", "ip")],
            event_id=str(uuid7()),
        )
        with pytest.raises(EnvelopeRejected) as semantic:
            service.submit_payload(non_canonical)
        assert semantic.value.field == "/results/assets/0/canonical_key"

        # A non-finite number has no aegis-c14n/1 form; the dead letter must still be storable.
        non_finite = _baseline_envelope(job_id, event_id=str(uuid7()))
        non_finite["results"]["observations"][0]["value"] = float("nan")
        with pytest.raises(EnvelopeRejected):
            service.submit_payload(non_finite)

        with _connect(dsn) as connection:
            assert _count(connection, "SELECT count(*) FROM ingestion_inbox") == 0
            assert _count(connection, "SELECT count(*) FROM graph_revision") == 0
            assert _count(connection, "SELECT count(*) FROM asset") == 0
            letters = cast(
                list[tuple[Any, ...]],
                connection.execute(
                    "SELECT source, payload, error FROM dead_letter ORDER BY created_at"
                ).fetchall(),
            )
            assert len(letters) == 5
            assert {str(row[0]) for row in letters} == {"ingestion"}
            assert all(str(row[2]["next_action"]) == "FIX_INPUT" for row in letters)
            for row in letters:
                validation.validate("common/error.v2.schema.json", row[2])


@requires_postgres
def test_thousand_concurrent_envelopes_never_duplicate_an_asset() -> None:
    total = 1000
    keys = [f"dns:bulk-{index:03d}.example" for index in range(100)]
    with throwaway_database() as dsn:
        _migrate(dsn)
        with _connect(dsn) as connection:
            seed_campaign(connection)
            jobs = seed_jobs(connection, total)

        service = IngestionService.from_dsn(dsn)
        envelopes = []
        for index, job_id in enumerate(jobs):
            left = keys[index % len(keys)]
            right = keys[(index + 1) % len(keys)]
            envelopes.append(
                build_envelope(
                    job_id,
                    assets=[asset(left, "domain"), asset(right, "domain")],
                    observations=[
                        observation(left, "asset.seen", True),
                        observation(right, "asset.seen", True),
                    ],
                )
            )

        def submit(envelope: dict[str, Any]) -> Any:
            return service.submit_payload(envelope)

        started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=24) as pool:
            receipts = list(pool.map(submit, envelopes))
        elapsed = time.perf_counter() - started

        assert len({receipt.revision for receipt in receipts}) == total
        assert all(receipt.accepted and not receipt.duplicate for receipt in receipts)
        with _connect(dsn) as connection:
            assert _count(connection, "SELECT count(*) FROM asset") == len(keys)
            assert _count(
                connection,
                "SELECT count(*) FROM asset a WHERE a.canonical_key LIKE %s",
                ("dns:bulk-%",),
            ) == len(keys)
            assert _count(connection, "SELECT count(DISTINCT canonical_key) FROM asset") == len(
                keys
            )
            observation_count = _count(connection, "SELECT count(*) FROM observation")
            assert observation_count == 2 * total
            outbox_before = _count(connection, "SELECT count(*) FROM outbox_event")

        # Replay all 1000 logical results with new event ids: a duplicate receipt, no new rows.
        replays = []
        for envelope in envelopes:
            replay = build_envelope(
                envelope["job_id"],
                assets=envelope["results"]["assets"],
                observations=envelope["results"]["observations"],
                event_id=str(uuid7()),
            )
            replays.append(replay)
        with ThreadPoolExecutor(max_workers=24) as pool:
            duplicate_receipts = list(pool.map(submit, replays))
        assert all(receipt.duplicate for receipt in duplicate_receipts)
        assert [receipt.revision for receipt in duplicate_receipts] == [
            receipt.revision for receipt in receipts
        ]
        with _connect(dsn) as connection:
            assert _count(connection, "SELECT count(*) FROM asset") == len(keys)
            assert _count(connection, "SELECT count(*) FROM observation") == observation_count
            assert _count(connection, "SELECT count(*) FROM outbox_event") == outbox_before
            outcomes: dict[str, int] = {
                str(row[0]): int(cast(int, row[1]))
                for row in connection.execute(
                    "SELECT outcome, count(*) FROM ingestion_attempt GROUP BY outcome"
                ).fetchall()
            }
            assert outcomes == {"first": total, "duplicate": total}
        # A useful number for the report, not an assertion of an unmeasured target.
        print(f"concurrency: {total} envelopes in {elapsed:.2f}s ({total / elapsed:.1f}/s)")


# A latency measurement depends on what else the host runs, so the gate leaves it out.
@pytest.mark.benchmark
@requires_postgres
def test_ingestion_p95_for_sub_megabyte_envelopes_is_under_thirty_seconds() -> None:
    samples = 12
    with throwaway_database() as dsn:
        _migrate(dsn)
        with _connect(dsn) as connection:
            seed_campaign(connection)
            jobs = seed_jobs(connection, samples)
        service = IngestionService.from_dsn(dsn)

        durations: list[float] = []
        sizes: list[int] = []
        for index, job_id in enumerate(jobs):
            prefix = f"latency-{index:02d}"
            assets = [
                asset(
                    f"dns:{prefix}-{asset_index:02d}.example",
                    "domain",
                    aliases=[
                        {
                            "namespace": "original",
                            "value": f"{prefix}-{asset_index:02d}-{alias_index}-" + "x" * 980,
                        }
                        for alias_index in range(8)
                    ],
                )
                for asset_index in range(50)
            ]
            observations = [
                observation(
                    f"dns:{prefix}-{asset_index:02d}.example",
                    "http.title",
                    f"{prefix} page {asset_index}",
                )
                for asset_index in range(50)
            ]
            envelope = build_envelope(job_id, assets=assets, observations=observations)
            sizes.append(len(json.dumps(envelope).encode("utf-8")))
            started = time.perf_counter()
            service.submit_payload(envelope)
            durations.append(time.perf_counter() - started)

        ordered = sorted(durations)
        p95 = ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]
        p50 = statistics.median(durations)
        largest = max(sizes)
        print(
            f"ingestion p50={p50 * 1000:.0f}ms p95={p95 * 1000:.0f}ms "
            f"max_envelope={largest / 1024:.0f}KiB samples={samples}"
        )
        assert largest < 1_048_576, "the measurement must stay under the 1 MB NFR envelope"
        assert p95 < 30.0, f"P95 {p95:.2f}s exceeds the 30s NFR"


def test_the_service_implements_the_ingestion_port() -> None:
    from aegis.common.ports import Ingestion

    def never_connect() -> Any:
        raise AssertionError("no connection may be opened here")

    assert isinstance(IngestionService(never_connect), Ingestion)


def test_support_fixture_ids_are_uuidv7() -> None:
    # Event and trace payloads carry Id fields, so fixture ids must satisfy the v2 pattern.
    for value in (str(uuid7()), CAMPAIGN_ID, SCOPE_ID, SEED_ID):
        assert value[14] == "7" and value[19] in "89ab", value
    assert IMAGE_DIGEST.startswith("sha256:")
    assert FINISHED_AT.endswith("Z")
    assert POLICY_VERSION.startswith("roe-") and PROVIDER_VERSION.startswith("v")
