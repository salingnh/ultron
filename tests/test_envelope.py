"""Collector-side envelope assembly and delivery (M06 → M27; interfaces §3, C03).

The envelope is checked against the contract schema through `aegis.validation`, so a field the
contract forbids (or a missing pin) fails here rather than in M27.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from aegis.common.ports import EvidenceObject
from aegis.contracts_gen.common.ids_v2_schema import Classification
from aegis.m06_runner import envelope as envelopes
from aegis.m06_runner.collector import CollectedFile

from . import m06_support

UUID7 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
JOB = envelopes.new_id()
INPUT = {"targets": ["internal.example"], "concurrency": 2, "rate_limit": 1}


def _results() -> dict[str, Any]:
    return {
        "assets": [
            {
                "kind": "domain",
                "canonical_key": "dns:a.internal.example",
                "discovered_from": ["dns:internal.example"],
                "confidence": 0.6,
                "evidence_refs": [{"local_ref": "result-jsonl"}],
            }
        ],
        "observations": [
            {
                "subject": "dns:a.internal.example",
                "predicate": "asset.seen",
                "value": True,
                "observed_at": "2026-11-24T00:00:00Z",
                "confidence": 0.6,
                "evidence_refs": [{"local_ref": "result-jsonl"}],
            }
        ],
        "relationships": [],
        "findings": [],
        "coverage": {"subjects": ["dns:a.internal.example"], "complete": True},
    }


def _evidence() -> list[envelopes.EnvelopeEvidence]:
    return [
        envelopes.EnvelopeEvidence(
            local_ref="result-jsonl",
            sha256="b" * 64,
            uri=f"s3://evidence/{m06_support.approved_task().campaign_id.root}/{JOB}/" + "b" * 64,
            size_bytes=12,
            media_type="application/x-ndjson",
            classification="INTERNAL",
        )
    ]


def _task(**overrides: Any) -> Any:
    defaults: dict[str, Any] = {
        "targets": [{"canonical_key": "dns:internal.example"}],
        "input": dict(INPUT),
    }
    defaults.update(overrides)
    return m06_support.approved_task(**defaults)


def _build(**overrides: Any) -> Any:
    manifest, _raw = m06_support.manifest()
    values: dict[str, Any] = {
        "task": _task(),
        "manifest": manifest,
        "job_id": JOB,
        "input_values": dict(INPUT),
        "results": _results(),
        "evidence": _evidence(),
        "status": "succeeded",
        "started_at": "2026-11-24T00:00:00Z",
        "finished_at": "2026-11-24T00:00:10Z",
        "exit_code": 0,
    }
    values.update(overrides)
    return envelopes.build_envelope(**values)


def test_envelope_carries_the_pins_and_the_dedup_key() -> None:
    task = _task()
    built = _build(task=task)
    from aegis.m06_runner.values import text

    assert UUID7.fullmatch(text(built.event_id)), text(built.event_id)
    assert built.dedup_key == f"job:{JOB}:envelope"
    assert built.campaign_id.root == task.campaign_id.root
    provider = built.provider
    assert str(provider.name) == "subfinder"
    assert str(provider.version) == "v2.17.0"
    assert str(provider.adapter_version.root) == "1.0.0"
    assert str(provider.image_digest.root) == task.image_digest.root
    assert built.provenance.seed_targets[0].model_dump() == task.targets[0].model_dump()
    assert built.status == "succeeded"
    assert built.provenance.exit_code == 0


def test_input_fingerprint_is_the_contract_canonical_hash() -> None:
    values = dict(INPUT)
    expected = envelopes.input_fingerprint(values)
    assert len(expected) == 64
    reordered = {"rate_limit": 1, "concurrency": 2, "targets": ["internal.example"]}
    assert expected == envelopes.input_fingerprint(reordered)
    assert expected != envelopes.input_fingerprint({**INPUT, "concurrency": 3})
    built = _build()
    assert str(built.provenance.input_fingerprint.root) == expected


def test_event_id_changes_per_submission_but_dedup_key_does_not() -> None:
    first = _build()
    second = _build()
    assert first.event_id != second.event_id
    assert first.dedup_key == second.dedup_key


def test_results_without_coverage_are_refused() -> None:
    results = _results()
    del results["coverage"]
    with pytest.raises(envelopes.EnvelopeError) as caught:
        _build(results=results)
    assert caught.value.code == "OUTPUT_INVALID"


def test_missing_seed_targets_are_refused_by_the_contract() -> None:
    task = _task()
    payload = {
        "task": task,
        "manifest": m06_support.manifest()[0],
        "job_id": JOB,
        "input_values": dict(INPUT),
        "results": _results(),
        "evidence": [],
        "status": "failed",
        "started_at": "2026-11-24T00:00:00Z",
        "finished_at": "2026-11-24T00:00:10Z",
    }
    built = envelopes.build_envelope(**payload)
    assert built.provenance.seed_targets


def test_error_object_is_contract_valid() -> None:
    error = envelopes.error_object(
        "OUTPUT_INVALID", "parser failed", technical_cause="Traceback ...", retryable=False
    )
    assert error["code"] == "OUTPUT_INVALID"
    assert error["next_action"] == "ESCALATE"


def test_http_client_posts_with_the_service_token_and_dedups() -> None:
    fake = m06_support.FakeIngestion().start()
    try:
        client = envelopes.HttpIngestionClient(fake.base_url, fake.service_token)
        built = _build()
        first = envelopes.submit(client, built)
        assert first.accepted is True
        assert first.duplicate is False
        second = envelopes.submit(client, built)
        assert second.duplicate is True
        assert second.event_id.root == first.event_id.root
        assert len(fake.received) == 2
        sent = fake.received[0]
        assert sent.headers["X-Aegis-Service-Token"] == fake.service_token
        assert sent.body["dedup_key"] == f"job:{JOB}:envelope"
        assert sent.body["schema_version"] == "2.0"
        assert sent.body["evidence"][0]["uri"].startswith("s3://evidence/")
    finally:
        fake.stop()


def test_http_client_ignores_host_proxy_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = m06_support.FakeIngestion().start()
    try:
        # A job proxy must never capture control-plane ingestion traffic.
        monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
        monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
        monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9")
        client = envelopes.HttpIngestionClient(fake.base_url, fake.service_token, timeout_seconds=5)
        receipt = envelopes.submit(client, _build())
        assert receipt.accepted is True
    finally:
        fake.stop()


def test_http_client_reports_a_bad_token() -> None:
    fake = m06_support.FakeIngestion().start()
    try:
        client = envelopes.HttpIngestionClient(fake.base_url, "wrong-token")
        with pytest.raises(envelopes.EnvelopeError) as caught:
            envelopes.submit(client, _build())
        assert caught.value.code == "INGESTION_HTTP_ERROR"
    finally:
        fake.stop()


def test_http_client_reports_an_unreachable_endpoint() -> None:
    port = m06_support.free_port()
    client = envelopes.HttpIngestionClient(f"http://127.0.0.1:{port}", "token", timeout_seconds=2)
    with pytest.raises(envelopes.EnvelopeError) as caught:
        envelopes.submit(client, _build())
    assert caught.value.code == "INGESTION_UNREACHABLE"


def test_envelope_snapshot_round_trips(tmp_path: Path) -> None:
    built = _build()
    path = tmp_path / "envelope.json"
    path.write_text(json.dumps(envelopes.envelope_document(built)), encoding="utf-8")
    loaded = envelopes.read_envelope(path)
    assert loaded.model_dump(mode="json") == built.model_dump(mode="json")


def test_evidence_reference_uses_the_collector_local_ref() -> None:
    collected = CollectedFile(
        relative_path="result.jsonl",
        local_ref="result-jsonl",
        size_bytes=10,
        sha256="c" * 64,
        media_type="application/x-ndjson",
    )
    reference = envelopes.evidence_reference(
        collected, uri="s3://evidence/x", classification=str(Classification.INTERNAL)
    )
    assert reference.local_ref == "result-jsonl"
    assert reference.kind == "raw_output"


def test_evidence_object_port_shape_is_what_the_envelope_claims() -> None:
    task = _task()
    stored = EvidenceObject(
        evidence_id="d" * 64,
        campaign_id=str(m06_support.approved_task().campaign_id.root),
        job_id=JOB,
        sha256="d" * 64,
        uri=f"s3://evidence/{task.campaign_id.root}/{JOB}/" + "d" * 64,
        media_type="text/plain",
        classification=Classification.PUBLIC,
    )
    reference = envelopes.EnvelopeEvidence(
        local_ref="raw",
        sha256=stored.sha256,
        uri=stored.uri,
        size_bytes=1,
        media_type=stored.media_type,
        classification="PUBLIC",
    )
    built = _build(evidence=[reference])
    assert built.evidence[0].local_ref == "raw"
    assert built.evidence[0].classification == Classification.PUBLIC


# --- the parser result shape the adapters really produce (G1.5c) ------------------------------
# `contracts/tests/conformance/harness.py` hands a parser one evidence entry named `raw`, lets it
# report `coverage_subjects`, and the collector stamps `observed_at`. The adapters follow that, so
# the collector must accept it: a real job's envelope would otherwise be rejected (or worse, its
# records quarantined by M27), which is what the G1.5c demo found.


def test_the_collector_turns_coverage_subjects_into_the_envelope_coverage() -> None:
    results = {
        "assets": [],
        "observations": [
            {"subject": "dns:a.internal.example", "predicate": "asset.seen", "value": True}
        ],
        "relationships": [],
        "findings": [],
        "coverage_subjects": ["dns:internal.example", "dns:b.internal.example"],
    }
    built = _build(results=results)
    from aegis.m06_runner.values import text as plain

    assert [plain(item) for item in built.coverage.subjects] == [
        "dns:b.internal.example",
        "dns:internal.example",
    ]
    assert built.coverage.complete is True


def test_the_collector_stamps_observed_at_on_every_record() -> None:
    results = {
        "assets": [],
        "observations": [
            {"subject": "dns:a.internal.example", "predicate": "asset.seen", "value": True}
        ],
        "relationships": [
            {
                "type": "SUBDOMAIN_OF",
                "from": "dns:a.internal.example",
                "to": "dns:internal.example",
                "confidence": 1.0,
            }
        ],
        "findings": [],
        "coverage_subjects": ["dns:internal.example"],
    }
    from datetime import UTC, datetime

    built = _build(results=results, finished_at="2026-11-24T06:00:00Z")
    stamped = datetime(2026, 11, 24, 6, 0, tzinfo=UTC)
    observation_at = built.results.observations[0].observed_at
    assert observation_at is not None and observation_at.root == stamped
    relationship_at = built.results.relationships[0].observed_at
    assert relationship_at is not None and relationship_at.root == stamped


def test_a_partial_run_keeps_its_subjects_but_not_a_complete_claim() -> None:
    results = {
        "assets": [],
        "observations": [],
        "relationships": [],
        "findings": [],
        "coverage_subjects": ["dns:internal.example"],
        "coverage": {"subjects": ["dns:internal.example"], "complete": False},
    }
    built = _build(results=results, status="partial")
    from aegis.m06_runner.values import text as plain

    assert built.coverage.complete is False
    assert [plain(item) for item in built.coverage.subjects] == ["dns:internal.example"]


def test_parser_results_without_coverage_are_still_refused() -> None:
    results: dict[str, Any] = {
        "assets": [],
        "observations": [],
        "relationships": [],
        "findings": [],
    }
    with pytest.raises(envelopes.EnvelopeError, match="coverage_subjects"):
        _build(results=results)
