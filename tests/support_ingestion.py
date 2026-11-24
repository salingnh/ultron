"""Builders and fixtures for the M27 (G1.4a) tests: campaigns/jobs/evidence and envelopes.

The DB helpers insert rows the way the owning modules would: the campaign/scope/policy rows of M01,
a policy decision and scan_job of M05, and `evidence` metadata of M28. M27 must never create those
rows itself, so the tests build them explicitly and only exercise the ingestion transaction.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from aegis.m27_ingestion.ids import uuid7

CAMPAIGN_ID = "01900000-0000-7000-8000-0000000c0001"
SCOPE_ID = "01900000-0000-7000-8000-0000000c0002"
SEED_ID = "01900000-0000-7000-8000-0000000c0003"
SEED_ASSET_KEY = "dns:seed.internal.example"
POLICY_VERSION = "roe-1"
CAPABILITY = "dns.enumerate_subdomains"
PROVIDER = "subfinder"
PROVIDER_VERSION = "v2.6.6"
TRACE = "0123456789abcdef0123456789abcdef"
FINISHED_AT = "2026-11-24T10:00:00Z"
STARTED_AT = "2026-11-24T09:59:00Z"
INPUT_FINGERPRINT = "a" * 64
IMAGE_DIGEST = "sha256:" + "d" * 64
ACTOR = {"kind": "operator", "id": "fixture-operator"}
POLICY = '{"max_parallel_jobs": 10, "max_duration_hours": 168}'


def seed_campaign(connection: psycopg.Connection[tuple[object, ...]]) -> None:
    """Campaign + scope + policy + one domain seed, in the shape the DDL accepts.

    M01 writes the snapshot before the campaign row, so the two deferred FKs require one
    transaction; a caller connection in autocommit mode is wrapped here.
    """
    with connection.transaction():
        _seed_campaign_rows(connection)


def _seed_campaign_rows(connection: psycopg.Connection[tuple[object, ...]]) -> None:
    connection.execute(
        "INSERT INTO policy_snapshot (policy_version, campaign_id, policy, policy_hash, created_by)"
        " VALUES (%s, %s, %s, %s, %s)",
        (POLICY_VERSION, CAMPAIGN_ID, POLICY, "1" * 64, Jsonb(ACTOR)),
    )
    connection.execute(
        "INSERT INTO scope_snapshot (scope_id, campaign_id, targets) VALUES (%s, %s, %s)",
        (SCOPE_ID, CAMPAIGN_ID, Jsonb({"domains": ["seed.internal.example"]})),
    )
    connection.execute(
        "INSERT INTO campaign (campaign_id, name, objective, current_policy_version, scope_id,"
        " created_by) VALUES (%s, 'G1.4a fixture', 'M27 ingestion', %s, %s, %s)",
        (CAMPAIGN_ID, POLICY_VERSION, SCOPE_ID, Jsonb(ACTOR)),
    )
    connection.execute(
        "INSERT INTO campaign_target (target_id, scope_id, kind, raw_value, canonical_key)"
        " VALUES (%s, %s, 'domain', 'seed.internal.example', %s)",
        (SEED_ID, SCOPE_ID, SEED_ASSET_KEY),
    )


def _decision(
    connection: psycopg.Connection[tuple[object, ...]], decision_id: str, key: str, input_json: str
) -> None:
    connection.execute(
        "INSERT INTO policy_decision (decision_id, campaign_id, capability, provider, targets,"
        " input, decision, rationale, requested_by, target_refs, policy_version, scope_id,"
        " idempotency_key, trace_id) VALUES (%s, %s, %s, %s, '{}', %s, 'approved', 'G1.4a', %s,"
        " %s, %s, %s, %s, %s)",
        (
            decision_id,
            CAMPAIGN_ID,
            CAPABILITY,
            PROVIDER,
            input_json,
            Jsonb(ACTOR),
            Jsonb([{"seed_id": SEED_ID}]),
            POLICY_VERSION,
            SCOPE_ID,
            key,
            TRACE,
        ),
    )


def seed_job(connection: psycopg.Connection[tuple[object, ...]], key: str) -> str:
    """One approved decision + one QUEUED job with the pins and target_refs M27 checks."""
    decision_id = str(uuid7())
    job_id = str(uuid7())
    input_json = '{"domains": ["seed.internal.example"]}'
    _decision(connection, decision_id, key, input_json)
    connection.execute(
        "INSERT INTO scan_job (job_id, campaign_id, decision_id, capability, provider,"
        " provider_version, adapter_version, image_digest, manifest_sha256, scan_cycle,"
        " job_fingerprint, policy_version, scope_id, input, targets, target_refs, requested_by,"
        " rationale, trace_id) VALUES (%s, %s, %s, %s, %s, %s, '1.0.0', %s, %s, %s, %s, %s, %s,"
        " %s, '{}', %s, %s, 'G1.4a', %s)",
        (
            job_id,
            CAMPAIGN_ID,
            decision_id,
            CAPABILITY,
            PROVIDER,
            PROVIDER_VERSION,
            IMAGE_DIGEST,
            "b" * 64,
            str(uuid7()),
            uuid.uuid5(uuid.NAMESPACE_URL, f"fingerprint:{key}").hex,
            POLICY_VERSION,
            SCOPE_ID,
            input_json,
            Jsonb([{"seed_id": SEED_ID}]),
            Jsonb(ACTOR),
            TRACE,
        ),
    )
    return job_id


def seed_jobs(connection: psycopg.Connection[tuple[object, ...]], count: int) -> list[str]:
    """`count` independent jobs (one envelope per job is one logical result), in one transaction."""
    jobs: list[str] = []
    with connection.transaction():
        for index in range(count):
            jobs.append(seed_job(connection, f"g14a:{index}"))
    return jobs


def seed_evidence(
    connection: psycopg.Connection[tuple[object, ...]],
    job_id: str,
    *,
    sha256: str,
    size_bytes: int,
    media_type: str = "application/json",
) -> str:
    """Evidence metadata as M28 writes it before the collector posts the envelope."""
    evidence_id = str(uuid7())
    uri = f"s3://evidence/{CAMPAIGN_ID}/{job_id}/{sha256}"
    connection.execute(
        "INSERT INTO evidence (evidence_id, sha256, storage_uri, campaign_id, job_id,"
        " size_bytes, media_type, kind, classification, source_tool)"
        " VALUES (%s, %s, %s, %s, %s, %s, %s, 'raw_output', 'INTERNAL', %s)",
        (evidence_id, sha256, uri, CAMPAIGN_ID, job_id, size_bytes, media_type, PROVIDER),
    )
    return evidence_id


def asset(
    canonical_key: str,
    kind: str,
    *,
    aliases: Sequence[dict[str, Any]] | None = None,
    discovered_from: Sequence[str] | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {"kind": kind, "canonical_key": canonical_key}
    if aliases is not None:
        item["aliases"] = list(aliases)
    if discovered_from is not None:
        item["discovered_from"] = list(discovered_from)
    return item


def observation(
    subject: str,
    predicate: str,
    value: object,
    *,
    evidence_refs: Sequence[dict[str, Any]] | None = None,
    polarity: str | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "subject": subject,
        "predicate": predicate,
        "value": value,
        "observed_at": FINISHED_AT,
    }
    if evidence_refs is not None:
        item["evidence_refs"] = list(evidence_refs)
    if polarity is not None:
        item["polarity"] = polarity
    return item


def relationship(
    relation_type: str,
    source: str,
    target: str,
    *,
    confidence: float = 0.9,
    evidence_refs: Sequence[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "type": relation_type,
        "from": source,
        "to": target,
        "observed_at": FINISHED_AT,
        "confidence": confidence,
    }
    if evidence_refs is not None:
        item["evidence_refs"] = list(evidence_refs)
    return item


def finding(subject: str, *, evidence_refs: Sequence[dict[str, Any]]) -> dict[str, Any]:
    return {
        "subject": subject,
        "rule_id": "cve:CVE-2024-0001",
        "title": "fixture finding",
        "evidence_refs": list(evidence_refs),
        "fingerprint_context": {"path": "/"},
    }


def build_envelope(
    job_id: str,
    *,
    assets: Sequence[dict[str, Any]] = (),
    observations: Sequence[dict[str, Any]] = (),
    relationships: Sequence[dict[str, Any]] = (),
    findings: Sequence[dict[str, Any]] = (),
    evidence: Sequence[dict[str, Any]] = (),
    coverage: Sequence[str] = (),
    event_id: str | None = None,
    dedup_key: str | None = None,
    campaign_id: str = CAMPAIGN_ID,
    scope_id: str = SCOPE_ID,
    policy_version: str = POLICY_VERSION,
    provider_name: str = PROVIDER,
    provider_version: str = PROVIDER_VERSION,
    seed_targets: Sequence[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """A ResultEnvelope as the collector posts it (JSON-ready dict)."""
    return {
        "schema_version": "2.0",
        "event_id": event_id or str(uuid7()),
        "dedup_key": dedup_key or f"job:{job_id}:envelope",
        "job_id": job_id,
        "campaign_id": campaign_id,
        "scope_id": scope_id,
        "capability": CAPABILITY,
        "provider": {
            "name": provider_name,
            "version": provider_version,
            "adapter_version": "1.0.0",
            "image_digest": IMAGE_DIGEST,
        },
        "policy_version": policy_version,
        "status": "succeeded",
        "coverage": {"subjects": list(coverage), "complete": True},
        "results": {
            "assets": list(assets),
            "observations": list(observations),
            "relationships": list(relationships),
            "findings": list(findings),
        },
        "evidence": list(evidence),
        "errors": [],
        "provenance": {
            "input_fingerprint": INPUT_FINGERPRINT,
            "started_at": STARTED_AT,
            "finished_at": FINISHED_AT,
            "seed_targets": list(seed_targets or [{"seed_id": SEED_ID}]),
        },
        "trace": {"trace_id": TRACE, "job_id": job_id, "campaign_id": campaign_id},
    }
