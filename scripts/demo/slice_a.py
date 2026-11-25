"""The G1.6 slice A stand-in of `make demo-g16c`: a fingerprinted service, ingested by M27.

Slice C starts where slice A ends: a service asset with `service.product` / `http.technology`
observations that carry a CPE and a version. Slice A's adapters (Naabu, fingerprintx/httpx) are a
separate task, so until they land this module plays their part at the *contract seam* and nowhere
else:

* it inserts the rows M05 writes for one approved job (a `policy_decision` and a `scan_job` with
  the campaign's own policy/scope and the seed target as `target_refs`); and
* it submits one `result-envelope.v2` through `IngestionService` - the same port the collector
  posts to - with the service/application assets and the observations slice A will produce.

So the demo exercises the real M27 transaction (assets, detail rows, observations, outbox events);
only the scanner output is a fixture. When slice A lands, delete this file and let its adapters
post the same envelope.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from typing import Any

from aegis.m27_ingestion.ids import uuid7
from aegis.m27_ingestion.service import IngestionService

CAPABILITY = "network.discover_services"
PROVIDER = "fingerprintx"
PROVIDER_VERSION = "v1.1.0"
ADAPTER_VERSION = "1.0.0"
IMAGE_DIGEST = "sha256:" + "d" * 64
MANIFEST_SHA256 = "b" * 64
ACTOR = {"kind": "operator", "id": "demo-g16c"}
TRACE = "0123456789abcdef0123456789abcdef"

#: What slice A's adapters will report for the lab: an old Apache on :80, nginx on :8080 and the
#: Spring application that nginx serves. The CPE strings are the fingerprinters' own vocabulary.
SERVICES: tuple[dict[str, Any], ...] = (
    {
        "key": "service:10.114.53.10:80/tcp",
        "kind": "service",
        "product": {
            "product": "Apache httpd",
            "version": "2.4.49",
            "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        },
    },
    {
        "key": "service:10.114.53.10:8080/tcp",
        "kind": "service",
        "product": {
            "product": "nginx",
            "version": "1.18.0",
            "cpe": "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*",
        },
    },
)
APPLICATION: dict[str, Any] = {
    "key": "app:http://10.114.53.10:8080",
    "kind": "application",
    "technologies": [
        "cpe:2.3:a:vmware:spring_framework:5.3.17:*:*:*:*:*:*:*",
        "Spring Boot",
    ],
}


def _moment() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _seed(connection: Any, campaign_id: str) -> tuple[str, str, str, str]:
    campaign = connection.execute(
        "SELECT current_policy_version, scope_id FROM campaign WHERE campaign_id = %s",
        (campaign_id,),
    ).fetchone()
    if campaign is None:
        raise RuntimeError(f"campaign {campaign_id} does not exist")
    target = connection.execute(
        "SELECT target_id, canonical_key FROM campaign_target WHERE scope_id = %s"
        " ORDER BY target_id LIMIT 1",
        (campaign["scope_id"],),
    ).fetchone()
    if target is None:
        raise RuntimeError(f"campaign {campaign_id} has no seed target")
    return (
        str(campaign["current_policy_version"]),
        str(campaign["scope_id"]),
        str(target["target_id"]),
        str(target["canonical_key"]),
    )


def _job(
    connection: Any,
    campaign_id: str,
    scope_id: str,
    policy_version: str,
    seed_id: str,
    seed_key: str,
) -> str:
    """A policy decision and a QUEUED job with the pins M27 checks (the rows M05 writes)."""
    decision_id, job_id = str(uuid7()), str(uuid7())
    # `targets` must be the canonical-key projection of `target_refs` (0001 trigger), and a
    # `canonical_key` ref resolves to the seed asset the campaign was created with.
    target_refs = [{"canonical_key": seed_key}]
    input_json = f'{{"targets": ["{seed_key}"]}}'
    with connection.transaction():
        connection.execute(
            "INSERT INTO policy_decision (decision_id, campaign_id, capability, provider, targets,"
            " input, decision, rationale, requested_by, target_refs, policy_version, scope_id,"
            " idempotency_key, trace_id)"
            " VALUES (%s, %s, %s, %s, '{}', %s, 'approved', 'G1.6c demo', %s, %s, %s, %s, %s, %s)",
            (
                decision_id,
                campaign_id,
                CAPABILITY,
                PROVIDER,
                input_json,
                _json(ACTOR),
                _json(target_refs),
                policy_version,
                scope_id,
                f"demo-g16c:{job_id}",
                TRACE,
            ),
        )
        connection.execute(
            "INSERT INTO scan_job (job_id, campaign_id, decision_id, capability, provider,"
            " provider_version, adapter_version, image_digest, manifest_sha256, scan_cycle,"
            " job_fingerprint, policy_version, scope_id, input, targets, target_refs, requested_by,"
            " rationale, trace_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,"
            " %s, %s, %s, 'G1.6c demo', %s)",
            (
                job_id,
                campaign_id,
                decision_id,
                CAPABILITY,
                PROVIDER,
                PROVIDER_VERSION,
                ADAPTER_VERSION,
                IMAGE_DIGEST,
                MANIFEST_SHA256,
                str(uuid7()),
                uuid.uuid5(uuid.NAMESPACE_URL, f"g16c:{job_id}").hex,
                policy_version,
                scope_id,
                input_json,
                [seed_key],
                _json(target_refs),
                _json(ACTOR),
                TRACE,
            ),
        )
    return job_id


def _json(value: Any) -> Any:
    from psycopg.types.json import Jsonb

    return Jsonb(value)


def _envelope(
    campaign_id: str, scope_id: str, policy_version: str, seed_key: str, job_id: str
) -> dict[str, Any]:
    moment = _moment()
    assets = [
        {"kind": item["kind"], "canonical_key": item["key"], "discovered_from": []}
        for item in SERVICES
    ]
    assets.append(
        {"kind": APPLICATION["kind"], "canonical_key": APPLICATION["key"], "discovered_from": []}
    )
    observations = [
        {
            "subject": item["key"],
            "predicate": "service.product",
            "value": item["product"],
            "observed_at": moment,
        }
        for item in SERVICES
    ]
    observations.append(
        {
            "subject": APPLICATION["key"],
            "predicate": "http.technology",
            "value": APPLICATION["technologies"],
            "observed_at": moment,
        }
    )
    subjects = [item["key"] for item in (*SERVICES, APPLICATION)]
    return {
        "schema_version": "2.0",
        "event_id": str(uuid7()),
        "dedup_key": f"job:{job_id}:envelope",
        "job_id": job_id,
        "campaign_id": campaign_id,
        "scope_id": scope_id,
        "capability": CAPABILITY,
        "provider": {
            "name": PROVIDER,
            "version": PROVIDER_VERSION,
            "adapter_version": ADAPTER_VERSION,
            "image_digest": IMAGE_DIGEST,
        },
        "policy_version": policy_version,
        "status": "succeeded",
        "coverage": {"subjects": subjects, "complete": True},
        "results": {
            "assets": assets,
            "observations": observations,
            "relationships": [],
            "findings": [],
        },
        "evidence": [],
        "errors": [],
        "provenance": {
            "input_fingerprint": "a" * 64,
            "started_at": moment,
            "finished_at": moment,
            "seed_targets": [{"canonical_key": seed_key}],
        },
        "trace": {"trace_id": TRACE, "job_id": job_id, "campaign_id": campaign_id},
    }


def ingest_services(connection: Any, campaign_id: str) -> dict[str, Any]:
    """Seed the job, submit the envelope through M27 and return what the demo asserts on."""
    policy_version, scope_id, seed_id, seed_key = _seed(connection, campaign_id)
    job_id = _job(connection, campaign_id, scope_id, policy_version, seed_id, seed_key)
    dsn = os.environ.get("AEGIS_PG_DSN")
    if not dsn:
        raise RuntimeError("AEGIS_PG_DSN is not set")
    receipt = IngestionService.from_dsn(dsn).submit_payload(
        _envelope(campaign_id, scope_id, policy_version, seed_key, job_id)
    )
    assets = {
        str(row["canonical_key"]): str(row["asset_id"])
        for row in connection.execute(
            "SELECT canonical_key, asset_id FROM asset WHERE canonical_key = ANY(%s)",
            ([item["key"] for item in (*SERVICES, APPLICATION)],),
        ).fetchall()
    }
    return {
        "job_id": job_id,
        "receipt": receipt.model_dump(mode="json"),
        "assets": assets,
        "subjects": [item["key"] for item in (*SERVICES, APPLICATION)],
    }
