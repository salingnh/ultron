"""Collector-side envelope assembly and the ingestion POST (M06 → M27; interfaces §3).

The collector is the only component that turns raw files into a `ResultEnvelope`:

* `event_id` is a fresh UUIDv7 per submission, `dedup_key` is `job:<job_id>:envelope`, so a retry
  reuses the lookup key while the submission id stays new (C03).
* `provider`, `policy_version`, `provenance.seed_targets` are copied from the approved task, so the
  envelope cannot claim a pin the job was not approved with.
* `provenance.input_fingerprint` is the SHA-256 of the accepted input under `aegis-c14n/1`.
* `observed_at` is stamped here: the parser is pure and never reads the clock.
* the finished document is validated with the shared `aegis.validation` hook before it is sent.

`canonicalization.v2.yaml` says a service may use any implementation that reproduces the reference
bytes; this module loads the contract's reference implementation by path (the same pattern
`aegis.validation` uses for `contracts/validation.py`) instead of writing a second canonicalizer
that could drift from the golden vectors.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cache
from pathlib import Path
from types import ModuleType
from typing import Any, Protocol, cast

from aegis import validation
from aegis.common.repo import repository_root
from aegis.contracts_gen.capability.approved_task_v2_schema import ApprovedTask
from aegis.contracts_gen.capability.provider_manifest_v2_schema import ProviderManifest
from aegis.contracts_gen.ingestion.ingest_receipt_v2_schema import IngestReceipt
from aegis.contracts_gen.ingestion.result_envelope_v2_schema import ResultEnvelope
from aegis.m06_runner.collector import CollectedFile
from aegis.m06_runner.values import text

ENVELOPE_SCHEMA = "ingestion/result-envelope.v2.schema.json"
ERROR_SCHEMA = "common/error.v2.schema.json"
DEDUP_KEY = "job:{job_id}:envelope"
SERVICE_TOKEN_HEADER = "X-Aegis-Service-Token"
INGESTION_PATH = "/api/v2/ingestion/results"
DEFAULT_KIND = "raw_output"


class EnvelopeError(RuntimeError):
    """The collector cannot build or deliver an envelope; carries the contract error code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


class IngestionClient(Protocol):
    """The `Ingestion` port (interfaces §6) at the wire level."""

    def submit(self, envelope: ResultEnvelope) -> IngestReceipt: ...


class _Canonicalizer(Protocol):
    def canonical_bytes(self, value: object) -> bytes: ...


@cache
def _canonicalizer() -> _Canonicalizer:
    path = repository_root() / "contracts" / "tests" / "canonicalization.py"
    spec = importlib.util.spec_from_file_location("aegis_contract_canonicalization", path)
    if spec is None or spec.loader is None:
        raise EnvelopeError("INTERNAL_ERROR", f"cannot load {path}")
    module: ModuleType = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as error:  # noqa: BLE001 - one loud, typed failure
        raise EnvelopeError("INTERNAL_ERROR", f"cannot import {path}: {error}") from error
    return cast(_Canonicalizer, module)


def canonical_bytes(value: object) -> bytes:
    return _canonicalizer().canonical_bytes(value)


def input_fingerprint(input_values: Mapping[str, Any]) -> str:
    """SHA-256 of the accepted input under `aegis-c14n/1` (C03)."""
    return hashlib.sha256(canonical_bytes(dict(input_values))).hexdigest()


def now_timestamp() -> str:
    """RFC 3339 UTC with the `Z` suffix the contract's `Timestamp` requires."""
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def new_id() -> str:
    """A UUIDv7 (RFC 9562): 48-bit millisecond prefix, version 7, variant 10."""
    millis = int(time.time() * 1000) & ((1 << 48) - 1)
    random_bits = int.from_bytes(os.urandom(10), "big")
    rand_a = random_bits >> 68
    rand_b = random_bits & ((1 << 62) - 1)
    value = (millis << 80) | (0x7 << 76) | (rand_a << 64) | (0b10 << 62) | rand_b
    return str(uuid.UUID(int=value))


def dedup_key(job_id: str) -> str:
    return DEDUP_KEY.format(job_id=job_id)


@dataclass(frozen=True)
class EnvelopeEvidence:
    """One raw output file as the envelope references it (contract `$defs/Evidence`)."""

    local_ref: str
    sha256: str
    uri: str
    size_bytes: int
    media_type: str
    classification: str
    kind: str = DEFAULT_KIND


def evidence_reference(
    collected: CollectedFile,
    *,
    uri: str,
    classification: str,
    kind: str = DEFAULT_KIND,
) -> EnvelopeEvidence:
    return EnvelopeEvidence(
        local_ref=collected.local_ref,
        sha256=collected.sha256,
        uri=uri,
        size_bytes=collected.size_bytes,
        media_type=collected.media_type,
        classification=classification,
        kind=kind,
    )


def error_object(
    code: str,
    message: str,
    *,
    technical_cause: str | None = None,
    next_action: str = "ESCALATE",
    retryable: bool = False,
) -> dict[str, Any]:
    """A contract `Error` object for the envelope's `errors[]`."""
    payload: dict[str, Any] = {
        "code": code,
        "message": message,
        "next_action": next_action,
        "retryable": retryable,
    }
    if technical_cause:
        payload["technical_cause"] = technical_cause[:4000]
    validation.validate(ERROR_SCHEMA, payload)
    return payload


def build_envelope(
    *,
    task: ApprovedTask,
    manifest: ProviderManifest,
    job_id: str,
    input_values: Mapping[str, Any],
    results: Mapping[str, Any],
    evidence: Sequence[EnvelopeEvidence],
    status: str,
    started_at: str,
    finished_at: str,
    exit_code: int | None = None,
    errors: Sequence[Mapping[str, Any]] = (),
) -> ResultEnvelope:
    """Assemble and validate the envelope of one finished job."""
    coverage = results.get("coverage")
    if not isinstance(coverage, Mapping):
        raise EnvelopeError("OUTPUT_INVALID", "parser results have no coverage object")
    if manifest.spec.runtime.outputPath is None:  # pragma: no cover - schema default is "/out"
        raise EnvelopeError("DEPENDENCY_MISSING", "pinned manifest declares no outputPath")
    payload: dict[str, Any] = {
        "schema_version": "2.0",
        "event_id": new_id(),
        "dedup_key": dedup_key(job_id),
        "job_id": job_id,
        "campaign_id": text(task.campaign_id),
        "scope_id": text(task.scope_id),
        "capability": text(task.capability),
        "provider": {
            "name": str(task.provider),
            "version": str(task.provider_version),
            "adapter_version": text(task.adapter_version),
            "image_digest": text(task.image_digest),
        },
        "policy_version": text(task.policy_version),
        "status": status,
        "coverage": dict(coverage),
        "results": {
            "assets": list(results.get("assets", [])),
            "observations": list(results.get("observations", [])),
            "relationships": list(results.get("relationships", [])),
            "findings": list(results.get("findings", [])),
        },
        "evidence": [
            {
                "local_ref": item.local_ref,
                "sha256": item.sha256,
                "uri": item.uri,
                "size_bytes": item.size_bytes,
                "media_type": item.media_type,
                "classification": item.classification,
                "kind": item.kind,
            }
            for item in evidence
        ],
        "errors": [dict(error) for error in errors],
        "provenance": {
            "input_fingerprint": input_fingerprint(input_values),
            "started_at": started_at,
            "finished_at": finished_at,
            "seed_targets": [reference.model_dump(mode="json") for reference in task.targets],
        },
        "trace": task.trace.model_dump(mode="json", exclude_none=True),
    }
    if exit_code is not None:
        payload["provenance"]["exit_code"] = exit_code
    validation.validate(ENVELOPE_SCHEMA, payload)
    return ResultEnvelope.model_validate(payload)


class HttpIngestionClient:
    """`POST /api/v2/ingestion/results` with the internal service token (G1 dev/lab)."""

    def __init__(self, base_url: str, service_token: str, *, timeout_seconds: float = 30.0) -> None:
        if not service_token:
            raise ValueError("the ingestion client needs the internal service token")
        self.base_url = base_url.rstrip("/")
        self.service_token = service_token
        self.timeout_seconds = timeout_seconds

    def submit(self, envelope: ResultEnvelope) -> IngestReceipt:
        payload = json.dumps(
            envelope.model_dump(mode="json", by_alias=True, exclude_none=True),
            separators=(",", ":"),
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}{INGESTION_PATH}",
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                SERVICE_TOKEN_HEADER: self.service_token,
            },
        )
        # Never route through a proxy the host may export (the job proxy is per job, this call is
        # control-plane traffic to the ingestion endpoint).
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(request, timeout=self.timeout_seconds) as response:
                body = response.read()
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", "replace")
            raise EnvelopeError(
                "INGESTION_HTTP_ERROR", f"HTTP {error.code}: {detail[:2000]}"
            ) from error
        except urllib.error.URLError as error:
            raise EnvelopeError("INGESTION_UNREACHABLE", str(error.reason)) from error
        try:
            document = json.loads(body)
        except json.JSONDecodeError as error:
            raise EnvelopeError("OUTPUT_INVALID", f"receipt is not JSON: {error}") from error
        validation.validate("ingestion/ingest-receipt.v2.schema.json", document)
        return IngestReceipt.model_validate(document)


def submit(client: IngestionClient, envelope: ResultEnvelope) -> IngestReceipt:
    """Send the envelope; a duplicate submission comes back as a receipt with `duplicate=true`."""
    return client.submit(envelope)


def envelope_document(envelope: ResultEnvelope) -> dict[str, Any]:
    """The wire document of an envelope (what `build_envelope` validated)."""
    return envelope.model_dump(mode="json", by_alias=True, exclude_none=True)


def read_envelope(path: Path) -> ResultEnvelope:
    """Load a persisted envelope snapshot (the collector freezes it before the first POST)."""
    return ResultEnvelope.model_validate(json.loads(path.read_text(encoding="utf-8")))


__all__ = [
    "EnvelopeError",
    "EnvelopeEvidence",
    "HttpIngestionClient",
    "IngestionClient",
    "build_envelope",
    "canonical_bytes",
    "dedup_key",
    "envelope_document",
    "error_object",
    "evidence_reference",
    "input_fingerprint",
    "new_id",
    "now_timestamp",
    "read_envelope",
    "submit",
]
