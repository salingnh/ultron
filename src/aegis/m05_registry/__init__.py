"""M05 — capability registry, manifest pins, policy decisions, signed tasks (owner: G1.1c/G1.2b).

`m05_registry.service.JobService` is the acceptance path both REST (`m26_api/jobs.py`) and MCP
(G1.2b) call; the modules below it are the pieces of that path:

* `manifest` / `registry` - admission and the immutable, hash-keyed manifest store;
* `canonical` / `signing` - `aegis-c14n/1` and the ApprovedTask HMAC (key id + rotation);
* `caps` / `targets` / `egress` / `dependency` - the policy checks and the signed egress binding;
* `errors` - every refusal as a contract `Error` with code, `next_action`, rule and HTTP status.
"""

from __future__ import annotations

from aegis.m05_registry.canonical import HASH_VERSION, job_fingerprint
from aegis.m05_registry.errors import M05Error, Refusal
from aegis.m05_registry.ids import trace_id, uuid7
from aegis.m05_registry.manifest import (
    ManifestRecord,
    ManifestRejected,
    admit_manifest,
    manifest_sha256,
)
from aegis.m05_registry.registry import (
    InMemoryManifestRegistry,
    ManifestNotFound,
    ManifestRegistry,
    ManifestVersionConflict,
    PostgresManifestRegistry,
)
from aegis.m05_registry.service import JobPage, JobService, PostgresJobService, SubmitOutcome
from aegis.m05_registry.signing import KeyRing, SignatureError, signing_input

__all__ = [
    "HASH_VERSION",
    "InMemoryManifestRegistry",
    "JobPage",
    "JobService",
    "KeyRing",
    "M05Error",
    "ManifestNotFound",
    "ManifestRecord",
    "ManifestRegistry",
    "ManifestRejected",
    "ManifestVersionConflict",
    "PostgresJobService",
    "PostgresManifestRegistry",
    "Refusal",
    "SignatureError",
    "SubmitOutcome",
    "admit_manifest",
    "job_fingerprint",
    "manifest_sha256",
    "signing_input",
    "trace_id",
    "uuid7",
]
