"""Fake M08 Adapter: deterministic answers built from contract fixtures."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from aegis.common.ports import (
    Adapter,
    CancelResult,
    Health,
    JobHandle,
    JobState,
    TaskContext,
    ValidationResult,
)
from aegis.contracts_gen.capability.approved_task_v2_schema import ApprovedTask
from aegis.contracts_gen.capability.job_v2_schema import JobStatus
from aegis.contracts_gen.capability.provider_manifest_v2_schema import ProviderManifest
from aegis.contracts_gen.ingestion.result_envelope_v2_schema import ResultEnvelope


class FakeAdapter(Adapter):
    """One adapter driven by a manifest and one envelope fixture.

    `describe` never has side effects; `start` is idempotent by key; `cancel` is best effort and a
    cancelled job still collects its (already produced) envelope - the interface allows both and
    the caller's lifecycle rules are M06's, not the fake's.
    """

    def __init__(self, manifest: ProviderManifest, envelope: ResultEnvelope) -> None:
        self._manifest = manifest
        self._envelope = envelope
        self._handles: dict[str, JobHandle] = {}
        self._cancelled: set[str] = set()

    def describe(self) -> ProviderManifest:
        return self._manifest

    def validate(self, ctx: TaskContext, input: Mapping[str, Any]) -> ValidationResult:
        accepted = bool(input)
        return ValidationResult(accepted=accepted)

    def start(self, ctx: TaskContext, task: ApprovedTask, key: str) -> JobHandle:
        return self._handles.setdefault(
            key,
            JobHandle(job_id=str(task.task_id.root), key=key, provider_job_id=f"fake-{key}"),
        )

    def status(self, handle: JobHandle) -> JobState:
        self._require(handle)
        if handle.key in self._cancelled:
            return JobState(status=JobStatus.CANCELLED, retry_after=0.0)
        return JobState(status=JobStatus.SUCCEEDED, retry_after=0.0)

    def cancel(self, handle: JobHandle) -> CancelResult:
        self._require(handle)
        self._cancelled.add(handle.key)
        return CancelResult(cancelled=True)

    def collect(self, handle: JobHandle) -> ResultEnvelope:
        self._require(handle)
        return self._envelope

    def health(self) -> Health:
        digest = self._manifest.spec.runtime.imageDigest
        return Health(
            ok=True,
            provider_version=self._manifest.spec.providerVersion,
            image_digest=str(digest.root) if digest is not None else "",
            dependencies=(),
        )

    def _require(self, handle: JobHandle) -> None:
        if self._handles.get(handle.key) != handle:
            raise RuntimeError(f"job {handle.job_id} was not started by this adapter")
