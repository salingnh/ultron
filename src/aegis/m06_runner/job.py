"""M06 job flow: prepare, run, contain, collect, store, parse, envelope, submit.

The order is the contract's (interfaces/README.md §3):

1. **Prepare before any container exists.** The spec is built from the approved task and the
   pinned manifest (`spec.build_spec`): argv rendering, target re-check (P3c), pin check, egress
   binding minus the deny set (E-1). A denied job has started nothing.
2. **Broker, then job.** An egress job gets its own internal network and the broker as the only
   peer; `HTTP(S)_PROXY`/`ALL_PROXY` point at it.
3. **Run and supervise.** The wall clock, cancel and OOM are decided here: on timeout or cancel the
   container is stopped, its remaining output is still collected, then it is removed. Output and
   evidence are never deleted.
4. **Collect, upload, verify.** Only regular files inside the caps; each file is uploaded to the
   evidence store and read back (`verify`) before the envelope claims it.
5. **Parse in isolation, then assemble and submit.** `dedup_key = job:<id>:envelope`; the envelope
   snapshot is written before the first POST, so a retry sends the same content again.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from aegis.common.ports import ContainerSpec, EvidenceObject, EvidenceStore, RunState
from aegis.contracts_gen.capability.approved_task_v2_schema import ApprovedTask
from aegis.contracts_gen.capability.provider_manifest_v2_schema import ProviderManifest
from aegis.contracts_gen.common.ids_v2_schema import Classification
from aegis.contracts_gen.ingestion.ingest_receipt_v2_schema import IngestReceipt
from aegis.contracts_gen.ingestion.result_envelope_v2_schema import ResultEnvelope
from aegis.m06_runner import collector, parser_host
from aegis.m06_runner import envelope as envelopes
from aegis.m06_runner import spec as specs
from aegis.m06_runner.collector import CollectionError, CollectionResult
from aegis.m06_runner.podman import JobLayout, PodmanRunner, RunnerError, WaitResult
from aegis.m06_runner.values import text

EnvelopeStatus = Literal["succeeded", "partial", "failed", "cancelled"]
TERMINAL_FAILURES = {"oom": "RESOURCE_LIMIT", "timeout": "EXECUTION_TIMEOUT"}


class JobError(RuntimeError):
    """The flow itself is misconfigured (missing store/client); not a job-level failure."""


@dataclass(frozen=True)
class JobPlan:
    """Everything M06 needs about one job; M02/M05 own the source of these values."""

    job_id: str
    task: ApprovedTask
    manifest: ProviderManifest
    input: Mapping[str, Any]
    manifest_bytes: bytes | None = None
    target_denylist: tuple[str, ...] = ()
    platform_cidrs: tuple[str, ...] = ()
    classification: Classification = Classification.INTERNAL


@dataclass
class JobOutcome:
    """What happened to one job; `error` is set whenever `status` is not succeeded/partial."""

    job_id: str
    status: EnvelopeStatus
    wait: WaitResult | None = None
    run: RunState | None = None
    collected: CollectionResult | None = None
    evidence: list[EvidenceObject] = field(default_factory=list)
    references: list[envelopes.EnvelopeEvidence] = field(default_factory=list)
    parser: parser_host.ParserRun | None = None
    envelope: ResultEnvelope | None = None
    receipt: IngestReceipt | None = None
    errors: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    @property
    def submitted(self) -> bool:
        return self.receipt is not None


class JobRunner:
    """Runs one job end to end on one host (the M06 invocation contract)."""

    def __init__(
        self,
        runner: PodmanRunner,
        store: EvidenceStore,
        *,
        ingestion: envelopes.IngestionClient | None = None,
        parser_limits: parser_host.ParserLimits | None = None,
        extra_parser_prefixes: Sequence[str] = (),
        extra_parser_python_path: Sequence[str] = (),
        use_parser_netns: bool = True,
    ) -> None:
        self.runner = runner
        self.store = store
        self.ingestion = ingestion
        self.parser_limits = parser_limits
        self.extra_parser_prefixes = tuple(extra_parser_prefixes)
        self.extra_parser_python_path = tuple(extra_parser_python_path)
        self.use_parser_netns = use_parser_netns

    # -- public -----------------------------------------------------------------------------

    def prepare(self, plan: JobPlan) -> tuple[Any, Any]:
        """The spec and egress policy of the job, before any container exists."""
        self.runner.ensure_network(plan.job_id)
        try:
            policy = specs.build_policy(
                plan.task,
                plan.manifest,
                plan.input,
                job_id=plan.job_id,
                platform_cidrs=plan.platform_cidrs,
                target_denylist=plan.target_denylist,
            )
            proxy = self.runner.broker_proxy(plan.job_id) if policy.mode == "egress" else None
            spec = specs.build_spec(
                plan.task,
                plan.manifest,
                plan.input,
                job_id=plan.job_id,
                broker_proxy=proxy,
                platform_cidrs=plan.platform_cidrs,
                target_denylist=plan.target_denylist,
                manifest_bytes=plan.manifest_bytes,
            )
        except Exception:
            self.runner.discard(plan.job_id)
            raise
        return spec, policy

    def execute(self, plan: JobPlan, *, cancel: Callable[[], bool] | None = None) -> JobOutcome:
        try:
            spec, policy = self.prepare(plan)
        except (specs.SpecError, RunnerError) as error:
            code = getattr(error, "code", "INTERNAL_ERROR")
            return JobOutcome(
                job_id=plan.job_id,
                status="failed",
                errors=[envelopes.error_object(code, str(error), next_action="FIX_INPUT")],
                error=str(error),
            )
        layout = self.runner.layout(plan.job_id).create()
        self._write_inputs(layout.input, plan.input)
        try:
            if policy.mode == "egress":
                self.runner.start_broker(plan.job_id, policy)
            started_at = envelopes.now_timestamp()
            handle = self.runner.run(spec)
        except RunnerError as error:
            # Nothing of this job may stay on the host (network, broker, half-started container).
            self.runner.discard(plan.job_id)
            return JobOutcome(
                job_id=plan.job_id,
                status="failed",
                errors=[
                    envelopes.error_object(
                        "INTERNAL_ERROR",
                        "the sandbox could not start the job",
                        technical_cause=str(error)[:4000],
                    )
                ],
                error=str(error),
            )
        outcome = JobOutcome(job_id=plan.job_id, status="failed")
        try:
            wait = self.runner.wait(handle, spec.timeout_seconds, cancel=cancel)
            outcome.wait = wait
            outcome.run = wait.state
            if wait.cancelled:
                # The contract does not build an envelope from a cancelled job's partial evidence;
                # what the tool wrote is still collected below and kept for the record.
                outcome.status = "cancelled"
                outcome.error = "CANCELLED"
                outcome.errors.append(
                    envelopes.error_object(
                        "CANCELLED",
                        "job cancelled by the coordinator; the envelope is not built",
                        next_action="NONE",
                    )
                )
            self._collect(plan, spec, layout, outcome)
            if wait.cancelled:
                return outcome
            self._parse(plan, layout, outcome)
            status, errors = self._status_of(outcome)
            outcome.status = status
            outcome.errors.extend(errors)
            if outcome.collected is not None and outcome.parser is not None:
                self._build_and_submit(plan, layout, outcome, started_at)
            return outcome
        finally:
            self.runner.remove(handle)

    def resubmit(self, plan: JobPlan) -> IngestReceipt | None:
        """Send the frozen envelope snapshot of a previous attempt again (dedup by content)."""
        if self.ingestion is None:
            raise JobError("an ingestion client is required to submit an envelope")
        path = self.runner.layout(plan.job_id).root / "envelope.json"
        if not path.exists():
            return None
        return envelopes.submit(self.ingestion, envelopes.read_envelope(path))

    # -- steps ------------------------------------------------------------------------------

    @staticmethod
    def _write_inputs(input_dir: Path, input_values: Mapping[str, Any]) -> None:
        targets = input_values.get("targets")
        if isinstance(targets, list) and all(isinstance(item, str) for item in targets):
            (input_dir / "targets.txt").write_text("\n".join(targets) + "\n", encoding="utf-8")

    def _collect(
        self, plan: JobPlan, spec: ContainerSpec, layout: JobLayout, outcome: JobOutcome
    ) -> None:
        try:
            outcome.collected = collector.collect(
                layout.output,
                max_bytes=spec.max_output_bytes,
                max_files=spec.max_output_files,
                max_uncompressed_bytes=spec.max_output_bytes,
            )
        except CollectionError as error:
            outcome.collected = None
            outcome.error = str(error)
            outcome.errors.append(
                envelopes.error_object(
                    "OUTPUT_INVALID",
                    f"job output rejected: {error.code}",
                    technical_cause=error.detail,
                    next_action="FIX_INPUT",
                )
            )
            return
        for item in outcome.collected.files:
            path = layout.output / item.relative_path
            try:
                stored = self.store.put(
                    text(plan.task.campaign_id),
                    plan.job_id,
                    path,
                    item.media_type,
                    plan.classification,
                )
            except Exception as error:  # noqa: BLE001 - any store failure means evidence is incomplete
                outcome.error = (
                    f"EVIDENCE_INCOMPLETE: upload of {item.relative_path} failed: {error}"
                )
                outcome.errors.append(
                    envelopes.error_object(
                        "EVIDENCE_INCOMPLETE",
                        f"evidence upload of {item.local_ref} failed",
                        technical_cause=str(error)[:4000],
                    )
                )
                return
            outcome.evidence.append(stored)
            outcome.references.append(
                envelopes.evidence_reference(
                    item, uri=stored.uri, classification=str(plan.classification)
                )
            )
            if not self.store.verify(stored.evidence_id):
                outcome.error = f"EVIDENCE_INCOMPLETE: {item.sha256} did not verify"
                outcome.errors.append(
                    envelopes.error_object(
                        "EVIDENCE_INCOMPLETE",
                        "stored evidence did not read back with the same SHA-256",
                        technical_cause=item.sha256,
                    )
                )
                return

    def _parse(self, plan: JobPlan, layout: JobLayout, outcome: JobOutcome) -> None:
        if outcome.error is not None:
            return
        stored_by_sha = {stored.sha256: stored for stored in outcome.evidence}
        evidence = [
            {
                "local_ref": reference.local_ref,
                "evidence_id": stored.evidence_id,
                "campaign_id": stored.campaign_id,
                "job_id": stored.job_id,
                "sha256": stored.sha256,
                "uri": stored.uri,
                "size_bytes": reference.size_bytes,
                "media_type": stored.media_type,
                "classification": str(stored.classification),
            }
            for reference in outcome.references
            for stored in (stored_by_sha[reference.sha256],)
        ]
        outcome.parser = parser_host.run_parser(
            plan.manifest.spec.parser.entrypoint,
            layout.output,
            plan.task.model_dump(mode="json"),
            evidence,
            limits=self.parser_limits,
            use_netns=self.use_parser_netns,
            extra_prefixes=self.extra_parser_prefixes,
            extra_python_path=self.extra_parser_python_path,
        )
        if not outcome.parser.ok:
            outcome.error = f"OUTPUT_INVALID: {outcome.parser.error}"
            outcome.errors.append(
                envelopes.error_object(
                    "OUTPUT_INVALID",
                    "the adapter parser could not read the job output",
                    technical_cause=outcome.parser.error or "unknown parser failure",
                    next_action="FIX_INPUT",
                )
            )

    @staticmethod
    def _status_of(outcome: JobOutcome) -> tuple[EnvelopeStatus, list[dict[str, Any]]]:
        errors: list[dict[str, Any]] = []
        run = outcome.run
        if outcome.error is not None:
            return "failed", errors
        if run is None:
            return "failed", errors
        if run.status in TERMINAL_FAILURES:
            errors.append(
                envelopes.error_object(
                    TERMINAL_FAILURES[run.status],
                    f"the sandbox ended the job with state {run.status}",
                    technical_cause=f"exit_code={run.exit_code}",
                )
            )
            return "failed", errors
        if run.status == "missing":
            errors.append(
                envelopes.error_object(
                    "INTERNAL_ERROR",
                    "the job container disappeared before the runner could inspect it",
                )
            )
            return "failed", errors
        if run.exit_code not in (0, None):
            errors.append(
                envelopes.error_object(
                    "TOOL_UNAVAILABLE",
                    "the tool exited non-zero",
                    technical_cause=f"exit_code={run.exit_code}",
                )
            )
            return "failed", errors
        skipped = outcome.collected.skipped if outcome.collected is not None else []
        if skipped:
            # A skipped hostile entry does not fail a job that produced usable output, but the
            # envelope must not claim a complete run.
            return "partial", errors
        return "succeeded", errors

    def _build_and_submit(
        self, plan: JobPlan, layout: JobLayout, outcome: JobOutcome, started_at: str
    ) -> None:
        if outcome.parser is None or outcome.parser.result is None:
            return
        results = dict(outcome.parser.result)
        coverage = results.get("coverage")
        if isinstance(coverage, Mapping) and outcome.status != "succeeded":
            results["coverage"] = {**coverage, "complete": False}
        try:
            envelope = envelopes.build_envelope(
                task=plan.task,
                manifest=plan.manifest,
                job_id=plan.job_id,
                input_values=plan.input,
                results=results,
                evidence=outcome.references,
                status=outcome.status,
                started_at=started_at,
                finished_at=envelopes.now_timestamp(),
                exit_code=outcome.run.exit_code if outcome.run is not None else None,
                errors=outcome.errors,
            )
        except (envelopes.EnvelopeError, ValueError) as error:
            outcome.status = "failed"
            outcome.error = str(error)
            outcome.errors.append(
                envelopes.error_object(
                    "OUTPUT_INVALID",
                    "the collector could not build a valid envelope",
                    technical_cause=str(error)[:4000],
                )
            )
            return
        outcome.envelope = envelope
        snapshot = layout.root / "envelope.json"
        snapshot.write_text(
            json.dumps(envelopes.envelope_document(envelope), indent=1, sort_keys=True),
            encoding="utf-8",
        )
        if self.ingestion is None:
            return
        try:
            outcome.receipt = envelopes.submit(self.ingestion, envelope)
        except envelopes.EnvelopeError as error:
            outcome.error = str(error)
            outcome.errors.append(
                envelopes.error_object(
                    "INTERNAL_ERROR",
                    "the envelope could not be delivered",
                    technical_cause=str(error),
                )
            )
