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
import logging
import time
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
from aegis.m05_registry.signing import KeyRing
from aegis.m06_runner import collector, parser_host
from aegis.m06_runner import envelope as envelopes
from aegis.m06_runner import spec as specs
from aegis.m06_runner.collector import CollectionError, CollectionResult
from aegis.m06_runner.lifecycle import (
    TERMINAL_DB_STATUSES,
    JobClaim,
    JobLifecycle,
    LifecycleError,
)
from aegis.m06_runner.podman import JobLayout, PodmanRunner, RunnerError, WaitResult
from aegis.m06_runner.values import text
from aegis.m28_evidence.catalog import CatalogError, EvidenceCatalog

EnvelopeStatus = Literal["succeeded", "partial", "failed", "cancelled"]
OutcomeStatus = Literal["succeeded", "partial", "failed", "cancelled", "skipped"]
DB_STATUS = {
    "succeeded": "SUCCEEDED",
    "partial": "SUCCEEDED",  # partial is a final result with incomplete coverage (C06)
    "failed": "FAILED",
    "cancelled": "CANCELLED",
}
TERMINAL_FAILURES = {"oom": "RESOURCE_LIMIT", "timeout": "EXECUTION_TIMEOUT"}
logger = logging.getLogger("aegis.m06.job")


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
    task_body: Mapping[str, Any] | None = None
    target_denylist: tuple[str, ...] = ()
    platform_cidrs: tuple[str, ...] = ()
    #: The campaign's RoE safety caps, read from the snapshot the task was signed against. The
    #: internet profile refuses a job without both (see `specs.build_policy`); a lab job ignores
    #: them because it never uses the broker.
    per_host_rps: float | None = None
    per_host_max_connections: int | None = None
    #: The campaign's authorization reference for the targets (operator-owned text), carried into
    #: every egress audit line of the job.
    authorization: str = ""
    classification: Classification = Classification.INTERNAL


@dataclass
class JobOutcome:
    """What happened to one job; `error` is set whenever `status` is not succeeded/partial."""

    job_id: str
    status: OutcomeStatus
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
        key_ring: KeyRing,
        ingestion: envelopes.IngestionClient | None = None,
        parser_limits: parser_host.ParserLimits | None = None,
        extra_parser_prefixes: Sequence[str] = (),
        extra_parser_python_path: Sequence[str] = (),
        use_parser_netns: bool = True,
        lifecycle: JobLifecycle | None = None,
        catalog: EvidenceCatalog | None = None,
        cancel_poll_seconds: float = 2.0,
    ) -> None:
        self.runner = runner
        self.store = store
        self.key_ring = key_ring
        self.ingestion = ingestion
        self.parser_limits = parser_limits
        self.extra_parser_prefixes = tuple(extra_parser_prefixes)
        self.extra_parser_python_path = tuple(extra_parser_python_path)
        self.use_parser_netns = use_parser_netns
        self.lifecycle = lifecycle
        self.catalog = catalog
        self.cancel_poll_seconds = cancel_poll_seconds

    # -- public -----------------------------------------------------------------------------

    def prepare(self, plan: JobPlan) -> tuple[Any, Any]:
        """The spec and egress policy of the job, before any container exists.

        The signed `network_profile` decides the network: `lab` attaches the container to the
        authorized lab network (the deployment must have an entry for the pinned image, else the job
        is refused - it never falls back to the internet), `internet` gives it its own per-job
        network whose only peer is the broker and needs a configured broker image plus an uplink.
        The egress policy is built and checked (E-1) either way.
        """
        body = _task_body(plan)
        profile = str(plan.task.network_profile)
        # A provider without networkAccess has no network at all: the profile contributes nothing.
        egress = plan.manifest.spec.permissions.networkAccess == "egress"
        entry = self.runner.profile_entry(profile, text(plan.task.image_digest)) if egress else None
        if egress and profile == "lab" and entry is None:
            raise specs.SpecError(
                "POLICY_DENIED",
                f"campaign profile lab, but this runner has no lab profile entry for "
                f"{text(plan.task.image_digest)}",
            )
        if profile == "internet":
            # A lab entry for this image is deliberately ignored: the campaign signed `internet`.
            entry = None
        if egress and entry is None:
            self.runner.ensure_network(plan.job_id)
        try:
            policy = specs.build_policy(
                plan.task,
                plan.manifest,
                plan.input,
                job_id=plan.job_id,
                task_body=body,
                key_ring=self.key_ring,
                platform_cidrs=plan.platform_cidrs,
                target_denylist=plan.target_denylist,
                authorization=plan.authorization,
                per_host_rps=plan.per_host_rps,
                per_host_max_connections=plan.per_host_max_connections,
            )
            if policy.mode == "egress" and entry is None:
                if not self.runner.broker_image:
                    raise specs.SpecError(
                        "DEPENDENCY_MISSING",
                        "an internet job needs the pinned broker image "
                        "(AEGIS_M06_BROKER_IMAGE) on this runner",
                    )
                if not self.runner.uplink_network:
                    raise specs.SpecError(
                        "DEPENDENCY_MISSING",
                        "an internet job needs the broker's uplink network "
                        "(the internet profile's `network`)",
                    )
            if (
                egress
                and profile == "internet"
                and policy.mode == "egress"
                and policy.egress_mode == "broker"
            ):
                specs.check_proxy_wiring(plan.manifest, None if entry is None else list(entry.args))
            proxy = (
                self.runner.broker_proxy(plan.job_id)
                if policy.mode == "egress" and policy.egress_mode == "broker" and entry is None
                else None
            )
            spec = specs.build_spec(
                plan.task,
                plan.manifest,
                plan.input,
                job_id=plan.job_id,
                task_body=body,
                key_ring=self.key_ring,
                broker_proxy=proxy,
                platform_cidrs=plan.platform_cidrs,
                target_denylist=plan.target_denylist,
                manifest_bytes=plan.manifest_bytes,
                authorization=plan.authorization,
                per_host_rps=plan.per_host_rps,
                per_host_max_connections=plan.per_host_max_connections,
            )
        except Exception:
            self.runner.discard(plan.job_id)
            raise
        return spec, policy

    def reject(self, job_id: str, code: str, detail: str) -> JobOutcome:
        """Terminalize a job M06 refuses before a plan exists, with the contract's error code.

        A job whose row cannot be planned (it never came through M05, its pinned manifest is not
        registered, its signed policy snapshot is gone) is a definite refusal: claiming it and
        recording the terminal result is the only honest outcome. Leaving it `VALIDATING` would
        retry the same impossible plan on every tick (G1.6 review, proposal 5).
        """
        outcome = JobOutcome(
            job_id=job_id,
            status="failed",
            errors=[
                envelopes.error_object(
                    code,
                    detail,
                    next_action="CHECK_PROVIDER" if code == "DEPENDENCY_MISSING" else "FIX_INPUT",
                )
            ],
            error=f"{code}: {detail}",
        )
        if self.lifecycle is None:
            return JobOutcome(
                job_id=job_id,
                status="skipped",
                error=f"{code}: {detail} (no lifecycle attached; nothing recorded)",
            )
        claim = self.lifecycle.claim(job_id)
        if claim is None:
            return JobOutcome(
                job_id=job_id,
                status="skipped",
                error=f"{code}: the job is no longer M06's to reject",
            )
        self._terminalize(claim, outcome)
        return outcome

    def execute(self, plan: JobPlan, *, cancel: Callable[[], bool] | None = None) -> JobOutcome:
        body = _task_body(plan)
        try:
            specs.verify_task(body, self.key_ring)
        except specs.SpecError as error:
            # A task M06 cannot verify is never executed; the job is terminalized FAILED so the
            # refusal is auditable on the row, and logged for the operator.
            logger.warning(
                "approved task refused before claim",
                extra={"job_id": plan.job_id, "capability": text(plan.task.capability)},
            )
            job_outcome = JobOutcome(
                job_id=plan.job_id,
                status="failed",
                errors=[
                    envelopes.error_object(
                        "POLICY_DENIED",
                        "the approved task signature could not be verified",
                        technical_cause=str(error)[:4000],
                        next_action="ESCALATE",
                    )
                ],
                error=str(error),
            )
            if self.lifecycle is not None:
                refused = self.lifecycle.claim(plan.job_id)
                if refused is not None:
                    self._terminalize(refused, job_outcome)
            return job_outcome
        claim: JobClaim | None = None
        if self.lifecycle is not None:
            claim = self.lifecycle.claim(plan.job_id)
            if claim is None:
                # Not VALIDATING any more (already dispatched by another worker, or cancelled).
                return JobOutcome(job_id=plan.job_id, status="skipped", error="NOT_VALIDATING")
            if self.lifecycle.cancel_requested(plan.job_id):
                # A cancel intent recorded before the container started wins: never run it.
                self.lifecycle.finish(claim, "CANCELLED")
                return JobOutcome(
                    job_id=plan.job_id,
                    status="cancelled",
                    error="CANCELLED",
                    errors=[
                        envelopes.error_object(
                            "CANCELLED",
                            "the job was cancelled before its sandbox started",
                            next_action="NONE",
                        )
                    ],
                )
        return self._run_claimed(plan, claim, cancel, adopted=False)

    def resume(
        self, plan: JobPlan, claim: JobClaim, *, cancel: Callable[[], bool] | None = None
    ) -> JobOutcome:
        """Continue a job this runner already claimed (a restarted runner, G1.5c).

        The container is adopted by name in `PodmanRunner.run` (idempotent by job id), so a job
        interrupted by a dead process reaches exactly one terminal row and one envelope: the tool
        keeps running in its container, and what it wrote is collected once. The generation and
        attempt come from the row, so the terminal callback is still the contract's compare-and-set.
        """
        return self._run_claimed(plan, claim, cancel, adopted=True)

    def _run_claimed(
        self,
        plan: JobPlan,
        claim: JobClaim | None,
        cancel: Callable[[], bool] | None,
        *,
        adopted: bool,
    ) -> JobOutcome:
        """Run or adopt one claimed job: prepare, run, collect, parse, submit, terminalize."""
        move_to_running = claim is not None and self.lifecycle is not None
        if adopted and claim is not None and self.lifecycle is not None:
            # A resumed job is normally already RUNNING; only a runner that died between claiming
            # and starting the container still has its row in DISPATCHED. Either way the row says
            # whether a container may exist for this attempt, and it is read once, before anything
            # starts.
            current = self.lifecycle.status(plan.job_id)
            if current in TERMINAL_DB_STATUSES:
                return JobOutcome(job_id=plan.job_id, status="skipped", error=f"JOB_{current}")
            move_to_running = current == "DISPATCHED"
        signal = _CancelSignal(
            cancel, self.lifecycle, plan.job_id, interval_seconds=self.cancel_poll_seconds
        )
        outcome = JobOutcome(job_id=plan.job_id, status="failed")
        try:
            try:
                spec, policy = self.prepare(plan)
            except (specs.SpecError, RunnerError) as error:
                code = getattr(error, "code", "INTERNAL_ERROR")
                outcome.errors.append(
                    envelopes.error_object(code, str(error), next_action="FIX_INPUT")
                )
                outcome.error = str(error)
                return outcome
            layout = self.runner.layout(plan.job_id).create()
            self._write_inputs(layout.input, plan.input, plan.manifest)
            try:
                if policy.mode == "egress" and spec.network_profile == "internet":
                    self.runner.start_broker(plan.job_id, policy)
                started_at = envelopes.now_timestamp()
                handle = self.runner.run(spec)
            except RunnerError as error:
                # Nothing of this job may stay on the host (network, broker, half-started job).
                self.runner.discard(plan.job_id)
                outcome.errors.append(
                    envelopes.error_object(
                        "INTERNAL_ERROR",
                        "the sandbox could not start the job",
                        technical_cause=str(error)[:4000],
                    )
                )
                outcome.error = str(error)
                return outcome
            try:
                if move_to_running and self.lifecycle is not None and claim is not None:
                    if not self.lifecycle.running(claim):
                        self.runner.stop(handle)
                        outcome.status = "skipped"
                        outcome.error = "JOB_NOT_CLAIMABLE"
                        return outcome
                wait = self.runner.wait(
                    handle,
                    spec.timeout_seconds,
                    cancel=signal,
                    max_output_bytes=spec.max_output_bytes,
                )
                outcome.wait = wait
                outcome.run = wait.state
                if wait.cancelled:
                    # The contract does not build an envelope from a cancelled job's partial
                    # evidence; what the tool wrote is still collected below and kept.
                    outcome.status = "cancelled"
                    outcome.error = "CANCELLED"
                    outcome.errors.append(
                        envelopes.error_object(
                            "CANCELLED",
                            "job cancelled by the coordinator; the envelope is not built",
                            next_action="NONE",
                        )
                    )
                if wait.capped:
                    # The runner stopped the tool because its output passed the manifest cap: the
                    # job is rejected (no envelope from output we refuse to keep), the evidence of
                    # what it wrote stays in the job directory for the record.
                    outcome.status = "failed"
                    outcome.error = "OUTPUT_BYTES_EXCEEDED: the sandbox stopped the tool at the cap"
                    outcome.errors.append(
                        envelopes.error_object(
                            "OUTPUT_INVALID",
                            "the job wrote more output than maxOutputMb allows",
                            technical_cause=(
                                f"max_output_bytes={spec.max_output_bytes}; the container was "
                                "stopped by the runner"
                            ),
                            next_action="FIX_INPUT",
                        )
                    )
                    return outcome
                if claim is not None and self.lifecycle is not None:
                    self.lifecycle.collecting(claim)
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
        finally:
            self._terminalize(claim, outcome)

    def _terminalize(self, claim: JobClaim | None, outcome: JobOutcome) -> None:
        """Record the terminal result; M06 is the only writer of these states (C06)."""
        if claim is None or self.lifecycle is None:
            return
        if outcome.status == "skipped":
            return
        status = DB_STATUS[outcome.status]
        error: dict[str, Any] | None = None
        if status == "FAILED":
            error = (
                outcome.errors[0]
                if outcome.errors
                else envelopes.error_object(
                    "INTERNAL_ERROR",
                    outcome.error or "the job failed without a recorded cause",
                )
            )
        event_id = None
        if outcome.receipt is not None:
            event_id = text(outcome.receipt.event_id)
        try:
            self.lifecycle.finish(
                claim,
                status,
                envelope_event_id=event_id,
                error=error,
                evidence_refs=[
                    {"evidence_id": stored.evidence_id, "sha256": stored.sha256, "uri": stored.uri}
                    for stored in outcome.evidence
                ],
            )
        except LifecycleError as failure:
            # The sandbox result is already recorded in the outcome; a rejected callback (for
            # example a stale attempt) is quarantined by the database, so surface it, never mask it.
            outcome.errors.append(
                envelopes.error_object(
                    "INTERNAL_ERROR",
                    "the terminal job callback was not recorded",
                    technical_cause=str(failure)[:4000],
                )
            )
            outcome.error = outcome.error or str(failure)

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
    def _write_inputs(
        input_dir: Path, input_values: Mapping[str, Any], manifest: ProviderManifest
    ) -> None:
        """Write the tool's input files; a target is written as the tool's value, not as a key.

        `input.targets` carries the contract's `DomainTarget`/`CanonicalKey` form, where the
        `dns:`/`ip:`/`service:`/... prefix is optional platform notation. A tool reading
        `/in/targets.txt` understands its own values, never our prefixes: writing
        `dns:lab.aegis.test` into the file makes Subfinder enumerate nothing at all, silently.

        The pinned manifest says how its tool reads a target (`runtime.targetsFormat`, G1.6b):
        `canonical` strips the prefix and keeps the rest (Subfinder/DNSx/naabu); `host_port` also
        drops the `/tcp` suffix of a service key so fingerprintx/httpx read `host:port`. The rule
        lives in `spec.tool_target` and `build_spec` already refused a `/udp` target for that
        format, so this method cannot widen what the job may scan.

        An integer-array `ports` input is staged the same way, as `/in/ports.txt` one port per
        line. The OI-12 rendering rule forbids joining a list into one argv element (an array
        becomes one argv element per item), and a port scanner has to receive the whole set in
        one argument (`-ports-file /in/ports.txt`); the file is the same kind of tool input as
        `targets.txt`, and nothing about the port set comes from the tool's output or from a
        manifest constant.
        """
        targets = input_values.get("targets")
        if isinstance(targets, list) and all(isinstance(item, str) for item in targets):
            name = specs.targets_format(manifest)
            values = [specs.tool_target(item, name) for item in targets]
            (input_dir / "targets.txt").write_text("\n".join(values) + "\n", encoding="utf-8")
        ports = input_values.get("ports")
        if (
            isinstance(ports, list)
            and ports
            and all(isinstance(port, int) and not isinstance(port, bool) for port in ports)
        ):
            (input_dir / "ports.txt").write_text(
                "\n".join(str(port) for port in ports) + "\n", encoding="utf-8"
            )

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
            verified = self.store.verify(stored.evidence_id)
            if self.catalog is not None:
                try:
                    evidence_id = self.catalog.record(
                        stored,
                        size_bytes=item.size_bytes,
                        source_tool=str(plan.task.provider),
                        verified=verified,
                    )
                    self.catalog.check(
                        evidence_id, verified, None if verified else "sha256 mismatch"
                    )
                except CatalogError as error:
                    outcome.error = f"EVIDENCE_INCOMPLETE: {error}"
                    outcome.errors.append(
                        envelopes.error_object(
                            "EVIDENCE_INCOMPLETE",
                            "the evidence metadata row was not recorded",
                            technical_cause=str(error)[:4000],
                        )
                    )
                    return
            if not verified:
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
            return
        problem = self._resolve_raw_refs(outcome, [ref.local_ref for ref in outcome.references])
        if problem is not None:
            outcome.error = problem
            outcome.errors.append(
                envelopes.error_object(
                    "OUTPUT_INVALID",
                    "the adapter parser referenced evidence the job does not have",
                    technical_cause=problem[:4000],
                    next_action="FIX_INPUT",
                )
            )

    @staticmethod
    def _resolve_raw_refs(outcome: JobOutcome, refs: list[str]) -> str | None:
        """Make a parser's contract `raw` evidence ref name a file the envelope actually carries.

        `interfaces/README.md` §1 and `contracts/tests/conformance/harness.py` hand a parser one
        evidence entry called `raw` (the tool's output), and both adapters emit
        `evidence_refs: [{local_ref: raw}]` because that is what they were given. The collector
        names its files after their path (`result-jsonl`), which is what the envelope publishes, so
        a `raw` ref has to be resolved once, here: to the job's single top-level output file (the
        tool writes into the manifest's `outputPath`). More than one candidate is a contract
        ambiguity that must fail loudly, not pick one.
        """
        if outcome.parser is None or not isinstance(outcome.parser.result, dict):
            return None
        raw_candidates = [ref for ref in refs if "/" not in ref]
        known = set(refs)
        for collection in ("observations", "relationships", "findings"):
            items = outcome.parser.result.get(collection) or []
            for item in items:
                for reference in item.get("evidence_refs") or []:
                    local_ref = reference.get("local_ref")
                    if local_ref not in (None, "raw") or local_ref in known:
                        continue
                    if len(raw_candidates) != 1:
                        return (
                            "OUTPUT_INVALID: the parser referenced 'raw' but the job wrote "
                            f"{len(raw_candidates)} top-level output files, so 'raw' is ambiguous"
                        )
                    reference["local_ref"] = raw_candidates[0]
        return None

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
        subjects = results.get("coverage_subjects")
        if isinstance(subjects, list) and outcome.status != "succeeded":
            # A partial run still names what it checked, but must not claim a complete coverage.
            results["coverage"] = {"subjects": subjects, "complete": False}
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
                limitations=_egress_limitations(self.runner.audit_records(plan.job_id)),
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


class _CancelSignal:
    """M06's cancel check: the caller's callback plus a throttled cancel-intent read (C06).

    The database is asked at most every `interval_seconds`, not on every 0.2 s poll: a cancel
    intent is a human action and the scheduler also terminalizes a job cancelled before dispatch.
    """

    def __init__(
        self,
        caller: Callable[[], bool] | None,
        lifecycle: JobLifecycle | None,
        job_id: str,
        *,
        interval_seconds: float = 2.0,
    ) -> None:
        self._caller = caller
        self._lifecycle = lifecycle
        self._job_id = job_id
        self._interval = max(interval_seconds, 0.1)
        self._checked_at: float | None = None
        self._requested = False

    def __call__(self) -> bool:
        if self._caller is not None and self._caller():
            return True
        if self._lifecycle is None:
            return False
        now = time.monotonic()
        if self._checked_at is None or now - self._checked_at >= self._interval:
            self._checked_at = now
            self._requested = self._lifecycle.cancel_requested(self._job_id)
        return self._requested


#: Reasons the broker refuses after the bounded wait: a scan must report those as incomplete
#: coverage, never as a closed port.
CAPPED_REASONS = frozenset({"RATE_LIMITED", "CONCURRENCY_LIMITED"})


def _egress_limitations(records: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Coverage limitations from the broker audit: any deny or cap timeout makes the run partial."""
    denied = [record for record in records if record.get("decision") == "deny"]
    if not denied:
        return []
    capped = [record for record in denied if record.get("reason") in CAPPED_REASONS]
    other = [record for record in denied if record.get("reason") not in CAPPED_REASONS]
    limitations: list[dict[str, Any]] = []
    if capped:
        limitations.append(
            {
                "code": "EGRESS_CAPPED",
                "message": (
                    f"{len(capped)} connection(s) waited past the RoE per-host cap and were "
                    "refused; the affected ports/hosts are unknown, not closed"
                ),
            }
        )
    if other:
        limitations.append(
            {
                "code": "EGRESS_DENIED",
                "message": (
                    f"{len(other)} connection(s) were refused by the egress policy (see the job "
                    "audit); the affected destinations were not reached"
                ),
            }
        )
    return limitations


def _task_body(plan: JobPlan) -> Mapping[str, Any]:
    """The exact dict M05 signed: the caller's copy when it has one, else the DTO's wire form."""
    return plan.task_body if plan.task_body is not None else plan.task.model_dump(mode="json")
