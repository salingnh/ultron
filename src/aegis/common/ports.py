"""Module ports (Python view of contracts/interfaces/README.md §1–7) and their result types.

The contract DTOs used here are the generated ones from `aegis.contracts_gen`; nothing in this
module redefines a contract shape. The small dataclasses below are the *internal* interface
values that have no JSON Schema of their own (handles, states, results). They are defined once
here so implementations in M04/M06/M27/M28 and the fakes in tests/fakes agree on the shape.

X-10 (plan §3): the six interfaces faked for G1 are Adapter, ContainerRunner, EvidenceStore,
ModelClient, Ingestion and the MCP/registry client. The collector (interfaces README §3) is a
procedure inside M06 rather than a separately injected interface, and Temporal (§7) is exercised
by the workflow tests of G1.1d; neither gets a fake here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol, runtime_checkable

from aegis.contracts_gen.agent.model_request_v2_schema import ModelRequest
from aegis.contracts_gen.agent.model_response_v2_schema import ModelResponse
from aegis.contracts_gen.campaign.roe_policy_v2_schema import Budget as PolicyBudget
from aegis.contracts_gen.capability.approved_task_v2_schema import ApprovedTask
from aegis.contracts_gen.capability.job_v2_schema import JobStatus
from aegis.contracts_gen.capability.provider_manifest_v2_schema import ProviderManifest
from aegis.contracts_gen.common.error_v2_schema import Error
from aegis.contracts_gen.common.ids_v2_schema import Classification
from aegis.contracts_gen.ingestion.ingest_receipt_v2_schema import IngestReceipt
from aegis.contracts_gen.ingestion.result_envelope_v2_schema import ResultEnvelope
from aegis.contracts_gen.mcp.capability_request_v2_schema import CapabilityRequest
from aegis.contracts_gen.mcp.capability_response_v2_schema import CapabilityResponse

__all__ = [
    "Adapter",
    "Budget",
    "BudgetExceeded",
    "CancelResult",
    "ContainerRunner",
    "ContainerSpec",
    "EvidenceObject",
    "EvidenceStore",
    "Excerpt",
    "Health",
    "Ingestion",
    "IngestionConflict",
    "JobHandle",
    "JobState",
    "ModelClient",
    "RegistryClient",
    "RunHandle",
    "RunState",
    "TaskContext",
    "ToolInfo",
    "ValidationResult",
]


class BudgetExceeded(RuntimeError):
    """The campaign budget is exhausted; the provider must not be called (M04)."""


class IngestionConflict(RuntimeError):
    """Same dedup_key with a different payload hash: 409 IDEMPOTENCY_CONFLICT (M27/C03)."""


# --- M08 Adapter ----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TaskContext:
    """Execution context handed to an adapter (campaign/policy pins, trace id)."""

    campaign_id: str
    policy_version: str
    scope_id: str
    trace_id: str


@dataclass(frozen=True, slots=True)
class ValidationResult:
    """Outcome of `Adapter.validate`; refused input carries contract errors, not free text."""

    accepted: bool
    errors: tuple[Error, ...] = ()


@dataclass(frozen=True, slots=True)
class JobHandle:
    """Adapter-side handle of one started job. `key` is the idempotency key of `start`."""

    job_id: str
    key: str
    provider_job_id: str | None = None


@dataclass(frozen=True, slots=True)
class JobState:
    """Adapter-side job state with the retry hint the interface promises (`retry_after`)."""

    status: JobStatus
    retry_after: float = 0.0
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class CancelResult:
    """Best-effort cancellation result; it is recorded as audit by the implementation."""

    cancelled: bool
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class Health:
    """Adapter health: pinned provider version and image digest, never a network probe."""

    ok: bool
    provider_version: str
    image_digest: str
    dependencies: tuple[str, ...] = ()
    detail: str | None = None


@runtime_checkable
class Adapter(Protocol):
    """Adapter SDK (contracts/interfaces/README.md §1)."""

    def describe(self) -> ProviderManifest: ...

    def validate(self, ctx: TaskContext, input: Mapping[str, Any]) -> ValidationResult: ...

    def start(self, ctx: TaskContext, task: ApprovedTask, key: str) -> JobHandle: ...

    def status(self, handle: JobHandle) -> JobState: ...

    def cancel(self, handle: JobHandle) -> CancelResult: ...

    def collect(self, handle: JobHandle) -> ResultEnvelope: ...

    def health(self) -> Health: ...


# --- M06 ContainerRunner --------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ContainerSpec:
    """Sandbox specification of one job, exactly the fields of interfaces/README.md §2."""

    job_id: str
    image_digest: str
    args: list[str]
    cpu: float
    memory_mb: int
    timeout_seconds: int
    max_output_bytes: int
    network: Literal["exec", "none"]
    #: Deployment network of the job (the campaign's signed `network_profile`): `lab` attaches the
    #: container to the deployment's lab network, `internet` to its own per-job network + broker.
    network_profile: Literal["lab", "internet"] = "lab"
    egress_mode: Literal["broker"] | None = None
    egress_binding: tuple[str, ...] = ()
    egress_proxy: str | None = None
    raw_socket: bool = False
    read_only_rootfs: bool = True
    user: str = "65534:65534"
    pids_limit: int = 512
    max_output_files: int = 50000
    seccomp_ruleset: str = "default"


@dataclass(frozen=True, slots=True)
class RunHandle:
    """Handle of a container run; the container name is the job id (idempotent `run`)."""

    job_id: str
    container_id: str


@dataclass(frozen=True, slots=True)
class RunState:
    """Observed container state (`inspect`)."""

    status: Literal["created", "running", "exited", "oom", "timeout", "missing"]
    exit_code: int | None = None


@runtime_checkable
class ContainerRunner(Protocol):
    """Sandbox runtime (contracts/interfaces/README.md §2)."""

    def run(self, spec: ContainerSpec) -> RunHandle: ...

    def inspect(self, handle: RunHandle) -> RunState: ...

    def stop(self, handle: RunHandle, grace_seconds: int = 10) -> None: ...

    def output_dir(self, handle: RunHandle) -> Path: ...

    def remove(self, handle: RunHandle) -> None: ...


# --- M28 EvidenceStore ----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EvidenceObject:
    """Stored evidence object; `uri` is the object-store location the collector records."""

    evidence_id: str
    campaign_id: str
    job_id: str
    sha256: str
    uri: str
    media_type: str
    classification: Classification


@dataclass(frozen=True, slots=True)
class Excerpt:
    """Bounded read of stored evidence (≤ 8 KiB by contract)."""

    evidence_id: str
    offset: int
    data: bytes
    truncated: bool


@runtime_checkable
class EvidenceStore(Protocol):
    """Evidence object store (contracts/interfaces/README.md §4)."""

    def put(
        self,
        campaign_id: str,
        job_id: str,
        path: Path,
        media_type: str,
        classification: Classification,
    ) -> EvidenceObject: ...

    def signed_url(self, evidence_id: str, ttl_seconds: int = 300) -> str: ...

    def excerpt(self, evidence_id: str, offset: int, max_bytes: int) -> Excerpt: ...

    def verify(self, evidence_id: str) -> bool: ...


# --- M04 ModelClient ------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Budget:
    """Campaign budget still available before a model call (from the policy snapshot)."""

    remaining_tokens: int
    remaining_cost_usd: float
    policy: PolicyBudget | None = None


@runtime_checkable
class ModelClient(Protocol):
    """LLM driver (contracts/interfaces/README.md §5)."""

    async def complete(self, req: ModelRequest, budget: Budget) -> ModelResponse: ...


# --- M27 Ingestion --------------------------------------------------------------------------


@runtime_checkable
class Ingestion(Protocol):
    """Ingestion endpoint (contracts/interfaces/README.md §6)."""

    def submit(self, envelope: ResultEnvelope) -> IngestReceipt: ...


# --- MCP / registry client ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ToolInfo:
    """`tools/list` entry: capability id plus the JSON Schema of its input."""

    name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class RegistryClient(Protocol):
    """MCP client side of M05 (capability tools) used by M03."""

    def list_tools(self) -> tuple[ToolInfo, ...]: ...

    def call(self, tool: str, request: CapabilityRequest) -> CapabilityResponse: ...
