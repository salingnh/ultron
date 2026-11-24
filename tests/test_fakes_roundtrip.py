"""The six fakes implement the ports and answer with contract-valid payloads.

Every fake output crosses two checks: the JSON Schema (with the shared semantic formats) and the
generated Pydantic model. That is the G1.1a acceptance "fakes pass contract round-trip tests".
"""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

import pytest

from aegis import validation
from aegis.common.ports import (
    Adapter,
    Budget,
    BudgetExceeded,
    ContainerRunner,
    ContainerSpec,
    EvidenceStore,
    Ingestion,
    IngestionConflict,
    ModelClient,
    RegistryClient,
    TaskContext,
    ToolInfo,
)
from aegis.contracts_gen.agent.model_request_v2_schema import ModelRequest
from aegis.contracts_gen.agent.model_response_v2_schema import ModelResponse
from aegis.contracts_gen.capability.approved_task_v2_schema import ApprovedTask
from aegis.contracts_gen.capability.job_v2_schema import JobStatus
from aegis.contracts_gen.capability.provider_manifest_v2_schema import ProviderManifest
from aegis.contracts_gen.common.ids_v2_schema import Classification, Sha256
from aegis.contracts_gen.ingestion.ingest_receipt_v2_schema import IngestReceipt
from aegis.contracts_gen.ingestion.result_envelope_v2_schema import Evidence, ResultEnvelope
from aegis.contracts_gen.mcp.capability_request_v2_schema import CapabilityRequest
from aegis.contracts_gen.mcp.capability_response_v2_schema import (
    CapabilityResponse,
    Decision,
)
from aegis.contracts_gen.mcp.capability_response_v2_schema import (
    JobStatus as ResponseJobStatus,
)
from tests.fakes import (
    FakeAdapter,
    FakeContainerRunner,
    FakeEvidenceStore,
    FakeIngestion,
    FakeModelClient,
    FakeRegistryClient,
)
from tests.support import load_fixture

TRACE_ID = "0123456789abcdef0123456789abcdef"


@pytest.fixture(scope="module")
def manifest() -> ProviderManifest:
    return ProviderManifest.model_validate(load_fixture("valid/manifest.subfinder.yaml"))


@pytest.fixture(scope="module")
def task() -> ApprovedTask:
    return ApprovedTask.model_validate(load_fixture("valid/approved-task.subfinder.json"))


@pytest.fixture(scope="module")
def envelope() -> ResultEnvelope:
    return ResultEnvelope.model_validate(load_fixture("valid/result-envelope.subfinder.json"))


@pytest.fixture(scope="module")
def context(task: ApprovedTask) -> TaskContext:
    return TaskContext(
        campaign_id=str(task.campaign_id.root),
        policy_version=str(task.policy_version.root),
        scope_id=str(task.scope_id.root),
        trace_id=TRACE_ID,
    )


def test_adapter_roundtrip(
    manifest: ProviderManifest, task: ApprovedTask, envelope: ResultEnvelope, context: TaskContext
) -> None:
    adapter = FakeAdapter(manifest, envelope)
    assert isinstance(adapter, Adapter)

    described = adapter.describe()
    validation.validate_model("capability/provider-manifest.v2.schema.json", described)

    assert adapter.validate(context, {"domain": "example.com"}).accepted
    assert not adapter.validate(context, {}).accepted

    handle = adapter.start(context, task, "job-key-1")
    assert adapter.start(context, task, "job-key-1") == handle, "start must be idempotent"
    assert adapter.status(handle).status is JobStatus.SUCCEEDED
    assert adapter.status(handle).retry_after == 0.0

    collected = adapter.collect(handle)
    assert collected == envelope
    validation.validate_model("ingestion/result-envelope.v2.schema.json", collected)

    assert adapter.cancel(handle).cancelled
    assert adapter.status(handle).status is JobStatus.CANCELLED

    health = adapter.health()
    assert health.ok
    assert health.provider_version
    assert health.image_digest.startswith("sha256:")


def test_container_runner_state_machine(tmp_path: Path, task: ApprovedTask) -> None:
    runner = FakeContainerRunner(base_dir=tmp_path)
    assert isinstance(runner, ContainerRunner)
    job_id = str(task.task_id.root)
    spec = ContainerSpec(
        job_id=job_id,
        image_digest="sha256:" + "a" * 64,
        args=["-d", "example.com"],
        cpu=0.5,
        memory_mb=256,
        timeout_seconds=60,
        max_output_bytes=1024,
        network="none",
    )

    handle = runner.run(spec)
    assert runner.run(spec) == handle, "run must be idempotent by job id"
    assert runner.inspect(handle).status == "running"
    output = runner.output_dir(handle)
    assert output.is_dir() and output == tmp_path / job_id
    assert runner.spec(job_id) == spec

    runner.stop(handle)
    state = runner.inspect(handle)
    assert state.status == "exited" and state.exit_code == 0

    runner.remove(handle)
    assert runner.inspect(handle).status == "missing"
    assert output.is_dir(), "remove keeps the collected output on disk"


def test_evidence_store_roundtrip(tmp_path: Path, envelope: ResultEnvelope) -> None:
    store = FakeEvidenceStore()
    assert isinstance(store, EvidenceStore)
    payload = tmp_path / "subfinder.jsonl"
    payload.write_bytes(b'{"host":"www.example.com"}\n')
    campaign_id = str(envelope.campaign_id.root)
    job_id = str(envelope.job_id.root)

    stored = store.put(
        campaign_id, job_id, payload, "application/x-ndjson", Classification.INTERNAL
    )
    assert stored.sha256 == hashlib.sha256(payload.read_bytes()).hexdigest()
    assert stored.uri == f"s3://evidence/{campaign_id}/{job_id}/{stored.sha256}"
    assert (
        store.put(campaign_id, job_id, payload, "application/x-ndjson", Classification.INTERNAL)
        == stored
    ), "put must be idempotent"

    # The stored object must be expressible as the contract's Evidence record.
    evidence = Evidence(
        local_ref="subfinder-jsonl",
        sha256=Sha256(stored.sha256),
        uri=stored.uri,
        size_bytes=len(payload.read_bytes()),
        media_type=stored.media_type,
        classification=stored.classification,
    )
    validation.validate_model("ingestion/result-envelope.v2.schema.json#/$defs/Evidence", evidence)

    assert store.verify(stored.evidence_id)
    assert store.signed_url(stored.evidence_id).startswith("fake-s3://evidence/")

    excerpt = store.excerpt(stored.evidence_id, 0, 2 * 8192)
    assert len(excerpt.data) <= 8192
    assert excerpt.truncated is False
    tail = store.excerpt(stored.evidence_id, 0, 5)
    assert tail.data == payload.read_bytes()[:5] and tail.truncated

    store.tamper(stored.evidence_id)
    assert not store.verify(stored.evidence_id)
    assert not store.verify("0" * 64)


def test_model_client_roundtrip(task: ApprovedTask) -> None:
    request = ModelRequest.model_validate(load_fixture("valid/model-request.agent-turn.json"))
    response = ModelResponse.model_validate(
        load_fixture("valid/model-response.tool-calls.openai.json")
    )
    client = FakeModelClient([response])
    assert isinstance(client, ModelClient)

    result = asyncio.run(
        client.complete(request, Budget(remaining_tokens=10_000, remaining_cost_usd=1.0))
    )
    assert result == response
    validation.validate_model("agent/model-response.v2.schema.json", result)
    assert client.calls == [request]

    with pytest.raises(BudgetExceeded):
        asyncio.run(client.complete(request, Budget(remaining_tokens=0, remaining_cost_usd=0.0)))
    assert len(client.calls) == 2


def test_ingestion_roundtrip(envelope: ResultEnvelope) -> None:
    receipt = IngestReceipt.model_validate(load_fixture("valid/ingest-receipt.json"))
    ingestion = FakeIngestion(receipt)
    assert isinstance(ingestion, Ingestion)

    first = ingestion.submit(envelope)
    assert first.event_id == envelope.event_id
    assert first.dedup_key == envelope.dedup_key
    assert first.duplicate is False
    validation.validate_model("ingestion/ingest-receipt.v2.schema.json", first)

    replay = ingestion.submit(envelope)
    assert replay.duplicate is True
    assert replay.event_id == first.event_id
    validation.validate_model("ingestion/ingest-receipt.v2.schema.json", replay)

    changed = envelope.model_copy(update={"policy_version": "roe-2"})
    with pytest.raises(IngestionConflict):
        ingestion.submit(changed)


def test_registry_client_roundtrip(envelope: ResultEnvelope) -> None:
    input_schema = validation.document("capabilities/dns/enumerate-subdomains.v2.schema.json")
    tool = ToolInfo(
        name="dns.enumerate_subdomains",
        description="Passive subdomain enumeration (Subfinder).",
        input_schema=input_schema,
    )
    response = CapabilityResponse(
        decision=Decision.approved,
        job_id=envelope.job_id,
        job_status=ResponseJobStatus.QUEUED,
        provider="subfinder",
        policy_version=envelope.policy_version,
    )
    client = FakeRegistryClient(tools=[tool], responses={tool.name: response})
    assert isinstance(client, RegistryClient)
    assert client.list_tools() == (tool,)

    request = load_fixture("valid/capability-input.enumerate-subdomains.json")
    parsed = CapabilityRequest.model_validate(
        {
            "input": request,
            "rationale": "Enumerate the campaign seed",
            "objective_id": str(envelope.event_id.root),
        }
    )
    answer = client.call(tool.name, parsed)
    assert answer == response
    validation.validate_model("mcp/capability-response.v2.schema.json", answer)
    assert client.calls == [(tool.name, parsed)]
