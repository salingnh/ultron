"""In-memory fakes of the six module interfaces (X-10).

They exist so G1 tasks integrate without a database, a container runtime, an object store or an
LLM: every fake is deterministic, keeps its state in memory and performs no I/O beyond the paths a
test hands it. Contract-facing outputs are the *contract fixtures* (contracts/fixtures/valid),
so the tests prove that what a fake returns is a valid contract payload, parsed by the generated
DTOs - the same payload a real implementation must produce.
"""

from __future__ import annotations

from tests.fakes.adapter import FakeAdapter
from tests.fakes.container_runner import FakeContainerRunner
from tests.fakes.evidence_store import FakeEvidenceStore
from tests.fakes.ingestion import FakeIngestion
from tests.fakes.model_client import FakeModelClient
from tests.fakes.registry_client import FakeRegistryClient

__all__ = [
    "FakeAdapter",
    "FakeContainerRunner",
    "FakeEvidenceStore",
    "FakeIngestion",
    "FakeModelClient",
    "FakeRegistryClient",
]
