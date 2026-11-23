"""Shared fixtures for the G0.2 spike tests.

Unit tests run anywhere. Integration tests need Podman and are selected with
``-m integration`` (or skipped when ``G02_PODMAN=1`` is not set).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

SPIKE_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = Path(
    os.environ.get("G02_REPO_ROOT", SPIKE_ROOT.parents[1])
)
CONTRACTS = REPO_ROOT / "contracts"


def pytest_configure(config):
    config.addinivalue_line("markers", "integration: needs rootless podman")
    config.addinivalue_line("markers", "userns: needs unprivileged user namespaces")


def pytest_collection_modifyitems(config, items):
    if os.environ.get("G02_PODMAN") == "1":
        return
    skip = pytest.mark.skip(reason="set G02_PODMAN=1 to run Podman integration tests")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(scope="session")
def contracts_dir() -> Path:
    assert CONTRACTS.is_dir(), f"contracts not found at {CONTRACTS}"
    return CONTRACTS


@pytest.fixture(scope="session")
def envelope_schema(contracts_dir: Path) -> dict:
    return json.loads(
        (contracts_dir / "ingestion" / "result-envelope.v2.schema.json").read_text()
    )


@pytest.fixture(scope="session")
def bbot_fixture() -> Path:
    return SPIKE_ROOT / "fixtures" / "bbot" / "bbot-passive.ndjson"
