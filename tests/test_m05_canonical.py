"""`aegis-c14n/1` in `src/` must produce the bytes the contract reference and golden vectors fix."""

from __future__ import annotations

import importlib.util
import json
import sys
from typing import Any

import pytest

from aegis.m05_registry.canonical import (
    CanonicalizationError,
    canonical_bytes,
    canonical_text,
    job_fingerprint,
    loads,
    sha256_hex,
)
from tests.support import REPO_ROOT

FIXTURES = REPO_ROOT / "contracts/fixtures/golden/hash/canonicalization.vectors.json"


def _reference() -> Any:
    path = REPO_ROOT / "contracts/tests/canonicalization.py"
    spec = importlib.util.spec_from_file_location("aegis_c14n_reference", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


REFERENCE = _reference()
VECTORS = json.loads(FIXTURES.read_text())


def test_golden_vectors_reproduce_the_contract_bytes() -> None:
    assert VECTORS["version"] == "aegis-c14n/1"
    for vector in VECTORS["vectors"]:
        assert canonical_text(vector["input"]) == vector["canonical"], vector["name"]
        assert sha256_hex(vector["input"]) == vector["sha256"], vector["name"]


SAMPLE_DOCUMENTS: list[dict[str, Any]] = [
    {},
    {"b": 1, "a": 2, "Z": 4, "é": 3},
    {"nested": {"z": [3, 1, {"b": True, "a": None}], "a": {}}},
    {"café": "naïve", "e\u0301": "combining"},
    {"numbers": [333333333.3333333, 1e30, 4.5, 0.002, 1e-27, 0, -0.0, 123456789012345]},
    {"strings": ["€$\u000f\nA'B\"\\/", "\u0001\u001f", "tab\there"]},
    {"array_order": [3, 1, 2], "empty": []},
    {"deep": {"a": {"b": {"c": [{"d": None}]}}}},
]


@pytest.mark.parametrize("document", SAMPLE_DOCUMENTS)
def test_byte_equality_with_the_contract_reference(document: dict[str, Any]) -> None:
    assert canonical_bytes(document) == REFERENCE.canonical_bytes(document)
    assert sha256_hex(document) == REFERENCE.sha256_hex(document)


def test_job_fingerprint_matches_the_contract_reference() -> None:
    job = {
        "campaign_id": "01934f6a-0000-7000-8000-000000000001",
        "capability": "dns.enumerate_subdomains",
        "policy_version": "roe-1",
        "provider": "subfinder",
        "provider_version": "v2.17.0",
        "adapter_version": "1.0.0",
        "image_digest": "sha256:" + "2" * 64,
        "manifest_sha256": "c" * 64,
        "target_refs": [{"seed_id": "01934f6a-0000-7000-8000-0000000000b1"}],
        "input": {"targets": ["internal.example"], "recursive": False},
        "scan_cycle": "01934f6a-0000-7000-8000-000000000001",
        "priority": 50,
        "depends_on": [],
        "requested_by": {"kind": "operator", "id": "fixture"},
    }
    assert job_fingerprint(job) == REFERENCE.job_fingerprint(job)
    # Scheduling, actor and audit fields are excluded by the field list, not by luck.
    changed = dict(job, priority=90, depends_on=["01934f6a-0000-7000-8000-0000000000ff"])
    assert job_fingerprint(changed) == job_fingerprint(job)
    changed_targets = dict(job, target_refs=[{"canonical_key": "dns:x.example"}])
    assert job_fingerprint(changed_targets) != job_fingerprint(job)


def test_fingerprint_refuses_a_missing_pin_instead_of_hashing_null() -> None:
    job = {"campaign_id": "x", "capability": "dns.resolve", "manifest_sha256": None}
    with pytest.raises(CanonicalizationError, match="missing"):
        job_fingerprint(job)


@pytest.mark.parametrize(
    "value",
    [
        {"n": float("nan")},
        {"n": float("inf")},
        {"n": 2**53 + 1},
        {"n": b"bytes"},
        {1: "non-string key"},
        {"\u00e9": 1, "e\u0301": 2},  # two keys that NFC-normalize to the same string
    ],
)
def test_values_without_one_canonical_form_are_refused(value: dict[Any, Any]) -> None:
    with pytest.raises(CanonicalizationError):
        canonical_text(value)


def test_json_text_with_duplicate_keys_is_refused() -> None:
    with pytest.raises(CanonicalizationError, match="duplicate"):
        loads('{"a": 1, "a": 2}')
    with pytest.raises(CanonicalizationError, match="non-finite"):
        loads('{"a": NaN}')
