"""`aegis-c14n/1` in the service: golden vectors, envelope projection and value hashing (C03)."""

from __future__ import annotations

import copy
import math
from typing import Any

import pytest

from aegis.m27_ingestion import canonical
from tests.support import load_fixture

GOLDEN = load_fixture("golden/hash/canonicalization.vectors.json")


def test_every_golden_vector_reproduces_the_published_bytes() -> None:
    assert GOLDEN["version"] == canonical.HASH_VERSION
    for vector in GOLDEN["vectors"]:
        with pytest.MonkeyPatch.context():
            assert canonical.canonical_text(vector["input"]) == vector["canonical"], vector["name"]
            assert canonical.sha256_hex(vector["input"]) == vector["sha256"], vector["name"]


def test_golden_envelope_hashes_match_the_published_payload_hash() -> None:
    expected = GOLDEN["envelope_payload_hash"]
    assert expected, "the golden file must pin at least one envelope payload hash"
    for fixture, digest in expected.items():
        payload = load_fixture(fixture)
        assert canonical.payload_hash(payload) == digest, fixture


def test_payload_hash_ignores_only_submission_identity() -> None:
    envelope = load_fixture("valid/result-envelope.subfinder.json")
    original = canonical.payload_hash(envelope)

    replay = copy.deepcopy(envelope)
    replay["event_id"] = "01900000-0000-7000-8000-00000000ff01"
    replay["trace"] = {"trace_id": "f" * 32}
    assert canonical.payload_hash(replay) == original, "event_id/trace are not business content"

    different_dedup_key = copy.deepcopy(envelope)
    different_dedup_key["dedup_key"] = "job:other:envelope"
    assert canonical.payload_hash(different_dedup_key) == original

    changed = copy.deepcopy(envelope)
    changed["status"] = "partial"
    assert canonical.payload_hash(changed) != original, "a business change must change the hash"
    changed = copy.deepcopy(envelope)
    changed["results"]["observations"][0]["value"] = {"changed": True}
    assert canonical.payload_hash(changed) != original


def test_every_envelope_property_is_classified() -> None:
    envelope = load_fixture("valid/result-envelope.subfinder.json")
    top_level = set(envelope)
    assert canonical.PAYLOAD_HASH_EXCLUDE <= top_level
    assert canonical.payload_hash(envelope)  # projection keeps every other property


def test_value_hash_is_the_same_canonical_form() -> None:
    value = {"type": "A", "value": "192.0.2.10", "ttl": 300}
    assert canonical.sha256_hex(value) == canonical.sha256_hex(dict(reversed(list(value.items()))))
    assert canonical.sha256_hex(value) != canonical.sha256_hex({**value, "ttl": 301})
    assert canonical.sha256_hex(None) == canonical.sha256_hex(None)
    assert canonical.sha256_hex(True) != canonical.sha256_hex(1), "bool is not a number"


@pytest.mark.parametrize(
    "value",
    [
        float("nan"),
        float("inf"),
        -math.inf,
        {"a": 2**53 + 1},
        10**400,
        {1: "non-string key"},
        {"a", "set is not JSON"},
    ],
)
def test_values_without_one_canonical_form_are_rejected(value: Any) -> None:
    with pytest.raises(canonical.CanonicalizationError):
        canonical.canonical_text(value)


def test_keys_that_collide_after_nfc_are_rejected() -> None:
    with pytest.raises(canonical.CanonicalizationError, match="collide"):
        canonical.canonical_text({"café": 1, "cafe\u0301": 2})


def test_number_forms_follow_rfc8785() -> None:
    assert canonical.canonical_text(1e30) == "1e+30"
    assert canonical.canonical_text(1e-7) == "1e-7"
    assert canonical.canonical_text(0.000001) == "0.000001"
    assert canonical.canonical_text(-0.0) == "0"
    assert canonical.canonical_text(4.5) == "4.5"
    assert canonical.canonical_text(10**15) == "1000000000000000"
