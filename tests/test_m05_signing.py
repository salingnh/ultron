"""ApprovedTask signing (OI-7): canonical input, key id, rotation, tamper and verify."""

from __future__ import annotations

import json

import pytest

from aegis.m05_registry.signing import (
    DEV_KEY_ID,
    ENV_ACTIVE,
    ENV_ALLOW_DEV,
    ENV_KEYS,
    InvalidSignature,
    KeyRing,
    SignatureError,
    SigningKeyUnavailable,
    UnknownSigningKey,
    signing_input,
)
from tests.support import load_fixture


def _task() -> dict[str, object]:
    task: dict[str, object] = dict(load_fixture("valid/approved-task.subfinder.json"))
    task.pop("signature")
    task.pop("signature_key_id")
    return task


def test_signing_input_is_canonical_and_excludes_the_signature() -> None:
    task = _task()
    first = signing_input(task, "g1-dev-1")
    reordered = dict(reversed(list(task.items())))
    assert first == signing_input(reordered, "g1-dev-1")
    # Envelope fields are excluded and cannot change the signed bytes.
    with_signature = {
        **task,
        "signature": "hmac-sha256:" + "0" * 64,
        "signature_key_id": "g1-dev-1",
    }
    assert signing_input(with_signature, "g1-dev-1") == first
    assert b'"purpose":"aegis.io/approved-task/v2"' in first
    assert b'"signature_key_id":"g1-dev-1"' in first


def test_sign_and_verify_roundtrip() -> None:
    ring = KeyRing.dev()
    task = _task()
    signature, key_id = ring.sign(task)
    assert key_id == DEV_KEY_ID
    assert signature.startswith("hmac-sha256:") and len(signature) == len("hmac-sha256:") + 64
    signed = {**task, "signature": signature, "signature_key_id": key_id}
    assert ring.verify(signed) == DEV_KEY_ID


@pytest.mark.parametrize(
    "field,value",
    [
        ("capability", "dns.resolve"),
        ("input", {"targets": ["other.example"], "recursive": True}),
        ("targets", [{"seed_id": "01934f6a-0000-7000-8000-0000000000b9"}]),
        ("priority", 99),
        ("depends_on", ["01934f6a-0000-7000-8000-0000000000b9"]),
        ("manifest_sha256", "0" * 64),
        (
            "egress_binding",
            {"mode": "none", "target_binding": "none", "entries": [], "target_addresses": []},
        ),
    ],
)
def test_every_signed_field_is_covered(field: str, value: object) -> None:
    ring = KeyRing(
        active_key_id="another-key",
        keys={DEV_KEY_ID: b"a" * 32, "another-key": b"b" * 32},
    )
    task = _task()
    signature, key_id = ring.sign(task)
    signed = {**task, "signature": signature, "signature_key_id": key_id}
    assert ring.verify(signed) == key_id
    tampered = {**signed, field: value}
    with pytest.raises(SignatureError):
        ring.verify(tampered)


def test_rotation_keeps_old_tasks_verifiable() -> None:
    ring = KeyRing.dev()
    task = _task()
    signature, key_id = ring.sign(task)
    old_task = {**task, "signature": signature, "signature_key_id": key_id}

    rotated = ring.rotate("g1-dev-2", b"2" * 32)
    assert rotated.active_key_id == "g1-dev-2"
    assert rotated.verify(old_task) == DEV_KEY_ID  # the old key is still in the ring
    new_signature, new_key_id = rotated.sign(task)
    assert new_key_id == "g1-dev-2"
    assert new_signature != signature
    assert (
        rotated.verify({**task, "signature": new_signature, "signature_key_id": new_key_id})
        == "g1-dev-2"
    )

    dropped = rotated.rotate("g1-dev-3", b"3" * 32, keep=False)
    with pytest.raises(UnknownSigningKey):
        dropped.verify(old_task)


def test_unknown_key_and_malformed_signature_are_refused() -> None:
    ring = KeyRing.dev()
    task = _task()
    signature, _ = ring.sign(task)
    with pytest.raises(UnknownSigningKey, match="does not hold"):
        ring.verify({**task, "signature": signature, "signature_key_id": "not-registered"})
    with pytest.raises(InvalidSignature, match="hmac-sha256"):
        ring.verify({**task, "signature": "sha1:abc", "signature_key_id": DEV_KEY_ID})
    with pytest.raises(InvalidSignature, match="signature_key_id"):
        ring.verify({**task, "signature": signature})


def test_key_ring_is_configured_or_fails_closed() -> None:
    with pytest.raises(SigningKeyUnavailable, match="refusing to sign"):
        KeyRing.from_env({})
    dev = KeyRing.from_env({ENV_ALLOW_DEV: "1"})
    assert dev.active_key_id == DEV_KEY_ID
    ring = KeyRing.from_env({ENV_KEYS: "k1:0011,k2:2233", ENV_ACTIVE: "k2"})
    assert ring.active_key_id == "k2" and ring.key_ids == ("k1", "k2")
    with pytest.raises(SigningKeyUnavailable, match="hex"):
        KeyRing.from_env({ENV_KEYS: "k1:zz", ENV_ACTIVE: "k1"})
    with pytest.raises(SigningKeyUnavailable, match="ACTIVE"):
        KeyRing.from_env({ENV_KEYS: "k1:0011"})
    with pytest.raises(SigningKeyUnavailable, match="not in the key ring"):
        KeyRing.from_env({ENV_KEYS: "k1:0011", ENV_ACTIVE: "k9"})


def test_a_signed_fixture_task_validates_against_the_contract() -> None:
    from aegis import validation

    ring = KeyRing.dev()
    task = load_fixture("valid/approved-task.subfinder.json")
    task.pop("signature_key_id")
    task.pop("signature")
    signature, key_id = ring.sign(task)
    signed = {**task, "signature": signature, "signature_key_id": key_id}
    validation.validate("capability/approved-task.v2.schema.json", signed)
    assert ring.verify(signed) == key_id
    # The stored form is JSON-safe: what M05 writes to scan_job.approved_task survives a round trip.
    assert json.loads(json.dumps(signed))["signature"] == signature
