"""ApprovedTask signing (OI-7): HMAC-SHA256 over an explicit `aegis-c14n/1` signing input.

The contract (`capability/approved-task.v2.schema.json`, `interfaces/README.md` §Chữ ký) fixes:

    signing input = aegis-c14n/1({"purpose": "aegis.io/approved-task/v2",
                                  "signature_key_id": <id>,
                                  "task": <task without "signature">})
    signature     = "hmac-sha256:" + hex(HMAC-SHA256(key[id], utf8(signing input)))

`signature_key_id` is inside the signed input, so a signature can never be relabelled with another
key. Rotation keeps every earlier key verifiable: signing uses the active key, verification accepts
any key in the ring. Secrets are configuration (env), never part of a task, fixture, log or report.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from dataclasses import dataclass, field
from os import environ
from typing import Any

from aegis.m05_registry.canonical import canonical_bytes

__all__ = [
    "DEV_KEY_ID",
    "DEV_SECRET",
    "KeyRing",
    "SignatureError",
    "InvalidSignature",
    "SigningKeyUnavailable",
    "UnknownSigningKey",
    "signing_input",
]

PURPOSE = "aegis.io/approved-task/v2"
SIGNATURE_PREFIX = "hmac-sha256:"
ENV_KEYS = "AEGIS_TASK_SIGNING_KEYS"
ENV_ACTIVE = "AEGIS_TASK_SIGNING_ACTIVE_KEY"
ENV_ALLOW_DEV = "AEGIS_ALLOW_DEV_SIGNING_KEY"

#: Development key (plan G1.1c: a dev key is acceptable; production key management is later work).
#: It is a *published* test key, so it is only used when a deployment explicitly opts in.
DEV_KEY_ID = "g1-dev-1"
DEV_SECRET = hashlib.sha256(b"aegis-dev-signing-key-do-not-use-in-production").digest()


class SignatureError(ValueError):
    """Base class for a task that cannot be trusted."""


class UnknownSigningKey(SignatureError):
    """The task names a key id that is not in the ring (or has been removed)."""


class InvalidSignature(SignatureError):
    """The HMAC does not match the canonical signing input."""


class SigningKeyUnavailable(RuntimeError):
    """No key ring can be configured: fail closed instead of signing with an accidental key."""


def signing_input(task: Mapping[str, Any], key_id: str) -> bytes:
    """The exact bytes HMAC covers, for signing and for verification (M06 uses the same helper).

    The task body excludes `signature` and `signature_key_id`: both are envelope fields, and the
    key id is signed exactly once (next to `purpose`), never twice.
    """
    if not key_id:
        raise SignatureError("signature_key_id is required")
    envelope = {"signature", "signature_key_id"}
    body = {key: value for key, value in task.items() if key not in envelope}
    return canonical_bytes({"purpose": PURPOSE, "signature_key_id": key_id, "task": body})


@dataclass(frozen=True, slots=True)
class KeyRing:
    """Every verification key plus the one that signs new tasks."""

    active_key_id: str
    keys: Mapping[str, bytes] = field(repr=False)

    def __post_init__(self) -> None:
        if self.active_key_id not in self.keys:
            raise SigningKeyUnavailable(
                f"active signing key {self.active_key_id!r} is not in the key ring"
            )
        for key_id, secret in self.keys.items():
            if not key_id or not secret:
                raise SigningKeyUnavailable("a key ring entry needs an id and a non-empty secret")

    @property
    def key_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self.keys))

    def sign(self, task: Mapping[str, Any], key_id: str | None = None) -> tuple[str, str]:
        """Return `(signature, key_id)` for a task that does not carry a signature yet."""
        signing_key_id = key_id or self.active_key_id
        try:
            secret = self.keys[signing_key_id]
        except KeyError as error:
            raise UnknownSigningKey(f"unknown signing key {signing_key_id!r}") from error
        digest = hmac.new(secret, signing_input(task, signing_key_id), hashlib.sha256).hexdigest()
        return f"{SIGNATURE_PREFIX}{digest}", signing_key_id

    def verify(self, task: Mapping[str, Any]) -> str:
        """Return the signing key id, or raise `SignatureError` when the task is not trustworthy."""
        signature = task.get("signature")
        if not isinstance(signature, str) or not signature.startswith(SIGNATURE_PREFIX):
            raise InvalidSignature("signature must be 'hmac-sha256:<64 hex>'")
        key_id = task.get("signature_key_id")
        if not isinstance(key_id, str) or not key_id:
            raise InvalidSignature("signature_key_id is required to verify a signature")
        try:
            secret = self.keys[key_id]
        except KeyError as error:
            raise UnknownSigningKey(
                f"signature names key {key_id!r}, which this ring does not hold "
                f"(known: {', '.join(self.key_ids)})"
            ) from error
        expected = hmac.new(secret, signing_input(task, key_id), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(f"{SIGNATURE_PREFIX}{expected}", signature):
            raise InvalidSignature("signature does not match the canonical task content")
        return key_id

    def rotate(self, new_key_id: str, secret: bytes, *, keep: bool = True) -> KeyRing:
        """Return a ring whose active key is new; earlier keys stay valid unless `keep=False`."""
        keys = dict(self.keys) if keep else {}
        keys[new_key_id] = secret
        return KeyRing(active_key_id=new_key_id, keys=keys)

    @classmethod
    def dev(cls) -> KeyRing:
        """The published development key (tests, local demo). Never a production configuration."""
        return cls(active_key_id=DEV_KEY_ID, keys={DEV_KEY_ID: DEV_SECRET})

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> KeyRing:
        """Load `AEGIS_TASK_SIGNING_KEYS='id:hexsecret,...'` + `AEGIS_TASK_SIGNING_ACTIVE_KEY`.

        With no configuration this fails closed. A deployment that knowingly runs with the published
        development key sets `AEGIS_ALLOW_DEV_SIGNING_KEY=1`; that is the G1 demo path, and the
        report says so.
        """
        source = environ if env is None else env
        raw = (source.get(ENV_KEYS) or "").strip()
        if not raw:
            if (source.get(ENV_ALLOW_DEV) or "").strip() == "1":
                return cls.dev()
            raise SigningKeyUnavailable(
                f"{ENV_KEYS} is not set; refusing to sign tasks (set it, or "
                f"{ENV_ALLOW_DEV}=1 for the documented development key {DEV_KEY_ID})"
            )
        keys: dict[str, bytes] = {}
        for entry in raw.split(","):
            entry = entry.strip()
            if not entry:
                continue
            key_id, separator, secret_hex = entry.partition(":")
            if not separator or not key_id or not secret_hex:
                raise SigningKeyUnavailable(
                    f"{ENV_KEYS} entries must be '<key id>:<hex secret>'; got a malformed entry"
                )
            try:
                keys[key_id] = bytes.fromhex(secret_hex)
            except ValueError as error:
                raise SigningKeyUnavailable(
                    f"{ENV_KEYS}: secret of key {key_id!r} is not hex"
                ) from error
        active = (source.get(ENV_ACTIVE) or "").strip()
        if not active:
            raise SigningKeyUnavailable(f"{ENV_ACTIVE} must name the key that signs new tasks")
        return cls(active_key_id=active, keys=keys)
