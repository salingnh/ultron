#!/usr/bin/env python3
"""Reference implementation of `aegis-c14n/1`, the canonical form both ingestion hashes use.

This module is a *conformance reference for tests only* (contracts/tests/): no service imports it.
The normative rules and the field lists live in `contracts/ingestion/canonicalization.v2.yaml`;
the golden vectors live in `contracts/fixtures/golden/hash/canonicalization.vectors.json`.
Services may use any implementation that reproduces these bytes.

aegis-c14n/1 = RFC 8785 (JSON Canonicalization Scheme) plus:
  * every string and every object key is normalized to Unicode NFC before hashing;
  * two object keys that collide after NFC normalization are rejected, not merged;
  * JSON text parsing rejects duplicate keys, NaN/Infinity and numbers that do not survive
    IEEE-754 double round-tripping (I-JSON, RFC 7493), so a value can never mean two things.

Hash projections (see the registry):
  * ResultEnvelope `payload_hash` = sha256(c14n(envelope minus event_id, dedup_key, trace)) —
    the submitted envelope's identity fields are outside the content hash.
  * ScanJob `job_fingerprint` = sha256(c14n(exactly the fields in JOB_FINGERPRINT_FIELDS)) —
    includes the TargetRef list and never the canonical-key `targets` projection.
"""
from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from decimal import Decimal

HASH_VERSION = "aegis-c14n/1"

#: ResultEnvelope top-level fields that are *not* content: submission id, lookup key, tracing.
PAYLOAD_HASH_EXCLUDE = frozenset({"event_id", "dedup_key", "trace"})

#: X-1: the single job fingerprint composition, aligned to AGENTS.md:54 plus the TargetRef list.
JOB_FINGERPRINT_FIELDS = (
    "campaign_id",
    "capability",
    "policy_version",
    "provider",
    "provider_version",
    "adapter_version",
    "image_digest",
    "manifest_sha256",
    "target_refs",
    "input",
    "scan_cycle",
)

_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


class CanonicalizationError(ValueError):
    """The value has no single deterministic canonical form; callers must reject it loudly."""


def _utf16_key(text: str) -> bytes:
    """RFC 8785 orders object keys by UTF-16 code units, not by Unicode code point."""
    return text.encode("utf-16-be")


def _normalized(value: str) -> str:
    text = unicodedata.normalize("NFC", value)
    try:
        text.encode("utf-8")
    except UnicodeEncodeError as exc:  # lone surrogate: not a Unicode scalar value
        raise CanonicalizationError(f"string is not valid Unicode: {value!r}") from exc
    return text


def _string(value: str) -> str:
    out = ['"']
    for ch in _normalized(value):
        escaped = _ESCAPES.get(ch)
        if escaped is not None:
            out.append(escaped)
        elif ch < " ":
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _shortest_digits(value: float) -> tuple[str, int]:
    """Shortest decimal digits that round-trip to `value`, plus their power-of-ten exponent."""
    _, digits, exponent = Decimal(repr(value)).as_tuple()
    text = "".join(map(str, digits))
    while len(text) > 1 and text.endswith("0"):
        text = text[:-1]
        exponent += 1
    return text, exponent


def _double(value: float) -> str:
    """ECMAScript Number::toString for a finite double (RFC 8785 §3.2.2.3)."""
    if value == 0:
        return "0"  # -0.0 has no distinct canonical form
    sign = "-" if value < 0 else ""
    digits, exponent = _shortest_digits(abs(value))
    k = len(digits)
    n = k + exponent
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return f"{sign}{digits[:n]}.{digits[n:]}"
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    mantissa = digits if k == 1 else f"{digits[0]}.{digits[1:]}"
    return f"{sign}{mantissa}e{'+' if n - 1 >= 0 else '-'}{abs(n - 1)}"


def _number(value: int | float) -> str:
    """A number has one canonical form only if a double holds it exactly (I-JSON, RFC 7493)."""
    if isinstance(value, bool):  # bool is an int subclass in Python and must stay "true"/"false"
        raise CanonicalizationError("bool is not a number")
    if isinstance(value, int):
        try:
            as_double = float(value)
        except OverflowError as exc:
            raise CanonicalizationError(f"integer {value} is outside the double range") from exc
        if not math.isfinite(as_double) or int(as_double) != value:
            raise CanonicalizationError(
                f"integer {value} does not survive IEEE-754 double round-tripping (I-JSON)")
        return _double(as_double)
    if not isinstance(value, float):
        raise CanonicalizationError(f"unsupported number type {type(value).__name__}")
    if not math.isfinite(value):
        raise CanonicalizationError(f"non-finite number {value!r}")
    return _double(value)


def _encode(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (int, float)):
        return _number(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_encode(item) for item in value) + "]"
    if isinstance(value, dict):
        return _object(value)
    raise CanonicalizationError(f"unsupported JSON value type {type(value).__name__}")


def _object(value: dict) -> str:
    pairs: list[tuple[str, object]] = []
    seen: set[str] = set()
    for key, item in value.items():
        if not isinstance(key, str):
            raise CanonicalizationError("object keys must be strings")
        normalized_key = _normalized(key)
        if normalized_key in seen:
            raise CanonicalizationError(
                f"object keys collide after NFC normalization: {normalized_key!r}")
        seen.add(normalized_key)
        pairs.append((normalized_key, item))
    pairs.sort(key=lambda pair: _utf16_key(pair[0]))
    return "{" + ",".join(f"{_string(key)}:{_encode(item)}" for key, item in pairs) + "}"


def canonical_text(value) -> str:
    """The canonical UTF-8 text of a JSON value (no trailing newline)."""
    return _encode(value)


def canonical_bytes(value) -> bytes:
    return canonical_text(value).encode("utf-8")


def sha256_hex(value) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _reject_constant(name: str):
    raise CanonicalizationError(f"non-finite number {name} is not JSON")


def _pairs_hook(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise CanonicalizationError("duplicate object key in JSON text")
    for key in result:
        _normalized(key)  # rejects lone surrogates and reports normalization problems early
    normalized = [_normalized(key) for key in result]
    if len(set(normalized)) != len(normalized):
        raise CanonicalizationError("object keys collide after NFC normalization in JSON text")
    return result


def loads(text: str):
    """Parse JSON text under the same strictness the canonical form needs (duplicates rejected)."""
    try:
        return json.loads(text, object_pairs_hook=_pairs_hook, parse_constant=_reject_constant)
    except json.JSONDecodeError as exc:
        raise CanonicalizationError(f"invalid JSON: {exc}") from exc


def canonical_bytes_from_json(text: str) -> bytes:
    return canonical_bytes(loads(text))


def payload_projection(envelope: dict) -> dict:
    """The business content of a ResultEnvelope: everything except submission id, key and trace."""
    if not isinstance(envelope, dict):
        raise CanonicalizationError("ResultEnvelope must be a JSON object")
    return {key: value for key, value in envelope.items() if key not in PAYLOAD_HASH_EXCLUDE}


def payload_hash(envelope: dict) -> str:
    return sha256_hex(payload_projection(envelope))


def job_fingerprint(job: dict) -> str:
    """X-1 fingerprint: campaign, config, tool/adapter version, image/manifest pin, refs/input, cycle."""
    if not isinstance(job, dict):
        raise CanonicalizationError("job must be a JSON object")
    missing = [field for field in JOB_FINGERPRINT_FIELDS if job.get(field) is None]
    if missing:
        # NULL pins belong to history only (0003/0005); they are never fingerprinted or dispatched.
        raise CanonicalizationError(f"job fingerprint input is missing {missing}")
    return sha256_hex({field: job[field] for field in JOB_FINGERPRINT_FIELDS})
