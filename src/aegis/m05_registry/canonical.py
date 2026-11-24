"""`aegis-c14n/1` for M05 hashes: the job fingerprint and the ApprovedTask signing input.

Normative rules and field lists: `contracts/ingestion/canonicalization.v2.yaml`; golden vectors:
`contracts/fixtures/golden/hash/canonicalization.vectors.json`; executable reference (tests only):
`contracts/tests/canonicalization.py`. The contract allows any implementation that reproduces those
bytes, so this module implements them in `src/` instead of importing test code into a service, and
`tests/test_m05_canonical.py` proves byte equality with the reference and the golden vectors.

aegis-c14n/1 = RFC 8785 (JCS) plus NFC normalization of every string and object key, rejection of
keys that collide after NFC, and rejection of numbers a double does not hold exactly.
"""

from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from decimal import Decimal
from typing import Any

__all__ = [
    "HASH_VERSION",
    "JOB_FINGERPRINT_FIELDS",
    "CanonicalizationError",
    "canonical_bytes",
    "canonical_text",
    "job_fingerprint",
    "loads",
    "sha256_hex",
]

HASH_VERSION = "aegis-c14n/1"

#: X-1: the single job fingerprint composition (contracts/ingestion/canonicalization.v2.yaml).
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
    """The value has no single deterministic canonical form; it is rejected, never coerced."""


def _utf16_key(text: str) -> bytes:
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
    sign, digits, raw_exponent = Decimal(repr(value)).as_tuple()
    del sign
    exponent = int(raw_exponent)
    text = "".join(map(str, digits))
    while len(text) > 1 and text.endswith("0"):
        text = text[:-1]
        exponent += 1
    return text, exponent


def _double(value: float) -> str:
    if value == 0:
        return "0"
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
    if isinstance(value, bool):
        raise CanonicalizationError("bool is not a number")
    if isinstance(value, int):
        try:
            as_double = float(value)
        except OverflowError as exc:
            raise CanonicalizationError(f"integer {value} is outside the double range") from exc
        if not math.isfinite(as_double) or int(as_double) != value:
            raise CanonicalizationError(
                f"integer {value} does not survive IEEE-754 double round-tripping (I-JSON)"
            )
        return _double(as_double)
    if not isinstance(value, float):
        raise CanonicalizationError(f"unsupported number type {type(value).__name__}")
    if not math.isfinite(value):
        raise CanonicalizationError(f"non-finite number {value!r}")
    return _double(value)


def _encode(value: Any) -> str:
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


def _object(value: dict[str, Any]) -> str:
    pairs: list[tuple[str, Any]] = []
    seen: set[str] = set()
    for key, item in value.items():
        if not isinstance(key, str):
            raise CanonicalizationError("object keys must be strings")
        normalized_key = _normalized(key)
        if normalized_key in seen:
            raise CanonicalizationError(
                f"object keys collide after NFC normalization: {normalized_key!r}"
            )
        seen.add(normalized_key)
        pairs.append((normalized_key, item))
    pairs.sort(key=lambda pair: _utf16_key(pair[0]))
    return "{" + ",".join(f"{_string(key)}:{_encode(item)}" for key, item in pairs) + "}"


def canonical_text(value: Any) -> str:
    """The canonical UTF-8 text of a JSON value (no trailing newline)."""
    return _encode(value)


def canonical_bytes(value: Any) -> bytes:
    return canonical_text(value).encode("utf-8")


def sha256_hex(value: Any) -> str:
    """sha256 of the canonical bytes, as the lowercase hex the contract regexes expect."""
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _reject_constant(name: str) -> Any:
    raise CanonicalizationError(f"non-finite number {name} is not JSON")


def _pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise CanonicalizationError("duplicate object key in JSON text")
    normalized = [_normalized(key) for key in result]
    if len(set(normalized)) != len(normalized):
        raise CanonicalizationError("object keys collide after NFC normalization in JSON text")
    return result


def loads(text: str) -> Any:
    """Parse JSON text with the strictness the canonical form needs (duplicates rejected)."""
    try:
        return json.loads(text, object_pairs_hook=_pairs_hook, parse_constant=_reject_constant)
    except json.JSONDecodeError as exc:
        raise CanonicalizationError(f"invalid JSON: {exc}") from exc


def job_fingerprint(job: dict[str, Any]) -> str:
    """X-1 fingerprint over JOB_FINGERPRINT_FIELDS; a missing pin is refused, not hashed."""
    if not isinstance(job, dict):
        raise CanonicalizationError("job must be a JSON object")
    missing = [field for field in JOB_FINGERPRINT_FIELDS if job.get(field) is None]
    if missing:
        raise CanonicalizationError(f"job fingerprint input is missing {missing}")
    return sha256_hex({field: job[field] for field in JOB_FINGERPRINT_FIELDS})
