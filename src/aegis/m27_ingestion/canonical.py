"""`aegis-c14n/1` — the canonical form M27 uses for every content hash (C03).

Normative rules: contracts/ingestion/canonicalization.v2.yaml. Golden vectors:
contracts/fixtures/golden/hash/canonicalization.vectors.json. The reference implementation lives in
contracts/tests/canonicalization.py and is test-only; this module is the service-side
implementation of the same bytes (RFC 8785 JSON Canonicalization Scheme plus NFC-normalized
strings and keys, duplicate-key rejection and I-JSON number limits).

Two projections are used here:

* `payload_hash(envelope)` — sha256 over the ResultEnvelope minus `event_id`, `dedup_key` and
  `trace`; `ingestion_inbox.payload_hash` stores it and a re-submission compares it verbatim.
* `sha256_hex(value)` — the `observation.value_hash` fast comparison column, over the same
  canonical form.
"""

from __future__ import annotations

import hashlib
import math
import unicodedata
from collections.abc import Mapping
from decimal import Decimal
from typing import Any, cast

__all__ = [
    "HASH_VERSION",
    "CanonicalizationError",
    "canonical_bytes",
    "canonical_text",
    "payload_hash",
    "payload_projection",
    "sha256_hex",
]

HASH_VERSION = "aegis-c14n/1"

#: ResultEnvelope top-level fields that are submission identity/tracing, not business content.
PAYLOAD_HASH_EXCLUDE = frozenset({"event_id", "dedup_key", "trace"})

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
    """The value has no single deterministic canonical form; M27 rejects it loudly."""


def _utf16_key(text: str) -> bytes:
    """RFC 8785 orders object keys by UTF-16 code units, not by Unicode code point."""
    return text.encode("utf-16-be")


def _normalized(value: str) -> str:
    text = unicodedata.normalize("NFC", value)
    try:
        text.encode("utf-8")
    except UnicodeEncodeError as error:  # lone surrogate: not a Unicode scalar value
        raise CanonicalizationError(f"string is not valid Unicode: {value!r}") from error
    return text


def _string(value: str) -> str:
    out = ['"']
    for character in _normalized(value):
        escaped = _ESCAPES.get(character)
        if escaped is not None:
            out.append(escaped)
        elif character < " ":
            out.append(f"\\u{ord(character):04x}")
        else:
            out.append(character)
    out.append('"')
    return "".join(out)


def _shortest_digits(value: float) -> tuple[str, int]:
    """Shortest decimal digits that round-trip to `value`, plus their power-of-ten exponent."""
    _, digits, exponent_value = Decimal(repr(value)).as_tuple()
    exponent = cast(int, exponent_value)
    text = "".join(str(digit) for digit in digits)
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
    length = len(digits)
    point = length + exponent
    if length <= point <= 21:
        return sign + digits + "0" * (point - length)
    if 0 < point <= 21:
        return f"{sign}{digits[:point]}.{digits[point:]}"
    if -6 < point <= 0:
        return sign + "0." + "0" * (-point) + digits
    mantissa = digits if length == 1 else f"{digits[0]}.{digits[1:]}"
    return f"{sign}{mantissa}e{'+' if point - 1 >= 0 else '-'}{abs(point - 1)}"


def _number(value: int | float) -> str:
    """A number has one canonical form only if a double holds it exactly (I-JSON, RFC 7493)."""
    if isinstance(value, bool):  # bool is an int subclass in Python and must stay "true"/"false"
        raise CanonicalizationError("bool is not a number")
    if isinstance(value, int):
        try:
            as_double = float(value)
        except OverflowError as error:
            raise CanonicalizationError(f"integer {value} is outside the double range") from error
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


def _encode(value: object) -> str:
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
    if isinstance(value, Mapping):
        return _object(value)
    raise CanonicalizationError(f"unsupported JSON value type {type(value).__name__}")


def _object(value: Mapping[object, Any]) -> str:
    pairs: list[tuple[str, object]] = []
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


def canonical_text(value: object) -> str:
    """The canonical UTF-8 text of a JSON value (no trailing newline)."""
    return _encode(value)


def canonical_bytes(value: object) -> bytes:
    return canonical_text(value).encode("utf-8")


def sha256_hex(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def payload_projection(envelope: Mapping[str, object]) -> dict[str, object]:
    """The business content of a ResultEnvelope: everything except submission id, key and trace."""
    return {key: value for key, value in envelope.items() if key not in PAYLOAD_HASH_EXCLUDE}


def payload_hash(envelope: Mapping[str, object]) -> str:
    """`ingestion_inbox.payload_hash`: sha256 over the envelope minus event_id/dedup_key/trace."""
    return sha256_hex(payload_projection(envelope))
