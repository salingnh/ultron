"""UUIDv7 values for the identifiers M27 mints (RFC 9562, `common/ids.v2.schema.json#/$defs/Id`).

Every id the contract exposes is a UUIDv7: asset, observation, relationship, provenance,
quarantine and the event_id of an outbox event. PostgreSQL 16 has no `uuidv7()` and the standard
library only gained `uuid.uuid7()` after 3.12, so the layout is built here: 48-bit Unix
millisecond timestamp, version 7, 12 random bits, variant 10, 62 random bits. Uniqueness comes
from the 74 random bits; monotonicity inside a millisecond is not promised, and nothing in the
contract compares ids by order.
"""

from __future__ import annotations

import os
import time
from uuid import UUID

__all__ = ["uuid7"]

_MS_MASK = (1 << 48) - 1
_RAND_A_MASK = (1 << 12) - 1
_RAND_B_MASK = (1 << 62) - 1


def uuid7() -> UUID:
    """A new UUIDv7 string value (lowercase, sortable by its embedded timestamp)."""
    milliseconds = (time.time_ns() // 1_000_000) & _MS_MASK
    randomness = int.from_bytes(os.urandom(10), "big")
    value = (
        (milliseconds << 80)
        | (0x7 << 76)
        | (((randomness >> 62) & _RAND_A_MASK) << 64)
        | (0b10 << 62)
        | (randomness & _RAND_B_MASK)
    )
    return UUID(int=value)
