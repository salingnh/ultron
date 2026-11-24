"""UUIDv7 identifiers for the M01 tables (contract: §Định danh, D2).

Every id in the contract is a lowercase UUIDv7, which sorts by creation time to the
millisecond. PostgreSQL and the contract schemas only check the shape, so the
generator lives here: 48 bits of Unix milliseconds, version 7, 12 bits `rand_a`,
the `10` variant, 62 bits `rand_b`.

Two ids minted in the same millisecond are ordered by their random tail; the
database cursor of the campaign list therefore orders by `(created_at,
campaign_id)` and never relies on the id alone.
"""

from __future__ import annotations

import os
import time
import uuid

__all__ = ["new_id", "uuid7"]

_VERSION = 0x7
_VARIANT = 0b10
_MILLISECONDS = 1 << 48


def uuid7(timestamp_ms: int | None = None) -> uuid.UUID:
    """A UUIDv7 for `timestamp_ms` (default: now)."""
    millis = time.time_ns() // 1_000_000 if timestamp_ms is None else timestamp_ms
    if not 0 <= millis < _MILLISECONDS:
        raise ValueError("UUIDv7 needs a 48-bit Unix millisecond timestamp")
    random_seed = int.from_bytes(os.urandom(10), "big")  # 80 random bits for the tail
    rand_a = (random_seed >> 68) & 0x0FFF
    rand_b = random_seed & ((1 << 62) - 1)
    value = (millis << 80) | (_VERSION << 76) | (rand_a << 64) | (_VARIANT << 62) | rand_b
    return uuid.UUID(int=value)


def new_id() -> str:
    """A new UUIDv7 as the lowercase string the contract uses."""
    return str(uuid7())
