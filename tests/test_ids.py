"""UUIDv7 shape and ordering (contract: every id is a lowercase UUIDv7)."""

from __future__ import annotations

import time
import uuid

from aegis.m01_campaign.ids import new_id, uuid7


def test_uuid7_has_the_contract_shape() -> None:
    generated = uuid7()
    assert isinstance(generated, uuid.UUID)
    assert generated.version == 7
    assert generated.variant == uuid.RFC_4122
    assert str(generated) == str(generated).lower()
    generated_id = new_id()
    assert generated_id == str(uuid.UUID(generated_id))


def test_uuid7_carries_the_millisecond_timestamp() -> None:
    millis = int(time.time() * 1000)
    generated = uuid7(millis)
    assert (generated.int >> 80) == millis


def test_uuid7_sorts_by_timestamp_and_never_repeats() -> None:
    early = uuid7(1_700_000_000_000)
    late = uuid7(1_700_000_001_000)
    assert early < late
    same_millisecond = {uuid7(1_700_000_000_000) for _ in range(100)}
    assert len(same_millisecond) == 100
