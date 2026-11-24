"""Typed failures of the M27 endpoint.

`EnvelopeRejected` means the envelope as a whole is refused before it is accepted: a contract
violation, a job/campaign/seed that does not belong together, or a dedup_key that is not the job's.
M27 records it in `dead_letter` (the payload is not silently dropped) and answers 400 `Error`.

`IdempotencyConflict` is the C03 409: the same dedup_key already committed a different business
content (or an unversioned hash). The decision and its `ingestion_attempt` row are committed first,
then the failure is raised, so a conflicting submission stays auditable.
"""

from __future__ import annotations

from aegis.common.ports import IngestionConflict

__all__ = ["EnvelopeRejected", "IdempotencyConflict"]


class EnvelopeRejected(Exception):
    """The whole envelope is refused; `error` is the contract `Error` payload for the caller."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        field: str | None = None,
        next_action: str = "FIX_INPUT",
    ) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.field = field
        self.next_action = next_action


class IdempotencyConflict(IngestionConflict):
    """Same dedup_key with different content: 409 IDEMPOTENCY_CONFLICT, nothing is overwritten."""

    def __init__(self, dedup_key: str, existing_payload_hash: str, reason: str) -> None:
        super().__init__(f"{dedup_key}: {reason}")
        self.dedup_key = dedup_key
        self.existing_payload_hash = existing_payload_hash
        self.reason = reason
