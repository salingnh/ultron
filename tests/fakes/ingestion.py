"""Fake M27 Ingestion: receipt-shaped answers with dedup_key replay, no database.

The receipt is scripted (a valid `ingest-receipt.v2` fixture) because the payload hash and revision
of the first commit are M27's business (C03, G1.4a). What the fake does own is the idempotency
rule the caller can observe: the same dedup_key with the same content returns the first receipt,
the same dedup_key with different content is a conflict.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from aegis.common.ports import Ingestion, IngestionConflict
from aegis.contracts_gen.ingestion.ingest_receipt_v2_schema import IngestReceipt
from aegis.contracts_gen.ingestion.result_envelope_v2_schema import ResultEnvelope

# event_id/dedup_key/trace are excluded from the business hash by the contract (C03); the fake only
# needs "same business content -> same fingerprint", not the contract's aegis-c14n/1 encoding.
EXCLUDED = {"event_id", "dedup_key", "trace"}


def _content_fingerprint(envelope: ResultEnvelope) -> str:
    payload = envelope.model_dump(mode="json", exclude=EXCLUDED)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


@dataclass
class FakeIngestion(Ingestion):
    """First submit returns the scripted receipt adapted to the envelope; replays are duplicates."""

    receipt: IngestReceipt
    _seen: dict[str, tuple[str, IngestReceipt]] = field(default_factory=dict, init=False)

    def submit(self, envelope: ResultEnvelope) -> IngestReceipt:
        fingerprint = _content_fingerprint(envelope)
        previous = self._seen.get(envelope.dedup_key)
        if previous is not None:
            recorded_fingerprint, receipt = previous
            if recorded_fingerprint != fingerprint:
                raise IngestionConflict(f"{envelope.dedup_key}: same dedup_key, different payload")
            return receipt.model_copy(update={"duplicate": True})
        receipt = self.receipt.model_copy(
            update={
                "event_id": envelope.event_id,
                "dedup_key": envelope.dedup_key,
                "duplicate": False,
            }
        )
        self._seen[envelope.dedup_key] = (fingerprint, receipt)
        return receipt
