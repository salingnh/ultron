"""M27 — ingestion gates G1–G7, inbox hash/receipt and outbox write (owner: G1.4a).

Modules:

* `canonical` — `aegis-c14n/1` payload/value hashes (C03);
* `normalize` — `aegis-norm/1` identity rules driven by the contract registry (G0.3c);
* `predicates` — the Observation predicate registry check (G4);
* `service` — `IngestionService`, the internal port and `POST /ingestion/results` pipeline;
* `router` — the FastAPI route and service-token check;
* `errors` — `EnvelopeRejected` (400, dead-lettered) and `IdempotencyConflict` (409).
"""

from __future__ import annotations

from aegis.m27_ingestion.service import IngestionService, is_ingestion

__all__ = ["IngestionService", "is_ingestion"]
