"""Fake M28 EvidenceStore: content-addressed objects held in memory, no S3 client."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from aegis.common.ports import EvidenceObject, EvidenceStore, Excerpt
from aegis.contracts_gen.common.ids_v2_schema import Classification

EXCERPT_LIMIT = 8 * 1024


@dataclass
class FakeEvidenceStore(EvidenceStore):
    """`put` is idempotent by sha256, like the `s3://evidence/{campaign}/{job}/{sha256}` key.

    `tamper` is a test helper that corrupts the stored bytes so `verify` can be shown to fail.
    """

    _objects: dict[str, bytes] = field(default_factory=dict, init=False)
    _metadata: dict[str, EvidenceObject] = field(default_factory=dict, init=False)

    def put(
        self,
        campaign_id: str,
        job_id: str,
        path: Path,
        media_type: str,
        classification: Classification,
    ) -> EvidenceObject:
        content = path.read_bytes()
        sha256 = hashlib.sha256(content).hexdigest()
        existing = self._metadata.get(sha256)
        if existing is not None:
            return existing
        evidence = EvidenceObject(
            evidence_id=sha256,
            campaign_id=campaign_id,
            job_id=job_id,
            sha256=sha256,
            uri=f"s3://evidence/{campaign_id}/{job_id}/{sha256}",
            media_type=media_type,
            classification=classification,
        )
        self._objects[sha256] = content
        self._metadata[sha256] = evidence
        return evidence

    def signed_url(self, evidence_id: str, ttl_seconds: int = 300) -> str:
        self._require(evidence_id)
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        return f"fake-s3://evidence/{evidence_id}?ttl={ttl_seconds}"

    def excerpt(self, evidence_id: str, offset: int, max_bytes: int) -> Excerpt:
        content = self._require(evidence_id)
        if offset < 0:
            raise ValueError("offset must be >= 0")
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        limit = min(max_bytes, EXCERPT_LIMIT)
        data = content[offset : offset + limit]
        truncated = offset + len(data) < len(content)
        return Excerpt(evidence_id=evidence_id, offset=offset, data=data, truncated=truncated)

    def verify(self, evidence_id: str) -> bool:
        content = self._objects.get(evidence_id)
        if content is None:
            return False
        return hashlib.sha256(content).hexdigest() == evidence_id

    def tamper(self, evidence_id: str) -> None:
        """Test helper: replace the stored bytes with something else (not part of the interface)."""
        self._require(evidence_id)
        self._objects[evidence_id] = b"tampered"

    def _require(self, evidence_id: str) -> bytes:
        content = self._objects.get(evidence_id)
        if content is None:
            raise KeyError(f"unknown evidence {evidence_id}")
        return content
