"""M28 evidence metadata rows: the `evidence` and `evidence_check` tables (0001).

The object lives in S3 (`store.S3EvidenceStore.put`); this is the PostgreSQL half: one append-only
row per stored object, keyed by `(job_id, sha256)`, plus one `evidence_check` row per SHA-256
re-read. M27's G3 gate resolves an envelope's evidence references against these rows, so the
collector writes the row right after the object verified: without it the ingestion of every
observation that cites the output would be quarantined as `evidence_reference_not_stored`.

`record()` is idempotent by `(job_id, sha256)`: a retried job re-uploads the same bytes and reuses
the row it already has.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from typing import Any

import psycopg

from aegis.common.ports import EvidenceObject
from aegis.contracts_gen.common.ids_v2_schema import Classification
from aegis.m06_runner.values import text

DSN_ENV = "AEGIS_PG_DSN"
SEARCH_PATH = "SET search_path = aegis, public"


class CatalogError(RuntimeError):
    """The evidence metadata could not be recorded; the collector must not pretend it was."""


class EvidenceCatalog:
    """`evidence` rows for the objects the collector stored."""

    def __init__(self, connect: Callable[[], psycopg.Connection[Any]]) -> None:
        self._connect = connect

    @classmethod
    def from_dsn(cls, dsn: str | None = None) -> EvidenceCatalog:
        target = dsn or os.environ.get(DSN_ENV)
        if not target:
            raise CatalogError(f"{DSN_ENV} is not set: M28 needs the control-plane PostgreSQL DSN")

        def _connect() -> psycopg.Connection[Any]:
            conn = psycopg.connect(target, autocommit=True)
            conn.execute(SEARCH_PATH)
            return conn

        return cls(_connect)

    def record(
        self,
        evidence: EvidenceObject,
        *,
        size_bytes: int,
        source_tool: str,
        kind: str = "raw_output",
        verified: bool = False,
        evidence_id: str | None = None,
    ) -> str:
        """Insert (or reuse) the row of one stored object; returns the evidence id.

        `evidence` is append-only (`forbid_update`), so `verified_at` is written once, at insert
        time, when the collector already read the object back; later re-reads are `evidence_check`
        rows.
        """
        classification = (
            evidence.classification.value
            if isinstance(evidence.classification, Classification)
            else str(evidence.classification)
        )
        with self._connect() as conn, conn.transaction():
            existing = conn.execute(
                "SELECT evidence_id FROM evidence WHERE job_id = %s AND sha256 = %s",
                (evidence.job_id, evidence.sha256),
            ).fetchone()
            if existing is not None:
                return str(existing[0])
            row = conn.execute(
                """
                INSERT INTO evidence (evidence_id, sha256, storage_uri, campaign_id, job_id,
                                      size_bytes, media_type, kind, classification, source_tool,
                                      verified_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        CASE WHEN %s THEN now() ELSE NULL END)
                RETURNING evidence_id
                """,
                (
                    evidence_id or _uuid7(),
                    evidence.sha256,
                    evidence.uri,
                    evidence.campaign_id,
                    evidence.job_id,
                    size_bytes,
                    evidence.media_type,
                    kind,
                    classification,
                    source_tool,
                    verified,
                ),
            ).fetchone()
        if row is None:
            raise CatalogError("the evidence row was not inserted")
        return str(row[0])

    def check(self, evidence_id: str, ok: bool, detail: str | None = None) -> None:
        """Record one hash re-read of the object (`evidence_check`, append-only)."""
        with self._connect() as conn, conn.transaction():
            conn.execute(
                "INSERT INTO evidence_check (evidence_id, ok, detail) VALUES (%s, %s, %s)",
                (evidence_id, ok, detail),
            )

    def rows(self, job_id: str) -> list[dict[str, Any]]:
        """The evidence rows of a job (tests and the read API)."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT evidence_id, sha256, storage_uri, size_bytes, media_type, kind,"
                " classification, verified_at FROM evidence WHERE job_id = %s ORDER BY sha256",
                (job_id,),
            ).fetchall()
        return [
            {
                "evidence_id": text(row[0]),
                "sha256": str(row[1]),
                "storage_uri": str(row[2]),
                "size_bytes": int(row[3]),
                "media_type": str(row[4]),
                "kind": str(row[5]),
                "classification": str(row[6]),
                "verified_at": row[7],
            }
            for row in rows
        ]


def _uuid7() -> str:
    from aegis.m06_runner.envelope import new_id

    return new_id()


def evidence_reference(evidence: EvidenceObject) -> Mapping[str, Any]:
    """The job callback's `evidence_refs` entry for one stored object."""
    return {"evidence_id": evidence.evidence_id, "sha256": evidence.sha256, "uri": evidence.uri}


__all__ = ["CatalogError", "EvidenceCatalog", "evidence_reference"]
