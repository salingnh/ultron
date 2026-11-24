"""The manifest registry: immutable records keyed by SHA-256, plus the resolution query.

Two implementations of the same small interface:

* `InMemoryManifestRegistry` - the MCP server's tool catalogue (G1.2b) and unit tests;
* `PostgresManifestRegistry` - the durable one (migration 0016). The table stores the exact bytes
  and
  a CHECK proves the hash describes them; this class re-derives the pins from those bytes on every
  read, so a disagreement between the stored index columns and the document is a loud error, not a
  quiet wrong pin.

Resolution ("which manifest serves this capability now") is a query over accepted records; it is
only
used when accepting a *new* job. Every accepted job pins `manifest_sha256` and is served by `get()`
afterwards - never by "latest" (contracts/interfaces/README.md §Manifest bất biến).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, Protocol

import psycopg
from psycopg.types.json import Jsonb

from aegis.m05_registry.manifest import ManifestRecord, admit_manifest, parse_document

__all__ = [
    "ManifestRegistry",
    "InMemoryManifestRegistry",
    "PostgresManifestRegistry",
    "ManifestNotFound",
    "ManifestVersionConflict",
]


class ManifestNotFound(LookupError):
    """No accepted manifest serves this hash/capability; the caller must not invent one."""


class ManifestVersionConflict(ValueError):
    """The same adapter version exists with different bytes: a re-registration, not a new build."""


class ManifestRegistry(Protocol):
    def register(self, raw: bytes, *, registered_by: dict[str, str]) -> ManifestRecord: ...

    def get(self, sha256: str) -> ManifestRecord: ...

    def resolve(self, capability: str, provider: str | None = None) -> ManifestRecord: ...

    def all(self) -> tuple[ManifestRecord, ...]: ...


def _check_version_conflict(existing: Iterable[ManifestRecord], record: ManifestRecord) -> None:
    for other in existing:
        if (
            other.capability,
            other.provider,
            other.provider_version,
            other.adapter_version,
        ) == (record.capability, record.provider, record.provider_version, record.adapter_version):
            if other.sha256 != record.sha256:
                raise ManifestVersionConflict(
                    f"{record.capability}/{record.provider} {record.provider_version} "
                    f"(adapter {record.adapter_version}) is already registered as "
                    f"{other.sha256}; a different build needs a new adapter_version"
                )


@dataclass
class InMemoryManifestRegistry:
    """Ordered registry for tests and the MCP tool catalogue (no database)."""

    _records: dict[str, ManifestRecord] = field(default_factory=dict, init=False)

    def register(self, raw: bytes, *, registered_by: dict[str, str]) -> ManifestRecord:
        record = admit_manifest(raw)
        if record.sha256 in self._records:
            return self._records[record.sha256]
        _check_version_conflict(self._records.values(), record)
        self._records[record.sha256] = record
        return record

    def get(self, sha256: str) -> ManifestRecord:
        try:
            return self._records[sha256]
        except KeyError as error:
            raise ManifestNotFound(
                f"manifest {sha256} is not in the registry (no 'latest' fallback)"
            ) from error

    def resolve(self, capability: str, provider: str | None = None) -> ManifestRecord:
        matches = [
            record
            for record in self._records.values()
            if record.capability == capability and (provider is None or record.provider == provider)
        ]
        if not matches:
            raise ManifestNotFound(
                f"no registered provider serves capability {capability!r}"
                + (f" for provider {provider!r}" if provider else "")
            )
        return matches[-1]

    def all(self) -> tuple[ManifestRecord, ...]:
        return tuple(self._records.values())


class PostgresManifestRegistry:
    """Registry backed by `aegis.provider_manifest` (0016); append-only, keyed by exact bytes."""

    def __init__(self, connect: Callable[[], psycopg.Connection[Any]]) -> None:
        self._connect = connect

    def register(self, raw: bytes, *, registered_by: dict[str, str]) -> ManifestRecord:
        record = admit_manifest(raw)
        with self._connect() as conn, conn.transaction():
            existing = conn.execute(
                "SELECT manifest_utf8 FROM provider_manifest WHERE manifest_sha256 = %s",
                (record.sha256,),
            ).fetchone()
            if existing is not None:
                return self._current(conn, record.sha256)
            _check_version_conflict(self._version_rows(conn, record), record)
            conn.execute(
                """
                INSERT INTO provider_manifest (
                  manifest_sha256, capability, provider, provider_version, adapter_version,
                  image_digest, input_schema_ref, manifest_utf8, registered_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    record.sha256,
                    record.capability,
                    record.provider,
                    record.provider_version,
                    record.adapter_version,
                    record.image_digest,
                    record.input_schema_ref,
                    raw,
                    Jsonb(registered_by),
                ),
            )
        return record

    def get(self, sha256: str) -> ManifestRecord:
        with self._connect() as conn:
            return self._current(conn, sha256, missing_is_error=True)

    def resolve(self, capability: str, provider: str | None = None) -> ManifestRecord:
        query = (
            "SELECT manifest_sha256 FROM provider_manifest WHERE capability = %s"
            + (" AND provider = %s" if provider else "")
            + " ORDER BY registered_at DESC, manifest_sha256 DESC LIMIT 1"
        )
        params: tuple[Any, ...] = (capability, provider) if provider else (capability,)
        with self._connect() as conn:
            row = conn.execute(query, params).fetchone()
            if row is None:
                raise ManifestNotFound(
                    f"no registered provider serves capability {capability!r}"
                    + (f" for provider {provider!r}" if provider else "")
                )
            return self._current(conn, str(row[0]))

    def all(self) -> tuple[ManifestRecord, ...]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT manifest_sha256 FROM provider_manifest "
                "ORDER BY registered_at, manifest_sha256"
            ).fetchall()
            return tuple(self._current(conn, str(row[0])) for row in rows)

    # --- internals ----------------------------------------------------------------------
    @staticmethod
    def _version_rows(
        conn: psycopg.Connection[Any], record: ManifestRecord
    ) -> list[ManifestRecord]:
        rows = conn.execute(
            "SELECT manifest_sha256 FROM provider_manifest WHERE capability = %s "
            "AND provider = %s AND provider_version = %s AND adapter_version = %s",
            (
                record.capability,
                record.provider,
                record.provider_version,
                record.adapter_version,
            ),
        ).fetchall()
        return [PostgresManifestRegistry._current(conn, str(row[0])) for row in rows]

    @staticmethod
    def _current(
        conn: psycopg.Connection[Any], sha256: str, *, missing_is_error: bool = False
    ) -> ManifestRecord:
        row = conn.execute(
            "SELECT manifest_sha256, capability, provider, provider_version, adapter_version, "
            "manifest_utf8 FROM provider_manifest WHERE manifest_sha256 = %s",
            (sha256,),
        ).fetchone()
        if row is None:
            if missing_is_error:
                raise ManifestNotFound(
                    f"manifest {sha256} is not in the registry (no 'latest' fallback)"
                )
            raise ManifestNotFound(f"manifest {sha256} disappeared while registering")
        raw = bytes(row[5])
        record = ManifestRecord(sha256=str(row[0]), raw=raw, document=parse_document(raw))
        stored = (str(row[1]), str(row[2]), str(row[3]), str(row[4]))
        derived = (
            record.capability,
            record.provider,
            record.provider_version,
            record.adapter_version,
        )
        if stored != derived:
            raise ManifestVersionConflict(
                f"manifest {sha256}: stored index {stored} disagrees with the pinned bytes "
                f"{derived}"
            )
        return record
