"""Feed sync of M18 (G1.6 slice C): download -> S3 (immutable) -> PostgreSQL -> intel.revision.v2.

One sync is one feed snapshot, in order (and in one transaction after the object is stored):

1. the exact bytes are stored in S3 under `feeds/<feed>/<version>/<sha256>.<ext>`: content
   addressed, so storing the same file twice is one object and the object cannot change under a
   snapshot;
2. `intel_snapshot` records `(feed, version)` once with the sha256, the source URI and `fetched_at`;
   the unique `(feed, version)` is the immutability guard: re-syncing the same version with
   different bytes is refused (`SnapshotConflict`), never silently overwritten;
3. each parsed record becomes a `vulnerability_revision` row, and only when its `content_hash`
   differs from the row already stored for `(vulnerability_id, source)` - `ON CONFLICT DO NOTHING`
   on 0001's unique `(vulnerability_id, source, content_hash)`, counted with `RETURNING`;
4. if at least one revision was written, `intel.revision.v2` is published to the outbox in the same
   transaction, so M20 re-runs matching on new evidence and never on a snapshot that did not commit.

The network is the CLI's job (`--source https://...` or `sync-nvd`), not this module's: a test or a
re-run from a downloaded file calls `sync` and the process never reaches a socket.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

import psycopg
from psycopg.types.json import Jsonb

from aegis.m18_intel import feeds
from aegis.m18_intel.feeds import VulnRecord

#: ids.v2 requires UUIDv7; M27 owns the generator today (one shared helper is a G1.4a proposal).
from aegis.m27_ingestion.ids import uuid7

__all__ = [
    "FeedSync",
    "FeedSyncError",
    "ObjectStore",
    "SnapshotConflict",
    "SyncReport",
    "connect",
    "connect_from_env",
    "object_key",
    "read_source",
]

SEARCH_PATH = "SET search_path = aegis, public"
PRODUCER = "M18"
EVENT_TYPE = "intel.revision.v2"
#: Where the raw feed bytes live in the bucket; separate from the evidence tree M28 owns.
OBJECT_PREFIX = "feeds"

Connection = psycopg.Connection[tuple[object, ...]]
Connect = Callable[[], Connection]

EXTENSIONS: Mapping[str, tuple[str, str]] = {
    feeds.NVD: ("json", "application/json"),
    feeds.KEV: ("json", "application/json"),
    feeds.EPSS: ("csv", "text/csv"),
}

#: The event schema bounds `impacted_ids` at 100000; a larger delta is truncated (documented).
IMPACTED_LIMIT = 100_000


class FeedSyncError(RuntimeError):
    """The snapshot could not be stored or loaded; nothing is half-applied."""


class SnapshotConflict(FeedSyncError):
    """`(feed, version)` already exists with different bytes: a published snapshot is immutable."""


class ObjectStore(Protocol):
    """The one object-store call a sync needs (M28's S3 client satisfies it)."""

    def put(self, key: str, data: bytes, *, content_type: str) -> None: ...

    def head(self, key: str) -> int | None: ...


@dataclass(frozen=True, slots=True)
class SyncReport:
    """What one sync did; the CLI prints it and the tests assert on it."""

    feed: str
    version: str
    snapshot_id: str
    records: int
    written: int
    unchanged: int
    withdrawn: int
    content_sha256: str
    storage_uri: str
    event_published: bool
    change_kinds: tuple[str, ...] = ()
    created_snapshot: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "feed": self.feed,
            "version": self.version,
            "snapshot_id": self.snapshot_id,
            "records": self.records,
            "written": self.written,
            "unchanged": self.unchanged,
            "withdrawn": self.withdrawn,
            "content_sha256": self.content_sha256,
            "storage_uri": self.storage_uri,
            "event_published": self.event_published,
            "change_kinds": list(self.change_kinds),
            "created_snapshot": self.created_snapshot,
        }


def object_key(feed: str, version: str, sha256: str, extension: str) -> str:
    return f"{OBJECT_PREFIX}/{feed}/{version}/{sha256}.{extension}"


def read_source(source: str) -> bytes:
    """The feed bytes from a local path or an `http(s)://` URL (the only network in this slice)."""
    if source.startswith(("http://", "https://")):
        import urllib.request

        with urllib.request.urlopen(source, timeout=120) as response:  # noqa: S310 - fixed scheme
            return bytes(response.read())
    return Path(source).read_bytes()


def connect(dsn: str) -> psycopg.Connection[dict[str, Any]]:
    """A dict-row connection in the contract search_path; autocommit like every other module.

    The search_path statement must not open an implicit transaction: `_load` then runs
    `connection.transaction()` as the snapshot's real transaction, and it commits. Without
    autocommit the earlier statement leaves a transaction open, `transaction()` becomes a
    savepoint, and closing the connection rolls the whole sync back (found by the demo gate).
    """
    from psycopg.rows import dict_row

    conn: psycopg.Connection[dict[str, Any]] = psycopg.connect(
        dsn, autocommit=True, row_factory=dict_row
    )
    conn.execute(SEARCH_PATH)
    return conn


def connect_from_env(env: Mapping[str, str] | None = None) -> psycopg.Connection[dict[str, Any]]:
    source = os.environ if env is None else env
    dsn = source.get("AEGIS_PG_DSN")
    if not dsn:
        raise FeedSyncError("AEGIS_PG_DSN is required to load an intel snapshot")
    return connect(dsn)


class FeedSync:
    """Loads feed snapshots and publishes the revision events; safe to run twice.

    `connect_` is a factory: one sync opens its own connection and closes it, so a sync can never
    commit half of a snapshot onto a connection someone else is using, and a caller that keeps its
    own connection (the matcher, a test) is unaffected.
    """

    def __init__(
        self,
        connect_: Callable[[], psycopg.Connection[Any]],
        store: ObjectStore,
        *,
        bucket: str = "evidence",
    ) -> None:
        self._connect = connect_
        self._store = store
        self._bucket = bucket

    def sync(
        self,
        feed: str,
        version: str,
        data: bytes,
        *,
        source_uri: str,
        snapshot_at: datetime | None = None,
        after_load: Callable[[psycopg.Connection[Any], str, Sequence[VulnRecord]], None]
        | None = None,
    ) -> SyncReport:
        if feed not in feeds.FEEDS:
            raise FeedSyncError(f"unknown feed {feed!r}; expected one of {', '.join(feeds.FEEDS)}")
        records = feeds.parse(feed, data, version=version)
        return self.sync_records(
            feed,
            version,
            data,
            records,
            source_uri=source_uri,
            snapshot_at=snapshot_at,
            after_load=after_load,
        )

    def sync_records(
        self,
        feed: str,
        version: str,
        data: bytes,
        records: Sequence[VulnRecord],
        *,
        source_uri: str,
        snapshot_at: datetime | None = None,
        after_load: Callable[[psycopg.Connection[Any], str, Sequence[VulnRecord]], None]
        | None = None,
    ) -> SyncReport:
        """Store raw feed bytes and load pre-parsed records in one atomic snapshot transaction."""
        if feed not in feeds.FEEDS:
            raise FeedSyncError(f"unknown feed {feed!r}; expected one of {', '.join(feeds.FEEDS)}")
        sha256 = hashlib.sha256(data).hexdigest()
        extension, media_type = EXTENSIONS[feed]
        key = object_key(feed, version, sha256, extension)
        if self._store.head(key) is None:
            self._store.put(key, data, content_type=media_type)
        moment = snapshot_at or feeds.snapshot_at_from(feed, data, fallback=datetime.now(UTC))
        return self._load(
            feed,
            version,
            records,
            sha256,
            key,
            source_uri,
            moment,
            after_load=after_load,
        )

    # -- internals ---------------------------------------------------------------------

    def _load(
        self,
        feed: str,
        version: str,
        records: Sequence[VulnRecord],
        sha256: str,
        key: str,
        source_uri: str,
        snapshot_at: datetime,
        *,
        after_load: Callable[[psycopg.Connection[Any], str, Sequence[VulnRecord]], None]
        | None = None,
    ) -> SyncReport:
        connection = self._connect()
        try:
            with connection.transaction():
                snapshot_id, created = self._snapshot(
                    connection, feed, version, snapshot_at, len(records), source_uri, sha256
                )
                previous = self._previous(connection, feed, [r.vulnerability_id for r in records])
                impacted, kinds = self._revisions(connection, feed, snapshot_id, records, previous)
                published = False
                if impacted:
                    published = self._emit(connection, feed, version, snapshot_at, impacted, kinds)
                if after_load is not None:
                    after_load(connection, snapshot_id, records)
            return SyncReport(
                feed=feed,
                version=version,
                snapshot_id=snapshot_id,
                records=len(records),
                written=len(impacted),
                unchanged=len(records) - len(impacted),
                withdrawn=sum(1 for record in records if record.withdrawn),
                content_sha256=sha256,
                storage_uri=f"s3://{self._bucket}/{key}",
                event_published=published,
                change_kinds=tuple(sorted(kinds)),
                created_snapshot=created,
            )
        except psycopg.Error as error:
            raise FeedSyncError(f"loading {feed}:{version} failed: {error}") from error
        finally:
            connection.close()

    def _snapshot(
        self,
        connection: psycopg.Connection[Any],
        feed: str,
        version: str,
        snapshot_at: datetime,
        count: int,
        source_uri: str,
        sha256: str,
    ) -> tuple[str, bool]:
        row = connection.execute(
            "INSERT INTO intel_snapshot (snapshot_id, feed, version, snapshot_at, record_count,"
            " source_uri, content_sha256) VALUES (%s, %s, %s, %s, %s, %s, %s)"
            " ON CONFLICT (feed, version) DO NOTHING"
            " RETURNING snapshot_id",
            (str(uuid7()), feed, version, snapshot_at, count, source_uri, sha256),
        ).fetchone()
        if row is not None:
            return str(row["snapshot_id"]), True
        existing = connection.execute(
            "SELECT snapshot_id, content_sha256 FROM intel_snapshot"
            " WHERE feed = %s AND version = %s",
            (feed, version),
        ).fetchone()
        if existing is None:  # pragma: no cover - the conflict proves it exists
            raise FeedSyncError(f"{feed}:{version} disappeared during the sync")
        if str(existing["content_sha256"]) != sha256:
            raise SnapshotConflict(
                f"{feed}:{version} is already stored with sha256 {existing['content_sha256']};"
                " the same version "
                "with different bytes is a new version, not a rewrite"
            )
        return str(existing["snapshot_id"]), False

    @staticmethod
    def _previous(
        connection: psycopg.Connection[Any], feed: str, ids: Sequence[str]
    ) -> dict[str, dict[str, Any]]:
        """The newest stored revision per vulnerability of this feed, before this sync writes."""
        wanted = sorted(set(ids))
        if not wanted:
            return {}
        rows = connection.execute(
            "SELECT DISTINCT ON (vulnerability_id) vulnerability_id, cvss, kev, epss, affected,"
            "       withdrawn"
            "  FROM vulnerability_revision"
            " WHERE source = %s AND vulnerability_id = ANY(%s)"
            " ORDER BY vulnerability_id, created_at DESC",
            (feed, wanted),
        ).fetchall()
        return {
            str(row["vulnerability_id"]): {
                "cvss": row["cvss"],
                "kev": row["kev"],
                "epss": row["epss"],
                "affected": row["affected"],
                "withdrawn": row["withdrawn"],
            }
            for row in rows
        }

    @staticmethod
    def _revisions(
        connection: psycopg.Connection[Any],
        feed: str,
        snapshot_id: str,
        records: Sequence[VulnRecord],
        previous: Mapping[str, Mapping[str, Any]],
    ) -> tuple[list[str], set[str]]:
        """Insert changed revisions in one batch SQL call and return impacted CVE ids + kinds."""
        if not records:
            return [], set()
        batch_rows: list[dict[str, Any]] = []
        by_id_hash: dict[tuple[str, str], VulnRecord] = {}
        for record in records:
            digest = record.content_hash()
            by_id_hash[(record.vulnerability_id, digest)] = record
            batch_rows.append(
                {
                    "vuln_rev_id": str(uuid7()),
                    "vulnerability_id": record.vulnerability_id,
                    "aliases": list(record.aliases),
                    "cvss": record.cvss,
                    "kev": record.kev,
                    "epss": record.epss,
                    "affected": record.affected,
                    "references_": record.references,
                    "published_at": _iso_or_none(record.published_at),
                    "modified_at": _iso_or_none(record.modified_at),
                    "withdrawn": record.withdrawn,
                    "content_hash": digest,
                }
            )
        inserted = connection.execute(
            "INSERT INTO vulnerability_revision (vuln_rev_id, vulnerability_id, source,"
            " snapshot_id, aliases, cvss, kev, epss, affected, references_, published_at,"
            " modified_at, withdrawn, content_hash)"
            " SELECT r.vuln_rev_id, r.vulnerability_id, %s, %s, r.aliases,"
            "        r.cvss, r.kev, r.epss, r.affected, r.references_, r.published_at,"
            "        r.modified_at, r.withdrawn, r.content_hash"
            "   FROM jsonb_to_recordset(%s::jsonb) AS r("
            "     vuln_rev_id uuid,"
            "     vulnerability_id text,"
            "     aliases text[],"
            "     cvss jsonb,"
            "     kev jsonb,"
            "     epss jsonb,"
            "     affected jsonb,"
            "     references_ jsonb,"
            "     published_at timestamptz,"
            "     modified_at timestamptz,"
            "     withdrawn boolean,"
            "     content_hash character(64)"
            "   )"
            " ON CONFLICT (vulnerability_id, source, content_hash) DO NOTHING"
            " RETURNING vulnerability_id, content_hash",
            (feed, snapshot_id, json.dumps(batch_rows, ensure_ascii=False)),
        ).fetchall()
        impacted: list[str] = []
        kinds: set[str] = set()
        for row in inserted:
            vid = str(row["vulnerability_id"])
            digest = str(row["content_hash"])
            impacted.append(vid)
            record_hit = by_id_hash.get((vid, digest))
            if record_hit is not None:
                kinds.add(_change_kind(feed, record_hit, previous.get(vid)))
        return impacted, kinds

    @staticmethod
    def _emit(
        connection: psycopg.Connection[Any],
        feed: str,
        version: str,
        snapshot_at: datetime,
        impacted: Sequence[str],
        kinds: set[str],
    ) -> bool:
        """Publish `intel.revision.v2`; the dedup key is the feed snapshot, not the record."""
        payload: dict[str, Any] = {
            "feed": feed,
            "version": version,
            "snapshot_at": snapshot_at.astimezone(UTC)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "impacted_ids": list(dict.fromkeys(impacted))[:IMPACTED_LIMIT],
        }
        if kinds:
            payload["change_kinds"] = sorted(kinds)
        row = connection.execute(
            "INSERT INTO outbox_event (event_id, type, producer, dedup_key, campaign_id, payload,"
            " trace) VALUES (%s, %s, %s, %s, NULL, %s, %s)"
            " ON CONFLICT (type, dedup_key) DO NOTHING RETURNING event_id",
            (
                str(uuid7()),
                EVENT_TYPE,
                PRODUCER,
                f"{feed}:{version}",
                Jsonb(payload),
                Jsonb({"trace_id": uuid4().hex}),
            ),
        ).fetchone()
        return row is not None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> FeedSync:
        from aegis.m28_evidence.store import S3Config, S3EvidenceClient

        config = S3Config.from_env(env)
        return cls(lambda: connect_from_env(env), S3EvidenceClient(config), bucket=config.bucket)


def _iso_or_none(moment: datetime | None) -> str | None:
    if moment is None:
        return None
    return moment.astimezone(UTC).isoformat()


def _change_kind(feed: str, record: VulnRecord, previous: Mapping[str, Any] | None) -> str:
    """Classify what this revision changes, for the event's `change_kinds`.

    Only a *content* change reaches this function (unchanged bytes are dropped by the unique
    `(vulnerability_id, source, content_hash)`), so the fallback is always "a new revision".
    """
    if previous is None:
        return "new_vuln"
    if record.withdrawn and not previous.get("withdrawn"):
        return "withdrawn"
    if feed == feeds.KEV:
        if record.kev is not None and previous.get("kev") is None:
            return "kev_added"
        if record.kev is None and previous.get("kev") is not None:
            return "kev_removed"
        return "new_vuln"
    if feed == feeds.EPSS:
        return "epss_changed"
    if record.affected != previous.get("affected"):
        return "affected_range_changed"
    if record.cvss != previous.get("cvss"):
        return "cvss_changed"
    return "new_vuln"
