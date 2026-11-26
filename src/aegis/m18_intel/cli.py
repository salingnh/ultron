"""Operator CLI of M18 (`python -m aegis.m18_intel <sync|sync-nvd|plan>`).

* `sync` - store one feed snapshot in S3 and load it into PostgreSQL, then publish
  `intel.revision.v2`. `--source` is a local path (a committed fixture slice, the CI/demo path) or
  an `http(s)` URL (the operator's refresh). Exit 0 on success, 1 on a refused snapshot.
* `sync-nvd` - paged NVD CVE API 2.0 bulk (all years) and incremental (`lastModified`) sync,
  resumable and idempotent. Optional API key is read only from the file named by
  `AEGIS_NVD_API_KEY_FILE` (never in argv or logs).
* `plan` - print the snapshots and latest NVD sync checkpoint already loaded, so an operator can
  see which intel the matcher will use before running it.

Environment: `AEGIS_PG_DSN`, S3 settings (`AEGIS_S3_ENDPOINT`, `AEGIS_S3_BUCKET`, optional
`AEGIS_S3_ACCESS_KEY`/`AEGIS_S3_SECRET_KEY`), and optional `AEGIS_NVD_API_KEY_FILE`.
Nothing here starts or removes a container.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from typing import Any

from aegis.m18_intel import feeds
from aegis.m18_intel.nvd_api import DEFAULT_RESULTS_PER_PAGE, NvdApiSync, NvdPageProgress
from aegis.m18_intel.sync import FeedSync, FeedSyncError, read_source


def _moment(text: str | None) -> datetime | None:
    if text is None:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _plan() -> int:
    from aegis.m18_intel.sync import connect_from_env

    connection = connect_from_env()
    try:
        rows = connection.execute(
            "SELECT feed, version, snapshot_id, snapshot_at, fetched_at, record_count,"
            "       content_sha256, source_uri"
            "  FROM intel_snapshot ORDER BY feed, snapshot_at DESC"
        ).fetchall()
        checkpoint_row = connection.execute(
            "SELECT run_id, mode, status, next_start_index, total_results, results_per_page,"
            "       window_start, window_end, last_modified_watermark, created_at"
            "  FROM intel_sync_checkpoint"
            " WHERE feed = 'nvd'"
            " ORDER BY created_at DESC, checkpoint_id DESC"
            " LIMIT 1"
        ).fetchone()
    finally:
        connection.close()
    document: dict[str, Any] = {
        "snapshots": [
            {
                "feed": row["feed"],
                "version": row["version"],
                "snapshot_id": str(row["snapshot_id"]),
                "snapshot_at": row["snapshot_at"],
                "fetched_at": row["fetched_at"],
                "record_count": row["record_count"],
                "content_sha256": row["content_sha256"],
                "source_uri": row["source_uri"],
            }
            for row in rows
        ],
        "nvd_checkpoint": dict(checkpoint_row) if checkpoint_row is not None else None,
    }
    print(json.dumps(document, indent=2, default=str))
    return 0


def _sync(argv: argparse.Namespace) -> int:
    try:
        data = read_source(argv.source)
        sync = FeedSync.from_env()
        report = sync.sync(
            argv.feed,
            argv.version,
            data,
            source_uri=argv.source,
            snapshot_at=_moment(argv.snapshot_at),
        )
    except (FeedSyncError, feeds.FeedError, ValueError, OSError) as error:
        print(f"intel sync refused: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report.as_dict(), indent=2))
    return 0


def _sync_nvd(argv: argparse.Namespace) -> int:
    def _progress(event: NvdPageProgress) -> None:
        if not argv.quiet:
            print(
                f"[m18] nvd {event.mode} {event.run_id} "
                f"w={event.window_index}/{event.window_total} "
                f"page={event.page} start={event.start_index}/{event.total_results} "
                f"records={event.page_records} written={event.written} "
                f"unchanged={event.unchanged} elapsed={event.elapsed_seconds:.1f}s",
                file=sys.stderr,
                flush=True,
            )

    try:
        syncer = NvdApiSync.from_env(api_url=argv.api_url)
        report = syncer.sync(
            mode=argv.mode,
            version=argv.version,
            since=_moment(argv.since),
            until=_moment(argv.until),
            results_per_page=argv.results_per_page,
            max_pages=argv.max_pages,
            resume=not argv.no_resume,
            on_page=_progress,
        )
    except (FeedSyncError, feeds.FeedError, ValueError, OSError) as error:
        print(f"nvd api sync refused: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report.as_dict(), indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m aegis.m18_intel")
    sub = parser.add_subparsers(dest="command", required=True)
    sync = sub.add_parser("sync", help="load one feed snapshot")
    sync.add_argument("--feed", required=True, choices=list(feeds.FEEDS))
    sync.add_argument("--version", required=True, help="snapshot version, e.g. the export date")
    sync.add_argument("--source", required=True, help="local path or http(s) URL of the export")
    sync.add_argument(
        "--snapshot-at",
        default=None,
        help="when the feed says the set is from (default: the feed's own date, else now)",
    )
    sync_nvd = sub.add_parser(
        "sync-nvd",
        help="paged NVD CVE 2.0 bulk + incremental sync (optional key via AEGIS_NVD_API_KEY_FILE)",
    )
    sync_nvd.add_argument(
        "--mode",
        choices=["auto", "full", "incremental"],
        default="auto",
        help=(
            "auto (resume or incremental after full), full (all years), or incremental"
            " (lastModified)"
        ),
    )
    sync_nvd.add_argument("--version", default=None, help="explicit run id / snapshot prefix")
    sync_nvd.add_argument("--since", default=None, help="incremental window start (RFC 3339)")
    sync_nvd.add_argument("--until", default=None, help="incremental window end (RFC 3339)")
    sync_nvd.add_argument(
        "--api-url",
        default=None,
        help="override NVD API 2.0 endpoint (defaults to AEGIS_NVD_API_URL or nist.gov)",
    )
    sync_nvd.add_argument(
        "--results-per-page",
        type=int,
        default=DEFAULT_RESULTS_PER_PAGE,
        help="NVD page size (1..2000)",
    )
    sync_nvd.add_argument("--max-pages", type=int, default=None, help="stop cleanly after N pages")
    sync_nvd.add_argument(
        "--no-resume",
        action="store_true",
        help="start a fresh run instead of resuming an in-progress checkpoint",
    )
    sync_nvd.add_argument("--quiet", action="store_true", help="suppress per-page stderr progress")
    sub.add_parser("plan", help="print the intel snapshots already loaded")
    parsed = parser.parse_args(argv)
    if parsed.command == "plan":
        return _plan()
    if parsed.command == "sync-nvd":
        return _sync_nvd(parsed)
    return _sync(parsed)


if __name__ == "__main__":
    sys.exit(main())
