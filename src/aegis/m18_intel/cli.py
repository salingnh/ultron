"""Operator CLI of M18 (G1.6 slice C): `python -m aegis.m18_intel <sync|plan>`.

* `sync` - store one feed snapshot in S3 and load it into PostgreSQL, then publish
  `intel.revision.v2`. `--source` is a local path (a committed fixture slice, the CI/demo path) or
  an `http(s)` URL (the operator's refresh). Exit 0 on success, 1 on a refused snapshot.
* `plan` - print the snapshots already loaded, so an operator can see which intel the matcher will
  use before running it.

Environment: `AEGIS_PG_DSN` and the S3 settings (`AEGIS_S3_ENDPOINT`, `AEGIS_S3_BUCKET`, optional
`AEGIS_S3_ACCESS_KEY`/`AEGIS_S3_SECRET_KEY`). Nothing here starts or removes a container.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from typing import Any

from aegis.m18_intel import feeds
from aegis.m18_intel.sync import FeedSync, FeedSyncError, read_source


def _moment(text: str | None) -> datetime | None:
    if text is None:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text)


def _plan() -> int:
    from aegis.m18_intel.sync import connect_from_env

    connection = connect_from_env()
    try:
        rows = connection.execute(
            "SELECT feed, version, snapshot_id, snapshot_at, fetched_at, record_count,"
            "       content_sha256, source_uri"
            "  FROM intel_snapshot ORDER BY feed, snapshot_at DESC"
        ).fetchall()
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
        ]
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
    sub.add_parser("plan", help="print the intel snapshots already loaded")
    parsed = parser.parse_args(argv)
    if parsed.command == "plan":
        return _plan()
    return _sync(parsed)


if __name__ == "__main__":
    sys.exit(main())
