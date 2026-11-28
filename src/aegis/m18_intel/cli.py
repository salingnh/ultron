"""Operator CLI of M18 (`python -m aegis.m18_intel <sync|sync-kev|sync-intel|sync-nvd|plan>`).

* `sync` - store one feed snapshot in S3 and load it into PostgreSQL, then publish
  `intel.revision.v2`. `--source` is a local path (a committed fixture slice, the CI/demo path) or
  an `http(s)` URL (the operator's refresh). Exit 0 on success, 1 on a refused snapshot.
* `sync-kev` - **refresh** the one configured KEV source: `deploy/intel/kev-source.json` (or
  `AEGIS_KEV_SOURCE_FILE`) names the `cisagov/kev-data` mirror; the refresh resolves the current
  HEAD commit of its default branch through the GitHub API, downloads the export at that commit and
  validates it (shape, size/count bounds, `catalogVersion` not older than the newest stored
  snapshot), then writes it. There is no fallback source and a failed step is an error.
  `--fixture PATH` loads a committed export instead (tests, CI, offline) with the same checks minus
  the live size bounds. `www.cisa.gov` answers HTTP 403 to this deployment's egress (item 61 trial
  D8), which is why the mirror is the configured source.
* `sync-intel` - the scheduled/incremental refresh: NVD (`auto`), EPSS when a source is configured,
  then KEV (`sync-kev`). It runs every leg, prints one JSON summary and exits 1 if any leg failed,
  so a timer never reports success while a feed is stale.
* `sync-nvd` - paged NVD CVE API 2.0 bulk (all years) and incremental (`lastModified`) sync,
  resumable and idempotent. Optional API key is read only from the file named by
  `AEGIS_NVD_API_KEY_FILE` (never in argv or logs).
* `plan` - print the snapshots and latest NVD sync checkpoint already loaded, so an operator can
  see which intel the matcher will use before running it.

Environment: `AEGIS_PG_DSN`, S3 settings (`AEGIS_S3_ENDPOINT`, `AEGIS_S3_BUCKET`, optional
`AEGIS_S3_ACCESS_KEY`/`AEGIS_S3_SECRET_KEY`), optional `AEGIS_NVD_API_KEY_FILE`,
`AEGIS_KEV_SOURCE_FILE`, `AEGIS_GITHUB_TOKEN_FILE`, `AEGIS_EPSS_SOURCE`/`AEGIS_EPSS_VERSION`.
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
from aegis.m18_intel.refresh import RefreshOptions, kev_report
from aegis.m18_intel.runs import recorded_refresh
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


def _sync_kev(argv: argparse.Namespace) -> int:
    """Refresh the configured KEV source and write the validated export."""
    try:
        report = kev_report(argv.fixture, argv.source_file)
    except (FeedSyncError, feeds.FeedError, ValueError, OSError) as error:
        print(f"kev sync refused: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, default=str))
    return 0


def _sync_intel(argv: argparse.Namespace) -> int:
    """The scheduled refresh: NVD, EPSS (when configured), KEV; exit 1 if any leg failed."""
    options = RefreshOptions(
        nvd_mode=argv.nvd_mode,
        api_url=argv.api_url,
        results_per_page=argv.results_per_page,
        skip_nvd=argv.skip_nvd,
        skip_kev=argv.skip_kev,
        epss_source=argv.epss_source,
        epss_version=argv.epss_version,
        snapshot_at=argv.snapshot_at,
        source_file=argv.source_file,
        kev_fixture=argv.kev_fixture,
    )
    try:
        document = recorded_refresh("manual", options, require_database=False)
    except (FeedSyncError, feeds.FeedError, ValueError, OSError) as error:
        print(f"intel refresh failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(document, indent=2, default=str))
    if not document["ok"]:
        print(
            "intel refresh failed: a feed is stale; fix the leg named above and re-run "
            "(nothing is silently skipped)",
            file=sys.stderr,
        )
        return 1
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
    sync_kev = sub.add_parser(
        "sync-kev",
        help="refresh the configured CISA KEV mirror (HEAD via GitHub API, no fallback source)",
    )
    sync_kev.add_argument(
        "--source-file",
        default=None,
        help="repository/limits config (default: AEGIS_KEV_SOURCE_FILE or "
        "deploy/intel/kev-source.json)",
    )
    sync_kev.add_argument(
        "--fixture",
        default=None,
        help="load this committed export instead of refreshing (tests/CI/offline)",
    )
    sync_intel = sub.add_parser(
        "sync-intel",
        help="scheduled/incremental refresh: NVD (auto), EPSS when configured, KEV",
    )
    sync_intel.add_argument(
        "--nvd-mode",
        choices=["auto", "full", "incremental"],
        default="auto",
        help="NVD sync mode (default auto: resume or incremental after a full run)",
    )
    sync_intel.add_argument("--api-url", default=None, help="override the NVD API endpoint")
    sync_intel.add_argument(
        "--results-per-page", type=int, default=DEFAULT_RESULTS_PER_PAGE, help="NVD page size"
    )
    sync_intel.add_argument("--skip-nvd", action="store_true", help="do not touch NVD")
    sync_intel.add_argument("--skip-kev", action="store_true", help="do not touch KEV")
    sync_intel.add_argument(
        "--epss-source",
        default=None,
        help="EPSS CSV path or URL (default AEGIS_EPSS_SOURCE; none = EPSS is reported skipped)",
    )
    sync_intel.add_argument(
        "--epss-version",
        default=None,
        help="EPSS score date (default AEGIS_EPSS_VERSION or today, UTC)",
    )
    sync_intel.add_argument("--snapshot-at", default=None, help="override the EPSS snapshot date")
    sync_intel.add_argument(
        "--source-file",
        default=None,
        help="KEV source config (default AEGIS_KEV_SOURCE_FILE or deploy/intel/kev-source.json)",
    )
    sync_intel.add_argument(
        "--kev-fixture",
        default=None,
        help="KEV fixture path instead of the live refresh (offline tests only)",
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
    if parsed.command == "sync-kev":
        return _sync_kev(parsed)
    if parsed.command == "sync-intel":
        return _sync_intel(parsed)
    if parsed.command == "sync-nvd":
        return _sync_nvd(parsed)
    return _sync(parsed)


if __name__ == "__main__":
    sys.exit(main())
