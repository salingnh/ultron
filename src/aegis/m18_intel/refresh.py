"""The `sync-intel` refresh (NVD, EPSS when configured, KEV) without a CLI or a schedule.

The CLI (`python -m aegis.m18_intel sync-intel`) and the scheduled M02 activity run the **same**
function, so a scheduled refresh cannot drift from the operator's one-shot refresh: both legs, the
same success rule (`ok` is true only when every leg succeeded), the same JSON shape. The function
never raises for a feed failure - a leg's error is recorded in `legs` and the caller decides what
exit/status it becomes - and it raises for a failure of the surrounding machinery (a bad option).

Nothing here touches a clock or a database of its own beyond the feeds' `FeedSync` connections; the
run ledger is `aegis.m18_intel.runs`, and the CLI/activity wrap this function with it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any, Literal

from aegis.m18_intel import feeds
from aegis.m18_intel.nvd_api import DEFAULT_RESULTS_PER_PAGE, NvdApiSync
from aegis.m18_intel.sync import FeedSync, FeedSyncError, read_source

__all__ = ["RefreshOptions", "kev_report", "refresh"]


@dataclass(frozen=True, slots=True)
class RefreshOptions:
    """What one refresh does; the CLI flags and the scheduled activity both map onto this."""

    nvd_mode: Literal["auto", "full", "incremental"] = "auto"
    api_url: str | None = None
    results_per_page: int = DEFAULT_RESULTS_PER_PAGE
    skip_nvd: bool = False
    skip_distro: bool = False
    skip_kev: bool = False
    epss_source: str | None = None
    epss_version: str | None = None
    snapshot_at: str | None = None
    source_file: str | None = None
    distro_source_file: str | None = None
    kev_fixture: str | None = None


def _moment(text: str | None) -> datetime | None:
    if text is None:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _last_kev_version() -> str | None:
    """The newest KEV `catalogVersion` already stored (the monotonic floor of a refresh)."""
    from aegis.m18_intel.sources import latest_catalog_version
    from aegis.m18_intel.sync import connect_from_env

    connection = connect_from_env()
    try:
        rows = connection.execute(
            "SELECT version FROM intel_snapshot WHERE feed = 'kev'"
        ).fetchall()
    finally:
        connection.close()
    return latest_catalog_version(str(row["version"]) for row in rows)


def kev_report(fixture: str | None, source_file: str | None) -> dict[str, Any]:
    """Refresh (or, with `fixture`, load) the configured KEV export and write it.

    Raises on any failure (API, download, validation, sync); the caller turns that into a failed
    leg. There is no fallback source.
    """
    from aegis.m18_intel.sources import KevSourceError, load_fixture, load_kev_source, refresh_kev

    source = load_kev_source(source_file)
    last_version = _last_kev_version()
    try:
        document = (
            load_fixture(source, fixture, last_version=last_version)
            if fixture is not None
            else refresh_kev(source, last_version=last_version)
        )
    except KevSourceError as error:
        raise FeedSyncError(f"kev: {error}") from error
    report = FeedSync.from_env().sync(
        "kev",
        document.catalog_version,
        document.data,
        source_uri=document.source,
        snapshot_at=document.released_at,
    )
    return {
        **report.as_dict(),
        "source_uri": document.source,
        "commit": document.commit or None,
        "branch": document.branch or None,
        "size_bytes": document.size_bytes,
        "catalog_version": document.catalog_version,
        "count": document.count,
    }


def _epss_refresh(options: RefreshOptions) -> dict[str, Any]:
    source = (options.epss_source or os.environ.get("AEGIS_EPSS_SOURCE", "")).strip()
    if not source:
        return {"status": "skipped", "reason": "no --epss-source or AEGIS_EPSS_SOURCE"}
    version = (
        options.epss_version
        or os.environ.get("AEGIS_EPSS_VERSION", "").strip()
        or date.today().isoformat()
    )
    data = read_source(source)
    report = FeedSync.from_env().sync(
        "epss", version, data, source_uri=source, snapshot_at=_moment(options.snapshot_at)
    )
    return report.as_dict()


def refresh(options: RefreshOptions) -> dict[str, Any]:
    """Run every leg; return `{ok, legs}` with a failed leg's error inside `legs`."""
    legs: dict[str, Any] = {}
    failed = False
    if not options.skip_nvd:
        try:
            report = NvdApiSync.from_env(api_url=options.api_url).sync(
                mode=options.nvd_mode,
                results_per_page=options.results_per_page,
            )
            legs["nvd"] = report.as_dict()
        except (FeedSyncError, feeds.FeedError, ValueError, OSError) as error:
            legs["nvd"] = {"error": str(error)}
            failed = True
    else:
        legs["nvd"] = {"status": "skipped"}
    if not options.skip_distro:
        try:
            from aegis.m18_intel.distro import sync_distro

            distro_report = sync_distro(source_file=options.distro_source_file)
            legs["distro"] = distro_report
            if not distro_report["ok"]:
                failed = True
        except (FeedSyncError, feeds.FeedError, ValueError, OSError) as error:
            legs["distro"] = {"error": str(error)}
            failed = True
    else:
        legs["distro"] = {"status": "skipped"}
    try:
        legs["epss"] = _epss_refresh(options)
    except (FeedSyncError, feeds.FeedError, ValueError, OSError) as error:
        legs["epss"] = {"error": str(error)}
        failed = True
    if not options.skip_kev:
        try:
            legs["kev"] = kev_report(options.kev_fixture, options.source_file)
        except (FeedSyncError, feeds.FeedError, ValueError, OSError) as error:
            legs["kev"] = {"error": str(error)}
            failed = True
    else:
        legs["kev"] = {"status": "skipped"}
    return {"ok": not failed, "legs": legs}
