"""Paged NVD CVE API 2.0 bulk and incremental (`lastModified`) sync for M18 (item 61).

Design goals:
* **Initial bulk sync (all years)**: pages `startIndex=0, resultsPerPage=2000, ...` through the
  entire NVD 2.0 catalogue (`https://services.nvd.nist.gov/rest/json/cves/2.0`), storing each page
  as an immutable content-addressed S3 snapshot + `intel_snapshot` + `vulnerability_revision` +
  `intel.revision.v2` (under the 100,000 `impacted_ids` schema cap) + `intel_sync_checkpoint`.
* **Incremental sync by `lastModified`**: queries `lastModStartDate`..`lastModEndDate` in chunks of
  at most 120 days (NVD's hard window limit), starting from the latest completed `modified_at`
  watermark (minus a 60 s overlap; unchanged CVEs are deduplicated by `content_hash`).
* **Resumable & idempotent**: every committed page appends a row to `intel_sync_checkpoint` in the
  same PostgreSQL transaction. A crash mid-sync leaves `status='in_progress'` at the exact next
  `startIndex` (and incremental window), so re-running resumes without re-fetching completed pages
  or hitting `SnapshotConflict`.
* **Optional API key without leakage**: `AEGIS_NVD_API_KEY_FILE` names a file path (never a key on
  argv or in logs/URLs/reports). Rate limits: 5 req / 30.5 s public, 50 req / 30.5 s keyed.
"""

from __future__ import annotations

import gzip
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, Protocol

import psycopg

from aegis.m18_intel import feeds
from aegis.m18_intel.sync import FeedSync, FeedSyncError
from aegis.m27_ingestion.ids import uuid7

__all__ = [
    "API_KEY_FILE_ENV",
    "API_URL_ENV",
    "DEFAULT_RESULTS_PER_PAGE",
    "MAX_MODIFIED_WINDOW_DAYS",
    "NVD_API_URL",
    "NvdApiSync",
    "NvdApiTransport",
    "NvdCorpusReport",
    "NvdRateLimiter",
    "SyncCheckpoint",
    "UrllibNvdTransport",
    "date_windows",
    "load_nvd_api_key",
]

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY_FILE_ENV = "AEGIS_NVD_API_KEY_FILE"
API_URL_ENV = "AEGIS_NVD_API_URL"
DEFAULT_RESULTS_PER_PAGE = 2000
MAX_MODIFIED_WINDOW_DAYS = 120
OVERLAP_SECONDS = 60
MAX_RETRIES = 5
REQUEST_TIMEOUT_SECONDS = 120.0
#: NVD 2.0 published rolling windows: 5 req / 30 s public, 50 req / 30 s with apiKey (0.5 s buffer).
PUBLIC_LIMIT = (5, 30.5, 6.1)
KEYED_LIMIT = (50, 30.5, 0.65)
RETRYABLE_HTTP_STATUS = frozenset({403, 429, 500, 502, 503, 504})

SyncMode = Literal["auto", "full", "incremental"]


@dataclass(frozen=True, slots=True)
class SyncCheckpoint:
    """Latest recorded NVD API 2.0 sync checkpoint from `intel_sync_checkpoint`."""

    run_id: str
    mode: Literal["full", "incremental"]
    status: Literal["in_progress", "completed"]
    next_start_index: int
    total_results: int | None
    results_per_page: int
    window_start: datetime | None
    window_end: datetime | None
    last_modified_watermark: datetime | None
    last_snapshot_id: str | None


@dataclass(frozen=True, slots=True)
class NvdPageProgress:
    """Progress update emitted per committed NVD API page (no secret fields)."""

    run_id: str
    mode: Literal["full", "incremental"]
    page: int
    start_index: int
    page_records: int
    total_results: int
    written: int
    unchanged: int
    elapsed_seconds: float
    window_index: int = 1
    window_total: int = 1


@dataclass(frozen=True, slots=True)
class NvdCorpusReport:
    """Summary of an `NvdApiSync.sync` run."""

    run_id: str
    mode: Literal["full", "incremental"]
    resumed: bool
    api_key_configured: bool
    pages_fetched: int
    records: int
    written: int
    unchanged: int
    withdrawn: int
    total_results: int | None
    completed: bool
    last_modified_watermark: datetime | None
    elapsed_seconds: float
    snapshot_ids: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "mode": self.mode,
            "resumed": self.resumed,
            "api_key_configured": self.api_key_configured,
            "pages_fetched": self.pages_fetched,
            "records": self.records,
            "written": self.written,
            "unchanged": self.unchanged,
            "withdrawn": self.withdrawn,
            "total_results": self.total_results,
            "completed": self.completed,
            "last_modified_watermark": (
                None
                if self.last_modified_watermark is None
                else self.last_modified_watermark.astimezone(UTC)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z")
            ),
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "snapshots": len(self.snapshot_ids),
        }


class NvdApiTransport(Protocol):
    """HTTP transport abstraction for NVD API 2.0 (injectable in tests)."""

    def get(self, url: str, *, api_key: str | None, timeout: float) -> bytes: ...


class NvdRateLimiter:
    """Rolling-window + minimum-spacing rate limiter for NVD API 2.0."""

    def __init__(
        self,
        *,
        has_api_key: bool,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        max_requests, window_seconds, min_interval = KEYED_LIMIT if has_api_key else PUBLIC_LIMIT
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.min_interval = min_interval
        self._monotonic = monotonic
        self._sleep = sleep
        self._stamps: deque[float] = deque()

    def acquire(self) -> None:
        while True:
            now = self._monotonic()
            while self._stamps and now - self._stamps[0] >= self.window_seconds - 1e-9:
                self._stamps.popleft()
            wait = 0.0
            if self._stamps:
                since_last = now - self._stamps[-1]
                if since_last < self.min_interval - 1e-9:
                    wait = max(wait, self.min_interval - since_last)
                if len(self._stamps) >= self.max_requests:
                    wait = max(wait, self.window_seconds - (now - self._stamps[0]))
            if wait <= 1e-9:
                self._stamps.append(now)
                return
            self._sleep(wait)


class UrllibNvdTransport:
    """Stdlib HTTPS transport with gzip decoding, rate limiting, and bounded retries."""

    def __init__(
        self,
        *,
        rate_limiter: NvdRateLimiter,
        sleep: Callable[[float], None] = time.sleep,
        max_retries: int = MAX_RETRIES,
    ) -> None:
        self._limiter = rate_limiter
        self._sleep = sleep
        self._max_retries = max_retries

    def get(self, url: str, *, api_key: str | None, timeout: float) -> bytes:
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "User-Agent": "aegis-m18-intel/1.0",
        }
        if api_key:
            headers["apiKey"] = api_key
        request = urllib.request.Request(url, headers=headers, method="GET")  # noqa: S310
        last_error: Exception | None = None
        for attempt in range(self._max_retries + 1):
            self._limiter.acquire()
            try:
                with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
                    raw = bytes(response.read())
                    encoding = str(response.headers.get("Content-Encoding") or "").lower()
                    if "gzip" in encoding or raw[:2] == b"\x1f\x8b":
                        return gzip.decompress(raw)
                    return raw
            except urllib.error.HTTPError as error:
                last_error = error
                if error.code not in RETRYABLE_HTTP_STATUS or attempt >= self._max_retries:
                    raise FeedSyncError(
                        f"NVD API request failed with HTTP {error.code} for {url}"
                    ) from error
                delay = _retry_delay(error.headers.get("Retry-After"), attempt)
                self._sleep(delay)
            except (urllib.error.URLError, TimeoutError, OSError, EOFError) as error:
                last_error = error
                if attempt >= self._max_retries:
                    raise FeedSyncError(f"NVD API request failed for {url}: {error}") from error
                self._sleep(_retry_delay(None, attempt))
        raise FeedSyncError(f"NVD API request failed for {url}: {last_error}")


def _retry_delay(retry_after: str | None, attempt: int) -> float:
    if retry_after is not None:
        text = retry_after.strip()
        if text.isdigit():
            return min(120.0, max(1.0, float(text)))
    return float(min(120.0, 10.0 * (2**attempt)))


def load_nvd_api_key(env: Mapping[str, str] | None = None) -> str | None:
    """Read optional NVD API key from the file named by `AEGIS_NVD_API_KEY_FILE`.

    The key never comes from CLI argv and is never echoed in errors or logs.
    """
    source = os.environ if env is None else env
    raw_path = source.get(API_KEY_FILE_ENV, "").strip()
    if not raw_path:
        return None
    path = Path(raw_path).expanduser()
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as error:
        raise FeedSyncError(
            f"cannot read NVD API key file configured by {API_KEY_FILE_ENV} ({path}): {error}"
        ) from error
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key_name, _, value = line.partition("=")
            if key_name.strip().upper() in {"NVD_API_KEY", "APIKEY", "API_KEY"}:
                cleaned = value.strip().strip('"').strip("'")
                if cleaned:
                    return cleaned
                break
            continue
        return line.strip('"').strip("'")
    raise FeedSyncError(f"NVD API key file configured by {API_KEY_FILE_ENV} ({path}) is empty")


def date_windows(
    start: datetime, end: datetime, *, max_days: int = MAX_MODIFIED_WINDOW_DAYS
) -> list[tuple[datetime, datetime]]:
    """Split `[start, end]` into chunks of at most `max_days` (NVD API 2.0 hard cap)."""
    start_utc = start.astimezone(UTC)
    end_utc = end.astimezone(UTC)
    if end_utc <= start_utc:
        return []
    span = timedelta(days=max_days)
    windows: list[tuple[datetime, datetime]] = []
    cursor = start_utc
    while cursor < end_utc:
        chunk_end = min(end_utc, cursor + span)
        windows.append((cursor, chunk_end))
        cursor = chunk_end
    return windows


def _nvd_timestamp(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _page_url(
    base_url: str,
    *,
    start_index: int,
    results_per_page: int,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
) -> str:
    params: dict[str, str] = {
        "resultsPerPage": str(results_per_page),
        "startIndex": str(start_index),
    }
    if window_start is not None and window_end is not None:
        params["lastModStartDate"] = _nvd_timestamp(window_start)
        params["lastModEndDate"] = _nvd_timestamp(window_end)
    sep = "&" if "?" in base_url else "?"
    return f"{base_url}{sep}{urllib.parse.urlencode(params)}"


class NvdApiSync:
    """Resumable, idempotent, snapshot-versioned NVD CVE 2.0 API syncer."""

    def __init__(
        self,
        feed_sync: FeedSync,
        *,
        api_url: str = NVD_API_URL,
        api_key: str | None = None,
        transport: NvdApiTransport | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._feed_sync = feed_sync
        self._api_url = api_url.rstrip("?")
        self._api_key = api_key
        self._monotonic = monotonic
        self._now = now
        if transport is None:
            limiter = NvdRateLimiter(
                has_api_key=bool(api_key),
                monotonic=monotonic,
                sleep=sleep,
            )
            transport = UrllibNvdTransport(rate_limiter=limiter, sleep=sleep)
        self._transport = transport

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
        *,
        api_url: str | None = None,
    ) -> NvdApiSync:
        source = os.environ if env is None else env
        feed_sync = FeedSync.from_env(source)
        resolved_url = api_url or source.get(API_URL_ENV, "").strip() or NVD_API_URL
        api_key = load_nvd_api_key(source)
        return cls(feed_sync, api_url=resolved_url, api_key=api_key)

    def latest_checkpoint(self) -> SyncCheckpoint | None:
        connection = self._feed_sync._connect()
        try:
            row = connection.execute(
                "SELECT run_id, mode, status, next_start_index, total_results,"
                "       results_per_page, window_start, window_end,"
                "       last_modified_watermark, last_snapshot_id"
                "  FROM intel_sync_checkpoint"
                " WHERE feed = 'nvd'"
                " ORDER BY created_at DESC, checkpoint_id DESC"
                " LIMIT 1"
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            return None
        return SyncCheckpoint(
            run_id=str(row["run_id"]),
            mode=row["mode"],
            status=row["status"],
            next_start_index=int(row["next_start_index"]),
            total_results=None if row["total_results"] is None else int(row["total_results"]),
            results_per_page=int(row["results_per_page"]),
            window_start=row["window_start"],
            window_end=row["window_end"],
            last_modified_watermark=row["last_modified_watermark"],
            last_snapshot_id=(
                None if row["last_snapshot_id"] is None else str(row["last_snapshot_id"])
            ),
        )

    def _latest_full_watermark(self) -> datetime | None:
        connection = self._feed_sync._connect()
        try:
            row = connection.execute(
                "SELECT last_modified_watermark"
                "  FROM intel_sync_checkpoint"
                " WHERE feed = 'nvd' AND status = 'completed'"
                "   AND last_modified_watermark IS NOT NULL"
                " ORDER BY created_at DESC, checkpoint_id DESC"
                " LIMIT 1"
            ).fetchone()
            if row is not None and row["last_modified_watermark"] is not None:
                return row["last_modified_watermark"]  # type: ignore[no-any-return]
            return None
        finally:
            connection.close()

    def _committed_versions(self, run_prefix: str) -> set[str]:
        connection = self._feed_sync._connect()
        try:
            rows = connection.execute(
                "SELECT version FROM intel_snapshot WHERE feed = 'nvd' AND version LIKE %s",
                (f"{run_prefix}/%",),
            ).fetchall()
            return {str(row["version"]) for row in rows}
        finally:
            connection.close()

    def sync(
        self,
        *,
        mode: SyncMode = "auto",
        version: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        results_per_page: int = DEFAULT_RESULTS_PER_PAGE,
        max_pages: int | None = None,
        resume: bool = True,
        on_page: Callable[[NvdPageProgress], None] | None = None,
    ) -> NvdCorpusReport:
        if results_per_page < 1 or results_per_page > DEFAULT_RESULTS_PER_PAGE:
            raise FeedSyncError(
                f"results_per_page must be between 1 and {DEFAULT_RESULTS_PER_PAGE}"
            )
        if max_pages is not None and max_pages < 1:
            raise FeedSyncError("max_pages must be >= 1")

        started = self._monotonic()
        checkpoint = self.latest_checkpoint()
        resumed = False
        chosen_mode: Literal["full", "incremental"]
        run_id: str
        start_index = 0
        watermark: datetime | None = (
            checkpoint.last_modified_watermark if checkpoint is not None else None
        )
        windows: list[tuple[datetime | None, datetime | None]]

        if mode == "auto":
            if resume and checkpoint is not None and checkpoint.status == "in_progress":
                resumed = True
                chosen_mode = checkpoint.mode
                run_id = checkpoint.run_id
                start_index = checkpoint.next_start_index
                results_per_page = checkpoint.results_per_page
                if chosen_mode == "incremental":
                    if checkpoint.window_start is None or checkpoint.window_end is None:
                        raise FeedSyncError("in-progress incremental checkpoint has no window")
                    end_target = (until or self._now()).astimezone(UTC)
                    windows = [(checkpoint.window_start, checkpoint.window_end)]
                    for tail_w in date_windows(checkpoint.window_end, end_target):
                        windows.append(tail_w)
                else:
                    windows = [(None, None)]
            else:
                completed_wm = self._latest_full_watermark()
                if completed_wm is not None:
                    chosen_mode = "incremental"
                    run_id = version or f"api2-inc-{self._now().strftime('%Y%m%dT%H%M%SZ')}"
                    win_start = since or (completed_wm - timedelta(seconds=OVERLAP_SECONDS))
                    win_end = until or self._now()
                    windows = list(date_windows(win_start, win_end))
                    if not windows:
                        windows = [(win_start, win_start + timedelta(seconds=1))]
                else:
                    chosen_mode = "full"
                    run_id = version or f"api2-full-{self._now().strftime('%Y%m%dT%H%M%SZ')}"
                    windows = [(None, None)]
        elif mode == "full":
            chosen_mode = "full"
            if (
                resume
                and checkpoint is not None
                and checkpoint.status == "in_progress"
                and checkpoint.mode == "full"
                and (version is None or version == checkpoint.run_id)
            ):
                resumed = True
                run_id = checkpoint.run_id
                start_index = checkpoint.next_start_index
                results_per_page = checkpoint.results_per_page
            else:
                run_id = version or f"api2-full-{self._now().strftime('%Y%m%dT%H%M%SZ')}"
            windows = [(None, None)]
        else:
            chosen_mode = "incremental"
            if (
                resume
                and checkpoint is not None
                and checkpoint.status == "in_progress"
                and checkpoint.mode == "incremental"
                and (version is None or version == checkpoint.run_id)
            ):
                resumed = True
                run_id = checkpoint.run_id
                start_index = checkpoint.next_start_index
                results_per_page = checkpoint.results_per_page
                if checkpoint.window_start is None or checkpoint.window_end is None:
                    raise FeedSyncError("in-progress incremental checkpoint has no window")
                end_target = (until or self._now()).astimezone(UTC)
                windows = [(checkpoint.window_start, checkpoint.window_end)]
                for tail_w in date_windows(checkpoint.window_end, end_target):
                    windows.append(tail_w)
            else:
                base_wm = since or self._latest_full_watermark()
                if base_wm is None:
                    raise FeedSyncError(
                        "incremental sync requires an initial full sync or --since timestamp"
                    )
                win_start = since or (base_wm - timedelta(seconds=OVERLAP_SECONDS))
                win_end = until or self._now()
                run_id = version or f"api2-inc-{self._now().strftime('%Y%m%dT%H%M%SZ')}"
                windows = list(date_windows(win_start, win_end))
                if not windows:
                    windows = [(win_start, win_start + timedelta(seconds=1))]

        committed_versions = self._committed_versions(run_id)
        pages_fetched = 0
        total_records = 0
        total_written = 0
        total_unchanged = 0
        total_withdrawn = 0
        last_total_results: int | None = None
        snapshot_ids: list[str] = []
        completed = False

        for w_idx, (w_start, w_end) in enumerate(windows):
            cursor = start_index if w_idx == 0 else 0
            while True:
                if max_pages is not None and pages_fetched >= max_pages:
                    return NvdCorpusReport(
                        run_id=run_id,
                        mode=chosen_mode,
                        resumed=resumed,
                        api_key_configured=bool(self._api_key),
                        pages_fetched=pages_fetched,
                        records=total_records,
                        written=total_written,
                        unchanged=total_unchanged,
                        withdrawn=total_withdrawn,
                        total_results=last_total_results,
                        completed=False,
                        last_modified_watermark=watermark,
                        elapsed_seconds=self._monotonic() - started,
                        snapshot_ids=tuple(snapshot_ids),
                    )
                if chosen_mode == "full":
                    page_version = f"{run_id}/p{cursor:07d}"
                else:
                    assert w_start is not None
                    page_version = f"{run_id}/w{w_start.strftime('%Y%m%d%H%M%S')}-p{cursor:07d}"
                if page_version in committed_versions:
                    cursor += results_per_page
                    continue

                url = _page_url(
                    self._api_url,
                    start_index=cursor,
                    results_per_page=results_per_page,
                    window_start=w_start,
                    window_end=w_end,
                )
                raw = self._transport.get(
                    url, api_key=self._api_key, timeout=REQUEST_TIMEOUT_SECONDS
                )
                document = json.loads(raw.decode("utf-8"))
                if not isinstance(document, dict):
                    raise FeedSyncError(f"NVD API page at startIndex={cursor} is not an object")
                total_results = int(document.get("totalResults") or 0)
                last_total_results = total_results
                records = feeds.parse_nvd(document)
                pages_fetched += 1

                page_max_mod = max(
                    (r.modified_at for r in records if r.modified_at is not None),
                    default=None,
                )
                if page_max_mod is not None and (watermark is None or page_max_mod > watermark):
                    watermark = page_max_mod

                next_index = cursor + len(records)
                window_done = (not records) or (next_index >= total_results)
                is_final_page = window_done and (w_idx == len(windows) - 1)
                if is_final_page and w_end is not None and (watermark is None or w_end > watermark):
                    watermark = w_end
                checkpoint_status: Literal["in_progress", "completed"] = (
                    "completed" if is_final_page else "in_progress"
                )
                next_win_start = (
                    windows[w_idx + 1][0] if (window_done and not is_final_page) else w_start
                )
                next_win_end = (
                    windows[w_idx + 1][1] if (window_done and not is_final_page) else w_end
                )
                next_cursor_for_cp = 0 if (window_done and not is_final_page) else next_index

                if not records:
                    self._record_empty_checkpoint(
                        run_id=run_id,
                        mode=chosen_mode,
                        status=checkpoint_status,
                        next_start_index=next_cursor_for_cp,
                        total_results=total_results,
                        results_per_page=results_per_page,
                        window_start=next_win_start,
                        window_end=next_win_end,
                        watermark=watermark,
                    )
                    if is_final_page:
                        completed = True
                    break

                def _write_checkpoint(
                    conn: psycopg.Connection[Any],
                    snap_id: str,
                    _recs: Any,
                    *,
                    _status: str = checkpoint_status,
                    _next: int = next_cursor_for_cp,
                    _tot: int = total_results,
                    _ws: datetime | None = next_win_start,
                    _we: datetime | None = next_win_end,
                    _wm: datetime | None = watermark,
                ) -> None:
                    self._insert_checkpoint(
                        conn,
                        run_id=run_id,
                        mode=chosen_mode,
                        status=_status,
                        next_start_index=_next,
                        total_results=_tot,
                        results_per_page=results_per_page,
                        window_start=_ws,
                        window_end=_we,
                        watermark=_wm,
                        last_snapshot_id=snap_id,
                    )

                report = self._feed_sync.sync_records(
                    feeds.NVD,
                    page_version,
                    raw,
                    records,
                    source_uri=url,
                    after_load=_write_checkpoint,
                )
                committed_versions.add(page_version)
                snapshot_ids.append(report.snapshot_id)
                total_records += report.records
                total_written += report.written
                total_unchanged += report.unchanged
                total_withdrawn += report.withdrawn
                if on_page is not None:
                    on_page(
                        NvdPageProgress(
                            run_id=run_id,
                            mode=chosen_mode,
                            page=pages_fetched,
                            start_index=cursor,
                            page_records=report.records,
                            total_results=total_results,
                            written=report.written,
                            unchanged=report.unchanged,
                            elapsed_seconds=self._monotonic() - started,
                            window_index=w_idx + 1,
                            window_total=len(windows),
                        )
                    )
                if window_done:
                    if is_final_page:
                        completed = True
                    break
                cursor = next_index

        return NvdCorpusReport(
            run_id=run_id,
            mode=chosen_mode,
            resumed=resumed,
            api_key_configured=bool(self._api_key),
            pages_fetched=pages_fetched,
            records=total_records,
            written=total_written,
            unchanged=total_unchanged,
            withdrawn=total_withdrawn,
            total_results=last_total_results,
            completed=completed,
            last_modified_watermark=watermark,
            elapsed_seconds=self._monotonic() - started,
            snapshot_ids=tuple(snapshot_ids),
        )

    def _record_empty_checkpoint(
        self,
        *,
        run_id: str,
        mode: Literal["full", "incremental"],
        status: Literal["in_progress", "completed"],
        next_start_index: int,
        total_results: int,
        results_per_page: int,
        window_start: datetime | None,
        window_end: datetime | None,
        watermark: datetime | None,
    ) -> None:
        conn = self._feed_sync._connect()
        try:
            with conn.transaction():
                self._insert_checkpoint(
                    conn,
                    run_id=run_id,
                    mode=mode,
                    status=status,
                    next_start_index=next_start_index,
                    total_results=total_results,
                    results_per_page=results_per_page,
                    window_start=window_start,
                    window_end=window_end,
                    watermark=watermark,
                    last_snapshot_id=None,
                )
        finally:
            conn.close()

    @staticmethod
    def _insert_checkpoint(
        conn: psycopg.Connection[Any],
        *,
        run_id: str,
        mode: str,
        status: str,
        next_start_index: int,
        total_results: int | None,
        results_per_page: int,
        window_start: datetime | None,
        window_end: datetime | None,
        watermark: datetime | None,
        last_snapshot_id: str | None,
    ) -> None:
        conn.execute(
            "INSERT INTO intel_sync_checkpoint (checkpoint_id, feed, run_id, mode, status,"
            " next_start_index, total_results, results_per_page, window_start, window_end,"
            " last_modified_watermark, last_snapshot_id)"
            " VALUES (%s, 'nvd', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                str(uuid7()),
                run_id,
                mode,
                status,
                next_start_index,
                total_results,
                results_per_page,
                window_start,
                window_end,
                watermark,
                last_snapshot_id,
            ),
        )
