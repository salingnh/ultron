"""Tests for M18 full and incremental NVD CVE API 2.0 sync (item 61)."""

from __future__ import annotations

import json
import urllib.parse
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import psycopg
import pytest

from aegis.m18_intel.nvd_api import (
    API_KEY_FILE_ENV,
    KEYED_LIMIT,
    PUBLIC_LIMIT,
    NvdApiSync,
    NvdRateLimiter,
    date_windows,
    load_nvd_api_key,
)
from aegis.m18_intel.sync import FeedSync, FeedSyncError
from tests import db_support as support
from tests import g16c_support as fixtures

pytestmark = support.requires_postgres


def _cve_entry(cve_id: str, product: str, version: str, modified: str) -> dict[str, Any]:
    return {
        "cve": {
            "id": cve_id,
            "vulnStatus": "Analyzed",
            "lastModified": modified,
            "descriptions": [{"lang": "en", "value": f"Test flaw in {product} {version}"}],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseScore": 7.5,
                            "baseSeverity": "HIGH",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        }
                    }
                ]
            },
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": (
                                        f"cpe:2.3:a:openbsd:{product}:{version}:*:*:*:*:*:*:*"
                                    ),
                                }
                            ]
                        }
                    ]
                }
            ],
        }
    }


class _FakeNvdTransport:
    def __init__(self, handler: Any) -> None:
        self._handler = handler
        self.calls: list[tuple[str, str | None]] = []

    def get(self, url: str, *, api_key: str | None, timeout: float) -> bytes:
        del timeout
        self.calls.append((url, api_key))
        payload = self._handler(url, len(self.calls))
        return json.dumps(payload).encode("utf-8")


def test_load_nvd_api_key_reads_file_and_never_leaks_secret(tmp_path: Path) -> None:
    assert load_nvd_api_key({}) is None

    plain_file = tmp_path / "nvd.key"
    plain_file.write_text("# comment\n  secret-key-xyz  \n", encoding="utf-8")
    assert load_nvd_api_key({API_KEY_FILE_ENV: str(plain_file)}) == "secret-key-xyz"

    env_file = tmp_path / "nvd.env"
    env_file.write_text('OTHER=1\nNVD_API_KEY="secret-key-abc"\n', encoding="utf-8")
    assert load_nvd_api_key({API_KEY_FILE_ENV: str(env_file)}) == "secret-key-abc"

    missing = tmp_path / "does-not-exist"
    with pytest.raises(FeedSyncError, match=API_KEY_FILE_ENV):
        load_nvd_api_key({API_KEY_FILE_ENV: str(missing)})


def _assert_rate_limit(has_key: bool, limit: tuple[int, float, float]) -> None:
    now = 100.0
    sleeps: list[float] = []

    def fake_monotonic() -> float:
        return now

    def fake_sleep(seconds: float) -> None:
        nonlocal now
        sleeps.append(seconds)
        now += seconds

    limiter = NvdRateLimiter(has_api_key=has_key, monotonic=fake_monotonic, sleep=fake_sleep)
    max_req, window, min_interval = limit
    for _ in range(max_req + 2):
        limiter.acquire()
    assert len(sleeps) >= max_req + 1
    assert all(s >= min_interval - 1e-6 for s in sleeps)
    assert now - 100.0 >= window - 1e-6


def test_rate_limiter_respects_public_and_keyed_nvd_limits() -> None:
    for has_key, limit in ((False, PUBLIC_LIMIT), (True, KEYED_LIMIT)):
        _assert_rate_limit(has_key, limit)


def test_date_windows_respects_120_day_cap() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    end = datetime(2026, 10, 1, tzinfo=UTC)
    windows = date_windows(start, end)
    assert len(windows) == 3
    assert windows[0][0] == start
    assert windows[-1][1] == end
    for win_start, win_end in windows:
        assert win_end - win_start <= timedelta(days=120)


def test_full_paged_sync_resume_and_incremental_by_last_modified(tmp_path: Path) -> None:
    key_file = tmp_path / "nvd.env"
    key_file.write_text("NVD_API_KEY=super-secret-nvd-token\n", encoding="utf-8")
    api_key = load_nvd_api_key({API_KEY_FILE_ENV: str(key_file)})

    all_entries = [
        _cve_entry(f"CVE-2026-000{i}", "openssh", f"8.{i}.0", f"2026-11-24T0{i}:00:00.000")
        for i in range(1, 6)
    ]
    inc_entry = _cve_entry("CVE-2026-0006", "openssh", "8.9p1", "2026-11-26T02:00:00.000")

    def serve(url: str, call_num: int) -> dict[str, Any]:
        del call_num
        query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        start_index = int(query["startIndex"][0])
        per_page = int(query["resultsPerPage"][0])
        if "lastModStartDate" in query:
            subset = [inc_entry]
        else:
            subset = all_entries
        page = subset[start_index : start_index + per_page]
        return {"totalResults": len(subset), "vulnerabilities": page}

    with support.migrated_database() as dsn:
        store = fixtures.MemoryStore()
        feed_sync = FeedSync(fixtures.connector(dsn), store)
        transport = _FakeNvdTransport(serve)
        fixed_now = datetime(2026, 11, 26, 3, 0, tzinfo=UTC)
        api_sync = NvdApiSync(
            feed_sync,
            api_key=api_key,
            transport=transport,
            now=lambda: fixed_now,
        )

        # Interrupt after 2 pages of 2 (4 of 5 CVEs).
        part1 = api_sync.sync(
            mode="full", version="api2-full-test", results_per_page=2, max_pages=2
        )
        assert part1.completed is False
        assert part1.resumed is False
        assert part1.pages_fetched == 2
        assert part1.records == 4
        assert part1.api_key_configured is True

        cp = api_sync.latest_checkpoint()
        assert cp is not None
        assert cp.status == "in_progress"
        assert cp.next_start_index == 4

        # Resume in auto mode: fetches only remaining page without refetching pages 0..1.
        part2 = api_sync.sync(mode="auto", results_per_page=2)
        assert part2.completed is True
        assert part2.resumed is True
        assert part2.mode == "full"
        assert part2.pages_fetched == 1
        assert part2.records == 1
        assert part2.written == 1
        assert part2.last_modified_watermark == datetime(2026, 11, 24, 5, 0, tzinfo=UTC)

        # Ensure key is passed via transport header arg, never URL or report.
        assert all(key == "super-secret-nvd-token" for _, key in transport.calls)
        assert all("super-secret" not in url for url, _ in transport.calls)
        assert "super-secret" not in json.dumps(part2.as_dict())

        # Subsequent auto sync switches to incremental from watermark - overlap.
        inc1 = api_sync.sync(mode="auto", results_per_page=2)
        assert inc1.completed is True
        assert inc1.mode == "incremental"
        assert inc1.written == 1
        last_url = transport.calls[-1][0]
        assert "lastModStartDate=2026-11-24T04%3A59%3A00.000Z" in last_url

        # Re-running immediately deduplicates unchanged CVEs without inserting duplicates.
        inc2 = api_sync.sync(mode="auto", results_per_page=2)
        assert inc2.completed is True
        assert inc2.mode == "incremental"
        assert inc2.written == 0
        assert inc2.unchanged == 1

        with psycopg.connect(dsn) as conn:
            conn.execute("SET search_path = aegis, public")
            count = conn.execute(
                "SELECT count(*) FROM vulnerability_current WHERE source = 'nvd'"
            ).fetchone()
            assert count is not None and count[0] == 6
