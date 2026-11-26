"""The configured KEV source (D8, item 61 trial): one pinned mirror, verified, no fallback.

`www.cisa.gov` answers HTTP 403 to this deployment's egress for every path (Akamai denies the
source IP: the KEV export, `/robots.txt` and `/` all answer the same "Access Denied" page, with a
browser User-Agent or without one). The configured source is therefore the official
`cisagov/kev-data` mirror on GitHub, pinned to a commit with its exact size and sha256; a download
that does not match is refused instead of becoming intel the matcher trusts. These tests are
offline: they pin the configuration and the verification, not the network.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from aegis.common.repo import repository_root
from aegis.m18_intel.sources import (
    DEFAULT_PIN_FILE,
    PinnedFeed,
    PinnedFeedError,
    fetch_pinned,
    load_pinned_feed,
)

PIN = repository_root() / DEFAULT_PIN_FILE
MIRROR = "https://raw.githubusercontent.com/cisagov/kev-data/"


def _pin(**overrides: Any) -> PinnedFeed:
    values: dict[str, Any] = {
        "feed": "kev",
        "url": f"{MIRROR}{'a' * 40}/known_exploited_vulnerabilities.json",
        "version": "2026.11.25",
        "size_bytes": 10,
        "sha256": "0" * 64,
        "catalog_version": "2026.11.25",
    }
    values.update(overrides)
    return PinnedFeed(**values)


def _document(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(PIN.read_text(encoding="utf-8"))
    document.update(overrides)
    return document


def _write(tmp_path: Path, document: dict[str, Any]) -> Path:
    path = tmp_path / "kev-source.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


class _Response:
    """The slice of `urlopen`'s response `fetch_pinned` reads."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self) -> bytes:
        return self._data

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def _serve(monkeypatch: pytest.MonkeyPatch, data: bytes) -> list[str]:
    seen: list[str] = []

    def urlopen(request: Any, timeout: float = 0) -> _Response:
        seen.append(str(getattr(request, "full_url", request)))
        return _Response(data)

    monkeypatch.setattr("aegis.m18_intel.sources.urllib.request.urlopen", urlopen)
    return seen


def _catalog(version: str = "2026.11.25", count: int = 1) -> bytes:
    document = {
        "catalogVersion": version,
        "count": count,
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-41773",
                "vendorProject": "Apache",
                "product": "HTTP Server",
                "dateAdded": "2021-11-03",
                "shortDescription": "path traversal",
                "requiredAction": "patch",
                "dueDate": "2021-11-17",
                "knownRansomwareCampaignUse": "Unknown",
            }
        ],
    }
    return json.dumps(document).encode("utf-8")


def test_the_committed_pin_names_the_github_mirror_and_nothing_else() -> None:
    pinned = load_pinned_feed("kev")
    assert pinned.feed == "kev"
    assert pinned.url.startswith(MIRROR)
    commit = pinned.url[len(MIRROR) :].split("/", 1)[0]
    assert len(commit) == 40 and set(commit) <= set("0123456789abcdef")
    assert "cisa.gov" not in pinned.url
    assert pinned.size_bytes > 0
    assert len(pinned.sha256) == 64
    assert pinned.version == pinned.catalog_version


def test_a_pin_that_names_cisa_gov_is_refused(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        _document(
            url=(
                "https://www.cisa.gov/sites/default/files/feeds/"
                "known_exploited_vulnerabilities.json"
            )
        ),
    )
    with pytest.raises(PinnedFeedError) as caught:
        load_pinned_feed("kev", path=path)
    assert "raw.githubusercontent.com" in str(caught.value)


def test_a_pin_without_a_commit_is_refused(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        _document(url=f"{MIRROR}develop/known_exploited_vulnerabilities.json"),
    )
    with pytest.raises(PinnedFeedError) as caught:
        load_pinned_feed("kev", path=path)
    assert "commit" in str(caught.value)


@pytest.mark.parametrize(
    "overrides",
    [
        {"feed": "nvd"},
        {"sha256": "not-a-sha"},
        {"size_bytes": 0},
        {"size_bytes": True},
        {"catalog_version": ""},
        {"version": ""},
    ],
)
def test_a_malformed_pin_is_refused(tmp_path: Path, overrides: dict[str, Any]) -> None:
    path = _write(tmp_path, _document(**overrides))
    with pytest.raises(PinnedFeedError):
        load_pinned_feed("kev", path=path)


def test_the_environment_points_the_deployment_at_its_own_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    other = _write(tmp_path, _document(version="2026.11.24", catalog_version="2026.11.24"))
    monkeypatch.setenv("AEGIS_KEV_SOURCE_FILE", str(other))
    assert load_pinned_feed("kev").version == "2026.11.24"


def test_pinned_bytes_are_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    data = _catalog()
    pinned = _pin(size_bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
    seen = _serve(monkeypatch, data)
    assert fetch_pinned(pinned) == data
    assert seen == [pinned.url]


def test_a_truncated_download_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    data = _catalog()
    pinned = _pin(size_bytes=len(data) + 1, sha256=hashlib.sha256(data).hexdigest())
    _serve(monkeypatch, data)
    with pytest.raises(PinnedFeedError) as caught:
        fetch_pinned(pinned)
    assert "bytes" in str(caught.value)


def test_changed_bytes_under_the_pin_are_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    data = _catalog()
    pinned = _pin(size_bytes=len(data), sha256="f" * 64)
    _serve(monkeypatch, data)
    with pytest.raises(PinnedFeedError) as caught:
        fetch_pinned(pinned)
    assert "sha256" in str(caught.value)


def test_a_file_that_is_not_the_pinned_catalogue_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = _catalog(version="2026.11.24")
    pinned = _pin(
        size_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        catalog_version="2026.11.25",
    )
    _serve(monkeypatch, data)
    with pytest.raises(PinnedFeedError) as caught:
        fetch_pinned(pinned)
    assert "catalogVersion" in str(caught.value)


def test_the_kev_fixture_slice_is_not_loaded_by_the_harness_any_more() -> None:
    """`make vulnlab-test` must assert against the configured catalogue, not the 3-row slice."""
    source = (repository_root() / "scripts/vulnlab/test_cases.py").read_text(encoding="utf-8")
    assert '"kev", INTEL_FIXTURES / "kev-slice.json"' not in source
    assert "load_pinned_feed" in source and "fetch_pinned" in source
