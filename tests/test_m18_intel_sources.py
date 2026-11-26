"""The configured KEV source (D8 follow-up): one mirror, refreshed at its HEAD, validated.

`www.cisa.gov` answers HTTP 403 to this deployment's egress for every path (Akamai IP denial), so
the source is the official `cisagov/kev-data` mirror on GitHub. The sync must not pin a commit: KEV
changes several times a week and a pinned file freezes production intel. It resolves the current
HEAD of the mirror's default branch through the GitHub API, downloads the export at that commit and
refuses anything that is not a complete, current, well-shaped catalogue — with no second source.

These tests are offline: the GitHub API and the raw file are fake responses, and the tests assert
exactly which URLs are requested (so a fallback to another host would fail them). The committed
3-row slice is the fixture path tests/CI/harnesses use.
"""

from __future__ import annotations

import dataclasses
import json
import urllib.error
from email.message import Message
from pathlib import Path
from typing import Any

import pytest

from aegis.common.repo import repository_root
from aegis.m18_intel import cli
from aegis.m18_intel.sources import (
    DEFAULT_SOURCE_FILE,
    KevSource,
    KevSourceError,
    catalog_key,
    latest_catalog_version,
    load_fixture,
    load_kev_source,
    refresh_kev,
    resolve_head,
    validate_catalog,
)

CONFIG = repository_root() / DEFAULT_SOURCE_FILE
COMMIT = "51e0a777743fa06957afbaeb280f8735d292c1be"
BRANCH = "develop"
RAW_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/"
    f"{COMMIT}/known_exploited_vulnerabilities.json"
)


def _entry(index: int = 0) -> dict[str, Any]:
    return {
        "cveID": f"CVE-2021-{40000 + index}",
        "vendorProject": "Apache",
        "product": "HTTP Server",
        "vulnerabilityName": "path traversal",
        "dateAdded": "2021-11-03",
        "requiredAction": "Apply updates",
        "dueDate": "2021-11-17",
        "knownRansomwareCampaignUse": "Unknown",
        "shortDescription": "x",
    }


def _catalog(
    version: str = "2026.11.25",
    entries: list[dict[str, Any]] | None = None,
    *,
    count: int | None = None,
) -> bytes:
    vulnerabilities = entries if entries is not None else [_entry(0), _entry(1), _entry(2)]
    document = {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": version,
        "dateReleased": "2026-11-25T19:48:12.4344Z",
        "count": len(vulnerabilities) if count is None else count,
        "vulnerabilities": vulnerabilities,
    }
    return json.dumps(document).encode("utf-8")


def _source(*, size_min: int = 1, size_max: int = 16 * 1024 * 1024) -> KevSource:
    """The real config, with bounds loosened for a small synthetic export."""
    return dataclasses.replace(
        load_kev_source(), size_min_bytes=size_min, size_max_bytes=size_max, count_min=1
    )


class _Response:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self) -> bytes:
        return self._data

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def _serve(monkeypatch: pytest.MonkeyPatch, *, raw: bytes | None = None) -> list[str]:
    """Fake GitHub + raw answers; any other host fails the test (there is no fallback)."""
    seen: list[str] = []

    def urlopen(request: Any, timeout: float = 0) -> _Response:
        url = str(getattr(request, "full_url", request))
        seen.append(url)
        if url.startswith("https://api.github.com/repos/cisagov/kev-data/commits"):
            return _Response(
                json.dumps(
                    [
                        {
                            "sha": COMMIT,
                            "commit": {"committer": {"date": "2026-11-25T22:59:40Z"}},
                        }
                    ]
                ).encode()
            )
        if url == "https://api.github.com/repos/cisagov/kev-data":
            return _Response(json.dumps({"default_branch": BRANCH}).encode())
        if url == RAW_URL:
            return _Response(_catalog() if raw is None else raw)
        raise AssertionError(f"the source requested an unexpected URL: {url}")

    monkeypatch.setattr("aegis.m18_intel.sources.urllib.request.urlopen", urlopen)
    return seen


def test_the_configured_source_is_the_official_mirror_with_sane_bounds() -> None:
    source = load_kev_source()
    assert source.repository == "cisagov/kev-data"
    assert source.file == "known_exploited_vulnerabilities.json"
    assert 0 < source.size_min_bytes < source.size_max_bytes
    assert 0 < source.count_min < source.count_max
    # The config describes the repository and the sanity bounds, never one frozen commit: a pinned
    # file is exactly the staleness this refresh exists to remove.
    document = json.loads(CONFIG.read_text(encoding="utf-8"))
    assert "sha256" not in document and "commit" not in document and "url" not in document
    # The note explains why cisa.gov is not used; no configured value may point at it.
    assert all("cisa.gov" not in str(value) for key, value in document.items() if key != "note")


@pytest.mark.parametrize(
    "overrides",
    [
        {"repository": "someone/kev-data"},
        {"file": "other.json"},
        {"feed": "nvd"},
        {"limits": {"size_min_bytes": 0, "size_max_bytes": 1, "count_min": 1, "count_max": 2}},
        {"limits": {"size_min_bytes": 10, "size_max_bytes": 10, "count_min": 1, "count_max": 2}},
        {"limits": {"size_min_bytes": 1, "size_max_bytes": 2, "count_min": 5, "count_max": 3}},
    ],
)
def test_a_malformed_source_config_is_refused(tmp_path: Path, overrides: dict[str, Any]) -> None:
    document = json.loads(CONFIG.read_text(encoding="utf-8"))
    document.update(overrides)
    path = tmp_path / "kev-source.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(KevSourceError):
        load_kev_source(path)


def test_catalogue_versions_order_in_both_stored_formats() -> None:
    assert catalog_key("2026.11.25") == (2026, 11, 25)
    assert catalog_key("2026-11-24") == (2026, 11, 24)
    assert latest_catalog_version(["2026-11-24", "2026.11.25", "garbage"]) == "2026.11.25"
    assert latest_catalog_version([]) is None
    with pytest.raises(KevSourceError):
        catalog_key("25.11.2026")


def test_resolve_head_asks_the_api_for_the_default_branch_then_the_file_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _serve(monkeypatch)
    head = resolve_head(load_kev_source())
    assert head.commit == COMMIT and head.branch == BRANCH
    assert head.committed_at is not None and head.committed_at.year == 2026
    assert seen == [
        "https://api.github.com/repos/cisagov/kev-data",
        "https://api.github.com/repos/cisagov/kev-data/commits"
        f"?path=known_exploited_vulnerabilities.json&sha={BRANCH}&per_page=1",
    ]


def test_refresh_downloads_exactly_the_resolved_commit_and_records_its_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _serve(monkeypatch)
    document = refresh_kev(_source())
    assert seen == [
        "https://api.github.com/repos/cisagov/kev-data",
        "https://api.github.com/repos/cisagov/kev-data/commits"
        f"?path=known_exploited_vulnerabilities.json&sha={BRANCH}&per_page=1",
        RAW_URL,
    ]
    assert document.source == RAW_URL  # the commit is part of the snapshot provenance
    assert document.commit == COMMIT and document.branch == BRANCH
    assert document.catalog_version == "2026.11.25" and document.count == 3
    assert len(document.sha256) == 64 and document.size_bytes == len(document.data)
    assert document.released_at is not None and document.released_at.year == 2026
    assert all("cisa.gov" not in url for url in seen)


def test_an_empty_commit_list_is_refused_instead_of_syncing_something_else(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def urlopen(request: Any, timeout: float = 0) -> _Response:
        url = str(getattr(request, "full_url", request))
        if url.endswith(
            "/commits?path=known_exploited_vulnerabilities.json&sha=develop&per_page=1"
        ):
            return _Response(b"[]")
        return _Response(json.dumps({"default_branch": BRANCH}).encode())

    monkeypatch.setattr("aegis.m18_intel.sources.urllib.request.urlopen", urlopen)
    with pytest.raises(KevSourceError) as caught:
        resolve_head(load_kev_source())
    assert "no commit" in str(caught.value)


def test_a_failed_api_call_is_loud_and_never_tries_another_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[str] = []

    def urlopen(request: Any, timeout: float = 0) -> _Response:
        seen.append(str(getattr(request, "full_url", request)))
        raise urllib.error.HTTPError(seen[-1], 503, "Service Unavailable", Message(), None)

    monkeypatch.setattr("aegis.m18_intel.sources.urllib.request.urlopen", urlopen)
    with pytest.raises(KevSourceError) as caught:
        refresh_kev(_source())
    assert "HTTP 503" in str(caught.value)
    assert len(seen) == 1 and "cisa.gov" not in seen[0]


def test_an_export_outside_the_configured_bounds_is_refused() -> None:
    source = load_kev_source()
    with pytest.raises(KevSourceError) as caught:
        validate_catalog(source, _catalog(), provenance="test")
    assert "bytes" in str(caught.value)  # a 3-entry document is far below size_min_bytes
    with pytest.raises(KevSourceError) as counted:
        validate_catalog(
            dataclasses.replace(source, size_min_bytes=1, count_min=100),
            _catalog(),
            provenance="test",
        )
    assert "entries" in str(counted.value)


@pytest.mark.parametrize(
    "document, expected",
    [
        (_catalog(count=4), "count=4"),
        (_catalog(entries=[_entry(0), _entry(0)]), "duplicated"),
        (_catalog(entries=[{**_entry(0), "cveID": "GHSA-1234"}]), "CVE id"),
        (_catalog(entries=[{**_entry(0), "dueDate": "17/11/2021"}]), "YYYY-MM-DD"),
        (
            _catalog(entries=[{k: v for k, v in _entry(0).items() if k != "product"}]),
            "product",
        ),
        (_catalog(version="2026/11/25"), "YYYY.MM.DD"),
    ],
)
def test_a_malformed_catalogue_is_refused(document: bytes, expected: str) -> None:
    with pytest.raises(KevSourceError) as caught:
        validate_catalog(_source(), document, provenance="test")
    assert expected in str(caught.value)


def test_a_rollback_is_refused_but_the_same_or_newer_catalogue_is_accepted() -> None:
    with pytest.raises(KevSourceError) as caught:
        validate_catalog(
            _source(), _catalog("2026.11.24"), provenance="test", last_version="2026-11-25"
        )
    assert "older" in str(caught.value)
    assert (
        validate_catalog(
            _source(), _catalog("2026.11.25"), provenance="test", last_version="2026-11-25"
        ).catalog_version
        == "2026.11.25"
    )
    assert (
        validate_catalog(
            _source(), _catalog("2026.11.26"), provenance="test", last_version="2026-11-25"
        ).catalog_version
        == "2026.11.26"
    )


def test_the_fixture_path_checks_the_same_shape_and_skips_only_the_live_bounds() -> None:
    fixture = repository_root() / "tests/fixtures/intel/kev-slice.json"
    document = load_fixture(load_kev_source(), fixture)
    assert document.count >= 1 and document.catalog_version
    assert document.source.startswith("fixture:")
    assert document.released_at is not None
    # The same bytes are refused by the live bounds: a fixture is not a deployable catalogue.
    with pytest.raises(KevSourceError):
        validate_catalog(load_kev_source(), fixture.read_bytes(), provenance="fixture")


def test_the_optional_github_token_is_read_from_a_file_and_never_required(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    token_file = tmp_path / "github-token"
    token_file.write_text("# comment\nghp_example\n", encoding="utf-8")
    seen: list[str] = []

    def urlopen(request: Any, timeout: float = 0) -> _Response:
        seen.append(request.headers.get("Authorization", ""))
        return _Response(json.dumps({"default_branch": BRANCH}).encode())

    monkeypatch.setenv("AEGIS_GITHUB_TOKEN_FILE", str(token_file))
    monkeypatch.setattr("aegis.m18_intel.sources.urllib.request.urlopen", urlopen)
    with pytest.raises(KevSourceError):
        # The second request has no fake answer; the first one must carry the token.
        resolve_head(load_kev_source())
    assert seen and seen[0] == "Bearer ghp_example"


def test_sync_intel_reports_a_skipped_epss_leg_and_skips_what_was_asked(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # A developer's shell may configure a real EPSS source; the test must not reach it.
    monkeypatch.delenv("AEGIS_EPSS_SOURCE", raising=False)
    monkeypatch.delenv("AEGIS_EPSS_VERSION", raising=False)
    code = cli.main(["sync-intel", "--skip-nvd", "--skip-kev"])
    body = json.loads(capsys.readouterr().out)
    assert code == 0 and body["ok"] is True
    assert body["legs"]["nvd"] == {"status": "skipped"}
    assert body["legs"]["kev"] == {"status": "skipped"}
    assert body["legs"]["epss"]["status"] == "skipped"
    assert "AEGIS_EPSS_SOURCE" in body["legs"]["epss"]["reason"]
