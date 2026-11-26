"""The one configured KEV source, refreshed from the official mirror's current commit.

`www.cisa.gov` is not reachable from this deployment's egress: every path of the host (the KEV
export, `/robots.txt` and `/`) answers **HTTP 403** from Akamai with the same "Access Denied" body
and an `x-reference-error` header, with a browser User-Agent and `Accept` headers or without them
(measured 2026-11-27, item 61 trial). The block is per source IP, so a header cannot fix it. The
configured source is the official `cisagov/kev-data` mirror on GitHub.

A commit pin (the previous version of this module) goes stale within days: CISA updates KEV several
times a week, and a pinned file made production intel freeze while the repository looked healthy.
The source therefore pins the *repository* and a refresh resolves the current HEAD of its default
branch through the GitHub API, downloads `known_exploited_vulnerabilities.json` at that commit and
validates it before a byte reaches PostgreSQL:

* strict document shape: the fields this deployment reads have the documented types, every entry
  has a `CVE-…` id, dates are dates, ids are unique and `count` equals the number of entries;
* sane size and count bounds from `deploy/intel/kev-source.json` (a truncated body or a small error
  document is refused before parsing);
* monotonic `catalogVersion`: a catalogue older than the newest snapshot already stored is refused,
  because a rollback, a stale cache or a branch serving yesterday's file is not an update;
* the resolved commit is recorded in the snapshot provenance (`source_uri` = the raw URL at that
  commit) together with the content sha256 and the catalogue version, so "what did this deployment
  match against" is answerable after the fact.

There is exactly one source and no fallback: a failed API call, an empty commit list, a download
error or a failed validation raises, and nothing falls back to `www.cisa.gov`, to a branch tip
fetched without the API, or to the committed fixture. `load_fixture` exists only for tests, CI and
the offline harness; the deployment path never selects it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegis.common.repo import repository_root

__all__ = [
    "DEFAULT_SOURCE_FILE",
    "KevDocument",
    "KevHead",
    "KevSource",
    "KevSourceError",
    "catalog_key",
    "download",
    "latest_catalog_version",
    "load_fixture",
    "load_kev_source",
    "refresh_kev",
    "resolve_head",
    "validate_catalog",
]

#: Deployment config of the KEV source; `AEGIS_KEV_SOURCE_FILE` points a deployment at its own copy.
DEFAULT_SOURCE_FILE = "deploy/intel/kev-source.json"
SOURCE_FILE_ENV = "AEGIS_KEV_SOURCE_FILE"
#: Optional GitHub token (a *file path*), never a value on a command line or in a log line.
GITHUB_TOKEN_FILE_ENV = "AEGIS_GITHUB_TOKEN_FILE"
REPOSITORY = "cisagov/kev-data"
EXPORT_FILE = "known_exploited_vulnerabilities.json"
API_BASE = "https://api.github.com"
RAW_BASE = "https://raw.githubusercontent.com"
_FETCH_TIMEOUT_SECONDS = 120
_USER_AGENT = "aegis-m18-intel/1.0 (+kev refresh)"
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_CATALOG_VERSION = re.compile(r"^(\d{4})[.-](\d{2})[.-](\d{2})$")
_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_MAX_REPORTED_PROBLEMS = 5
#: The KEV entry fields this deployment stores (`feeds.parse_kev`); a missing one is a shape change.
_ENTRY_STRINGS = (
    "cveID",
    "vendorProject",
    "product",
    "vulnerabilityName",
    "dateAdded",
    "requiredAction",
    "dueDate",
)


class KevSourceError(ValueError):
    """The config, the API answer, the download or the export does not hold: the sync refuses."""


@dataclass(frozen=True, slots=True)
class KevSource:
    """The one configured KEV source and the sanity bounds an export must satisfy."""

    feed: str
    repository: str
    file: str
    size_min_bytes: int
    size_max_bytes: int
    count_min: int
    count_max: int


@dataclass(frozen=True, slots=True)
class KevHead:
    """The commit a refresh resolved for the mirror's default branch."""

    commit: str
    branch: str
    committed_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class KevDocument:
    """A validated export, with the provenance the snapshot row keeps."""

    data: bytes
    source: str
    commit: str
    branch: str
    sha256: str
    size_bytes: int
    catalog_version: str
    count: int
    released_at: datetime | None


def catalog_key(version: str) -> tuple[int, int, int]:
    """A comparable key for `2026.11.25` (KEV) and `2026-11-24` (the fixture slices' versions)."""
    match = _CATALOG_VERSION.match(version.strip())
    if match is None:
        raise KevSourceError(
            f"catalogue version {version!r} is not YYYY.MM.DD (or YYYY-MM-DD); cannot order it"
        )
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def latest_catalog_version(versions: Iterable[str]) -> str | None:
    """The newest parseable version of `versions` (unparseable stored versions are skipped)."""
    best: tuple[tuple[int, int, int], str] | None = None
    for version in versions:
        try:
            key = catalog_key(version)
        except KevSourceError:
            continue
        if best is None or key > best[0]:
            best = (key, version)
    return None if best is None else best[1]


def _source_path(path: str | Path | None) -> Path:
    if path is not None:
        return Path(path).expanduser()
    override = os.environ.get(SOURCE_FILE_ENV)
    if override:
        return Path(override).expanduser()
    return repository_root() / DEFAULT_SOURCE_FILE


def _positive_int(document: Mapping[str, Any], key: str, file: Path) -> int:
    value = document.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise KevSourceError(f"{file}: {key} must be a positive integer")
    return value


def load_kev_source(path: str | Path | None = None) -> KevSource:
    """Read and validate the configured source; every malformed field is refused here."""
    file = _source_path(path)
    try:
        document = json.loads(file.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise KevSourceError(f"the KEV source config is missing: {file}") from error
    except (OSError, ValueError) as error:
        raise KevSourceError(f"the KEV source config cannot be read: {file}: {error}") from error
    if not isinstance(document, dict):
        raise KevSourceError(f"{file}: the KEV source config must be a JSON object")
    if document.get("feed") != "kev":
        raise KevSourceError(f"{file}: pins feed {document.get('feed')!r}, not 'kev'")
    if document.get("repository") != REPOSITORY:
        raise KevSourceError(
            f"{file}: the only configured KEV source is {REPOSITORY!r}, got "
            f"{document.get('repository')!r}"
        )
    if document.get("file") != EXPORT_FILE:
        raise KevSourceError(f"{file}: the export must be {EXPORT_FILE!r}")
    limits = document.get("limits")
    if not isinstance(limits, dict):
        raise KevSourceError(f"{file}: limits must be an object")
    size_min = _positive_int(limits, "size_min_bytes", file)
    size_max = _positive_int(limits, "size_max_bytes", file)
    count_min = _positive_int(limits, "count_min", file)
    count_max = _positive_int(limits, "count_max", file)
    if size_min >= size_max:
        raise KevSourceError(f"{file}: size_min_bytes must be below size_max_bytes")
    if count_min >= count_max:
        raise KevSourceError(f"{file}: count_min must be below count_max")
    return KevSource(
        feed="kev",
        repository=REPOSITORY,
        file=EXPORT_FILE,
        size_min_bytes=size_min,
        size_max_bytes=size_max,
        count_min=count_min,
        count_max=count_max,
    )


def _github_token() -> str | None:
    raw_path = os.environ.get(GITHUB_TOKEN_FILE_ENV, "").strip()
    if not raw_path:
        return None
    path = Path(raw_path).expanduser()
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as error:
        raise KevSourceError(
            f"cannot read the GitHub token file configured by {GITHUB_TOKEN_FILE_ENV}: {error}"
        ) from error
    for line in content.splitlines():
        cleaned = line.strip()
        if cleaned and not cleaned.startswith("#"):
            return cleaned
    raise KevSourceError(f"the GitHub token file configured by {GITHUB_TOKEN_FILE_ENV} is empty")


def _fetch(url: str, *, api: bool = False) -> bytes:
    """GET one URL; a non-2xx answer, a timeout or a network error raises (never a fallback)."""
    headers = {"User-Agent": _USER_AGENT}
    if api:
        headers["Accept"] = "application/vnd.github+json"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
        token = _github_token()
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=_FETCH_TIMEOUT_SECONDS) as response:  # noqa: S310
            return response.read()  # type: ignore[no-any-return]
    except urllib.error.HTTPError as error:
        raise KevSourceError(f"{url} answered HTTP {error.code}: {error.reason}") from error
    except OSError as error:
        raise KevSourceError(f"cannot fetch {url}: {error}") from error


def _json_document(url: str, api: bool = True) -> Any:
    data = _fetch(url, api=api)
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise KevSourceError(f"{url} did not answer JSON: {error}") from error


def _moment(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)


def resolve_head(source: KevSource) -> KevHead:
    """The current HEAD commit of the mirror's default branch (GitHub API, two requests)."""
    repository = _json_document(f"{API_BASE}/repos/{source.repository}")
    if not isinstance(repository, dict):
        raise KevSourceError("the GitHub repository answer is not an object")
    branch = repository.get("default_branch")
    if not isinstance(branch, str) or not branch:
        raise KevSourceError("the GitHub repository answer has no default_branch")
    commits = _json_document(
        f"{API_BASE}/repos/{source.repository}/commits?path={source.file}&sha={branch}&per_page=1"
    )
    if not isinstance(commits, list) or not commits:
        raise KevSourceError(
            f"{source.repository} has no commit for {source.file} on {branch!r}; "
            "refusing to sync a catalogue that cannot be resolved"
        )
    head = commits[0]
    if not isinstance(head, dict):
        raise KevSourceError("the GitHub commit answer is not an object")
    commit = head.get("sha")
    if not isinstance(commit, str) or not _COMMIT.match(commit):
        raise KevSourceError(f"the GitHub commit answer has no 40-hex sha: {commit!r}")
    commit_details = head.get("commit")
    committed_at = None
    if isinstance(commit_details, dict):
        committer = commit_details.get("committer")
        if isinstance(committer, dict):
            committed_at = _moment(committer.get("date"))
    return KevHead(commit=commit, branch=branch, committed_at=committed_at)


def download(source: KevSource, commit: str) -> bytes:
    """The export at exactly that commit: an immutable URL, one request."""
    if not _COMMIT.match(commit):
        raise KevSourceError(f"refusing to download from a non-commit ref {commit!r}")
    return _fetch(f"{RAW_BASE}/{source.repository}/{commit}/{source.file}")


def _validate_entry(entry: Any, index: int, problems: list[str], seen: set[str]) -> None:
    where = f"vulnerabilities[{index}]"
    if not isinstance(entry, dict):
        problems.append(f"{where} is not an object")
        return
    for key in _ENTRY_STRINGS:
        value = entry.get(key)
        if not isinstance(value, str) or not value.strip():
            problems.append(f"{where}.{key} must be a non-empty string")
    for key in ("dateAdded", "dueDate"):
        value = entry.get(key)
        if isinstance(value, str) and value and not _DATE.match(value):
            problems.append(f"{where}.{key} is not YYYY-MM-DD: {value!r}")
    ransomware = entry.get("knownRansomwareCampaignUse")
    if ransomware is not None and not isinstance(ransomware, str):
        problems.append(f"{where}.knownRansomwareCampaignUse must be a string")
    cve_id = entry.get("cveID")
    if isinstance(cve_id, str):
        if not _CVE_ID.match(cve_id):
            problems.append(f"{where}.cveID is not a CVE id: {cve_id!r}")
        elif cve_id in seen:
            problems.append(f"{where}.cveID is duplicated: {cve_id}")
        else:
            seen.add(cve_id)


def validate_catalog(
    source: KevSource,
    data: bytes,
    *,
    provenance: str,
    commit: str = "",
    branch: str = "",
    last_version: str | None = None,
    enforce_bounds: bool = True,
) -> KevDocument:
    """Refuse anything that is not a complete, current, well-formed KEV catalogue."""
    if enforce_bounds and not (source.size_min_bytes <= len(data) <= source.size_max_bytes):
        raise KevSourceError(
            f"KEV export is {len(data)} bytes, outside the configured "
            f"{source.size_min_bytes}..{source.size_max_bytes}; refusing it"
        )
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise KevSourceError(f"KEV export is not JSON: {error}") from error
    if not isinstance(document, dict):
        raise KevSourceError("KEV export is not a JSON object")
    catalog_version = document.get("catalogVersion")
    if not isinstance(catalog_version, str) or not catalog_version.strip():
        raise KevSourceError("KEV export has no catalogVersion")
    version_key = catalog_key(catalog_version)
    entries = document.get("vulnerabilities")
    if not isinstance(entries, list):
        raise KevSourceError("KEV export has no vulnerabilities array")
    declared = document.get("count")
    if not isinstance(declared, int) or isinstance(declared, bool):
        raise KevSourceError("KEV export has no integer count")
    if declared != len(entries):
        raise KevSourceError(
            f"KEV export says count={declared} but carries {len(entries)} entry(ies)"
        )
    if enforce_bounds and not (source.count_min <= declared <= source.count_max):
        raise KevSourceError(
            f"KEV export has {declared} entries, outside the configured "
            f"{source.count_min}..{source.count_max}; refusing it"
        )
    if last_version is not None:
        previous_key = catalog_key(last_version)
        if version_key < previous_key:
            raise KevSourceError(
                f"KEV export catalogVersion {catalog_version} is older than the newest stored "
                f"snapshot {last_version}; refusing a rollback"
            )
    problems: list[str] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        if len(problems) > _MAX_REPORTED_PROBLEMS:
            break
        _validate_entry(entry, index, problems, seen)
    if problems:
        listed = "; ".join(problems[:_MAX_REPORTED_PROBLEMS])
        more = (
            f" (+{len(problems) - _MAX_REPORTED_PROBLEMS} more)"
            if len(problems) > _MAX_REPORTED_PROBLEMS
            else ""
        )
        raise KevSourceError(f"KEV export does not have the documented shape: {listed}{more}")
    return KevDocument(
        data=data,
        source=provenance,
        commit=commit,
        branch=branch,
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        catalog_version=catalog_version,
        count=declared,
        released_at=_moment(document.get("dateReleased")),
    )


def refresh_kev(source: KevSource, *, last_version: str | None = None) -> KevDocument:
    """Resolve the mirror's current commit, download that export and validate it.

    `last_version` is the newest `catalogVersion` already stored; a catalogue older than it is
    refused (see the module docstring). Every failure raises; there is no second source.
    """
    head = resolve_head(source)
    data = download(source, head.commit)
    provenance = f"{RAW_BASE}/{source.repository}/{head.commit}/{source.file}"
    return validate_catalog(
        source,
        data,
        provenance=provenance,
        commit=head.commit,
        branch=head.branch,
        last_version=last_version,
    )


def load_fixture(
    source: KevSource, path: str | Path, *, last_version: str | None = None
) -> KevDocument:
    """A committed export for tests/CI/offline runs: shape and version rules, no size bounds.

    The bounds in the config describe the *live* catalogue; a committed slice is deliberately
    small. Everything else (shape, `count`, unique ids, monotonic version) is checked the same way,
    because a test must fail for the same reason a deployment would.
    """
    file = Path(path).expanduser()
    try:
        data = file.read_bytes()
    except OSError as error:
        raise KevSourceError(f"cannot read the KEV fixture {file}: {error}") from error
    return validate_catalog(
        source,
        data,
        provenance=f"fixture:{file}",
        last_version=last_version,
        enforce_bounds=False,
    )
