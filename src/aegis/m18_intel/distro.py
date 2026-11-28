"""The distro fix-data feed (item 80): Ubuntu OVAL and the Debian security tracker.

A banner like `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.18` carries a **distro** package: upstream
NVD says 8.9p1 is inside CVE-2024-6387's affected range, but Ubuntu shipped the fix in
`1:8.9p1-3ubuntu0.10` (and later). Upstream matching alone reports a patched host as vulnerable.
This feed is the offline, authoritative answer to "did the distro ship the fix":

* Ubuntu: the per-release OVAL file (`com.ubuntu.<release>.cve.oval.xml.bz2`, updated daily).
  One `definition` per CVE; its `criterion` points at a `dpkginfo_test` → the source package object
  and an `evr` state that is the **fixed** version (`less than` = still vulnerable);
* Debian: the security tracker `data/json`, keyed by source package, with the per-release
  `status` and `fixed_version` (the JSON also publishes `open`/`undetermined`).

Both are single downloads per release, so there is no page to resume: content addressing +
`(feed, version)` immutability make a retried sync idempotent, and a failed download simply fails
the leg (the next run retries the whole file). The snapshot version is
`<distro>-<release>-<feed date>-<sha256 prefix>`: a changed file is a new snapshot, the same file is
the same snapshot.

One record = one CVE on one release. `affected` is:

    {"distro": {"id": "ubuntu", "release": "jammy", "codename": "22.04"},
     "packages": {"openssh": {"fixed": "1:8.9p1-3ubuntu0.10", "status": "fixed"}}}

The release is in the value (and therefore in the record's content hash), because the same CVE has
a different fix per release and `vulnerability_current` must not shadow one release with another;
M20 reads the newest revision **per release**. A Debian `open` entry has `fixed: null`, which means
"known affected, no fix yet" and is enough to keep the NVD candidate.
"""

from __future__ import annotations

import bz2
import hashlib
import io
import json
import os
import re
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

from aegis.common.repo import repository_root
from aegis.m18_intel import feeds
from aegis.m18_intel.feeds import FeedError, VulnRecord
from aegis.m18_intel.sync import FeedSync, FeedSyncError

__all__ = [
    "DEFAULT_SOURCE_FILE",
    "DistroConfig",
    "DistroSource",
    "DistroSourceError",
    "FetchResult",
    "fetch_url",
    "load_distro_sources",
    "parse_debian_tracker",
    "parse_ubuntu_oval",
    "sync_distro",
]

DEFAULT_SOURCE_FILE = "deploy/intel/distro-sources.json"
SOURCE_FILE_ENV = "AEGIS_DISTRO_SOURCE_FILE"
FEED = feeds.DISTRO
_USER_AGENT = "aegis-m18-intel/1.0 (+distro fix data)"
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_FETCH_TIMEOUT_SECONDS = 600
_KINDS = ("ubuntu-oval", "debian-tracker")


class DistroSourceError(ValueError):
    """The config, the download, the document shape or the bounds do not hold: refuse the sync."""


@dataclass(frozen=True, slots=True)
class DistroSource:
    """One release of one distro: where its fix data comes from and how big it may be."""

    id: str
    release: str
    codename: str
    kind: str
    url: str
    size_min_bytes: int
    size_max_bytes: int
    count_min: int
    count_max: int

    @property
    def key(self) -> str:
        return f"{self.id}-{self.release}"


@dataclass(frozen=True, slots=True)
class DistroConfig:
    """The configured sources plus the CPE-product → distro-source-package map."""

    sources: tuple[DistroSource, ...]
    packages: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class FetchResult:
    data: bytes
    last_modified: datetime | None


def _positive_int(document: Mapping[str, Any], key: str, where: str) -> int:
    value = document.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise DistroSourceError(f"{where}: {key} must be a positive integer")
    return value


def _source_path(path: str | Path | None) -> Path:
    if path is not None:
        return Path(path).expanduser()
    override = os.environ.get(SOURCE_FILE_ENV)
    if override:
        return Path(override).expanduser()
    return repository_root() / DEFAULT_SOURCE_FILE


def load_distro_sources(path: str | Path | None = None) -> DistroConfig:
    """Read and validate the configured distro sources; every malformed field is refused."""
    file = _source_path(path)
    try:
        document = json.loads(file.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise DistroSourceError(f"the distro source config is missing: {file}") from error
    except (OSError, ValueError) as error:
        raise DistroSourceError(
            f"the distro source config cannot be read: {file}: {error}"
        ) from error
    if not isinstance(document, dict):
        raise DistroSourceError(f"{file}: the distro source config must be a JSON object")
    if document.get("feed") != FEED:
        raise DistroSourceError(f"{file}: pins feed {document.get('feed')!r}, not {FEED!r}")
    packages = document.get("packages")
    if not isinstance(packages, dict) or not all(
        isinstance(key, str) and isinstance(value, str) and key and value
        for key, value in packages.items()
    ):
        raise DistroSourceError(
            f"{file}: packages must map CPE product names to distro package names"
        )
    raw_sources = document.get("sources")
    if not isinstance(raw_sources, list) or not raw_sources:
        raise DistroSourceError(f"{file}: sources must be a non-empty array")
    sources: list[DistroSource] = []
    seen: set[tuple[str, str]] = set()
    for index, entry in enumerate(raw_sources):
        where = f"{file}: sources[{index}]"
        if not isinstance(entry, dict):
            raise DistroSourceError(f"{where} must be an object")
        values: dict[str, Any] = {}
        for key in ("id", "release", "codename", "kind", "url"):
            value = entry.get(key)
            if not isinstance(value, str) or not value.strip():
                raise DistroSourceError(f"{where}.{key} must be a non-empty string")
            values[key] = value.strip()
        if values["kind"] not in _KINDS:
            raise DistroSourceError(f"{where}.kind must be one of {', '.join(_KINDS)}")
        source = DistroSource(
            id=values["id"],
            release=values["release"],
            codename=values["codename"],
            kind=values["kind"],
            url=values["url"],
            size_min_bytes=_positive_int(entry, "size_min_bytes", where),
            size_max_bytes=_positive_int(entry, "size_max_bytes", where),
            count_min=_positive_int(entry, "count_min", where),
            count_max=_positive_int(entry, "count_max", where),
        )
        if source.size_min_bytes >= source.size_max_bytes:
            raise DistroSourceError(f"{where}: size_min_bytes must be below size_max_bytes")
        if source.count_min >= source.count_max:
            raise DistroSourceError(f"{where}: count_min must be below count_max")
        if (source.id, source.release) in seen:
            raise DistroSourceError(f"{where}: duplicate source {source.key}")
        seen.add((source.id, source.release))
        sources.append(source)
    return DistroConfig(sources=tuple(sources), packages=dict(packages))


def fetch_url(url: str) -> FetchResult:
    """GET one export once; a non-2xx answer or a network error raises (never a fallback)."""
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=_FETCH_TIMEOUT_SECONDS) as response:  # noqa: S310
            data = response.read()
            last_modified = _http_moment(response.headers.get("Last-Modified"))
    except urllib.error.HTTPError as error:
        raise DistroSourceError(f"{url} answered HTTP {error.code}: {error.reason}") from error
    except OSError as error:
        raise DistroSourceError(f"cannot fetch {url}: {error}") from error
    return FetchResult(data=data, last_modified=last_modified)


def _http_moment(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        moment = parsedate_to_datetime(value)
    except TypeError, ValueError:
        return None
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _oval_evr(text: str, datatype: str) -> str:
    """Normalize an OVAL `evr` to the dpkg version.

    Canonical's current files use `debian_evr_string` and the value **is** the dpkg version
    (`1:8.9p1-3ubuntu0.10`). Older/other OVAL writers use `evr_string` with an OVAL epoch prefix
    (`0:1:8.9p1-3ubuntu0.10`), which is not part of the dpkg version and must be dropped. The
    datatype, not the presence of a colon, says which one this is - `1:` in the dpkg form is the
    package's own epoch.
    """
    cleaned = text.strip()
    if datatype == "debian_evr_string":
        return cleaned
    epoch, separator, rest = cleaned.partition(":")
    if separator and epoch.isdigit() and rest:
        return rest
    return cleaned


def parse_ubuntu_oval(data: bytes, source: DistroSource) -> list[VulnRecord]:
    """One record per CVE definition that carries a fixed package version.

    The document is streamed: it is 300+ MB uncompressed, and `iterparse` + `clear()` keeps only the
    definition/test/object/state maps this resolution needs. A definition whose state has no
    `evr` (an unfixed CVE) is not recorded; absence means "no fix published", which M20 treats as
    unknown and keeps the upstream candidate.
    """
    stream: Any = bz2.BZ2File(io.BytesIO(data)) if data[:3] == b"BZh" else io.BytesIO(data)
    definitions: dict[str, tuple[str, list[str]]] = {}
    tests: dict[str, tuple[str | None, str | None]] = {}
    objects: dict[str, str] = {}
    states: dict[str, str] = {}
    try:
        for _event, elem in ET.iterparse(stream, events=("end",)):
            tag = _local(elem.tag)
            if tag == "definition":
                definition = elem.get("id") or ""
                cve = _oval_cve(elem)
                refs = [
                    str(child.get("test_ref"))
                    for child in elem.iter()
                    if _local(child.tag) == "criterion" and child.get("test_ref")
                ]
                if cve is not None and definition and refs:
                    definitions[definition] = (cve, refs)
                elem.clear()
            elif tag == "dpkginfo_test":
                test_id = elem.get("id") or ""
                object_ref = None
                state_ref = None
                for child in elem:
                    name = _local(child.tag)
                    if name == "object":
                        object_ref = child.get("object_ref")
                    elif name == "state":
                        state_ref = child.get("state_ref")
                if test_id:
                    tests[test_id] = (object_ref, state_ref)
                elem.clear()
            elif tag == "dpkginfo_object":
                object_id = elem.get("id") or ""
                package_name = _oval_object_package(elem)
                if object_id and package_name is not None:
                    objects[object_id] = package_name
                elem.clear()
            elif tag == "dpkginfo_state":
                state_id = elem.get("id") or ""
                evr = next((child for child in elem if _local(child.tag) == "evr"), None)
                if (
                    state_id
                    and evr is not None
                    and (evr.get("operation") or "").strip() == "less than"
                    and isinstance(evr.text, str)
                    and evr.text.strip()
                ):
                    states[state_id] = _oval_evr(evr.text, (evr.get("datatype") or "").strip())
                elem.clear()
            elif tag in {"definitions", "tests", "objects", "states"}:
                # The section is complete: dropping its (already read) children keeps a streamed
                # 300+ MB OVAL document's memory flat instead of leaving empty elements behind.
                elem.clear()
    except ET.ParseError as error:
        raise DistroSourceError(f"{source.key}: the OVAL XML is malformed: {error}") from error
    records: list[VulnRecord] = []
    for cve, test_refs in definitions.values():
        packages: dict[str, dict[str, Any]] = {}
        for test_ref in test_refs:
            test = tests.get(test_ref)
            if test is None:
                continue
            object_ref, state_ref = test
            package = objects.get(object_ref or "")
            fixed = states.get(state_ref or "")
            if package is None or fixed is None:
                continue
            packages[package] = {"fixed": fixed, "status": "fixed"}
        if not packages:
            continue
        records.append(
            VulnRecord(
                vulnerability_id=cve,
                affected={
                    "distro": {
                        "id": source.id,
                        "release": source.release,
                        "codename": source.codename,
                    },
                    "packages": packages,
                },
                references=[
                    {"url": f"https://ubuntu.com/security/{cve}", "source": "ubuntu", "tags": []}
                ],
            )
        )
    if not records:
        raise DistroSourceError(f"{source.key}: the OVAL export has no CVE with a fixed version")
    return records


#: Canonical writes `<name var_ref="..."/>`; the **source** package this object is about is in the
#: object's comment ("The 'openssh' package binaries"). The variable lists Ubuntu's binary package
#: names (openssh-server, ssh, ...), not the source name the fix data is keyed by.
_OBJECT_COMMENT = re.compile(r"The '(?P<package>[^']+)' package")


def _oval_object_package(element: ET.Element) -> str | None:
    """The source package an object is about, from its inline name or its comment."""
    name = next((child for child in element if _local(child.tag) == "name"), None)
    if name is not None and isinstance(name.text, str) and name.text.strip():
        return name.text.strip()
    match = _OBJECT_COMMENT.search(element.get("comment") or "")
    return None if match is None else match.group("package")


def _oval_cve(definition: ET.Element) -> str | None:
    for elem in definition.iter():
        if _local(elem.tag) != "reference":
            continue
        ref_id = elem.get("ref_id")
        if isinstance(ref_id, str) and _CVE.match(ref_id):
            return ref_id
    title = next((elem.text for elem in definition.iter() if _local(elem.tag) == "title"), None)
    if isinstance(title, str):
        match = re.search(r"(CVE-\d{4}-\d{4,})", title)
        if match is not None:
            return match.group(1)
    return None


def parse_debian_tracker(data: bytes, source: DistroSource) -> list[VulnRecord]:
    """One record per (source package, CVE) the tracker lists for this release."""
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise DistroSourceError(f"{source.key}: the Debian tracker is not JSON: {error}") from error
    if not isinstance(document, dict):
        raise DistroSourceError(f"{source.key}: the Debian tracker must be a JSON object")
    records: list[VulnRecord] = []
    for package, entries in document.items():
        if not isinstance(package, str) or not isinstance(entries, dict):
            continue
        for cve, entry in entries.items():
            if not isinstance(cve, str) or not _CVE.match(cve) or not isinstance(entry, dict):
                continue
            releases = entry.get("releases")
            if not isinstance(releases, dict):
                continue
            release = releases.get(source.release)
            if not isinstance(release, dict):
                continue
            status = release.get("status")
            fixed = release.get("fixed_version")
            if status not in {"resolved", "open"}:
                continue
            if status == "resolved" and not isinstance(fixed, str):
                continue
            records.append(
                VulnRecord(
                    vulnerability_id=cve,
                    affected={
                        "distro": {
                            "id": source.id,
                            "release": source.release,
                            "codename": source.codename,
                        },
                        "packages": {
                            package: {
                                "fixed": fixed if status == "resolved" else None,
                                "status": status,
                            }
                        },
                    },
                    references=[
                        {
                            "url": f"https://security-tracker.debian.org/tracker/{cve}",
                            "source": "debian",
                            "tags": [],
                        }
                    ],
                )
            )
    if not records:
        raise DistroSourceError(
            f"{source.key}: the Debian tracker has no entry for release {source.release!r}"
        )
    return records


def _validate_records(source: DistroSource, records: list[VulnRecord]) -> None:
    if not source.count_min <= len(records) <= source.count_max:
        raise DistroSourceError(
            f"{source.key}: {len(records)} record(s), outside the configured "
            f"{source.count_min}..{source.count_max}; refusing the export"
        )
    for record in records:
        if not _CVE.match(record.vulnerability_id):
            raise DistroSourceError(f"{source.key}: {record.vulnerability_id!r} is not a CVE id")
        if not isinstance(record.affected, dict) or not record.affected.get("packages"):
            raise DistroSourceError(
                f"{source.key}: {record.vulnerability_id} has no package fix data"
            )


def _version_prefix(feed_date: datetime, sha256: str) -> str:
    return f"{feed_date.astimezone(UTC).date().isoformat()}-{sha256[:8]}"


def sync_distro(
    *,
    source_file: str | Path | None = None,
    sync: FeedSync | None = None,
    fetch: Callable[[str], FetchResult] = fetch_url,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Download each configured export once and load one snapshot per release.

    A failing source is recorded and the other sources still load; the caller (`sync-intel` or the
    activity) turns `ok: false` into a failed leg. Nothing is silently skipped: every configured
    source appears in `sources`, with its error when it failed.
    """
    config = load_distro_sources(source_file)
    writer = sync or FeedSync.from_env()
    moment = now or datetime.now(UTC)
    fetched: dict[str, FetchResult | str] = {}
    results: dict[str, Any] = {}
    errors: list[dict[str, str]] = []
    for source in config.sources:
        try:
            if source.url not in fetched:
                try:
                    fetched[source.url] = fetch(source.url)
                except (DistroSourceError, OSError) as error:
                    fetched[source.url] = str(error)
            result = fetched[source.url]
            if isinstance(result, str):
                raise DistroSourceError(result)
            data = result.data
            if not source.size_min_bytes <= len(data) <= source.size_max_bytes:
                raise DistroSourceError(
                    f"{source.key}: {len(data)} bytes, outside the configured "
                    f"{source.size_min_bytes}..{source.size_max_bytes}; refusing the export"
                )
            parser = parse_ubuntu_oval if source.kind == "ubuntu-oval" else parse_debian_tracker
            records = parser(data, source)
            _validate_records(source, records)
            snapshot_at = result.last_modified or moment
            version = (
                f"{source.key}-{_version_prefix(snapshot_at, hashlib.sha256(data).hexdigest())}"
            )
            report = writer.sync_records(
                FEED,
                version,
                data,
                records,
                source_uri=f"{source.url}#{source.release}",
                snapshot_at=snapshot_at,
            )
            results[source.key] = report.as_dict()
        except (DistroSourceError, FeedError, FeedSyncError, ValueError, OSError) as error:
            results[source.key] = {"error": str(error)}
            errors.append({"source": source.key, "error": str(error)})
    return {"ok": not errors, "sources": results, "errors": errors}
