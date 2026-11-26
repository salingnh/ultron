"""Pinned external feed sources: deployment data, verified before it is loaded.

`www.cisa.gov` is not reachable from this deployment's egress: every path of the host (the KEV
export, `/robots.txt` and `/`) answers **HTTP 403** from Akamai with the same "Access Denied" body
and an `x-reference-error` header, with a browser User-Agent and `Accept` headers or without them
(measured 2026-11-27, item 61 trial). The block is per source IP, so it cannot be fixed with a
header. The configured KEV source is therefore the official `cisagov/kev-data` mirror on GitHub,
pinned to a commit.

A pin is a deployment decision, not an optimisation: the file's URL (which already carries the
commit), its exact size and its sha256 are recorded in `deploy/intel/kev-source.json`, and a
download that does not match them is refused. There is exactly **one** configured source: nothing
here falls back to `www.cisa.gov`, to the committed 3-row fixture slice, or to an older pin.
Refreshing KEV is a deliberate pin bump (commit, size, sha256 and catalog version together), which
also makes "which catalogue did this deployment match against" answerable from the repository.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegis.common.repo import repository_root

__all__ = [
    "DEFAULT_PIN_FILE",
    "PinnedFeed",
    "PinnedFeedError",
    "fetch_pinned",
    "load_pinned_feed",
]

#: Deployment config of the KEV source; `AEGIS_KEV_SOURCE_FILE` points a deployment at its own copy.
DEFAULT_PIN_FILE = "deploy/intel/kev-source.json"
PIN_FILE_ENV = "AEGIS_KEV_SOURCE_FILE"
#: The mirror's file; the URL must name this repository and this commit-pinned path.
_MIRROR_PREFIX = "https://raw.githubusercontent.com/cisagov/kev-data/"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_FETCH_TIMEOUT_SECONDS = 120
_USER_AGENT = "aegis-m18-intel/1.0 (+kev pin)"


class PinnedFeedError(ValueError):
    """The pin file, the download or the pinned metadata does not hold; the sync must refuse."""


@dataclass(frozen=True, slots=True)
class PinnedFeed:
    """One configured feed export: where it comes from, and the bytes it must be."""

    feed: str
    url: str
    version: str
    size_bytes: int
    sha256: str
    catalog_version: str


def _pin_path(path: str | Path | None) -> Path:
    if path is not None:
        return Path(path).expanduser()
    override = os.environ.get(PIN_FILE_ENV)
    if override:
        return Path(override).expanduser()
    return repository_root() / DEFAULT_PIN_FILE


def load_pinned_feed(feed: str = "kev", *, path: str | Path | None = None) -> PinnedFeed:
    """Read and validate the pin file of one feed; every malformed field is refused here."""
    file = _pin_path(path)
    try:
        document = json.loads(file.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise PinnedFeedError(f"the {feed} source pin is missing: {file}") from error
    except (OSError, ValueError) as error:
        raise PinnedFeedError(f"the {feed} source pin cannot be read: {file}: {error}") from error
    if not isinstance(document, dict):
        raise PinnedFeedError(f"{file}: the pin must be a JSON object")

    pinned_feed = document.get("feed")
    if pinned_feed != feed:
        raise PinnedFeedError(f"{file}: pins feed {pinned_feed!r}, not {feed!r}")
    url = document.get("url")
    if not isinstance(url, str) or not url.startswith(_MIRROR_PREFIX):
        raise PinnedFeedError(
            f"{file}: url must start with {_MIRROR_PREFIX!r} (the pinned official mirror); "
            f"got {url!r}"
        )
    commit = url[len(_MIRROR_PREFIX) :].split("/", 1)[0]
    if not _COMMIT.match(commit):
        raise PinnedFeedError(
            f"{file}: the mirror path must start with a 40-hex commit (an immutable pin), "
            f"not {commit!r}"
        )
    version = document.get("version")
    if not isinstance(version, str) or not version.strip():
        raise PinnedFeedError(f"{file}: version must be a non-empty string")
    catalog_version = document.get("catalog_version")
    if not isinstance(catalog_version, str) or not catalog_version.strip():
        raise PinnedFeedError(f"{file}: catalog_version must be a non-empty string")
    size = document.get("size_bytes")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise PinnedFeedError(f"{file}: size_bytes must be a positive integer")
    sha256 = document.get("sha256")
    if not isinstance(sha256, str) or not _SHA256.match(sha256):
        raise PinnedFeedError(f"{file}: sha256 must be 64 lowercase hex characters")
    return PinnedFeed(
        feed=feed,
        url=url,
        version=version,
        size_bytes=size,
        sha256=sha256,
        catalog_version=catalog_version,
    )


def fetch_pinned(pinned: PinnedFeed) -> bytes:
    """Download the one configured URL and refuse bytes that are not the pinned ones.

    The checksum is checked before the feed is parsed and before anything is written, so a mirror
    that changed under the pin (a moved branch, a proxy, a truncated body) fails here instead of
    becoming intel the matcher trusts.
    """
    request = urllib.request.Request(pinned.url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=_FETCH_TIMEOUT_SECONDS) as response:  # noqa: S310
            data: bytes = response.read()
    except OSError as error:
        raise PinnedFeedError(f"{pinned.feed}: cannot fetch {pinned.url}: {error}") from error
    if len(data) != pinned.size_bytes:
        raise PinnedFeedError(
            f"{pinned.feed}: {pinned.url} answered {len(data)} bytes, the pin says "
            f"{pinned.size_bytes}; refusing an unpinned export"
        )
    digest = hashlib.sha256(data).hexdigest()
    if digest != pinned.sha256:
        raise PinnedFeedError(
            f"{pinned.feed}: {pinned.url} has sha256 {digest}, the pin says {pinned.sha256}; "
            "refusing an unpinned export"
        )
    _verify_catalog_version(pinned, data)
    return data


def _verify_catalog_version(pinned: PinnedFeed, data: bytes) -> None:
    """The catalogue's version must be the pinned one (a pin naming another file is wrong)."""
    try:
        document: Any = json.loads(data.decode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise PinnedFeedError(f"{pinned.feed}: the pinned export is not JSON: {error}") from error
    catalog_version = document.get("catalogVersion") if isinstance(document, dict) else None
    if catalog_version != pinned.catalog_version:
        raise PinnedFeedError(
            f"{pinned.feed}: the export says catalogVersion {catalog_version!r}, the pin says "
            f"{pinned.catalog_version!r}"
        )
