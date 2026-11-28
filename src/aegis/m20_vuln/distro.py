"""Distro fix data for a CPE match (item 80): is the observed package version *patched*?

NVD answers "does this upstream version fall in the vulnerable range". A distro package with the
same upstream version can be either vulnerable or fixed, because the distro backports fixes without
changing the upstream version:

    SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.18      (jammy, fixed for CVE-2024-6387)
    SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.3      (jammy, still vulnerable)

This module answers the distro half. A `DistroRef` is what the observation recorded (distro id,
source package, distro package version, release when the banner names one). `DistroFixes` reads
M18's `distro` revisions (the newest revision **per release**, since `vulnerability_current` has one
row per CVE and would otherwise hide one release behind another) and decides:

* FIXED - every release whose fix line shares the observed upstream version has a fix version at or
  below the observed package version. The candidate is suppressed (or retracted if it existed);
* VULNERABLE - at least one such release is still above the observed version, or the tracker says
  `open` (known affected, no fix). The upstream candidate stands;
* UNKNOWN - no distro row for this CVE/package, or no release's fix line matches the observed
  upstream version. The candidate also stands: absence of fix data is not "fixed", and the report
  counts it (`distro_unresolved`) instead of pretending.

The release is often not in the banner (Ubuntu's `3ubuntu0.18` does not name jammy), so a release is
**compatible** when its fix version's upstream part equals the observed upstream part: the fix line
`1:8.9p1-3ubuntu0.10` is jammy's, while noble's `1:9.6p1-...` is not. A known release (Debian's
`deb12` → `12`) narrows the search before that comparison. Epochs are taken from the fix line when
the banner omits them (dpkg's epoch is not printed in a banner): the distro's own package version
already carries it.

Version order is dpkg's, not NVD's: epoch, then upstream (with `~` sorting before everything), then
the `-revision` part.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegis.common.repo import repository_root
from aegis.m18_intel.distro import DEFAULT_SOURCE_FILE, SOURCE_FILE_ENV

__all__ = [
    "DISTRO_FIXED_METHOD",
    "FIXED",
    "UNKNOWN",
    "VULNERABLE",
    "DistroDecision",
    "DistroFixes",
    "DistroRef",
    "compare_dpkg_versions",
    "distro_from_value",
    "parse_dpkg_version",
]

FIXED = "fixed"
VULNERABLE = "vulnerable"
UNKNOWN = "unknown"
#: `package_vuln_match.match_method` of a retraction the distro data decided (not NVD).
DISTRO_FIXED_METHOD = "distro_fixed"


@dataclass(frozen=True, slots=True)
class DpkgVersion:
    """A Debian version: `[epoch:]upstream[-revision]`."""

    raw: str
    epoch: int
    upstream: str
    revision: str


def parse_dpkg_version(text: str) -> DpkgVersion:
    raw = text.strip()
    epoch = 0
    rest = raw
    head, separator, tail = raw.partition(":")
    if separator and head.isdigit():
        epoch = int(head)
        rest = tail
    if "-" in rest:
        upstream, _, revision = rest.rpartition("-")
    else:
        upstream, revision = rest, ""
    if not upstream:
        raise ValueError(f"not a Debian package version: {text!r}")
    return DpkgVersion(raw=raw, epoch=epoch, upstream=upstream, revision=revision)


def _order(char: str | None) -> int:
    if char == "~":
        return -1
    if char is None:
        return 0
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def _compare_part(left: str, right: str) -> int:
    """dpkg's non-version part order: `~` < end < digits (handled by the caller) < letters."""
    index = 0
    while index < len(left) or index < len(right):
        a = left[index] if index < len(left) else None
        b = right[index] if index < len(right) else None
        if (a is not None and a.isdigit()) or (b is not None and b.isdigit()):
            break
        order_a, order_b = _order(a), _order(b)
        if order_a != order_b:
            return -1 if order_a < order_b else 1
        index += 1
    return 0


def _compare_upstream(left: str, right: str) -> int:
    """dpkg's upstream/revision comparison (digits numerically, the rest by `_order`)."""
    a = b = 0
    while a < len(left) or b < len(right):
        prefix = _compare_part(left[a:], right[b:])
        if prefix != 0:
            return prefix
        while a < len(left) and not left[a].isdigit():
            a += 1
        while b < len(right) and not right[b].isdigit():
            b += 1
        first_difference = 0
        while a < len(left) and b < len(right) and left[a].isdigit() and right[b].isdigit():
            if first_difference == 0:
                first_difference = ord(left[a]) - ord(right[b])
            a += 1
            b += 1
        if a < len(left) and left[a].isdigit():
            return 1
        if b < len(right) and right[b].isdigit():
            return -1
        if first_difference != 0:
            return -1 if first_difference < 0 else 1
        # The next non-digit run (`~`, `.`, letters) is compared by `_compare_part` on the next
        # loop: skipping it here would make `1.0~rc1` sort after `1.0`.
    return 0


def compare_dpkg_versions(left: str, right: str) -> int:
    """-1/0/1 for `left` before/equal/after `right` in dpkg order."""
    a = parse_dpkg_version(left)
    b = parse_dpkg_version(right)
    if a.epoch != b.epoch:
        return -1 if a.epoch < b.epoch else 1
    upstream = _compare_upstream(a.upstream, b.upstream)
    if upstream != 0:
        return upstream
    return _compare_upstream(a.revision, b.revision)


@dataclass(frozen=True, slots=True)
class DistroRef:
    """The distro package an observation recorded."""

    id: str
    release: str | None
    package: str
    version: str

    @property
    def parsed(self) -> DpkgVersion:
        return parse_dpkg_version(self.version)


def distro_from_value(value: object) -> DistroRef | None:
    """The recorded `distro` object of a `service.product` value, when it is complete."""
    if not isinstance(value, dict):
        return None
    raw = value.get("distro")
    if not isinstance(raw, dict):
        return None
    identifier = raw.get("id")
    package = raw.get("package")
    version = raw.get("version")
    release = raw.get("release")
    if not all(isinstance(item, str) and item.strip() for item in (identifier, package, version)):
        return None
    if release is not None and (not isinstance(release, str) or not release.strip()):
        return None
    version_text = str(version)
    try:
        parse_dpkg_version(version_text)
    except ValueError:
        return None
    return DistroRef(
        id=str(identifier).strip().lower(),
        release=None if release is None else str(release).strip(),
        package=str(package).strip(),
        version=version_text.strip(),
    )


@dataclass(frozen=True, slots=True)
class DistroDecision:
    """What the distro data says about one (distro package, CVE) pair."""

    status: str
    package: str
    release: str | None = None
    fixed_version: str | None = None

    @property
    def fixed(self) -> bool:
        return self.status == FIXED


@dataclass(frozen=True, slots=True)
class _Row:
    distro_id: str
    release: str
    codename: str
    package: str
    fixed: str | None


def _package_map(source_file: str | Path | None) -> Mapping[str, str]:
    path = (
        Path(source_file).expanduser()
        if source_file is not None
        else Path(os.environ.get(SOURCE_FILE_ENV) or repository_root() / DEFAULT_SOURCE_FILE)
    )
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError, ValueError:
        return {}
    packages = document.get("packages") if isinstance(document, dict) else None
    return packages if isinstance(packages, dict) else {}


class DistroFixes:
    """The distro fix rows of the packages one matcher run can meet, indexed for a decision."""

    def __init__(
        self,
        connection: Any,
        products: Iterable[str],
        packages: Mapping[str, str] | None = None,
        *,
        source_file: str | Path | None = None,
    ) -> None:
        self._packages = dict(packages) if packages is not None else _package_map(source_file)
        self._rows: dict[tuple[str, str], list[_Row]] = {}
        distro_packages = sorted({self._packages.get(product, product) for product in products})
        if not distro_packages:
            return
        rows = connection.execute(
            "SELECT DISTINCT ON"
            "       (vulnerability_id, affected->'distro'->>'id', affected->'distro'->>'release')"
            "       vulnerability_id, affected"
            "  FROM vulnerability_revision"
            " WHERE source = 'distro' AND affected->'packages' ?| %s"
            " ORDER BY vulnerability_id, affected->'distro'->>'id',"
            "          affected->'distro'->>'release', created_at DESC, vuln_rev_id DESC",
            (distro_packages,),
        ).fetchall()
        for row in rows:
            affected = row["affected"]
            if not isinstance(affected, dict):
                continue
            distro = affected.get("distro")
            packages_ = affected.get("packages")
            if not isinstance(distro, dict) or not isinstance(packages_, dict):
                continue
            identifier = str(distro.get("id") or "")
            release = str(distro.get("release") or "")
            codename = str(distro.get("codename") or "")
            if not identifier or not release:
                continue
            for package, entry in packages_.items():
                if not isinstance(package, str) or not isinstance(entry, dict):
                    continue
                if package not in distro_packages:
                    continue
                fixed = entry.get("fixed")
                self._rows.setdefault((identifier, str(row["vulnerability_id"])), []).append(
                    _Row(
                        distro_id=identifier,
                        release=release,
                        codename=codename,
                        package=package,
                        fixed=fixed if isinstance(fixed, str) and fixed.strip() else None,
                    )
                )

    @property
    def has_rows(self) -> bool:
        return bool(self._rows)

    def decide(self, ref: DistroRef | None, vulnerability_id: str) -> DistroDecision:
        if ref is None:
            return DistroDecision(UNKNOWN, package="")
        package = self._packages.get(ref.package, ref.package)
        rows = [
            row for row in self._rows.get((ref.id, vulnerability_id), ()) if row.package == package
        ]
        if ref.release is not None:
            wanted = ref.release.lower()
            rows = [row for row in rows if wanted in {row.release.lower(), row.codename.lower()}]
        if not rows:
            return DistroDecision(UNKNOWN, package=package)
        installed = ref.parsed
        compatible: list[tuple[_Row, str]] = []
        open_rows: list[_Row] = []
        for row in rows:
            if row.fixed is None:
                open_rows.append(row)
                continue
            try:
                fix = parse_dpkg_version(row.fixed)
            except ValueError:
                continue
            if fix.upstream != installed.upstream:
                continue
            compatible.append((row, row.fixed))
        if not compatible:
            if open_rows:
                return DistroDecision(
                    VULNERABLE,
                    package=package,
                    release=open_rows[0].release,
                )
            return DistroDecision(UNKNOWN, package=package)
        versions = [_installed_with_epoch(ref.version, fixed) for _row, fixed in compatible]
        fixed_versions = [fixed for _row, fixed in compatible]
        if all(
            compare_dpkg_versions(observed, fixed) >= 0
            for observed, fixed in zip(versions, fixed_versions, strict=True)
        ):
            return DistroDecision(
                FIXED,
                package=package,
                release=compatible[0][0].release,
                fixed_version=min(fixed_versions, key=_DpkgKey),
            )
        return DistroDecision(
            VULNERABLE,
            package=package,
            release=compatible[0][0].release,
            fixed_version=fixed_versions[0],
        )


def _installed_with_epoch(installed: str, fixed: str) -> str:
    """Use the fix line's epoch when the banner's version omits it (dpkg does not banner it)."""
    if ":" in installed:
        return installed
    try:
        epoch = parse_dpkg_version(fixed).epoch
    except ValueError:
        return installed
    return installed if epoch == 0 else f"{epoch}:{installed}"


class _DpkgKey:
    """Sort keys for `min` through the dpkg order (no `total_ordering` on a frozen dataclass)."""

    __slots__ = ("value",)

    def __init__(self, value: str) -> None:
        self.value = value

    def __lt__(self, other: _DpkgKey) -> bool:
        return compare_dpkg_versions(self.value, other.value) < 0
