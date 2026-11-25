"""CPE 2.3 parsing and version-range evaluation for the M20 matcher (G1.6 slice C).

NVD publishes affectedness as CPE match criteria plus version bounds:

    "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
    "versionStartIncluding": "1.0.0", "versionEndExcluding": "1.15.0", "vulnerable": true

Matching an observation's CPE against that needs three things, and only these are implemented:

* `parse_cpe` - the 2.3 formatted string (and its 2.2 URI form `cpe:/a:vendor:product:version`)
  split into its components with the CPE escaping rules (`\\:` is a literal colon inside a part);
* `compare_versions` - a deterministic version order, documented below, used for the bounds;
* `CpeMatch.matches` - the four NVD bound fields and the exact-version form, with `vulnerable`
  kept so an excluded configuration is visible.

Version order (deliberately small and documented, because NVD does not publish an algorithm):
tokens split on `.`, `-`, `_` and `+`; two numeric tokens compare numerically, otherwise tokens
compare case-insensitively as strings; when one version runs out of tokens the shorter one is
lower unless the remaining token is numeric `0` (so `1.24` == `1.24.0` and `1.24 < 1.24.1`) or a
pre-release word (`rc`, `beta`, `alpha`, `pre`, `dev`, `snapshot`), which sorts the longer version
before the release (`1.0-rc1 < 1.0`). A
range bound therefore behaves like the operator's `sort -V` for the versions NVD publishes; a
non-standard version (a distro suffix, `~rc1`) is compared as text, and the candidate keeps its
lower confidence. An unknown version never matches a bound (no version, no range decision).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = [
    "Cpe",
    "CpeMatch",
    "CpeVersion",
    "compare_versions",
    "parse_cpe",
    "parse_version",
]

_CPE23 = re.compile(r"^cpe:2\.3:(?P<body>.+)$")
_CPE22 = re.compile(r"^cpe:/")
_ESCAPED_COLON = "\x00"


class CpeError(ValueError):
    """The string is not a CPE the matcher can use."""


@dataclass(frozen=True, slots=True)
class Cpe:
    """The parts of a CPE that identify a product; `version` is `*`/`-` when unspecified."""

    part: str
    vendor: str
    product: str
    version: str
    update: str = "*"

    @property
    def product_key(self) -> tuple[str, str]:
        return (self.vendor.lower(), self.product.lower())

    @property
    def has_version(self) -> bool:
        return self.version not in {"*", "-", ""}

    def as_text(self, *, with_version: bool = True) -> str:
        version = self.version if with_version else "*"
        return f"cpe:2.3:{self.part}:{self.vendor}:{self.product}:{version}:*:*:*:*:*:*"


def _split_formatted(body: str) -> list[str]:
    body = body.replace("\\\\", "\x01").replace("\\:", _ESCAPED_COLON)
    parts = body.split(":")
    return [part.replace(_ESCAPED_COLON, ":").replace("\x01", "\\").lower() for part in parts]


def parse_cpe(text: object) -> Cpe:
    """Parse a CPE 2.3 formatted string or a CPE 2.2 URI; raise `CpeError` otherwise."""
    if not isinstance(text, str) or not text.strip():
        raise CpeError(f"not a CPE string: {text!r}")
    raw = text.strip()
    if (match := _CPE23.match(raw)) is not None:
        parts = _split_formatted(match.group("body"))
        if len(parts) < 3:
            raise CpeError(f"a CPE 2.3 string needs at least part:vendor:product: {text!r}")
        padded = parts + ["*"] * (11 - len(parts))
        return Cpe(
            part=padded[0],
            vendor=padded[1],
            product=padded[2],
            version=padded[3],
            update=padded[4],
        )
    if _CPE22.match(raw) is not None:
        parts = [part.lower() for part in raw.removeprefix("cpe:/").split(":")]
        if len(parts) < 3:
            raise CpeError(f"a CPE 2.2 URI needs at least part:vendor:product: {text!r}")
        padded = parts + ["*"] * (5 - len(parts))
        return Cpe(
            part=padded[0],
            vendor=padded[1],
            product=padded[2],
            version=padded[3],
            update=padded[4],
        )
    raise CpeError(f"not a CPE string: {text!r}")


@dataclass(frozen=True, slots=True)
class CpeVersion:
    """A version string in the order `compare_versions` defines."""

    raw: str
    tokens: tuple[tuple[int, object], ...]

    def __str__(self) -> str:  # pragma: no cover - debugging aid
        return self.raw


_TOKEN = re.compile(r"[0-9]+|[A-Za-z]+|[^0-9A-Za-z]+")


def parse_version(text: object) -> CpeVersion:
    if not isinstance(text, str) or not text.strip():
        raise CpeError(f"not a version string: {text!r}")
    raw = text.strip().lower()
    tokens: list[tuple[int, object]] = []
    for token in _TOKEN.findall(raw):
        if token.isdigit():
            tokens.append((0, int(token)))
        elif token.isalpha():
            tokens.append((1, token))
        else:  # punctuation carries no order; it separates tokens
            continue
    if not tokens:
        raise CpeError(f"not a version string: {text!r}")
    return CpeVersion(raw=raw, tokens=tuple(tokens))


def compare_versions(left: str | CpeVersion, right: str | CpeVersion) -> int:
    """-1/0/1 for `left` before/equal/after `right`; raises `CpeError` on a non-version."""
    a = left if isinstance(left, CpeVersion) else parse_version(left)
    b = right if isinstance(right, CpeVersion) else parse_version(right)
    for index in range(max(len(a.tokens), len(b.tokens))):
        if index >= len(a.tokens):
            if _is_zero_tail(b.tokens[index:]):
                return 0
            return 1 if _is_prerelease_tail(b.tokens[index:]) else -1
        if index >= len(b.tokens):
            if _is_zero_tail(a.tokens[index:]):
                return 0
            return -1 if _is_prerelease_tail(a.tokens[index:]) else 1
        (kind_a, value_a), (kind_b, value_b) = a.tokens[index], b.tokens[index]
        if kind_a == kind_b:
            if value_a == value_b:
                continue
            return -1 if value_a < value_b else 1  # type: ignore[operator]
        # A number sorts before a word ("1.0" < "1.0a"), the same way `sort -V` orders them.
        return -1 if kind_a < kind_b else 1
    return 0


PRE_RELEASE = frozenset({"alpha", "beta", "rc", "pre", "preview", "dev", "snapshot"})


def _is_zero_tail(tokens: tuple[tuple[int, object], ...]) -> bool:
    return all(kind == 0 and value == 0 for kind, value in tokens)


def _is_prerelease_tail(tokens: tuple[tuple[int, object], ...]) -> bool:
    return bool(tokens) and tokens[0][0] == 1 and tokens[0][1] in PRE_RELEASE


@dataclass(frozen=True, slots=True)
class CpeMatch:
    """One `cpeMatch` entry of an NVD configuration, as stored in `affected.cpe_match`."""

    criteria: str
    vulnerable: bool
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None

    @classmethod
    def from_json(cls, entry: object) -> CpeMatch:
        if not isinstance(entry, dict):
            raise CpeError(f"a cpeMatch entry must be an object: {entry!r}")
        criteria = entry.get("criteria")
        if not isinstance(criteria, str):
            raise CpeError(f"a cpeMatch entry has no criteria: {entry!r}")
        return cls(
            criteria=criteria,
            vulnerable=bool(entry.get("vulnerable", False)),
            version_start_including=_text(entry.get("version_start_including")),
            version_start_excluding=_text(entry.get("version_start_excluding")),
            version_end_including=_text(entry.get("version_end_including")),
            version_end_excluding=_text(entry.get("version_end_excluding")),
        )

    @property
    def cpe(self) -> Cpe:
        return parse_cpe(self.criteria)

    def matches(self, cpe: Cpe) -> bool:
        """True when this entry's product and version bounds contain `cpe`."""
        target = parse_cpe(self.criteria)
        if target.part != cpe.part or target.product_key != cpe.product_key:
            return False
        if not cpe.has_version:
            return False
        version = parse_version(cpe.version)
        if target.has_version and target.version != "*":
            return compare_versions(version, parse_version(target.version)) == 0
        return self._within(version)

    def _within(self, version: CpeVersion) -> bool:
        if self.version_start_including is not None:
            if compare_versions(version, parse_version(self.version_start_including)) < 0:
                return False
        if self.version_start_excluding is not None:
            if compare_versions(version, parse_version(self.version_start_excluding)) <= 0:
                return False
        if self.version_end_including is not None:
            if compare_versions(version, parse_version(self.version_end_including)) > 0:
                return False
        if self.version_end_excluding is not None:
            if compare_versions(version, parse_version(self.version_end_excluding)) >= 0:
                return False
        return True

    @property
    def exact(self) -> bool:
        """An exact-version criterion (`cpe:2.3:a:v:p:1.2.3` rather than a range or `*`)."""
        if any(
            bound is not None
            for bound in (
                self.version_start_including,
                self.version_start_excluding,
                self.version_end_including,
                self.version_end_excluding,
            )
        ):
            return False
        return self.cpe.has_version

    def range_text(self) -> str | None:
        """Human-readable bounds for the candidate row; None when the criterion is exact."""
        if self.exact:
            return None
        parts: list[str] = []
        if self.version_start_including is not None:
            parts.append(f">= {self.version_start_including}")
        if self.version_start_excluding is not None:
            parts.append(f"> {self.version_start_excluding}")
        if self.version_end_including is not None:
            parts.append(f"<= {self.version_end_including}")
        if self.version_end_excluding is not None:
            parts.append(f"< {self.version_end_excluding}")
        return ", ".join(parts) if parts else None


def _text(value: object) -> str | None:
    if value is None:
        return None
    return value if isinstance(value, str) and value.strip() else None
