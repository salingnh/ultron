"""Package identity shared by the artifact adapters (G2-D).

An OCI image scanned by three different tools must yield **one** package asset per installed
package, or the "same package+CVE from several providers -> one finding" rule cannot hold: M20's
finding fingerprint is built on the asset id, so Trivy's purl and Grype's purl for the same
`deb` package have to normalize to the same key. This module is that one rule.

What is kept (identity): purl type, namespace, name and the installed version. What is dropped
(scanner bookkeeping, not identity):

* **qualifiers** (`arch`, `distro`, `upstream`, `epoch`, ...): tools disagree (Trivy emits
  `arch`/`distro`, Syft adds `upstream=...`, Grype echoes its SBOM). Two purls that differ only in
  qualifiers are the same installed package.
* **subpath**: a location inside the package, not the package.
* URL-encoded segments stay encoded exactly as the tool wrote them; M07's normalizer re-encodes on
  ingest, so decoding here would produce a second, different key for the same bytes.

The version is the **purl's** version, with the Debian `epoch` qualifier folded back in
(`pkg:deb/debian/bsdutils@2.33.1-0.1?epoch=1` -> `1:2.33.1-0.1`), because that is the installed
identity Trivy, Syft and Grype all encode in the purl. Trivy's `Packages[].Version` field is *not*
that identity on several Debian packages (it is the upstream version, e.g. `6.1+20181013` for an
installed `6.1+20181013-2+deb10u2`), so using it would put a finding's `InstalledVersion` on a
different asset than the package it belongs to - the demo showed 258 findings quarantined as
`unknown_subject_asset` before this rule. A purl without a version is not identity
(`asset_package.version` is NOT NULL), so that record is skipped by the parser, never guessed.
"""

from __future__ import annotations

import re

__all__ = ["NO_VERSION", "normalize_package_purl", "purl_without_version"]


NO_VERSION = ""
#: `aegis-norm/1`'s purl rules, copied faithfully (the adapter may not import the core): the key
#: M27 stores is `normalize(normalize(key))`, so a parser that writes a `+` where the rule writes
#: `%2B` has its asset quarantined as `non_canonical_key`.
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_HEX = "0123456789ABCDEF"
_PURL_LOWERCASE = frozenset({"npm", "composer"})
_PURL_TYPE = re.compile(r"[a-z0-9.+-]+")


def _percent_decode(text: str) -> str:
    out = bytearray()
    index = 0
    while index < len(text):
        character = text[index]
        if character == "%":
            escape = text[index + 1 : index + 3]
            if len(escape) != 2 or any(char not in "0123456789abcdefABCDEF" for char in escape):
                raise ValueError(f"malformed percent escape at offset {index}")
            out.append(int(escape, 16))
            index += 3
            continue
        out.extend(character.encode("utf-8"))
        index += 1
    return out.decode("utf-8")


def _percent_encode(text: str) -> str:
    out: list[str] = []
    for character in text:
        if character in _UNRESERVED:
            out.append(character)
            continue
        out.extend("%" + _HEX[byte >> 4] + _HEX[byte & 0xF] for byte in character.encode("utf-8"))
    return "".join(out)


def _pypi_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _split(purl: str) -> tuple[str, str, str, str, str]:
    """`(type, namespace, name, version, epoch)` of a `pkg:` purl; other qualifiers/subpath gone."""
    body = purl[4:] if purl.lower().startswith("pkg:") else purl
    body, _, _subpath = body.partition("#")
    body, _, qualifiers = body.partition("?")
    version = ""
    at = body.rfind("@")
    if at > 0 and "/" not in body[at:]:
        body, version = body[:at], body[at + 1 :]
    segments = body.split("/")
    package_type = segments[0].lower()
    namespace = "/".join(segments[1:-1])
    name = segments[-1] if len(segments) > 1 else ""
    epoch = ""
    for item in filter(None, qualifiers.split("&")):
        key, _, value = item.partition("=")
        if key == "epoch":
            epoch = _percent_decode(value)
    return package_type, namespace, name, version, epoch


def normalize_package_purl(purl: str) -> str:
    """The canonical package purl of one installed package, or "" when it has no version."""
    package_type, namespace, name, version, epoch = _split(purl)
    if not package_type or not name or not _PURL_TYPE.fullmatch(package_type):
        return NO_VERSION
    if version and epoch and not version.startswith(epoch + ":"):
        version = f"{epoch}:{version}"
    chosen = version.strip()
    if not chosen or chosen != version:
        return NO_VERSION
    try:
        decoded_namespace = (
            [_percent_decode(segment) for segment in namespace.split("/")] if namespace else []
        )
        decoded_name = _percent_decode(name)
        decoded_version = _percent_decode(chosen)
    except ValueError, UnicodeDecodeError:
        return NO_VERSION
    if not decoded_name or any(not segment for segment in decoded_namespace):
        return NO_VERSION
    if package_type in _PURL_LOWERCASE:
        decoded_namespace = [segment.lower() for segment in decoded_namespace]
        decoded_name = decoded_name.lower()
    elif package_type == "pypi":
        decoded_name = _pypi_name(decoded_name)
    encoded_namespace = "/".join(_percent_encode(segment) for segment in decoded_namespace)
    head = (
        f"pkg:{package_type}/{encoded_namespace}/" if decoded_namespace else f"pkg:{package_type}/"
    )
    return f"{head}{_percent_encode(decoded_name)}@{_percent_encode(decoded_version)}"


def purl_without_version(purl: str) -> str:
    """The purl without its version (`pkg:deb/debian/adduser`), for fingerprint context only."""
    package_type, namespace, name, _version, _epoch = _split(purl)
    if not package_type or not name:
        return purl
    head = f"pkg:{package_type}/{namespace}/" if namespace else f"pkg:{package_type}/"
    return f"{head}{name}"
