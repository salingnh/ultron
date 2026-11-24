"""Seed targets of a campaign and the canonical key each seed has (C02/G5, M01).

`scope_snapshot.targets` keeps the request verbatim (it is a snapshot, not an
allowlist); `campaign_target` is one append-only row per seed and is the origin of
the provenance chain. The table's `canonical_key` is NULL exactly for seeds that
have no asset identity: `keyword` and `cidr` per the DDL comment, and any seed the
`aegis-norm/1` rules deliberately do not treat as an identity (a non-http(s) URL,
a URL with credentials, ...). Fabricating a key for those would mint an identity
the ingestion rules later quarantine.

The rules implemented here are the seed subset of `aegis-norm/1`
(`contracts/ingestion/normalization.v2.yaml`): domain, ip, url, email. They are a
service implementation, not the test reference: `contracts/tests/normalization.py`
is test-only by its own header, so the tests prove this implementation reproduces
the published golden vectors byte for byte (`tests/test_campaign_targets.py`).
The sensitive query-parameter lists are *data* of the contract and are loaded from
it, as normalization.v2.yaml requires ("import it from here instead of choosing
their own").
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import cache
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any, cast

import psycopg
import yaml

from aegis.common.repo import contract_path

from .ids import new_id

__all__ = [
    "NORM_VERSION",
    "SEED_ARRAY_KINDS",
    "SeedIdentityError",
    "SeedTarget",
    "insert_seeds",
    "seed_canonical_key",
    "seed_targets",
]

NORM_VERSION = "aegis-norm/1"

#: campaign-create target arrays -> campaign_target.kind.
SEED_ARRAY_KINDS: dict[str, str] = {
    "domains": "domain",
    "ips": "ip",
    "urls": "url",
    "emails": "email",
    "keywords": "keyword",
}

_MAX_KEY_LENGTH = 2048
_CONTROL = re.compile(r"[\x00-\x20\x7f]")
_LABEL = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?")
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_HEX = "0123456789ABCDEF"
_HTTP_URL = re.compile(
    r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://(?P<authority>[^/?#]*)(?P<path>/.*)?"
)


class SeedIdentityError(ValueError):
    """A raw seed that has no `aegis-norm/1` identity; `reason` is the published code."""

    def __init__(self, reason: str, message: str) -> None:
        self.reason = reason
        super().__init__(f"{reason}: {message}")


@dataclass(frozen=True, slots=True)
class SeedTarget:
    """One campaign_target row before it is written."""

    kind: str
    raw_value: str
    canonical_key: str | None


# --------------------------------------------------------------------------- contract data


@cache
def _query_identity() -> tuple[frozenset[str], tuple[str, ...], tuple[str, ...]]:
    """The sensitive query-parameter lists, read from the contract bundle (not copied)."""
    document = yaml.safe_load(
        contract_path("ingestion", "normalization.v2.yaml").read_text(encoding="utf-8")
    )
    if not isinstance(document, dict):
        raise RuntimeError("contracts/ingestion/normalization.v2.yaml must be a mapping")
    mapping = cast(dict[str, Any], document)
    try:
        exact = frozenset(str(value).lower() for value in mapping["sensitive_query_params"])
        suffixes = tuple(str(value).lower() for value in mapping["sensitive_query_param_suffixes"])
        prefixes = tuple(str(value).lower() for value in mapping["sensitive_query_param_prefixes"])
    except KeyError as error:
        raise RuntimeError(
            f"contracts/ingestion/normalization.v2.yaml has no {error.args[0]}"
        ) from error
    return exact, suffixes, prefixes


def _is_sensitive_param(name: str) -> bool:
    exact, suffixes, prefixes = _query_identity()
    folded = name.lower()
    if folded in exact or folded.startswith(prefixes):
        return True
    return any(folded.endswith(separator + suffix) for suffix in suffixes for separator in ".-_")


# --------------------------------------------------------------------------- helpers


def _percent_decode(text: str, reason: str) -> str:
    out = bytearray()
    index = 0
    while index < len(text):
        char = text[index]
        if char == "%":
            escape = text[index + 1 : index + 3]
            if len(escape) != 2 or any(char not in "0123456789abcdefABCDEF" for char in escape):
                raise SeedIdentityError(reason, f"malformed percent escape at offset {index}")
            out.append(int(escape, 16))
            index += 3
            continue
        try:
            out.extend(char.encode("utf-8"))
        except UnicodeEncodeError as error:
            raise SeedIdentityError(reason, f"not UTF-8 encodable: {error}") from error
        index += 1
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SeedIdentityError(reason, "percent escapes are not UTF-8") from error


def _percent_encode(text: str) -> str:
    out: list[str] = []
    for char in text:
        if char in _UNRESERVED:
            out.append(char)
            continue
        out.extend("%" + _HEX[byte >> 4] + _HEX[byte & 0xF] for byte in char.encode("utf-8"))
    return "".join(out)


def _percent_normalize(text: str) -> str:
    return _percent_encode(_percent_decode(text, "invalid_url_percent"))


def _canonical_ip(address: IPv4Address | IPv6Address) -> str:
    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return str(address)


def _domain(raw: str) -> str:
    if _CONTROL.search(raw) or any(char in raw for char in "/:@?#%\\"):
        raise SeedIdentityError("invalid_domain", f"not a bare hostname: {raw!r}")
    value = raw[:-1] if raw.endswith(".") else raw
    if not value:
        raise SeedIdentityError("invalid_domain", "empty name after the root dot")
    try:
        ip_address(value)
    except ValueError:
        pass
    else:
        raise SeedIdentityError("ip_as_domain", f"{raw!r} is an IP literal, not a domain")
    if all(label.isdigit() for label in value.split(".")):
        raise SeedIdentityError("invalid_domain", f"{raw!r} is an all-numeric name")
    try:
        name = value.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise SeedIdentityError("invalid_domain", str(error)) from error
    if len(name) > 253 or not all(_LABEL.fullmatch(label) for label in name.split(".")):
        raise SeedIdentityError("invalid_domain", f"not a usable domain name: {raw!r}")
    return name


def _ip(raw: str) -> str:
    if raw != raw.strip() or _CONTROL.search(raw):
        raise SeedIdentityError("invalid_ip", f"whitespace or control character in {raw!r}")
    if "%" in raw:
        raise SeedIdentityError("zone_id_not_identity", f"zone id in {raw!r}")
    if "/" in raw:
        raise SeedIdentityError("cidr_not_identity", f"{raw!r} is a network, not one asset")
    try:
        address = ip_address(raw)
    except ValueError as error:
        raise SeedIdentityError("invalid_ip", str(error)) from error
    return _canonical_ip(address)


def _port(raw: str) -> int:
    if not raw.isascii() or not raw.isdigit() or (len(raw) > 1 and raw[0] == "0"):
        raise SeedIdentityError(
            "invalid_port", f"port {raw!r} must be digits without a leading zero"
        )
    port = int(raw)
    if not 1 <= port <= 65535:
        raise SeedIdentityError("invalid_port", f"port {port} outside 1..65535")
    return port


def _remove_dot_segments(path: str) -> str:
    """RFC 3986 §5.2.4; never climbs above the root and keeps a trailing slash."""
    source, output = path, ""
    while source:
        if source.startswith("../"):
            source = source[3:]
        elif source.startswith("./"):
            source = source[2:]
        elif source.startswith("/./"):
            source = source[2:]
        elif source == "/.":
            source = "/"
        elif source.startswith("/../"):
            source = source[3:]
            output = output[: output.rfind("/")] if output.rfind("/") > 0 else ""
        elif source == "/..":
            source = "/"
            output = output[: output.rfind("/")] if output.rfind("/") > 0 else ""
        elif source in {".", ".."}:
            source = ""
        else:
            end = source.find("/", 1) if source.startswith("/") else source.find("/")
            if end < 0:
                output, source = output + source, ""
            else:
                output, source = output + source[:end], source[end:]
    return output


def _path(raw: str) -> str:
    encoded = "/".join(_percent_normalize(segment) for segment in raw.split("/"))
    return _remove_dot_segments(encoded)


def _http_parts(raw: str) -> dict[str, Any]:
    if _CONTROL.search(raw) or "\\" in raw:
        raise SeedIdentityError("invalid_url_char", f"unencoded space or backslash: {raw!r}")
    head, hashmark, fragment = raw.partition("#")
    if "#" in fragment:
        raise SeedIdentityError("invalid_url", f"more than one fragment delimiter: {raw!r}")
    pre, question, query = head.partition("?")
    match = _HTTP_URL.fullmatch(pre)
    if match is None:
        raise SeedIdentityError("invalid_url", f"not an absolute URL: {raw!r}")
    scheme = match["scheme"].lower()
    if scheme not in {"http", "https"}:
        raise SeedIdentityError("invalid_url_scheme", f"scheme {scheme!r} is not http/https")
    authority = match["authority"]
    if "@" in authority:
        raise SeedIdentityError("url_has_userinfo", "credentials in the authority are not identity")
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0:
            raise SeedIdentityError("invalid_url", f"unterminated IPv6 literal: {raw!r}")
        host, rest = authority[1:end], authority[end + 1 :]
        if rest and not rest.startswith(":"):
            raise SeedIdentityError("invalid_url", f"trailing junk after the host: {raw!r}")
        port = rest[1:] if rest else ""
    elif ":" in authority:
        host, _, port = authority.rpartition(":")
    else:
        host, port = authority, ""
    if not host:
        raise SeedIdentityError("invalid_url", f"empty host: {raw!r}")
    try:
        address = _canonical_ip(ip_address(host))
    except ValueError:
        try:
            address = _domain(host)
        except SeedIdentityError as error:
            raise SeedIdentityError("invalid_url", f"bad host {host!r}: {error}") from error
    number = _port(port) if port else (443 if scheme == "https" else 80)
    path = match["path"] or ""
    return {
        "scheme": scheme,
        "host": address,
        "port": number,
        "path": _path(path) if path else "/",
        "query": _query(query) if question else "",
        "fragment": fragment,
    }


def _query(raw: str) -> str:
    pairs: list[tuple[str, str]] = []
    for part in raw.split("&"):
        if not part:
            continue
        name, _, value = part.partition("=")
        decoded = _percent_decode(name, "invalid_url_percent")
        if not decoded or _is_sensitive_param(decoded):
            continue
        pairs.append((_percent_normalize(name), _percent_normalize(value)))
    pairs.sort()
    return "&".join(f"{name}={value}" for name, value in pairs)


def _url(raw: str) -> str:
    parts = _http_parts(raw)
    host = f"[{parts['host']}]" if ":" in parts["host"] else parts["host"]
    key = f"url:{parts['scheme']}://{host}:{parts['port']}{parts['path']}"
    if parts["query"]:
        key += "?" + parts["query"]
    return key


def _email(raw: str) -> str:
    if _CONTROL.search(raw) or raw != raw.strip():
        raise SeedIdentityError("invalid_email", f"whitespace or control character in {raw!r}")
    if raw.count("@") != 1:
        raise SeedIdentityError("invalid_email", f"expected exactly one @: {raw!r}")
    local, _, domain = raw.partition("@")
    if not local or len(local) > 64:
        raise SeedIdentityError("invalid_email", f"bad local part length: {raw!r}")
    if any(char in '(),:;<>[]"\\' for char in local):
        raise SeedIdentityError("invalid_email", f"bad character in the local part: {raw!r}")
    try:
        normalized = _domain(domain)
    except SeedIdentityError as error:
        raise SeedIdentityError("invalid_email", f"bad domain {domain!r}: {error}") from error
    return f"email:{local}@{normalized}"


_RULES = {
    "domain": lambda raw: f"dns:{_domain(raw)}",
    "ip": lambda raw: f"ip:{_ip(raw)}",
    "url": _url,
    "email": _email,
}


# --------------------------------------------------------------------------- seeds


def seed_canonical_key(kind: str, raw: str) -> str | None:
    """The seed's canonical key, or None when the seed has no identity under aegis-norm/1."""
    rule = _RULES.get(kind)
    if rule is None:
        # keyword, cidr, and any kind outside the seed subset: no asset identity by rule.
        return None
    try:
        key = rule(raw)
    except SeedIdentityError:
        return None
    return key if len(key) <= _MAX_KEY_LENGTH else None


def _kind_of(array: str, raw: str) -> str:
    if array == "ips":
        return "cidr" if "/" in raw else "ip"
    return SEED_ARRAY_KINDS[array]


def seed_targets(targets: Mapping[str, Sequence[str]]) -> list[SeedTarget]:
    """Flatten a campaign-create `targets` object into campaign_target rows."""
    rows: list[SeedTarget] = []
    for array in SEED_ARRAY_KINDS:
        for raw in targets.get(array) or ():
            row_kind = _kind_of(array, raw)
            rows.append(SeedTarget(row_kind, raw, seed_canonical_key(row_kind, raw)))
    return rows


def insert_seeds(
    connection: psycopg.Connection[Any],
    *,
    scope_id: str,
    targets: Mapping[str, Sequence[str]],
) -> list[SeedTarget]:
    """Write the seed rows of one scope snapshot; returns what was written."""
    rows = seed_targets(targets)
    with connection.cursor() as cursor:
        for row in rows:
            cursor.execute(
                """
                INSERT INTO aegis.campaign_target
                  (target_id, scope_id, kind, raw_value, canonical_key)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (new_id(), scope_id, row.kind, row.raw_value, row.canonical_key),
            )
    return rows
