"""`aegis-norm/1` — the canonical identity rules M27 re-derives before it mints an asset row.

Normative registry: contracts/ingestion/normalization.v2.yaml (version `aegis-norm/1`, locked at
G0.3c). Golden vectors: contracts/fixtures/golden/identity/normalization.vectors.json. The
test-only reference implementation is contracts/tests/normalization.py; this module is the
service implementation of the same outputs.

The registry stays the single source for the parts that are data: the version id, the sensitive
query-parameter list (one list for the whole system: adapters, M07 and M27) and the stable reason
codes of a quarantined record. The per-kind rules are code; a rules change is `aegis-norm/2`, never
an edit here.

M27 never rewrites an adapter key. It re-normalizes the stored `canonical_key` and quarantines the
record when the key does not come back unchanged (`non_canonical_key`) or when the declared
`Asset.kind` disagrees with the key prefix (`canonical_key_kind_mismatch`). Those two reasons are
M27 gate reasons, not normalization-rule reasons, so they are not in the registry's
`rejected_reasons` list.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from functools import cache
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any, cast

import yaml

from aegis.common.repo import contract_path

__all__ = [
    "ASSET_KIND_MISMATCH",
    "CANONICAL_KEY_MAX_LENGTH",
    "KEY_PREFIX_KINDS",
    "NON_CANONICAL_KEY",
    "NORM_VERSION",
    "REASONS",
    "SENSITIVE_QUERY_PARAM_PREFIXES",
    "SENSITIVE_QUERY_PARAM_SUFFIXES",
    "SENSITIVE_QUERY_PARAMS",
    "KeyRejection",
    "NormalizationError",
    "Normalized",
    "canonical_key",
    "is_sensitive_param",
    "kind_of_key",
    "normalize",
    "validate_key",
]

NORM_VERSION = "aegis-norm/1"
CANONICAL_KEY_MAX_LENGTH = 2048

#: M27 gate reasons for a stored key that the rules do not reproduce (not registry reasons).
NON_CANONICAL_KEY = "non_canonical_key"
ASSET_KIND_MISMATCH = "canonical_key_kind_mismatch"


@cache
def _registry() -> dict[str, Any]:
    document = yaml.safe_load(
        contract_path("ingestion/normalization.v2.yaml").read_text(encoding="utf-8")
    )
    if not isinstance(document, dict):
        raise RuntimeError("contracts/ingestion/normalization.v2.yaml must be a mapping")
    if document.get("version") != NORM_VERSION:
        # Claiming one version while applying another version's rules would silently mint keys
        # that are not comparable. A rules bump is a code change plus a new version id.
        raise RuntimeError(
            f"normalization registry is {document.get('version')!r}, this implementation is "
            f"{NORM_VERSION!r}"
        )
    return cast(dict[str, Any], document)


def _string_sequence(key: str) -> tuple[str, ...]:
    value = _registry().get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise RuntimeError(f"normalization registry: {key} must be a list of strings")
    return tuple(value)


#: Query parameters that never enter a URL identity (rule `query_identity`).
SENSITIVE_QUERY_PARAMS = frozenset(_string_sequence("sensitive_query_params"))
SENSITIVE_QUERY_PARAM_SUFFIXES = _string_sequence("sensitive_query_param_suffixes")
SENSITIVE_QUERY_PARAM_PREFIXES = _string_sequence("sensitive_query_param_prefixes")

#: Stable reason codes of a quarantined record (`rejected_reasons` in the registry).
REASONS = frozenset(str(reason) for reason in cast(dict[str, Any], _registry()["rejected_reasons"]))

_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_HEX = "0123456789ABCDEF"
_CONTROL = re.compile(r"[\x00-\x20\x7f]")
_LABEL = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?")
_PURL_TYPE = re.compile(r"[a-z0-9.+-]+")
_PURL_QUALIFIER_KEY = re.compile(r"[a-z0-9._-]+")
_HEX40 = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_CASE_INSENSITIVE_HOSTS = frozenset({"github.com", "gitlab.com", "bitbucket.org"})
_DEFAULT_SCHEME_PORTS = {"http": "80", "https": "443", "ssh": "22", "git": "9418"}
_PURL_LOWERCASE = frozenset({"npm", "composer"})
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*")


class NormalizationError(ValueError):
    """A raw value that must be quarantined instead of given a made-up identity."""

    def __init__(self, reason: str, message: str):
        if reason not in REASONS:
            raise ValueError(f"unregistered normalization reason {reason!r}")
        super().__init__(f"{reason}: {message}")
        self.reason = reason


class KeyRejection(ValueError):
    """A stored canonical_key that the rules do not reproduce byte for byte (M27 gate reason)."""

    def __init__(self, reason: str, message: str):
        super().__init__(f"{reason}: {message}")
        self.reason = reason


@dataclass(frozen=True, slots=True)
class Normalized:
    """One identity: the rules version, kind, canonical key and the per-kind detail row values."""

    version: str
    kind: str
    canonical_key: str
    detail: dict[str, object] | None


# --------------------------------------------------------------------------- helpers


def _percent_decode(text: str, reason: str) -> str:
    out = bytearray()
    index = 0
    while index < len(text):
        character = text[index]
        if character == "%":
            escape = text[index + 1 : index + 3]
            if len(escape) != 2 or any(
                character not in "0123456789abcdefABCDEF" for character in escape
            ):
                raise NormalizationError(reason, f"malformed percent escape at offset {index}")
            out.append(int(escape, 16))
            index += 3
            continue
        try:
            out.extend(character.encode("utf-8"))
        except UnicodeEncodeError as error:
            raise NormalizationError(reason, f"not UTF-8 encodable: {error}") from error
        index += 1
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError as error:
        raise NormalizationError(reason, "percent escapes are not UTF-8") from error


def _percent_encode(text: str) -> str:
    out = []
    for character in text:
        if character in _UNRESERVED:
            out.append(character)
            continue
        for byte in character.encode("utf-8"):
            out.append("%" + _HEX[byte >> 4] + _HEX[byte & 0xF])
    return "".join(out)


def _percent_normalize(text: str, reason: str = "invalid_url_percent") -> str:
    return _percent_encode(_percent_decode(text, reason))


def is_sensitive_param(name: str) -> bool:
    """True when a query parameter name must not enter a URL identity (rule `query_identity`)."""
    folded = name.lower()
    if folded in SENSITIVE_QUERY_PARAMS or folded.startswith(SENSITIVE_QUERY_PARAM_PREFIXES):
        return True
    return any(
        folded.endswith(separator + suffix)
        for suffix in SENSITIVE_QUERY_PARAM_SUFFIXES
        for separator in ".-_"
    )


def _canonical_ip(address: IPv4Address | IPv6Address) -> str:
    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return str(address)


# --------------------------------------------------------------------------- rules


def _domain(raw: str) -> str:
    if _CONTROL.search(raw) or any(character in raw for character in "/:@?#%\\"):
        raise NormalizationError("invalid_domain", f"not a bare hostname: {raw!r}")
    value = raw[:-1] if raw.endswith(".") else raw
    if not value:
        raise NormalizationError("invalid_domain", "empty name after the root dot")
    try:
        ip_address(value)
    except ValueError:
        pass
    else:
        raise NormalizationError("ip_as_domain", f"{raw!r} is an IP literal, not a domain")
    if all(label.isdigit() for label in value.split(".")):
        raise NormalizationError(
            "invalid_domain", f"{raw!r} is an all-numeric name, likely a bad IP"
        )
    try:
        name = value.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise NormalizationError("invalid_domain", str(error)) from error
    if len(name) > 253 or not all(_LABEL.fullmatch(label) for label in name.split(".")):
        raise NormalizationError("invalid_domain", f"not a usable domain name: {raw!r}")
    return name


def _ip(raw: str) -> str:
    if raw != raw.strip() or _CONTROL.search(raw):
        raise NormalizationError("invalid_ip", f"whitespace or control character in {raw!r}")
    if "%" in raw:
        raise NormalizationError("zone_id_not_identity", f"zone id in {raw!r}")
    if "/" in raw:
        raise NormalizationError("cidr_not_identity", f"{raw!r} is a network, not one asset")
    try:
        address = ip_address(raw)
    except ValueError as error:
        raise NormalizationError("invalid_ip", str(error)) from error
    return _canonical_ip(address)


def _port(raw: str) -> int:
    if not raw.isascii() or not raw.isdigit() or (len(raw) > 1 and raw[0] == "0"):
        raise NormalizationError(
            "invalid_port", f"port {raw!r} must be digits without a leading zero"
        )
    port = int(raw)
    if not 1 <= port <= 65535:
        raise NormalizationError("invalid_port", f"port {port} outside 1..65535")
    return port


def _service(raw: str) -> tuple[str, dict[str, object]]:
    match = re.fullmatch(
        r"(?:(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://)?"
        r"(?P<host>\[[^\[\]]+\]|[^:/\[\]]+):(?P<port>[^/:]*)"
        r"(?:/(?P<suffix>[A-Za-z]+))?",
        raw,
    )
    if match is None:
        raise NormalizationError(
            "invalid_service", f"expected `<host>:<port>/<transport>`: {raw!r}"
        )
    transports = {
        (value or "").lower() for value in (match["scheme"], match["suffix"]) if value is not None
    }
    if len(transports) != 1 or not transports <= {"tcp", "udp"}:
        raise NormalizationError(
            "invalid_transport",
            f"transport must be one of tcp/udp and never contradictory: {raw!r}",
        )
    host = match["host"]
    address = _ip(host[1:-1] if host.startswith("[") else host)
    port = _port(match["port"])
    transport = transports.pop()
    host = f"[{address}]" if ":" in address else address
    detail: dict[str, object] = {"ip": address, "port": port, "transport": transport}
    return f"service:{host}:{port}/{transport}", detail


def _query(raw: str) -> str:
    pairs: list[tuple[str, str]] = []
    for part in raw.split("&"):
        if not part:
            continue
        name, _, value = part.partition("=")
        decoded = _percent_decode(name, "invalid_url_percent")
        if not decoded or is_sensitive_param(decoded):
            continue
        pairs.append((_percent_normalize(name), _percent_normalize(value)))
    pairs.sort()
    return "&".join(f"{name}={value}" for name, value in pairs)


def _remove_dot_segments(path: str) -> str:
    """RFC 3986 §5.2.4; never climbs above the root and keeps a trailing slash it is entitled to."""
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
    # Encode each segment before removing dot segments: `%2E` (unreserved) becomes `.`, so an
    # escaped traversal is canonicalized too, while `%2F` stays content and never splits a segment.
    encoded = "/".join(_percent_normalize(segment) for segment in raw.split("/"))
    return _remove_dot_segments(encoded)


def _http_parts(raw: str) -> dict[str, object]:
    if _CONTROL.search(raw) or "\\" in raw:
        raise NormalizationError(
            "invalid_url_char", f"unencoded space, control character or backslash: {raw!r}"
        )
    head, _, fragment = raw.partition("#")
    if "#" in fragment:
        raise NormalizationError("invalid_url", f"more than one fragment delimiter: {raw!r}")
    pre, question, query = head.partition("?")
    match = re.fullmatch(
        r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://(?P<authority>[^/?#]*)(?P<path>/.*)?", pre
    )
    if match is None:
        raise NormalizationError("invalid_url", f"not an absolute URL: {raw!r}")
    scheme = match["scheme"].lower()
    if scheme not in {"http", "https"}:
        raise NormalizationError("invalid_url_scheme", f"scheme {scheme!r} is not http/https")
    authority = match["authority"]
    if "@" in authority:
        raise NormalizationError(
            "url_has_userinfo", "credentials in the authority are not identity"
        )
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0:
            raise NormalizationError("invalid_url", f"unterminated IPv6 literal: {raw!r}")
        host, rest = authority[1:end], authority[end + 1 :]
        if rest and not rest.startswith(":"):
            raise NormalizationError("invalid_url", f"trailing junk after the host: {raw!r}")
        port = rest[1:] if rest else ""
    elif ":" in authority:
        host, _, port = authority.rpartition(":")
    else:
        host, port = authority, ""
    if not host:
        raise NormalizationError("invalid_url", f"empty host: {raw!r}")
    try:
        address = _canonical_ip(ip_address(host))
    except ValueError:
        try:
            address = _domain(host)
        except NormalizationError as error:
            raise NormalizationError("invalid_url", f"bad host {host!r}: {error}") from error
    if port:
        number = _port(port)
    else:
        number = 443 if scheme == "https" else 80
    path = match["path"] or ""
    return {
        "scheme": scheme,
        "host": address,
        "port": number,
        "path": _path(path) if path else "/",
        "query": _query(query) if question else "",
        "fragment": fragment,
    }


def _url(raw: str) -> tuple[str, dict[str, object]]:
    parts = _http_parts(raw)
    host = f"[{parts['host']}]" if ":" in cast(str, parts["host"]) else cast(str, parts["host"])
    key = f"url:{parts['scheme']}://{host}:{parts['port']}{parts['path']}"
    if parts["query"]:
        key += "?" + cast(str, parts["query"])
    detail = {name: parts[name] for name in ("scheme", "host", "port", "path", "query")}
    return key, detail


def _application(raw: str) -> str:
    parts = _http_parts(raw)
    if parts["fragment"] or parts["query"] or parts["path"] not in {"", "/"}:
        raise NormalizationError(
            "invalid_application", f"an endpoint with a path or query belongs to kind url: {raw!r}"
        )
    host = f"[{parts['host']}]" if ":" in cast(str, parts["host"]) else cast(str, parts["host"])
    return f"app:{parts['scheme']}://{host}:{parts['port']}"


def _email(raw: str) -> str:
    if _CONTROL.search(raw) or raw != raw.strip():
        raise NormalizationError("invalid_email", f"whitespace or control character in {raw!r}")
    if raw.count("@") != 1:
        raise NormalizationError("invalid_email", f"expected exactly one @: {raw!r}")
    local, _, domain = raw.partition("@")
    if not local or len(local) > 64:
        raise NormalizationError("invalid_email", f"bad local part length: {raw!r}")
    if any(character in '(),:;<>[]"\\' for character in local):
        raise NormalizationError("invalid_email", f"bad character in the local part: {raw!r}")
    try:
        normalized = _domain(domain)
    except NormalizationError as error:
        raise NormalizationError("invalid_email", f"bad domain {domain!r}: {error}") from error
    return f"email:{local}@{normalized}"


def _pypi_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _package(raw: str) -> tuple[str, dict[str, object]]:
    if _CONTROL.search(raw) or raw != raw.strip():
        raise NormalizationError("invalid_purl", f"whitespace or control character in {raw!r}")
    body = raw[4:] if raw.lower().startswith("pkg:") else raw
    body, _, subpath = body.partition("#")
    if not body or "#" in subpath:
        raise NormalizationError("invalid_purl", f"bad purl: {raw!r}")
    body, _, qualifiers = body.partition("?")
    if "?" in qualifiers:
        raise NormalizationError("invalid_purl", f"more than one qualifier delimiter: {raw!r}")
    version = ""
    at = body.rfind("@")
    if at > 0 and "/" not in body[at:]:
        body, version = body[:at], body[at + 1 :]
    segments = body.split("/")
    if len(segments) < 2:
        raise NormalizationError("invalid_purl", f"purl needs a type and a name: {raw!r}")
    package_type = _percent_decode(segments[0], "invalid_purl").lower()
    if not _PURL_TYPE.fullmatch(package_type):
        raise NormalizationError("invalid_purl", f"bad purl type {package_type!r}")
    decoded = [_percent_decode(segment, "invalid_purl") for segment in segments[1:]]
    if any(not segment for segment in decoded):
        raise NormalizationError("invalid_purl", f"empty purl component: {raw!r}")
    namespace, name = decoded[:-1], decoded[-1]
    if package_type in _PURL_LOWERCASE:
        namespace = [segment.lower() for segment in namespace]
        name = name.lower()
    elif package_type == "pypi":
        name = _pypi_name(name)
    version = _percent_decode(version, "invalid_purl")
    if not version:
        raise NormalizationError(
            "package_version_required", f"asset_package.version is NOT NULL, so {raw!r} has no row"
        )
    qualifier_pairs: dict[str, str] = {}
    for item in filter(None, qualifiers.split("&")):
        key, _, value = item.partition("=")
        decoded_key = _percent_decode(key, "invalid_purl").lower()
        if not _PURL_QUALIFIER_KEY.fullmatch(decoded_key):
            raise NormalizationError("invalid_purl", f"bad qualifier key {key!r}")
        if decoded_key in qualifier_pairs:
            raise NormalizationError(
                "purl_duplicate_qualifier", f"duplicate qualifier {decoded_key!r}"
            )
        qualifier_pairs[decoded_key] = _percent_decode(value, "invalid_purl")
    purl = f"pkg:{package_type}/"
    purl += "/".join(_percent_encode(segment) for segment in namespace)
    purl += ("/" if namespace else "") + _percent_encode(name)
    purl += "@" + _percent_encode(version)
    if qualifier_pairs:
        purl += "?" + "&".join(
            f"{key}={_percent_encode(qualifier_pairs[key])}" for key in sorted(qualifier_pairs)
        )
    subpath_segments = [segment for segment in subpath.split("/") if segment]
    if subpath_segments:
        purl += "#" + "/".join(
            _percent_encode(_percent_decode(segment, "invalid_purl"))
            for segment in subpath_segments
        )
    detail: dict[str, object] = {
        "purl": purl,
        "ecosystem": package_type,
        "name": name,
        "version": version,
    }
    return "purl:" + purl, detail


def _digest(raw: str) -> str:
    if not raw or _CONTROL.search(raw) or raw != raw.strip():
        raise NormalizationError("invalid_digest", f"empty or padded digest: {raw!r}")
    if not raw.lower().startswith("sha256:"):
        raise NormalizationError(
            "invalid_digest", f"only sha256 digests identify an asset: {raw!r}"
        )
    value = raw[7:].lower()
    if not _HEX64.fullmatch(value):
        raise NormalizationError("invalid_digest", f"not 64 hex characters: {raw!r}")
    return value


def _oci_image(raw: str) -> str:
    repository, separator, digest = raw.rpartition("@")
    if separator:
        if not repository:
            raise NormalizationError(
                "invalid_digest", f"empty repository before the digest: {raw!r}"
            )
    else:
        digest = raw
        if not digest.lower().startswith("sha256:"):
            raise NormalizationError(
                "image_tag_not_identity", f"a tag or repository alone is mutable: {raw!r}"
            )
    return "oci:sha256:" + _digest(digest)


def _repo(raw: str) -> str:
    if _CONTROL.search(raw) or raw != raw.strip():
        raise NormalizationError("invalid_repo", f"whitespace or control character in {raw!r}")
    value = raw
    scheme = ""
    if "#" in value:
        raise NormalizationError(
            "mutable_ref_not_identity", f"a ref is not part of the repository identity: {raw!r}"
        )
    if "://" in value:
        scheme, _, value = value.partition("://")
        scheme = scheme.lower()
        if not _SCHEME.fullmatch(scheme):
            raise NormalizationError("invalid_repo", f"bad scheme in {raw!r}")
        netloc, _, tail = value.partition("/")
        if "@" in netloc:
            netloc = netloc.rpartition("@")[2]
        value = netloc + "/" + tail if tail else netloc
    else:
        head, _, tail = value.partition(":")
        if head and tail and "/" not in head and "@" in head:  # scp form user@host:path
            value = head.rpartition("@")[2] + "/" + tail
    if value.lower().endswith(".git"):
        value = value[:-4]
    value = value.rstrip("/")
    if "@" in value:
        raise NormalizationError(
            "mutable_ref_not_identity", f"a ref is not part of the repository identity: {raw!r}"
        )
    if not value or any(character in value for character in "?#%\\"):
        raise NormalizationError("invalid_repo", f"not a repository reference: {raw!r}")
    host, _, path = value.partition("/")
    host = host.lower().removeprefix("www.")
    port = ""
    if ":" in host:
        host, _, port = host.rpartition(":")
        if not port.isascii() or not port.isdigit() or (len(port) > 1 and port[0] == "0"):
            raise NormalizationError(
                "invalid_repo",
                f"a bare `host:port` is ambiguous with the scp form; add a scheme: {raw!r}",
            )
        if not 1 <= int(port) <= 65535:
            raise NormalizationError("invalid_repo", f"port {port} outside 1..65535")
        if port == _DEFAULT_SCHEME_PORTS.get(scheme):
            port = ""
    try:
        host = _domain(host)
    except NormalizationError as error:
        raise NormalizationError("invalid_repo", f"bad host {host!r}: {error}") from error
    segments = path.split("/")
    if len(segments) < 2 or any(segment in {"", ".", ".."} for segment in segments):
        raise NormalizationError("invalid_repo", f"expected `<host>/<owner>/<name>`: {raw!r}")
    if host in _CASE_INSENSITIVE_HOSTS:
        segments = [segment.lower() for segment in segments]
    authority = f"{host}:{port}" if port else host
    return f"{authority}/{'/'.join(segments)}"


def _repo_snapshot(raw: str) -> str:
    if "#" in raw:
        value, _, commit = raw.partition("#")
        if "#" in commit or "/" in commit:
            raise NormalizationError("mutable_ref_not_identity", f"not a commit id: {raw!r}")
    else:
        at = raw.rfind("@")
        if at <= 0:
            raise NormalizationError(
                "mutable_ref_not_identity", f"a snapshot needs a commit: {raw!r}"
            )
        value, commit = raw[:at], raw[at + 1 :]
    commit = commit.lower()
    if not _HEX40.fullmatch(commit):
        raise NormalizationError(
            "mutable_ref_not_identity",
            f"a branch, tag or short id cannot identify a snapshot: {raw!r}",
        )
    try:
        repository = _repo(value)
    except NormalizationError as error:
        raise NormalizationError("invalid_repo", str(error)) from error
    return f"git:{repository}@{commit}"


def _artifact(raw: str) -> str:
    value = raw
    for separator in ("@", "#"):
        if separator in value:
            value = value.rpartition(separator)[2]
    return "artifact:sha256:" + _digest(value)


Rule = Callable[[str], "str | tuple[str, dict[str, object]]"]

#: kind -> rule. Every entry matches `rules:` in contracts/ingestion/normalization.v2.yaml.
RULES: dict[str, Rule] = {
    "domain": lambda raw: f"dns:{_domain(raw)}",
    "ip": lambda raw: f"ip:{_ip(raw)}",
    "service": _service,
    "application": _application,
    "url": _url,
    "email": _email,
    "package": _package,
    "oci_image": _oci_image,
    "repo": lambda raw: f"repo:{_repo(raw)}",
    "repo_snapshot": _repo_snapshot,
    "artifact": _artifact,
}

#: CanonicalKey namespace -> AssetKind (only kinds with an aegis-norm/1 rule).
KEY_PREFIX_KINDS: dict[str, str] = {
    "dns": "domain",
    "ip": "ip",
    "service": "service",
    "app": "application",
    "url": "url",
    "email": "email",
    "purl": "package",
    "oci": "oci_image",
    "repo": "repo",
    "git": "repo_snapshot",
    "artifact": "artifact",
}


def normalize(kind: str, raw: str) -> Normalized:
    """Return the identity of `raw` declared as `kind`, or raise NormalizationError."""
    if not isinstance(raw, str) or not raw or not raw.strip():
        raise NormalizationError("empty_input", "empty input has no identity")
    rule = RULES.get(kind)
    if rule is None:
        raise NormalizationError(
            "kind_not_supported", f"no aegis-norm/1 rule for kind {kind!r}; quarantine the record"
        )
    produced = rule(raw)
    canonical_key, detail = produced if isinstance(produced, tuple) else (produced, None)
    if len(canonical_key) > CANONICAL_KEY_MAX_LENGTH:
        raise NormalizationError(
            "too_long", f"{len(canonical_key)} characters exceeds the schema maxLength"
        )
    return Normalized(NORM_VERSION, kind, canonical_key, detail)


def canonical_key(kind: str, raw: str) -> str:
    return normalize(kind, raw).canonical_key


def kind_of_key(key: str) -> str:
    """The AssetKind a stored key's namespace belongs to, or NormalizationError."""
    prefix, _, _ = key.partition(":")
    kind = KEY_PREFIX_KINDS.get(prefix)
    if kind is None:
        raise NormalizationError("kind_not_supported", f"unknown key prefix {prefix!r}")
    return kind


def validate_key(key: str, declared_kind: str | None = None) -> Normalized:
    """Re-derive `key` with aegis-norm/1; raise KeyRejection unless it reproduces it unchanged."""
    body = key.partition(":")[2]
    normalized = normalize(kind_of_key(key), body)
    if declared_kind is not None and declared_kind != normalized.kind:
        raise KeyRejection(
            ASSET_KIND_MISMATCH,
            f"kind {declared_kind!r} does not match key namespace {normalized.kind!r}: {key!r}",
        )
    if normalized.canonical_key != key:
        raise KeyRejection(
            NON_CANONICAL_KEY,
            f"stored key {key!r} re-normalizes to {normalized.canonical_key!r}; never rewritten",
        )
    return normalized
