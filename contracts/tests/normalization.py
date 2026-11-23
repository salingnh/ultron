#!/usr/bin/env python3
"""Reference implementation of `aegis-norm/1`, the rules that turn a raw observation into an asset id.

This module is a *conformance reference for tests only* (contracts/tests/): no service imports it.
The normative rules, the per-kind table and the sensitive query-parameter list live in
`contracts/ingestion/normalization.v2.yaml`; the golden vectors live in
`contracts/fixtures/golden/identity/normalization.vectors.json`. M07 may use any implementation
that reproduces these outputs byte for byte.

Normalization is a pure function of (version, kind, raw): the same raw value always yields the same
CanonicalKey, and a stored key normalizes back to itself (the golden suite asserts that fixed point),
so replaying a job or a result resolves to the asset row it already produced.
"""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address
import re
from typing import Callable

NORM_VERSION = "aegis-norm/1"
CANONICAL_KEY_MAX_LENGTH = 2048

#: Query parameters that never enter a URL identity (see rule `query_identity`).
SENSITIVE_QUERY_PARAMS = frozenset({
    "access_token", "access-token", "accesstoken", "api_key", "api-key", "apikey", "auth",
    "auth_token", "authorization", "awsaccesskeyid", "client_secret", "code", "credential",
    "credentials", "csrf", "csrf_token", "csrftoken", "expires", "id_token", "jwt", "key",
    "nonce", "oauth_token", "otp", "password", "passwd", "pwd", "sas", "secret", "session",
    "session_id", "sessionid", "sig", "signature", "state", "token",
})
SENSITIVE_QUERY_PARAM_SUFFIXES = (
    "credential", "credentials", "password", "passwd", "secret", "signature", "token",
)
SENSITIVE_QUERY_PARAM_PREFIXES = ("x-amz-", "x-goog-")

#: Stable reason codes for a quarantined record (contracts/ingestion/normalization.v2.yaml).
REASONS = frozenset({
    "empty_input", "kind_not_supported", "invalid_domain", "ip_as_domain", "invalid_ip",
    "cidr_not_identity", "zone_id_not_identity", "invalid_service", "invalid_port",
    "invalid_transport", "invalid_application", "invalid_url", "invalid_url_scheme",
    "invalid_url_char", "invalid_url_percent", "url_has_userinfo", "invalid_email",
    "invalid_purl", "package_version_required", "purl_duplicate_qualifier",
    "image_tag_not_identity", "invalid_digest", "invalid_repo", "mutable_ref_not_identity",
    "too_long",
})

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
            raise ValueError(f"unregistered reason {reason!r}")
        super().__init__(f"{reason}: {message}")
        self.reason = reason


@dataclass(frozen=True)
class Normalized:
    version: str
    kind: str
    canonical_key: str
    detail: dict | None


# --------------------------------------------------------------------------- helpers

def _percent_decode(text: str, reason: str) -> str:
    out = bytearray()
    i = 0
    while i < len(text):
        char = text[i]
        if char == "%":
            escape = text[i + 1:i + 3]
            if len(escape) != 2 or any(c not in "0123456789abcdefABCDEF" for c in escape):
                raise NormalizationError(reason, f"malformed percent escape at offset {i}")
            out.append(int(escape, 16))
            i += 3
            continue
        try:
            out.extend(char.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise NormalizationError(reason, f"not UTF-8 encodable: {exc}") from exc
        i += 1
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise NormalizationError(reason, "percent escapes are not UTF-8") from exc


def _percent_encode(text: str) -> str:
    out = []
    for char in text:
        if char in _UNRESERVED:
            out.append(char)
            continue
        for byte in char.encode("utf-8"):
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
    if _CONTROL.search(raw) or any(char in raw for char in "/:@?#%\\"):
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
        raise NormalizationError("invalid_domain", f"{raw!r} is an all-numeric name, likely a bad IP")
    try:
        name = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise NormalizationError("invalid_domain", str(exc)) from exc
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
    except ValueError as exc:
        raise NormalizationError("invalid_ip", str(exc)) from exc
    return _canonical_ip(address)


def _port(raw: str) -> int:
    if not raw.isascii() or not raw.isdigit() or (len(raw) > 1 and raw[0] == "0"):
        raise NormalizationError("invalid_port", f"port {raw!r} must be digits without a leading zero")
    port = int(raw)
    if not 1 <= port <= 65535:
        raise NormalizationError("invalid_port", f"port {port} outside 1..65535")
    return port


def _service(raw: str) -> tuple[str, dict]:
    match = re.fullmatch(
        r"(?:(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://)?"
        r"(?P<host>\[[^\[\]]+\]|[^:/\[\]]+):(?P<port>[^/:]*)"
        r"(?:/(?P<suffix>[A-Za-z]+))?",
        raw,
    )
    if match is None:
        raise NormalizationError("invalid_service", f"expected `<host>:<port>/<transport>`: {raw!r}")
    transports = {
        (value or "").lower()
        for value in (match["scheme"], match["suffix"])
        if value is not None
    }
    if len(transports) != 1 or not transports <= {"tcp", "udp"}:
        raise NormalizationError(
            "invalid_transport", f"transport must be one of tcp/udp and never contradictory: {raw!r}"
        )
    host = match["host"]
    address = _ip(host[1:-1] if host.startswith("[") else host)
    port = _port(match["port"])
    transport = transports.pop()
    host = f"[{address}]" if ":" in address else address
    detail = {"ip": address, "port": port, "transport": transport}
    return f"service:{host}:{port}/{transport}", detail


def _query(raw: str) -> str:
    pairs = []
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
            output = output[:output.rfind("/")] if output.rfind("/") > 0 else ""
        elif source == "/..":
            source = "/"
            output = output[:output.rfind("/")] if output.rfind("/") > 0 else ""
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


def _http_parts(raw: str) -> dict:
    if _CONTROL.search(raw) or "\\" in raw:
        raise NormalizationError("invalid_url_char", f"unencoded space, control character or backslash: {raw!r}")
    head, hashmark, fragment = raw.partition("#")
    if "#" in fragment:
        raise NormalizationError("invalid_url", f"more than one fragment delimiter: {raw!r}")
    pre, question, query = head.partition("?")
    match = re.fullmatch(r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://(?P<authority>[^/?#]*)(?P<path>/.*)?", pre)
    if match is None:
        raise NormalizationError("invalid_url", f"not an absolute URL: {raw!r}")
    scheme = match["scheme"].lower()
    if scheme not in {"http", "https"}:
        raise NormalizationError("invalid_url_scheme", f"scheme {scheme!r} is not http/https")
    authority = match["authority"]
    if "@" in authority:
        raise NormalizationError("url_has_userinfo", "credentials in the authority are not identity")
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0:
            raise NormalizationError("invalid_url", f"unterminated IPv6 literal: {raw!r}")
        host, rest = authority[1:end], authority[end + 1:]
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
        except NormalizationError as exc:
            raise NormalizationError("invalid_url", f"bad host {host!r}: {exc}") from exc
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


def _url(raw: str) -> tuple[str, dict]:
    parts = _http_parts(raw)
    host = f"[{parts['host']}]" if ":" in parts["host"] else parts["host"]
    key = f"url:{parts['scheme']}://{host}:{parts['port']}{parts['path']}"
    if parts["query"]:
        key += "?" + parts["query"]
    detail = {name: parts[name] for name in ("scheme", "host", "port", "path", "query")}
    return key, detail


def _application(raw: str) -> str:
    parts = _http_parts(raw)
    if parts["fragment"] or parts["query"] or parts["path"] not in {"", "/"}:
        raise NormalizationError(
            "invalid_application", f"an endpoint with a path or query belongs to kind url: {raw!r}"
        )
    host = f"[{parts['host']}]" if ":" in parts["host"] else parts["host"]
    return f"app:{parts['scheme']}://{host}:{parts['port']}"


def _email(raw: str) -> str:
    if _CONTROL.search(raw) or raw != raw.strip():
        raise NormalizationError("invalid_email", f"whitespace or control character in {raw!r}")
    if raw.count("@") != 1:
        raise NormalizationError("invalid_email", f"expected exactly one @: {raw!r}")
    local, _, domain = raw.partition("@")
    if not local or len(local) > 64:
        raise NormalizationError("invalid_email", f"bad local part length: {raw!r}")
    if any(char in '(),:;<>[]"\\' for char in local):
        raise NormalizationError("invalid_email", f"bad character in the local part: {raw!r}")
    try:
        normalized = _domain(domain)
    except NormalizationError as exc:
        raise NormalizationError("invalid_email", f"bad domain {domain!r}: {exc}") from exc
    return f"email:{local}@{normalized}"


def _pypi_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _package(raw: str) -> tuple[str, dict]:
    if _CONTROL.search(raw) or raw != raw.strip():
        raise NormalizationError("invalid_purl", f"whitespace or control character in {raw!r}")
    body = raw[4:] if raw.lower().startswith("pkg:") else raw
    body, hashmark, subpath = body.partition("#")
    if not body or "#" in subpath:
        raise NormalizationError("invalid_purl", f"bad purl: {raw!r}")
    body, question, qualifiers = body.partition("?")
    if "?" in qualifiers:
        raise NormalizationError("invalid_purl", f"more than one qualifier delimiter: {raw!r}")
    version = ""
    at = body.rfind("@")
    if at > 0 and "/" not in body[at:]:
        body, version = body[:at], body[at + 1:]
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
            raise NormalizationError("purl_duplicate_qualifier", f"duplicate qualifier {decoded_key!r}")
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
        purl += "#" + "/".join(_percent_encode(_percent_decode(s, "invalid_purl")) for s in subpath_segments)
    detail = {"purl": purl, "ecosystem": package_type, "name": name, "version": version}
    return "purl:" + purl, detail


def _digest(raw: str) -> str:
    if not raw or _CONTROL.search(raw) or raw != raw.strip():
        raise NormalizationError("invalid_digest", f"empty or padded digest: {raw!r}")
    if not raw.lower().startswith("sha256:"):
        raise NormalizationError("invalid_digest", f"only sha256 digests identify an asset: {raw!r}")
    value = raw[7:].lower()
    if not _HEX64.fullmatch(value):
        raise NormalizationError("invalid_digest", f"not 64 hex characters: {raw!r}")
    return value


def _oci_image(raw: str) -> str:
    repository, separator, digest = raw.rpartition("@")
    if separator:
        if not repository:
            raise NormalizationError("invalid_digest", f"empty repository before the digest: {raw!r}")
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
    if not value or any(char in value for char in "?#%\\"):
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
    except NormalizationError as exc:
        raise NormalizationError("invalid_repo", f"bad host {host!r}: {exc}") from exc
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
            raise NormalizationError("mutable_ref_not_identity", f"a snapshot needs a commit: {raw!r}")
        value, commit = raw[:at], raw[at + 1:]
    commit = commit.lower()
    if not _HEX40.fullmatch(commit):
        raise NormalizationError(
            "mutable_ref_not_identity", f"a branch, tag or short id cannot identify a snapshot: {raw!r}"
        )
    try:
        repository = _repo(value)
    except NormalizationError as exc:
        raise NormalizationError("invalid_repo", str(exc)) from exc
    return f"git:{repository}@{commit}"


def _artifact(raw: str) -> str:
    value = raw
    for separator in ("@", "#"):
        if separator in value:
            value = value.rpartition(separator)[2]
    return "artifact:sha256:" + _digest(value)


#: kind -> rule. Every entry matches `rules:` in contracts/ingestion/normalization.v2.yaml.
RULES: dict[str, Callable[[str], str | tuple[str, dict]]] = {
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
#: CanonicalKey namespace -> AssetKind (only kinds with a rule).
KEY_PREFIX_KINDS = {
    "dns": "domain", "ip": "ip", "service": "service", "app": "application", "url": "url",
    "email": "email", "purl": "package", "oci": "oci_image", "repo": "repo", "git": "repo_snapshot",
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


def renormalize_key(key: str) -> str:
    """Re-normalize a stored CanonicalKey; it must return the same key (identity is stable)."""
    prefix, _, body = key.partition(":")
    kind = KEY_PREFIX_KINDS.get(prefix)
    if kind is None:
        raise NormalizationError("kind_not_supported", f"unknown key prefix {prefix!r}")
    return canonical_key(kind, body)
