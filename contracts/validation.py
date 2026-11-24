"""Reference conformance checks required by this contract bundle.

Every schema consumer must enable these semantic formats, including generated
DTO validators. These functions validate values; M07 still owns normalization.
"""
from __future__ import annotations

import socket
from ipaddress import ip_address, ip_network
from pathlib import Path
import re
from urllib.parse import urlsplit

from jsonschema import FormatChecker
from openapi_spec_validator import OpenAPIV31SpecValidator


DOMAIN = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)


def domain_name(value: str) -> bool:
    return bool(DOMAIN.fullmatch(value))


def domain_seed(value: str) -> bool:
    try:
        # Preserve the original seed; validate the normalized IDNA candidate.
        candidate = value[:-1] if value.endswith(".") else value
        return domain_name(candidate.encode("idna").decode("ascii").lower())
    except UnicodeError:
        return False


def ip_literal(value: str, *, canonical: bool = False) -> bool:
    if "%" in value:  # interface-local scope IDs are not asset identities
        return False
    try:
        address = ip_address(value)
        return not canonical or str(address) == value
    except ValueError:
        return False


def ip_or_cidr(value: str) -> bool:
    if "/" not in value:
        return ip_literal(value)
    if "%" in value:
        return False
    try:
        address, prefix = value.rsplit("/", 1)
        if not prefix.isascii() or not prefix.isdigit():
            return False
        ip_address(address)
        ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def canonical_key(value: str) -> bool:
    kind, _, body = value.partition(":")
    if kind == "dns":
        return domain_name(body)
    if kind == "ip":
        return ip_literal(body, canonical=True)
    if kind == "service":
        address, _, transport = body.rpartition("/")
        host, _, port = address.rpartition(":")
        bracketed = host.startswith("[") and host.endswith("]")
        host = host[1:-1] if bracketed else host
        return (
            transport in {"tcp", "udp"}
            and ip_literal(host, canonical=True)
            and (":" in host) == bracketed
            and 1 <= len(port) <= 5 and port.isascii() and port.isdigit()
            and str(int(port)) == port and 1 <= int(port) <= 65535
        )
    if kind in {"app", "url"}:
        try:
            parsed = urlsplit(body)
            host = parsed.hostname or ""
            authority = f"[{host}]:{parsed.port}" if ":" in host else f"{host}:{parsed.port}"
            return (
                parsed.scheme in {"http", "https"}
                and parsed.username is None and parsed.password is None
                and parsed.port is not None and 1 <= parsed.port <= 65535
                and parsed.netloc == authority
                and not parsed.fragment
                and (ip_literal(host, canonical=True) or domain_name(host))
                and (kind == "url" or not parsed.path and not parsed.query)
            )
        except ValueError:
            return False
    # Other namespaces are checked by their schema branches.
    return True


# Platform egress deny set (C05/S1.5a, OI-5). This is a constant of the platform, never provider data:
# no manifest field can declare or widen it, the registry refuses an `egressSources` host that hits it,
# and the broker must apply the same list. IPv4 addresses embedded in IPv6 (mapped, NAT64, 6to4,
# Teredo) are rejected as their own networks, so a provider cannot smuggle `169.254.169.254` in that
# shape either. Runtime enforcement belongs to G1.3a; this is the reference list the contract checks
# and the registry share.
EGRESS_DENY_NETWORKS = tuple(ip_network(n) for n in (
    "0.0.0.0/8",       # unspecified / this-network
    "127.0.0.0/8",     # IPv4 loopback
    "169.254.0.0/16",  # IPv4 link-local / cloud metadata
    "224.0.0.0/4",     # IPv4 multicast
    "240.0.0.0/4",     # IPv4 reserved
    "100.100.100.200/32",  # Alibaba Cloud metadata (R-5)
    "::/128",          # IPv6 unspecified
    "::1/128",         # IPv6 loopback
    "::/96",           # IPv4-compatible IPv6 (::7f00:1, ::127.0.0.1) - R-5
    "fe80::/10",       # IPv6 link-local (fe80:: - febf::), named explicitly since S1 follow-up
    "fec0::/10",       # deprecated IPv6 site-local - R-5
    "fd00:ec2::254/128",   # AWS instance metadata over IPv6 - R-5
    "ff00::/8",        # IPv6 multicast
    "64:ff9b::/96",    # NAT64 well-known prefix
    "64:ff9b:1::/48",  # NAT64 local-use prefix
    "2002::/16",       # 6to4
    "2001::/32",       # Teredo
))
EGRESS_DENY_HOSTS = frozenset({
    "localhost", "localhost.localdomain", "metadata", "metadata.google.internal", "instance-data",
    "kubernetes.default", "kubernetes.default.svc",
})


def _host_literal(value: str) -> object | None:
    """The address a host names literally, with `inet_aton(3)` semantics for IPv4 (R-5).

    `getaddrinfo` reads `127.1`, `2130706433`, `0x7f000001` and `017700000001` as loopback, so a
    declared `egressSources` host must be judged the same way; a plain `ip_address()` call would
    treat them as DNS names and let them through registry admission.
    """
    text = value.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        return ip_address(text)
    except ValueError:
        pass
    try:
        return ip_address(socket.inet_aton(text))
    except OSError:
        return None


def denied_egress_host(host: str) -> bool:
    """True when an `egressSources` host is in the platform deny set and must never be connectable."""
    value = (host or "").strip().lower().rstrip(".")
    if not value:
        return True
    if value in EGRESS_DENY_HOSTS or value.endswith(".localhost"):
        return True
    address = _host_literal(value)
    if address is None:
        return False  # a DNS name: only the exact-name rules above apply; the broker pins its answers
    candidates = [address]
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        candidates.append(mapped)
    return any(candidate in network for candidate in candidates for network in EGRESS_DENY_NETWORKS)


def format_checker() -> FormatChecker:
    checker = FormatChecker()
    checks = {
        "aegis-canonical-key": canonical_key,
        "aegis-domain-target": lambda value: domain_name(value.removeprefix("dns:")),
        "aegis-domain-seed": domain_seed,
        "aegis-ip-address": ip_literal,
        "aegis-ip-or-cidr": ip_or_cidr,
    }
    for name, check in checks.items():
        def validate(value, check=check):
            return not isinstance(value, str) or check(value)
        checker.checks(name)(validate)
    return checker


def openapi_errors(document: dict, source: Path) -> list[str]:
    """Validate all OpenAPI3.1 objects; resolve local refs from the source URI."""
    return [
        f"/{'/'.join(map(str, error.path))}: {error.message}"
        for error in OpenAPIV31SpecValidator(
            document, base_uri=source.resolve().as_uri()
        ).iter_errors()
    ]
