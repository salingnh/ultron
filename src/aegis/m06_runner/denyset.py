"""Platform egress deny set and host-literal normalization (M06; R-5, OI-5, E-1).

The always-deny set is a platform constant, never provider data (S1.5a, 02-nen-tang §Sandbox).
`contracts/validation.py` holds the contract copy used by registry admission; this module is the
runtime copy used by the egress broker and by the ContainerSpec builder, and
`tests/test_denyset.py` fails if the runtime copy stops covering the contract one. The
standard-library only import surface is deliberate: the broker image ships this file alone.

`normalize_host()` gives IPv4 literals the semantics `inet_aton(3)` has, so `127.1`,
`2130706433`, `0x7f000001` and `017700000001` are recognised as the loopback address instead of
being treated as DNS names (review R-5).
"""

from __future__ import annotations

import ipaddress
import socket
from enum import StrEnum

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class DenyReason(StrEnum):
    """Stable wire reason codes; they are part of the audited decision."""

    METADATA = "DENY_METADATA"
    LOOPBACK = "DENY_LOOPBACK"
    LINK_LOCAL = "DENY_LINK_LOCAL"
    UNSPECIFIED = "DENY_UNSPECIFIED"
    MULTICAST = "DENY_MULTICAST"
    RESERVED = "DENY_RESERVED"
    EMBEDDED_V4 = "DENY_EMBEDDED_V4"


def _nets(*values: str) -> tuple[IPNetwork, ...]:
    return tuple(ipaddress.ip_network(value) for value in values)


# Cloud instance metadata: reachable only with a job's own credentials, never by a scanner. The
# addresses are tagged for a specific reason code; they are already inside the networks below.
METADATA_ADDRESSES = frozenset({"169.254.169.254", "100.100.100.200", "fd00:ec2::254"})

# Ordered: the first matching network decides the reason code. The set is exactly
# `contracts/validation.py::EGRESS_DENY_NETWORKS` (the registry side of the same platform constant);
# `tests/test_denyset.py` fails if the two ever differ (R-5).
DENY_NETWORKS: tuple[tuple[IPNetwork, DenyReason], ...] = (
    *((net, DenyReason.UNSPECIFIED) for net in _nets("0.0.0.0/8", "::/128")),
    *((net, DenyReason.LOOPBACK) for net in _nets("127.0.0.0/8", "::1/128")),
    *((net, DenyReason.LINK_LOCAL) for net in _nets("169.254.0.0/16", "fe80::/10")),
    *((net, DenyReason.MULTICAST) for net in _nets("224.0.0.0/4", "ff00::/8")),
    # Reserved, deprecated and IPv4-carrying IPv6 ranges: `::/96` is IPv4-compatible IPv6
    # (`::7f00:1`), `fec0::/10` deprecated site-local, the rest transport forms of an IPv4 address.
    *(
        (net, DenyReason.RESERVED)
        for net in _nets(
            "240.0.0.0/4", "100.100.100.200/32", "fec0::/10", "fd00:ec2::254/128", "::/96"
        )
    ),
    *(
        (net, DenyReason.EMBEDDED_V4)
        for net in _nets(
            "64:ff9b::/96",  # NAT64 well-known prefix
            "64:ff9b:1::/48",  # NAT64 local-use prefix
            "2002::/16",  # 6to4
            "2001::/32",  # Teredo
        )
    ),
)

DENY_HOSTS = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata",
        "metadata.google.internal",
        "instance-data",
        "kubernetes.default",
        "kubernetes.default.svc",
    }
)
DENY_SUFFIXES = (".localhost",)

MAPPED_V6 = ipaddress.ip_network("::ffff:0:0/96")

_V4_CHARS = frozenset("0123456789abcdefABCDEFxX.")


def _parse_ipv4_aton(text: str) -> ipaddress.IPv4Address | None:
    """An IPv4 literal with `inet_aton(3)` semantics (1-4 parts, octal/hex/plain)."""
    if not text or not set(text) <= _V4_CHARS:
        return None
    try:
        return ipaddress.IPv4Address(socket.inet_aton(text))
    except OSError:
        return None


def normalize_host(host: str) -> IPAddress | None:
    """The address `host` names literally, or None when it is a DNS name.

    IPv4 accepts the forms `getaddrinfo(3)` accepts through `inet_aton(3)`; IPv6 accepts the
    bracketed form a proxy request carries. A scope id (`fe80::1%eth0`) is returned as the
    address it names: the caller denies it as link-local.
    """
    value = (host or "").strip()
    if not value:
        return None
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    ipv4 = _parse_ipv4_aton(value)
    if ipv4 is not None:
        return ipv4
    scoped = value.split("%", 1)[0]
    try:
        return ipaddress.ip_address(scoped)
    except ValueError:
        return None


def host_key(host: str) -> str:
    """Comparison key of a host: a literal address in canonical form, else the lowercased name."""
    literal = normalize_host(host)
    if literal is not None:
        return str(literal)
    return (host or "").strip().lower().rstrip(".")


def deny_reason(address: IPAddress) -> DenyReason | None:
    """Why this address must never be connected to, or None when it may be."""
    if str(address) in METADATA_ADDRESSES:
        return DenyReason.METADATA
    if isinstance(address, ipaddress.IPv6Address):
        mapped = address.ipv4_mapped
        if mapped is not None:
            # IPv4-mapped IPv6 is the same destination as its embedded address: deny exactly what
            # the IPv4 rules deny and let the rest be judged by the same binding.
            return deny_reason(mapped)
    for net, reason in DENY_NETWORKS:
        if address.version == net.version and address in net:
            return reason
    return None


def denied_host(host: str) -> DenyReason | None:
    """Why the name/literal `host` is in the deny set itself, or None.

    Mirrors `contracts/validation.py::denied_egress_host` (plus literal normalization) so the
    runner and registry refuse the same declared source before any connection is attempted.
    """
    value = (host or "").strip().lower().rstrip(".")
    if not value:
        return DenyReason.RESERVED
    if value in DENY_HOSTS or value.endswith(DENY_SUFFIXES):
        return DenyReason.RESERVED
    literal = normalize_host(value)
    if literal is None:
        return None
    return deny_reason(literal)
