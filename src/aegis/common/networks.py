"""Address ranges the internet profile always denies (R4, item #61).

A campaign's RoE can name a *seed* CIDR the owner is authorized to assess; every other private
address is not reachable from an internet job, whatever an operator-supplied `target_denylist`
says and whatever a discovered name happens to resolve to. The list is a platform constant (the
same role `contracts/validation.py::EGRESS_DENY_NETWORKS` has for the always-deny set), shared by
M05 (which refuses to sign a private target outside an authorized private seed) and M06 (which
builds the broker/DNS/L3 deny rules), so the two sides cannot drift.

Link-local is not here: it is already in the always-deny set (`denyset.py::LINK_LOCAL`) and no
authorization can lift it.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence

__all__ = ["PRIVATE", "PRIVATE_NETWORKS", "is_private", "subnet_inside"]

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Network = ipaddress.IPv4Network | ipaddress.IPv6Network

#: RFC 1918, CGNAT (RFC 6598) and ULA (RFC 4193). Ordered for stable audit output.
PRIVATE_NETWORKS: tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "fc00::/7",
)

PRIVATE: tuple[Network, ...] = tuple(ipaddress.ip_network(entry) for entry in PRIVATE_NETWORKS)


def is_private(address: IPAddress) -> bool:
    """True when the address is inside one of the always-denied private ranges."""
    return any(address.version == network.version and address in network for network in PRIVATE)


def subnet_inside(network: Network, parents: Sequence[Network]) -> bool:
    """True when `network` is completely inside one of `parents` (same address family).

    `ipaddress` types `subnet_of` as family-specific; a call site that mixes an IPv4 and an IPv6
    parent must neither raise nor guess, so the family is compared once here.
    """
    for parent in parents:
        if isinstance(network, ipaddress.IPv4Network) and isinstance(parent, ipaddress.IPv4Network):
            if network.subnet_of(parent):
                return True
        elif isinstance(network, ipaddress.IPv6Network) and isinstance(
            parent, ipaddress.IPv6Network
        ):
            if network.subnet_of(parent):
                return True
    return False
