"""Egress policy for one sandbox job (spike G0.2).

Pure, stdlib-only policy engine used by the egress broker and by unit tests.
It answers one question: may this job open a TCP connection to ``host:port``,
and if yes, to exactly which resolved address?

Design rules (see docs/living/dac-ta-ky-thuat/02-nen-tang.md §Sandbox):

* Everything is denied unless it is bound to the job: an address must be in a
  job target (``target_ips``) or in a resolved host of a provider source that
  the manifest declared (``sources``).
* Some addresses are denied even when a name resolves to them (loopback,
  link-local/metadata, multicast, unspecified, mapped/NAT64/6to4 forms of the
  same, platform control/data CIDRs, campaign target denylist).
* Resolution happens in the control plane; every address of the answer is
  checked and the connection is pinned to the checked address. A name that
  resolves to a denied address is denied as a whole (fail closed), otherwise a
  DNS-rebinding answer could smuggle a denied address past the check.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Sequence

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# Wire reason codes are part of the audited decision; keep them stable.
ALWAYS_DENY_V4: tuple[IPNetwork, ...] = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",  # "this network"; also blocks 0.0.0.0
        "127.0.0.0/8",  # loopback
        "169.254.0.0/16",  # link-local incl. 169.254.169.254 metadata
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved + 255.255.255.255 broadcast
    )
)

ALWAYS_DENY_V6: tuple[IPNetwork, ...] = tuple(
    ipaddress.ip_network(n)
    for n in (
        "::/128",  # unspecified
        "::1/128",  # loopback
        "fe80::/10",  # link-local
        "fec0::/10",  # deprecated site-local
        "ff00::/8",  # multicast
        "2001:db8::/32",  # documentation
        "fd00:ec2::254/128",  # cloud metadata over IPv6 (AWS-style)
    )
)

# IPv6 forms that embed an IPv4 address; the embedded address is re-checked.
MAPPED_V6 = ipaddress.ip_network("::ffff:0:0/96")
NAT64_V6 = (
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
)
SIX_TO_FOUR_V6 = ipaddress.ip_network("2002::/16")
# Teredo encodes the server IPv4 in bits 32..63.
TEREDO_V6 = ipaddress.ip_network("2001::/32")


class Reason(str, Enum):
    OK = "OK"
    EGRESS_DISABLED = "EGRESS_DISABLED"
    PORT_NOT_ALLOWED = "PORT_NOT_ALLOWED"
    RESOLVE_FAILED = "RESOLVE_FAILED"
    RESOLVED_TOO_MANY = "RESOLVED_TOO_MANY"
    NOT_BOUND_TO_JOB = "NOT_BOUND_TO_JOB"
    DENY_LOOPBACK = "DENY_LOOPBACK"
    DENY_LINK_LOCAL = "DENY_LINK_LOCAL"
    DENY_UNSPECIFIED = "DENY_UNSPECIFIED"
    DENY_MULTICAST = "DENY_MULTICAST"
    DENY_RESERVED = "DENY_RESERVED"
    DENY_PLATFORM_NETWORK = "DENY_PLATFORM_NETWORK"
    DENY_TARGET_DENYLIST = "DENY_TARGET_DENYLIST"
    DENY_EMBEDDED_V4 = "DENY_EMBEDDED_V4"


@dataclass(frozen=True)
class SourceAllow:
    """One declared provider source: an endpoint set a manifest may contact."""

    id: str
    hosts: tuple[str, ...]
    ports: tuple[int, ...]
    addresses: tuple[IPNetwork, ...] = ()  # pinned by M05 at dispatch time


@dataclass(frozen=True)
class JobEgressPolicy:
    job_id: str
    mode: str = "egress"  # "egress" | "none"
    target_ips: tuple[IPNetwork, ...] = ()
    target_ports: tuple[int, ...] = ()
    sources: tuple[SourceAllow, ...] = ()
    platform_cidrs: tuple[IPNetwork, ...] = ()
    deny_cidrs: tuple[IPNetwork, ...] = ()
    max_resolved: int = 8
    resolver: "Resolver | None" = field(default=None, compare=False)

    @property
    def allowed_networks(self) -> tuple[IPNetwork, ...]:
        nets: list[IPNetwork] = list(self.target_ips)
        for src in self.sources:
            nets.extend(src.addresses)
        return tuple(nets)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: Reason
    host: str
    port: int
    pinned: str | None = None
    resolved: tuple[str, ...] = ()
    source_id: str | None = None

    def as_audit(self) -> dict:
        return {
            "decision": "allow" if self.allowed else "deny",
            "reason": self.reason.value,
            "host": self.host,
            "port": self.port,
            "pinned": self.pinned,
            "resolved": list(self.resolved),
            "source_id": self.source_id,
        }


class Resolver:
    """Control-plane resolver. One lookup per connection, never cached."""

    def resolve(self, host: str) -> list[str]:
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return []
        out: list[str] = []
        for info in infos:
            addr = info[4][0]
            if addr not in out:
                out.append(addr)
        return out


def _classify_always_denied(addr: IPAddress) -> Reason | None:
    """Return the deny reason for addresses that are never reachable."""
    if isinstance(addr, ipaddress.IPv4Address):
        if addr.is_loopback:
            return Reason.DENY_LOOPBACK
        if addr.is_link_local:
            return Reason.DENY_LINK_LOCAL
        if addr.is_unspecified:
            return Reason.DENY_UNSPECIFIED
        if addr.is_multicast:
            return Reason.DENY_MULTICAST
        if any(addr in net for net in ALWAYS_DENY_V4):
            return Reason.DENY_RESERVED
        return None

    # IPv6 (and IPv4-mapped/NAT64/6to4/Teredo forms).
    inner_reason = _check_embedded_v6(addr)
    if inner_reason is not None:
        return inner_reason
    if addr.is_loopback:
        return Reason.DENY_LOOPBACK
    if addr.is_link_local:
        return Reason.DENY_LINK_LOCAL
    if addr.is_unspecified:
        return Reason.DENY_UNSPECIFIED
    if addr.is_multicast:
        return Reason.DENY_MULTICAST
    if any(addr in net for net in ALWAYS_DENY_V6):
        return Reason.DENY_RESERVED
    return None


def _check_embedded_v6(addr: ipaddress.IPv6Address) -> Reason | None:
    """Deny IPv6 transport forms whose embedded IPv4 is denied."""
    if addr.ipv4_mapped is not None:
        return _classify_always_denied(addr.ipv4_mapped)
    for net in NAT64_V6:
        if addr in net:
            inner = ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
            reason = _classify_always_denied(inner)
            if reason is not None:
                return reason
            # Even a "clean" NAT64 address is only usable when its embedded
            # target is bound to the job; treat the v4 form as the subject.
            return None
    if addr in SIX_TO_FOUR_V6:
        inner = ipaddress.IPv4Address((int(addr) >> 80) & 0xFFFFFFFF)
        reason = _classify_always_denied(inner)
        if reason is not None:
            return reason
    if addr in TEREDO_V6:
        server = ipaddress.IPv4Address((int(addr) >> 64) & 0xFFFFFFFF)
        reason = _classify_always_denied(server)
        if reason is not None:
            return reason
    return None


def _literal_address(host: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def decide(
    policy: JobEgressPolicy,
    host: str,
    port: int,
    *,
    resolver: Resolver | None = None,
) -> Decision:
    """Return the allow/deny decision for one connection attempt."""
    if policy.mode != "egress":
        return Decision(False, Reason.EGRESS_DISABLED, host, port)
    if not (1 <= port <= 65535):
        return Decision(False, Reason.PORT_NOT_ALLOWED, host, port)

    literal = _literal_address(host)
    if literal is not None:
        resolved = [str(literal)]
    else:
        res = resolver or policy.resolver or Resolver()
        try:
            resolved = res.resolve(host)
        except Exception:  # resolver failure is a deny, never a pass
            return Decision(False, Reason.RESOLVE_FAILED, host, port)
        if not resolved:
            return Decision(False, Reason.RESOLVE_FAILED, host, port)
        if len(resolved) > policy.max_resolved:
            return Decision(False, Reason.RESOLVED_TOO_MANY, host, port)

    addresses: list[IPAddress] = []
    for text in resolved:
        try:
            addresses.append(ipaddress.ip_address(text))
        except ValueError:
            return Decision(False, Reason.RESOLVE_FAILED, host, port)

    # 2. Address safety first: these reasons stay stable no matter which ports
    #    the job happens to have bound, and a denied address never reaches the
    #    dial path. Checked for the whole answer: one denied address denies
    #    the name.

    for addr in addresses:
        reason = _classify_always_denied(addr)
        if reason is not None:
            return Decision(False, reason, host, port, resolved=tuple(resolved))
        if any(addr in net for net in policy.platform_cidrs):
            return Decision(
                False, Reason.DENY_PLATFORM_NETWORK, host, port, resolved=tuple(resolved)
            )
        if any(addr in net for net in policy.deny_cidrs):
            return Decision(
                False, Reason.DENY_TARGET_DENYLIST, host, port, resolved=tuple(resolved)
            )

    # 3. Which binding covers this request? A declared provider source (by
    #    host and port) or the job's own targets (by allowed port).
    normalised = host.lower().rstrip(".")
    source = next(
        (
            src
            for src in policy.sources
            if normalised in {h.lower().rstrip(".") for h in src.hosts}
            and port in src.ports
        ),
        None,
    )
    if source is not None:
        allowed_nets = source.addresses or policy.allowed_networks
        source_id: str | None = source.id
    elif port in policy.target_ports:
        allowed_nets = policy.target_ips
        source_id = None
    else:
        return Decision(False, Reason.PORT_NOT_ALLOWED, host, port, resolved=tuple(resolved))

    # 4. Every address must be inside the binding (fail closed on extras).
    for addr in addresses:
        if not any(addr in net for net in allowed_nets):
            return Decision(
                False, Reason.NOT_BOUND_TO_JOB, host, port, resolved=tuple(resolved)
            )

    return Decision(
        True,
        Reason.OK,
        host,
        port,
        pinned=str(addresses[0]),
        resolved=tuple(resolved),
        source_id=source_id,
    )


def load_policy(raw: dict) -> JobEgressPolicy:
    """Build a policy from the JSON document the runner writes per job."""

    def nets(values: Iterable[str]) -> tuple[IPNetwork, ...]:
        return tuple(ipaddress.ip_network(v, strict=False) for v in values)

    sources = []
    for src in raw.get("sources", []):
        sources.append(
            SourceAllow(
                id=src["id"],
                hosts=tuple(h.lower() for h in src.get("hosts", [])),
                ports=tuple(int(p) for p in src.get("ports", [])),
                addresses=nets(src.get("addresses", [])),
            )
        )
    return JobEgressPolicy(
        job_id=raw["job_id"],
        mode=raw.get("mode", "egress"),
        target_ips=nets(raw.get("target_ips", [])),
        target_ports=tuple(int(p) for p in raw.get("target_ports", [])),
        sources=tuple(sources),
        platform_cidrs=nets(raw.get("platform_cidrs", [])),
        deny_cidrs=nets(raw.get("deny_cidrs", [])),
        max_resolved=int(raw.get("max_resolved", 8)),
    )


def is_denied_address(addr: IPAddress) -> Reason | None:
    """Public helper for tests and for M05-side target validation."""
    return _classify_always_denied(addr)


def iter_resolved_hosts(hosts: Sequence[str], resolver: Resolver | None = None) -> list[str]:
    res = resolver or Resolver()
    out: list[str] = []
    for host in hosts:
        lit = _literal_address(host)
        out.extend([str(lit)] if lit else res.resolve(host))
    return out
