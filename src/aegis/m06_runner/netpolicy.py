"""Egress policy of one sandbox job (M06; S1.5a §Sandbox, findings R-5/E-1).

The decision engine the per-job broker uses. It is pure and standard-library only so the broker
image carries no contract or HTTP dependencies, and so the rules are unit-testable without Podman.

Rules (02-nen-tang §Sandbox "Egress đã khóa"):

* Nothing is reachable unless it is bound to the job: a destination is either a resolved target of
  the task (`target_ips` + `target_ports`) or a declared provider source (`sources`, matched by
  host and port).
* Some addresses are denied whatever the binding says: the always-deny set in `denyset.py`
  (loopback, link-local/metadata, multicast, unspecified, reserved, IPv4 embedded in IPv6), the
  platform's own control/data networks and the campaign target denylist. Composition is
  `(targets ∪ sources) − deny`, so the deny set wins.
* Resolution happens in the control plane. Every address of the answer is checked and the
  connection is pinned to the checked address; a name that resolves to one denied address is
  denied as a whole (DNS rebinding), and a redirect is a new request that is checked again.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum

from aegis.m06_runner.denyset import (
    DenyReason,
    IPAddress,
    IPNetwork,
    deny_reason,
    host_key,
    normalize_host,
)

#: A source may declare this many addresses at most; a name resolving to more is refused.
DEFAULT_MAX_RESOLVED = 8


class Reason(StrEnum):
    OK = "OK"
    EGRESS_DISABLED = "EGRESS_DISABLED"
    PORT_NOT_ALLOWED = "PORT_NOT_ALLOWED"
    RESOLVE_FAILED = "RESOLVE_FAILED"
    RESOLVED_TOO_MANY = "RESOLVED_TOO_MANY"
    NOT_BOUND_TO_JOB = "NOT_BOUND_TO_JOB"
    DENY_PLATFORM_NETWORK = "DENY_PLATFORM_NETWORK"
    DENY_TARGET_DENYLIST = "DENY_TARGET_DENYLIST"
    # A private address the campaign did not name as a target is not reachable from the internet
    # profile: an internet job talks to the addresses the campaign signed, not to whatever the
    # host's own network happens to contain.
    DENY_PRIVATE = "DENY_PRIVATE"
    # Safety caps of the internet profile (RoE): the broker refuses instead of stalling the tool.
    RATE_LIMITED = "RATE_LIMITED"
    CONCURRENCY_LIMITED = "CONCURRENCY_LIMITED"
    # The always-deny reasons share their wire value with denyset.DenyReason.
    DENY_METADATA = DenyReason.METADATA.value
    DENY_LOOPBACK = DenyReason.LOOPBACK.value
    DENY_LINK_LOCAL = DenyReason.LINK_LOCAL.value
    DENY_UNSPECIFIED = DenyReason.UNSPECIFIED.value
    DENY_MULTICAST = DenyReason.MULTICAST.value
    DENY_RESERVED = DenyReason.RESERVED.value
    DENY_EMBEDDED_V4 = DenyReason.EMBEDDED_V4.value


def _reason_for(denied: DenyReason) -> Reason:
    return Reason(denied.value)


def _in_any(address: IPAddress, networks: tuple[IPNetwork, ...]) -> bool:
    return any(address in network for network in networks)


@dataclass(frozen=True)
class SourceAllow:
    """One declared provider source (`permissions.egressSources[]`)."""

    id: str
    hosts: tuple[str, ...]
    ports: tuple[int, ...]
    addresses: tuple[IPNetwork, ...] = ()  # pinned by M05 at dispatch time, optional

    def covers(self, host: str, port: int) -> bool:
        if port not in self.ports:
            return False
        key = host_key(host)
        return any(host_key(candidate) == key for candidate in self.hosts)


@dataclass(frozen=True)
class JobEgressPolicy:
    """The policy document the runner writes per job and the broker enforces.

    `profile` is the campaign's `network_profile` (signed in the task). `lab` jobs do not use a
    broker at all today; the field still travels so an audit line always names the profile that was
    in force. On `internet`, `private_cidrs` are denied unless the address is one of the signed
    target addresses (`target_ips`, i.e. the campaign explicitly targets it), and
    `per_host_rps`/`per_host_max_connections` are the RoE safety caps the broker applies.
    """

    job_id: str
    mode: str = "egress"  # "egress" | "none"
    profile: str = "lab"  # "lab" | "internet"
    campaign_id: str = ""
    authorization: str = ""
    target_ips: tuple[IPNetwork, ...] = ()
    target_ports: tuple[int, ...] = ()
    sources: tuple[SourceAllow, ...] = ()
    platform_cidrs: tuple[IPNetwork, ...] = ()
    deny_cidrs: tuple[IPNetwork, ...] = ()
    private_cidrs: tuple[IPNetwork, ...] = ()
    #: Names the job may resolve through the broker's DNS front end: the task's target names and the
    #: manifest's declared source hosts. `dns_target_names` is the subset whose answers are narrowed
    #: to the signed target addresses (a target name never resolves to something the broker would
    #: refuse to connect to).
    dns_names: tuple[str, ...] = ()
    dns_target_names: tuple[str, ...] = ()
    dns_ttl: int = 30
    per_host_rps: float | None = None
    per_host_max_connections: int | None = None
    max_resolved: int = DEFAULT_MAX_RESOLVED
    resolver: Resolver | None = field(default=None, compare=False, repr=False)

    @property
    def binding_hosts(self) -> tuple[str, ...]:
        """`host:port` strings of the effective binding (targets by address, sources by name)."""
        bound: list[str] = []
        for net in self.target_ips:
            for port in self.target_ports:
                bound.append(f"{net.network_address}:{port}")
        for source in self.sources:
            for host in source.hosts:
                for port in source.ports:
                    bound.append(f"{host}:{port}")
        return tuple(bound)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: Reason
    host: str
    port: int
    pinned: str | None = None
    resolved: tuple[str, ...] = ()
    source_id: str | None = None

    def as_audit(self) -> dict[str, object]:
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
    """Control-plane resolver: one lookup per connection, no cache (a rebinding answer must be
    checked on every request)."""

    def resolve(self, host: str) -> list[str]:
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return []
        addresses: list[str] = []
        for info in infos:
            address = str(info[4][0])
            if address not in addresses:
                addresses.append(address)
        return addresses


def _parse_addresses(values: Iterable[str]) -> tuple[IPAddress, ...]:
    addresses: list[IPAddress] = []
    for value in values:
        try:
            addresses.append(ipaddress.ip_address(value))
        except ValueError as error:
            raise ValueError(f"resolved value is not an address: {value!r}") from error
    return tuple(addresses)


def decide(
    policy: JobEgressPolicy,
    host: str,
    port: int,
    *,
    resolver: Resolver | None = None,
) -> Decision:
    """Allow or deny one connection attempt, pinning the address that was checked."""
    if policy.mode != "egress":
        return Decision(False, Reason.EGRESS_DISABLED, host, port)
    if not (1 <= port <= 65535):
        return Decision(False, Reason.PORT_NOT_ALLOWED, host, port)

    literal = normalize_host(host)
    resolved: tuple[str, ...]
    if literal is not None:
        resolved = (str(literal),)
    else:
        answer = resolver or policy.resolver or Resolver()
        try:
            resolved_values = answer.resolve(host)
        except Exception:  # noqa: BLE001 - a resolver failure is a deny, never a pass
            return Decision(False, Reason.RESOLVE_FAILED, host, port)
        if not resolved_values:
            return Decision(False, Reason.RESOLVE_FAILED, host, port)
        if len(resolved_values) > policy.max_resolved:
            return Decision(False, Reason.RESOLVED_TOO_MANY, host, port)
        try:
            address_values = _parse_addresses(resolved_values)
        except ValueError:
            return Decision(False, Reason.RESOLVE_FAILED, host, port)
        resolved = tuple(str(address) for address in address_values)

    try:
        addresses = _parse_addresses(resolved)
    except ValueError:
        return Decision(False, Reason.RESOLVE_FAILED, host, port)

    # 1. Address safety first, over the whole answer: one denied address denies the name, and a
    #    denied address never reaches the dial path whatever the job has bound.
    for address in addresses:
        denied = deny_reason(address)
        if denied is not None:
            return Decision(False, _reason_for(denied), host, port, resolved=resolved)
        if _in_any(address, policy.platform_cidrs):
            return Decision(False, Reason.DENY_PLATFORM_NETWORK, host, port, resolved=resolved)
        if _in_any(address, policy.deny_cidrs):
            return Decision(False, Reason.DENY_TARGET_DENYLIST, host, port, resolved=resolved)
        # Internet profile: the host's private networks are not reachable unless the campaign
        # explicitly targets the address (a signed target address is the campaign's own choice).
        if _in_any(address, policy.private_cidrs) and not _in_any(address, policy.target_ips):
            return Decision(False, Reason.DENY_PRIVATE, host, port, resolved=resolved)

    # 2. Which binding covers the request: a declared provider source (by host and port) or the
    #    job's own resolved targets (by target port).
    source = next((item for item in policy.sources if item.covers(host, port)), None)
    if source is not None:
        # A source binds the name and port; its pinned addresses, when M05 supplied any, narrow
        # the answer set instead of widening the target binding.
        if source.addresses and not all(
            any(address in net for net in source.addresses) for address in addresses
        ):
            return Decision(False, Reason.NOT_BOUND_TO_JOB, host, port, resolved=resolved)
    elif port in policy.target_ports:
        if not all(any(address in net for net in policy.target_ips) for address in addresses):
            return Decision(False, Reason.NOT_BOUND_TO_JOB, host, port, resolved=resolved)
    else:
        return Decision(False, Reason.PORT_NOT_ALLOWED, host, port, resolved=resolved)

    return Decision(
        True,
        Reason.OK,
        host,
        port,
        pinned=resolved[0],
        resolved=resolved,
        source_id=source.id if source is not None else None,
    )


def _nets(values: Iterable[str]) -> tuple[IPNetwork, ...]:
    return tuple(ipaddress.ip_network(value, strict=False) for value in values)


def load_policy(raw: dict[str, object]) -> JobEgressPolicy:
    """Build a policy from the JSON document the runner writes per job."""

    def nets(values: object) -> tuple[IPNetwork, ...]:
        return _nets([str(value) for value in values]) if isinstance(values, list) else ()

    def ports(values: object) -> tuple[int, ...]:
        return tuple(int(value) for value in values) if isinstance(values, list) else ()

    raw_sources = raw.get("sources")
    sources: list[SourceAllow] = []
    if isinstance(raw_sources, list):
        for item in raw_sources:
            if not isinstance(item, dict):
                raise ValueError("a source must be an object")
            source_addresses = item.get("addresses")
            sources.append(
                SourceAllow(
                    id=str(item["id"]),
                    hosts=tuple(host_key(str(host)) for host in item.get("hosts", [])),
                    ports=ports(item.get("ports")),
                    addresses=nets(source_addresses) if source_addresses is not None else (),
                )
            )
    # Fail closed: a document without a profile is not a policy this broker can enforce, and an
    # unknown profile could silently turn the internet deny rules off.
    profile = raw.get("profile")
    if not isinstance(profile, str) or profile not in {"lab", "internet"}:
        raise ValueError(f"unknown network profile {profile!r} in the egress policy")
    raw_rps = raw.get("per_host_rps")
    raw_max = raw.get("per_host_max_connections")
    per_host_rps = None if raw_rps is None else float(str(raw_rps))
    per_host_max = None if raw_max is None else int(str(raw_max))
    return JobEgressPolicy(
        job_id=str(raw["job_id"]),
        mode=str(raw.get("mode", "egress")),
        profile=profile,
        campaign_id=str(raw.get("campaign_id", "")),
        authorization=str(raw.get("authorization", "")),
        target_ips=nets(raw.get("target_ips")),
        target_ports=ports(raw.get("target_ports")),
        sources=tuple(sources),
        platform_cidrs=nets(raw.get("platform_cidrs")),
        deny_cidrs=nets(raw.get("deny_cidrs")),
        private_cidrs=nets(raw.get("private_cidrs")),
        dns_names=tuple(str(name) for name in _list(raw.get("dns_names"))),
        dns_target_names=tuple(str(name) for name in _list(raw.get("dns_target_names"))),
        dns_ttl=int(str(raw.get("dns_ttl", 30))),
        per_host_rps=per_host_rps,
        per_host_max_connections=per_host_max,
        max_resolved=int(str(raw.get("max_resolved", DEFAULT_MAX_RESOLVED))),
    )


def _list(value: object) -> list[object]:
    return list(value) if isinstance(value, list) else []


def policy_document(policy: JobEgressPolicy) -> dict[str, object]:
    """The JSON document of a policy: what the runner writes and the broker loads."""
    return {
        "job_id": policy.job_id,
        "mode": policy.mode,
        "profile": policy.profile,
        "campaign_id": policy.campaign_id,
        "authorization": policy.authorization,
        "target_ips": [str(net) for net in policy.target_ips],
        "target_ports": list(policy.target_ports),
        "sources": [
            {
                "id": source.id,
                "hosts": list(source.hosts),
                "ports": list(source.ports),
                "addresses": [str(net) for net in source.addresses],
            }
            for source in policy.sources
        ],
        "platform_cidrs": [str(net) for net in policy.platform_cidrs],
        "deny_cidrs": [str(net) for net in policy.deny_cidrs],
        "private_cidrs": [str(net) for net in policy.private_cidrs],
        "dns_names": list(policy.dns_names),
        "dns_target_names": list(policy.dns_target_names),
        "dns_ttl": policy.dns_ttl,
        "per_host_rps": policy.per_host_rps,
        "per_host_max_connections": policy.per_host_max_connections,
        "max_resolved": policy.max_resolved,
    }


def with_resolver(policy: JobEgressPolicy, resolver: Resolver) -> JobEgressPolicy:
    """Copy of `policy` using an explicit resolver (tests, or a resolver with a timeout)."""
    return replace(policy, resolver=resolver)


def iter_resolved_hosts(hosts: Sequence[str], resolver: Resolver | None = None) -> list[str]:
    """Resolve declared hosts at spec-build time (used to pin `SourceAllow.addresses`)."""
    answer = resolver or Resolver()
    resolved: list[str] = []
    for host in hosts:
        literal = normalize_host(host)
        resolved.extend([str(literal)] if literal is not None else answer.resolve(host))
    return resolved
