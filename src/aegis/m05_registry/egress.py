"""Egress binding (E-1/OI-5): the exact broker allow-set that is signed into the task.

Binding = (resolved target addresses ∪ `permissions.egressSources`) − platform deny set.

* `targetBinding: none` - the provider never connects to the job target, so the binding is its
declared
  sources only (host:port per protocol/port). Ports come from the manifest, hosts are lowercase.
* `targetBinding: required` - M05 resolves each target to addresses (an `ip` seed directly, a
  `domain`
  seed through a `TargetBinder` - injectable, so tests never touch DNS), pins them in the task and
  adds
  one entry per address × each `input.ports` value.
* Addresses in the platform deny set are subtracted, never "allowed anyway" (OI-5). A broker binding
  that ends up empty is refused instead of being treated as "open everything".

Input that names destinations the pinned manifest does not declare (`sources`, `resolvers`) is
refused
before the binding is built - the manifest's `egressSources` is the only allowed set (C05).
"""

from __future__ import annotations

import ipaddress
import secrets
import socket
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from aegis import validation
from aegis.common import dns_cname
from aegis.contracts_gen.common.error_v2_schema import NextAction
from aegis.m05_registry.errors import M05Error
from aegis.m05_registry.manifest import ManifestRecord
from aegis.m05_registry.targets import ResolvedTargets

__all__ = [
    "EgressBinding",
    "SystemTargetBinder",
    "TargetBinder",
    "build_egress_binding",
    "check_declared_destinations",
]


@runtime_checkable
class TargetBinder(Protocol):
    """Resolve a target name to the addresses M05 pins into the signed task."""

    def addresses(self, value: str) -> tuple[str, ...]: ...


def _address_literal(raw: str, *, prefix: str) -> str:
    """The address a target names, without the canonical-key prefix and IPv6 brackets."""
    value = raw.strip()
    if value.lower().startswith(prefix):
        value = value[len(prefix) :]
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    return value


class SystemTargetBinder:
    """The production binder: system resolver, A/AAAA, sorted and de-duplicated."""

    def __init__(self, resolver: Any = None) -> None:
        self._resolver = resolver or socket.getaddrinfo

    def addresses(self, value: str) -> tuple[str, ...]:
        try:
            infos = self._resolver(value, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except OSError as error:
            raise M05Error.policy_denied(
                "target_unresolvable",
                f"target {value!r} cannot be resolved for a target-bound egress binding: {error}",
                next_action=NextAction.FIX_INPUT,
            ) from error
        addresses: set[str] = set()
        for info in infos:
            try:
                addresses.add(str(ipaddress.ip_address(str(info[4][0]))))
            except ValueError:
                continue
        if not addresses:
            raise M05Error.policy_denied(
                "target_unresolvable",
                f"target {value!r} resolved to no address",
                next_action=NextAction.FIX_INPUT,
            )
        return tuple(sorted(addresses))


@dataclass(frozen=True, slots=True)
class EgressBinding:
    mode: str
    target_binding: str
    entries: tuple[str, ...]
    target_addresses: tuple[str, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "target_binding": self.target_binding,
            "entries": list(self.entries),
            "target_addresses": list(self.target_addresses),
        }


def _format_host(host: str) -> str:
    host = host.strip().lower().rstrip(".")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host
    return f"[{address}]" if address.version == 6 else str(address)


def _denied(address: str) -> bool:
    return validation.denied_egress_host(address)


Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def _networks(values: Sequence[str]) -> tuple[Network, ...]:
    networks: list[Network] = []
    for value in values:
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            continue
    return tuple(networks)


def _in_platform(address: str, networks: Sequence[Network]) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(parsed.version == net.version and parsed in net for net in networks)


def check_declared_destinations(record: ManifestRecord, merged_input: Mapping[str, Any]) -> None:
    """Refuse input that reaches a destination the pinned manifest does not declare (C05)."""
    permissions = record.permissions
    declared = permissions.get("egressSources") or []
    source_ids = {str(source.get("id")) for source in declared}
    unknown_sources = sorted(
        str(source) for source in merged_input.get("sources") or [] if str(source) not in source_ids
    )
    if unknown_sources:
        raise M05Error.policy_denied(
            "egress_source_not_declared",
            f"sources {unknown_sources} are not egressSources of the pinned manifest",
            field="/input/sources",
        )
    dns_hosts = {
        _format_host(str(host))
        for source in declared
        if source.get("protocol") == "dns"
        for host in source.get("hosts") or []
    }
    unknown_resolvers = sorted(
        str(resolver)
        for resolver in merged_input.get("resolvers") or []
        if _format_host(str(resolver)) not in dns_hosts
    )
    if unknown_resolvers:
        raise M05Error.policy_denied(
            "resolver_not_declared",
            f"resolvers {unknown_resolvers} are not declared 'dns' egressSources of the "
            f"pinned manifest",
            field="/input/resolvers",
        )


def build_egress_binding(
    record: ManifestRecord,
    *,
    merged_input: Mapping[str, Any],
    targets: ResolvedTargets,
    binder: TargetBinder,
    network_profile: str = "internet",
    platform_cidrs: Sequence[str] = (),
    authorized_suffixes: Sequence[str] = (),
) -> EgressBinding:
    """Compute the signed allow-set; refuse a binding that would be empty or unbounded.

    On the internet profile a `protocol: dns` source is not signed: a raw tunnel to a public
    resolver would bypass the broker's DNS name binding (F4). Targets are checked against the
    platform's own networks (B1) before they can be signed.
    """
    permissions = record.permissions
    if permissions.get("networkAccess") != "egress":
        return EgressBinding(mode="none", target_binding="none", entries=(), target_addresses=())

    platform = _networks(platform_cidrs)
    entries: set[str] = set()
    for source in permissions.get("egressSources") or []:
        if network_profile == "internet" and str(source.get("protocol")) == "dns":
            continue
        for host in source.get("hosts") or []:
            for port in source.get("ports") or []:
                entries.add(f"{_format_host(str(host))}:{int(port)}")

    wildcard_checked = False
    target_binding = str(permissions.get("targetBinding") or "none")
    addresses: list[str] = []
    if target_binding == "required":
        ports = [int(port) for port in merged_input.get("ports") or []]
        if not ports:
            raise M05Error.policy_denied(
                "target_ports_required",
                "a target-bound egress binding needs input.ports",
                field="/input/ports",
            )
        for ref, kind, raw in zip(targets.refs, targets.kinds, targets.raw, strict=True):
            if network_profile == "internet" and _is_host_name(raw):
                _refuse_a_foreign_cname(raw, authorized_suffixes=authorized_suffixes)
            if network_profile == "internet" and not wildcard_checked and _is_host_name(raw):
                _refuse_a_wildcard(raw, authorized_suffixes=authorized_suffixes, binder=binder)
                wildcard_checked = True
            resolved = _target_addresses(ref=ref, kind=kind, raw=raw, binder=binder)
            for address in resolved:
                if _denied(address):
                    continue  # deny set wins over resolved targets (OI-5)
                if network_profile == "internet" and _in_platform(address, platform):
                    # B1: on the internet profile the platform's own networks are never a signed
                    # target. A lab campaign targets the authorized lab network by design.
                    raise M05Error.policy_denied(
                        "target_platform_network",
                        f"target address {address} is inside the platform deny set",
                        next_action=NextAction.FIX_INPUT,
                    )
                addresses.append(address)
                for port in ports:
                    entries.add(f"{_format_host(address)}:{port}")
        if not addresses:
            raise M05Error.out_of_scope(
                "target_denied",
                "every resolved target address is in the platform deny set; the broker would open "
                "nothing",
            )

    if not entries:
        declared = permissions.get("egressSources") or []
        dns_only = bool(declared) and all(
            str(source.get("protocol")) == "dns" for source in declared
        )
        if network_profile == "internet" and dns_only and target_binding != "required":
            # A passive DNS provider (DNSx) has no L7 destination on the internet profile: its
            # egress is the broker's DNS front end, which is not part of this binding (F4).
            return EgressBinding(
                mode="broker", target_binding="none", entries=(), target_addresses=()
            )
        raise M05Error.policy_denied(
            "egress_binding_empty",
            f"manifest provider {record.provider} declares egress but no openable destination; an "
            "empty broker binding is a configuration error, not 'everything allowed'",
        )
    return EgressBinding(
        # The channel is the pinned manifest's `egressMode` (broker L7 or the l3 gateway); it is
        # signed into the task and M06 refuses a task whose mode disagrees with the manifest.
        mode=str(permissions.get("egressMode") or "broker"),
        target_binding=target_binding,
        entries=tuple(sorted(entries)),
        target_addresses=tuple(sorted(set(addresses))),
    )


def _is_host_name(raw: str) -> bool:
    value = raw.strip().lower()
    return not value.startswith(("ip:", "cidr:", "service:", "seed:")) and not _is_address(value)


def _is_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return False
    return True


def _under_suffix(name: str, suffixes: Sequence[str]) -> bool:
    host = name.strip(".").lower()
    return any(host == zone or host.endswith("." + zone) for zone in suffixes if zone)


def _refuse_a_foreign_cname(host: str, *, authorized_suffixes: Sequence[str]) -> None:
    """F3 guardrail 2: a name that CNAMEs out of the authorized suffixes stays passive-only.

    The chain is what turns an owner name into a third-party address (a CDN, a SaaS endpoint, a
    re-registered dangling target). An unknown chain (resolver down) is not a refusal; the target
    addresses are still checked against the platform and deny sets.
    """
    if not authorized_suffixes:
        return
    try:
        chain = dns_cname.cname_chain(host)
    except (OSError, ValueError):
        return
    foreign = [name for name in chain if not _under_suffix(name, authorized_suffixes)]
    if foreign:
        raise M05Error.policy_denied(
            "target_cname_outside_authorization",
            f"{host} resolves through {foreign[0]}, outside the authorized suffixes "
            f"{sorted(authorized_suffixes)}; the target stays passive-only",
            next_action=NextAction.FIX_INPUT,
        )


def _wildcard_parents(host: str, suffixes: Sequence[str]) -> list[str]:
    """The zones a wildcard record for this name could live at, limited to authorized suffixes."""
    labels = [label for label in host.strip(".").lower().split(".") if label]
    parents: set[str] = set()
    for suffix in suffixes:
        zone = suffix.strip(".").lower()
        if host == zone or host.endswith("." + zone):
            parents.add(zone)
    for index in range(1, len(labels) - 1):
        candidate = ".".join(labels[index:])
        if any(candidate == zone or candidate.endswith("." + zone) for zone in parents):
            parents.add(candidate)
    # The deepest parent says nothing extra about a wildcard at a shallower zone, and every probe
    # is a real DNS query: keep the authorized zone and the immediate parent.
    immediate = ".".join(labels[1:])
    keep = {zone for zone in parents if zone == immediate or zone in suffixes}
    return sorted(keep)


def _refuse_a_wildcard(
    host: str, *, authorized_suffixes: Sequence[str], binder: TargetBinder
) -> None:
    """F3 guardrail 4: a wildcard under the target's zone makes every label resolve.

    A wildcard turns a single discovered name into an unbounded address set, so active signing is
    refused and the campaign stays passive; the operator can narrow the target.
    """
    for parent in _wildcard_parents(host, authorized_suffixes)[:2]:
        probe = f"aegis-wildcard-{secrets.token_hex(4)}.{parent}"
        try:
            answers = binder.addresses(probe)
        except M05Error:
            continue
        if answers:
            raise M05Error.policy_denied(
                "wildcard_dns",
                f"{parent} answers a random label ({probe} -> {sorted(answers)[0]}); active "
                "scanning of a wildcard zone is refused",
                next_action=NextAction.FIX_INPUT,
            )


def _target_addresses(
    *, ref: Mapping[str, str], kind: str, raw: str, binder: TargetBinder
) -> tuple[str, ...]:
    """Addresses the broker may pin for one resolved target.

    `raw` is what `resolve_targets` recorded: a seed's own `raw_value`, or the *input text* for an
    asset ref - and the contract's input form for an address/service asset is its canonical key
    (`ip:`/`service:`, capabilities/network/discover-services.v2). Reading only the bare literal
    refused every address-targeted job whose target was an asset the campaign had discovered;
    the key's own prefix and brackets are notation, so they are removed here, once.
    """
    if kind == "ip":
        value = _address_literal(raw, prefix="ip:")
        try:
            return (str(ipaddress.ip_address(value)),)
        except ValueError as error:
            raise M05Error.policy_denied(
                "target_not_bindable",
                f"target {raw!r} is not an IP address",
                next_action=NextAction.FIX_INPUT,
            ) from error
    if kind == "domain":
        value = raw.strip().lower().rstrip(".")
        value = value[4:] if value.startswith("dns:") else value
        return binder.addresses(value)
    if kind == "service":
        # service:<host>:<port>/<proto> (bracketed IPv6 host) - the address part is what the broker
        # pins. A literal address stays a literal; only a name goes through the binder.
        body = raw.split(":", 1)[1] if raw.startswith("service:") else raw
        host = body.rsplit("/", 1)[0] if "/" in body else body
        if host.startswith("["):
            return (host[1 : host.index("]")],)
        address, sep, port = host.rpartition(":")
        if sep and port.isdigit():
            return (address,)
        return binder.addresses(host)
    raise M05Error.policy_denied(
        "target_not_bindable",
        f"target kind {kind!r} cannot be bound to network addresses for a target-bound provider",
        next_action=NextAction.FIX_INPUT,
    )
