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
import socket
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from aegis import validation
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
) -> EgressBinding:
    """Compute the signed allow-set; refuse a binding that would be empty or unbounded."""
    permissions = record.permissions
    if permissions.get("networkAccess") != "egress":
        return EgressBinding(mode="none", target_binding="none", entries=(), target_addresses=())

    entries: set[str] = set()
    for source in permissions.get("egressSources") or []:
        for host in source.get("hosts") or []:
            for port in source.get("ports") or []:
                entries.add(f"{_format_host(str(host))}:{int(port)}")

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
            resolved = _target_addresses(ref=ref, kind=kind, raw=raw, binder=binder)
            for address in resolved:
                if _denied(address):
                    continue  # deny set wins over resolved targets (OI-5)
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
        raise M05Error.policy_denied(
            "egress_binding_empty",
            f"manifest provider {record.provider} declares egress but no openable destination; an "
            "empty broker binding is a configuration error, not 'everything allowed'",
        )
    return EgressBinding(
        mode="broker",
        target_binding=target_binding,
        entries=tuple(sorted(entries)),
        target_addresses=tuple(sorted(set(addresses))),
    )


def _target_addresses(
    *, ref: Mapping[str, str], kind: str, raw: str, binder: TargetBinder
) -> tuple[str, ...]:
    if kind == "ip":
        try:
            return (str(ipaddress.ip_address(raw.strip())),)
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
        # service:<host>:<port>/<proto> - the address part is what the broker pins
        body = raw.split(":", 1)[1] if raw.startswith("service:") else raw
        host = body.split(":", 1)[0]
        return binder.addresses(host)
    raise M05Error.policy_denied(
        "target_not_bindable",
        f"target kind {kind!r} cannot be bound to network addresses for a target-bound provider",
        next_action=NextAction.FIX_INPUT,
    )
