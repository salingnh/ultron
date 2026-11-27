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
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

import psycopg

from aegis import validation
from aegis.common import dns_cname
from aegis.common.networks import PRIVATE, is_private, subnet_inside
from aegis.contracts_gen.common.error_v2_schema import NextAction
from aegis.m05_registry.errors import M05Error
from aegis.m05_registry.manifest import ManifestRecord
from aegis.m05_registry.targets import ResolvedTargets
from aegis.m06_runner.denyset import checked_address

__all__ = [
    "ActiveProvenance",
    "DomainProvenance",
    "EgressBinding",
    "SystemTargetBinder",
    "TargetBinder",
    "build_egress_binding",
    "check_declared_destinations",
    "load_active_provenance",
]


@runtime_checkable
class TargetBinder(Protocol):
    """Resolve a target name to the addresses M05 pins into the signed task.

    A failure must say which failure it is, because the wildcard probe (F3 guardrail 4) may only
    read "no such name" as "no wildcard": raise an `M05Error` with rule `target_unresolvable` when
    the name does not exist (NXDOMAIN / no address), and any other rule - `target_lookup_failed` is
    the conventional one - when the resolver could not be asked. A binder that collapses the two
    into `target_unresolvable` makes an outage look like an empty zone (item 61 follow-up).
    """

    def addresses(self, value: str) -> tuple[str, ...]: ...


def _address_literal(raw: str, *, prefix: str) -> str:
    """The address a target names, without the canonical-key prefix and IPv6 brackets."""
    value = raw.strip()
    if value.lower().startswith(prefix):
        value = value[len(prefix) :]
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    return value


#: `getaddrinfo` errors that mean "this name does not exist" (an NXDOMAIN answer), as opposed to a
#: resolver that could not be asked. The wildcard probe treats only the former as "no wildcard".
MISSING_NAME_ERRORS = frozenset(
    getattr(socket, name) for name in ("EAI_NONAME", "EAI_NODATA") if hasattr(socket, name)
)


class SystemTargetBinder:
    """The production binder: system resolver, A/AAAA, sorted and de-duplicated.

    The two failure modes are distinct, because the wildcard guardrail (F3 guardrail 4) may only
    read "this name does not exist" as "no wildcard record": `target_unresolvable` is an NXDOMAIN
    answer, `target_lookup_failed` is a resolver that could not be asked (timeout, SERVFAIL, no
    resolver configured). A caller that must fail closed refuses on the latter (item 61 follow-up).
    """

    def __init__(self, resolver: Any = None) -> None:
        self._resolver = resolver or socket.getaddrinfo

    def addresses(self, value: str) -> tuple[str, ...]:
        try:
            infos = self._resolver(value, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror as error:
            if error.errno in MISSING_NAME_ERRORS:
                raise M05Error.policy_denied(
                    "target_unresolvable",
                    f"target {value!r} does not exist ({error})",
                    next_action=NextAction.FIX_INPUT,
                ) from error
            raise M05Error.policy_denied(
                "target_lookup_failed",
                f"the resolver could not be asked about {value!r}: {error}",
                next_action=NextAction.FIX_INPUT,
            ) from error
        except OSError as error:
            raise M05Error.policy_denied(
                "target_lookup_failed",
                f"the resolver could not be asked about {value!r}: {error}",
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
class DomainProvenance:
    """One domain that resolved to an `ip` asset in a campaign, with its recorded CNAME chain."""

    name: str
    cname_targets: tuple[str, ...] = ()
    wildcard_observed: bool = False


@dataclass(frozen=True, slots=True)
class ActiveProvenance:
    """Seed IP/CIDR networks and DB DNS provenance used to gate active targets on internet."""

    seed_networks: tuple[Network, ...] = ()
    by_address: Mapping[str, tuple[DomainProvenance, ...]] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class EgressBinding:
    mode: str
    target_binding: str
    entries: tuple[str, ...]
    target_addresses: tuple[str, ...]
    #: The private seed CIDRs the campaign's RoE lists: the only private ranges M06 may reach from
    #: an internet job (R4). Signed with the rest of the binding, so M06 never infers it.
    authorized_private_cidrs: tuple[str, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "target_binding": self.target_binding,
            "entries": list(self.entries),
            "target_addresses": list(self.target_addresses),
            "authorized_private_cidrs": list(self.authorized_private_cidrs),
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
    provenance: ActiveProvenance | None = None,
) -> EgressBinding:
    """Compute the signed allow-set; refuse a binding that would be empty or unbounded.

    On the internet profile a `protocol: dns` source is not signed: a raw tunnel to a public
    resolver would bypass the broker's DNS name binding (F4). Targets are checked against the
    platform's own networks (B1) and active-eligibility provenance (F3) before they can be signed.

    Every address is normalised first (R3): an IPv4-mapped answer is the IPv4 destination the kernel
    dials, so the platform/private checks must see it and the task must sign the IPv4 form; SIIT's
    IPv4-translated form is refused. On the internet profile a private address is signed only when
    the campaign's RoE lists a private *seed* CIDR that covers it (R4); the covering seed CIDRs are
    signed into the binding so M06 enforces the same rule instead of trusting the address alone.
    """
    permissions = record.permissions
    if permissions.get("networkAccess") != "egress":
        return EgressBinding(mode="none", target_binding="none", entries=(), target_addresses=())

    declared = permissions.get("egressSources") or []
    dns_only = bool(declared) and all(str(source.get("protocol")) == "dns" for source in declared)
    platform = _networks(platform_cidrs)
    entries: set[str] = set()
    for source in declared:
        if network_profile == "internet" and str(source.get("protocol")) == "dns":
            continue
        for host in source.get("hosts") or []:
            for port in source.get("ports") or []:
                entries.add(f"{_format_host(str(host))}:{int(port)}")

    wildcard_zones: dict[str, tuple[str, str] | None] = {}
    active_provenance = provenance or ActiveProvenance()
    # R4: the private ranges the RoE authorizes for this campaign, as seed networks. A seed that is
    # not itself completely inside a private range does not authorize one (no 0.0.0.0/0 loophole).
    private_seeds = tuple(
        network for network in active_provenance.seed_networks if subnet_inside(network, PRIVATE)
    )
    target_binding = str(permissions.get("targetBinding") or "none")
    if network_profile == "internet" and dns_only and target_binding != "required":
        # A DNS-only provider on the internet profile (F4) resolves names through the broker's
        # DNS front end instead of dialing a recursive resolver directly; sign the bound DNS names.
        for _ref, kind, raw in zip(targets.refs, targets.kinds, targets.raw, strict=True):
            if kind == "domain" or _is_host_name(raw):
                host = raw.strip().lower().rstrip(".").removeprefix("dns:")
                if not host.isascii():
                    host = host.encode("idna").decode("ascii")
                if host and not _denied(host):
                    entries.add(f"dns:{host}")
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
            if network_profile == "internet" and (kind == "domain" or _is_host_name(raw)):
                host = raw.strip().lower().rstrip(".").removeprefix("dns:")
                if authorized_suffixes and not _under_suffix(host, authorized_suffixes):
                    raise M05Error.policy_denied(
                        "target_passive_only",
                        f"target {raw!r} is outside the authorized suffixes "
                        f"{sorted(authorized_suffixes)}; it stays passive-only",
                        next_action=NextAction.FIX_INPUT,
                    )
                _refuse_a_foreign_cname(host, authorized_suffixes=authorized_suffixes)
                _refuse_a_wildcard(
                    host,
                    authorized_suffixes=authorized_suffixes,
                    binder=binder,
                    wildcard_zones=wildcard_zones,
                )
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
                parsed_address = ipaddress.ip_address(address)
                if network_profile == "internet" and is_private(parsed_address):
                    # R4: the host's own private networks are not an internet target unless the
                    # RoE lists the private seed CIDR that covers this address. This is what stops
                    # a discovered name (split-horizon DNS, a dangling CNAME) from turning an
                    # "internet" campaign into a scan of the owner's office LAN.
                    covered = any(
                        parsed_address.version == network.version and parsed_address in network
                        for network in private_seeds
                    )
                    if not covered:
                        raise M05Error.policy_denied(
                            "target_private_network",
                            f"target address {address} is private and the campaign RoE lists no "
                            "private seed CIDR covering it; it stays passive-only",
                            next_action=NextAction.FIX_INPUT,
                        )
                if network_profile == "internet" and kind in ("ip", "service"):
                    _require_active_eligible(
                        raw=raw,
                        address=address,
                        authorized_suffixes=authorized_suffixes,
                        binder=binder,
                        provenance=active_provenance,
                        wildcard_zones=wildcard_zones,
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
        authorized_private_cidrs=(
            tuple(sorted({str(network) for network in private_seeds}))
            if network_profile == "internet"
            else ()
        ),
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
    re-registered dangling target). An unknown chain is a refusal too (R5): a resolver failure used
    to sign the name, so an attacker who can make the lookup fail got the guardrail skipped. The
    caller states its refusal reason instead ("the chain cannot be checked"), which is honest and
    stable, instead of pretending the name has no foreign hop.
    """
    if not authorized_suffixes:
        return
    try:
        chain = dns_cname.cname_chain(host)
    except (OSError, ValueError) as error:
        raise M05Error.policy_denied(
            "target_cname_lookup_failed",
            f"the CNAME chain of {host} cannot be checked ({error}); the target stays passive-only",
            next_action=NextAction.FIX_INPUT,
        ) from error
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


def _wildcard_unknown(parent: str, probe: str, error: BaseException) -> M05Error:
    """The refusal for a wildcard probe whose answer is unknown (never "no wildcard")."""
    return M05Error.policy_denied(
        "target_wildcard_unknown",
        f"the wildcard probe of {parent} ({probe}) cannot be checked ({error}); active signing "
        "stays refused until the resolver answers",
        next_action=NextAction.FIX_INPUT,
    )


def _wildcard_hit(
    host: str,
    *,
    authorized_suffixes: Sequence[str],
    binder: TargetBinder,
    wildcard_zones: dict[str, tuple[str, str] | None],
) -> tuple[str, str, str] | None:
    """Return `(parent, probe, answer)` if any parent zone of `host` answers a random label.

    Only a *missing* probe name is evidence that the zone has no wildcard: a resolver error is
    unknown, and unknown must refuse rather than sign (item 61 follow-up: the same fail-open as
    R5 - a failing lookup could skip the wildcard guardrail). A random label normally answers
    NXDOMAIN, which the binder reports as `target_unresolvable`; a timeout, a SERVFAIL or no
    resolver at all is `target_lookup_failed` (or a raw `OSError`) and refuses with
    `target_wildcard_unknown`.
    """
    for parent in _wildcard_parents(host, authorized_suffixes)[:2]:
        if parent in wildcard_zones:
            cached = wildcard_zones[parent]
            if cached is not None:
                return parent, cached[0], cached[1]
            continue
        probe = f"aegis-wildcard-{secrets.token_hex(4)}.{parent}"
        try:
            answers = binder.addresses(probe)
        except M05Error as error:
            if getattr(error.refusal, "rule", "") == "target_unresolvable":
                # The name does not exist: the expected answer for a random label, so no wildcard.
                wildcard_zones[parent] = None
                continue
            raise _wildcard_unknown(parent, probe, error) from error
        except OSError as error:
            raise _wildcard_unknown(parent, probe, error) from error
        if answers:
            first = sorted(answers)[0]
            wildcard_zones[parent] = (probe, first)
            return parent, probe, first
        wildcard_zones[parent] = None
    return None


def _refuse_a_wildcard(
    host: str,
    *,
    authorized_suffixes: Sequence[str],
    binder: TargetBinder,
    wildcard_zones: dict[str, tuple[str, str] | None],
) -> None:
    """F3 guardrail 4: a wildcard under the target's zone makes every label resolve.

    A wildcard turns a single discovered name into an unbounded address set, so active signing is
    refused and the campaign stays passive; the operator can narrow the target. A probe the
    resolver could not answer is a refusal too (`target_wildcard_unknown`): unknown is not clean.
    """
    hit = _wildcard_hit(
        host,
        authorized_suffixes=authorized_suffixes,
        binder=binder,
        wildcard_zones=wildcard_zones,
    )
    if hit is not None:
        parent, probe, answer = hit
        raise M05Error.policy_denied(
            "wildcard_dns",
            f"{parent} answers a random label ({probe} -> {answer}); active "
            "scanning of a wildcard zone is refused",
            next_action=NextAction.FIX_INPUT,
        )


def _require_active_eligible(
    *,
    raw: str,
    address: str,
    authorized_suffixes: Sequence[str],
    binder: TargetBinder,
    provenance: ActiveProvenance,
    wildcard_zones: dict[str, tuple[str, str] | None],
) -> None:
    """F3 guardrail 2 & 4 for ip/service targets on the internet profile.

    An address is active-eligible only if (a) it sits inside a seed IP/CIDR of the campaign's
    authorized scope, or (b) DB resolution provenance shows at least one domain under
    `authorized_suffixes` that resolved to it with no CNAME hop outside `authorized_suffixes` and
    not via a wildcard zone. Otherwise the target stays passive-only and is refused at M05.
    """
    parsed = ipaddress.ip_address(address)
    if any(parsed.version == net.version and parsed in net for net in provenance.seed_networks):
        return
    domains = provenance.by_address.get(address, ())
    if not domains:
        raise M05Error.policy_denied(
            "target_passive_only",
            f"target {raw!r} ({address}) is not inside a seed IP/CIDR and has no authorized DNS "
            "resolution provenance; it stays passive-only",
            next_action=NextAction.FIX_INPUT,
        )
    cname_failure: tuple[str, str] | None = None
    wildcard_failure: str | None = None
    for domain in domains:
        if not authorized_suffixes or not _under_suffix(domain.name, authorized_suffixes):
            continue
        foreign = [
            hop for hop in domain.cname_targets if not _under_suffix(hop, authorized_suffixes)
        ]
        if foreign:
            if cname_failure is None:
                cname_failure = (domain.name, foreign[0])
            continue
        if domain.wildcard_observed or (
            _wildcard_hit(
                domain.name,
                authorized_suffixes=authorized_suffixes,
                binder=binder,
                wildcard_zones=wildcard_zones,
            )
            is not None
        ):
            if wildcard_failure is None:
                wildcard_failure = domain.name
            continue
        return  # At least one clean authorized non-CNAME-escaping non-wildcard name resolved to it.
    if cname_failure is not None:
        source_name, hop = cname_failure
        raise M05Error.policy_denied(
            "target_cname_outside_authorization",
            f"target {raw!r} ({address}) only resolved through {source_name} -> {hop}, outside "
            f"the authorized suffixes {sorted(authorized_suffixes)}; the target stays passive-only",
            next_action=NextAction.FIX_INPUT,
        )
    if wildcard_failure is not None:
        raise M05Error.policy_denied(
            "wildcard_dns",
            f"target {raw!r} ({address}) only resolved through wildcard-matching name "
            f"{wildcard_failure}; active scanning of a wildcard zone is refused (passive-only)",
            next_action=NextAction.FIX_INPUT,
        )
    raise M05Error.policy_denied(
        "target_passive_only",
        f"target {raw!r} ({address}) has no provenance under the authorized suffixes "
        f"{sorted(authorized_suffixes)}; it stays passive-only",
        next_action=NextAction.FIX_INPUT,
    )


def _seed_networks(conn: psycopg.Connection[Any], scope_id: str) -> tuple[Network, ...]:
    rows = conn.execute(
        "SELECT kind, raw_value FROM campaign_target "
        "WHERE scope_id = %s AND kind IN ('ip', 'cidr')",
        (scope_id,),
    ).fetchall()
    networks: list[Network] = []
    for kind, raw_value in rows:
        text_val = str(raw_value or "").strip()
        if not text_val:
            continue
        try:
            if str(kind) == "ip":
                addr = ipaddress.ip_address(_address_literal(text_val, prefix="ip:"))
                networks.append(ipaddress.ip_network(f"{addr}/{addr.max_prefixlen}", strict=False))
            else:
                networks.append(ipaddress.ip_network(text_val, strict=False))
        except ValueError:
            continue
    return tuple(networks)


def _cname_chain_from_db(
    conn: psycopg.Connection[Any],
    *,
    campaign_id: str,
    domain_key: str,
    max_hops: int = 5,
) -> tuple[str, ...]:
    hops: list[str] = []
    visited = {domain_key}
    queue = [domain_key]
    while queue and len(hops) < max_hops:
        current = queue.pop(0)
        rows = conn.execute(
            "SELECT o.value ->> 'value' FROM observation o "
            "JOIN asset a ON a.asset_id = o.subject_asset_id "
            "WHERE o.campaign_id = %s AND a.canonical_key = %s "
            "AND o.predicate = 'dns.record' AND o.polarity = 'present' "
            "AND (o.value ->> 'type') = 'CNAME'",
            (campaign_id, current),
        ).fetchall()
        for (target_raw,) in rows:
            target = str(target_raw or "").strip().lower().rstrip(".")
            if not target:
                continue
            hops.append(target)
            next_key = f"dns:{target}"
            if next_key not in visited:
                visited.add(next_key)
                queue.append(next_key)
    return tuple(hops)


def _wildcard_observed_in_db(
    conn: psycopg.Connection[Any], *, campaign_id: str, domain_key: str
) -> bool:
    row = conn.execute(
        "SELECT 1 FROM observation o "
        "JOIN asset a ON a.asset_id = o.subject_asset_id "
        "WHERE o.campaign_id = %s AND a.canonical_key = %s "
        "AND o.predicate = 'dns.wildcard' AND o.polarity = 'present' "
        "AND o.value = 'true'::jsonb LIMIT 1",
        (campaign_id, domain_key),
    ).fetchone()
    return row is not None


def load_active_provenance(
    conn: psycopg.Connection[Any],
    *,
    campaign_id: str,
    scope_id: str,
    targets: ResolvedTargets,
    binder: TargetBinder,
) -> ActiveProvenance:
    """Load seed IP/CIDRs and campaign DNS provenance for `ip`/`service` targets."""
    seeds = _seed_networks(conn, scope_id)
    addresses: list[str] = []
    for ref, kind, raw in zip(targets.refs, targets.kinds, targets.raw, strict=True):
        if kind not in ("ip", "service"):
            continue
        try:
            resolved = _target_addresses(ref=ref, kind=kind, raw=raw, binder=binder)
        except M05Error:
            continue
        for addr in resolved:
            if addr not in addresses:
                addresses.append(addr)

    by_address: dict[str, tuple[DomainProvenance, ...]] = {}
    for addr in addresses:
        try:
            parsed = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if any(parsed.version == net.version and parsed in net for net in seeds):
            continue
        ip_key = f"ip:{parsed}"
        domain_rows = conn.execute(
            """
            SELECT DISTINCT d.canonical_key
              FROM asset d
             WHERE d.kind = 'domain'
               AND (
                 EXISTS (
                   SELECT 1
                     FROM relationship r
                     JOIN asset ip ON ip.asset_id = r.to_asset_id
                    WHERE r.campaign_id = %s
                      AND r.type = 'RESOLVES_TO'
                      AND r.valid_to IS NULL
                      AND r.from_asset_id = d.asset_id
                      AND ip.canonical_key = %s
                 )
                 OR EXISTS (
                   SELECT 1
                     FROM observation o
                    WHERE o.campaign_id = %s
                      AND o.subject_asset_id = d.asset_id
                      AND o.predicate = 'dns.record'
                      AND o.polarity = 'present'
                      AND (o.value ->> 'type') IN ('A', 'AAAA')
                      AND (o.value ->> 'value') = %s
                 )
               )
             ORDER BY d.canonical_key
            """,
            (campaign_id, ip_key, campaign_id, str(parsed)),
        ).fetchall()
        provenance_list: list[DomainProvenance] = []
        for (domain_key_raw,) in domain_rows:
            domain_key = str(domain_key_raw)
            cnames = _cname_chain_from_db(conn, campaign_id=campaign_id, domain_key=domain_key)
            wildcard = _wildcard_observed_in_db(
                conn, campaign_id=campaign_id, domain_key=domain_key
            )
            if not wildcard:
                wildcard = any(
                    _wildcard_observed_in_db(conn, campaign_id=campaign_id, domain_key=f"dns:{hop}")
                    for hop in cnames
                )
            provenance_list.append(
                DomainProvenance(
                    name=domain_key.removeprefix("dns:"),
                    cname_targets=cnames,
                    wildcard_observed=wildcard,
                )
            )
        if provenance_list:
            by_address[addr] = tuple(provenance_list)
    return ActiveProvenance(seed_networks=seeds, by_address=by_address)


def _target_addresses(
    *, ref: Mapping[str, str], kind: str, raw: str, binder: TargetBinder
) -> tuple[str, ...]:
    """Addresses the broker may pin for one resolved target.

    `raw` is what `resolve_targets` recorded: a seed's own `raw_value`, or the *input text* for an
    asset ref - and the contract's input form for an address/service asset is its canonical key
    (`ip:`/`service:`, capabilities/network/discover-services.v2). Reading only the bare literal
    refused every address-targeted job whose target was an asset the campaign had discovered;
    the key's own prefix and brackets are notation, so they are removed here, once.

    The result is normalised (R3): an IPv4-mapped answer becomes its IPv4 address - the destination
    the kernel actually dials - so every later check (platform, private, deny) sees it, and the
    signed binding carries the same form M06 will compare against. SIIT's IPv4-translated form is
    refused: it has no legitimate use here and no IPv4 rule would ever match it.
    """
    if kind == "ip":
        value = _address_literal(raw, prefix="ip:")
        try:
            return _normalised_addresses([str(ipaddress.ip_address(value))], raw=raw)
        except ValueError as error:
            raise M05Error.policy_denied(
                "target_not_bindable",
                f"target {raw!r} is not an IP address",
                next_action=NextAction.FIX_INPUT,
            ) from error
    if kind == "domain":
        value = raw.strip().lower().rstrip(".")
        value = value[4:] if value.startswith("dns:") else value
        return _normalised_addresses(binder.addresses(value), raw=raw)
    if kind == "service":
        # service:<host>:<port>/<proto> (bracketed IPv6 host) - the address part is what the broker
        # pins. A literal address stays a literal; only a name goes through the binder.
        body = raw.split(":", 1)[1] if raw.startswith("service:") else raw
        host = body.rsplit("/", 1)[0] if "/" in body else body
        if host.startswith("["):
            return _normalised_addresses([host[1 : host.index("]")]], raw=raw)
        address, sep, port = host.rpartition(":")
        if sep and port.isdigit():
            return _normalised_addresses([address], raw=raw)
        return _normalised_addresses(binder.addresses(host), raw=raw)
    raise M05Error.policy_denied(
        "target_not_bindable",
        f"target kind {kind!r} cannot be bound to network addresses for a target-bound provider",
        next_action=NextAction.FIX_INPUT,
    )


def _normalised_addresses(values: Sequence[str], *, raw: str) -> tuple[str, ...]:
    """The addresses of one target in the form the task signs (R3)."""
    normalised: list[str] = []
    for value in values:
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError as error:
            raise M05Error.policy_denied(
                "target_not_bindable",
                f"target {raw!r} resolved to {value!r}, which is not an address",
                next_action=NextAction.FIX_INPUT,
            ) from error
        address, embedded = checked_address(parsed)
        if embedded is not None:
            raise M05Error.policy_denied(
                "target_reserved_network",
                f"target {raw!r} names {value}, a form the sandbox never dials ({embedded.value})",
                next_action=NextAction.FIX_INPUT,
            )
        normalised.append(str(address))
    return tuple(normalised)
