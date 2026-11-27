"""The platform's own networks and host addresses: the deny set every sandbox must carry (B1).

The always-deny set of the sandbox (`02-nen-tang.md` §Sandbox) includes the platform's control and
data networks. That list cannot be a constant: it depends on the host (compose projects, the
podman default network, the broker's uplink). A runner therefore computes it at start-up from
three sources and refuses internet jobs while it is empty:

* `AEGIS_M06_PLATFORM_CIDRS` - operator-declared CIDRs (comma-separated), for networks this code
  cannot see (a remote control plane, a VPN);
* every podman network that is **not** a per-job network (a network carrying the runner's
  `aegis.role=network` label) - the dev/compose networks, the lab, the vulnlab, the default
  `podman` network **and the broker's uplink**;
* every address of the host's own interfaces (/32 and /128), because a job that reached one of
  them would be talking to the platform.

This module also serves M05: a target inside this set is refused at acceptance, so it is never
signed into an `ApprovedTask` in the first place. Both processes read the same function, so the
two sides cannot drift.

Standard library only, plus the `podman` and `ip` binaries the deployment already needs. A
failure to read either is `PlatformDenySetUnavailable` - callers must fail closed for internet
work.
"""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

__all__ = [
    "ENV_CIDRS",
    "PlatformDenySetUnavailable",
    "PlatformNetwork",
    "host_addresses",
    "platform_cidrs",
    "platform_networks",
]

ENV_CIDRS = "AEGIS_M06_PLATFORM_CIDRS"
#: A per-job network carries this label (set by `PodmanRunner._ensure_network`); every other podman
#: network is platform infrastructure.
NETWORK_ROLE_LABEL = "aegis.role=network"
PODMAN = os.environ.get("AEGIS_PODMAN") or shutil.which("podman") or "podman"
IP = shutil.which("ip") or "ip"


Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class PlatformDenySetUnavailable(RuntimeError):
    """The platform's own networks/addresses cannot be read; internet work must be refused."""


@dataclass(frozen=True, slots=True)
class PlatformNetwork:
    name: str
    subnets: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]


def _run(argv: list[str]) -> str:
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=60)
    except (OSError, subprocess.SubprocessError) as error:
        raise PlatformDenySetUnavailable(f"{' '.join(argv[:3])}: {error}") from error
    if completed.returncode != 0:
        raise PlatformDenySetUnavailable(
            f"{' '.join(argv[:3])} failed: {(completed.stderr or completed.stdout).strip()[:400]}"
        )
    return completed.stdout


def _network_subnets(data: Mapping[str, object]) -> tuple[Network, ...]:
    subnets: list[Network] = []
    raw_subnets = data.get("subnets")
    for item in raw_subnets if isinstance(raw_subnets, list) else []:
        if not isinstance(item, Mapping):
            continue
        value = item.get("subnet")
        if not isinstance(value, str):
            continue
        try:
            subnets.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            continue
    return tuple(subnets)


def platform_networks() -> tuple[PlatformNetwork, ...]:
    """Every podman network that is not a per-job network (including the broker's uplink)."""
    listed = _run([PODMAN, "network", "ls", "--format", "{{.Name}}"]).split()
    if not listed:
        raise PlatformDenySetUnavailable("podman reports no network at all")
    inspected = _run([PODMAN, "network", "inspect", *listed])
    try:
        documents = json.loads(inspected)
    except json.JSONDecodeError as error:
        raise PlatformDenySetUnavailable(f"podman network inspect is not JSON: {error}") from error
    networks: list[PlatformNetwork] = []
    for document in documents:
        if not isinstance(document, Mapping):
            continue
        name = str(document.get("name", ""))
        labels = document.get("labels") or {}
        if isinstance(labels, Mapping) and str(labels.get("aegis.role", "")) == "network":
            # The runner's own per-job network: the job plus its broker, not platform data.
            continue
        networks.append(PlatformNetwork(name=name, subnets=_network_subnets(document)))
    return tuple(networks)


def host_addresses() -> tuple[Network, ...]:
    """The host's own addresses as /32 and /128 networks (a job must never reach one)."""
    output = _run([IP, "-o", "addr", "show"])
    addresses: dict[str, Network] = {}
    for line in output.splitlines():
        parts = line.split()
        # "2: eth0    inet 10.0.0.5/24 brd ..."
        for index, token in enumerate(parts):
            if token not in {"inet", "inet6"} or index + 1 >= len(parts):
                continue
            try:
                interface = ipaddress.ip_interface(parts[index + 1])
            except ValueError:
                continue
            address = interface.ip
            # A link-local address without its zone is still the host's own; keep the /32 view.
            addresses[str(address)] = ipaddress.ip_network(
                f"{address}/{address.max_prefixlen}", strict=False
            )
    if not addresses:
        raise PlatformDenySetUnavailable("ip reports no host address")
    return tuple(addresses.values())


def platform_cidrs(env: Mapping[str, str] | None = None) -> tuple[str, ...]:
    """The platform deny set of this host as CIDR strings, deduplicated.

    Order: operator-declared, podman networks, host addresses. The caller passes the result to the
    sandbox policy and the L3 rules; an empty result is an error, never "nothing to deny".
    """
    source = os.environ if env is None else env
    networks = platform_networks()
    hosts = host_addresses()
    entries: dict[str, Network] = {}
    for value in str(source.get(ENV_CIDRS, "")).split(","):
        value = value.strip()
        if not value:
            continue
        try:
            entries[value] = ipaddress.ip_network(value, strict=False)
        except ValueError as error:
            raise PlatformDenySetUnavailable(
                f"{ENV_CIDRS} contains {value!r}, which is not a CIDR: {error}"
            ) from error
    for network in networks:
        for subnet in network.subnets:
            entries[str(subnet)] = subnet
    for address in hosts:
        entries[str(address)] = address
    if not entries:
        raise PlatformDenySetUnavailable("the platform deny set is empty")
    return tuple(entries)


def describe(networks: Iterable[PlatformNetwork]) -> str:
    """A short human description for logs (names and subnets, no addresses of secrets)."""
    return "; ".join(
        f"{network.name}={'/'.join(str(subnet) for subnet in network.subnets) or 'no-subnet'}"
        for network in networks
    )
