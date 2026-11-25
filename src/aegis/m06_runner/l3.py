"""L3 gateway mode of the job broker (G1.6 item 5).

For a provider that cannot speak to the L7 broker (fingerprintx), the broker becomes the **gateway**
of the job's network: the job's default route points at it, and it forwards IPv4 under nftables
rules that allow exactly the signed IP:port set and drop everything else. The job container keeps
zero capabilities; `NET_ADMIN` exists only in the broker's own network namespace, which is where the
rules and the forwarding live.

Rules (all in the broker's namespace):

* **forward**: `policy drop`, established/related accepted, then one `ip daddr <target> tcp dport
  <port>` rule per **signed** destination pair. A target address is the address M05 pinned into the
  signed `egress_binding.target_addresses`; a source is the pinned manifest's declared source host,
  resolved now in the control plane and pinned into a rule, so no name is resolved at packet time.
* **postrouting**: masquerade on the uplink interface (the job's addresses are private to the job
  network).
* **input**: default drop, established accepted, and the broker's DNS listener (UDP/TCP 53) - the
  only service a job may reach at the gateway. The proxy ports are not needed on this channel.
* The always-deny set is implied by the default drop, and M06 refuses a signed entry inside it, so
  a rule can never be installed for metadata/loopback/link-local/platform networks.

Audit: the broker samples the nftables counters of its own ruleset and writes one `kind: l3` line
per destination rule whose counters grew (destination, port, packets, bytes) and one for the drop
rule (the denied aggregate), so the evidence names every destination that was actually reached and
the fact that other traffic was dropped. A per-5-tuple log would need conntrack/nfnetlink, which a
rootless broker cannot read (measured on this host: `/proc/net/nf_conntrack` is empty inside the
user namespace and a ctnetlink dump times out); the rule set is one destination pair per counter,
which is the granularity the signed binding is written at.

Standard library only; the `nft` and `ip` binaries come from the broker image.
"""

from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from aegis.m06_runner import netpolicy
from aegis.m06_runner.netpolicy import JobEgressPolicy

__all__ = [
    "CounterSnapshot",
    "L3Gateway",
    "Rule",
    "RuleCounter",
    "allow_rules",
    "nft_script",
    "parse_nft_counters",
    "uplink_interface",
]

TABLE = "aegis_l3"
POLL_SECONDS = 0.5


@dataclass(frozen=True, slots=True)
class Rule:
    address: str
    port: int
    protocol: str = "tcp"

    def nft(self) -> str:
        family = "ip6" if ipaddress.ip_address(self.address).version == 6 else "ip"
        return (
            f"        {family} daddr {self.address} {self.protocol} dport {self.port} "
            "ct state new counter accept"
        )


@dataclass(frozen=True, slots=True)
class RuleCounter:
    address: str
    port: int
    packets: int = 0
    bytes: int = 0


@dataclass(frozen=True, slots=True)
class CounterSnapshot:
    rules: tuple[RuleCounter, ...] = ()
    dropped_packets: int = 0
    dropped_bytes: int = 0


def allow_rules(
    policy: JobEgressPolicy, resolver: Callable[[str], list[str]] | None = None
) -> tuple[Rule, ...]:
    """The signed destination pairs, one nft rule each.

    Targets come from the **signed** `target_addresses` (never re-resolved); sources are the pinned
    manifest's declared hosts, resolved once here and pinned into the rule, so the packet path has
    no name resolution. A source that resolves to nothing fails the install (the broker refuses to
    start rather than installing a partial allow set).
    """
    resolve = resolver or netpolicy.Resolver().resolve
    rules: set[Rule] = set()
    for network in policy.target_ips:
        for port in policy.target_ports:
            rules.add(Rule(str(network.network_address), int(port)))
    for source in policy.sources:
        for host in source.hosts:
            try:
                literal = ipaddress.ip_address(host)
            except ValueError:
                addresses = resolve(host)
            else:
                addresses = [str(literal)]
            if not addresses:
                raise RuntimeError(f"declared source {host!r} did not resolve; refusing to open L3")
            for address in addresses:
                if not _address_allowed(policy, address):
                    continue
                for port in source.ports:
                    rules.add(Rule(str(ipaddress.ip_address(address)), int(port)))
    if not rules:
        raise RuntimeError("an L3 policy with no allowed destination is not a valid policy")
    return tuple(sorted(rules, key=lambda rule: (rule.address, rule.port, rule.protocol)))


def _address_allowed(policy: JobEgressPolicy, address: str) -> bool:
    from aegis.m06_runner.denyset import deny_reason

    parsed = ipaddress.ip_address(address)
    if deny_reason(parsed) is not None:
        return False
    if any(parsed in network for network in policy.platform_cidrs):
        return False
    if any(parsed in network for network in policy.deny_cidrs):
        return False
    if any(parsed in network for network in policy.private_cidrs) and not any(
        parsed in network for network in policy.target_ips
    ):
        return False
    return True


def uplink_interface(
    bind: str, *, run: Callable[..., subprocess.CompletedProcess[str]] | None = None
) -> str:
    """The non-loopback interface whose address is not the broker's job-network address.

    The broker runs with exactly two legs: the job network (where it binds) and the uplink. The
    interface carrying the job address is not the way out, so the other one is the uplink.
    """
    runner = run or subprocess.run
    output = runner(  # noqa: S603 - fixed binary from the broker image
        ["ip", "-o", "-4", "addr", "show"],
        capture_output=True,
        text=True,
        check=False,
    )
    if output.returncode != 0:
        raise RuntimeError(f"cannot read interfaces: {output.stderr.strip()[:400]}")
    candidates: list[str] = []
    for line in output.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[1] == "lo":
            continue
        name = parts[1]
        address = parts[3].split("/")[0]
        if address != bind:
            candidates.append(name)
    if len(candidates) != 1:
        raise RuntimeError(
            f"expected exactly one uplink interface besides {bind}, found {candidates}"
        )
    return candidates[0]


def nft_script(
    rules: Iterable[Rule],
    *,
    uplink: str,
    dns_port: int = 53,
) -> str:
    """The whole ruleset, applied atomically in one `nft -f` call."""
    lines = [
        f"table ip {TABLE} {{",
        "  chain input {",
        "    type filter hook input priority filter; policy drop;",
        '    iifname "lo" accept',
        "    ct state established,related accept",
        f"    udp dport {dns_port} accept",
        f"    tcp dport {dns_port} accept",
        "  }",
        "  chain forward {",
        "    type filter hook forward priority filter; policy drop;",
        "    ct state established,related accept",
    ]
    lines += [rule.nft() for rule in rules]
    lines += [
        "        counter drop",
        "  }",
        "  chain postrouting {",
        "    type nat hook postrouting priority srcnat; policy accept;",
        f'    oifname "{uplink}" masquerade',
        "  }",
        "}",
    ]
    return "\n".join(lines) + "\n"


def parse_nft_counters(document: str) -> CounterSnapshot:
    """Read the counters of the generated ruleset from `nft -j list table`.

    One counter per destination pair (the rule the binding produced) plus the aggregate drop
    counter. A rule without a counter, or in another chain, is ignored: the audit is exactly the
    forwarding decision.
    """
    data = json.loads(document or "{}")
    rules: list[RuleCounter] = []
    dropped = (0, 0)
    for item in data.get("nftables", []):
        rule = item.get("rule")
        if not rule or rule.get("chain") != "forward":
            continue
        address: str | None = None
        port: int | None = None
        counter: dict[str, Any] | None = None
        is_drop = False
        for expression in rule.get("expr", []):
            match = expression.get("match")
            if isinstance(match, dict):
                payload = (match.get("left") or {}).get("payload") or {}
                if payload.get("field") == "daddr" and isinstance(match.get("right"), str):
                    address = str(match["right"])
                if payload.get("field") == "dport" and isinstance(match.get("right"), int):
                    port = int(match["right"])
            if isinstance(expression.get("counter"), dict):
                counter = expression["counter"]
            if "drop" in expression:
                is_drop = True
        if counter is None:
            continue
        packets = int(counter.get("packets", 0))
        octets = int(counter.get("bytes", 0))
        if is_drop:
            dropped = (packets, octets)
        elif address is not None and port is not None:
            rules.append(RuleCounter(address, port, packets, octets))
    return CounterSnapshot(tuple(rules), dropped[0], dropped[1])


class L3Gateway:
    """Install the ruleset, then audit the flows of this namespace until stopped."""

    def __init__(self, policy: JobEgressPolicy, audit: Any, *, bind: str) -> None:
        self.policy = policy
        self.audit = audit
        self.bind = bind
        self.uplink = ""
        self.rules: tuple[Rule, ...] = ()
        self._counters: dict[tuple[str, int], int] = {}
        self._dropped = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._nft = shutil.which("nft") or "nft"

    def install(self) -> None:
        self.rules = allow_rules(self.policy)
        self.uplink = uplink_interface(self.bind)
        script = nft_script(self.rules, uplink=self.uplink)
        applied = subprocess.run(  # noqa: S603 - fixed binary from the broker image
            [self._nft, "-f", "-"],
            input=script,
            capture_output=True,
            text=True,
            check=False,
        )
        if applied.returncode != 0:
            raise RuntimeError(
                f"nft could not install the L3 ruleset: {applied.stderr.strip()[:800]}"
            )
        self._report("installed")

    def start(self) -> None:
        self._thread = threading.Thread(target=self._audit_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        try:
            subprocess.run(  # noqa: S603 - fixed binary from the broker image
                [self._nft, "delete", "table", "ip", TABLE],
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError:
            pass

    # -- audit -------------------------------------------------------------------------------

    def _audit_loop(self) -> None:
        while not self._stop.wait(POLL_SECONDS):
            try:
                self.sample()
            except OSError:  # pragma: no cover - the table file is always there in a netns
                return

    def counters(self) -> CounterSnapshot:
        read = subprocess.run(  # noqa: S603 - fixed binary from the broker image
            [self._nft, "-j", "list", "table", "ip", TABLE],
            capture_output=True,
            text=True,
            check=False,
        )
        if read.returncode != 0:
            raise RuntimeError(f"cannot read the L3 counters: {read.stderr.strip()[:400]}")
        return parse_nft_counters(read.stdout)

    def sample(self, snapshot: CounterSnapshot | None = None) -> None:
        """One counter snapshot: emit a line per rule whose packets grew, and for the drop rule."""
        current = snapshot or self.counters()
        for counter in current.rules:
            key = (counter.address, counter.port)
            previous = self._counters.get(key, 0)
            if counter.packets > previous:
                self._write(
                    {
                        "kind": "l3",
                        "event": "flow",
                        "dst": counter.address,
                        "dport": counter.port,
                        "packets": counter.packets - previous,
                        "bytes": max(0, counter.bytes),
                    }
                )
            self._counters[key] = counter.packets
        if current.dropped_packets > self._dropped:
            self._write(
                {
                    "kind": "l3",
                    "event": "denied",
                    "packets": current.dropped_packets - self._dropped,
                    "bytes": max(0, current.dropped_bytes),
                }
            )
        self._dropped = current.dropped_packets

    def _write(self, record: dict[str, Any]) -> None:
        write = getattr(self.audit, "write_l3", None)
        if write is not None:
            write(record)

    def _report(self, event: str) -> None:
        self._write(
            {
                "kind": "l3",
                "event": event,
                "uplink": self.uplink,
                "rules": [f"{rule.address}:{rule.port}/{rule.protocol}" for rule in self.rules],
                "policy": "drop",
            }
        )
