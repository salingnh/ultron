"""The L3 gateway rules and flow audit (G1.6 item 5): pure logic, no kernel needed.

`nft` and `ip` are only executed by the broker at run time; here the generated ruleset, the
conntrack parser and the open/close audit are checked against fixed inputs, so a rule cannot widen
silently.
"""

from __future__ import annotations

import ipaddress
import json
import subprocess
from pathlib import Path

import pytest

from aegis.m06_runner import l3
from aegis.m06_runner.netpolicy import JobEgressPolicy, SourceAllow

TARGET = "198.51.100.7"
PRIVATE = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")


class StubResolver:
    def __init__(self, answers: dict[str, list[str]]) -> None:
        self.answers = answers
        self.asked: list[str] = []

    def resolve(self, host: str) -> list[str]:
        self.asked.append(host)
        return list(self.answers.get(host, []))


def _policy(
    *,
    targets: tuple[str, ...] = (TARGET,),
    ports: tuple[int, ...] = (8080,),
    sources: tuple[SourceAllow, ...] = (),
    rps: float | None = None,
    max_connections: int | None = None,
) -> JobEgressPolicy:
    return JobEgressPolicy(
        job_id="job-1",
        per_host_rps=rps,
        per_host_max_connections=max_connections,
        profile="internet",
        egress_mode="l3",
        target_ips=tuple(
            ipaddress.ip_network(f"{address}/{ipaddress.ip_address(address).max_prefixlen}")
            for address in targets
        ),
        target_ports=ports,
        sources=sources,
        private_cidrs=tuple(ipaddress.ip_network(entry) for entry in PRIVATE),
    )


def test_target_rules_come_from_the_signed_address_port_pairs() -> None:
    rules = l3.allow_rules(_policy(targets=(TARGET, "198.51.100.8"), ports=(80, 443)))
    assert {(rule.address, rule.port) for rule in rules} == {
        (TARGET, 80),
        (TARGET, 443),
        ("198.51.100.8", 80),
        ("198.51.100.8", 443),
    }


def test_a_source_name_is_resolved_once_and_pinned_into_the_rule() -> None:
    stub = StubResolver({"crt.sh": ["93.184.216.34"]})
    policy = _policy(sources=(SourceAllow(id="crtsh", hosts=("crt.sh",), ports=(443,)),))
    rules = l3.allow_rules(policy, stub.resolve)
    assert stub.asked == ["crt.sh"]
    assert any(rule.address == "93.184.216.34" and rule.port == 443 for rule in rules)


def test_a_source_that_resolves_into_the_deny_set_gets_no_rule() -> None:
    stub = StubResolver({"crt.sh": ["169.254.169.254", "93.184.216.34"]})
    policy = _policy(sources=(SourceAllow(id="crtsh", hosts=("crt.sh",), ports=(443,)),))
    rules = l3.allow_rules(policy, stub.resolve)
    assert "169.254.169.254" not in {rule.address for rule in rules}
    assert "93.184.216.34" in {rule.address for rule in rules}


def test_a_source_that_does_not_resolve_fails_the_install() -> None:
    with pytest.raises(RuntimeError, match="did not resolve"):
        l3.allow_rules(
            _policy(sources=(SourceAllow(id="crtsh", hosts=("crt.sh",), ports=(443,)),)),
            StubResolver({}).resolve,
        )


def test_a_private_target_stays_allowed_but_a_private_source_does_not() -> None:
    stub = StubResolver({"intranet.example": ["10.1.2.3"]})
    policy = _policy(
        targets=("10.9.9.9",),
        ports=(8080,),
        sources=(SourceAllow(id="intranet", hosts=("intranet.example",), ports=(443,)),),
    )
    rules = l3.allow_rules(policy, stub.resolve)
    addresses = {rule.address for rule in rules}
    assert "10.9.9.9" in addresses  # the campaign targets it
    assert "10.1.2.3" not in addresses  # a private source is not a signed target


def test_the_ruleset_drops_by_default_and_allows_only_the_rules() -> None:
    policy = _policy(sources=(SourceAllow(id="crtsh", hosts=("93.184.216.34",), ports=(443,)),))
    script = l3.nft_script(l3.allow_rules(policy), uplink="eth1")
    assert "table ip aegis_l3" in script
    assert script.count("type filter hook forward priority filter; policy drop;") == 1
    assert 'oifname "eth1" masquerade' in script
    assert f"ip daddr {TARGET} tcp dport 8080 ct state new counter accept" in script
    assert "ip daddr 93.184.216.34 tcp dport 443 ct state new counter accept" in script
    # Only DNS at the gateway on the input side; no proxy port, no metadata.
    assert "udp dport 53 accept" in script and "tcp dport 53 accept" in script
    assert "169.254" not in script and "127.0.0.0" not in script


def test_an_emptied_policy_is_refused() -> None:
    with pytest.raises(RuntimeError, match="no allowed destination"):
        l3.allow_rules(_policy(targets=(), ports=()))


NFT_JSON = json.dumps(
    {
        "nftables": [
            {"metainfo": {"version": "1.1.6"}},
            {"table": {"family": "ip", "name": "aegis_l3", "handle": 1}},
            {
                "chain": {
                    "family": "ip",
                    "table": "aegis_l3",
                    "name": "forward",
                    "handle": 1,
                    "type": "filter",
                    "hook": "forward",
                    "prio": 0,
                    "policy": "drop",
                }
            },
            {
                "rule": {
                    "family": "ip",
                    "table": "aegis_l3",
                    "chain": "forward",
                    "handle": 2,
                    "expr": [
                        {
                            "match": {
                                "op": "in",
                                "left": {"ct": {"key": "state"}},
                                "right": ["established", "related"],
                            }
                        },
                        {"accept": None},
                    ],
                }
            },
            {
                "rule": {
                    "family": "ip",
                    "table": "aegis_l3",
                    "chain": "forward",
                    "handle": 3,
                    "expr": [
                        {
                            "match": {
                                "op": "==",
                                "left": {"payload": {"protocol": "ip", "field": "daddr"}},
                                "right": TARGET,
                            }
                        },
                        {
                            "match": {
                                "op": "==",
                                "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                                "right": 8080,
                            }
                        },
                        {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": "new"}},
                        {"counter": {"packets": 3, "bytes": 180}},
                        {"accept": None},
                    ],
                }
            },
            {
                "rule": {
                    "family": "ip",
                    "table": "aegis_l3",
                    "chain": "forward",
                    "handle": 4,
                    "expr": [
                        {"counter": {"packets": 2, "bytes": 120}},
                        {"drop": None},
                    ],
                }
            },
        ]
    }
)


def test_the_rule_counters_are_read_from_the_nftables_json() -> None:
    snapshot = l3.parse_nft_counters(NFT_JSON)
    assert snapshot.rules == (l3.RuleCounter(TARGET, 8080, 3, 180),)
    assert snapshot.dropped_packets == 2 and snapshot.dropped_bytes == 120


def test_a_counter_that_grew_is_audited_once() -> None:
    audit = _Audit()
    gateway = l3.L3Gateway(_policy(), audit, bind="10.97.0.2")
    gateway.sample(l3.parse_nft_counters(NFT_JSON))
    assert str(audit.records[-1]["event"]) == "denied"
    assert str(audit.records[-2]["event"]) == "flow"
    assert audit.records[-2]["dst"] == TARGET and audit.records[-2]["dport"] == 8080
    assert audit.records[-2]["packets"] == 3
    gateway.sample(l3.parse_nft_counters(NFT_JSON))
    assert len(audit.records) == 2, "unchanged counters are not re-audited"
    grown = NFT_JSON.replace('"packets": 3', '"packets": 5')
    gateway.sample(l3.parse_nft_counters(grown))
    assert str(audit.records[-1]["event"]) == "flow" and audit.records[-1]["packets"] == 2


def test_the_uplink_is_the_other_interface() -> None:
    def fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=(
                "1: lo    inet 127.0.0.1/8 scope host lo\n"
                "2: eth0    inet 10.97.0.2/24 brd 10.97.0.255 scope global eth0\n"
                "3: eth1    inet 10.89.0.5/24 brd 10.89.0.255 scope global eth1\n"
            ),
            stderr="",
        )

    assert l3.uplink_interface("10.97.0.2", run=fake_run) == "eth1"


def test_an_unclear_uplink_fails_closed() -> None:
    def fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=[], returncode=0, stdout="1: eth0 inet 10.97.0.2/24 scope global eth0\n", stderr=""
        )

    with pytest.raises(RuntimeError, match="expected exactly one uplink"):
        l3.uplink_interface("10.97.0.2", run=fake_run)


class _Audit:
    def __init__(self) -> None:
        self.records: list[dict[str, object]] = []

    def write_l3(self, record: dict[str, object]) -> None:
        self.records.append(record)


def test_an_l3_job_is_refused_without_a_deployment_hook(tmp_path: Path) -> None:
    """The hook is deployment data: no hook configured, or a missing/non-executable one = refuse."""
    from aegis.common.ports import ContainerSpec
    from aegis.m06_runner.podman import PodmanRunner, RunnerError

    spec = ContainerSpec(
        job_id="job-1",
        image_digest="sha256:" + "a" * 64,
        args=["true"],
        cpu=1.0,
        memory_mb=64,
        timeout_seconds=10,
        max_output_bytes=1024,
        network="exec",
        egress_mode="l3",
    )
    runner = PodmanRunner(base_dir=tmp_path)
    with pytest.raises(RunnerError, match="route hook"):
        runner._write_l3_hook(spec)
    runner.l3_hook = tmp_path / "missing-hook"
    with pytest.raises(RunnerError, match="missing or not executable"):
        runner._write_l3_hook(spec)
    hook = tmp_path / "hook.sh"
    hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    hook.chmod(0o644)
    runner.l3_hook = hook
    with pytest.raises(RunnerError, match="missing or not executable"):
        runner._write_l3_hook(spec)


def test_the_l3_ruleset_carries_the_roe_caps_per_destination() -> None:
    """F2: the L3 channel caps by destination address (not per port) via dynamic sets/meters."""
    policy = _policy(
        sources=(SourceAllow(id="crtsh", hosts=("93.184.216.34",), ports=(80, 443)),),
        rps=1.0,
        max_connections=2,
    )
    script = l3.nft_script(
        l3.allow_rules(policy),
        uplink="eth1",
        rate_per_second=policy.per_host_rps,
        max_connections=policy.per_host_max_connections,
    )
    assert "set rl4" in script and "set cc4" in script
    rl_rule = (
        "ip daddr @allowed4 ct state new update @rl4 "
        "{ ip daddr limit rate over 60/minute } counter drop"
    )
    cc_rule = "ip daddr @allowed4 ct state new add @cc4 { ip daddr ct count over 2 } counter drop"
    assert script.count(rl_rule) == 1
    assert script.count(cc_rule) == 1
    # Both ports share one meter evaluated before either accept rule.
    assert script.index(cc_rule) < script.index("ip daddr 93.184.216.34 tcp dport 80")
    assert script.index(cc_rule) < script.index("ip daddr 93.184.216.34 tcp dport 443")
    assert "tcp dport 80 ct state new limit" not in script
    assert "tcp dport 443 ct state new limit" not in script
    assert l3.per_minute_cap(0.5) == 30
    assert l3.per_minute_cap(2.5) == 150
    assert l3.per_minute_cap(None) is None


def test_l3_ruleset_emits_ip6_meters_and_sums_meter_drops() -> None:
    policy = _policy(
        targets=("2001:db8::10",),
        ports=(80, 443),
        rps=1.0,
        max_connections=3,
    )
    script = l3.nft_script(
        l3.allow_rules(policy),
        uplink="eth1",
        rate_per_second=policy.per_host_rps,
        max_connections=policy.per_host_max_connections,
    )
    assert "table ip6 aegis_l3" in script
    assert "set rl6" in script and "set cc6" in script
    rl6_rule = (
        "ip6 daddr @allowed6 ct state new update @rl6 "
        "{ ip6 daddr limit rate over 60/minute } counter drop"
    )
    cc6_rule = (
        "ip6 daddr @allowed6 ct state new add @cc6 { ip6 daddr ct count over 3 } counter drop"
    )
    assert script.count(rl6_rule) == 1
    assert script.count(cc6_rule) == 1
    assert script.index(cc6_rule) < script.index("ip6 daddr 2001:db8::10 tcp dport 80")

    doc = json.dumps(
        {
            "nftables": [
                {
                    "rule": {
                        "chain": "forward",
                        "expr": [{"counter": {"packets": 5, "bytes": 300}}, {"drop": None}],
                    }
                },
                {
                    "rule": {
                        "chain": "forward",
                        "expr": [{"counter": {"packets": 2, "bytes": 120}}, {"drop": None}],
                    }
                },
            ]
        }
    )
    snapshot = l3.parse_nft_counters(doc)
    assert snapshot.dropped_packets == 7 and snapshot.dropped_bytes == 420
