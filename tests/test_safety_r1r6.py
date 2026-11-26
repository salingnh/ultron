"""Regressions of the second internet-egress safety review (item #61, findings R1-R6).

Each test is the reviewer's re-verification probe turned into an assertion, one block per finding:

* R1 the L3 rule builder and `build_policy` apply the platform/deny sets to signed targets, and the
  platform set is a per-task snapshot, not a per-process one;
* R2 the broker checks that a name is bound before it resolves it;
* R3 M05 normalises IPv4-mapped/SIIT targets and signs the IPv4 form;
* R4 a private target needs a private *seed* CIDR the RoE lists, at M05 and at M06;
* R5 a CNAME lookup failure refuses the target instead of signing it;
* R6 M06 validates the structured authorization, not a rendered string.

Requirement 7 (every resolver stubbed) is enforced by the autouse guard in `conftest.py`; the last
block asserts that guard itself works.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Any

import pytest

from aegis.common import dns_cname
from aegis.common import platform as platform_set
from aegis.m05_registry import egress as m05_egress
from aegis.m05_registry.errors import M05Error
from aegis.m05_registry.service import PostgresJobService
from aegis.m06_runner import l3, netpolicy
from aegis.m06_runner.authorization import Authorization, authorization_of
from aegis.m06_runner.netpolicy import JobEgressPolicy, Resolver, SourceAllow
from aegis.m06_runner.spec import SpecError

from . import m06_support

INTERNET = "internet"


# --- helpers --------------------------------------------------------------------------------


class RecordingResolver(Resolver):
    def __init__(self, answers: dict[str, list[str]] | None = None) -> None:
        self.answers = answers or {}
        self.asked: list[str] = []

    def resolve(self, host: str) -> list[str]:
        self.asked.append(host)
        return list(self.answers.get(host, []))


def _l3_policy(
    target: str,
    *,
    platform: tuple[str, ...] = (),
    deny: tuple[str, ...] = (),
    private: tuple[str, ...] = (),
) -> JobEgressPolicy:
    return JobEgressPolicy(
        job_id="job-r1",
        egress_mode="l3",
        profile=INTERNET,
        target_ips=(ipaddress.ip_network(f"{target}/32"),),
        target_ports=(80, 443),
        platform_cidrs=tuple(ipaddress.ip_network(entry) for entry in platform),
        deny_cidrs=tuple(ipaddress.ip_network(entry) for entry in deny),
        private_cidrs=tuple(ipaddress.ip_network(entry) for entry in ("10.0.0.0/8", "fc00::/7")),
        authorized_private_cidrs=tuple(ipaddress.ip_network(entry) for entry in private),
    )


def _bound_task(
    addresses: list[str],
    ports: list[int],
    *,
    refs: list[str] | None = None,
    extra_binding: dict[str, Any] | None = None,
) -> tuple[Any, Any, bytes]:
    """A signed internet task whose binding M05 would produce for `addresses`."""
    manifest, raw = m06_support.target_bound_manifest()
    task_refs = refs or [f"ip:{address}" for address in addresses]
    entries = sorted(
        f"{ipaddress.ip_address(address)}:{port}" for address in addresses for port in ports
    )
    binding: dict[str, Any] = {
        "mode": "broker",
        "target_binding": "required",
        "entries": entries,
        "target_addresses": sorted(addresses),
    }
    binding.update(extra_binding or {})
    task = m06_support.task_for_manifest(
        manifest,
        raw,
        network_profile=INTERNET,
        targets=[{"canonical_key": reference} for reference in task_refs],
        input={
            "targets": task_refs,
            "ports": ports,
            "packets_per_second": 100,
            "concurrency": 1,
        },
        egress_binding=binding,
    )
    return task, manifest, raw


def _input(addresses: list[str], ports: list[int], refs: list[str] | None = None) -> dict[str, Any]:
    return {
        "targets": refs or [f"ip:{address}" for address in addresses],
        "ports": ports,
        "packets_per_second": 100,
        "concurrency": 1,
    }


# --- R1: the L3 allow set and build_policy apply the deny sets to signed targets ---------------


def test_l3_refuses_a_signed_target_inside_the_platform_deny_set() -> None:
    policy = _l3_policy("10.231.1.10", platform=("10.231.1.0/24",))
    with pytest.raises(RuntimeError, match="platform network"):
        l3.allow_rules(policy)


def test_l3_refuses_a_signed_target_inside_the_campaign_denylist() -> None:
    policy = _l3_policy("203.0.113.10", deny=("203.0.113.0/24",))
    with pytest.raises(RuntimeError, match="denylist"):
        l3.allow_rules(policy)


def test_l3_refuses_a_signed_private_target_outside_the_roe_private_seed() -> None:
    policy = _l3_policy("10.1.2.3")
    with pytest.raises(RuntimeError):
        l3.allow_rules(policy)
    allowed = _l3_policy("10.1.2.3", private=("10.1.2.0/24",))
    assert [rule.address for rule in l3.allow_rules(allowed)] == ["10.1.2.3", "10.1.2.3"]


def test_build_policy_refuses_a_signed_target_inside_the_platform_deny_set() -> None:
    # A stale or forged M05 signed a platform address: M06 must not install a rule for it, even
    # though the broker would deny the connection again at request time (the L3 channel would not).
    task, manifest, raw = _bound_task(["10.231.1.10"], [5432])
    with pytest.raises(SpecError, match="platform deny set") as caught:
        m06_support.build_policy_for(
            task,
            manifest,
            raw,
            platform_cidrs=("10.231.1.0/24",),
            input_values=_input(["10.231.1.10"], [5432]),
        )
    assert caught.value.code == "POLICY_DENIED"


def test_build_policy_refuses_a_signed_target_inside_the_campaign_denylist() -> None:
    task, manifest, raw = _bound_task(["203.0.113.10"], [80])
    with pytest.raises(SpecError, match="target_denylist"):
        m06_support.build_policy_for(
            task,
            manifest,
            raw,
            target_denylist=("203.0.113.0/24",),
            input_values=_input(["203.0.113.10"], [80]),
        )


def _platform_run(
    monkeypatch: pytest.MonkeyPatch, networks: list[dict[str, Any]], host: str
) -> None:
    def run(argv: list[str], **_kwargs: object) -> str:
        if argv[:3] == [platform_set.PODMAN, "network", "ls"]:
            return "\n".join(str(item["name"]) for item in networks) + "\n"
        if argv[:3] == [platform_set.PODMAN, "network", "inspect"]:
            return json.dumps(networks)
        if argv[:2] == [platform_set.IP, "-o"]:
            return host
        raise AssertionError(argv)

    monkeypatch.setattr(platform_set, "_run", run)


def test_the_runner_reads_the_platform_set_again_for_every_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aegis.m06_runner.loop import LoopConfig

    networks: list[dict[str, Any]] = [
        {"name": "dev", "labels": {}, "subnets": [{"subnet": "10.89.0.0/24"}]}
    ]
    _platform_run(
        monkeypatch,
        networks,
        "2: eth0    inet 172.16.8.88/22 brd 172.16.11.255 scope global eth0\n",
    )
    config = LoopConfig(dsn="postgresql://unused", base_dir=__import__("pathlib").Path("/tmp/x"))
    assert "10.231.1.0/24" not in config.platform_deny_set()[0]
    # A network created after the process started (vulnlab-up, a new compose project) is denied for
    # the next job: the set is not the start-up snapshot (R1).
    networks.append({"name": "late", "labels": {}, "subnets": [{"subnet": "10.231.1.0/24"}]})
    cidrs, error = config.platform_deny_set()
    assert error == "" and "10.231.1.0/24" in cidrs


def test_m05_reads_the_platform_set_again_for_every_task(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Registry:
        pass

    networks: list[dict[str, Any]] = [
        {"name": "dev", "labels": {}, "subnets": [{"subnet": "10.89.0.0/24"}]}
    ]
    _platform_run(
        monkeypatch,
        networks,
        "2: eth0    inet 172.16.8.88/22 brd 172.16.11.255 scope global eth0\n",
    )
    service = PostgresJobService(
        lambda: (_ for _ in ()).throw(AssertionError("no database in this test")),
        registry=_Registry(),  # type: ignore[arg-type]
        key_ring=m06_support.ANY_RING,
        platform_env={},
    )
    assert "10.231.1.0/24" not in service._platform_deny_set()[0]
    networks.append({"name": "late", "labels": {}, "subnets": [{"subnet": "10.231.1.0/24"}]})
    cidrs, error = service._platform_deny_set()
    assert error == "" and "10.231.1.0/24" in cidrs


# --- R2: no resolution of a name the job is not bound to ---------------------------------------


def test_the_broker_refuses_an_unbound_name_before_resolving_it() -> None:
    policy = JobEgressPolicy(
        job_id="job-r2",
        profile=INTERNET,
        sources=(SourceAllow(id="crtsh", hosts=("crt.sh",), ports=(443,)),),
        dns_names=("bound.example",),
    )
    resolver = RecordingResolver({"exfil.attacker.example": ["203.0.113.9"]})
    decision = netpolicy.decide(policy, "exfil.attacker.example", 80, resolver=resolver)
    assert decision.reason is netpolicy.Reason.NOT_BOUND_TO_JOB
    assert resolver.asked == []  # nothing left the broker: the DNS exfil path is closed

    # A bound name (declared source) is resolved, as before.
    resolver = RecordingResolver({"crt.sh": ["93.184.216.34"]})
    assert netpolicy.decide(policy, "crt.sh", 443, resolver=resolver).allowed
    assert resolver.asked == ["crt.sh"]


# --- R3: M05 normalises mapped/SIIT targets and signs the IPv4 form ---------------------------


def _binding_for(address: str, *, platform: tuple[str, ...] = ()) -> m05_egress.EgressBinding:
    record = m06_support.record("manifest.naabu.yaml")
    return m05_egress.build_egress_binding(
        record,
        merged_input={"targets": [address], "ports": [443]},
        targets=m06_support.resolved_targets(record, [address]),
        binder=m06_support.StaticBinder({}),
        network_profile=INTERNET,
        platform_cidrs=platform,
        # An `ip:` target must be active-eligible (F3): the test campaign seeded the documentation
        # range its addresses come from.
        provenance=m05_egress.ActiveProvenance(
            seed_networks=(ipaddress.ip_network("203.0.113.0/24"),)
        ),
    )


def test_m05_signs_the_ipv4_form_of_a_mapped_target() -> None:
    binding = _binding_for("::ffff:203.0.113.7")
    assert binding.target_addresses == ("203.0.113.7",)
    assert binding.entries == ("203.0.113.7:443",)


def test_m05_checks_a_mapped_target_as_ipv4_against_the_platform_set() -> None:
    with pytest.raises(M05Error) as caught:
        _binding_for("::ffff:10.231.1.10", platform=("10.231.1.0/24",))
    assert caught.value.refusal.rule == "target_platform_network"


def test_m05_refuses_a_siit_target() -> None:
    with pytest.raises(M05Error) as caught:
        _binding_for("::ffff:0:cb00:7107")
    assert caught.value.refusal.rule == "target_reserved_network"


# --- R4: a private target needs a private seed CIDR the RoE lists -----------------------------


def _private_binding(seeds: tuple[str, ...] = ()) -> m05_egress.EgressBinding:
    record = m06_support.record("manifest.naabu.yaml")
    return m05_egress.build_egress_binding(
        record,
        merged_input={"targets": ["192.168.77.5"], "ports": [443]},
        targets=m06_support.resolved_targets(record, ["192.168.77.5"]),
        binder=m06_support.StaticBinder({}),
        network_profile=INTERNET,
        provenance=m05_egress.ActiveProvenance(
            seed_networks=tuple(ipaddress.ip_network(seed) for seed in seeds),
            by_address={"192.168.77.5": (m05_egress.DomainProvenance(name="db.internal.example"),)},
        ),
        authorized_suffixes=("internal.example",),
    )


def test_m05_refuses_a_private_target_the_roe_did_not_seed() -> None:
    with pytest.raises(M05Error) as caught:
        _private_binding()
    assert caught.value.refusal.rule == "target_private_network"
    # A seed that is not itself private does not authorize a private address either.
    with pytest.raises(M05Error) as caught:
        _private_binding(seeds=("203.0.113.0/24",))
    assert caught.value.refusal.rule == "target_private_network"


def test_m05_signs_a_private_target_and_the_seed_cidr_that_covers_it() -> None:
    binding = _private_binding(seeds=("192.168.0.0/16",))
    assert binding.target_addresses == ("192.168.77.5",)
    assert binding.authorized_private_cidrs == ("192.168.0.0/16",)


def test_build_policy_refuses_a_signed_private_target_without_a_roe_seed() -> None:
    task, manifest, raw = _bound_task(["192.168.77.5"], [443])
    with pytest.raises(SpecError, match="private seed CIDR") as caught:
        m06_support.build_policy_for(
            task, manifest, raw, input_values=_input(["192.168.77.5"], [443])
        )
    assert caught.value.code == "POLICY_DENIED"


def test_build_policy_refuses_a_signed_private_cidr_that_is_not_private() -> None:
    task, manifest, raw = _bound_task(
        ["203.0.113.10"],
        [443],
        extra_binding={"authorized_private_cidrs": ["0.0.0.0/0"]},
    )
    with pytest.raises(SpecError, match="not a private range"):
        m06_support.build_policy_for(
            task, manifest, raw, input_values=_input(["203.0.113.10"], [443])
        )


def test_a_private_target_with_the_signed_seed_is_reachable_inside_it_only() -> None:
    task, manifest, raw = _bound_task(
        ["192.168.77.5"],
        [443],
        extra_binding={"authorized_private_cidrs": ["192.168.0.0/16"]},
    )
    policy = m06_support.build_policy_for(
        task, manifest, raw, input_values=_input(["192.168.77.5"], [443])
    )
    assert ipaddress.ip_network("192.168.0.0/16") in policy.authorized_private_cidrs
    resolver = RecordingResolver({"db.internal.example": ["192.168.77.5"]})
    assert netpolicy.decide(policy, "192.168.77.5", 443, resolver=resolver).allowed
    # Any private address outside the signed seed stays refused (the office LAN next door).
    assert (
        netpolicy.decide(policy, "10.9.9.9", 443, resolver=resolver).reason
        is netpolicy.Reason.DENY_PRIVATE
    )


# --- R5: a CNAME lookup failure refuses the target --------------------------------------------


def test_a_cname_lookup_failure_refuses_the_target(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(_host: str) -> tuple[str, ...]:
        raise OSError("resolver unreachable")

    monkeypatch.setattr(dns_cname, "cname_chain", broken)
    record = m06_support.record("manifest.naabu.yaml")
    targets = m06_support.resolved_targets(record, ["dns:www.internal.example"])
    with pytest.raises(M05Error) as caught:
        m05_egress.build_egress_binding(
            record,
            merged_input={"targets": ["dns:www.internal.example"], "ports": [443]},
            targets=targets,
            binder=m06_support.StaticBinder({"www.internal.example": ["203.0.113.7"]}),
            network_profile=INTERNET,
            authorized_suffixes=("internal.example",),
        )
    assert caught.value.refusal.rule == "target_cname_lookup_failed"


def test_no_system_resolver_is_a_lookup_failure_not_an_empty_chain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(dns_cname, "resolver_address", lambda *_args, **_kwargs: None)
    with pytest.raises(OSError, match="no system resolver"):
        dns_cname.cname_chain("www.internal.example")


# --- R6: the structured authorization, not a rendered string ----------------------------------


def test_a_mapping_with_missing_fields_is_not_an_authorization() -> None:
    authorization, problem = authorization_of({"owner": "owner"})
    assert authorization is None and "reference" in problem
    for value, expected in (
        ({}, "owner"),
        (
            {"owner": "", "reference": "a b", "date": "2026-11-25", "authorized_suffixes": ["a"]},
            "owner",
        ),
        (
            {"owner": "o", "reference": "ref", "date": "2026-13-40", "authorized_suffixes": ["a"]},
            "date",
        ),
        (
            {"owner": "o", "reference": "ref", "date": "2026-11-25", "authorized_suffixes": []},
            "authorized_suffixes",
        ),
        (
            {
                "owner": "o",
                "reference": "ref",
                "date": "2026-11-25",
                "authorized_suffixes": ["a"],
                "extra": 1,
            },
            "unknown",
        ),
        ("owner | ref | 2026-11-25 | a", "not an object"),
        (None, "no authorization"),
    ):
        authorization, problem = authorization_of(value)
        assert authorization is None, value
        assert expected in problem, (value, problem)


def test_a_complete_authorization_renders_one_audit_line() -> None:
    authorization, problem = authorization_of(
        {
            "owner": "owner",
            "reference": "owner, item 61, 2026-11-25",
            "date": "2026-11-25",
            "authorized_suffixes": ["Internal.Example", "internal.example"],
        }
    )
    assert problem == ""
    assert isinstance(authorization, Authorization)
    assert authorization.reference_line() == (
        "owner | owner, item 61, 2026-11-25 | 2026-11-25 | internal.example"
    )


def test_build_policy_refuses_an_internet_job_without_the_structured_authorization() -> None:
    task, manifest, raw = _bound_task(["203.0.113.10"], [443])
    with pytest.raises(SpecError, match="structured authorization"):
        m06_support.build_policy_for(
            task,
            manifest,
            raw,
            authorization=None,
            input_values=_input(["203.0.113.10"], [443]),
        )


# --- requirement 7: the resolver guard ---------------------------------------------------------


def test_the_resolver_guard_stops_an_unstubbed_lookup() -> None:
    from .conftest import SystemResolverReached

    with pytest.raises(SystemResolverReached):
        __import__("socket").getaddrinfo("aegis-unstubbed.example", None)
    # A literal and a local name need no DNS and stay allowed (in-process test servers use them).
    assert __import__("socket").getaddrinfo("127.0.0.1", 1, type=__import__("socket").SOCK_STREAM)
