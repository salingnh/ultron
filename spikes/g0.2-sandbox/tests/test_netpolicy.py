"""Policy unit tests: the egress decision must be fail-closed."""

from __future__ import annotations

import pytest

from aegis_g02 import netpolicy


class FakeResolver:
    def __init__(self, table: dict[str, list[str]]):
        self.table = table

    def resolve(self, host: str) -> list[str]:
        return self.table.get(host, [])


def policy(**kwargs) -> netpolicy.JobEgressPolicy:
    base = dict(
        job_id="job-1",
        mode="egress",
        target_ips=(netpolicy.ipaddress.ip_network("192.0.2.10/32"),),
        target_ports=(443, 80),
    )
    base.update(kwargs)
    return netpolicy.JobEgressPolicy(**base)


def decide(host, port=443, resolver=None, **kwargs):
    return netpolicy.decide(policy(**kwargs), host, port, resolver=resolver)


@pytest.mark.parametrize(
    "address,reason",
    [
        ("127.0.0.1", netpolicy.Reason.DENY_LOOPBACK),
        ("127.0.0.53", netpolicy.Reason.DENY_LOOPBACK),
        ("0.0.0.0", netpolicy.Reason.DENY_UNSPECIFIED),
        ("169.254.169.254", netpolicy.Reason.DENY_LINK_LOCAL),
        ("224.0.0.1", netpolicy.Reason.DENY_MULTICAST),
        ("::1", netpolicy.Reason.DENY_LOOPBACK),
        ("::", netpolicy.Reason.DENY_UNSPECIFIED),
        ("fe80::1", netpolicy.Reason.DENY_LINK_LOCAL),
        ("fd00:ec2::254", netpolicy.Reason.DENY_RESERVED),
        ("::ffff:127.0.0.1", netpolicy.Reason.DENY_LOOPBACK),
        ("::ffff:169.254.169.254", netpolicy.Reason.DENY_LINK_LOCAL),
    ],
)
def test_always_denied_even_when_bound(address, reason):
    decision = decide(
        address, target_ips=(netpolicy.ipaddress.ip_network("0.0.0.0/0"),), target_ports=(443,)
    )
    assert not decision.allowed
    assert decision.reason == reason


def test_nat64_and_6to4_embedded_ipv4_are_checked():
    assert (
        netpolicy.is_denied_address(netpolicy.ipaddress.ip_address("64:ff9b::7f00:1"))
        is netpolicy.Reason.DENY_LOOPBACK
    )
    assert (
        netpolicy.is_denied_address(netpolicy.ipaddress.ip_address("2002:7f00:1::1"))
        is netpolicy.Reason.DENY_LOOPBACK
    )
    assert netpolicy.is_denied_address(netpolicy.ipaddress.ip_address("2001:0:7f00:1::1")) is not None


def test_allowed_when_bound_to_job_target():
    decision = decide(
        "192.0.2.10", resolver=FakeResolver({"cdn.acme-lab.example": ["192.0.2.10"]})
    )
    assert decision.allowed and decision.pinned == "192.0.2.10"


def test_unbound_address_denied():
    decision = decide("192.0.2.99")
    assert decision.reason is netpolicy.Reason.NOT_BOUND_TO_JOB


def test_port_not_allowed():
    decision = decide("192.0.2.10", port=5432)
    assert decision.reason is netpolicy.Reason.PORT_NOT_ALLOWED


def test_platform_cidr_denied_even_if_bound():
    decision = decide(
        "192.0.2.10", platform_cidrs=(netpolicy.ipaddress.ip_network("192.0.2.0/24"),)
    )
    assert decision.reason is netpolicy.Reason.DENY_PLATFORM_NETWORK


def test_target_denylist_denied_even_if_bound():
    decision = decide(
        "192.0.2.10", deny_cidrs=(netpolicy.ipaddress.ip_network("192.0.2.0/28"),)
    )
    assert decision.reason is netpolicy.Reason.DENY_TARGET_DENYLIST


def test_rebinding_answer_with_one_denied_address_denies_the_name():
    resolver = FakeResolver({"rebind.acme-lab.example": ["192.0.2.10", "127.0.0.1"]})
    decision = decide("rebind.acme-lab.example", resolver=resolver)
    assert not decision.allowed
    assert decision.reason is netpolicy.Reason.DENY_LOOPBACK


def test_answer_outside_binding_denies_the_name():
    resolver = FakeResolver({"mixed.acme-lab.example": ["192.0.2.10", "192.0.2.99"]})
    decision = decide("mixed.acme-lab.example", resolver=resolver)
    assert decision.reason is netpolicy.Reason.NOT_BOUND_TO_JOB


def test_resolution_failure_is_deny_not_allow():
    decision = decide("nxdomain.acme-lab.example", resolver=FakeResolver({}))
    assert decision.reason is netpolicy.Reason.RESOLVE_FAILED


def test_too_many_answers_denied():
    resolver = FakeResolver(
        {"many.acme-lab.example": [f"192.0.2.{i}" for i in range(10)]}
    )
    decision = decide("many.acme-lab.example", resolver=resolver)
    assert decision.reason is netpolicy.Reason.RESOLVED_TOO_MANY


def test_declared_source_allows_its_host_only():
    source = netpolicy.SourceAllow(
        id="crt.sh",
        hosts=("crt.sh",),
        ports=(443,),
        addresses=(netpolicy.ipaddress.ip_network("192.0.2.80/32"),),
    )
    pol = policy(sources=(source,))
    ok = netpolicy.decide(
        pol, "crt.sh", 443, resolver=FakeResolver({"crt.sh": ["192.0.2.80"]})
    )
    assert ok.allowed and ok.source_id == "crt.sh"
    wrong_port = netpolicy.decide(
        pol, "crt.sh", 25, resolver=FakeResolver({"crt.sh": ["192.0.2.80"]})
    )
    assert wrong_port.reason is netpolicy.Reason.PORT_NOT_ALLOWED
    other_host = netpolicy.decide(
        pol, "evil.example", 443, resolver=FakeResolver({"evil.example": ["192.0.2.80"]})
    )
    assert other_host.reason is netpolicy.Reason.NOT_BOUND_TO_JOB


def test_network_none_denies_everything():
    decision = netpolicy.decide(policy(mode="none"), "192.0.2.10", 443)
    assert decision.reason is netpolicy.Reason.EGRESS_DISABLED
