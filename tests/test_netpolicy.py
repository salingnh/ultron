"""The per-job egress decision engine (S1.5a §Sandbox; findings R-5 and E-1).

Pure unit tests: one stub resolver returns fixed answers, so every scenario (rebinding answer,
unbound name, embedded IPv4) is deterministic and needs no network.
"""

from __future__ import annotations

import ipaddress

import pytest

from aegis.m06_runner import netpolicy
from aegis.m06_runner.netpolicy import JobEgressPolicy, Reason, Resolver, SourceAllow, decide


class StubResolver(Resolver):
    def __init__(self, answers: dict[str, list[str]]) -> None:
        self.answers = answers

    def resolve(self, host: str) -> list[str]:
        return list(self.answers.get(host, []))


def _source_only(*hosts: str, ports: tuple[int, ...] = (443,)) -> JobEgressPolicy:
    return JobEgressPolicy(
        job_id="job-1",
        sources=(
            SourceAllow(
                id="crtsh",
                hosts=hosts,
                ports=ports,
            ),
        ),
    )


def test_egress_disabled_denies_everything() -> None:
    policy = JobEgressPolicy(job_id="job-1", mode="none")
    assert decide(policy, "crt.sh", 443).reason is Reason.EGRESS_DISABLED


def test_declared_source_is_allowed_and_pinned() -> None:
    policy = _source_only("crt.sh")
    resolver = StubResolver({"crt.sh": ["93.184.216.34"]})
    decision = decide(policy, "crt.sh", 443, resolver=resolver)
    assert decision.allowed
    assert decision.pinned == "93.184.216.34"
    assert decision.source_id == "crtsh"
    assert decision.as_audit()["decision"] == "allow"


def test_source_binding_is_per_host_and_port() -> None:
    policy = _source_only("crt.sh")
    resolver = StubResolver({"crt.sh": ["93.184.216.34"], "evil.test": ["93.184.216.34"]})
    assert decide(policy, "crt.sh", 8443, resolver=resolver).reason is Reason.PORT_NOT_ALLOWED
    assert decide(policy, "evil.test", 443, resolver=resolver).reason is Reason.PORT_NOT_ALLOWED


def test_any_answer_in_the_deny_set_denies_the_name() -> None:
    # DNS rebinding: one denied answer is enough, the good answer does not rescue the name.
    policy = _source_only("crt.sh")
    resolver = StubResolver({"crt.sh": ["93.184.216.34", "127.0.0.1"]})
    decision = decide(policy, "crt.sh", 443, resolver=resolver)
    assert not decision.allowed
    assert decision.reason is Reason.DENY_LOOPBACK
    assert decision.resolved == ("93.184.216.34", "127.0.0.1")


def test_deny_set_wins_over_a_bound_target() -> None:
    policy = JobEgressPolicy(
        job_id="job-1",
        target_ips=(ipaddress.ip_network("127.0.0.1/32"),),
        target_ports=(8080,),
    )
    decision = decide(policy, "127.0.0.1", 8080)
    assert not decision.allowed
    assert decision.reason is Reason.DENY_LOOPBACK


def test_target_binding_allows_only_resolved_targets() -> None:
    policy = JobEgressPolicy(
        job_id="job-1",
        target_ips=(ipaddress.ip_network("10.1.2.3/32"),),
        target_ports=(8080,),
    )
    resolver = StubResolver({"a.example": ["10.1.2.3"]})
    assert decide(policy, "a.example", 8080, resolver=resolver).allowed
    assert decide(policy, "10.1.2.3", 8080).allowed
    assert decide(policy, "a.example", 8081, resolver=resolver).reason is Reason.PORT_NOT_ALLOWED
    outside = StubResolver({"a.example": ["10.1.2.4"]})
    assert decide(policy, "a.example", 8080, resolver=outside).reason is Reason.NOT_BOUND_TO_JOB


def test_foreign_answer_for_a_bound_name_is_refused() -> None:
    policy = JobEgressPolicy(
        job_id="job-1",
        target_ips=(ipaddress.ip_network("10.1.2.3/32"),),
        target_ports=(8080,),
    )
    resolver = StubResolver({"a.example": ["10.1.2.3", "10.9.9.9"]})
    assert decide(policy, "a.example", 8080, resolver=resolver).reason is Reason.NOT_BOUND_TO_JOB


def test_pinned_source_addresses_narrow_the_answer_set() -> None:
    policy = JobEgressPolicy(
        job_id="job-1",
        sources=(
            SourceAllow(
                id="crtsh",
                hosts=("crt.sh",),
                ports=(443,),
                addresses=(ipaddress.ip_network("93.184.216.34/32"),),
            ),
        ),
    )
    good = StubResolver({"crt.sh": ["93.184.216.34"]})
    bad = StubResolver({"crt.sh": ["203.0.113.5"]})
    assert decide(policy, "crt.sh", 443, resolver=good).allowed
    assert decide(policy, "crt.sh", 443, resolver=bad).reason is Reason.NOT_BOUND_TO_JOB


def test_platform_network_and_campaign_denylist() -> None:
    policy = JobEgressPolicy(
        job_id="job-1",
        sources=(SourceAllow(id="api", hosts=("api.example",), ports=(443,)),),
        platform_cidrs=(ipaddress.ip_network("10.88.0.0/16"),),
        deny_cidrs=(ipaddress.ip_network("10.50.0.0/16"),),
    )
    platform = StubResolver({"api.example": ["10.88.1.5"]})
    denied = StubResolver({"api.example": ["10.50.1.5"]})
    assert (
        decide(policy, "api.example", 443, resolver=platform).reason is Reason.DENY_PLATFORM_NETWORK
    )
    assert decide(policy, "api.example", 443, resolver=denied).reason is Reason.DENY_TARGET_DENYLIST


def test_resolution_failures_are_denies() -> None:
    policy = _source_only("crt.sh")
    assert decide(policy, "crt.sh", 443, resolver=StubResolver({})).reason is Reason.RESOLVE_FAILED
    flood = StubResolver({"crt.sh": [f"192.0.2.{index}" for index in range(20)]})
    assert decide(policy, "crt.sh", 443, resolver=flood).reason is Reason.RESOLVED_TOO_MANY


def test_literal_deny_forms_are_recognised_without_dns() -> None:
    policy = _source_only("localhost")
    for literal, reason in (
        ("127.1", Reason.DENY_LOOPBACK),
        ("2130706433", Reason.DENY_LOOPBACK),
        ("0x7f000001", Reason.DENY_LOOPBACK),
        ("::7f00:1", Reason.DENY_RESERVED),
        ("fec0::1", Reason.DENY_RESERVED),
        ("fd00:ec2::254", Reason.DENY_METADATA),
        ("100.100.100.200", Reason.DENY_METADATA),
        ("fe80::1", Reason.DENY_LINK_LOCAL),
    ):
        decision = decide(policy, literal, 443)
        assert decision.reason is reason, literal


def test_policy_document_round_trip() -> None:
    policy = JobEgressPolicy(
        job_id="job-1",
        target_ips=(ipaddress.ip_network("10.1.2.3/32"),),
        target_ports=(8080,),
        sources=(SourceAllow(id="crtsh", hosts=("crt.sh",), ports=(443,)),),
        platform_cidrs=(ipaddress.ip_network("10.88.0.0/16"),),
        deny_cidrs=(ipaddress.ip_network("10.50.0.0/16"),),
    )
    reloaded = netpolicy.load_policy(netpolicy.policy_document(policy))
    assert reloaded == policy
    assert reloaded.binding_hosts == policy.binding_hosts
    assert "crt.sh:443" in reloaded.binding_hosts


def test_binding_hosts_names_target_addresses_and_sources() -> None:
    policy = JobEgressPolicy(
        job_id="job-1",
        target_ips=(ipaddress.ip_network("10.1.2.3/32"),),
        target_ports=(8080, 8443),
        sources=(SourceAllow(id="crtsh", hosts=("crt.sh",), ports=(443,)),),
    )
    assert set(policy.binding_hosts) == {"10.1.2.3:8080", "10.1.2.3:8443", "crt.sh:443"}


def test_invalid_port_is_refused() -> None:
    policy = _source_only("crt.sh")
    assert decide(policy, "crt.sh", 0).reason is Reason.PORT_NOT_ALLOWED
    assert decide(policy, "crt.sh", 70000).reason is Reason.PORT_NOT_ALLOWED


@pytest.mark.parametrize("host", ["metadata.google.internal", "instance-data"])
def test_declared_metadata_names_are_denied_at_runtime(host: str) -> None:
    policy = _source_only(host)
    resolver = StubResolver({host: ["169.254.169.254"]})
    assert decide(policy, host, 443, resolver=resolver).reason is Reason.DENY_METADATA
