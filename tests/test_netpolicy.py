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
        self.asked: list[str] = []

    def resolve(self, host: str) -> list[str]:
        self.asked.append(host)
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
    # R2: a name that is not a bound source/target name is refused before any lookup, so the
    # resolver is never asked about it (it would be a DNS channel out of the sandbox).
    assert decide(policy, "evil.test", 443, resolver=resolver).reason is Reason.NOT_BOUND_TO_JOB
    assert resolver.asked == ["crt.sh"]


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
        # R2: the tool dials a name, so the name must be in the signed DNS binding too.
        dns_names=("a.example",),
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
        dns_names=("a.example",),
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


# --- internet profile (G1.6) -----------------------------------------------------------------

PRIVATE = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")


def _internet(
    *hosts: str, targets: tuple[str, ...] = (), private: tuple[str, ...] = ()
) -> JobEgressPolicy:
    return JobEgressPolicy(
        job_id="job-1",
        profile="internet",
        sources=(SourceAllow(id="crtsh", hosts=hosts, ports=(443,)),),
        target_ips=tuple(ipaddress.ip_network(f"{address}/32") for address in targets),
        private_cidrs=tuple(ipaddress.ip_network(entry) for entry in PRIVATE),
        authorized_private_cidrs=tuple(ipaddress.ip_network(entry) for entry in private),
    )


def test_a_private_answer_is_denied_on_the_internet_profile() -> None:
    policy = _internet("intranet.example")
    resolver = StubResolver({"intranet.example": ["10.1.2.3"]})
    decision = decide(policy, "intranet.example", 443, resolver=resolver)
    assert decision.reason is Reason.DENY_PRIVATE
    assert decision.resolved == ("10.1.2.3",)
    # An IPv6 ULA is the same rule, not a second code path.
    resolver6 = StubResolver({"intranet.example": ["fd00::10"]})
    assert decide(policy, "intranet.example", 443, resolver=resolver6).reason is Reason.DENY_PRIVATE


def test_a_private_address_inside_a_roe_private_seed_is_allowed() -> None:
    # R4: a private address is reachable only when the RoE lists the private seed CIDR that covers
    # it (signed as `authorized_private_cidrs`), not merely because the address is a signed target.
    policy = _internet("internal.example", targets=("10.1.2.3",), private=("10.1.2.0/24",))
    resolver = StubResolver({"internal.example": ["10.1.2.3"]})
    decision = decide(policy, "internal.example", 443, resolver=resolver)
    assert decision.allowed and decision.pinned == "10.1.2.3"


def test_a_signed_private_target_without_a_roe_private_seed_is_denied() -> None:
    # The old rule exempted every signed target address, so a name that resolved into the owner's
    # LAN was reachable once M05 signed it. Only the RoE's own listing exempts a private address.
    policy = _internet("internal.example", targets=("10.1.2.3",))
    resolver = StubResolver({"internal.example": ["10.1.2.3"]})
    assert decide(policy, "internal.example", 443, resolver=resolver).reason is Reason.DENY_PRIVATE


def test_the_lab_profile_keeps_private_ranges_reachable_when_bound() -> None:
    # A lab job runs on the lab network; `private_cidrs` is empty there, so the G1.5c behaviour is
    # unchanged and a signed binding is still required.
    policy = JobEgressPolicy(
        job_id="job-1",
        profile="lab",
        sources=(SourceAllow(id="lab", hosts=("crt.sh",), ports=(443,)),),
    )
    resolver = StubResolver({"crt.sh": ["10.114.53.80"]})
    assert decide(policy, "crt.sh", 443, resolver=resolver).allowed


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ({"job_id": "job-1"}, "profile"),
        ({"job_id": "job-1", "profile": "dmz"}, "unknown network profile"),
    ],
)
def test_a_policy_document_without_a_valid_profile_is_refused(
    document: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        netpolicy.load_policy(document)


def test_the_policy_document_carries_the_profile_caps_and_authorization() -> None:
    policy = JobEgressPolicy(
        job_id="job-1",
        profile="internet",
        campaign_id="01934f6a-0000-7000-8000-000000000001",
        authorization="owner, item 61, 2026-11-25",
        private_cidrs=(ipaddress.ip_network("10.0.0.0/8"),),
        per_host_rps=0.5,
        per_host_max_connections=1,
    )
    document = netpolicy.policy_document(policy)
    assert document["profile"] == "internet"
    assert document["authorization"] == "owner, item 61, 2026-11-25"
    assert netpolicy.load_policy(document) == policy
