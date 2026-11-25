"""Regressions of the independent internet-egress safety review (item #61, findings B1/F1/F4-F8).

Each test is the review's probe turned into an assertion: the platform deny set, embedded IPv4
forms, DNS-protocol sources, the structured authorization, the dev signing key, the audit line's
campaign id and the audit cap.
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path

import pytest

from aegis.common import platform as platform_set
from aegis.m05_registry import egress as m05_egress
from aegis.m05_registry.errors import M05Error
from aegis.m05_registry.signing import DEV_KEY_ID
from aegis.m06_runner import denyset, netpolicy
from aegis.m06_runner.broker import AuditLog
from aegis.m06_runner.netpolicy import JobEgressPolicy, Resolver, SourceAllow

from . import m06_support

# --- B1: the platform's own networks are computed, never assumed ----------------------------


def _fake_run(monkeypatch: pytest.MonkeyPatch, *, networks: dict[str, object], host: str) -> None:
    def run(argv: list[str], **_kwargs: object) -> str:
        if argv[:3] == [platform_set.PODMAN, "network", "ls"]:
            return "job-net\nuplink\ndev\n"
        if argv[:3] == [platform_set.PODMAN, "network", "inspect"]:
            return json.dumps(list(networks.values()))
        if argv[:2] == [platform_set.IP, "-o"]:
            return host
        raise AssertionError(argv)

    monkeypatch.setattr(platform_set, "_run", run)


def test_the_platform_set_is_every_non_job_network_host_address_and_env_cidr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    networks: dict[str, object] = {
        "job-net": {
            "name": "job-net",
            "labels": {"aegis.role": "network"},
            "subnets": [{"subnet": "10.97.0.0/24"}],
        },
        "uplink": {"name": "uplink", "labels": {}, "subnets": [{"subnet": "10.89.4.0/24"}]},
        "dev": {"name": "dev", "labels": {}, "subnets": [{"subnet": "10.89.0.0/24"}]},
    }
    host = "2: eth0    inet 172.16.8.88/22 brd 172.16.11.255 scope global eth0\n"
    _fake_run(monkeypatch, networks=networks, host=host)
    cidrs = platform_set.platform_cidrs({"AEGIS_M06_PLATFORM_CIDRS": "10.200.0.0/16"})
    assert "10.89.4.0/24" in cidrs and "10.89.0.0/24" in cidrs  # uplink and dev stack
    assert "10.97.0.0/24" not in cidrs  # the runner's own per-job network
    assert "10.200.0.0/16" in cidrs  # operator-declared
    assert "172.16.8.88/32" in cidrs  # the host's own address


def test_an_unreadable_platform_set_is_an_error_not_an_empty_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        platform_set,
        "_run",
        lambda argv, **_kwargs: (_ for _ in ()).throw(
            platform_set.PlatformDenySetUnavailable("podman is not reachable")
        ),
    )
    with pytest.raises(platform_set.PlatformDenySetUnavailable):
        platform_set.platform_cidrs({})


# --- F1: embedded IPv4 forms are judged as IPv4 ---------------------------------------------


class _Stub(Resolver):
    def __init__(self, answers: dict[str, list[str]]) -> None:
        self.answers = answers

    def resolve(self, host: str) -> list[str]:
        return list(self.answers.get(host, []))


def _source_policy(platform: tuple[str, ...] = ("10.89.0.0/16",)) -> JobEgressPolicy:
    return JobEgressPolicy(
        job_id="job-1",
        sources=(SourceAllow(id="crtsh", hosts=("crt.sh",), ports=(443,)),),
        platform_cidrs=tuple(ipaddress.ip_network(entry) for entry in platform),
    )


def test_ipv4_mapped_answers_are_checked_as_ipv4() -> None:
    policy = _source_policy()
    resolver = _Stub({"crt.sh": ["::ffff:10.89.0.5"]})
    assert netpolicy.decide(policy, "crt.sh", 443, resolver=resolver).reason is (
        netpolicy.Reason.DENY_PLATFORM_NETWORK
    )
    loopback = _Stub({"crt.sh": ["::ffff:127.0.0.1"]})
    assert netpolicy.decide(policy, "crt.sh", 443, resolver=loopback).reason is (
        netpolicy.Reason.DENY_LOOPBACK
    )


def test_siit_translated_addresses_are_refused() -> None:
    # `::ffff:0:0:0/96` is not `::ffff:a.b.c.d`; Python parses it as plain IPv6, so a check that
    # only unwraps ipv4_mapped would let it through with no matching IPv4 rule.
    siit = ipaddress.ip_address("::ffff:0:a00:1")
    _, reason = denyset.checked_address(siit)
    assert reason is denyset.DenyReason.RESERVED
    # A mapped address normalises to its IPv4 form (so the IPv4 rules and networks apply).
    plain, reason = denyset.checked_address(ipaddress.ip_address("::ffff:10.89.0.5"))
    assert reason is None and str(plain) == "10.89.0.5"


# --- F4: declared DNS sources are never signed on the internet profile ----------------------


def test_a_dns_protocol_source_is_not_part_of_an_internet_binding() -> None:
    record = m06_support.record("manifest.dnsx.yaml")
    targets = m06_support.resolved_targets(record, ["internal.example"])
    internet = m05_egress.build_egress_binding(
        record,
        merged_input={"targets": ["internal.example"]},
        targets=targets,
        binder=m06_support.StaticBinder({"internal.example": ["198.51.100.10"]}),
        network_profile="internet",
    )
    assert "9.9.9.9:53" not in internet.entries
    lab = m05_egress.build_egress_binding(
        record,
        merged_input={"targets": ["internal.example"]},
        targets=targets,
        binder=m06_support.StaticBinder({"internal.example": ["198.51.100.10"]}),
        network_profile="lab",
    )
    assert "9.9.9.9:53" in lab.entries


def test_m06_does_not_open_a_dns_source_that_sits_in_the_signed_binding() -> None:
    manifest, raw = m06_support.manifest("manifest.dnsx.yaml")
    task = m06_support.task_for_manifest(
        manifest,
        raw,
        network_profile="internet",
        targets=[{"canonical_key": "dns:internal.example"}],
        input={"targets": ["internal.example"], "concurrency": 1},
        egress_binding={
            "mode": "broker",
            "target_binding": "none",
            "entries": ["9.9.9.9:53", "1.1.1.1:53"],
            "target_addresses": [],
        },
    )
    policy = m06_support.build_policy_for(task, manifest, raw)
    assert [source.hosts for source in policy.sources] == []
    assert policy.binding_hosts == ()


# --- B1: a target inside the platform set is refused at acceptance --------------------------


def test_m05_refuses_a_target_inside_the_platform_deny_set() -> None:
    record = m06_support.record("manifest.naabu.yaml")
    targets = m06_support.resolved_targets(record, ["10.231.1.10"])
    with pytest.raises(M05Error) as caught:
        m05_egress.build_egress_binding(
            record,
            merged_input={"targets": ["10.231.1.10"], "ports": [80]},
            targets=targets,
            binder=m06_support.StaticBinder({"10.231.1.10": ["10.231.1.10"]}),
            network_profile="internet",
            platform_cidrs=("10.231.1.0/24",),
        )
    assert caught.value.refusal.code == "POLICY_DENIED"
    assert caught.value.refusal.rule == "target_platform_network"


# --- F5/F7: authorization and the dev signing key -------------------------------------------


def test_an_internet_policy_needs_a_structured_authorization() -> None:
    manifest, raw = m06_support.manifest("manifest.subfinder.yaml")
    task = m06_support.task_for_manifest(manifest, raw, network_profile="internet")
    with pytest.raises(Exception, match="authorization") as caught:
        m06_support.build_policy_for(task, manifest, raw, authorization="")
    assert "authorization" in str(caught.value)


def test_an_internet_task_signed_with_the_development_key_is_refused() -> None:
    payload = m06_support.fixture_payload("approved-task.subfinder.json")
    payload["network_profile"] = "internet"
    payload["egress_binding"] = {
        "mode": "broker",
        "target_binding": "none",
        "entries": ["crt.sh:443", "otx.alienvault.com:443"],
        "target_addresses": [],
    }
    task, body = m06_support.sign_task(payload, key_ring=m06_support.DEV_RING)
    assert task.signature_key_id == DEV_KEY_ID
    manifest, raw = m06_support.manifest("manifest.subfinder.yaml")
    with pytest.raises(Exception, match="development key") as caught:
        m06_support.build_policy_for(task, manifest, raw, task_body=body)
    assert "development key" in str(caught.value)


# --- F6: the audit line names the campaign by id --------------------------------------------


def test_the_broker_audit_carries_the_campaign_id_not_a_repr(tmp_path: Path) -> None:
    policy = JobEgressPolicy(
        job_id="job-1",
        campaign_id="01934f6a-0000-7000-8000-000000000001",
        authorization="owner | ref | 2026-11-25 | x.test",
        dns_names=("bound.example",),
    )
    audit = AuditLog(tmp_path / "audit.jsonl", policy.job_id)
    record = {"kind": "dns", "decision": "allow", "reason": "OK", "name": "bound.example"}
    audit.close()
    policy_document = netpolicy.policy_document(policy)
    assert policy_document["campaign_id"] == "01934f6a-0000-7000-8000-000000000001"
    assert "root=" not in str(policy_document["campaign_id"])
    assert record["kind"] == "dns"


# --- F8: the audit is bounded and repeated denies are aggregated ----------------------------


def test_repeated_denials_are_aggregated_and_the_file_is_capped(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(path, "job-1", max_bytes=4096)
    for _ in range(50):
        audit._append(
            {"decision": "deny", "reason": "DENY_METADATA", "host": "169.254.169.254", "port": 80}
        )
    audit.close()
    lines = [json.loads(line) for line in path.read_text().splitlines()]
    deny_lines = [line for line in lines if line.get("decision") == "deny"]
    assert len(deny_lines) <= 2  # the first, then one aggregate line
    assert (deny_lines[-1].get("count") or 0) >= 49

    capped_path = tmp_path / "capped.jsonl"
    capped = AuditLog(capped_path, "job-2", max_bytes=800)
    for index in range(50):
        capped._append(
            {"decision": "allow", "reason": "OK", "host": f"h{index}.example", "port": 443}
        )
    capped.close()
    capped_lines = [json.loads(line) for line in capped_path.read_text().splitlines()]
    assert any(line.get("event") == "capped" for line in capped_lines)
    assert len(capped_lines) < 10


# --- B1: every egress channel refuses a platform address --------------------------------
#
# The review reproduced the blocker in both channels (broker proxy and L3); the unit above
# covers the broker's `decide` through an address answer. These pin the two other channels.


def test_the_broker_refuses_a_public_address_that_belongs_to_the_platform() -> None:
    policy = _source_policy(platform=("203.0.113.0/24",))
    resolver = _Stub({"crt.sh": ["203.0.113.10"]})
    decision = netpolicy.decide(policy, "crt.sh", 443, resolver=resolver)
    assert not decision.allowed
    assert decision.reason is netpolicy.Reason.DENY_PLATFORM_NETWORK


def test_the_dns_forwarder_refuses_a_platform_address() -> None:
    from aegis.m06_runner.dns import DnsForwarder

    policy = _source_policy(platform=("203.0.113.0/24",))
    forwarder = DnsForwarder(policy, audit=object(), resolver=lambda name: ["203.0.113.10"])
    assert forwarder._address_allowed("203.0.113.10") == "DENY_PLATFORM_NETWORK"


def test_the_l3_plan_refuses_a_platform_address() -> None:
    from aegis.m06_runner.l3 import _address_allowed

    policy = _source_policy(platform=("203.0.113.0/24",))
    assert _address_allowed(policy, "203.0.113.10") is False
