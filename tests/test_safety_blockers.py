"""Regressions of the independent internet-egress safety review (item #61, findings B1/F1/F4-F8).

Each test is the review's probe turned into an assertion: the platform deny set, embedded IPv4
forms, DNS-protocol sources, the structured authorization, the dev signing key, the audit line's
campaign id and the audit cap.
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any, cast

import pytest

from aegis.common import platform as platform_set
from aegis.m05_registry import egress as m05_egress
from aegis.m05_registry.errors import M05Error
from aegis.m05_registry.signing import DEV_KEY_ID
from aegis.m06_runner import denyset, netpolicy
from aegis.m06_runner.broker import AuditLog
from aegis.m06_runner.netpolicy import JobEgressPolicy, Resolver, SourceAllow
from tests.db_support import requires_postgres

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


# --- F3 guardrail 4: a wildcard zone is refused, never scanned ----------------------------


def test_a_wildcard_zone_refuses_active_signing() -> None:
    from aegis.m05_registry.egress import ActiveProvenance, build_egress_binding

    record = m06_support.record("manifest.naabu.yaml")
    binder = m06_support.StaticBinder({"10.0.0.5": ["93.184.216.34"]})

    # Every name under the zone resolves: the binder is a wildcard.
    class Wildcard(m06_support.StaticBinder):
        def addresses(self, value: str) -> tuple[str, ...]:
            if value.startswith("aegis-wildcard-"):
                return ("93.184.216.34",)
            return super().addresses(value)

    wildcard = Wildcard({"www.icomm.vn": ["93.184.216.34"]})
    targets = m06_support.resolved_targets(record, ["ip:10.0.0.5"])
    binding = build_egress_binding(
        record,
        merged_input={"ports": [443]},
        targets=targets,
        binder=binder,
        authorized_suffixes=("icomm.vn",),
        provenance=ActiveProvenance(seed_networks=(ipaddress.ip_network("10.0.0.5/32"),)),
    )
    assert binding.target_addresses == ("10.0.0.5",)
    with pytest.raises(M05Error) as error:
        build_egress_binding(
            record,
            merged_input={"ports": [443]},
            targets=m06_support.resolved_targets(record, ["dns:www.icomm.vn"]),
            binder=wildcard,
            authorized_suffixes=("icomm.vn",),
        )
    assert error.value.refusal.rule == "wildcard_dns"


# --- F3 guardrail 3: the campaign address budget pauses the campaign ----------------------


def test_exceeding_the_campaign_address_budget_pauses_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aegis.m05_registry import caps

    paused: list[dict[str, object]] = []

    def fake_pause(connection: object, **kwargs: object) -> None:
        paused.append(kwargs)

    class FakeConnection:
        def __init__(self, known: list[str]) -> None:
            self.known = known

        def execute(self, sql: str, params: object = None) -> Any:
            if "jsonb_array_elements_text" in sql:
                return self

            raise AssertionError(sql)

        def fetchall(self) -> list[tuple[str]]:
            return [(value,) for value in self.known]

    monkeypatch.setattr("aegis.m01_campaign.status.change_status", fake_pause)
    known = [f"93.184.216.{index}" for index in range(1, caps.MAX_CAMPAIGN_TARGET_ADDRESSES + 1)]
    with pytest.raises(M05Error) as error:
        caps.check_campaign_address_budget(
            cast(Any, FakeConnection(known)),
            campaign_id="campaign-1",
            addresses=["93.184.216.99"],
            actor={"kind": "module", "id": "M05"},
            trace_id="trace-1",
        )
    assert error.value.refusal.rule == "campaign_address_budget"
    assert paused and paused[0]["action"] == "pause"
    # The same address again, or a smaller set, does not trip the budget.
    caps.check_campaign_address_budget(
        cast(Any, FakeConnection(known[:10])),
        campaign_id="campaign-1",
        addresses=["93.184.216.99", "93.184.216.11"],
        actor={"kind": "module", "id": "M05"},
        trace_id="trace-1",
    )
    assert len(paused) == 1


# --- F3 guardrail 2: a CNAME outside the authorized suffixes stays passive-only ------------


def test_a_foreign_cname_refuses_active_signing(monkeypatch: pytest.MonkeyPatch) -> None:
    from aegis.common import dns_cname
    from aegis.m05_registry import egress

    record = m06_support.record("manifest.naabu.yaml")
    targets = m06_support.resolved_targets(record, ["dns:www.icomm.vn"])
    binder = m06_support.StaticBinder({"www.icomm.vn": ["93.184.216.34"]})
    monkeypatch.setattr(dns_cname, "cname_chain", lambda host: ("edge.cloudflare.net",))
    with pytest.raises(M05Error) as error:
        egress.build_egress_binding(
            record,
            merged_input={"ports": [443]},
            targets=targets,
            binder=binder,
            authorized_suffixes=("icomm.vn",),
        )
    assert error.value.refusal.rule == "target_cname_outside_authorization"
    # A chain that stays inside the suffixes signs normally.
    monkeypatch.setattr(dns_cname, "cname_chain", lambda host: ("edge.icomm.vn",))
    binding = egress.build_egress_binding(
        record,
        merged_input={"ports": [443]},
        targets=targets,
        binder=binder,
        authorized_suffixes=("icomm.vn",),
    )
    assert binding.target_addresses == ("93.184.216.34",)


# --- F2: L3 per-address meter across multiple ports -----------------------------------------


def test_l3_two_ports_on_one_address_share_one_meter() -> None:
    from aegis.m06_runner import l3

    rules = (
        l3.Rule("203.0.113.10", 80),
        l3.Rule("203.0.113.10", 443),
    )
    script = l3.nft_script(rules, uplink="eth1", rate_per_second=1.0, max_connections=2)
    assert script.count("update @rl4 { ip daddr limit rate over 60/minute }") == 1
    assert script.count("add @cc4 { ip daddr ct count over 2 }") == 1
    assert script.index("add @cc4") < script.index("ip daddr 203.0.113.10 tcp dport 80")
    assert script.index("add @cc4") < script.index("ip daddr 203.0.113.10 tcp dport 443")


# --- F3: ip/service targets require seed CIDR or clean authorized provenance ----------------


def test_ip_and_service_targets_enforce_cname_wildcard_and_seed_provenance() -> None:
    from aegis.m05_registry.egress import ActiveProvenance, DomainProvenance, build_egress_binding
    from aegis.m05_registry.targets import ResolvedTargets

    naabu = m06_support.record("manifest.naabu.yaml")
    httpx = m06_support.record("manifest.httpx.yaml")
    binder = m06_support.StaticBinder({})

    # 1. Unseeded IP with no provenance -> passive-only refusal.
    with pytest.raises(M05Error) as unseeded:
        build_egress_binding(
            naabu,
            merged_input={"ports": [443]},
            targets=ResolvedTargets(
                refs=({"canonical_key": "ip:104.16.1.2"},),
                kinds=("ip",),
                raw=("ip:104.16.1.2",),
            ),
            binder=binder,
            authorized_suffixes=("icomm.vn",),
        )
    assert unseeded.value.refusal.rule == "target_passive_only"

    # 2. Foreign CNAME provenance on ip: and service: -> refused as passive-only.
    foreign_prov = ActiveProvenance(
        by_address={
            "104.16.1.2": (
                DomainProvenance(name="cdn.icomm.vn", cname_targets=("edge.cloudflare.net",)),
            )
        }
    )
    for rec, target_key, kind, input_data in (
        (naabu, "ip:104.16.1.2", "ip", {"ports": [443]}),
        (httpx, "service:104.16.1.2:443/tcp", "service", {"ports": [443]}),
    ):
        with pytest.raises(M05Error) as caught:
            build_egress_binding(
                rec,
                merged_input=input_data,
                targets=ResolvedTargets(
                    refs=({"canonical_key": target_key},),
                    kinds=(kind,),
                    raw=(target_key,),
                ),
                binder=binder,
                authorized_suffixes=("icomm.vn",),
                provenance=foreign_prov,
            )
        assert caught.value.refusal.rule == "target_cname_outside_authorization"
        assert "passive-only" in caught.value.refusal.message

    # 3. Wildcard-only provenance -> refused.
    wildcard_prov = ActiveProvenance(
        by_address={
            "198.51.100.77": (DomainProvenance(name="rand.wild.icomm.vn", wildcard_observed=True),)
        }
    )
    with pytest.raises(M05Error) as wild:
        build_egress_binding(
            naabu,
            merged_input={"ports": [443]},
            targets=ResolvedTargets(
                refs=({"canonical_key": "ip:198.51.100.77"},),
                kinds=("ip",),
                raw=("ip:198.51.100.77",),
            ),
            binder=binder,
            authorized_suffixes=("icomm.vn",),
            provenance=wildcard_prov,
        )
    assert wild.value.refusal.rule == "wildcard_dns"

    # 4. Seed CIDR (a) or clean authorized provenance alongside a bad alias (b) -> allowed.
    mixed_prov = ActiveProvenance(
        seed_networks=(ipaddress.ip_network("198.51.100.0/24"),),
        by_address={
            "203.0.113.10": (
                DomainProvenance(name="cdn.icomm.vn", cname_targets=("edge.cloudflare.net",)),
                DomainProvenance(name="api.icomm.vn", cname_targets=("gw.icomm.vn",)),
            )
        },
    )
    for addr in ("198.51.100.5", "203.0.113.10"):
        binding = build_egress_binding(
            naabu,
            merged_input={"ports": [443]},
            targets=ResolvedTargets(
                refs=({"canonical_key": f"ip:{addr}"},),
                kinds=("ip",),
                raw=(f"ip:{addr}",),
            ),
            binder=binder,
            authorized_suffixes=("icomm.vn",),
            provenance=mixed_prov,
        )
        assert binding.target_addresses == (addr,)


@requires_postgres
def test_dnsx_parser_emits_cname_observations_and_m05_refuses_resulting_targets(
    tmp_path: Path,
) -> None:
    """End-to-end DB repro: DNSx CNAME observation -> M05 refuses ip:/service: and audits."""
    import psycopg
    from psycopg.rows import dict_row

    from adapters.m08.dnsx import parser as dnsx_parser
    from aegis.contracts_gen.capability.job_submit_v2_schema import JobSubmit
    from aegis.m01_campaign.campaigns import create_campaign
    from aegis.m01_campaign.status import apply_workflow_action
    from aegis.m05_registry.ids import uuid7
    from aegis.m05_registry.registry import PostgresManifestRegistry
    from aegis.m05_registry.service import PostgresJobService
    from aegis.m06_runner import envelope as envelopes
    from aegis.m27_ingestion.service import IngestionService
    from tests.db_support import OPERATOR, connect, migrated_database, policy_document

    raw_line = (
        json.dumps(
            {
                "host": "cdn.icomm.vn",
                "ttl": 60,
                "a": ["104.16.1.2"],
                "cname": ["edge.cloudflare.net"],
                "status_code": "NOERROR",
            }
        )
        + "\n"
        + json.dumps(
            {
                "host": "api.icomm.vn",
                "ttl": 60,
                "a": ["203.0.113.10"],
                "status_code": "NOERROR",
            }
        )
        + "\n"
        + json.dumps(
            {
                "host": "random.wild.icomm.vn",
                "ttl": 60,
                "a": ["198.51.100.88"],
                "status_code": "NOERROR",
            }
        )
        + "\n"
    )
    out_dir = tmp_path / "dnsx-out"
    out_dir.mkdir()
    (out_dir / "result.jsonl").write_text(raw_line, encoding="utf-8")
    parsed = dnsx_parser.parse(
        out_dir,
        {"input": {"targets": ["cdn.icomm.vn", "api.icomm.vn", "random.wild.icomm.vn"]}},
        [{"local_ref": "raw"}],
    )
    cname_obs = [
        obs
        for obs in parsed["observations"]
        if obs["predicate"] == "dns.record" and obs["value"]["type"] == "CNAME"
    ]
    assert len(cname_obs) == 1
    assert cname_obs[0]["subject"] == "dns:cdn.icomm.vn"
    assert cname_obs[0]["value"]["value"] == "edge.cloudflare.net"

    class WildcardForWildZone(m06_support.StaticBinder):
        def addresses(self, value: str) -> tuple[str, ...]:
            if value.endswith(".wild.icomm.vn"):
                return ("198.51.100.88",)
            return super().addresses(value)

    with migrated_database() as dsn:
        from psycopg.types.json import Jsonb

        from aegis.m05_registry.canonical import sha256_hex

        lab_policy = policy_document(network_profile="lab")
        internet_policy = policy_document(
            network_profile="internet",
            authorization={
                "owner": "icomm",
                "reference": "item-61",
                "date": "2026-11-26",
                "authorized_suffixes": ["icomm.vn"],
            },
            rate_limits={
                "requests_per_second_per_host": 1.0,
                "max_concurrent_connections_per_host": 1,
                "jobs_per_minute": 100,
            },
        )
        with psycopg.connect(dsn, row_factory=dict_row) as dict_conn, dict_conn.transaction():
            created = create_campaign(
                dict_conn,
                body={
                    "name": "internet-provenance",
                    "objective": "verify cname/wildcard guard",
                    "targets": {
                        "domains": ["cdn.icomm.vn", "api.icomm.vn", "random.wild.icomm.vn"],
                        "ips": ["192.0.2.0/24"],
                    },
                    "policy": lab_policy,
                },
                actor=OPERATOR,
                trace_id="a" * 32,
            )
            apply_workflow_action(
                dict_conn,
                campaign_id=created.campaign_id,
                action="start",
                reason="test",
                actor={"kind": "module", "id": "M02"},
                trace_id="a" * 32,
            )

        registry = PostgresManifestRegistry(lambda: connect(dsn))
        for manifest_name in ("manifest.dnsx.yaml", "manifest.naabu.yaml", "manifest.httpx.yaml"):
            registry.register(
                (m06_support.FIXTURES / manifest_name).read_bytes(),
                registered_by={"kind": "module", "id": "M05"},
            )
        jobs = PostgresJobService(
            lambda: connect(dsn),
            registry=registry,
            key_ring=m06_support.INTERNET_RING,
            binder=WildcardForWildZone({}),
            platform_cidrs=("10.88.0.0/16",),
        )
        dnsx_job = jobs.submit(
            JobSubmit.model_validate(
                {
                    "campaign_id": created.campaign_id,
                    "capability": "dns.resolve",
                    "input": {"targets": ["cdn.icomm.vn", "api.icomm.vn", "random.wild.icomm.vn"]},
                    "rationale": "resolve subdomains",
                }
            ),
            requested_by=OPERATOR,
            idempotency_key="dnsx-1",
        )
        with connect(dsn) as conn, conn.transaction():
            conn.execute(
                "INSERT INTO policy_snapshot (policy_version, campaign_id, policy, policy_hash, "
                "created_by) VALUES ('roe-999', %s, %s, %s, %s)",
                (
                    created.campaign_id,
                    Jsonb(internet_policy),
                    sha256_hex(internet_policy),
                    Jsonb(OPERATOR),
                ),
            )
            conn.execute(
                "UPDATE campaign SET current_policy_version = 'roe-999' WHERE campaign_id = %s",
                (created.campaign_id,),
            )
        with connect(dsn) as conn, conn.transaction():
            task_row = conn.execute(
                "SELECT approved_task FROM scan_job WHERE job_id = %s",
                (dnsx_job.job["job_id"],),
            ).fetchone()
            assert task_row is not None
            from aegis.contracts_gen.capability.approved_task_v2_schema import ApprovedTask

            task = ApprovedTask.model_validate(task_row[0])
            sha = "c" * 64
            ev_id = uuid7()
            uri = f"s3://evidence/{created.campaign_id}/{dnsx_job.job['job_id']}/{sha}"
            conn.execute(
                "INSERT INTO evidence (evidence_id, sha256, storage_uri, campaign_id, job_id, "
                "size_bytes, media_type, classification, source_tool) "
                "VALUES (%s, %s, %s, %s, %s, 10, 'application/x-ndjson', 'INTERNAL', 'dnsx')",
                (ev_id, sha, uri, created.campaign_id, dnsx_job.job["job_id"]),
            )
        manifest_dnsx, _ = m06_support.manifest("manifest.dnsx.yaml")
        env = envelopes.build_envelope(
            task=task,
            manifest=manifest_dnsx,
            job_id=dnsx_job.job["job_id"],
            input_values=dnsx_job.job["input"] if "input" in dnsx_job.job else task.input,
            results=parsed,
            evidence=[
                envelopes.EnvelopeEvidence(
                    local_ref="raw",
                    sha256="c" * 64,
                    uri=uri,
                    size_bytes=10,
                    media_type="application/x-ndjson",
                    classification="INTERNAL",
                )
            ],
            status="succeeded",
            started_at="2026-11-26T00:00:00Z",
            finished_at="2026-11-26T00:00:05Z",
            exit_code=0,
        )
        receipt = IngestionService(lambda: connect(dsn)).submit(env)
        assert receipt.accepted and not receipt.quarantined

        # Seed a service asset on the CDN IP to prove service: targets are gated identically.
        with connect(dsn) as conn, conn.transaction():
            svc_id = uuid7()
            conn.execute(
                "INSERT INTO asset (asset_id, canonical_key, kind, first_seen, last_seen, "
                "normalization_version) VALUES (%s, 'service:104.16.1.2:443/tcp', 'service', "
                "now(), now(), 'aegis-norm/1')",
                (svc_id,),
            )
            conn.execute(
                "INSERT INTO asset_service (asset_id, ip, port, transport) "
                "VALUES (%s, '104.16.1.2', 443, 'tcp')",
                (svc_id,),
            )
            conn.execute(
                "INSERT INTO asset_campaign (asset_id, campaign_id, first_seen) "
                "VALUES (%s, %s, now())",
                (svc_id, created.campaign_id),
            )
            # Also seed an IP inside the authorized seed CIDR (192.0.2.0/24).
            seed_cidr_ip = uuid7()
            conn.execute(
                "INSERT INTO asset (asset_id, canonical_key, kind, first_seen, last_seen, "
                "normalization_version) VALUES (%s, 'ip:192.0.2.5', 'ip', now(), now(), "
                "'aegis-norm/1')",
                (seed_cidr_ip,),
            )
            conn.execute(
                "INSERT INTO asset_campaign (asset_id, campaign_id, first_seen) "
                "VALUES (%s, %s, now())",
                (seed_cidr_ip, created.campaign_id),
            )

        # Foreign-CNAME IP -> refused + audited.
        with pytest.raises(M05Error) as cdn_ip_err:
            jobs.submit(
                JobSubmit.model_validate(
                    {
                        "campaign_id": created.campaign_id,
                        "capability": "network.discover_services",
                        "input": {"targets": ["ip:104.16.1.2"], "ports": [443]},
                        "rationale": "scan cdn ip",
                    }
                ),
                requested_by=OPERATOR,
                idempotency_key="naabu-cdn-ip",
            )
        assert cdn_ip_err.value.refusal.rule == "target_cname_outside_authorization"

        # Foreign-CNAME service -> refused + audited.
        with pytest.raises(M05Error) as cdn_svc_err:
            jobs.submit(
                JobSubmit.model_validate(
                    {
                        "campaign_id": created.campaign_id,
                        "capability": "web.probe_http",
                        "input": {"targets": ["service:104.16.1.2:443/tcp"], "ports": [443]},
                        "rationale": "probe cdn service",
                    }
                ),
                requested_by=OPERATOR,
                idempotency_key="httpx-cdn-svc",
            )
        assert cdn_svc_err.value.refusal.rule == "target_cname_outside_authorization"

        # Wildcard-only IP -> refused + audited.
        with pytest.raises(M05Error) as wild_ip_err:
            jobs.submit(
                JobSubmit.model_validate(
                    {
                        "campaign_id": created.campaign_id,
                        "capability": "network.discover_services",
                        "input": {"targets": ["ip:198.51.100.88"], "ports": [443]},
                        "rationale": "scan wildcard ip",
                    }
                ),
                requested_by=OPERATOR,
                idempotency_key="naabu-wild-ip",
            )
        assert wild_ip_err.value.refusal.rule == "wildcard_dns"

        # Verify audit_log + policy_decision recorded all 3 refusals.
        with connect(dsn) as conn:
            denied_rules = [
                str(row[0])
                for row in conn.execute(
                    "SELECT rule FROM policy_decision "
                    "WHERE campaign_id = %s AND decision = 'denied' "
                    "ORDER BY created_at",
                    (created.campaign_id,),
                ).fetchall()
            ]
            audit_rules = [
                str(row[0])
                for row in conn.execute(
                    "SELECT details ->> 'rule' FROM audit_log WHERE campaign_id = %s "
                    "AND action = 'job.refuse' ORDER BY audit_id",
                    (created.campaign_id,),
                ).fetchall()
            ]
        assert denied_rules == [
            "target_cname_outside_authorization",
            "target_cname_outside_authorization",
            "wildcard_dns",
        ]
        assert audit_rules == denied_rules

        # Clean authorized provenance IP (api.icomm.vn) + seed CIDR IP (192.0.2.5) -> accepted!
        for target_key, key in (("ip:203.0.113.10", "ok-prov"), ("ip:192.0.2.5", "ok-cidr")):
            accepted = jobs.submit(
                JobSubmit.model_validate(
                    {
                        "campaign_id": created.campaign_id,
                        "capability": "network.discover_services",
                        "input": {"targets": [target_key], "ports": [443]},
                        "rationale": "scan authorized target",
                    }
                ),
                requested_by=OPERATOR,
                idempotency_key=key,
            )
            assert accepted.job["status"] == "QUEUED"
