"""ContainerSpec assembly: argv rendering (OI-12), target re-check (P3c), pins and egress (E-1).

The manifest fixtures are the contract's own (`contracts/fixtures/valid/manifest.*.yaml`), so a
change to their shape breaks this test, as it should: M06 reads exactly the pinned document.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Mapping
from typing import Any

import pytest
import yaml

from aegis.contracts_gen.capability.provider_manifest_v2_schema import ProviderManifest
from aegis.m05_registry.signing import KeyRing
from aegis.m06_runner import netpolicy, spec
from aegis.m06_runner.spec import SpecError

from . import m06_support


def _manifest(mutate: Any = None) -> tuple[ProviderManifest, bytes]:
    value, raw = m06_support.manifest("manifest.subfinder.yaml")
    if mutate is not None:
        payload = yaml.safe_load(raw)
        mutate(payload)
        raw = json.dumps(payload, sort_keys=True).encode()
        value = ProviderManifest.model_validate(payload)
    return value, raw


def _input(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {"targets": ["internal.example"], "concurrency": 2, "rate_limit": 1}
    values.update(overrides)
    return values


# --- argv rendering (OI-12) ------------------------------------------------------------------


def test_args_template_renders_typed_values() -> None:
    manifest, _ = _manifest()
    schema = spec.load_input_schema(manifest.spec.inputSchemaRef)
    args = spec.render_args(manifest.spec.runtime.argsTemplate or [], _input(), schema)
    assert args[:3] == ["-silent", "-duc", "-json"]
    assert args[-4:] == ["-t", "2", "-rl", "1"]
    assert "/in/targets.txt" in args


def test_array_renders_one_element_per_item() -> None:
    """OI-12: an array field becomes one argv element per item, never one joined string.

    The pinned `network.discover_services` manifest reads its port set from `/in/ports.txt`
    (`-ports-file`), because the tool takes one port list argument and a joined value cannot be
    rendered without breaking this rule; the rule itself is checked here, on the same input schema.
    """
    schema = spec.load_input_schema("schema://network/discover-services/v2")
    args = spec.render_args(["-p", "${input.ports}"], {"ports": [80, 443]}, schema)
    assert args == ["-p", "80", "443"]


def test_boolean_renders_as_lowercase_word() -> None:
    manifest, _ = _manifest(
        lambda payload: payload["spec"]["runtime"].update(
            {"argsTemplate": ["-recursive=${input.recursive}"]}
        )
    )
    with pytest.raises(SpecError, match="exactly one"):
        spec.render_args(
            ["-recursive=${input.recursive}"],
            _input(recursive=True),
            spec.load_input_schema("schema://dns/enumerate-subdomains/v2"),
        )
    manifest, _ = _manifest(
        lambda payload: payload["spec"]["runtime"].update({"argsTemplate": ["${input.recursive}"]})
    )
    args = spec.render_args(
        ["${input.recursive}"],
        _input(recursive=True),
        spec.load_input_schema(manifest.spec.inputSchemaRef),
    )
    assert args == ["true"]


def test_free_form_string_and_ref_arrays_are_refused() -> None:
    schema = spec.load_input_schema("schema://dns/enumerate-subdomains/v2")
    with pytest.raises(SpecError) as caught:
        spec.render_args(["${input.targets}"], _input(), schema)
    assert caught.value.code == "POLICY_DENIED"


def test_negative_number_would_become_a_flag_and_is_refused() -> None:
    schema = spec.load_input_schema("schema://dns/enumerate-subdomains/v2")
    with pytest.raises(SpecError, match="flag"):
        spec.render_args(["-max", "${input.max_results}"], _input(max_results=-5), schema)


def test_unknown_field_and_missing_value_are_refused() -> None:
    schema = spec.load_input_schema("schema://dns/enumerate-subdomains/v2")
    with pytest.raises(SpecError, match="unknown input field"):
        spec.render_args(["${input.nope}"], _input(), schema)
    with pytest.raises(SpecError, match="which is missing"):
        spec.render_args(["${input.max_results}"], _input(), schema)


def test_two_placeholders_in_one_element_are_refused() -> None:
    schema = spec.load_input_schema("schema://dns/enumerate-subdomains/v2")
    with pytest.raises(SpecError, match="exactly one"):
        spec.render_args(["${input.concurrency}${input.rate_limit}"], _input(), schema)


# --- target re-check (P3c) -------------------------------------------------------------------


def test_input_targets_must_match_the_task_refs() -> None:
    task = m06_support.approved_task()
    spec.recheck_targets(task, {"targets": ["internal.example"]})
    with pytest.raises(SpecError) as caught:
        spec.recheck_targets(task, {"targets": ["internal.example", "other.example"]})
    assert caught.value.code == "POLICY_DENIED"


def test_canonical_key_target_must_be_in_the_task_refs() -> None:
    task = m06_support.approved_task(
        targets=[{"canonical_key": "dns:internal.example"}],
        input={"targets": ["internal.example"], "concurrency": 2, "rate_limit": 1},
    )
    spec.recheck_targets(task, {"targets": ["internal.example"]})
    with pytest.raises(SpecError) as caught:
        spec.recheck_targets(task, {"targets": ["other.example"]})
    assert caught.value.code == "POLICY_DENIED"


def test_duplicate_and_invalid_targets_are_refused() -> None:
    task = m06_support.approved_task()
    with pytest.raises(SpecError, match="duplicates"):
        spec.recheck_targets(task, {"targets": ["internal.example", "internal.example"]})
    with pytest.raises(SpecError, match="neither a domain target"):
        spec.recheck_targets(task, {"targets": ["-rf"]})


def test_no_input_targets_means_nothing_to_recheck() -> None:
    spec.recheck_targets(m06_support.approved_task(), {"concurrency": 1})


# --- spec assembly ---------------------------------------------------------------------------


def _build(manifest: ProviderManifest, raw: bytes, **kwargs: Any) -> Any:
    # The job-flow tests model an internet job (broker + uplink) unless a test says otherwise;
    # the internet profile needs the RoE caps, so the helper supplies test caps.
    task_overrides = {"network_profile": "internet", **kwargs.pop("task", {})}
    task = m06_support.task_for_manifest(manifest, raw, **task_overrides)
    values = kwargs.pop("input", _input())
    platform = kwargs.pop("platform_cidrs", ("10.88.0.0/16",))
    denylist = kwargs.pop("target_denylist", ())
    kwargs.setdefault("per_host_rps", 5.0)
    kwargs.setdefault("per_host_max_connections", 2)
    kwargs.setdefault("authorization", m06_support.AUTHORIZATION)
    return spec.build_spec(
        task,
        manifest,
        values,
        job_id="job-1",
        task_body=m06_support.body_of(task),
        key_ring=m06_support.ANY_RING,
        broker_proxy="http://10.97.0.2:3128",
        platform_cidrs=platform,
        target_denylist=denylist,
        manifest_bytes=raw,
        **kwargs,
    )


def _binding(
    entries: list[str],
    addresses: list[str] | None = None,
    *,
    target_binding: str = "required",
    mode: str = "broker",
    private_seed: str = "10.0.0.0/8",
) -> dict[str, Any]:
    # The test target 10.1.2.3 is private, so the binding carries the private seed CIDR a RoE would
    # list for it (R4): without it, an internet task with a private target is refused.
    return {
        "mode": mode,
        "target_binding": target_binding,
        "entries": entries,
        "target_addresses": addresses or [],
        "authorized_private_cidrs": [private_seed] if addresses else [],
    }


def test_egress_spec_carries_manifest_budget_and_source_binding() -> None:
    manifest, raw = _manifest()
    built = _build(manifest, raw)
    assert built.cpu == 1.0
    assert built.memory_mb == 512
    assert built.timeout_seconds == 900
    assert built.max_output_bytes == 64 * 1024 * 1024
    assert built.network == "exec"
    assert built.egress_mode == "broker"
    assert built.egress_proxy == "http://10.97.0.2:3128"
    assert built.raw_socket is False
    assert set(built.egress_binding) == {
        "crt.sh:443",
        "otx.alienvault.com:443",
        "api.hackertarget.com:443",
        "rapiddns.io:443",
        "web.archive.org:443",
        "web.archive.org:80",
        "index.commoncrawl.org:443",
    }
    assert built.args[-4:] == ["-t", "2", "-rl", "1"]


def test_network_none_spec_has_no_egress() -> None:
    def no_egress(payload: dict[str, Any]) -> None:
        permissions = payload["spec"]["permissions"]
        permissions.update({"networkAccess": "none"})
        for key in ("egressMode", "egressSources", "targetBinding", "targetPorts"):
            permissions.pop(key, None)

    manifest, raw = _manifest(no_egress)
    built = _build(
        manifest,
        raw,
        task={"egress_binding": _binding([], target_binding="none", mode="none")},
    )
    assert built.network == "none"
    assert built.egress_mode is None
    assert built.egress_proxy is None
    assert built.egress_binding == ()


def test_pin_mismatch_is_refused_before_anything_runs() -> None:
    # The task is signed over the real manifest; a manifest with another digest must not be used.
    manifest, raw = _manifest()
    task = m06_support.task_for_manifest(manifest, raw)
    other_manifest, other_raw = _manifest(
        lambda payload: payload["spec"]["runtime"].update({"imageDigest": "sha256:" + "1" * 64})
    )
    with pytest.raises(SpecError, match="image_digest mismatch"):
        spec.build_spec(
            task,
            other_manifest,
            _input(),
            job_id="job-1",
            task_body=m06_support.body_of(task),
            key_ring=m06_support.ANY_RING,
            broker_proxy="http://10.97.0.2:3128",
            manifest_bytes=other_raw,
        )
    assert manifest.spec.runtime.imageDigest is not None


def test_manifest_bytes_must_match_the_pin() -> None:
    manifest, raw = _manifest()
    task = m06_support.task_for_manifest(manifest, raw)
    with pytest.raises(SpecError, match="manifest_sha256 mismatch"):
        spec.build_spec(
            task,
            manifest,
            _input(),
            job_id="job-1",
            task_body=m06_support.body_of(task),
            key_ring=m06_support.ANY_RING,
            broker_proxy="http://10.97.0.2:3128",
            manifest_bytes=raw + b" ",
        )


def test_a_signed_binding_inside_the_deny_set_is_refused() -> None:
    manifest, raw = _manifest()

    def denied_source(payload: dict[str, Any]) -> None:
        payload["spec"]["permissions"]["egressSources"] = [
            {"id": "metadata", "hosts": ["127.1"], "ports": [80], "protocol": "http"}
        ]

    manifest, raw = _manifest(denied_source)
    task = m06_support.task_for_manifest(
        manifest, raw, egress_binding=_binding(["127.1:80"], target_binding="none")
    )
    with pytest.raises(SpecError, match="always-deny set"):
        spec.build_policy(
            task,
            manifest,
            _input(),
            job_id="job-1",
            task_body=m06_support.body_of(task),
            key_ring=m06_support.ANY_RING,
        )


def test_a_signed_binding_cannot_widen_the_declared_sources() -> None:
    manifest, raw = _manifest()
    task = m06_support.task_for_manifest(
        manifest,
        raw,
        egress_binding=_binding(
            [
                "crt.sh:443",
                "otx.alienvault.com:443",
                "api.hackertarget.com:443",
                "rapiddns.io:443",
                "web.archive.org:443",
                "web.archive.org:80",
                "index.commoncrawl.org:443",
                "evil.example:443",
            ],
            target_binding="none",
        ),
    )
    with pytest.raises(SpecError, match="neither a declared source nor a target address"):
        spec.build_policy(
            task,
            manifest,
            _input(),
            job_id="job-1",
            task_body=m06_support.body_of(task),
            key_ring=m06_support.ANY_RING,
        )


def test_a_signed_binding_must_cover_every_declared_source() -> None:
    manifest, raw = _manifest()
    task = m06_support.task_for_manifest(
        manifest, raw, egress_binding=_binding(["crt.sh:443"], target_binding="none")
    )
    with pytest.raises(SpecError, match="does not cover declared source"):
        spec.build_policy(
            task,
            manifest,
            _input(),
            job_id="job-1",
            task_body=m06_support.body_of(task),
            key_ring=m06_support.ANY_RING,
        )


def test_the_signed_binding_is_the_source_of_truth_for_a_seed_target() -> None:
    # E-1: M05 resolves a seed target into the signed binding, so M06 covers it without touching
    # the campaign tables. `target_addresses` is the pinned evidence of that resolution.
    manifest, raw = m06_support.target_bound_manifest()
    task = m06_support.task_for_manifest(
        manifest,
        raw,
        capability="network.discover_services",
        targets=[{"seed_id": "01934f6a-0000-7000-8000-0000000000b1"}],
        egress_binding=_binding(["10.114.53.53:8080"], ["10.114.53.53"]),
    )
    policy = spec.build_policy(
        task,
        manifest,
        {"targets": ["10.114.53.53"], "ports": [8080]},
        job_id="job-1",
        task_body=m06_support.body_of(task),
        key_ring=m06_support.ANY_RING,
    )
    assert policy.mode == "egress"
    assert [str(net) for net in policy.target_ips] == ["10.114.53.53/32"]
    assert policy.target_ports == (8080,)
    assert [source.id for source in policy.sources] == ["target"]
    decision = netpolicy.decide(policy, "10.114.53.53", 8080)
    assert decision.allowed and decision.source_id == "target"


def test_signed_binding_missing_an_ip_ref_address_is_refused() -> None:
    manifest, raw = m06_support.target_bound_manifest()
    task = m06_support.task_for_manifest(
        manifest,
        raw,
        capability="network.discover_services",
        targets=[{"canonical_key": "ip:10.1.2.3"}],
        egress_binding=_binding(["10.1.2.3:8080"], [], target_binding="required"),
    )
    with pytest.raises(SpecError, match="omits task target address"):
        spec.build_policy(
            task,
            manifest,
            {"targets": ["ip:10.1.2.3"], "ports": [8080]},
            job_id="job-1",
            task_body=m06_support.body_of(task),
            key_ring=m06_support.ANY_RING,
        )


def test_target_bound_job_uses_the_signed_binding_ports() -> None:
    manifest, raw = m06_support.target_bound_manifest()
    task_input = {
        "targets": ["ip:10.1.2.3"],
        "ports": [8080, 8443],
        "packets_per_second": 100,
        "concurrency": 1,
        "version_intensity": 0,
    }
    task = m06_support.task_for_manifest(
        manifest,
        raw,
        capability="network.discover_services",
        targets=[{"canonical_key": "ip:10.1.2.3"}],
        egress_binding=_binding(["10.1.2.3:8080", "10.1.2.3:8443"], ["10.1.2.3"]),
    )
    built = spec.build_spec(
        task,
        manifest,
        task_input,
        job_id="job-1",
        task_body=m06_support.body_of(task),
        key_ring=m06_support.ANY_RING,
        broker_proxy="http://10.97.0.2:3128",
        manifest_bytes=raw,
    )
    assert set(built.egress_binding) == {"10.1.2.3:8080", "10.1.2.3:8443"}
    # The port set reaches the tool as the staged input file; the scan rate is the job's own input,
    # rendered by the OI-12 rule (never a manifest default quietly replacing it).
    index = built.args.index("-ports-file")
    assert built.args[index + 1] == "/in/ports.txt"
    index = built.args.index("-rate")
    assert built.args[index + 1] == "100"


def test_target_in_the_deny_set_is_refused_before_the_spec_exists() -> None:
    manifest, raw = m06_support.target_bound_manifest()
    task = m06_support.task_for_manifest(
        manifest,
        raw,
        capability="network.discover_services",
        targets=[{"canonical_key": "ip:169.254.169.254"}],
        egress_binding=_binding(["169.254.169.254:80"], ["169.254.169.254"]),
    )
    with pytest.raises(SpecError, match="always-deny set"):
        spec.build_spec(
            task,
            manifest,
            {
                "targets": ["ip:169.254.169.254"],
                "ports": [80],
                "packets_per_second": 100,
                "concurrency": 1,
                "version_intensity": 0,
            },
            job_id="job-1",
            task_body=m06_support.body_of(task),
            key_ring=m06_support.ANY_RING,
            broker_proxy="http://10.97.0.2:3128",
            manifest_bytes=raw,
        )


def test_target_binding_required_needs_ports() -> None:
    manifest, raw = m06_support.target_bound_manifest()
    task = m06_support.task_for_manifest(
        manifest,
        raw,
        capability="network.discover_services",
        targets=[{"canonical_key": "ip:10.1.2.3"}],
        egress_binding=_binding(["10.1.2.3:8080"], ["10.1.2.3"]),
    )
    with pytest.raises(SpecError) as caught:
        spec.build_spec(
            task,
            manifest,
            {"targets": ["ip:10.1.2.3"]},
            job_id="job-1",
            task_body=m06_support.body_of(task),
            key_ring=m06_support.ANY_RING,
            broker_proxy="http://10.97.0.2:3128",
            manifest_bytes=raw,
        )
    assert caught.value.code == "POLICY_DENIED"


def test_policy_includes_platform_cidrs_and_campaign_denylist() -> None:
    manifest, raw = _manifest()
    task = m06_support.task_for_manifest(manifest, raw)
    policy = spec.build_policy(
        task,
        manifest,
        _input(),
        job_id="job-1",
        task_body=m06_support.body_of(task),
        key_ring=m06_support.ANY_RING,
        platform_cidrs=("10.88.0.0/16",),
        target_denylist=("10.50.0.0/16", "denied.example"),
    )
    assert policy.mode == "egress"
    assert ipaddress.ip_network("10.88.0.0/16") in policy.platform_cidrs
    assert ipaddress.ip_network("10.50.0.0/16") in policy.deny_cidrs
    # A denied *name* cannot be a CIDR; the broker only reaches declared names, so it stays closed.
    assert len(policy.deny_cidrs) == 1
    decision = netpolicy.decide(
        policy, "crt.sh", 443, resolver=_StubResolver({"crt.sh": ["93.184.216.34"]})
    )
    assert decision.allowed


def test_spec_job_id_is_the_container_name() -> None:
    manifest, raw = _manifest()
    built = _build(manifest, raw)
    assert built.job_id == "job-1"


# --- OI-7: M06 accepts only M05-signed tasks ------------------------------------------------


def test_verify_task_accepts_the_m05_signature() -> None:
    task = m06_support.approved_task()
    assert spec.verify_task(m06_support.body_of(task), m06_support.DEV_RING) == "g1-dev-1"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("input", {"targets": ["evil.example"], "concurrency": 2, "rate_limit": 1}),
        ("targets", [{"seed_id": "01934f6a-0000-7000-8000-0000000000b2"}]),
        ("priority", 99),
        ("image_digest", "sha256:" + "2" * 64),
        ("provider_version", "v9.9.9"),
        ("manifest_sha256", "3" * 64),
        ("policy_version", "roe-9"),
        ("requested_by", {"kind": "agent", "id": "01934f6a-0000-7000-8000-0000000000c9"}),
        (
            "egress_binding",
            {
                "mode": "broker",
                "target_binding": "none",
                "entries": ["evil.example:443"],
                "target_addresses": [],
            },
        ),
    ],
)
def test_tampering_with_any_signed_field_is_refused(field: str, value: Any) -> None:
    task = m06_support.approved_task()
    document = m06_support.body_of(task)
    document[field] = value
    with pytest.raises(SpecError) as caught:
        spec.verify_task(document, m06_support.DEV_RING)
    assert caught.value.code == "POLICY_DENIED"
    assert "signature rejected" in str(caught.value)


def test_unknown_signing_key_is_refused() -> None:
    rogue = KeyRing(active_key_id="rogue-1", keys={"rogue-1": b"x" * 32})
    payload = m06_support._fixture("approved-task.subfinder.json")
    _task, document = m06_support.sign_task(payload, key_ring=rogue)
    with pytest.raises(SpecError) as caught:
        spec.verify_task(document, m06_support.DEV_RING)
    assert "does not hold" in str(caught.value)


def test_a_rotated_ring_still_verifies_older_tasks() -> None:
    task = m06_support.approved_task()  # signed with the g1-dev-1 key
    rotated = m06_support.DEV_RING.rotate("g1-dev-2", b"y" * 32)
    assert spec.verify_task(m06_support.body_of(task), rotated) == "g1-dev-1"


def test_build_spec_verifies_before_anything_else() -> None:
    manifest, raw = _manifest()
    task = m06_support.task_for_manifest(manifest, raw)
    document = m06_support.body_of(task)
    document["input"] = {"targets": ["evil.example"], "concurrency": 2, "rate_limit": 1}
    with pytest.raises(SpecError, match="signature rejected"):
        spec.build_spec(
            task,
            manifest,
            _input(),
            job_id="job-1",
            task_body=document,
            key_ring=m06_support.ANY_RING,
            broker_proxy="http://10.97.0.2:3128",
            manifest_bytes=raw,
        )


def test_input_schema_reference_must_resolve() -> None:
    with pytest.raises(SpecError) as caught:
        spec.load_input_schema("schema://dns/does-not-exist/v2")
    assert caught.value.code == "DEPENDENCY_MISSING"


def test_target_ports_from_input_are_bounded() -> None:
    manifest, raw = m06_support.target_bound_manifest()
    task = m06_support.task_for_manifest(
        manifest,
        raw,
        capability="network.discover_services",
        targets=[{"canonical_key": "ip:10.1.2.3"}],
        egress_binding=_binding(["10.1.2.3:8080"], ["10.1.2.3"]),
    )
    with pytest.raises(SpecError, match="out of range"):
        spec.build_spec(
            task,
            manifest,
            {
                "targets": ["ip:10.1.2.3"],
                "ports": [70000],
                "packets_per_second": 100,
                "concurrency": 1,
                "version_intensity": 0,
            },
            job_id="job-1",
            task_body=m06_support.body_of(task),
            key_ring=m06_support.ANY_RING,
            broker_proxy="http://10.97.0.2:3128",
            manifest_bytes=raw,
        )


def test_policy_contract_shape_stays_json() -> None:
    policy = netpolicy.JobEgressPolicy(job_id="job-1")
    document: Mapping[str, Any] = netpolicy.policy_document(policy)
    assert json.loads(json.dumps(document))["job_id"] == "job-1"


# --- network profiles (G1.6) ------------------------------------------------------------------


def test_the_internet_profile_needs_the_roe_safety_caps() -> None:
    manifest, raw = _manifest()
    task = m06_support.task_for_manifest(manifest, raw, network_profile="internet")
    with pytest.raises(SpecError, match="rate_limits") as caught:
        spec.build_policy(
            task,
            manifest,
            _input(),
            job_id="job-1",
            task_body=m06_support.body_of(task),
            key_ring=m06_support.ANY_RING,
            authorization=m06_support.AUTHORIZATION,
            platform_cidrs=("10.88.0.0/16",),
        )
    assert caught.value.code == "POLICY_DENIED"


def test_the_internet_profile_denies_private_ranges_except_signed_targets() -> None:
    manifest, raw = _manifest()
    task = m06_support.task_for_manifest(manifest, raw, network_profile="internet")
    policy = spec.build_policy(
        task,
        manifest,
        _input(),
        job_id="job-1",
        task_body=m06_support.body_of(task),
        key_ring=m06_support.ANY_RING,
        authorization=m06_support.AUTHORIZATION,
        platform_cidrs=("10.88.0.0/16",),
        per_host_rps=0.5,
        per_host_max_connections=1,
    )
    assert policy.profile == "internet"
    assert ipaddress.ip_network("10.0.0.0/8") in policy.private_cidrs
    assert policy.per_host_rps == 0.5
    assert policy.per_host_max_connections == 1
    # DNS-over-broker: the target name and the declared sources are the only resolvable names.
    assert policy.dns_target_names == ("internal.example",)
    assert policy.dns_names == (
        "api.hackertarget.com",
        "crt.sh",
        "index.commoncrawl.org",
        "internal.example",
        "otx.alienvault.com",
        "rapiddns.io",
        "web.archive.org",
    )
    assert policy.dns_ttl == 30
    # A declared source that resolves into the host's own private network is refused on the
    # internet profile (no signed target covers it) and allowed on the lab profile.
    resolver = _StubResolver({"crt.sh": ["10.0.0.9"]})
    assert (
        netpolicy.decide(policy, "crt.sh", 443, resolver=resolver).reason
        is netpolicy.Reason.DENY_PRIVATE
    )
    lab_task = m06_support.task_for_manifest(manifest, raw, network_profile="lab")
    lab_policy = spec.build_policy(
        lab_task,
        manifest,
        _input(),
        job_id="job-1",
        task_body=m06_support.body_of(lab_task),
        key_ring=m06_support.ANY_RING,
        resolver=resolver,
    )
    assert lab_policy.private_cidrs == ()
    assert netpolicy.decide(lab_policy, "crt.sh", 443, resolver=resolver).allowed


def test_the_lab_profile_needs_no_caps_and_has_no_proxy() -> None:
    manifest, raw = _manifest()
    built = _build(manifest, raw, task={"network_profile": "lab"})
    assert built.network_profile == "lab"
    assert built.egress_proxy is None
    assert built.network == "exec"


def test_the_spec_carries_the_signed_profile() -> None:
    manifest, raw = _manifest()
    built = _build(manifest, raw)
    assert built.network_profile == "internet"


def test_the_port_list_is_capped_by_the_pinned_input_schema() -> None:
    manifest, raw = m06_support.target_bound_manifest()
    # `network/discover-services/v2` (pinned by the manifest's inputSchemaRef, and the manifest
    # bytes by manifest_sha256) states maxItems 1000 for `ports`: a job cannot widen the scan.
    discover = spec.load_input_schema("schema://network/discover-services/v2")
    cap = discover["properties"]["ports"]["maxItems"]
    ports = list(range(1, cap + 2))
    task = m06_support.task_for_manifest(
        manifest,
        raw,
        capability="network.discover_services",
        network_profile="internet",
        targets=[{"canonical_key": "ip:10.1.2.3"}],
        egress_binding=_binding(["10.1.2.3:80"], ["10.1.2.3"]),
    )
    with pytest.raises(SpecError, match=f"caps it at {cap}") as caught:
        spec.build_spec(
            task,
            manifest,
            # The pinned Naabu argv renders the scan rate too; the port cap is what this test is
            # about, and it is checked before any binding/argv work can pass.
            {
                "targets": ["ip:10.1.2.3"],
                "ports": ports,
                "packets_per_second": 100,
                "concurrency": 1,
            },
            job_id="job-1",
            task_body=m06_support.body_of(task),
            key_ring=m06_support.ANY_RING,
            broker_proxy="http://10.97.0.2:3128",
            manifest_bytes=raw,
            authorization=m06_support.AUTHORIZATION,
            platform_cidrs=("10.88.0.0/16",),
            per_host_rps=0.5,
            per_host_max_connections=1,
        )
    assert caught.value.code == "POLICY_DENIED"


def _manifest_of(manifest: Any, edit: Any) -> tuple[Any, bytes]:
    payload = json.loads(manifest.model_dump_json(exclude_none=True))
    edit(payload)
    raw = json.dumps(payload, sort_keys=True).encode("utf-8")
    return ProviderManifest.model_validate(payload), raw


class _StubResolver(netpolicy.Resolver):
    def __init__(self, answers: dict[str, list[str]]) -> None:
        self.answers = answers

    def resolve(self, host: str) -> list[str]:
        return list(self.answers.get(host, []))


# --- G1.6b: service targets, targetsFormat and proxy awareness --------------------------------


def test_host_port_renders_a_service_target_as_the_tools_own_value() -> None:
    """`targetsFormat: host_port` writes `host:port`; the DNS default keeps the old form."""
    assert spec.tool_target("service:10.1.2.3:8080/tcp", "host_port") == "10.1.2.3:8080"
    assert spec.tool_target("service:[2001:db8::10]:8443/tcp", "host_port") == "[2001:db8::10]:8443"
    assert spec.tool_target("dns:example.test", "host_port") == "example.test"
    assert spec.tool_target("dns:example.test", "canonical") == "example.test"
    assert spec.tool_target("service:10.1.2.3:8080/tcp", "canonical") == "10.1.2.3:8080/tcp"


def test_the_target_file_carries_the_manifest_those_values(tmp_path: Any) -> None:
    from aegis.m06_runner.job import JobRunner

    manifest, _ = m06_support.manifest("manifest.httpx.yaml")
    JobRunner._write_inputs(  # noqa: SLF001 - the seam under test
        tmp_path,
        {"targets": ["service:10.1.2.3:8080/tcp", "service:10.1.2.4:8443/tcp"]},
        manifest,
    )
    assert (tmp_path / "targets.txt").read_text() == "10.1.2.3:8080\n10.1.2.4:8443\n"


def test_host_port_refuses_a_udp_service_target() -> None:
    """The file cannot say which transport the job meant, so the job is refused, not guessed."""
    manifest, raw = m06_support.manifest("manifest.fingerprintx.yaml")
    key = "service:10.1.2.3:5353/udp"
    task = m06_support.task_for_manifest(
        manifest,
        raw,
        network_profile="lab",
        targets=[{"canonical_key": key}],
        input={"targets": [key], "ports": [5353]},
        egress_binding=_binding(["10.1.2.3:5353"], ["10.1.2.3"]),
    )
    with pytest.raises(SpecError, match="host_port cannot express"):
        spec.build_spec(
            task,
            manifest,
            {"targets": [key], "ports": [5353]},
            job_id="job-1",
            task_body=m06_support.body_of(task),
            key_ring=m06_support.ANY_RING,
            manifest_bytes=raw,
        )


def test_a_service_target_binds_its_own_address() -> None:
    """`service:<ip>:<port>/tcp` is a broker destination like an `ip:` ref (M06 side of E-1)."""
    manifest, raw = m06_support.manifest("manifest.httpx.yaml")
    key = "service:10.1.2.3:8080/tcp"
    values = {"targets": [key], "ports": [8080], "concurrency": 4, "timeout_seconds": 10}
    task = m06_support.task_for_manifest(
        manifest,
        raw,
        network_profile="lab",
        targets=[{"canonical_key": key}],
        input=values,
        egress_binding=_binding(["10.1.2.3:8080"], ["10.1.2.3"]),
    )
    built = spec.build_spec(
        task,
        manifest,
        values,
        job_id="job-1",
        task_body=m06_support.body_of(task),
        key_ring=m06_support.ANY_RING,
        manifest_bytes=raw,
    )
    assert built.network == "exec"
    assert set(built.egress_binding) == {"10.1.2.3:8080"}
    index = built.args.index("-threads")
    assert built.args[index + 1] == "4"
    timeout_index = built.args.index("-timeout")
    assert built.args[timeout_index + 1] == "10"


def test_a_non_proxy_aware_provider_rides_the_l3_channel() -> None:
    """G1.6b: `proxyAware: false` is truthful; the manifest asks for L3, not the broker."""
    manifest, raw = m06_support.manifest("manifest.fingerprintx.yaml")
    assert manifest.spec.permissions.proxyAware is False
    assert str(manifest.spec.permissions.egressMode) == "l3"
    key = "service:10.1.2.3:8080/tcp"
    values = {"targets": [key], "ports": [8080], "timeout_ms": 2000}
    task = m06_support.task_for_manifest(
        manifest,
        raw,
        network_profile="internet",
        targets=[{"canonical_key": key}],
        input=values,
        egress_binding=_binding(["10.1.2.3:8080"], ["10.1.2.3"], mode="l3"),
    )
    built = spec.build_spec(
        task,
        manifest,
        values,
        job_id="job-1",
        task_body=m06_support.body_of(task),
        key_ring=m06_support.ANY_RING,
        manifest_bytes=raw,
        authorization=m06_support.AUTHORIZATION,
        platform_cidrs=("10.88.0.0/16",),
        per_host_rps=1.0,
        per_host_max_connections=1,
    )
    # An l3 job needs no proxy of its network; the gateway filters by the signed IP:port set.
    assert built.egress_mode == "l3"
    assert built.egress_proxy is None
    assert set(built.egress_binding) == {"10.1.2.3:8080"}


def test_a_manifest_that_needs_its_proxy_flag_is_refused_without_it() -> None:
    """A tool that ignores the proxy environment must not run when the profile omits its flag."""
    manifest, raw = m06_support.manifest("manifest.subfinder.yaml")
    spec.check_proxy_wiring(manifest, ["-sources", "crtsh", "-proxy", "${broker_http}"])
    with pytest.raises(SpecError, match="needs its proxy as '-proxy'") as caught:
        spec.check_proxy_wiring(manifest, ["-sources", "crtsh"])
    assert caught.value.code == "POLICY_DENIED"
    with pytest.raises(SpecError):
        spec.check_proxy_wiring(manifest, None)
    # A manifest without a flag needs nothing.
    httpx, _ = m06_support.manifest("manifest.httpx.yaml")
    spec.check_proxy_wiring(httpx, None)
