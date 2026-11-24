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
    assert args[:2] == ["-silent", "-json"]
    assert args[-4:] == ["-t", "2", "-rl", "1"]
    assert "/in/targets.txt" in args


def test_array_renders_one_element_per_item() -> None:
    manifest, _ = m06_support.target_bound_manifest()
    schema = spec.load_input_schema(manifest.spec.inputSchemaRef)
    args = spec.render_args(
        manifest.spec.runtime.argsTemplate or [],
        {"targets": ["ip:10.0.0.5"], "ports": [80, 443]},
        schema,
    )
    index = args.index("-p")
    assert args[index + 1 : index + 3] == ["80", "443"]


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
    assert caught.value.code == "TARGET_REFS_MISMATCH"


def test_canonical_key_target_must_be_in_the_task_refs() -> None:
    task = m06_support.approved_task(
        targets=[{"canonical_key": "dns:internal.example"}],
        input={"targets": ["internal.example"], "concurrency": 2, "rate_limit": 1},
    )
    spec.recheck_targets(task, {"targets": ["internal.example"]})
    with pytest.raises(SpecError) as caught:
        spec.recheck_targets(task, {"targets": ["other.example"]})
    assert caught.value.code == "TARGET_REFS_MISMATCH"


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
    task = m06_support.task_for_manifest(manifest, raw, **kwargs.pop("task", {}))
    values = kwargs.pop("input", _input())
    platform = kwargs.pop("platform_cidrs", ("10.88.0.0/16",))
    denylist = kwargs.pop("target_denylist", ())
    return spec.build_spec(
        task,
        manifest,
        values,
        job_id="job-1",
        task_body=m06_support.body_of(task),
        key_ring=m06_support.DEV_RING,
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
) -> dict[str, Any]:
    return {
        "mode": mode,
        "target_binding": target_binding,
        "entries": entries,
        "target_addresses": addresses or [],
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
    assert set(built.egress_binding) == {"crt.sh:443", "otx.alienvault.com:443"}
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
            key_ring=m06_support.DEV_RING,
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
            key_ring=m06_support.DEV_RING,
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
            key_ring=m06_support.DEV_RING,
        )


def test_a_signed_binding_cannot_widen_the_declared_sources() -> None:
    manifest, raw = _manifest()
    task = m06_support.task_for_manifest(
        manifest,
        raw,
        egress_binding=_binding(
            ["crt.sh:443", "otx.alienvault.com:443", "evil.example:443"], target_binding="none"
        ),
    )
    with pytest.raises(SpecError, match="neither a declared source nor a target address"):
        spec.build_policy(
            task,
            manifest,
            _input(),
            job_id="job-1",
            task_body=m06_support.body_of(task),
            key_ring=m06_support.DEV_RING,
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
            key_ring=m06_support.DEV_RING,
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
        key_ring=m06_support.DEV_RING,
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
            key_ring=m06_support.DEV_RING,
        )


def test_target_bound_job_uses_the_signed_binding_ports() -> None:
    manifest, raw = m06_support.target_bound_manifest()
    task_input = {"targets": ["ip:10.1.2.3"], "ports": [8080, 8443]}
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
        key_ring=m06_support.DEV_RING,
        broker_proxy="http://10.97.0.2:3128",
        manifest_bytes=raw,
    )
    assert set(built.egress_binding) == {"10.1.2.3:8080", "10.1.2.3:8443"}
    index = built.args.index("-p")
    assert built.args[index + 1 : index + 3] == ["8080", "8443"]


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
            {"targets": ["ip:169.254.169.254"], "ports": [80]},
            job_id="job-1",
            task_body=m06_support.body_of(task),
            key_ring=m06_support.DEV_RING,
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
            key_ring=m06_support.DEV_RING,
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
        key_ring=m06_support.DEV_RING,
        platform_cidrs=("10.88.0.0/16",),
        target_denylist=("10.50.0.0/16", "denied.example"),
    )
    assert policy.mode == "egress"
    assert ipaddress.ip_network("10.88.0.0/16") in policy.platform_cidrs
    assert ipaddress.ip_network("10.50.0.0/16") in policy.deny_cidrs
    # A denied *name* cannot be a CIDR; the broker only reaches declared names, so it stays closed.
    assert len(policy.deny_cidrs) == 1
    decision = netpolicy.decide(policy, "crt.sh", 443)
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
            key_ring=m06_support.DEV_RING,
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
            {"targets": ["ip:10.1.2.3"], "ports": [70000]},
            job_id="job-1",
            task_body=m06_support.body_of(task),
            key_ring=m06_support.DEV_RING,
            broker_proxy="http://10.97.0.2:3128",
            manifest_bytes=raw,
        )


def test_policy_contract_shape_stays_json() -> None:
    policy = netpolicy.JobEgressPolicy(job_id="job-1")
    document: Mapping[str, Any] = netpolicy.policy_document(policy)
    assert json.loads(json.dumps(document))["job_id"] == "job-1"
