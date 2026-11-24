"""`aegis-norm/1` in the service: golden vectors and parity with the contract reference (G0.3c).

The golden file is the independent expectation (written from the rules); the reference module in
`contracts/tests/normalization.py` is the conformance implementation. M27 must reproduce both,
because the key it re-derives is what decides whether an asset is the same asset.
"""

from __future__ import annotations

import runpy
from typing import Any

import pytest

from aegis.m27_ingestion import normalize
from tests.support import REPO_ROOT, load_fixture

GOLDEN = load_fixture("golden/identity/normalization.vectors.json")
REFERENCE: dict[str, Any] = runpy.run_path(str(REPO_ROOT / "contracts/tests/normalization.py"))


def test_the_registry_version_is_the_implemented_version() -> None:
    assert GOLDEN["version"] == normalize.NORM_VERSION
    registry = load_fixture("../../contracts/ingestion/normalization.v2.yaml")
    assert registry["version"] == normalize.NORM_VERSION


def test_the_sensitive_parameter_list_is_the_shared_one() -> None:
    assert normalize.SENSITIVE_QUERY_PARAMS == REFERENCE["SENSITIVE_QUERY_PARAMS"]
    assert normalize.SENSITIVE_QUERY_PARAM_SUFFIXES == REFERENCE["SENSITIVE_QUERY_PARAM_SUFFIXES"]
    assert normalize.SENSITIVE_QUERY_PARAM_PREFIXES == REFERENCE["SENSITIVE_QUERY_PARAM_PREFIXES"]


def test_every_golden_vector_is_reproduced() -> None:
    for vector in GOLDEN["vectors"]:
        produced = normalize.normalize(vector["kind"], vector["raw"])
        assert produced.canonical_key == vector["canonical_key"], vector["name"]
        assert produced.detail == vector.get("detail"), vector["name"]
        assert produced.version == normalize.NORM_VERSION


def test_every_rejected_vector_keeps_its_reason() -> None:
    for vector in GOLDEN["rejected"]:
        with pytest.raises(normalize.NormalizationError) as ours:
            normalize.normalize(vector["kind"], vector["raw"])
        assert ours.value.reason == vector["reason"], vector["name"]
        with pytest.raises(REFERENCE["NormalizationError"]) as reference:
            REFERENCE["normalize"](vector["kind"], vector["raw"])
        assert reference.value.reason == vector["reason"], vector["name"]


def test_collapse_groups_produce_one_key() -> None:
    for group in GOLDEN["collapses"]:
        keys = {normalize.canonical_key(group["kind"], raw) for raw in group["raws"]}
        assert keys == {group["canonical_key"]}, group["name"]


def test_a_stored_key_normalizes_back_to_itself() -> None:
    keys = [vector["canonical_key"] for vector in GOLDEN["vectors"]]
    keys += [group["canonical_key"] for group in GOLDEN["collapses"]]
    for key in keys:
        assert normalize.validate_key(key).canonical_key == key, key


def test_parity_with_the_reference_implementation() -> None:
    for vector in GOLDEN["vectors"]:
        ours = normalize.normalize(vector["kind"], vector["raw"])
        reference = REFERENCE["normalize"](vector["kind"], vector["raw"])
        assert (ours.canonical_key, ours.detail) == (
            reference.canonical_key,
            reference.detail,
        ), vector["name"]


def test_an_adapter_key_that_is_not_canonical_is_detected_not_rewritten() -> None:
    # Passes the CanonicalKey structure regex but aegis-norm/1 compresses the IPv6 literal.
    with pytest.raises(normalize.KeyRejection) as rejection:
        normalize.validate_key("ip:0:0:0:0:0:0:0:1")
    assert rejection.value.reason == normalize.NON_CANONICAL_KEY

    with pytest.raises(normalize.KeyRejection) as mismatch:
        normalize.validate_key("ip:192.0.2.10", "domain")
    assert mismatch.value.reason == normalize.ASSET_KIND_MISMATCH


def test_every_listed_sensitive_parameter_is_dropped() -> None:
    for parameter in normalize.SENSITIVE_QUERY_PARAMS:
        key = normalize.canonical_key("url", f"https://example.com/?{parameter}=secret&keep=1")
        assert key == "url:https://example.com:443/?keep=1", parameter
    assert normalize.is_sensitive_param("X-Amz-Signature")
    assert normalize.is_sensitive_param("api-token")
    assert not normalize.is_sensitive_param("id")


def test_unsupported_kinds_are_quarantined_not_invented() -> None:
    for kind in ("cloud_resource", "k8s_workload"):
        with pytest.raises(normalize.NormalizationError) as rejection:
            normalize.normalize(kind, "anything")
        assert rejection.value.reason == "kind_not_supported"
