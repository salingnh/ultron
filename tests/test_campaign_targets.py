"""Seed canonical keys: the service implementation must reproduce aegis-norm/1 byte for byte.

The authoritative expectations are the published golden vectors
(`contracts/fixtures/golden/identity/normalization.vectors.json`); the reference
implementation in `contracts/tests/normalization.py` is test-only and used here as a
second, independent check of the same inputs. The service implementation is a
separate module (as that reference's header requires: no service imports it).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest

from aegis.contracts_gen.campaign.campaign_create_v2_schema import CampaignCreate
from aegis.m01_campaign.targets import (
    SEED_ARRAY_KINDS,
    SeedTarget,
    seed_canonical_key,
    seed_targets,
)

from .campaign_support import fixture

SEED_KINDS = ("domain", "ip", "url", "email")


def _golden() -> dict[str, Any]:
    path = (
        Path(__file__).resolve().parents[1]
        / "contracts/fixtures/golden/identity/normalization.vectors.json"
    )
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _reference() -> ModuleType:
    """The contract's test-only reference implementation, loaded by path."""
    path = Path(__file__).resolve().parents[1] / "contracts/tests/normalization.py"
    spec = importlib.util.spec_from_file_location("aegis_norm_reference", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_service_implementation_reproduces_the_golden_vectors() -> None:
    golden = _golden()
    assert golden["version"] == "aegis-norm/1"
    checked = 0
    for vector in golden["vectors"]:
        if vector["kind"] not in SEED_KINDS:
            continue
        assert seed_canonical_key(vector["kind"], vector["raw"]) == vector["canonical_key"], vector[
            "name"
        ]
        checked += 1
    assert checked >= 25, "the golden set must cover the seed kinds"


def test_golden_rejections_have_no_seed_identity() -> None:
    for vector in _golden()["rejected"]:
        if vector["kind"] not in SEED_KINDS:
            continue
        assert seed_canonical_key(vector["kind"], vector["raw"]) is None, vector["name"]


def test_golden_collapses_map_to_one_key() -> None:
    for vector in _golden()["collapses"]:
        if vector["kind"] not in SEED_KINDS:
            continue
        keys = {seed_canonical_key(vector["kind"], raw) for raw in vector["raws"]}
        assert len(keys) == 1 and None not in keys, vector["name"]


def test_seed_implementation_matches_the_reference_on_every_input() -> None:
    reference = _reference()
    golden = _golden()
    raws: set[tuple[str, str]] = set()
    for vector in golden["vectors"] + golden["rejected"]:
        if vector["kind"] in SEED_KINDS:
            raws.add((vector["kind"], vector["raw"]))
    for vector in golden["collapses"]:
        if vector["kind"] in SEED_KINDS:
            raws.update((vector["kind"], raw) for raw in vector["raws"])
    raws.update(
        (kind, raw)
        for kind, raw in [
            ("domain", "Example.COM."),
            ("domain", "Bücher.Example"),
            ("ip", "2001:db8:0:0:0:0:0:1"),
            ("ip", "::ffff:10.0.0.1"),
            ("url", "HTTPS://Example.COM:443/a/../b?token=x&a=1"),
            ("url", "http://[2001:db8::1]/"),
            ("email", "User.Name@Bücher.Example"),
        ]
    )
    for kind, raw in sorted(raws):
        try:
            expected = reference.canonical_key(kind, raw)
        except reference.NormalizationError:
            expected = None
        assert seed_canonical_key(kind, raw) == expected, (kind, raw)


@pytest.mark.parametrize(
    ("kind", "raw", "expected"),
    [
        ("domain", "Internal.Example.", "dns:internal.example"),
        ("ip", "10.20.0.1", "ip:10.20.0.1"),
        ("ip", "2001:DB8::1", "ip:2001:db8::1"),
        ("url", "https://portal.example", "url:https://portal.example:443/"),
        ("url", "http://portal.example:8080/a?b=2&a=1", "url:http://portal.example:8080/a?a=1&b=2"),
        ("email", "Analyst@Example.COM", "email:Analyst@example.com"),
        # Documented NULL cases: no asset identity on purpose.
        ("keyword", "acme corp", None),
        ("cidr", "10.20.0.0/24", None),
        ("url", "ftp://files.example/pub", None),
        ("url", "https://user:secret@example.com/", None),
        ("domain", "10.0.0.1", None),
        ("service", "10.0.0.1:443/tcp", None),
    ],
)
def test_seed_canonical_key_cases(kind: str, raw: str, expected: str | None) -> None:
    assert seed_canonical_key(kind, raw) == expected


def test_seed_targets_flattens_arrays_and_splits_ip_from_cidr() -> None:
    rows = seed_targets(
        {
            "domains": ["Internal.Example."],
            "ips": ["10.20.0.1", "10.20.0.0/24"],
            "urls": ["https://portal.example/login"],
            "emails": ["Analyst@Example.COM"],
            "keywords": ["acme corp"],
        }
    )
    assert [(row.kind, row.raw_value) for row in rows] == [
        ("domain", "Internal.Example."),
        ("ip", "10.20.0.1"),
        ("cidr", "10.20.0.0/24"),
        ("url", "https://portal.example/login"),
        ("email", "Analyst@Example.COM"),
        ("keyword", "acme corp"),
    ]
    assert [row.canonical_key for row in rows] == [
        "dns:internal.example",
        "ip:10.20.0.1",
        None,
        "url:https://portal.example:443/login",
        "email:Analyst@example.com",
        None,
    ]
    assert isinstance(rows[0], SeedTarget)


def test_contract_fixture_parses_into_the_generated_dto() -> None:
    body = fixture("valid/campaign-create.json")
    model = CampaignCreate.model_validate(body)
    # The verbatim seed snapshot is the input snapshot: dumping must not invent fields.
    dumped = model.model_dump(mode="json", exclude_unset=True, by_alias=True)
    assert dumped["targets"] == body["targets"]
    assert set(SEED_ARRAY_KINDS) >= {"domains", "ips", "urls", "emails", "keywords"}
