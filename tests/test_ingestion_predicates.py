"""G4 predicate registry checks used by M27 before an observation is written."""

from __future__ import annotations

import pytest

from aegis.m27_ingestion import predicates


def test_the_registry_is_loaded_from_the_contract() -> None:
    registry = predicates.predicates()
    assert "dns.record" in registry
    assert "asset.seen" in registry
    assert registry["asset.seen"].value_type == "boolean"
    assert "service" in registry["asset.seen"].subject_kinds
    assert registry["net.port_state"].enum == ("open", "closed", "filtered")


def test_a_valid_observation_passes() -> None:
    assert (
        predicates.check_value("dns.record", {"type": "A", "value": "192.0.2.1"}, "domain") is None
    )
    assert predicates.check_value("asset.seen", True, "domain") is None
    assert predicates.check_value("http.status", 200, "url") is None
    assert predicates.check_value("http.technology", ["nginx"], "application") is None


@pytest.mark.parametrize(
    ("predicate", "value", "subject_kind", "reason"),
    [
        ("dns.not_registered", True, "domain", predicates.UNKNOWN_PREDICATE),
        ("dns.record", {"type": "A"}, "ip", predicates.PREDICATE_SUBJECT_MISMATCH),
        ("dns.record", "not an object", "domain", predicates.PREDICATE_TYPE_MISMATCH),
        ("asset.seen", "true", "domain", predicates.PREDICATE_TYPE_MISMATCH),
        ("asset.seen", 1, "domain", predicates.PREDICATE_TYPE_MISMATCH),
        ("http.status", True, "url", predicates.PREDICATE_TYPE_MISMATCH),
        ("net.port_state", "half-open", "service", predicates.PREDICATE_ENUM_MISMATCH),
        ("http.technology", ["nginx", 1], "url", predicates.PREDICATE_TYPE_MISMATCH),
    ],
)
def test_each_gate_failure_has_a_stable_reason(
    predicate: str, value: object, subject_kind: str, reason: str
) -> None:
    assert predicates.check_value(predicate, value, subject_kind) == reason
