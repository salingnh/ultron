"""The contracts generate the DTOs, and the generated DTOs accept the contract fixtures.

This is the G1.1a round-trip gate for the codegen half of the task: every `valid/*` fixture must
satisfy its JSON Schema (including the semantic `aegis-*` formats of contracts/validation.py),
parse into the generated Pydantic model, and survive a dump/re-parse cycle; every `invalid/*`
fixture must be refused.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from aegis import validation
from tests.support import (
    dto_module,
    invalid_fixtures,
    load_fixture,
    root_dto,
    valid_fixtures,
)

VALID = sorted(valid_fixtures().items())
INVALID = sorted(invalid_fixtures().items())
WITH_ROOT_DTO = [(fixture, reference) for fixture, reference in VALID if "#" not in reference]
FRAGMENT_REFS = [(fixture, reference) for fixture, reference in VALID if "#" in reference]


@pytest.mark.parametrize(("fixture", "reference"), VALID, ids=[fixture for fixture, _ in VALID])
def test_valid_fixture_satisfies_contract(fixture: str, reference: str) -> None:
    validation.validate(reference, load_fixture(fixture))


@pytest.mark.parametrize(("fixture", "reference"), INVALID, ids=[fixture for fixture, _ in INVALID])
def test_invalid_fixture_is_refused(fixture: str, reference: str) -> None:
    assert validation.errors(reference, load_fixture(fixture)), f"{fixture} was accepted"


@pytest.mark.parametrize(
    ("fixture", "reference"),
    WITH_ROOT_DTO,
    ids=[fixture for fixture, _ in WITH_ROOT_DTO],
)
def test_generated_dto_roundtrip(fixture: str, reference: str) -> None:
    payload = load_fixture(fixture)
    model = root_dto(reference)
    parsed = model.model_validate(payload)
    # Only the fields the payload actually carried: a generated default must not invent a key the
    # contract conditionally forbids (see validation.validate_model).
    dumped = parsed.model_dump(mode="json", by_alias=True, exclude_unset=True)
    validation.validate(reference, dumped)
    assert model.model_validate(dumped) == parsed
    validation.validate_model(reference, parsed)


@pytest.mark.parametrize(
    ("fixture", "reference"),
    FRAGMENT_REFS,
    ids=[fixture for fixture, _ in FRAGMENT_REFS],
)
def test_fragment_fixture_uses_generated_module(fixture: str, reference: str) -> None:
    # A fixture that points at a $defs sub-schema has no generated root model; the module that
    # owns the parent schema must still exist and import (drift of the module naming is a codegen
    # change, not a test detail).
    assert dto_module(reference).__name__.startswith("aegis.contracts_gen.")


def test_every_contract_schema_has_a_generated_module() -> None:
    for reference in sorted(validation.schemas()):
        assert dto_module(reference).__name__


def test_semantic_format_is_enforced_by_the_shared_hook() -> None:
    # Pydantic ignores `format: aegis-iana-timezone` (it is not a JSON Schema standard format), so
    # this proves the shared hook in contracts/validation.py is what rejects it, not a regex copy.
    payload = load_fixture("valid/campaign-create.json")
    payload["targets"]["domains"] = ["-not-a-domain.example"]
    model = root_dto("campaign/campaign-create.v2.schema.json").model_validate(payload)
    with pytest.raises(validation.ContractViolation) as violation:
        validation.validate_model("campaign/campaign-create.v2.schema.json", model)
    assert "aegis-domain-seed" in str(violation.value)
    assert any("aegis-domain-seed" in error for error in violation.value.errors)


def test_generated_dto_refuses_unknown_field() -> None:
    payload = load_fixture("valid/campaign-create.json")
    payload["not_in_the_contract"] = True
    with pytest.raises(ValidationError):
        root_dto("campaign/campaign-create.v2.schema.json").model_validate(payload)


def test_sub_schema_reference_validation_uses_the_parent_resource() -> None:
    actor = validation.document("common/ids.v2.schema.json#/$defs/Actor")
    assert actor.get("type") == "object"
    assert not validation.errors(
        "common/ids.v2.schema.json#/$defs/Actor", {"kind": "operator", "id": "opaque-1"}
    )
    assert validation.errors("common/ids.v2.schema.json#/$defs/Actor", {"kind": "robot"})
