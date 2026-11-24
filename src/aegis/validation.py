"""Single semantic validation hook for every contract consumer.

Contracts are JSON Schema 2020-12 plus a set of semantic formats (`aegis-canonical-key`,
`aegis-domain-seed`, `aegis-ip-or-cidr`, `aegis-iana-timezone`, ...). The reference checks live in
contracts/validation.py and are part of the contract bundle; this module loads that file **by
path from the checkout** instead of copying it, so a schema consumer (service, generated DTO
validator, conformance test) can never validate against a stale fork of the rules.

Usage:

    from aegis import validation
    validation.validate("capability/approved-task.v2.schema.json", payload)   # raises
    validation.errors("common/ids.v2.schema.json#/$defs/Actor", payload)      # list[str]

The generated Pydantic models enforce the structural keywords themselves; they cannot enforce
the `aegis-*` formats (Pydantic ignores unknown formats), so a consumer calls this hook on the
payload as well. `validate_model()` does the dump-and-check in one step.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from functools import cache
from pathlib import Path
from types import ModuleType
from typing import Any, Protocol, cast

from jsonschema import Draft202012Validator, FormatChecker
from pydantic import BaseModel
from referencing import Registry, Resource

from aegis.common.repo import repository_root

CONTRACTS_BASE_URI = "https://aegis.io/contracts/"

__all__ = [
    "ContractUnavailable",
    "ContractViolation",
    "denied_egress_host",
    "document",
    "errors",
    "format_checker",
    "openapi_errors",
    "problems",
    "schemas",
    "validate",
    "validate_model",
]


class ContractUnavailable(RuntimeError):
    """contracts/ cannot be loaded (missing checkout, unreadable schema, unparsable README)."""


class ContractViolation(ValueError):
    """A payload does not satisfy its contract; `errors` lists every problem found."""

    def __init__(self, reference: str, errors: list[str]) -> None:
        self.reference = reference
        self.errors = tuple(errors)
        detail = "; ".join(self.errors[:5]) if self.errors else "no detail"
        super().__init__(f"{reference}: {detail}")


class _ContractChecks(Protocol):
    """The callables contracts/validation.py must expose (OI: shared validator)."""

    def format_checker(self) -> FormatChecker: ...

    def openapi_errors(self, document: dict[str, Any], source: Path) -> list[str]: ...

    def denied_egress_host(self, host: str) -> bool: ...


@cache
def _checks() -> _ContractChecks:
    path = repository_root() / "contracts/validation.py"
    spec = importlib.util.spec_from_file_location("aegis_contract_validation", path)
    if spec is None or spec.loader is None:
        raise ContractUnavailable(f"cannot load {path}")
    module: ModuleType = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as error:  # noqa: BLE001 - surfaced as one loud, typed failure
        sys.modules.pop(spec.name, None)
        raise ContractUnavailable(f"cannot import {path}: {error}") from error
    for attribute in ("format_checker", "openapi_errors", "denied_egress_host"):
        if not hasattr(module, attribute):
            raise ContractUnavailable(f"{path} has no {attribute}()")
    return cast(_ContractChecks, module)


def format_checker() -> FormatChecker:
    """The semantic `aegis-*` format checker declared by contracts/validation.py."""
    return _checks().format_checker()


def denied_egress_host(host: str) -> bool:
    """True when `host` is in the platform egress deny set (C05/OI-5, contracts/validation.py).

    The deny set is a platform constant, so every consumer (M05 registry admission, the M06 broker)
    reads it from the contract bundle instead of keeping a second copy that can drift.
    """
    return _checks().denied_egress_host(host)


def openapi_errors(document_: dict[str, Any], source: Path) -> list[str]:
    """OpenAPI 3.1 conformance errors (delegates to the contract bundle)."""
    return _checks().openapi_errors(document_, source)


@cache
def schemas() -> dict[str, dict[str, Any]]:
    """Every contract JSON Schema, keyed by its path relative to contracts/."""
    root = repository_root() / "contracts"
    loaded: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*.schema.json")):
        relative = path.relative_to(root).as_posix()
        if relative.startswith("fixtures/"):
            continue
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ContractUnavailable(f"cannot read schema {relative}: {error}") from error
        if not isinstance(document, dict):
            raise ContractUnavailable(f"{relative}: a schema must be a JSON object")
        loaded[relative] = cast(dict[str, Any], document)
    if not loaded:
        raise ContractUnavailable(f"no *.schema.json under {root}")
    return loaded


@cache
def _registry() -> Registry:
    registry: Registry = Registry()
    for relative, schema in schemas().items():
        identifier = schema.get("$id")
        expected = CONTRACTS_BASE_URI + relative
        if identifier != expected:
            raise ContractUnavailable(f"{relative}: $id must be {expected}, is {identifier}")
        registry = registry.with_resource(identifier, Resource.from_contents(schema))
    return registry


def _split(reference: str) -> tuple[str, str | None]:
    path, _, fragment = reference.partition("#")
    if not path:
        raise ContractUnavailable(f"contract reference has no schema path: {reference!r}")
    if path not in schemas():
        raise ContractUnavailable(f"unknown contract schema: {path}")
    return path, (fragment or None)


def document(reference: str) -> dict[str, Any]:
    """The parsed schema (or sub-schema, when `reference` carries a JSON pointer)."""
    path, pointer = _split(reference)
    schema = schemas()[path]
    if pointer is None:
        return schema
    node: Any = schema
    for part in [token for token in pointer.lstrip("/").split("/") if token]:
        try:
            node = node[part.replace("~1", "/").replace("~0", "~")]
        except (KeyError, TypeError) as error:
            raise ContractUnavailable(f"{reference}: pointer does not exist ({error})") from error
    if not isinstance(node, dict):
        raise ContractUnavailable(f"{reference}: pointer does not select an object")
    return node


def _validator(reference: str) -> Draft202012Validator:
    path, pointer = _split(reference)
    if pointer is None:
        schema = schemas()[path]
    else:
        # Validate a sub-schema through its parent resource: an absolute $ref into the registry
        # selects the pointer, and the sub-schema keeps the document's $id as base URI, so its
        # own relative $refs ($defs, sibling files) still resolve.
        schema = {"$ref": f"{CONTRACTS_BASE_URI}{path}#{pointer}"}
    return Draft202012Validator(schema, registry=_registry(), format_checker=format_checker())


def problems(reference: str, instance: Any) -> list[tuple[str, str]]:
    """Every contract violation of `instance` as `(JSON Pointer, message)`, by document path."""
    validator = _validator(reference)
    found = sorted(validator.iter_errors(instance), key=lambda error: list(error.absolute_path))
    return [
        (f"/{'/'.join(str(part) for part in error.absolute_path)}", error.message)
        for error in found
    ]


def errors(reference: str, instance: Any) -> list[str]:
    """Every contract violation of `instance`, ordered by document path."""
    return [f"{pointer}: {message}" for pointer, message in problems(reference, instance)]


def validate(reference: str, instance: Any) -> None:
    """Raise `ContractViolation` unless `instance` satisfies the contract."""
    found = errors(reference, instance)
    if found:
        raise ContractViolation(reference, found)


def validate_model(reference: str, model: BaseModel) -> None:
    """Validate the wire form a caller is about to send, so semantic formats are checked too.

    `exclude_unset=True` is deliberate: a field the caller never set is not sent, so a codegen
    default can never inject a key the contract forbids in that context (for example
    `permissions.targetPorts` is a `const` default in the generated model but the contract refuses
    it when `targetBinding` is `none`). A required field the caller forgot stays missing, which is
    exactly the failure the caller needs to see.
    """
    payload = model.model_dump(mode="json", by_alias=True, exclude_unset=True)
    validate(reference, payload)
