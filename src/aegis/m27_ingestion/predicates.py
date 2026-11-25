"""The Observation predicate registry (G4): every predicate/type/subject-kind rule M27 enforces.

Normative source: contracts/ingestion/predicates.v2.yaml. An adapter may only emit a predicate that
is listed there, with the declared `value_type`, on one of its `subject_kinds`, and inside the
declared `enum` when there is one. A record that fails the check is quarantined with the gate G4 and
one of the stable reasons below; it is never coerced into a shape the registry does not publish.

The YAML is read from the checkout (one copy, like every other registry) and cached per process.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache
from typing import Any, cast

import yaml

from aegis.common.repo import contract_path

__all__ = [
    "PREDICATE_ENUM_MISMATCH",
    "graph_predicate",
    "PREDICATE_SUBJECT_MISMATCH",
    "PREDICATE_TYPE_MISMATCH",
    "Predicate",
    "UNKNOWN_PREDICATE",
    "check_value",
    "predicate",
]

UNKNOWN_PREDICATE = "unknown_predicate"
PREDICATE_TYPE_MISMATCH = "predicate_value_type_mismatch"
PREDICATE_SUBJECT_MISMATCH = "predicate_subject_kind_mismatch"
PREDICATE_ENUM_MISMATCH = "predicate_value_outside_enum"


@dataclass(frozen=True, slots=True)
class Predicate:
    """One registry row: the value type, the allowed subject kinds, an optional enum, graph flag."""

    name: str
    value_type: str
    subject_kinds: frozenset[str]
    enum: tuple[object, ...] | None = None
    graph: bool = False


@cache
def predicates() -> dict[str, Predicate]:
    document = yaml.safe_load(
        contract_path("ingestion/predicates.v2.yaml").read_text(encoding="utf-8")
    )
    if not isinstance(document, dict) or not isinstance(document.get("predicates"), dict):
        raise RuntimeError("contracts/ingestion/predicates.v2.yaml has no `predicates` mapping")
    rows: dict[str, Predicate] = {}
    for name, row in cast(dict[str, Any], document["predicates"]).items():
        if not isinstance(name, str) or not isinstance(row, dict):
            raise RuntimeError(f"predicate registry row {name!r} is not a mapping")
        kinds = row.get("subject_kinds")
        if not isinstance(kinds, list) or not all(isinstance(kind, str) for kind in kinds):
            raise RuntimeError(f"predicate {name}: subject_kinds must be a list of strings")
        value_type = row.get("value_type")
        if not isinstance(value_type, str):
            raise RuntimeError(f"predicate {name}: value_type must be a string")
        enum = row.get("enum")
        if enum is not None and not isinstance(enum, list):
            raise RuntimeError(f"predicate {name}: enum must be a list")
        graph = row.get("graph", False)
        if not isinstance(graph, bool):
            raise RuntimeError(f"predicate {name}: graph must be a boolean")
        rows[name] = Predicate(
            name=name,
            value_type=value_type,
            subject_kinds=frozenset(kinds),
            enum=tuple(enum) if enum is not None else None,
            graph=graph,
        )
    return rows


def predicate(name: str) -> Predicate | None:
    return predicates().get(name)


def graph_predicate(name: str) -> bool:
    """True when the registry marks this predicate for the `:Observation` graph projection (M23)."""
    rule = predicate(name)
    return bool(rule is not None and rule.graph)


def _matches_type(value: object, value_type: str) -> bool:
    # bool is an int subclass in Python and must not satisfy integer/number.
    if value_type == "string":
        return isinstance(value, str)
    if value_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if value_type == "number":
        return isinstance(value, int | float) and not isinstance(value, bool)
    if value_type == "boolean":
        return isinstance(value, bool)
    if value_type == "object":
        return isinstance(value, dict)
    if value_type == "string_list":
        return isinstance(value, list) and all(isinstance(item, str) for item in value)
    return False


def check_value(name: str, value: object, subject_kind: str) -> str | None:
    """The G4 quarantine reason for one observation, or None when the record is valid."""
    rule = predicate(name)
    if rule is None:
        return UNKNOWN_PREDICATE
    if subject_kind not in rule.subject_kinds:
        return PREDICATE_SUBJECT_MISMATCH
    if not _matches_type(value, rule.value_type):
        return PREDICATE_TYPE_MISMATCH
    if rule.enum is not None and value not in rule.enum:
        return PREDICATE_ENUM_MISMATCH
    return None
