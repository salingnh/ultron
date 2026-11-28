"""The finding transition table (`contracts/finding/transitions.v2.yaml`) as one rule set.

A status change of a finding is never decided by the caller: M20, M21, M24 and the operator API
all ask this module whether `(from_status, to_status)` is allowed for the module acting, and
whether the table's `requires` are satisfied (a reason, evidence with a sha256). The table is read
from the contract bundle by path, so there is one copy of the rule and a code change cannot drift
from the schema.

`by` is the *acting* side, not the producer of the HTTP call: the operator transition endpoint of
M26 acts as `operator` (the server-verified principal), while the finding producer acts as `M20`.
"""

from __future__ import annotations

from collections.abc import Mapping
from functools import cache
from typing import Any

import yaml

from aegis.common.repo import contract_path

__all__ = [
    "TRANSITIONS",
    "FindingTransitionTable",
    "TransitionRule",
    "load_transitions",
    "rule_for",
]

TRANSITIONS = ("finding", "transitions.v2.yaml")
#: Who may act on a finding; the table uses the same tokens.
ACTORS = ("M20", "M21", "M24", "operator")
REQUIREMENTS = ("reason", "evidence")


class TransitionRule(Mapping[str, Any]):
    """One row of the table with its `from`/`to`/`by`/`requires` normalized."""

    def __init__(self, raw: Mapping[str, Any]) -> None:
        self.raw = dict(raw)
        source = raw.get("from")
        if source is None:
            self.from_statuses: tuple[str | None, ...] = (None,)
        elif isinstance(source, list):
            self.from_statuses = tuple(source)
        else:
            self.from_statuses = (str(source),)
        self.to_status = str(raw["to"])
        by = raw.get("by") or ()
        self.actors: tuple[str, ...] = tuple(str(item) for item in by)
        self.requires: tuple[str, ...] = tuple(str(item) for item in raw.get("requires") or ())
        self.note = raw.get("note")

    def __getitem__(self, key: str) -> Any:
        return self.raw[key]

    def __iter__(self) -> Any:
        return iter(self.raw)

    def __len__(self) -> int:
        return len(self.raw)


class FindingTransitionTable:
    """Every allowed transition, loaded from the contract bundle once per process."""

    def __init__(self, rules: tuple[TransitionRule, ...]) -> None:
        self.rules = rules

    def rule_for(self, from_status: str | None, to_status: str, by: str) -> TransitionRule | None:
        """The first table row allowing this change for `by`, or None (a refusal)."""
        for rule in self.rules:
            if (
                from_status in rule.from_statuses
                and rule.to_status == to_status
                and by in rule.actors
            ):
                return rule
        return None


@cache
def load_transitions() -> FindingTransitionTable:
    """Parse the published table; an unreadable or malformed table fails loudly."""
    path = contract_path(*TRANSITIONS)
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not isinstance(document.get("transitions"), list):
        raise ValueError(f"{path}: transitions.v2.yaml needs a `transitions` list")
    rules: list[TransitionRule] = []
    for index, raw in enumerate(document["transitions"]):
        if not isinstance(raw, dict):
            raise ValueError(f"{path}: transitions[{index}] must be a mapping")
        rule = TransitionRule(raw)
        if not rule.actors or any(actor not in ACTORS for actor in rule.actors):
            raise ValueError(f"{path}: transitions[{index}].by is not one of {ACTORS}")
        unknown = [item for item in rule.requires if item not in REQUIREMENTS]
        if unknown:
            raise ValueError(f"{path}: transitions[{index}] requires unknown {unknown}")
        if not rule.from_statuses or any(
            status is not None and not isinstance(status, str) for status in rule.from_statuses
        ):
            raise ValueError(f"{path}: transitions[{index}].from is malformed")
        rules.append(rule)
    return FindingTransitionTable(tuple(rules))


def rule_for(from_status: str | None, to_status: str, by: str) -> TransitionRule | None:
    """Shorthand for `load_transitions().rule_for(...)`."""
    return load_transitions().rule_for(from_status, to_status, by)
