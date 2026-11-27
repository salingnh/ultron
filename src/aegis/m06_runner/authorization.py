"""The structured RoE authorization of an internet task (F5, R6; item #61).

`policy_snapshot.policy -> authorization` is the owner's statement that the targets are theirs:
who authorized it (`owner`), the evidence (`reference`), the date and the domain suffixes the
campaign may touch. M06 used to accept any non-empty *rendered* string, so a mapping with only one
field rendered as `" |  |  | "` and passed; every field is checked here instead, and the rendered
line exists only for the audit record.

The rules mirror `contracts/campaign/roe-policy.v2.schema.json` and the database mirror
`aegis.is_roe_authorization` (migration 0006). The contract and database own acceptance of a
campaign; this module is what M06 believes at dispatch time, so it must not trust the database row
to have been written by a validating writer.
"""

from __future__ import annotations

import datetime
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

__all__ = ["Authorization", "authorization_of"]

#: The closed key set of the authorization object; anything else is not the shape M05 signed.
AUTHORIZATION_KEYS = frozenset({"owner", "reference", "date", "authorized_suffixes"})
MAX_SUFFIXES = 100


@dataclass(frozen=True, slots=True)
class Authorization:
    """A validated authorization object."""

    owner: str
    reference: str
    date: str
    suffixes: tuple[str, ...]

    def reference_line(self) -> str:
        """The audit form: owner, evidence, date and the authorized suffixes, one line."""
        return f"{self.owner} | {self.reference} | {self.date} | {', '.join(self.suffixes)}"


def _text_field(value: Mapping[str, Any], key: str, minimum: int, maximum: int) -> str | None:
    raw = value.get(key)
    if not isinstance(raw, str):
        return None
    stripped = raw.strip()
    return stripped if minimum <= len(stripped) <= maximum else None


def _date_field(value: Mapping[str, Any]) -> str | None:
    raw = value.get("date")
    if not isinstance(raw, str):
        return None
    try:
        parsed = datetime.date.fromisoformat(raw.strip())
    except ValueError:
        return None
    return parsed.isoformat()


def authorization_of(value: object) -> tuple[Authorization | None, str]:
    """The authorization object of a policy snapshot, and why it is unusable (`""` when it is).

    Returning the reason lets the caller refuse with a definite, auditable explanation instead of
    a generic "missing authorization": the operator needs to know which field is wrong.
    """
    if value is None:
        return None, "the campaign RoE has no authorization object"
    if not isinstance(value, Mapping):
        return None, "the campaign RoE authorization is not an object"
    unknown = sorted(str(key) for key in set(value) - AUTHORIZATION_KEYS)
    if unknown:
        return None, f"the campaign RoE authorization has unknown field(s) {unknown}"
    owner = _text_field(value, "owner", 1, 200)
    if owner is None:
        return None, "authorization.owner must be 1-200 characters"
    reference = _text_field(value, "reference", 3, 300)
    if reference is None:
        return None, "authorization.reference must be 3-300 characters"
    date = _date_field(value)
    if date is None:
        return None, "authorization.date must be a real YYYY-MM-DD date"
    raw_suffixes = value.get("authorized_suffixes")
    if not isinstance(raw_suffixes, list) or not 1 <= len(raw_suffixes) <= MAX_SUFFIXES:
        return None, "authorization.authorized_suffixes must list 1-100 suffixes"
    suffixes: list[str] = []
    for item in raw_suffixes:
        if not isinstance(item, str) or not item.strip():
            return None, "authorization.authorized_suffixes must be non-empty names"
        host = item.strip().lower().rstrip(".")
        if host not in suffixes:
            suffixes.append(host)
    if not suffixes:
        return None, "authorization.authorized_suffixes must list at least one suffix"
    return Authorization(owner=owner, reference=reference, date=date, suffixes=tuple(suffixes)), ""
