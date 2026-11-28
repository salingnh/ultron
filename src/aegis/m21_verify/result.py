"""The verification result document (`verification-result.v2`) as a contract object.

The provider writes what it saw; this module is the one reader. Every consumer (M06's adapter
parser in tests, M21 at decision time) validates the same closed schema and refuses a document that
does not match, so a swapped or truncated output file is a loud failure instead of a weaker
decision. The document carries **no expected value**: no canary, no threshold, no "matched" flag.

`load_result` reads bytes (the stored evidence object) and returns a validated document; the sha256
of the bytes is checked by the caller against the evidence row before the document is used.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, cast

from aegis import validation

__all__ = [
    "RESULT_SCHEMA",
    "ResultDocument",
    "ResultError",
    "load_result",
    "validate_result",
]

RESULT_SCHEMA = "verification/verification-result.v2.schema.json"


class ResultError(ValueError):
    """The bytes are not a valid verification result document."""


@dataclass(frozen=True, slots=True)
class ResultDocument:
    """One validated result document and its parsed members (the schema stays the source)."""

    raw: dict[str, Any]

    @property
    def check_id(self) -> str:
        return str(self.raw["check_id"])

    @property
    def check_pack_sha256(self) -> str:
        return str(self.raw["check_pack_sha256"])

    @property
    def tool(self) -> Mapping[str, Any]:
        return cast(Mapping[str, Any], self.raw["tool"])

    @property
    def targets(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(cast(list[Mapping[str, Any]], self.raw["targets"]))

    @property
    def requests_sent(self) -> int:
        return int(self.raw["requests_sent"])

    @property
    def request_cap(self) -> int:
        return int(self.raw["request_cap"])

    @property
    def errors(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(cast(list[Mapping[str, Any]], self.raw["errors"]))

    def role(self, name: str) -> Mapping[str, Any] | None:
        return next((target for target in self.targets if target.get("role") == name), None)


def validate_result(document: Any) -> ResultDocument:
    """Validate a parsed document against the contract; raises `ResultError` on any problem."""
    if not isinstance(document, dict):
        raise ResultError("the verification result must be a JSON object")
    problems = validation.problems(RESULT_SCHEMA, document)
    if problems:
        pointer, message = problems[0]
        raise ResultError(
            f"verification-result.v2 violates the contract at {pointer or '/'}: {message}"
        )
    return ResultDocument(raw=document)


def load_result(content: bytes) -> ResultDocument:
    """Parse and validate the stored result document."""
    try:
        document = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ResultError(f"the verification result is not JSON: {error}") from error
    return validate_result(document)
