"""The M21 decision table: one pure function from a result document and the run's expectation.

The table is applied in order and the first applicable row wins (design §8.2):

  0  structural - the wrong document for this run (check id, pack hash, targets, cap, errors,
     a role that did not answer) is INCONCLUSIVE with the reason; a missing answer is never read
     as a negative;
  1  not specific - a catch-all that answers the real and the impossible path with the same 200
     body, or a canary-shaped value that is not this run's canary (echo/fake), is INCONCLUSIVE;
  2  the patched twin reproduced the observation: the twin is not a control, INCONCLUSIVE;
  3  the benign control matched: the observation is not specific, INCONCLUSIVE;
  4  positive matched and both controls answered without matching (lab): **VERIFIED**;
  5  the same on the internet (E1 only, no twin): **OBSERVED**, no status change;
  6  the positive did not match and both controls answered without matching: **NOT_REPRODUCED**
     (never FIXED, never FALSE_POSITIVE);
  7  a run that would verify a finding that moved since the request: INCONCLUSIVE (`stale`).

The oracles are per check (`checks.v2.yaml` `oracle`), and each one only compares server-held
values with what the document says was observed. G2-B implements `canary-extract`; the E1 oracles
(`certificate-property`, `tls-version-list`, `product-version`, `listing-name`) arrive with the
config-verify provider (slice S4) and are refused by name until then, never guessed.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from aegis.common.verification import VerificationCheck
from aegis.m21_verify.result import ResultDocument

__all__ = [
    "CANARY_PATTERN",
    "Decision",
    "Expectation",
    "FindingFacts",
    "OracleError",
    "RoleTarget",
    "decide",
    "token_sha256",
]

#: The shape of a canary the lab template extracts (`AEGIS-CANARY-<32 hex>`). A token of this shape
#: whose sha256 is not this run's canary is a fake/echo, never a hit.
CANARY_PATTERN = re.compile(r"AEGIS-CANARY-[0-9a-f]{32}")
LAB_ROLES = ("positive", "patched_twin", "benign")
INTERNET_ROLES = ("positive",)


class OracleError(RuntimeError):
    """The run cannot be decided by code (an oracle without an implementation), never a verdict."""


@dataclass(frozen=True, slots=True)
class RoleTarget:
    """One role of the run as the signed task named it."""

    role: str
    address: str
    port: int
    asset_id: str | None = None


@dataclass(frozen=True, slots=True)
class FindingFacts:
    """What M21 needs to know about the finding: its current sequence and, for E1, its location."""

    status: str
    transition_seq: int
    product: str | None = None
    version: str | None = None


@dataclass(frozen=True, slots=True)
class Expectation:
    """Everything M21 holds before reading the evidence; nothing comes from the request body."""

    check: VerificationCheck
    network_profile: str
    expected_seq: int
    target: RoleTarget
    controls: tuple[RoleTarget, ...] = ()
    check_pack_sha256: str | None = None
    canary_sha256: str | None = None
    canary_name_sha256: str | None = None
    canary_path: str | None = None
    benign_path: str | None = None
    finding: FindingFacts | None = None
    run_at: datetime | None = None

    @property
    def lab(self) -> bool:
        return self.network_profile == "lab"

    def control(self, role: str) -> RoleTarget | None:
        return self.signed().get(role)

    def signed(self) -> dict[str, RoleTarget]:
        """Every role the run must answer, as the signed task named it.

        A lab check's benign control is a request path on the positive host (the reviewed registry:
        `requests.cap = 2 paths x 2 addresses`), so when the task names no separate benign endpoint
        the positive target itself is the signed benign role.
        """
        roles = {"positive": self.target}
        for item in self.controls:
            roles[item.role] = item
        if self.check.lab_only and "benign" not in roles:
            roles["benign"] = RoleTarget("benign", self.target.address, self.target.port)
        return roles


@dataclass(frozen=True, slots=True)
class Decision:
    """The outcome, the summary M21 stores in `matched`, and the human reason."""

    outcome: str
    reason: str
    positive: bool = False
    control_a: bool = False
    control_b: bool = False
    discriminating: bool = False

    def matched(self) -> dict[str, Any]:
        """The `matched` member of the run row: inputs/outputs only, never a body or a canary."""
        return {
            "positive": self.positive,
            "control_a": self.control_a,
            "control_b": self.control_b,
            "discriminating": self.discriminating,
            "reason": self.reason[:2000],
        }

    @classmethod
    def inconclusive(cls, reason: str, **members: bool) -> Decision:
        return cls("INCONCLUSIVE", reason, **members)


def token_sha256(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _requests(target: Mapping[str, Any] | None) -> tuple[Mapping[str, Any], ...]:
    if target is None:
        return ()
    return tuple(target.get("requests") or ())


def _has_canary(target: Mapping[str, Any] | None, expected: str | None) -> bool:
    """True when one extracted token is exactly this run's canary (by hash, never by value)."""
    if target is None or expected is None:
        return False
    return any(
        isinstance(token, str) and token_sha256(token) == expected
        for request in _requests(target)
        for token in request.get("tokens") or ()
    )


def _tokens(target: Mapping[str, Any] | None) -> list[str]:
    if target is None:
        return []
    return [
        token
        for request in _requests(target)
        for token in request.get("tokens") or ()
        if isinstance(token, str)
    ]


def _answered(target: Mapping[str, Any] | None) -> bool:
    return target is not None and bool(target.get("answered")) and bool(_requests(target))


def _status(request: Mapping[str, Any]) -> int | None:
    value = request.get("status")
    return value if isinstance(value, int) else None


def _body(request: Mapping[str, Any]) -> str | None:
    value = request.get("body_sha256")
    return value if isinstance(value, str) else None


def required_roles(expectation: Expectation) -> tuple[str, ...]:
    """The roles this run must have answered: every declared control on the lab, only the positive
    on the internet (there is no twin there, and the internet pack carries E1 checks only)."""
    if not expectation.lab:
        return INTERNET_ROLES
    check = expectation.check
    roles = ["positive"]
    if check.targets.control_patched_twin:
        roles.append("patched_twin")
    if check.targets.control_benign:
        roles.append("benign")
    return tuple(roles)


def _role_matches(document: ResultDocument, expectation: Expectation) -> str | None:
    """The reason the document's roles are not the signed run's roles, or None."""
    required = required_roles(expectation)
    seen = {str(target.get("role")) for target in document.targets}
    if seen != set(required):
        return f"the result carries roles {sorted(seen)}, the run requires {sorted(required)}"
    expected_roles = expectation.signed()
    for role in required:
        target = document.role(role)
        signed = expected_roles.get(role)
        if target is None or signed is None:
            return f"role {role} has no signed target"
        if (
            str(target.get("address")) != signed.address
            or int(target.get("port", 0)) != signed.port
        ):
            return (
                f"role {role} answered from {target.get('address')}:{target.get('port')}, "
                f"the signed task names {signed.address}:{signed.port}"
            )
    return None


def _structural(document: ResultDocument, expectation: Expectation) -> Decision | None:
    """Row 0: the document must be this run's, complete, inside the cap and error-free."""
    check = expectation.check
    if document.check_id != check.check_id:
        return Decision.inconclusive(
            f"the evidence is for check {document.check_id!r}, the task signed {check.check_id!r}"
        )
    if expectation.check_pack_sha256 is not None and (
        document.check_pack_sha256 != expectation.check_pack_sha256
    ):
        return Decision.inconclusive(
            "the evidence was produced against another check pack than the signed task names"
        )
    if document.request_cap != check.request_cap:
        return Decision.inconclusive(
            f"the evidence ran with a cap of {document.request_cap}, the registry pins "
            f"{check.request_cap}"
        )
    if document.requests_sent > check.request_cap:
        return Decision.inconclusive(
            f"{document.requests_sent} requests exceed the check's cap of {check.request_cap}"
        )
    # The benign role repeats one request of the positive host (its path is the control), so the
    # run's count is the unique (address, port, path) set, not the sum of the role entries.
    counted = len(
        {
            (target.get("address"), target.get("port"), request.get("path"))
            for target in document.targets
            for request in _requests(target)
        }
    )
    if counted != document.requests_sent:
        return Decision.inconclusive(
            f"the evidence claims {document.requests_sent} requests but records {counted}"
        )
    if document.errors:
        codes = sorted({str(item.get("code")) for item in document.errors})
        return Decision.inconclusive(f"the provider reported errors: {', '.join(codes)}")
    mismatch = _role_matches(document, expectation)
    if mismatch is not None:
        return Decision.inconclusive(mismatch)
    for role in required_roles(expectation):
        target = document.role(role)
        if not _answered(target):
            return Decision.inconclusive(f"role {role} did not answer; silence is not a negative")
    return None


def _canary_extract(document: ResultDocument, expectation: Expectation) -> Decision:
    """L1: a canary read outside the served content, with both negative controls negative."""
    check = expectation.check
    if expectation.canary_sha256 is None:
        raise OracleError(f"{check.check_id}: the deployment has no canary hash for this check")
    if expectation.canary_path is None or expectation.benign_path is None:
        raise OracleError(f"{check.check_id}: the deployment has no canary/benign paths")
    positive = document.role("positive")
    twin = document.role("patched_twin")
    benign = document.role("benign")
    positive_hit = _has_canary(positive, expectation.canary_sha256)
    twin_hit = _has_canary(twin, expectation.canary_sha256)
    benign_hit = _has_canary(benign, expectation.canary_sha256)

    # Row 1a: a canary-shaped value that is not this run's canary (echo, another deployment's
    # canary, a fake). The comparison is by hash, so the value itself never reaches a log.
    for role, target in (("positive", positive), ("patched_twin", twin), ("benign", benign)):
        for token in _tokens(target):
            if CANARY_PATTERN.fullmatch(token) and token_sha256(token) != expectation.canary_sha256:
                return Decision.inconclusive(
                    f"role {role} returned a canary-shaped value that is not this run's canary",
                    positive=positive_hit,
                    control_a=twin_hit,
                    control_b=benign_hit,
                )

    # Row 1b: catch-all - the real path and a path that cannot exist answered with the same 200
    # body, so the answer says nothing about the vulnerability.
    real = next(
        (item for item in _requests(positive) if item.get("path") == expectation.canary_path),
        None,
    )
    impossible = next(
        (item for item in _requests(positive) if item.get("path") == expectation.benign_path),
        None,
    )
    if (
        real is not None
        and impossible is not None
        and _status(real) == 200
        and _status(impossible) == 200
        and _body(real) is not None
        and _body(real) == _body(impossible)
    ):
        return Decision.inconclusive(
            "the real path and a nonexistent path answered with the same 200 body (catch-all)"
        )

    matched = dict(positive=positive_hit, control_a=twin_hit, control_b=benign_hit)
    if twin_hit:  # Row 2
        return Decision.inconclusive(
            "the patched twin reproduced the read; the twin is not a control", **matched
        )
    if benign_hit:  # Row 3
        return Decision.inconclusive(
            "the benign control read the canary; the observation is not specific", **matched
        )
    if positive_hit:  # Row 4 (lab; a labOnly check never has an internet run)
        return Decision(
            "VERIFIED",
            "the positive target read the canary; the patched twin and the benign path did not",
            positive=True,
            control_a=False,
            control_b=False,
            discriminating=True,
        )
    # Row 6: every role answered and none matched.
    return Decision(
        "NOT_REPRODUCED",
        "the target answered but did not read the canary; that is not a fix",
        positive=False,
        control_a=False,
        control_b=False,
        discriminating=True,
    )


def _e1(document: ResultDocument, expectation: Expectation) -> Decision:
    """Rows 4/5/6 for a configuration check (implemented with the config-verify provider)."""
    check = expectation.check
    raise OracleError(
        f"{check.check_id}: the {check.oracle} oracle is not implemented yet "
        "(it arrives with the config-verify provider)"
    )


ORACLES: dict[str, Callable[[ResultDocument, Expectation], Decision]] = {
    "canary-extract": _canary_extract,
}


def decide(document: ResultDocument, expectation: Expectation) -> Decision:
    """Apply the M21 table; deterministic and free of IO, so tests can replay a stored document."""
    structural = _structural(document, expectation)
    if structural is not None:
        return structural
    oracle = ORACLES.get(expectation.check.oracle)
    if oracle is None:
        return _e1(document, expectation)
    decision = oracle(document, expectation)
    if decision.outcome == "VERIFIED" and not expectation.lab:
        # Row 5: no twin exists outside the lab, so the same observation is OBSERVED only.
        return Decision(
            "OBSERVED",
            "observed on the internet without a patched twin; no promotion",
            positive=decision.positive,
            control_a=decision.control_a,
            control_b=decision.control_b,
            discriminating=False,
        )
    return decision
