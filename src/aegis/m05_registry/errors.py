"""M05 refusals as contract errors: the one place a decision maps to HTTP, error code and rule.

Every refusal carries a contract `Error` (code + next_action from `common/error.v2.schema.json`),
the
event `rule` string (`policy.denied.v2` publishes it), an JSON Pointer `field` when it is an input
problem, and the HTTP status the REST layer answers.

Two refusals are deliberately different:

* `INPUT_INVALID` (400) is a client error raised *before* a policy decision exists: the request
  cannot
  name a resolvable target, or its merged input does not satisfy the pinned input schema. The
  contract
  cannot record it as a `policy_decision` (0012 requires resolved TargetRefs for every new
  decision),
  and OpenAPI only promises `policy.denied.v2` for a job refused by policy (403) - so it is answered
  with `Error` and no decision row.
* A policy refusal (`POLICY_DENIED`, `OUT_OF_SCOPE`, `RATE_LIMITED`) is a decision: M05 records it
  with the resolved TargetRefs it refuses and emits `policy.denied.v2` in the same transaction.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aegis.contracts_gen.common.error_v2_schema import Error, ErrorCode, NextAction

__all__ = ["M05Error", "Refusal"]

_DECIDED_CODES = frozenset(
    {ErrorCode.POLICY_DENIED, ErrorCode.OUT_OF_SCOPE, ErrorCode.RATE_LIMITED}
)


@dataclass(frozen=True, slots=True)
class Refusal:
    """A contract error plus the HTTP status and the policy rule that produced it."""

    code: ErrorCode
    rule: str
    message: str
    next_action: NextAction
    status_code: int
    field: str | None = None
    retry_after_seconds: int | None = None
    next_action_detail: str | None = None
    retryable: bool | None = None

    def payload(self, trace_id: str | None = None) -> dict[str, Any]:
        """The contract `Error` wire form: fixed keys plus the optional ones that are set."""
        body: dict[str, Any] = {
            "code": str(self.code),
            "message": self.message,
            "next_action": str(self.next_action),
        }
        optional = {
            "field": self.field,
            "retry_after_seconds": self.retry_after_seconds,
            "next_action_detail": self.next_action_detail,
            "retryable": self.retryable,
            "trace_id": trace_id,
        }
        body.update({key: value for key, value in optional.items() if value is not None})
        return body

    def error(self, trace_id: str | None = None) -> Error:
        return Error.model_validate(self.payload(trace_id))

    def body(self, trace_id: str | None = None) -> dict[str, Any]:
        return self.payload(trace_id)

    @property
    def is_decision(self) -> bool:
        """True when the refusal is a policy decision (recorded + published), not a bad request."""
        return self.code in _DECIDED_CODES


class M05Error(Exception):
    """Raised by M05 when a request is refused; carries a `Refusal`, never free text."""

    def __init__(self, refusal: Refusal) -> None:
        super().__init__(f"{refusal.code}: {refusal.message}")
        self.refusal = refusal

    # --- constructors -------------------------------------------------------------------
    @classmethod
    def input_invalid(cls, message: str, *, field: str | None = None) -> M05Error:
        return cls(
            Refusal(
                code=ErrorCode.INPUT_INVALID,
                rule="schema",
                message=message,
                next_action=NextAction.FIX_INPUT,
                status_code=400,
                field=field,
                retryable=False,
            )
        )

    @classmethod
    def policy_denied(
        cls,
        rule: str,
        message: str,
        *,
        field: str | None = None,
        next_action: NextAction = NextAction.FIX_INPUT,
        detail: str | None = None,
    ) -> M05Error:
        return cls(
            Refusal(
                code=ErrorCode.POLICY_DENIED,
                rule=rule,
                message=message,
                next_action=next_action,
                status_code=403,
                field=field,
                next_action_detail=detail,
                retryable=False,
            )
        )

    @classmethod
    def out_of_scope(cls, rule: str, message: str, *, field: str | None = None) -> M05Error:
        return cls(
            Refusal(
                code=ErrorCode.OUT_OF_SCOPE,
                rule=rule,
                message=message,
                next_action=NextAction.FIX_INPUT,
                status_code=403,
                field=field,
                retryable=False,
            )
        )

    @classmethod
    def rate_limited(cls, rule: str, message: str, retry_after_seconds: int) -> M05Error:
        return cls(
            Refusal(
                code=ErrorCode.RATE_LIMITED,
                rule=rule,
                message=message,
                next_action=NextAction.RETRY_LATER,
                status_code=429,
                retry_after_seconds=max(1, retry_after_seconds),
                retryable=True,
            )
        )

    @classmethod
    def idempotency_conflict(cls, message: str) -> M05Error:
        return cls(
            Refusal(
                code=ErrorCode.IDEMPOTENCY_CONFLICT,
                rule="idempotency_key",
                message=message,
                next_action=NextAction.FIX_INPUT,
                status_code=409,
                retryable=False,
            )
        )

    @classmethod
    def not_found(cls, message: str) -> M05Error:
        return cls(
            Refusal(
                code=ErrorCode.DEPENDENCY_MISSING,
                rule="not_found",
                message=message,
                next_action=NextAction.NONE,
                status_code=404,
                retryable=False,
            )
        )

    @classmethod
    def dependency_missing(cls, message: str, *, field: str | None = None) -> M05Error:
        return cls(
            Refusal(
                code=ErrorCode.DEPENDENCY_MISSING,
                rule="dependency_missing",
                message=message,
                next_action=NextAction.ESCALATE,
                status_code=503,
                field=field,
                retryable=True,
            )
        )
