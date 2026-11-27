"""M05 job acceptance: one transaction per submission (decision, signed task, job, deps, event).

The flow the contract describes (`contracts/mcp/README.md:22`,
`contracts/interfaces/README.md` §Manifest
bất biến, `contracts/README.md` §Scheduling) is implemented once here, for both the REST route
(`m26_api/jobs.py`, G1.1c) and the MCP server (G1.2b, which calls `submit`):

1. load the campaign and its **current** policy snapshot; a terminal campaign cannot accept work;
2. resolve the pinned manifest (`ManifestRegistry.resolve`) and refuse an unknown capability as a
   recorded policy decision, not as a 500;
3. merge `inputDefaults`, validate the merged input against the pinned capability schema, and keep
that
   merged value - it is what the decision approves, what the job stores and what the runner executes
   (0014 compares them);
4. resolve `input.targets` to TargetRefs (seeds of the campaign, or known assets: P3a);
5. check the campaign caps, the declared egress destinations and the dependency graph;
6. compute the egress binding (E-1) and the job fingerprint (X-1);
7. deduplicate: same `Idempotency-Key` + same body replays; same fingerprint + same scheduling
replays;
   either one with a different body/scheduling is `409`;
8. sign the ApprovedTask (OI-7), validate it against the contract, store decision + job +
   dependencies
   and the task in one transaction; a refusal stores a `denied` decision and publishes
   `policy.denied.v2` in the same transaction.

A refusal that happens before any TargetRef exists (unresolvable target, invalid input, bad
schema) is
`400 INPUT_INVALID` and writes no decision: 0012 requires every new decision to carry resolved refs,
and
OpenAPI only publishes `policy.denied.v2` for a policy refusal (403/429).

Two caller-shaped facts are parameters, never request fields (C05):

* `requested_by` is the server-verified initiator (`operator|module`); the REST route passes the
  authenticated operator principal, and the MCP path (which has no operator credential) omits it so
  M05 derives the run's operator - the latest RUNNING transition actor, else the campaign creator;
* `proposed_by` is the proposing agent session (`{kind: agent, id}`) and is only set on the MCP
  path, where a bound `agent_session` exists. It is written to the decision (with `session_id`, as
  0012 requires) and to the job, and it binds the `Idempotency-Key` to that session (E-4): a replay
  of a key whose decision names another session - or a REST caller without one - is
  `IDEMPOTENCY_CONFLICT`, not a job.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

import psycopg
from psycopg.types.json import Jsonb
from pydantic import RootModel

from aegis import validation
from aegis.common import platform as platform_set
from aegis.contracts_gen.capability.job_submit_v2_schema import JobSubmit
from aegis.contracts_gen.common.error_v2_schema import NextAction
from aegis.m01_campaign.audit import record_audit
from aegis.m05_registry.canonical import job_fingerprint, sha256_hex
from aegis.m05_registry.caps import (
    CampaignPolicy,
    check_campaign_address_budget,
    check_campaign_caps,
    merge_input,
    network_profile,
)
from aegis.m05_registry.dependency import check_dependencies
from aegis.m05_registry.egress import (
    EgressBinding,
    TargetBinder,
    build_egress_binding,
    check_declared_destinations,
    load_active_provenance,
)
from aegis.m05_registry.errors import M05Error, Refusal
from aegis.m05_registry.ids import trace_id as new_trace_id
from aegis.m05_registry.ids import uuid7
from aegis.m05_registry.manifest import ManifestRecord
from aegis.m05_registry.registry import ManifestNotFound, ManifestRegistry
from aegis.m05_registry.signing import KeyRing
from aegis.m05_registry.targets import ResolvedTargets, resolve_targets

__all__ = [
    "JobPage",
    "JobService",
    "PostgresJobService",
    "SubmitOutcome",
    "TERMINAL_STATUSES",
]

TERMINAL_STATUSES = frozenset({"SUCCEEDED", "FAILED", "CANCELLED"})
JOB_STATUSES = (
    "QUEUED",
    "VALIDATING",
    "DISPATCHED",
    "RUNNING",
    "COLLECTING",
    "SUCCEEDED",
    "FAILED",
    "CANCELLED",
)
JOB_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
NO_CAMPAIGN_WORK = frozenset({"COMPLETED", "FAILED", "CANCELLED"})
TASK_SCHEMA = "capability/approved-task.v2.schema.json"
JOB_SCHEMA = "capability/job.v2.schema.json"
DENIED_EVENT_SCHEMA = "events/policy.denied.v2.schema.json"


@dataclass(frozen=True, slots=True)
class SubmitOutcome:
    """A job the request created (202) or replayed (200); `job` is the job.v2 payload."""

    job: dict[str, Any]
    replayed: bool
    decision_id: str


@dataclass(frozen=True, slots=True)
class JobPage:
    items: tuple[dict[str, Any], ...]
    next_cursor: str | None


@dataclass(frozen=True, slots=True)
class _StoredRequest:
    decision_id: str
    request_hash: str | None
    decision: str
    rule: str | None
    error: Mapping[str, Any] | None
    session_id: str | None


@dataclass(frozen=True, slots=True)
class _Rejection:
    """A committed denial that is raised to the caller only after the transaction succeeded."""

    error: M05Error


class JobService(Protocol):
    """The seam the REST/MCP layers use; `PostgresJobService` is the G1 implementation."""

    def submit(
        self,
        request: JobSubmit,
        *,
        requested_by: Mapping[str, str] | None,
        idempotency_key: str,
        proposed_by: Mapping[str, str] | None = None,
        trace_id: str | None = None,
    ) -> SubmitOutcome: ...

    def get_job(self, job_id: str) -> dict[str, Any]: ...

    def list_jobs(
        self,
        *,
        campaign_id: str,
        status: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> JobPage: ...

    def cancel(
        self, job_id: str, *, requested_by: Mapping[str, str], reason: str | None = None
    ) -> dict[str, Any]: ...


def _plain(value: Any) -> Any:
    """Unwrap generated `RootModel` ids/timestamps into the plain JSON values they carry.

    datamodel-codegen emits e.g. `Id = RootModel[constr(...)]`, so a DTO field is not a `str`;
    psycopg and `aegis-c14n/1` both work on plain values, and `str(root_model)` is `root='...'`.
    """
    if isinstance(value, RootModel):
        return _plain(value.root)
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items()}
    return value


def _isoformat(value: Any) -> str:
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    return str(value)


INITIATOR_KINDS = frozenset({"operator", "module"})


def _as_initiator(actor: Any) -> dict[str, str] | None:
    """The actor as an initiator (`{kind: operator|module, id}`), or None when it is not one.

    The same shape 0010's `aegis.is_initiator` enforces: exactly the two keys, a non-empty opaque
    id. An agent, a label or a self-declared string is not an initiator (C05).
    """
    if not isinstance(actor, Mapping) or set(actor) != {"kind", "id"}:
        return None
    kind, identifier = actor.get("kind"), actor.get("id")
    if kind not in INITIATOR_KINDS or not isinstance(identifier, str):
        return None
    if not 1 <= len(identifier.strip()) <= 200:
        return None
    return {"kind": str(kind), "id": identifier}


class PostgresJobService:
    """M05 policy checkpoint + decision log + job rows, on PostgreSQL 16."""

    def __init__(
        self,
        connect: Callable[[], psycopg.Connection[Any]],
        *,
        registry: ManifestRegistry,
        key_ring: KeyRing,
        binder: TargetBinder | None = None,
        platform_cidrs: Sequence[str] | None = None,
        platform_env: Mapping[str, str] | None = None,
    ) -> None:
        self._connect = connect
        self._registry = registry
        self._key_ring = key_ring
        self._binder = binder
        #: Tests and single-host deployments can pin the set; otherwise it is read from the host for
        #: **every** task (R1): the set is a snapshot of podman networks and host addresses, and a
        #: network created after this process started must still be denied.
        self._platform_cidrs_override = None if platform_cidrs is None else tuple(platform_cidrs)
        self._platform_env = platform_env

    def _platform_deny_set(self) -> tuple[tuple[str, ...], str]:
        """The platform deny set right now, and why it could not be read (``""`` when it was)."""
        if self._platform_cidrs_override is not None:
            return self._platform_cidrs_override, ""
        try:
            return platform_set.platform_cidrs(self._platform_env), ""
        except platform_set.PlatformDenySetUnavailable as error:
            return (), str(error)

    # --- submission ---------------------------------------------------------------------
    def submit(
        self,
        request: JobSubmit,
        *,
        requested_by: Mapping[str, str] | None,
        idempotency_key: str,
        proposed_by: Mapping[str, str] | None = None,
        trace_id: str | None = None,
    ) -> SubmitOutcome:
        if not idempotency_key or not idempotency_key.strip():
            raise M05Error.input_invalid("Idempotency-Key is required", field="/Idempotency-Key")
        body_hash = sha256_hex(request.model_dump(mode="json", exclude_none=True))
        trace = trace_id or new_trace_id()
        actor = self._initiator(request, requested_by)
        with self._connect() as conn:
            with conn.transaction():
                try:
                    outcome: SubmitOutcome | _Rejection = self._submit_in_transaction(
                        conn,
                        request=request,
                        requested_by=actor,
                        proposed_by=None if proposed_by is None else dict(proposed_by),
                        idempotency_key=idempotency_key.strip(),
                        body_hash=body_hash,
                        trace_id=trace,
                    )
                except M05Error as error:
                    # A refusal is an event: it must leave a trace even when no policy decision can
                    # exist (0012 needs resolved refs). The row commits with the refusal.
                    outcome = _Rejection(error=error)
                if isinstance(outcome, _Rejection):
                    self._audit_refusal(
                        conn,
                        error=outcome.error,
                        request=request,
                        requested_by=actor,
                        trace_id=trace,
                    )
        if isinstance(outcome, _Rejection):
            raise outcome.error
        return outcome

    def _initiator(
        self, request: JobSubmit, requested_by: Mapping[str, str] | None
    ) -> dict[str, str]:
        """Who started the work: the caller's verified principal, or the current campaign run's.

        The REST route passes the authenticated operator principal. The MCP path has no operator
        credential - only an agent session - so M05 derives the initiator from the campaign the
        request names: the actor of the latest RUNNING transition (who started or resumed this run),
        else the campaign creator (C05/OI-4). The agent stays the *proposer* (`proposed_by`); a
        module id is reserved for module-initiated jobs, which neither path is. Deriving it here
        keeps the human chain readable from the job row alone.
        """
        if requested_by is not None:
            return dict(requested_by)
        campaign_id = str(_plain(request.campaign_id))
        with self._connect() as conn:
            observed = conn.execute(
                "SELECT actor FROM campaign_status_change WHERE campaign_id = %s "
                "AND to_status = 'RUNNING' ORDER BY seq DESC LIMIT 1",
                (campaign_id,),
            ).fetchone()
            creator = conn.execute(
                "SELECT created_by FROM campaign WHERE campaign_id = %s", (campaign_id,)
            ).fetchone()
        if creator is None:
            raise M05Error.not_found(f"campaign {campaign_id} does not exist")
        if observed is not None:
            actor = _as_initiator(observed[0])
            if actor is None:  # pragma: no cover - M01 writes operator|module actors
                raise M05Error.dependency_missing(
                    f"campaign {campaign_id}: the latest RUNNING transition actor is not an "
                    "initiator (operator|module); refusing to attribute a job to it"
                )
            return actor
        creator_actor = _as_initiator(creator[0])
        if creator_actor is None:  # pragma: no cover - M01 writes the verified principal
            raise M05Error.dependency_missing(
                f"campaign {campaign_id} has no server-verified initiator (operator|module); "
                "refusing to record a job that cannot be attributed"
            )
        return creator_actor

    def _submit_in_transaction(
        self,
        conn: psycopg.Connection[Any],
        *,
        request: JobSubmit,
        requested_by: dict[str, str],
        proposed_by: dict[str, str] | None,
        idempotency_key: str,
        body_hash: str,
        trace_id: str,
    ) -> SubmitOutcome | _Rejection:
        campaign = self._campaign(conn, str(_plain(request.campaign_id)))
        stored = self._stored_request(conn, campaign.campaign_id, idempotency_key)
        if stored is not None:
            return self._replay_request(conn, stored, proposed_by=proposed_by, body_hash=body_hash)

        try:
            return self._accept(
                conn,
                request=request,
                campaign=campaign,
                requested_by=requested_by,
                proposed_by=proposed_by,
                idempotency_key=idempotency_key,
                body_hash=body_hash,
                trace_id=trace_id,
            )
        except M05Error:
            raise

    def _accept(
        self,
        conn: psycopg.Connection[Any],
        *,
        request: JobSubmit,
        campaign: CampaignPolicy,
        requested_by: dict[str, str],
        proposed_by: dict[str, str] | None,
        idempotency_key: str,
        body_hash: str,
        trace_id: str,
    ) -> SubmitOutcome | _Rejection:
        decision_id = uuid7()
        task_id = uuid7()
        job_id = uuid7()
        # Generated DTOs type ids/rationale as `constr` subclasses; psycopg only adapts plain str.
        capability = str(_plain(request.capability))
        provider = None if request.provider is None else str(_plain(request.provider))
        scan_cycle = uuid7() if request.scan_cycle is None else str(_plain(request.scan_cycle))
        rationale = str(_plain(request.rationale))
        priority = int(_plain(request.priority) if request.priority is not None else 50)

        try:
            record = self._registry.resolve(capability, provider)
        except ManifestNotFound as error:
            # The decision log can still name the seeds the caller meant: resolve them from the raw
            # input before refusing, so a denial keeps its provenance (0012 requires refs).
            targets = resolve_targets(
                conn,
                campaign_id=campaign.campaign_id,
                scope_id=campaign.scope_id,
                values=_plain(request.input).get("targets") or [],
            )
            return self._deny(
                conn,
                campaign=campaign,
                decision_id=decision_id,
                requested_by=requested_by,
                proposed_by=proposed_by,
                idempotency_key=idempotency_key,
                body_hash=body_hash,
                trace_id=trace_id,
                capability=capability,
                provider=provider,
                merged_input=dict(_plain(request.input)),
                targets=targets,
                error=M05Error.policy_denied(
                    "capability_unknown",
                    f"{error}; register the provider manifest before requesting this capability",
                    next_action=NextAction.CHECK_PROVIDER,
                ),
            )

        merged_input = merge_input(record, _plain(request.input))
        targets = resolve_targets(
            conn,
            campaign_id=campaign.campaign_id,
            scope_id=campaign.scope_id,
            values=merged_input.get("targets") or [],
        )
        depends_on: list[str] = []
        try:
            self._check_target_kinds(record, targets)
            check_declared_destinations(record, merged_input)
            profile = network_profile(campaign.policy)
            platform_cidrs: tuple[str, ...] = ()
            if profile == "internet":
                authorization_value = campaign.policy.get("authorization")
                if not isinstance(authorization_value, Mapping) or not authorization_value:
                    raise M05Error.policy_denied(
                        "authorization_missing",
                        "an internet campaign needs a structured authorization in its RoE "
                        "(owner, reference, date, authorized_suffixes)",
                        field="/policy/authorization",
                    )
                platform_cidrs, platform_error = self._platform_deny_set()
                if not platform_cidrs:
                    raise M05Error.policy_denied(
                        "platform_deny_set_unavailable",
                        "the platform deny set cannot be read on this host; refusing to sign an "
                        "internet task without it"
                        + (f": {platform_error}" if platform_error else ""),
                    )
            check_campaign_caps(
                conn,
                policy=campaign,
                record=record,
                merged_input=merged_input,
                raw_targets=list(targets.raw),
            )
            depends_on = check_dependencies(
                conn,
                campaign_id=campaign.campaign_id,
                job_id=job_id,
                depends_on=[str(_plain(item)) for item in request.depends_on or []],
            )
            active_binder = self._binder or _MissingBinder()
            active_provenance = None
            if profile == "internet":
                # The seed networks are needed for every internet task, not only a target-bound one:
                # the private seed CIDRs the RoE lists are signed into the binding (R4), and a
                # dns-only provider's answers are judged against them at M06.
                active_provenance = load_active_provenance(
                    conn,
                    campaign_id=campaign.campaign_id,
                    scope_id=campaign.scope_id,
                    targets=targets,
                    binder=active_binder,
                )
            binding = build_egress_binding(
                record,
                merged_input=merged_input,
                targets=targets,
                binder=active_binder,
                network_profile=profile,
                platform_cidrs=platform_cidrs,
                authorized_suffixes=_authorized_suffixes(campaign.policy),
                provenance=active_provenance,
            )
            if binding.target_addresses:
                check_campaign_address_budget(
                    conn,
                    campaign_id=campaign.campaign_id,
                    addresses=binding.target_addresses,
                    actor={"kind": "module", "id": "M05"},
                    trace_id=trace_id,
                )
        except M05Error as error:
            return self._deny(
                conn,
                campaign=campaign,
                decision_id=decision_id,
                requested_by=requested_by,
                proposed_by=proposed_by,
                idempotency_key=idempotency_key,
                body_hash=body_hash,
                trace_id=trace_id,
                capability=capability,
                provider=record.provider,
                merged_input=merged_input,
                targets=targets,
                error=error,
            )

        fingerprint = job_fingerprint(
            {
                "campaign_id": campaign.campaign_id,
                "capability": record.capability,
                "policy_version": campaign.policy_version,
                "provider": record.provider,
                "provider_version": record.provider_version,
                "adapter_version": record.adapter_version,
                "image_digest": record.image_digest,
                "manifest_sha256": record.sha256,
                "target_refs": list(targets.refs),
                "input": merged_input,
                "scan_cycle": scan_cycle,
            }
        )

        existing = self._existing_fingerprint(conn, fingerprint)
        if existing is not None:
            return self._replay_existing(
                conn,
                job_id=existing,
                priority=priority,
                depends_on=depends_on,
            )

        task = self._build_task(
            task_id=task_id,
            decision_id=decision_id,
            campaign=campaign,
            record=record,
            merged_input=merged_input,
            targets=targets,
            requested_by=requested_by,
            proposed_by=proposed_by,
            rationale=rationale,
            trace_id=trace_id,
            scan_cycle=scan_cycle,
            priority=priority,
            depends_on=depends_on,
            idempotency_key=idempotency_key,
            binding=binding,
        )
        signature, key_id = self._key_ring.sign(task)
        task["signature"] = signature
        task["signature_key_id"] = key_id
        self._validate_task(task)
        self._key_ring.verify(task)

        try:
            with conn.transaction():
                self._insert_decision(
                    conn,
                    decision_id=decision_id,
                    campaign=campaign,
                    capability=record.capability,
                    provider=record.provider,
                    merged_input=merged_input,
                    targets=targets,
                    requested_by=requested_by,
                    proposed_by=proposed_by,
                    idempotency_key=idempotency_key,
                    body_hash=body_hash,
                    trace_id=trace_id,
                    decision="approved",
                    task=task,
                )
                self._insert_job(
                    conn,
                    job_id=job_id,
                    campaign=campaign,
                    record=record,
                    decision_id=decision_id,
                    scan_cycle=scan_cycle,
                    fingerprint=fingerprint,
                    merged_input=merged_input,
                    targets=targets,
                    requested_by=requested_by,
                    proposed_by=proposed_by,
                    rationale=str(request.rationale),
                    trace_id=trace_id,
                    priority=priority,
                    task=task,
                )
                for dependency in depends_on:
                    conn.execute(
                        "INSERT INTO job_dependency (campaign_id, job_id, depends_on_job_id) "
                        "VALUES (%s, %s, %s)",
                        (campaign.campaign_id, job_id, dependency),
                    )
        except psycopg.errors.UniqueViolation as error:
            # A concurrent submission won the same fingerprint or the same Idempotency-Key. Its rows
            # committed, so answer with them instead of failing the caller (this transaction's
            # savepoint rolled back, nothing of ours survives).
            existing = self._existing_fingerprint(conn, fingerprint)
            if existing is not None:
                return self._replay_existing(
                    conn, job_id=existing, priority=priority, depends_on=depends_on
                )
            stored = self._stored_request(conn, campaign.campaign_id, idempotency_key)
            if stored is not None:
                return self._replay_request(
                    conn, stored, proposed_by=proposed_by, body_hash=body_hash
                )
            raise error
        return SubmitOutcome(
            job=self._job_payload(conn, job_id), replayed=False, decision_id=decision_id
        )

    # --- pieces -----------------------------------------------------------------------------
    def _campaign(self, conn: psycopg.Connection[Any], campaign_id: str) -> CampaignPolicy:
        row = conn.execute(
            "SELECT campaign_id, status, current_policy_version, scope_id FROM campaign "
            "WHERE campaign_id = %s",
            (campaign_id,),
        ).fetchone()
        if row is None:
            raise M05Error.not_found(f"campaign {campaign_id} does not exist")
        status = str(row[1])
        if status in NO_CAMPAIGN_WORK:
            raise M05Error.policy_denied(
                "campaign_terminal",
                f"campaign {campaign_id} is {status}; a terminal campaign accepts no new work",
            )
        policy_version = str(row[2])
        snapshot = conn.execute(
            "SELECT policy FROM policy_snapshot WHERE policy_version = %s", (policy_version,)
        ).fetchone()
        if snapshot is None:
            raise M05Error.dependency_missing(
                f"campaign {campaign_id} points at policy {policy_version}, which has no snapshot"
            )
        policy = snapshot[0]
        validation.validate("campaign/roe-policy.v2.schema.json", policy)
        return CampaignPolicy(
            campaign_id=str(row[0]),
            policy_version=policy_version,
            scope_id=str(row[3]),
            policy=policy,
        )

    @staticmethod
    def _check_target_kinds(record: ManifestRecord, targets: ResolvedTargets) -> None:
        accepted = {str(kind) for kind in record.spec.get("acceptsTargetKinds") or []}
        if not accepted:
            return
        for kind in targets.kinds:
            if kind not in accepted:
                raise M05Error.policy_denied(
                    "target_kind_not_accepted",
                    f"provider {record.provider} does not accept target kind {kind!r}",
                    field="/targets",
                )

    def _stored_request(
        self, conn: psycopg.Connection[Any], campaign_id: str, idempotency_key: str
    ) -> _StoredRequest | None:
        row = conn.execute(
            "SELECT decision_id, request_hash, decision, rule, error, session_id "
            "FROM policy_decision WHERE campaign_id = %s AND idempotency_key = %s",
            (campaign_id, idempotency_key),
        ).fetchone()
        if row is None:
            return None
        return _StoredRequest(
            decision_id=str(row[0]),
            request_hash=None if row[1] is None else str(row[1]),
            decision=str(row[2]),
            rule=None if row[3] is None else str(row[3]),
            error=row[4],
            session_id=None if row[5] is None else str(row[5]),
        )

    @staticmethod
    def _raw_targets(request: JobSubmit) -> list[str]:
        """The requested target values as text, before any resolution (audit evidence).

        A malformed `targets` (a bare string, an object) is recorded exactly as sent - the audit row
        is the only evidence of a refusal that cannot resolve a TargetRef, so it must not be empty
        just because the request was wrong.
        """
        values = _plain(request.input).get("targets")
        if isinstance(values, list):
            return [str(value) for value in values if isinstance(value, (str, int, float))]
        if isinstance(values, (str, int, float)):
            return [str(values)]
        return []

    def _audit_refusal(
        self,
        conn: psycopg.Connection[Any],
        *,
        error: M05Error,
        request: JobSubmit,
        requested_by: Mapping[str, str],
        trace_id: str,
    ) -> None:
        """One M25 row per refused submission (M05): actor, raw targets, code, rule, trace.

        A policy refusal also has its `policy_decision` row and its event; this row is what a
        refusal that cannot have a decision (400 INPUT_INVALID before any TargetRef exists) has
        instead, so no refusal is invisible in the audit trail.
        """
        refusal = error.refusal
        details: dict[str, Any] = {
            "code": str(refusal.code),
            "rule": refusal.rule,
            "next_action": str(refusal.next_action),
            "message": refusal.message[:2000],
        }
        if refusal.field is not None:
            details["field"] = refusal.field
        if refusal.retry_after_seconds is not None:
            details["retry_after_seconds"] = refusal.retry_after_seconds
        record_audit(
            conn,
            actor=requested_by,
            action="job.refuse",
            trace_id=trace_id,
            campaign_id=str(_plain(request.campaign_id)),
            capability_id=str(_plain(request.capability)),
            targets=self._raw_targets(request),
            details=details,
        )

    def _replay_request(
        self,
        conn: psycopg.Connection[Any],
        stored: _StoredRequest,
        *,
        proposed_by: Mapping[str, str] | None,
        body_hash: str,
    ) -> SubmitOutcome | _Rejection:
        """Replay the request a key already produced - only to the caller that key belongs to.

        E-4: `(campaign_id, idempotency_key)` is unique per campaign in 0001, so a second agent
        session could send another session's `<session>:step:<n>` key and receive its job. The
        decision row records the proposing session, and the key is answered to that session only;
        any other caller (another session, or a REST caller without a session) is a conflict.
        """
        caller = None if proposed_by is None else str(proposed_by.get("id") or "")
        if stored.session_id != caller:
            raise M05Error.idempotency_conflict(
                "Idempotency-Key belongs to another session; a key is not transferable between "
                "sessions - reuse the key your own session created the request with, or use a new "
                "key"
            )
        return self._replay_stored(conn, stored, body_hash=body_hash)

    def _replay_stored(
        self, conn: psycopg.Connection[Any], stored: _StoredRequest, *, body_hash: str
    ) -> SubmitOutcome | _Rejection:
        if stored.request_hash is not None and stored.request_hash != body_hash:
            raise M05Error.idempotency_conflict(
                "Idempotency-Key was first used for a different request body; send the "
                "original body to replay the accepted job, or use a new key"
            )
        if stored.decision == "denied":
            return _Rejection(error=self._stored_refusal(stored))
        job = conn.execute(
            "SELECT job_id FROM scan_job WHERE decision_id = %s", (stored.decision_id,)
        ).fetchone()
        if job is None:
            raise M05Error.not_found(
                f"decision {stored.decision_id} is approved but its job row is missing"
            )
        return SubmitOutcome(
            job=self._job_payload(conn, str(job[0])), replayed=True, decision_id=stored.decision_id
        )

    @staticmethod
    def _stored_refusal(stored: _StoredRequest) -> M05Error:
        error = dict(stored.error or {})
        code = str(error.get("code") or "POLICY_DENIED")
        next_action = str(error.get("next_action") or NextAction.FIX_INPUT)
        status_code = {
            "RATE_LIMITED": 429,
            "OUT_OF_SCOPE": 403,
            "POLICY_DENIED": 403,
        }.get(code, 403)
        refusal = Refusal(
            code=code,  # type: ignore[arg-type]
            rule=stored.rule or "policy",
            message=str(error.get("message") or "the request was denied by policy"),
            next_action=next_action,  # type: ignore[arg-type]
            status_code=status_code,
            field=error.get("field"),
            retry_after_seconds=error.get("retry_after_seconds"),
            next_action_detail=error.get("next_action_detail"),
            retryable=error.get("retryable"),
        )
        return M05Error(refusal)

    def _existing_fingerprint(self, conn: psycopg.Connection[Any], fingerprint: str) -> str | None:
        row = conn.execute(
            "SELECT job_id FROM scan_job WHERE job_fingerprint = %s", (fingerprint,)
        ).fetchone()
        return None if row is None else str(row[0])

    def _replay_existing(
        self,
        conn: psycopg.Connection[Any],
        *,
        job_id: str,
        priority: int,
        depends_on: Sequence[str],
    ) -> SubmitOutcome:
        stored = conn.execute(
            "SELECT priority, decision_id FROM scan_job WHERE job_id = %s", (job_id,)
        ).fetchone()
        if stored is None:  # pragma: no cover - the row was selected a statement earlier
            raise M05Error.not_found(f"job {job_id} disappeared")
        dependencies = {
            str(row[0])
            for row in conn.execute(
                "SELECT depends_on_job_id FROM job_dependency WHERE job_id = %s", (job_id,)
            ).fetchall()
        }
        if int(stored[0]) != priority or dependencies != set(depends_on):
            raise M05Error.idempotency_conflict(
                f"an identical scan (fingerprint of job {job_id}) is already accepted with "
                "different scheduling; priority/depends_on of an accepted job are immutable - "
                "keep the original scheduling or use a new scan_cycle"
            )
        return SubmitOutcome(
            job=self._job_payload(conn, job_id), replayed=True, decision_id=str(stored[1])
        )

    def _build_task(
        self,
        *,
        task_id: str,
        decision_id: str,
        campaign: CampaignPolicy,
        record: ManifestRecord,
        merged_input: Mapping[str, Any],
        targets: ResolvedTargets,
        requested_by: Mapping[str, str],
        proposed_by: Mapping[str, str] | None,
        rationale: str,
        trace_id: str,
        scan_cycle: str,
        priority: int,
        depends_on: Sequence[str],
        idempotency_key: str,
        binding: EgressBinding,
    ) -> dict[str, Any]:
        task: dict[str, Any] = {
            "task_id": task_id,
            "decision_id": decision_id,
            "campaign_id": campaign.campaign_id,
            "scope_id": campaign.scope_id,
            "policy_version": campaign.policy_version,
            # The campaign's RoE decides the network profile; it is signed with the task so M06
            # never picks lab vs internet from its own environment (G1.6). A campaign that omits
            # the field runs on `internet` (the operator default); demo/CI set `lab` explicitly.
            "network_profile": network_profile(campaign.policy),
            "capability": record.capability,
            "provider": record.provider,
            "provider_version": record.provider_version,
            "adapter_version": record.adapter_version,
            "image_digest": record.image_digest,
            "manifest_sha256": record.sha256,
            "scan_cycle": scan_cycle,
            "input": dict(merged_input),
            "targets": [dict(ref) for ref in targets.refs],
            "idempotency_key": idempotency_key,
            "requested_by": dict(requested_by),
            "rationale": rationale,
            "trace": {"trace_id": trace_id, "campaign_id": campaign.campaign_id},
            "priority": priority,
            "depends_on": list(depends_on),
            "egress_binding": binding.to_json(),
        }
        if proposed_by is not None:
            # Server-derived proposer (C05): only the MCP path has an agent session, and the value
            # comes from the session M05 resolved, never from the request body.
            task["proposed_by"] = dict(proposed_by)
        return task

    @staticmethod
    def _validate_task(task: Mapping[str, Any]) -> None:
        try:
            validation.validate(TASK_SCHEMA, dict(task))
        except validation.ContractViolation as error:
            raise M05Error.input_invalid(
                f"the task M05 built does not satisfy the contract: {error}"
            ) from error

    def _insert_decision(
        self,
        conn: psycopg.Connection[Any],
        *,
        decision_id: str,
        campaign: CampaignPolicy,
        capability: str,
        provider: str | None,
        merged_input: Mapping[str, Any],
        targets: ResolvedTargets,
        requested_by: Mapping[str, str],
        proposed_by: Mapping[str, str] | None,
        idempotency_key: str,
        body_hash: str,
        trace_id: str,
        decision: str,
        task: Mapping[str, Any] | None = None,
        rule: str | None = None,
        error: Mapping[str, Any] | None = None,
    ) -> None:
        conn.execute(
            """
            INSERT INTO policy_decision (
              decision_id, campaign_id, session_id, capability, provider, targets, target_refs,
              input, decision, rule, error, rationale, requested_by, proposed_by, policy_version,
              scope_id, idempotency_key, trace_id, request_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                decision_id,
                campaign.campaign_id,
                None if proposed_by is None else proposed_by.get("id"),
                capability,
                provider,
                list(targets.projection),
                Jsonb(list(targets.refs)),
                Jsonb(dict(merged_input)),
                decision,
                rule,
                None if error is None else Jsonb(dict(error)),
                str(task["rationale"]) if task else f"refused by policy {campaign.policy_version}",
                Jsonb(dict(requested_by)),
                None if proposed_by is None else Jsonb(dict(proposed_by)),
                campaign.policy_version,
                campaign.scope_id,
                idempotency_key,
                trace_id,
                body_hash,
            ),
        )

    def _insert_job(
        self,
        conn: psycopg.Connection[Any],
        *,
        job_id: str,
        campaign: CampaignPolicy,
        record: ManifestRecord,
        decision_id: str,
        scan_cycle: str,
        fingerprint: str,
        merged_input: Mapping[str, Any],
        targets: ResolvedTargets,
        requested_by: Mapping[str, str],
        proposed_by: Mapping[str, str] | None,
        rationale: str,
        trace_id: str,
        priority: int,
        task: Mapping[str, Any],
    ) -> None:
        conn.execute(
            """
            INSERT INTO scan_job (
              job_id, campaign_id, decision_id, capability, provider, provider_version,
              adapter_version, image_digest, scan_cycle, job_fingerprint, policy_version, scope_id,
              input, targets, target_refs, requested_by, proposed_by, rationale, trace_id, priority,
              manifest_sha256,
              approved_task)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s)
            """,
            (
                job_id,
                campaign.campaign_id,
                decision_id,
                record.capability,
                record.provider,
                record.provider_version,
                record.adapter_version,
                record.image_digest,
                scan_cycle,
                fingerprint,
                campaign.policy_version,
                campaign.scope_id,
                Jsonb(dict(merged_input)),
                list(targets.projection),
                Jsonb(list(targets.refs)),
                Jsonb(dict(requested_by)),
                None if proposed_by is None else Jsonb(dict(proposed_by)),
                rationale,
                trace_id,
                priority,
                record.sha256,
                Jsonb(dict(task)),
            ),
        )

    def _deny(
        self,
        conn: psycopg.Connection[Any],
        *,
        campaign: CampaignPolicy,
        decision_id: str,
        requested_by: Mapping[str, str],
        proposed_by: Mapping[str, str] | None,
        idempotency_key: str,
        body_hash: str,
        trace_id: str,
        capability: str,
        provider: str | None,
        merged_input: Mapping[str, Any],
        targets: ResolvedTargets,
        error: M05Error,
    ) -> _Rejection:
        refusal = error.refusal
        self._insert_decision(
            conn,
            decision_id=decision_id,
            campaign=campaign,
            capability=capability,
            provider=provider,
            merged_input=merged_input,
            targets=targets,
            requested_by=requested_by,
            proposed_by=proposed_by,
            idempotency_key=idempotency_key,
            body_hash=body_hash,
            trace_id=trace_id,
            decision="denied",
            rule=refusal.rule,
            error=refusal.body(trace_id),
        )
        self._publish_denied(
            conn,
            campaign=campaign,
            decision_id=decision_id,
            requested_by=requested_by,
            trace_id=trace_id,
            capability=capability,
            targets=targets,
            refusal=refusal,
        )
        return _Rejection(error=error)

    def _publish_denied(
        self,
        conn: psycopg.Connection[Any],
        *,
        campaign: CampaignPolicy,
        decision_id: str,
        requested_by: Mapping[str, str],
        trace_id: str,
        capability: str,
        targets: ResolvedTargets,
        refusal: Refusal,
    ) -> None:
        payload = {
            "decision_id": decision_id,
            "campaign_id": campaign.campaign_id,
            "capability": capability,
            "targets": list(targets.raw),
            "policy_version": campaign.policy_version,
            "error": refusal.body(trace_id),
            "rule": refusal.rule,
            "requested_by": dict(requested_by),
            "denied_at": _isoformat(datetime.now(UTC)),
        }
        validation.validate(DENIED_EVENT_SCHEMA, payload)
        conn.execute(
            "INSERT INTO outbox_event (event_id, type, producer, dedup_key, campaign_id, "
            "payload, trace) "
            "VALUES (%s, 'policy.denied.v2', 'M05', %s, %s, %s, %s)",
            (
                uuid7(),
                decision_id,
                campaign.campaign_id,
                Jsonb(payload),
                Jsonb({"trace_id": trace_id, "campaign_id": campaign.campaign_id}),
            ),
        )

    # --- reads ------------------------------------------------------------------------------
    def get_job(self, job_id: str) -> dict[str, Any]:
        job_id = _job_id(job_id)
        with self._connect() as conn:
            return self._job_payload(conn, job_id)

    def list_jobs(
        self,
        *,
        campaign_id: str,
        status: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> JobPage:
        if limit < 1 or limit > 200:
            raise M05Error.input_invalid("limit must be between 1 and 200", field="/limit")
        if status is not None and status not in JOB_STATUSES:
            raise M05Error.input_invalid(
                f"status must be one of {', '.join(JOB_STATUSES)}", field="/status"
            )
        conditions = ["campaign_id = %s"]
        params: list[Any] = [campaign_id]
        if status:
            conditions.append("status = %s")
            params.append(status)
        if cursor:
            created_at, job_id = _decode_cursor(cursor)
            conditions.append("(created_at, job_id) > (%s, %s)")
            params.extend([created_at, job_id])
        query = (
            "SELECT job_id FROM scan_job WHERE "
            + " AND ".join(conditions)
            + " ORDER BY created_at, job_id LIMIT %s"
        )
        params.append(limit + 1)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
            ids = [str(row[0]) for row in rows]
            page = ids[:limit]
            items = tuple(self._job_payload(conn, job_id) for job_id in page)
            next_cursor = None
            if len(ids) > limit and items:
                next_cursor = _encode_cursor(items[-1]["created_at"], items[-1]["job_id"])
        return JobPage(items=items, next_cursor=next_cursor)

    def cancel(
        self, job_id: str, *, requested_by: Mapping[str, str], reason: str | None = None
    ) -> dict[str, Any]:
        job_id = _job_id(job_id)
        with self._connect() as conn, conn.transaction():
            row = conn.execute(
                "SELECT status, generation, attempt FROM scan_job WHERE job_id = %s FOR UPDATE",
                (job_id,),
            ).fetchone()
            if row is None:
                raise M05Error.not_found(f"job {job_id} does not exist")
            outcome = conn.execute(
                "SELECT aegis.request_job_cancel(%s, %s, %s)",
                (job_id, Jsonb(dict(requested_by)), reason),
            ).fetchone()
            if outcome is not None and str(outcome[0]) == "requested" and str(row[0]) == "QUEUED":
                # A queued job has no runner to stop: record the intent and terminalise it now.
                # The scheduler (M02/G1.1d) may have written a wait reason on this job; 0014 only
                # allows one while the job is QUEUED, so it is cleared before the terminal CAS.
                conn.execute("UPDATE scan_job SET wait_reason = NULL WHERE job_id = %s", (job_id,))
                conn.execute(
                    "SELECT aegis.record_job_callback(%s, %s, %s, 'CANCELLED')",
                    (job_id, int(row[1]), int(row[2])),
                )
            return self._job_payload(conn, job_id)

    # --- job.v2 read model ------------------------------------------------------------------
    def _job_payload(self, conn: psycopg.Connection[Any], job_id: str) -> dict[str, Any]:
        row = conn.execute(
            """
            SELECT job_id, campaign_id, capability, provider, provider_version, status, attempt,
                   generation, cancel_requested_at, cancel_requested_by, cancel_reason, wait_reason,
                   job_fingerprint, scan_cycle, policy_version, scope_id,
                   target_refs, requested_by, proposed_by, rationale, created_at, started_at,
                   finished_at, envelope_event_id, error, priority, adapter_version, manifest_sha256
              FROM scan_job WHERE job_id = %s
            """,
            (job_id,),
        ).fetchone()
        if row is None:
            raise M05Error.not_found(f"job {job_id} does not exist")
        payload: dict[str, Any] = {
            "job_id": str(row[0]),
            "campaign_id": str(row[1]),
            "capability": str(row[2]),
            "provider": str(row[3]),
            "status": str(row[5]),
            "attempt": int(row[6]),
            "generation": int(row[7]),
            "job_fingerprint": str(row[12]),
            "policy_version": str(row[14]),
            "scope_id": str(row[15]),
            "requested_by": row[17],
            "created_at": _isoformat(row[20]),
            "priority": int(row[25]),
            "adapter_version": str(row[26]),
            "depends_on": [
                str(dep[0])
                for dep in conn.execute(
                    "SELECT depends_on_job_id FROM job_dependency WHERE job_id = %s "
                    "ORDER BY depends_on_job_id",
                    (job_id,),
                ).fetchall()
            ],
        }
        optional = {
            "provider_version": row[4],
            "cancel": None,
            "wait_reason": row[11],
            "scan_cycle": None if row[13] is None else str(row[13]),
            "targets": row[16],
            "proposed_by": row[18],
            "rationale": row[19],
            "started_at": None if row[21] is None else _isoformat(row[21]),
            "finished_at": None if row[22] is None else _isoformat(row[22]),
            "envelope_event_id": None if row[23] is None else str(row[23]),
            "error": row[24],
            "manifest_sha256": row[27],
        }
        if row[8] is not None:
            optional["cancel"] = {
                "requested_at": _isoformat(row[8]),
                "requested_by": row[9],
                **({"reason": str(row[10])} if row[10] else {}),
            }
        for key, value in optional.items():
            if value is not None:
                payload[key] = value
        try:
            validation.validate(JOB_SCHEMA, payload)
        except validation.ContractViolation as error:
            raise RuntimeError(f"job {job_id} read model violates job.v2: {error}") from error
        return payload


class _MissingBinder:
    """Refuse a target-bound provider until a binder is configured (no silent DNS from tests)."""

    def addresses(self, value: str) -> tuple[str, ...]:
        raise M05Error.policy_denied(
            "target_binding_unavailable",
            f"target-bound provider needs a server-side resolver; {value!r} was not resolved",
            next_action=NextAction.CHECK_PROVIDER,
        )


def _job_id(value: str) -> str:
    """Reject an id that is not a contract Id before it reaches a uuid column (500 would lie)."""
    text = str(value)
    if not JOB_ID.fullmatch(text):
        raise M05Error.input_invalid("job_id must be a UUIDv7 id", field="/job_id")
    return text


def _encode_cursor(created_at: str, job_id: str) -> str:
    import base64
    import json

    raw = json.dumps({"created_at": created_at, "job_id": job_id}, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_cursor(cursor: str) -> tuple[str, str]:
    import base64
    import json

    padded = cursor + "=" * (-len(cursor) % 4)
    try:
        document = json.loads(base64.urlsafe_b64decode(padded.encode()).decode())
        return str(document["created_at"]), str(document["job_id"])
    except (ValueError, KeyError, TypeError) as error:
        raise M05Error.input_invalid("cursor is not a job cursor", field="/cursor") from error


def _authorized_suffixes(policy: Mapping[str, Any]) -> tuple[str, ...]:
    """The RoE's authorized suffixes, for the wildcard probe (F3 guardrail 4)."""
    authorization = policy.get("authorization")
    if not isinstance(authorization, Mapping):
        return ()
    suffixes = authorization.get("authorized_suffixes")
    if not isinstance(suffixes, list):
        return ()
    return tuple(str(value).strip(".").lower() for value in suffixes)
