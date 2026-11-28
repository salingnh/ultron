"""M21's one transaction: read the job's evidence, decide, record the run, and (only) verify.

The decision row is append-only and unique by `job_id`, so this function is idempotent: a Temporal
retry, a second dispatcher tick or an operator re-run of the CLI returns the committed row and
writes nothing. When the decision is VERIFIED it writes the finding transition through
`aegis.common.finding_write` - the same writer M20 and the operator API use - with actor
`{kind: module, id: M21}`, cause `verification` and the positive evidence. Every other outcome
changes no finding: NOT_REPRODUCED is not a fix, INCONCLUSIVE is not a pass, OBSERVED is internet
evidence only.

What is refused before a row exists (a loud failure the caller retries, never a fake outcome):

* the job is not a `verify.check` job, or its signed task is not there (it never came through M05);
* the check id is not in the reviewed registry, or the deployment has no controls/canary for it;
* the evidence object is missing, or its sha256 is not the one the evidence row promises;
* the result document does not satisfy `verification-result.v2`.

What is an outcome row (rows 0 and 7 of the table): a result document that is not this run's, a
target that did not answer, a request cap exceeded, a stale request sequence, or a finding the
operator already decided - all INCONCLUSIVE with the reason on the row.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from aegis.common.finding_transitions import rule_for
from aegis.common.finding_write import TransitionRefused, write_transition
from aegis.common.verification import VerificationCheck, load_checks
from aegis.m21_verify.controls import CheckControls, ControlMap, cached_controls, controls_for
from aegis.m21_verify.evidence import (
    EvidenceError,
    EvidenceReader,
    EvidenceRow,
    evidence_from_row,
    pick_evidence,
    read_document,
)
from aegis.m21_verify.oracle import Decision, Expectation, FindingFacts, RoleTarget, decide
from aegis.m21_verify.result import ResultDocument
from aegis.m21_verify.targets import address_port

__all__ = [
    "DECIDED_BY",
    "PRODUCER",
    "RunRecord",
    "VerificationError",
    "decide_campaign",
    "decide_job",
    "open_runs",
]

PRODUCER = "M21"
DECIDED_BY = {"kind": "module", "id": PRODUCER}
#: A run row exists only for these job states; anything else is not decidable yet.
DECIDABLE = ("SUCCEEDED",)
#: Oracles whose run needs the deployment's canary hashes (the read model omits them otherwise).
CANARY_ORACLES = ("canary-extract",)
LISTING_ORACLES = ("listing-name",)


class VerificationError(RuntimeError):
    """The run cannot be decided (missing job/task/evidence/registry), not a verdict."""


@dataclass(frozen=True, slots=True)
class RunRecord:
    """What one `decide_job` call produced; `written` is false for a replay."""

    verification_id: str
    job_id: str
    finding_id: str
    outcome: str
    reason: str
    transition_seq: int | None
    written: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "verification_id": self.verification_id,
            "job_id": self.job_id,
            "finding_id": self.finding_id,
            "outcome": self.outcome,
            "reason": self.reason,
            "transition_seq": self.transition_seq,
            "written": self.written,
        }


def _row(connection: psycopg.Connection[Any], sql: str, params: Sequence[Any]) -> dict[str, Any]:
    row = connection.execute(sql, params).fetchone()
    return {} if row is None else dict(row)


def _control_targets(
    connection: psycopg.Connection[Any],
    input_block: Mapping[str, Any],
    finding_asset: str,
    *,
    check: VerificationCheck,
) -> list[RoleTarget]:
    """The signed roles; a lab check's benign control defaults to the positive host's path."""
    raw = input_block.get("controls") or []
    if not isinstance(raw, list):
        raise VerificationError("the signed task's controls are not a list")
    roles: list[RoleTarget] = []
    for item in raw:
        if not isinstance(item, Mapping):
            raise VerificationError("a signed control entry is not an object")
        key = str(item.get("target"))
        address, port = address_port(key)
        asset = _row(connection, "SELECT asset_id FROM asset WHERE canonical_key = %s", (key,))
        roles.append(
            RoleTarget(
                role=str(item.get("role")),
                address=address,
                port=port,
                asset_id=None if not asset else str(asset["asset_id"]),
            )
        )
    if check.lab_only and not any(role.role == "benign" for role in roles):
        address, port = address_port(finding_asset)
        roles.append(RoleTarget(role="benign", address=address, port=port))
    return roles


def _evidence_rows(connection: psycopg.Connection[Any], job_id: str) -> list[EvidenceRow]:
    rows = connection.execute(
        "SELECT evidence_id, storage_uri, sha256, media_type, size_bytes"
        "  FROM evidence WHERE job_id = %s ORDER BY created_at, evidence_id",
        (job_id,),
    ).fetchall()
    return [evidence_from_row(row) for row in rows]


def _existing_run(connection: psycopg.Connection[Any], job_id: str) -> dict[str, Any] | None:
    row = connection.execute(
        "SELECT * FROM verification_run WHERE job_id = %s", (job_id,)
    ).fetchone()
    return None if row is None else dict(row)


def _replay(run: Mapping[str, Any]) -> RunRecord:
    matched = run.get("matched") or {}
    return RunRecord(
        verification_id=str(run["verification_id"]),
        job_id=str(run["job_id"]),
        finding_id=str(run["finding_id"]),
        outcome=str(run["outcome"]),
        reason=str(matched.get("reason", "")),
        transition_seq=None if run["transition_seq"] is None else int(run["transition_seq"]),
        written=False,
    )


def _expectation(
    connection: psycopg.Connection[Any],
    *,
    task: Mapping[str, Any],
    check: VerificationCheck,
    mapping: CheckControls | None,
    canaries: ControlMap,
    network_profile: str,
) -> tuple[Expectation, dict[str, Any], list[dict[str, Any]], Mapping[str, Any]]:
    input_block = task.get("input")
    if not isinstance(input_block, Mapping):
        raise VerificationError("the approved task has no input block")
    if str(input_block.get("check_id")) != check.check_id:
        raise VerificationError("the approved task's check id is not the registry's")
    pack = str(input_block.get("check_pack_sha256") or "")
    if len(pack) != 64:
        raise VerificationError("the approved task does not pin a check pack")
    expected_seq = input_block.get("expected_seq")
    if not isinstance(expected_seq, int):
        raise VerificationError("the approved task has no expected_seq")
    finding_id = str(input_block.get("finding_id") or "")
    finding = _row(connection, "SELECT * FROM finding WHERE finding_id = %s", (finding_id,))
    if not finding:
        raise VerificationError(f"the approved task names finding {finding_id}, which is gone")
    canonical = _row(
        connection, "SELECT canonical_key FROM asset WHERE asset_id = %s", (finding["asset_id"],)
    )
    if not canonical:
        raise VerificationError(f"finding {finding_id} has no asset")
    canonical_key = str(canonical["canonical_key"])
    address, port = address_port(canonical_key)
    targets = input_block.get("targets")
    if not isinstance(targets, list) or list(targets) != [canonical_key]:
        raise VerificationError(
            "the signed target is not the finding's asset; a verification target comes from the "
            "finding, never from the request"
        )
    controls = _control_targets(connection, input_block, canonical_key, check=check)
    location = finding.get("location") or {}
    expectation = Expectation(
        check=check,
        network_profile=network_profile,
        expected_seq=expected_seq,
        target=RoleTarget(
            role="positive", address=address, port=port, asset_id=str(finding["asset_id"])
        ),
        controls=tuple(controls),
        check_pack_sha256=pack,
        canary_sha256=canaries.canary_sha256,
        canary_name_sha256=canaries.canary_name_sha256,
        canary_path=None if mapping is None else mapping.canary_path,
        benign_path=None if mapping is None else mapping.benign_path,
        finding=FindingFacts(
            status=str(finding["status"]),
            transition_seq=int(finding["transition_seq"]),
            product=location.get("product") if isinstance(location, Mapping) else None,
            version=location.get("version") if isinstance(location, Mapping) else None,
        ),
        run_at=datetime.now(UTC),
    )
    target_ref = {
        "asset_id": str(finding["asset_id"]),
        "canonical_key": canonical_key,
        "address": address,
        "port": port,
    }
    control_docs = [
        {
            "role": role.role,
            "address": role.address,
            "port": role.port,
            "asset_id": role.asset_id,
        }
        for role in controls
        if role.role in ("patched_twin", "benign")
    ]
    return expectation, target_ref, control_docs, finding


def decide_job(
    connection: psycopg.Connection[Any],
    job_id: str,
    *,
    reader: EvidenceReader,
    controls: ControlMap | None = None,
) -> RunRecord | None:
    """Decide one `verify.check` job; None while it is not a completed, accepted job."""
    with connection.transaction():
        job = _row(connection, "SELECT * FROM scan_job WHERE job_id = %s FOR UPDATE", (job_id,))
        if not job:
            raise VerificationError(f"job {job_id} does not exist")
        if str(job["capability"]) != "verify.check":
            raise VerificationError(f"job {job_id} is {job['capability']}, not a verify.check job")
        existing = _existing_run(connection, job_id)
        if existing is not None:
            return _replay(existing)
        if str(job["status"]) not in DECIDABLE or job["envelope_event_id"] is None:
            return None
        task = job.get("approved_task")
        if not isinstance(task, Mapping):
            raise VerificationError(f"job {job_id} has no signed approved task")
        input_block = task.get("input")
        if not isinstance(input_block, Mapping):
            raise VerificationError(f"job {job_id} has no approved input")
        check_id = str(input_block.get("check_id"))
        check = load_checks().by_id(check_id)
        if check is None:
            raise VerificationError(f"check {check_id!r} is not in the reviewed registry")
        network_profile = str(task.get("network_profile"))
        if network_profile not in ("lab", "internet"):
            raise VerificationError(f"job {job_id} has an unknown network profile")
        if network_profile == "internet" and check.lab_only:
            raise VerificationError(
                f"check {check_id!r} is lab-only; an internet job for it cannot be decided"
            )
        mapping_map = controls if controls is not None else cached_controls()
        mapping = controls_for(mapping_map, check_id)
        if check.lab_only and mapping is None:
            raise VerificationError(f"the deployment has no controls for check {check_id!r}")
        started = job.get("started_at")
        finished = job.get("finished_at")
        if started is None or finished is None:
            raise VerificationError(f"job {job_id} has no start/finish time")
        expectation, target_ref, control_docs, finding = _expectation(
            connection,
            task=task,
            check=check,
            mapping=mapping,
            canaries=mapping_map,
            network_profile=network_profile,
        )
        provider = str(task.get("provider"))
        try:
            evidence = pick_evidence(_evidence_rows(connection, job_id), provider)
            document = read_document(reader, evidence, provider=provider, task=task)
        except EvidenceError as error:
            raise VerificationError(str(error)) from error

        decision = decide(document, expectation)
        transition_seq: int | None = None
        if decision.outcome == "VERIFIED":
            decision, transition_seq = _verify(
                connection,
                decision=decision,
                finding=finding,
                expected_seq=expectation.expected_seq,
                evidence_id=evidence.evidence_id,
            )
        verification_id = _record(
            connection,
            job=job,
            finding=finding,
            check=check,
            expectation=expectation,
            decision=decision,
            document=document,
            evidence=evidence,
            target_ref=target_ref,
            controls=control_docs,
            transition_seq=transition_seq,
            started=started,
            finished=finished,
        )
        return RunRecord(
            verification_id=verification_id,
            job_id=str(job["job_id"]),
            finding_id=str(finding["finding_id"]),
            outcome=decision.outcome,
            reason=decision.reason,
            transition_seq=transition_seq,
            written=True,
        )


def _verify(
    connection: psycopg.Connection[Any],
    *,
    decision: Decision,
    finding: Mapping[str, Any],
    expected_seq: int,
    evidence_id: str,
) -> tuple[Decision, int | None]:
    """Turn a would-be VERIFIED into the transition, or into the reason it cannot be one."""
    status = str(finding["status"])
    current = int(finding["transition_seq"])
    if current != expected_seq:
        return (
            Decision.inconclusive(
                f"the finding moved to transition_seq {current}, the request expected "
                f"{expected_seq}; the run is stale",
                positive=decision.positive,
                control_a=decision.control_a,
                control_b=decision.control_b,
            ),
            None,
        )
    if status == "VERIFIED":
        # An operator asked to verify an already-verified finding: the row records the run against
        # the current sequence and writes no second transition.
        return decision, current
    if rule_for(status, "VERIFIED", PRODUCER) is None:
        return (
            Decision.inconclusive(
                f"the finding is {status}; an operator decision or a fixed finding is not "
                "overridden by a verification run",
                positive=decision.positive,
                control_a=decision.control_a,
                control_b=decision.control_b,
            ),
            None,
        )
    try:
        written = write_transition(
            connection,
            finding_id=str(finding["finding_id"]),
            from_status=status,
            to_status="VERIFIED",
            reason="verification: the positive target reproduced the condition; both negative "
            "controls did not",
            evidence_id=evidence_id,
            actor=DECIDED_BY,
            cause="verification",
            old_severity=str(finding["severity"]),
            new_severity=str(finding["severity"]),
            campaign_id=str(finding["first_campaign_id"]),
            seq=current + 1,
            producer=PRODUCER,
        )
    except TransitionRefused as error:
        return (
            Decision.inconclusive(
                f"the finding moved since the request: {error}",
                positive=decision.positive,
                control_a=decision.control_a,
                control_b=decision.control_b,
            ),
            None,
        )
    return decision, written.seq


def _record(
    connection: psycopg.Connection[Any],
    *,
    job: Mapping[str, Any],
    finding: Mapping[str, Any],
    check: VerificationCheck,
    expectation: Expectation,
    decision: Decision,
    document: ResultDocument,
    evidence: EvidenceRow,
    target_ref: Mapping[str, Any],
    controls: Sequence[Mapping[str, Any]],
    transition_seq: int | None,
    started: Any,
    finished: Any,
) -> str:
    from aegis.m27_ingestion.ids import uuid7

    verification_id = str(uuid7())
    canary = expectation.canary_sha256 if check.oracle in CANARY_ORACLES else None
    canary_name = expectation.canary_name_sha256 if check.oracle in LISTING_ORACLES else None
    # One result file carries the positive and both controls' responses, so all three references
    # name the same evidence object; the role-by-role answer is in `matched`.
    connection.execute(
        "INSERT INTO verification_run (verification_id, finding_id, campaign_id, job_id, check_id,"
        " check_class, network_profile, check_pack_sha256, outcome, requests_sent, request_cap,"
        " target_ref, controls, canary_sha256, canary_name_sha256, positive_evidence_id,"
        " control_a_evidence_id, control_b_evidence_id, matched, requested_by, decided_by,"
        " transition_seq, started_at, finished_at)"
        " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,"
        " %s, %s, %s, %s, %s)",
        (
            verification_id,
            str(finding["finding_id"]),
            str(job["campaign_id"]),
            str(job["job_id"]),
            check.check_id,
            check.check_class,
            expectation.network_profile,
            document.check_pack_sha256,
            decision.outcome,
            document.requests_sent,
            check.request_cap,
            Jsonb(dict(target_ref)),
            Jsonb([dict(item) for item in controls]),
            canary,
            canary_name,
            evidence.evidence_id,
            evidence.evidence_id,
            evidence.evidence_id,
            Jsonb(decision.matched()),
            Jsonb(dict(job["requested_by"])),
            Jsonb(DECIDED_BY),
            transition_seq,
            started,
            finished,
        ),
    )
    return verification_id


def _undecided(connection: psycopg.Connection[Any], campaign_id: str) -> list[str]:
    rows = connection.execute(
        "SELECT j.job_id FROM scan_job j"
        "  LEFT JOIN verification_run v ON v.job_id = j.job_id"
        " WHERE j.campaign_id = %s AND j.capability = 'verify.check'"
        "   AND j.status = 'SUCCEEDED' AND j.envelope_event_id IS NOT NULL"
        "   AND v.verification_id IS NULL"
        " ORDER BY j.finished_at, j.job_id",
        (campaign_id,),
    ).fetchall()
    return [str(row["job_id"]) for row in rows]


def open_runs(connection: psycopg.Connection[Any], campaign_id: str) -> list[str]:
    """The campaign's done-but-undecided `verify.check` jobs (the cheap guard before a pass)."""
    return _undecided(connection, campaign_id)


def decide_campaign(
    connection: psycopg.Connection[Any],
    campaign_id: str,
    *,
    reader: EvidenceReader,
    controls: ControlMap | None = None,
) -> list[RunRecord]:
    """Decide every completed, undecided `verify.check` job of one campaign (idempotent)."""
    decided: list[RunRecord] = []
    for job_id in _undecided(connection, campaign_id):
        record = decide_job(connection, job_id, reader=reader, controls=controls)
        if record is not None:
            decided.append(record)
    return decided
