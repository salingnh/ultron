"""M20 finding producer (G2 slice A): raise a finding from the current CVE candidates.

A candidate is a *decision* (`package_vuln_match`, newest row of an `(asset, vulnerability)` pair
with `matched`, `aegis.m20_vuln.visibility`). This module turns the current decisions into the
product's finding record - the thing the operator sees in the Findings screen:

* **one finding per `(asset, CVE)`**: `rule_id = cve:<id>`, `category = vulnerability`,
  `vulnerability_ids = [id]`. The fingerprint is `sha256(aegis-c14n/1({asset_id, rule_id,
  location}))`, so it is stable across scanner versions and intel revisions (05 §Correlation), and
  the same asset+CVE can never become two findings. The UI groups findings; hiding some of them
  would lose data (owner decision 2026-11-28);
* a version/CPE match reaches **CANDIDATE only**. `CORROBORATED` needs an independent second
  evidence source or a distro-confirmed package version (transitions.v2.yaml after OD-C); a single
  banner is never corroboration;
* `finding_run` is written per **covering scan** - one row per job that observed the affected
  product, `seen = true` when that scan's version is in the affected range and `seen = false` when
  it observed the same product outside the range. A scan that saw the product without a version is
  *not* coverage (VERSION_UNKNOWN, not absence). Only a complete per-scan decision writes
  `seen = false`, never "the scan did not mention it";
* `finding_source` is written per `(scan, provider)` for the scans that saw the finding, with the
  provider's evidence ids and the candidate document the decision was made on;
* a retracted candidate (0008, `matched = false` at a newer intel revision) is **not** a reason to
  close a finding: `transitions.v2.yaml` lets M20 write FIXED only with evidence, and an intel
  withdrawal is not remediation evidence. The finding keeps its status and the withdrawal stays in
  the records that already exist - the newest `package_vuln_match` decision (`matched = false`,
  `retraction_reason`, new `vuln_rev_id`) and its `vulnerability.matched.v2` event, both written by
  the matcher in the same transaction;
* **FIXED needs a rescan that observed the affected product at a version outside the affected
  range, and that scan must be observed after the latest affected observation** - new remediation
  evidence with the scan's raw output, in observation order. An archived scan that only arrives
  late is history: its `finding_run` is kept, but it cannot close a finding whose affected version
  was observed later (nor can an older observation in the same batch mask the newer one). A scan
  that merely does not see the finding (`seen=false` without an out-of-range version) is not
  evidence, and this engine never writes FIXED from one. A candidate that re-appears after FIXED
  moves it to **REGRESSED** (`cause = scan`), and that inverse is chronological too: a late
  archived observation from before the remediation is history, not a regression;
* an operator's FALSE_POSITIVE/ACCEPTED_RISK is not reopened automatically: a re-run of the matcher
  would otherwise fight the operator every time;
* every transition writes one `finding_transition` row and one `finding.changed.v2` outbox event in
  the same transaction, so M23 projects the change from the same commit;
* each raised/refreshed finding is assessed by `aegis.m20_vuln.severity` (C07): agent-authored
  severity, UNRATED plus a stored reason when no model or no campaign budget is available.

Idempotency is the database's: the finding fingerprint is unique, `finding_run`/`finding_source`
have their own primary keys, and the event's dedup key is `<finding_id>:<seq>`.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

import psycopg
from psycopg.types.json import Jsonb

from aegis import validation
from aegis.common.finding_transitions import rule_for
from aegis.common.ports import ModelClient
from aegis.m20_vuln import severity, visibility
from aegis.m20_vuln.configurations import (
    Configuration,
    decide,
    observe,
    parse_configurations,
    products,
)
from aegis.m20_vuln.cpe import Cpe
from aegis.m20_vuln.matching import TARGET_PREDICATES, inspect_product_observation
from aegis.m27_ingestion.ids import uuid7

__all__ = [
    "EVENT_TYPE",
    "FindingsEngine",
    "FindingsReport",
    "PRODUCER",
    "SEVERITY_SCHEMA",
    "finding_fingerprint",
]

PRODUCER = "M20"
EVENT_TYPE = "finding.changed.v2"
EVENT_SCHEMA = "events/finding.changed.v2.schema.json"
SEVERITY_SCHEMA = severity.SEVERITY_SCHEMA
#: Open statuses whose intel withdrawal is noted but never closed without remediation evidence.
RETRACTABLE = ("CANDIDATE", "CORROBORATED", "VERIFIED", "REGRESSED")
#: Statuses the transition table lets M20 move to FIXED (with evidence).
REMEDIABLE = ("CANDIDATE", "CORROBORATED", "VERIFIED", "REGRESSED")
#: Operator decisions that a re-run of the matcher does not override.
OPERATOR_FINAL = ("FALSE_POSITIVE", "ACCEPTED_RISK")
#: A finding is assessed while it describes an open issue.
ASSESSABLE = ("CANDIDATE", "CORROBORATED", "REGRESSED")


def finding_fingerprint(asset_id: str, rule_id: str, location: Mapping[str, Any] | None) -> str:
    """The stable finding fingerprint: asset + rule + location, canonical JSON, sha256 hex.

    `aegis-c14n/1` (the contract's canonical form) over the three fields 05 §Correlation names;
    nothing that changes per scan (engine id, timestamp, scanner severity) can enter it.
    """
    document = {
        "asset_id": str(asset_id),
        "rule_id": str(rule_id),
        "location": dict(location or {}),
    }
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class _Pair:
    """One newest decision of an `(asset, vulnerability)` pair."""

    asset_id: str
    canonical_key: str
    asset_kind: str
    match_id: str
    vulnerability_id: str
    vuln_rev_id: str
    snapshot_id: str | None
    match_method: str
    affected_range: str | None
    confidence: float
    campaign_id: str | None
    matched: bool
    retraction_reason: str | None
    decided_at: Any


@dataclass(frozen=True, slots=True)
class _ScanObservation:
    """All present product observations of one asset in one scan."""

    scan_id: str
    campaign_id: str
    provider: str
    provider_version: str
    cpes: tuple[Cpe, ...]
    evidence_ids: tuple[str, ...]
    observed_at: Any


@dataclass(frozen=True, slots=True)
class _RunPlan:
    """What one covering scan says about the finding."""

    scan: _ScanObservation
    seen: bool
    evidence_id: str | None
    #: For `seen=false`: the product/version the scan observed outside the affected range.
    detail: str = ""


@dataclass
class FindingsReport:
    """Counters of one raising pass; the CLI and the demo print it."""

    pairs: int = 0
    findings_created: int = 0
    findings_existing: int = 0
    runs: int = 0
    sources: int = 0
    transitions: int = 0
    events: int = 0
    #: Intel withdrawals seen with no remediation evidence; the finding keeps its status.
    withdrawals_kept_open: int = 0
    #: Findings closed by a rescan that observed a version outside the affected range.
    fixed_by_rescan: int = 0
    reappeared: int = 0
    suppressed: int = 0
    blocked_no_evidence: int = 0
    assessments: int = 0
    assessments_created: int = 0
    unrated: int = 0
    dry_run: bool = False
    findings: list[dict[str, Any]] = field(default_factory=list)
    withdrawals: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        document = dict(self.__dict__)
        document.pop("findings")
        document.pop("withdrawals")
        return document


class FindingsEngine:
    """Raises/refreshes findings from M20's current candidates; every write is idempotent."""

    def __init__(self, connection: psycopg.Connection[Any]) -> None:
        self._conn = connection

    def run(
        self,
        *,
        campaign_id: str | None = None,
        only_vulnerabilities: Iterable[str] | None = None,
        dry_run: bool = False,
        assess: bool = True,
        model: ModelClient | None = None,
        provider: str | None = None,
        model_name: str | None = None,
        prompt_version: str = severity.PROMPT_VERSION,
    ) -> FindingsReport:
        report = FindingsReport(dry_run=dry_run)
        only = None if only_vulnerabilities is None else sorted(set(only_vulnerabilities))
        matched, retracted = self._pairs(campaign_id, only)
        report.pairs = len(matched)
        touched: list[str] = []
        for pair in matched:
            if dry_run:
                report.findings.append(
                    {
                        "asset_id": pair.asset_id,
                        "canonical_key": pair.canonical_key,
                        "vulnerability_id": pair.vulnerability_id,
                        "status": "CANDIDATE",
                    }
                )
                continue
            with self._conn.transaction():
                finding_id, created, changed = self._raise(pair, report)
            touched.append(finding_id)
            if changed:
                report.findings.append(
                    {
                        "finding_id": finding_id,
                        "asset_id": pair.asset_id,
                        "canonical_key": pair.canonical_key,
                        "vulnerability_id": pair.vulnerability_id,
                        "created": created,
                    }
                )
        for pair in retracted:
            if dry_run:
                report.withdrawals.append(
                    {
                        "asset_id": pair.asset_id,
                        "canonical_key": pair.canonical_key,
                        "vulnerability_id": pair.vulnerability_id,
                        "reason": pair.retraction_reason,
                    }
                )
                continue
            with self._conn.transaction():
                self._retract(pair, report)
        if assess and not dry_run:
            self._assess(
                sorted(set(touched)),
                report,
                model=model,
                provider=provider,
                model_name=model_name,
                prompt_version=prompt_version,
            )
        return report

    # --- reads ------------------------------------------------------------------------------

    def _pairs(
        self, campaign_id: str | None, only: Sequence[str] | None
    ) -> tuple[list[_Pair], list[_Pair]]:
        rows = self._conn.execute(
            "WITH "
            + visibility.LATEST_DECISION_CTE
            + " SELECT latest.match_id, latest.package_asset_id, latest.vulnerability_id,"
            "        latest.match_method,"
            "        latest.affected_range, latest.confidence, latest.snapshot_id, latest.matched,"
            "        latest.created_at, m.vuln_rev_id, m.campaign_id, m.retraction_reason,"
            "        a.canonical_key, a.kind"
            "   FROM latest"
            "   JOIN package_vuln_match m ON m.match_id = latest.match_id"
            "   JOIN asset a ON a.asset_id = latest.package_asset_id"
            "  WHERE (%s::uuid IS NULL OR EXISTS ("
            "          SELECT 1 FROM asset_campaign ac"
            "           WHERE ac.asset_id = latest.package_asset_id"
            "             AND ac.campaign_id = %s::uuid))"
            "    AND (%s::text[] IS NULL OR latest.vulnerability_id = ANY(%s::text[]))"
            "  ORDER BY a.canonical_key, latest.vulnerability_id",
            (None, None, campaign_id, campaign_id, only, only),
        ).fetchall()
        matched: list[_Pair] = []
        retracted: list[_Pair] = []
        for row in rows:
            pair = _Pair(
                asset_id=str(row["package_asset_id"]),
                canonical_key=str(row["canonical_key"]),
                asset_kind=str(row["kind"]),
                match_id=str(row["match_id"]),
                vulnerability_id=str(row["vulnerability_id"]),
                vuln_rev_id=str(row["vuln_rev_id"]),
                snapshot_id=None if row["snapshot_id"] is None else str(row["snapshot_id"]),
                match_method=str(row["match_method"]),
                affected_range=(
                    None if row["affected_range"] is None else str(row["affected_range"])
                ),
                confidence=float(row["confidence"] if row["confidence"] is not None else 0.0),
                campaign_id=None if row["campaign_id"] is None else str(row["campaign_id"]),
                matched=bool(row["matched"]),
                retraction_reason=(
                    None if row["retraction_reason"] is None else str(row["retraction_reason"])
                ),
                decided_at=row["created_at"],
            )
            (matched if pair.matched else retracted).append(pair)
        return matched, retracted

    def _observations(self, asset_id: str) -> list[_ScanObservation]:
        """Every present product/technology observation of the asset, grouped per scan."""
        rows = self._conn.execute(
            "SELECT observation_id, scan_id, campaign_id, predicate, value, provider,"
            "       provider_version, evidence_ids, observed_at"
            "  FROM observation"
            " WHERE subject_asset_id = %s AND predicate = ANY(%s) AND polarity = 'present'"
            " ORDER BY observed_at DESC, ingested_at DESC",
            (asset_id, list(TARGET_PREDICATES)),
        ).fetchall()
        grouped: dict[str, dict[str, Any]] = {}
        order: list[str] = []
        for row in rows:
            inspection = inspect_product_observation(str(row["predicate"]), row["value"])
            if not inspection.cpes:
                continue
            scan_id = str(row["scan_id"])
            if scan_id not in grouped:
                grouped[scan_id] = {
                    "campaign_id": str(row["campaign_id"]),
                    "provider": str(row["provider"]),
                    "provider_version": str(row["provider_version"]),
                    "cpes": [],
                    "evidence_ids": [],
                    "observed_at": row["observed_at"],
                }
                order.append(scan_id)
            entry = grouped[scan_id]
            entry["cpes"].extend(inspection.cpes)
            for evidence_id in row["evidence_ids"] or ():
                text = str(evidence_id)
                if text not in entry["evidence_ids"]:
                    entry["evidence_ids"].append(text)
            if row["observed_at"] > entry["observed_at"]:
                entry["observed_at"] = row["observed_at"]
        return [
            _ScanObservation(
                scan_id=scan_id,
                campaign_id=entry["campaign_id"],
                provider=entry["provider"],
                provider_version=entry["provider_version"],
                cpes=tuple(entry["cpes"]),
                evidence_ids=tuple(entry["evidence_ids"]),
                observed_at=entry["observed_at"],
            )
            for scan_id, entry in ((scan_id, grouped[scan_id]) for scan_id in order)
        ]

    def _configurations(self, vuln_rev_id: str) -> tuple[Configuration, ...]:
        row = self._conn.execute(
            "SELECT affected FROM vulnerability_revision WHERE vuln_rev_id = %s",
            (vuln_rev_id,),
        ).fetchone()
        if row is None:
            return ()
        return parse_configurations(row["affected"])

    def _finding_by_fingerprint(
        self, fingerprint: str, *, for_update: bool = True
    ) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM finding WHERE fingerprint = %s" + (" FOR UPDATE" if for_update else ""),
            (fingerprint,),
        ).fetchone()
        return None if row is None else dict(row)

    def _run_plans(
        self, pair: _Pair, scans: Sequence[_ScanObservation]
    ) -> tuple[list[_RunPlan], tuple[Cpe, ...]]:
        """Per-scan coverage plus the CPE the title names (from the newest deciding scan)."""
        configurations = self._configurations(pair.vuln_rev_id)
        if not configurations:
            return [], ()
        index_keys = set(products(configurations))
        plans: list[_RunPlan] = []
        for scan in scans:
            decision = decide(configurations, observe(scan.cpes))
            affected = tuple(cpe for cpe in scan.cpes if cpe.product_key in index_keys)
            if decision.criterion is not None:
                plans.append(
                    _RunPlan(
                        scan=scan,
                        seen=True,
                        evidence_id=scan.evidence_ids[0] if scan.evidence_ids else None,
                    )
                )
            elif affected:
                observed = ", ".join(
                    f"{cpe.vendor}:{cpe.product} {cpe.version}"
                    for cpe in affected
                    if cpe.version and cpe.version not in {"*", "-"}
                )
                plans.append(
                    _RunPlan(
                        scan=scan,
                        seen=False,
                        evidence_id=scan.evidence_ids[0] if scan.evidence_ids else None,
                        detail=observed or "product observed",
                    )
                )
        if not any(plan.seen for plan in plans) and scans:
            # The asset-level decision used the union of scans (a configuration that ANDs two
            # products observed by different jobs). No single scan can be judged alone, but the
            # newest scan that observed the product is where the evidence is; record it as seen
            # rather than claiming absence (`seen = false`) for a candidate that matched.
            newest = scans[0]
            affected = tuple(cpe for cpe in newest.cpes if cpe.product_key in index_keys)
            if affected:
                plans.append(
                    _RunPlan(
                        scan=newest,
                        seen=True,
                        evidence_id=newest.evidence_ids[0] if newest.evidence_ids else None,
                    )
                )
        deciding = [plan for plan in plans if plan.seen and plan.scan.cpes]
        product: tuple[Cpe, ...] = ()
        if deciding:
            index_keys = set(products(configurations))
            product = tuple(cpe for cpe in deciding[0].scan.cpes if cpe.product_key in index_keys)
        return plans, product

    # --- writes -----------------------------------------------------------------------------

    def _raise(self, pair: _Pair, report: FindingsReport) -> tuple[str, bool, bool]:
        rule_id = f"cve:{pair.vulnerability_id}"
        location: dict[str, Any] = {}
        fingerprint = finding_fingerprint(pair.asset_id, rule_id, location)
        existing = self._finding_by_fingerprint(fingerprint)
        scans = self._observations(pair.asset_id)
        plans, product = self._run_plans(pair, scans)
        seen_plans = [plan for plan in plans if plan.seen and plan.evidence_id]
        if existing is None:
            if not seen_plans:
                report.blocked_no_evidence += 1
                return "", False, False
            finding_id = self._create(pair, rule_id, location, fingerprint, product, seen_plans[0])
            report.findings_created += 1
            self._write_runs(finding_id, plans, report, status="CANDIDATE")
            self._write_sources(finding_id, pair, seen_plans, report)
            self._transition(
                finding_id=finding_id,
                from_status=None,
                to_status="CANDIDATE",
                reason=(
                    f"CPE/version match {pair.vulnerability_id} at intel revision "
                    f"{pair.vuln_rev_id} ({pair.match_method})"
                ),
                evidence_id=seen_plans[0].evidence_id,
                cause="scan",
                old_severity="UNRATED",
                new_severity="UNRATED",
                campaign_id=self._campaign_of(pair),
                seq=1,
                report=report,
            )
            return finding_id, True, True

        finding_id = str(existing["finding_id"])
        status = str(existing["status"])
        report.findings_existing += 1
        newest_seen = max((plan.scan.observed_at for plan in seen_plans), default=None)
        if newest_seen is not None:
            self._conn.execute(
                "UPDATE finding SET last_seen = GREATEST(last_seen, %s) WHERE finding_id = %s",
                (newest_seen, finding_id),
            )
        # A run that already exists is not new evidence; only a scan this finding has not seen yet
        # can close it (or reopen it, when it saw the vulnerable version again).
        run_rows = self._conn.execute(
            "SELECT scan_id, seen, observed_at FROM finding_run WHERE finding_id = %s",
            (finding_id,),
        ).fetchall()
        known = {str(row["scan_id"]) for row in run_rows}
        # The lifecycle is chronological: new evidence must be observed after what it would change.
        # `last_seen` is the latest affected observation the finding has recorded; a plan from this
        # same batch may be newer still, so it counts too (otherwise a batch that carries both an
        # old out-of-range scan and a new affected one would close on the older one).
        affected_times = [row["observed_at"] for row in run_rows if row["seen"]]
        affected_times.extend(plan.scan.observed_at for plan in plans if plan.seen)
        affected_times.append(existing["last_seen"])
        latest_affected = max(affected_times)
        new_seen = [
            plan
            for plan in plans
            if plan.seen and plan.evidence_id and plan.scan.scan_id not in known
        ]
        new_out_of_range = [
            plan for plan in plans if not plan.seen and plan.scan.scan_id not in known
        ]
        # Remediation evidence exists only after the latest affected observation (history before it
        # stays a run, never a FIXED). A qualifying rescan without raw evidence cannot close it.
        qualifying = [plan for plan in new_out_of_range if plan.scan.observed_at > latest_affected]
        evidenced_fixes = [plan for plan in qualifying if plan.evidence_id]
        if status in REMEDIABLE and len(evidenced_fixes) < len(qualifying):
            report.blocked_no_evidence += 1
        # Reopening is chronological too: a late archived observation from before the remediation
        # that closed the finding is history, not a regression.
        fix_at = self._fix_observed_at(finding_id) if status == "FIXED" else None
        fresh_seen = [plan for plan in new_seen if fix_at is None or plan.scan.observed_at > fix_at]
        run_status = status
        transition: tuple[str, _RunPlan] | None = None
        if status in OPERATOR_FINAL:
            report.suppressed += 1
            self._write_runs(finding_id, plans, report, status=run_status)
            self._write_sources(finding_id, pair, seen_plans, report)
            return finding_id, False, False
        if status == "FIXED" and fresh_seen:
            run_status = "REGRESSED"
            transition = ("REGRESSED", fresh_seen[0])
        elif status in REMEDIABLE and evidenced_fixes:
            # New remediation evidence: a rescan observed the affected product at a version
            # outside the range (not merely "the scan did not mention it"), with its raw output.
            run_status = "FIXED"
            transition = ("FIXED", evidenced_fixes[0])
        self._write_runs(finding_id, plans, report, status=run_status)
        self._write_sources(finding_id, pair, seen_plans, report)
        if transition is None:
            return finding_id, False, False
        to_status, plan = transition
        if to_status == "REGRESSED":
            reason = (
                f"candidate re-matched at intel revision {pair.vuln_rev_id} ({pair.match_method})"
            )
            report.reappeared += 1
        else:
            reason = (
                f"rescan {plan.scan.scan_id} observed {plan.detail} outside the affected range "
                f"of {pair.vulnerability_id}"
            )
            report.fixed_by_rescan += 1
        self._transition(
            finding_id=finding_id,
            from_status=status,
            to_status=to_status,
            reason=reason,
            evidence_id=plan.evidence_id,
            cause="scan",
            old_severity=str(existing["severity"]),
            new_severity=str(existing["severity"]),
            campaign_id=self._campaign_of(pair),
            seq=int(existing["transition_seq"]) + 1,
            report=report,
        )
        return finding_id, False, True

    def _fix_observed_at(self, finding_id: str) -> Any | None:
        """When the remediation that produced the newest FIXED was *observed*.

        The transition cites the rescan's evidence, so its `finding_run.observed_at` is the
        remediation time. The transition's own `created_at` is only a fallback: a late archive can
        arrive long after the scan it carries, and the comparison must use observation time.
        """
        row = self._conn.execute(
            "SELECT fr.observed_at"
            "  FROM finding_transition ft"
            "  JOIN finding_run fr ON fr.finding_id = ft.finding_id"
            "   AND fr.evidence_id = ft.evidence_id"
            " WHERE ft.finding_id = %s AND ft.to_status = 'FIXED' AND ft.evidence_id IS NOT NULL"
            " ORDER BY ft.seq DESC LIMIT 1",
            (finding_id,),
        ).fetchone()
        if row is not None:
            return row["observed_at"]
        row = self._conn.execute(
            "SELECT created_at FROM finding_transition WHERE finding_id = %s"
            " AND to_status = 'FIXED' ORDER BY seq DESC LIMIT 1",
            (finding_id,),
        ).fetchone()
        return None if row is None else row["created_at"]

    def _campaign_of(self, pair: _Pair) -> str:
        if pair.campaign_id is None:
            raise ValueError(
                f"candidate {pair.vulnerability_id} on {pair.canonical_key} has no campaign "
                "provenance; a finding cannot be raised without one"
            )
        return pair.campaign_id

    def _create(
        self,
        pair: _Pair,
        rule_id: str,
        location: Mapping[str, Any],
        fingerprint: str,
        product: Sequence[Cpe],
        primary: _RunPlan,
    ) -> str:
        finding_id = str(uuid7())
        campaign_id = self._campaign_of(pair)
        title = _title(pair, product)
        observed_at = primary.scan.observed_at
        self._conn.execute(
            "INSERT INTO finding (finding_id, fingerprint, asset_id, rule_id, category, title,"
            " vulnerability_ids, location, match_method, status, severity, transition_seq,"
            " confidence, first_seen, last_seen, first_job_id, first_campaign_id)"
            " VALUES (%s, %s, %s, %s, 'vulnerability', %s, %s, %s, %s, 'CANDIDATE', 'UNRATED',"
            " 1, %s, %s, %s, %s, %s)",
            (
                finding_id,
                fingerprint,
                pair.asset_id,
                rule_id,
                title,
                [pair.vulnerability_id],
                Jsonb(dict(location)),
                pair.match_method,
                round(float(pair.confidence), 3),
                observed_at,
                observed_at,
                primary.scan.scan_id,
                campaign_id,
            ),
        )
        return finding_id

    def _write_runs(
        self,
        finding_id: str,
        plans: Sequence[_RunPlan],
        report: FindingsReport,
        *,
        status: str,
    ) -> list[_RunPlan]:
        """One running row per covering scan; returns the plans this call actually inserted."""
        inserted_plans: list[_RunPlan] = []
        if not finding_id:
            return inserted_plans
        for plan in plans:
            if plan.seen and plan.evidence_id is None:
                continue
            inserted = self._conn.execute(
                "INSERT INTO finding_run (finding_id, scan_id, seen, status, severity,"
                " severity_reason, evidence_id, observed_at)"
                " VALUES (%s, %s, %s, %s, 'UNRATED', %s, %s, %s)"
                " ON CONFLICT (finding_id, scan_id) DO NOTHING RETURNING scan_id",
                (
                    finding_id,
                    plan.scan.scan_id,
                    plan.seen,
                    status,
                    None if plan.seen else f"observed {plan.detail} outside the affected range",
                    plan.evidence_id,
                    plan.scan.observed_at,
                ),
            ).fetchone()
            if inserted is not None:
                report.runs += 1
                inserted_plans.append(plan)
        return inserted_plans

    def _write_sources(
        self,
        finding_id: str,
        pair: _Pair,
        plans: Sequence[_RunPlan],
        report: FindingsReport,
    ) -> None:
        if not finding_id:
            return
        for plan in plans:
            if not plan.scan.evidence_ids:
                continue
            candidate = {
                "vulnerability_id": pair.vulnerability_id,
                "match_method": pair.match_method,
                "affected_range": pair.affected_range,
                "confidence": pair.confidence,
                "snapshot_id": pair.snapshot_id,
                "vuln_rev_id": pair.vuln_rev_id,
                "match_id": pair.match_id,
            }
            inserted = self._conn.execute(
                "INSERT INTO finding_source (finding_id, scan_id, provider, provider_version,"
                " candidate, evidence_ids, observed_at)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s)"
                " ON CONFLICT (finding_id, scan_id, provider) DO NOTHING RETURNING provider",
                (
                    finding_id,
                    plan.scan.scan_id,
                    plan.scan.provider,
                    plan.scan.provider_version,
                    Jsonb(candidate),
                    list(plan.scan.evidence_ids),
                    plan.scan.observed_at,
                ),
            ).fetchone()
            if inserted is not None:
                report.sources += 1

    def _retract(self, pair: _Pair, report: FindingsReport) -> None:
        """Note an intel withdrawal without closing the finding.

        A feed revision that takes a candidate back says the advisory changed, not that the asset
        was remediated: `transitions.v2.yaml` allows FIXED only with evidence, and the finding's
        prior scan output is not evidence of a fix. So the status and `transition_seq` stay, no
        transition and no `finding.changed.v2` are written, and the withdrawal remains in the
        records that already hold it: the newest `package_vuln_match` decision (`matched = false`
        with `retraction_reason` and the new `vuln_rev_id`) and that decision's
        `vulnerability.matched.v2` event. A rescan that observes the product outside the affected
        range is the evidence that closes it (`_raise`).
        """
        rule_id = f"cve:{pair.vulnerability_id}"
        fingerprint = finding_fingerprint(pair.asset_id, rule_id, {})
        existing = self._finding_by_fingerprint(fingerprint)
        if existing is None:
            return
        status = str(existing["status"])
        if status not in RETRACTABLE:
            return
        report.withdrawals_kept_open += 1
        report.withdrawals.append(
            {
                "finding_id": str(existing["finding_id"]),
                "vulnerability_id": pair.vulnerability_id,
                "canonical_key": pair.canonical_key,
                "status": status,
                "reason": pair.retraction_reason or "NO_LONGER_MATCHES",
                "vuln_rev_id": pair.vuln_rev_id,
            }
        )

    def _transition(
        self,
        *,
        finding_id: str,
        from_status: str | None,
        to_status: str,
        reason: str,
        evidence_id: str | None,
        cause: str,
        old_severity: str | None,
        new_severity: str | None,
        campaign_id: str,
        seq: int,
        report: FindingsReport,
    ) -> None:
        if rule_for(from_status, to_status, PRODUCER) is None:
            raise ValueError(
                f"transitions.v2.yaml refuses {from_status} -> {to_status} by {PRODUCER}"
            )
        changed_at = _now(self._conn)
        if seq > 1:
            updated = self._conn.execute(
                "UPDATE finding SET status = %s, transition_seq = %s"
                " WHERE finding_id = %s AND transition_seq = %s RETURNING transition_seq",
                (to_status, seq, finding_id, seq - 1),
            ).fetchone()
            if updated is None:
                raise ValueError(
                    f"finding {finding_id} is not at transition_seq {seq - 1}: "
                    "a concurrent writer changed it"
                )
        self._conn.execute(
            "INSERT INTO finding_transition (finding_id, seq, from_status, to_status, reason,"
            " evidence_id, actor, cause, created_at)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                finding_id,
                seq,
                from_status,
                to_status,
                reason,
                evidence_id,
                Jsonb({"kind": "module", "id": PRODUCER}),
                cause,
                changed_at,
            ),
        )
        report.transitions += 1
        self._emit(
            finding_id=finding_id,
            seq=seq,
            from_status=from_status,
            to_status=to_status,
            reason=reason,
            evidence_id=evidence_id,
            cause=cause,
            old_severity=old_severity,
            new_severity=new_severity,
            campaign_id=campaign_id,
            changed_at=changed_at,
            report=report,
        )

    def _emit(
        self,
        *,
        finding_id: str,
        seq: int,
        from_status: str | None,
        to_status: str,
        reason: str,
        evidence_id: str | None,
        cause: str,
        old_severity: str | None,
        new_severity: str | None,
        campaign_id: str,
        changed_at: str,
        report: FindingsReport,
    ) -> None:
        row = self._conn.execute(
            "SELECT asset_id FROM finding WHERE finding_id = %s", (finding_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"finding {finding_id} disappeared while emitting its event")
        payload: dict[str, Any] = {
            "finding_id": finding_id,
            "transition_seq": seq,
            "asset_id": str(row["asset_id"]),
            "campaign_id": campaign_id,
            "old_status": from_status,
            "new_status": to_status,
            "old_severity": old_severity,
            "new_severity": new_severity,
            "reason": reason,
            "changed_by": {"kind": "module", "id": PRODUCER},
            "cause": cause,
            "changed_at": changed_at,
        }
        if evidence_id is not None:
            payload["evidence_ref"] = evidence_id
        problems = validation.problems(EVENT_SCHEMA, payload)
        if problems:
            pointer, message = problems[0]
            raise ValueError(
                f"finding.changed.v2 payload violates the contract at {pointer or '/'}: {message}"
            )
        inserted = self._conn.execute(
            "INSERT INTO outbox_event (event_id, type, producer, dedup_key, campaign_id, payload,"
            " trace) VALUES (%s, %s, %s, %s, %s, %s, %s)"
            " ON CONFLICT (type, dedup_key) DO NOTHING RETURNING event_id",
            (
                str(uuid7()),
                EVENT_TYPE,
                PRODUCER,
                f"{finding_id}:{seq}",
                campaign_id,
                Jsonb(payload),
                Jsonb({"trace_id": uuid4().hex}),
            ),
        ).fetchone()
        if inserted is not None:
            report.events += 1

    def _assess(
        self,
        finding_ids: Sequence[str],
        report: FindingsReport,
        *,
        model: ModelClient | None,
        provider: str | None,
        model_name: str | None,
        prompt_version: str,
    ) -> None:
        assessable: list[str] = []
        for finding_id in finding_ids:
            row = self._conn.execute(
                "SELECT status FROM finding WHERE finding_id = %s", (finding_id,)
            ).fetchone()
            if row is not None and str(row["status"]) in ASSESSABLE:
                assessable.append(finding_id)
        for finding_id in assessable:
            with self._conn.transaction():
                outcome = severity.assess_findings(
                    self._conn,
                    [finding_id],
                    trigger="scan",
                    model=model,
                    provider=provider,
                    model_name=model_name,
                    prompt_version=prompt_version,
                )[0]
            report.assessments += 1
            if outcome.created:
                report.assessments_created += 1
            if outcome.severity == "UNRATED":
                report.unrated += 1


def _title(pair: _Pair, product: Sequence[Cpe]) -> str:
    component = ""
    if product:
        cpe = product[0]
        parts = [part for part in (cpe.vendor, cpe.product, cpe.version) if part and part != "*"]
        component = " ".join(parts)
    if component:
        title = f"{pair.vulnerability_id} affects {component} on {pair.canonical_key}"
    else:
        title = f"{pair.vulnerability_id} affects {pair.canonical_key}"
    return title[:500]


def _now(connection: psycopg.Connection[Any]) -> str:
    row = connection.execute("SELECT now() AS at").fetchone()
    if row is None:  # pragma: no cover - PostgreSQL always answers now()
        raise RuntimeError("SELECT now() returned no row")
    return str(row["at"].isoformat()).replace("+00:00", "Z")
