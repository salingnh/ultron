"""M20 finding producer for scanner candidates (G2-D): one finding, N provider sources.

An artifact scanner (Trivy, Grype, ...) reports a finding per `(package, rule)`; M27 validated and
stored those candidates (`finding_candidate`) without inventing a finding row. This engine owns that
decision, exactly like `aegis.m20_vuln.findings` does for a CPE/version candidate:

* **one finding per `(asset, rule_id)`**: `rule_id` is the scanner's stable rule (`cve:<id>`,
  `trivy-secret:<detector>`, ...) and the fingerprint is `sha256(aegis-c14n/1({asset_id, rule_id,
  location}))` over the package location, so two providers that report the same package+CVE produce
  the **same** fingerprint and therefore one finding - the `finding_source` rows are per
  `(scan, provider)`, which is the "1 finding, 3 sources" rule of the plan;
* a candidate reaches **CANDIDATE only**: a tool's own verdict is a signal, not independent
  verification. Reaching CORROBORATED needs the transition table's independent second source
  (OD-C), which this engine does not decide;
* `finding_run` is written per covering scan with `seen = true` and the evidence that scan produced.
  Absence is never a fix: an image scan that no longer reports the CVE may simply use a newer
  vulnerability DB, so nothing here writes FIXED (`transitions.v2.yaml` requires evidence of a fix);
  a finding that was FIXED and is reported again by a newer scan becomes **REGRESSED**;
* an operator's FALSE_POSITIVE/ACCEPTED_RISK is not reopened by a re-run (counted as `suppressed`);
* every raised/refreshed finding is assessed by `aegis.m20_vuln.severity` (C07): agent-authored
  severity, or UNRATED with the stored reason when there is no model or no campaign budget.

Idempotency is the database's: the fingerprint is unique, runs/sources have their own keys, and the
event's dedup key is `<finding_id>:<seq>`, so a replay of the same scan adds no row and no event.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from psycopg.types.json import Jsonb

from aegis.common.ports import ModelClient
from aegis.m20_vuln import severity
from aegis.m20_vuln.findings import OPERATOR_FINAL, FindingWriter, finding_fingerprint
from aegis.m27_ingestion.ids import uuid7

__all__ = ["CandidateFindingsEngine", "CandidateReport", "PRODUCER"]

PRODUCER = "M20"
#: The scanner itself asserted the finding; `finding.v2.match_method` names this case.
MATCH_METHOD = "scanner_direct"


@dataclass
class CandidateReport:
    """Counters of one candidate pass; the CLI prints them."""

    groups: int = 0
    findings_created: int = 0
    findings_existing: int = 0
    runs: int = 0
    sources: int = 0
    transitions: int = 0
    events: int = 0
    suppressed: int = 0
    reappeared: int = 0
    blocked_no_evidence: int = 0
    assessments: int = 0
    assessments_created: int = 0
    unrated: int = 0
    candidates: int = 0
    dry_run: bool = False
    findings: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        document = dict(self.__dict__)
        document.pop("findings")
        return document


@dataclass(frozen=True, slots=True)
class _Candidate:
    candidate_id: str
    campaign_id: str
    scan_id: str
    provider: str
    provider_version: str
    rule_id: str
    category: str
    title: str
    location: dict[str, Any]
    vulnerability_ids: tuple[str, ...]
    cwe_ids: tuple[str, ...]
    scanner_severity: str | None
    confidence: float | None
    evidence_ids: tuple[str, ...]
    observed_at: Any


@dataclass(frozen=True, slots=True)
class _Group:
    asset_id: str
    canonical_key: str
    kind: str
    rule_id: str
    candidates: tuple[_Candidate, ...]

    @property
    def newest(self) -> _Candidate:
        # The row order is (observed_at, candidate_id): the last one is the newest, deterministic.
        return self.candidates[-1]

    @property
    def location(self) -> dict[str, Any]:
        """The finding location: the package the rule is about, never a scanner-specific path.

        A path or a fixed version changes with the scanner, the image layer layout or the DB, and a
        fingerprint that moves would split one issue into several findings. The package's identity
        (`purl:`) is the stable part, and it is the same for every provider that reports it.
        """
        if self.canonical_key.startswith("purl:"):
            return {"package_purl": self.canonical_key[5:]}
        return {}


class CandidateFindingsEngine(FindingWriter):
    """Raises/refreshes findings from the scanner candidates M27 stored (idempotent writes)."""

    def run(
        self,
        *,
        campaign_id: str | None = None,
        dry_run: bool = False,
        assess: bool = True,
        model: ModelClient | None = None,
        provider: str | None = None,
        model_name: str | None = None,
        prompt_version: str = severity.PROMPT_VERSION,
    ) -> CandidateReport:
        report = CandidateReport(dry_run=dry_run)
        groups = self._groups(campaign_id)
        report.groups = len(groups)
        report.candidates = sum(len(group.candidates) for group in groups)
        for group in groups:
            if not any(candidate.evidence_ids for candidate in group.candidates):
                report.blocked_no_evidence += 1
                continue
            if dry_run:
                report.findings.append(
                    {
                        "asset_id": group.asset_id,
                        "canonical_key": group.canonical_key,
                        "rule_id": group.rule_id,
                        "providers": sorted({item.provider for item in group.candidates}),
                        "status": "CANDIDATE",
                    }
                )
                continue
            with self._conn.transaction():
                finding_id, created, changed = self._raise(group, report)
            if changed:
                report.findings.append(
                    {
                        "finding_id": finding_id,
                        "asset_id": group.asset_id,
                        "canonical_key": group.canonical_key,
                        "rule_id": group.rule_id,
                        "providers": sorted({item.provider for item in group.candidates}),
                        "created": created,
                    }
                )
        if assess and not dry_run:
            self._assess(
                report,
                campaign_id=campaign_id,
                only_vulnerabilities=None,
                model=model,
                provider=provider,
                model_name=model_name,
                prompt_version=prompt_version,
            )
        return report

    # --- reads ------------------------------------------------------------------------------

    def _groups(self, campaign_id: str | None) -> list[_Group]:
        rows = self._conn.execute(
            "SELECT c.candidate_id, c.campaign_id, c.scan_id, c.subject_asset_id, c.provider,"
            "       c.provider_version,"
            "       c.rule_id, c.category, c.title, c.location, c.vulnerability_ids, c.cwe_ids,"
            "       c.scanner_severity, c.confidence, c.evidence_ids, c.observed_at,"
            "       a.canonical_key, a.kind"
            "  FROM finding_candidate c JOIN asset a ON a.asset_id = c.subject_asset_id"
            " WHERE (%s::uuid IS NULL OR c.campaign_id = %s::uuid)"
            " ORDER BY a.canonical_key, c.rule_id, c.observed_at, c.candidate_id",
            (campaign_id, campaign_id),
        ).fetchall()
        grouped: dict[tuple[str, str], list[_Candidate]] = {}
        meta: dict[tuple[str, str], tuple[str, str, str]] = {}
        for row in rows:
            key = (str(row["subject_asset_id"]), str(row["rule_id"]))
            candidate = _Candidate(
                candidate_id=str(row["candidate_id"]),
                campaign_id=str(row["campaign_id"]),
                scan_id=str(row["scan_id"]),
                provider=str(row["provider"]),
                provider_version=str(row["provider_version"]),
                rule_id=str(row["rule_id"]),
                category=str(row["category"]),
                title=str(row["title"]),
                location=dict(row["location"] or {}),
                vulnerability_ids=tuple(str(item) for item in row["vulnerability_ids"] or ()),
                cwe_ids=tuple(str(item) for item in row["cwe_ids"] or ()),
                scanner_severity=(
                    None if row["scanner_severity"] is None else str(row["scanner_severity"])
                ),
                confidence=(None if row["confidence"] is None else float(row["confidence"])),
                evidence_ids=tuple(str(item) for item in row["evidence_ids"] or ()),
                observed_at=row["observed_at"],
            )
            grouped.setdefault(key, []).append(candidate)
            meta.setdefault(
                key, (str(row["subject_asset_id"]), str(row["canonical_key"]), str(row["kind"]))
            )
        return [
            _Group(
                asset_id=meta[key][0],
                canonical_key=meta[key][1],
                kind=meta[key][2],
                rule_id=key[1],
                candidates=tuple(candidates),
            )
            for key, candidates in grouped.items()
        ]

    def _fix_observed_at(self, finding_id: str) -> Any | None:
        """When the remediation that produced the newest FIXED was *observed* (same rule as V1)."""
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

    # --- writes -----------------------------------------------------------------------------

    def _raise(self, group: _Group, report: CandidateReport) -> tuple[str, bool, bool]:
        location = group.location
        fingerprint = finding_fingerprint(group.asset_id, group.rule_id, location)
        existing = self._finding_by_fingerprint(fingerprint)
        # One row per (scan, provider): two tools in one arc, or the same tool twice, keep one
        # source row each; the newest candidate of that pair is the record.
        per_source: dict[tuple[str, str], _Candidate] = {}
        for candidate in group.candidates:
            if not candidate.evidence_ids:
                continue
            per_source[(candidate.scan_id, candidate.provider)] = candidate
        sources = sorted(
            per_source.values(), key=lambda item: (item.observed_at, item.candidate_id)
        )
        if not sources:
            report.blocked_no_evidence += 1
            return "", False, False
        first = sources[0]
        newest = sources[-1]
        if existing is None:
            finding_id = self._create(group, location, fingerprint, sources)
            report.findings_created += 1
            self._write_runs(finding_id, sources, report, status="CANDIDATE")
            self._write_sources(finding_id, sources, report)
            self._transition(
                finding_id=finding_id,
                from_status=None,
                to_status="CANDIDATE",
                reason=(
                    f"scanner {group.rule_id} on {group.canonical_key} reported by "
                    + ", ".join(sorted({item.provider for item in sources}))
                ),
                evidence_id=first.evidence_ids[0],
                cause="scan",
                old_severity="UNRATED",
                new_severity="UNRATED",
                campaign_id=first.campaign_id,
                seq=1,
                report=report,
            )
            return finding_id, True, True

        finding_id = str(existing["finding_id"])
        status = str(existing["status"])
        report.findings_existing += 1
        self._conn.execute(
            "UPDATE finding SET last_seen = GREATEST(last_seen, %s) WHERE finding_id = %s",
            (newest.observed_at, finding_id),
        )
        known = {
            (str(row["scan_id"]), str(row["provider"]))
            for row in self._conn.execute(
                "SELECT scan_id, provider FROM finding_source WHERE finding_id = %s",
                (finding_id,),
            ).fetchall()
        }
        fresh = [item for item in sources if (item.scan_id, item.provider) not in known]
        if status in OPERATOR_FINAL:
            report.suppressed += 1
            self._write_runs(finding_id, sources, report, status=status)
            self._write_sources(finding_id, sources, report)
            return finding_id, False, False
        transition: tuple[str, _Candidate] | None = None
        if status == "FIXED":
            fix_at = self._fix_observed_at(finding_id)
            newer = [item for item in fresh if fix_at is None or item.observed_at > fix_at]
            if newer:
                transition = ("REGRESSED", newer[0])
        self._write_runs(finding_id, sources, report, status="REGRESSED" if transition else status)
        self._write_sources(finding_id, sources, report)
        if transition is None:
            return finding_id, False, False
        to_status, item = transition
        report.reappeared += 1
        self._transition(
            finding_id=finding_id,
            from_status=status,
            to_status=to_status,
            reason=(
                f"scanner {group.rule_id} reported again by {item.provider} "
                f"({item.scan_id}) after the fix"
            ),
            evidence_id=item.evidence_ids[0],
            cause="scan",
            old_severity=str(existing["severity"]),
            new_severity=str(existing["severity"]),
            campaign_id=item.campaign_id,
            seq=int(existing["transition_seq"]) + 1,
            report=report,
        )
        return finding_id, False, True

    def _create(
        self,
        group: _Group,
        location: dict[str, Any],
        fingerprint: str,
        sources: list[_Candidate],
    ) -> str:
        finding_id = str(uuid7())
        newest = sources[-1]
        first = sources[0]
        vulnerabilities = sorted({item for entry in sources for item in entry.vulnerability_ids})
        confidences = [item.confidence for item in sources if item.confidence is not None]
        self._conn.execute(
            "INSERT INTO finding (finding_id, fingerprint, asset_id, rule_id, category, title,"
            " vulnerability_ids, location, match_method, status, severity, transition_seq,"
            " confidence, first_seen, last_seen, first_job_id, first_campaign_id)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'CANDIDATE', 'UNRATED', 1, %s, %s, %s,"
            "         %s, %s)",
            (
                finding_id,
                fingerprint,
                group.asset_id,
                group.rule_id,
                newest.category,
                newest.title[:500],
                vulnerabilities,
                Jsonb(location),
                MATCH_METHOD,
                None if not confidences else round(max(confidences), 3),
                first.observed_at,
                newest.observed_at,
                first.scan_id,
                first.campaign_id,
            ),
        )
        return finding_id

    def _write_runs(
        self,
        finding_id: str,
        sources: list[_Candidate],
        report: CandidateReport,
        *,
        status: str,
    ) -> None:
        for item in sources:
            inserted = self._conn.execute(
                "INSERT INTO finding_run (finding_id, scan_id, seen, status, severity,"
                " severity_reason, evidence_id, observed_at)"
                " VALUES (%s, %s, TRUE, %s, 'UNRATED', NULL, %s, %s)"
                " ON CONFLICT (finding_id, scan_id) DO NOTHING RETURNING scan_id",
                (finding_id, item.scan_id, status, item.evidence_ids[0], item.observed_at),
            ).fetchone()
            if inserted is not None:
                report.runs += 1

    def _write_sources(
        self, finding_id: str, sources: list[_Candidate], report: CandidateReport
    ) -> None:
        for item in sources:
            candidate = {
                "candidate_id": item.candidate_id,
                "rule_id": item.rule_id,
                "category": item.category,
                "title": item.title,
                "location": item.location,
                "vulnerability_ids": list(item.vulnerability_ids),
                "cwe_ids": list(item.cwe_ids),
                "scanner_severity": item.scanner_severity,
                "confidence": item.confidence,
                "provider": item.provider,
                "provider_version": item.provider_version,
                "scan_id": item.scan_id,
            }
            inserted = self._conn.execute(
                "INSERT INTO finding_source (finding_id, scan_id, provider, provider_version,"
                " scanner_severity, candidate, evidence_ids, observed_at)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
                " ON CONFLICT (finding_id, scan_id, provider) DO NOTHING RETURNING provider",
                (
                    finding_id,
                    item.scan_id,
                    item.provider,
                    item.provider_version,
                    item.scanner_severity,
                    Jsonb(candidate),
                    list(item.evidence_ids),
                    item.observed_at,
                ),
            ).fetchone()
            if inserted is not None:
                report.sources += 1
