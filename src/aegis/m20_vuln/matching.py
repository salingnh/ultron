"""M20-lite CVE matcher (G1.6 slice C): observations -> candidate AFFECTED_BY rows + events.

The matcher reads the *current* state of PostgreSQL, never a payload or the network:

* targets are the newest `service.product` / `http.technology` observation of every asset (one row
  per subject and predicate, `polarity = present`); only a value carrying a CPE and a version is a
  target - a bare product name is not matched by guesswork;
* the catalogue is `vulnerability_current` for `source = nvd` (withdrawn excluded): NVD CPE match
  criteria and their version bounds, indexed by `(vendor, product)` so a target looks at one bucket;
* a hit becomes one `package_vuln_match` row (`cpe_range`, confidence 0.7 for an exact-version
  criterion and 0.6 for a range) and one `vulnerability.matched.v2` outbox event in the same
  transaction, so M23 projects the candidate and the edge from the same commit.

Candidates only: this module never writes `finding` and never raises a candidate to VERIFIED - that
needs evidence and is G2's decision (AGENTS.md). Idempotency is the database's: migration 0004's
unique `(package_asset_id, vulnerability_id, vuln_rev_id, match_method)` turns a re-run into
`ON CONFLICT DO NOTHING`, and a new intel snapshot is a new `vuln_rev_id`, hence a new candidate.

A delta run (`--changed-since <seq>`) restricts the catalogue to the CVE ids of the
`intel.revision.v2` events after that cursor, which is what "re-run matching when a feed snapshot
loads" means without walking the whole catalogue.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

import psycopg
from psycopg.types.json import Jsonb

from aegis.m20_vuln.cpe import Cpe, CpeError, CpeMatch, parse_cpe

#: ids.v2 requires UUIDv7; M27 owns the generator today (one shared helper is a G1.4a proposal).
from aegis.m27_ingestion.ids import uuid7

__all__ = [
    "Candidate",
    "MatchReport",
    "Matcher",
    "Target",
    "TARGET_PREDICATES",
    "connect",
    "changed_vulnerabilities",
]

SEARCH_PATH = "SET search_path = aegis, public"
PRODUCER = "M20"
EVENT_TYPE = "vulnerability.matched.v2"
TARGET_PREDICATES = ("service.product", "http.technology")
#: Confidence of a candidate: an exact-version criterion beats a range, both stay candidates.
CONFIDENCE_EXACT = 0.7
CONFIDENCE_RANGE = 0.6

Connection = psycopg.Connection[Any]
Connect = Callable[[], Connection]


def connect(dsn: str) -> Connection:
    connection: Connection = psycopg.connect(dsn, row_factory=psycopg.rows.dict_row)
    connection.execute(SEARCH_PATH)
    return connection


def connect_from_env(env: Mapping[str, str] | None = None) -> Connection:
    source = os.environ if env is None else env
    dsn = source.get("AEGIS_PG_DSN")
    if not dsn:
        raise RuntimeError("AEGIS_PG_DSN is required to run the CVE matcher")
    return connect(dsn)


@dataclass(frozen=True, slots=True)
class Target:
    """One asset with at least one CPE+version the catalogue can be matched against."""

    asset_id: str
    canonical_key: str
    kind: str
    campaign_id: str
    observation_id: str
    predicate: str
    cpes: tuple[Cpe, ...]
    skipped: int = 0


@dataclass(frozen=True, slots=True)
class Candidate:
    """One decided match, before it is stored."""

    asset_id: str
    vulnerability_id: str
    vuln_rev_id: str
    snapshot_id: str
    confidence: float
    affected_range: str | None
    match_method: str = "cpe_range"


@dataclass
class MatchReport:
    """Counters of one matcher run; the CLI prints them and the tests assert them."""

    targets: int = 0
    targets_with_cpe: int = 0
    skipped_values: int = 0
    catalogue_revisions: int = 0
    catalogue_criteria: int = 0
    considered: int = 0
    new_matches: int = 0
    existing_matches: int = 0
    events: int = 0
    dry_run: bool = False
    cursor: int | None = None
    vulnerabilities_filter: int | None = None
    matches: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        document = dict(self.__dict__)
        document.pop("matches")
        return document


class _Catalogue:
    """NVD CPE criteria indexed by `(vendor, product)`, loaded from `vulnerability_current`."""

    def __init__(self, connection: Connection, only: Iterable[str] | None = None) -> None:
        wanted = None if only is None else sorted(set(only))
        if wanted is not None and not wanted:
            self.entries: dict[str, tuple[str, str, tuple[CpeMatch, ...]]] = {}
            self.by_product: dict[tuple[str, str], list[str]] = {}
            return
        rows = connection.execute(
            "SELECT vulnerability_id, vuln_rev_id, snapshot_id, affected"
            "  FROM vulnerability_current"
            " WHERE source = 'nvd' AND NOT withdrawn AND affected IS NOT NULL"
            "   AND (%s::text[] IS NULL OR vulnerability_id = ANY(%s::text[]))"
            " ORDER BY vulnerability_id",
            (wanted, wanted),
        ).fetchall()
        entries: dict[str, tuple[str, str, tuple[CpeMatch, ...]]] = {}
        by_product: dict[tuple[str, str], list[str]] = {}
        for row in rows:
            matches = _matches_of(row["affected"])
            if not matches:
                continue
            entries[str(row["vulnerability_id"])] = (
                str(row["vuln_rev_id"]),
                str(row["snapshot_id"]),
                tuple(matches),
            )
            for match in matches:
                by_product.setdefault(match.cpe.product_key, []).append(
                    str(row["vulnerability_id"])
                )
        self.entries = entries
        self.by_product = by_product

    @property
    def revisions(self) -> int:
        return len(self.entries)

    @property
    def criteria(self) -> int:
        return sum(len(matches) for _, _, matches in self.entries.values())

    def candidates(self, cpes: Sequence[Cpe]) -> list[Candidate]:
        """The strongest criterion per vulnerability for one target's CPEs."""
        best: dict[str, Candidate] = {}
        for cpe in cpes:
            for vulnerability_id in self.by_product.get(cpe.product_key, ()):
                revision_id, snapshot_id, matches = self.entries[vulnerability_id]
                for match in matches:
                    if not match.vulnerable or not match.matches(cpe):
                        continue
                    confidence = CONFIDENCE_EXACT if match.exact else CONFIDENCE_RANGE
                    previous = best.get(vulnerability_id)
                    if previous is not None and previous.confidence >= confidence:
                        continue
                    best[vulnerability_id] = Candidate(
                        asset_id="",
                        vulnerability_id=vulnerability_id,
                        vuln_rev_id=revision_id,
                        snapshot_id=snapshot_id,
                        confidence=confidence,
                        affected_range=match.range_text(),
                    )
        return list(best.values())


def _matches_of(affected: object) -> list[CpeMatch]:
    if not isinstance(affected, dict):
        return []
    entries = affected.get("cpe_match")
    if not isinstance(entries, list):
        return []
    matches: list[CpeMatch] = []
    for entry in entries:
        try:
            matches.append(CpeMatch.from_json(entry))
        except (CpeError, KeyError):
            continue  # a criterion this matcher cannot read is skipped, not guessed
    return matches


def _targets(connection: Connection, campaign_id: str | None) -> tuple[list[Target], int]:
    rows = connection.execute(
        "SELECT DISTINCT ON (o.subject_asset_id, o.predicate)"
        "       o.observation_id, o.campaign_id, o.predicate, o.subject_asset_id, o.value,"
        "       a.canonical_key, a.kind"
        "  FROM observation o JOIN asset a ON a.asset_id = o.subject_asset_id"
        " WHERE o.predicate = ANY(%s) AND o.polarity = 'present'"
        "   AND (%s::uuid IS NULL OR o.campaign_id = %s::uuid)"
        " ORDER BY o.subject_asset_id, o.predicate, o.observed_at DESC, o.ingested_at DESC",
        (list(TARGET_PREDICATES), campaign_id, campaign_id),
    ).fetchall()
    targets: list[Target] = []
    skipped = 0
    for row in rows:
        cpes, rejected = _cpes_of(str(row["predicate"]), row["value"])
        skipped += rejected
        if not cpes:
            continue
        targets.append(
            Target(
                asset_id=str(row["subject_asset_id"]),
                canonical_key=str(row["canonical_key"]),
                kind=str(row["kind"]),
                campaign_id=str(row["campaign_id"]),
                observation_id=str(row["observation_id"]),
                predicate=str(row["predicate"]),
                cpes=tuple(cpes),
                skipped=rejected,
            )
        )
    return targets, skipped


def _cpes_of(predicate: str, value: object) -> tuple[list[Cpe], int]:
    """CPE + version pairs of one observation value; anything else is counted as skipped."""
    found: list[Cpe] = []
    rejected = 0
    if predicate == "service.product":
        if not isinstance(value, dict):
            return [], 1
        version = value.get("version")
        if isinstance(value.get("cpe"), str):
            try:
                parsed = parse_cpe(value["cpe"])
            except CpeError:
                return [], 1
            if isinstance(version, str) and version and not parsed.has_version:
                parsed = Cpe(
                    part=parsed.part,
                    vendor=parsed.vendor,
                    product=parsed.product,
                    version=version,
                    update=parsed.update,
                )
            return ([parsed] if parsed.has_version else []), 0 if parsed.has_version else 1
        vendor, product = value.get("vendor"), value.get("product")
        if isinstance(vendor, str) and isinstance(product, str) and isinstance(version, str):
            try:
                return [parse_cpe(f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*")], 0
            except CpeError:
                return [], 1
        return [], 1
    if predicate == "http.technology":
        entries = value if isinstance(value, list) else [value]
        for entry in entries:
            try:
                parsed = parse_cpe(entry)
            except CpeError:
                rejected += 1
                continue
            if parsed.has_version:
                found.append(parsed)
            else:
                rejected += 1
        return found, rejected
    return [], 0


def changed_vulnerabilities(connection: Connection, after_seq: int) -> tuple[set[str], int]:
    """CVE ids of the `intel.revision.v2` events after `after_seq`, plus the new cursor."""
    rows = connection.execute(
        "SELECT seq, payload FROM outbox_event"
        " WHERE type = 'intel.revision.v2' AND seq > %s ORDER BY seq",
        (after_seq,),
    ).fetchall()
    ids: set[str] = set()
    cursor = after_seq
    for row in rows:
        payload = row["payload"] if isinstance(row["payload"], dict) else {}
        for vulnerability_id in payload.get("impacted_ids") or ():
            if isinstance(vulnerability_id, str):
                ids.add(vulnerability_id)
        cursor = max(cursor, int(row["seq"]))
    return ids, cursor


class Matcher:
    """Runs the matching pass; every write is idempotent and auditable."""

    def __init__(self, connection: Connection) -> None:
        self._conn = connection

    def run(
        self,
        *,
        campaign_id: str | None = None,
        only_vulnerabilities: set[str] | None = None,
        dry_run: bool = False,
        cursor: int | None = None,
    ) -> MatchReport:
        report = MatchReport(
            dry_run=dry_run,
            cursor=cursor,
            vulnerabilities_filter=(
                None if only_vulnerabilities is None else len(only_vulnerabilities)
            ),
        )
        targets, skipped = _targets(self._conn, campaign_id)
        report.targets = len(targets)
        report.skipped_values = skipped
        report.targets_with_cpe = sum(1 for target in targets if target.cpes)
        catalogue = _Catalogue(self._conn, only_vulnerabilities)
        report.catalogue_revisions = catalogue.revisions
        report.catalogue_criteria = catalogue.criteria
        for target in targets:
            candidates = catalogue.candidates(target.cpes)
            if not candidates:
                continue
            report.considered += len(candidates)
            for candidate in candidates:
                candidate = Candidate(
                    asset_id=target.asset_id,
                    vulnerability_id=candidate.vulnerability_id,
                    vuln_rev_id=candidate.vuln_rev_id,
                    snapshot_id=candidate.snapshot_id,
                    confidence=candidate.confidence,
                    affected_range=candidate.affected_range,
                )
                if dry_run:
                    report.matches.append(_summary(candidate, target))
                    report.new_matches += 1
                    continue
                with self._conn.transaction():
                    inserted = self._store(candidate, target)
                    if inserted is None:
                        report.existing_matches += 1
                        continue
                    report.new_matches += 1
                    report.events += 1 if self._emit(inserted, candidate, target) else 0
                    report.matches.append(_summary(candidate, target))
        return report

    def _store(self, candidate: Candidate, target: Target) -> str | None:
        row = self._conn.execute(
            "INSERT INTO package_vuln_match (match_id, package_asset_id, vulnerability_id,"
            " vuln_rev_id, match_method, affected_range, matched, confidence, snapshot_id,"
            " campaign_id) VALUES (%s, %s, %s, %s, %s, %s, TRUE, %s, %s, %s)"
            " ON CONFLICT (package_asset_id, vulnerability_id, vuln_rev_id, match_method)"
            " DO NOTHING RETURNING match_id",
            (
                str(uuid7()),
                candidate.asset_id,
                candidate.vulnerability_id,
                candidate.vuln_rev_id,
                candidate.match_method,
                candidate.affected_range,
                candidate.confidence,
                candidate.snapshot_id,
                target.campaign_id,
            ),
        ).fetchone()
        return None if row is None else str(row["match_id"])

    def _emit(self, match_id: str, candidate: Candidate, target: Target) -> bool:
        payload = {
            "match_id": match_id,
            "asset_id": candidate.asset_id,
            "canonical_key": target.canonical_key,
            "vulnerability_id": candidate.vulnerability_id,
            "campaign_id": target.campaign_id,
        }
        row = self._conn.execute(
            "INSERT INTO outbox_event (event_id, type, producer, dedup_key, campaign_id, payload,"
            " trace) VALUES (%s, %s, %s, %s, %s, %s, %s)"
            " ON CONFLICT (type, dedup_key) DO NOTHING RETURNING event_id",
            (
                str(uuid7()),
                EVENT_TYPE,
                PRODUCER,
                match_id,
                target.campaign_id,
                Jsonb(payload),
                Jsonb({"trace_id": uuid4().hex}),
            ),
        ).fetchone()
        return row is not None


def _summary(candidate: Candidate, target: Target) -> dict[str, Any]:
    return {
        "asset": target.canonical_key,
        "asset_id": candidate.asset_id,
        "vulnerability_id": candidate.vulnerability_id,
        "confidence": candidate.confidence,
        "affected_range": candidate.affected_range,
        "match_method": candidate.match_method,
        "snapshot_id": candidate.snapshot_id,
    }
