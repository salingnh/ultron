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

import json
import os
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

import psycopg

from aegis.m20_vuln.cpe import (
    CompiledCpeMatch,
    Cpe,
    CpeError,
    CpeMatch,
    parse_cpe,
    parse_version,
)

#: ids.v2 requires UUIDv7; M27 owns the generator today (one shared helper is a G1.4a proposal).
from aegis.m27_ingestion.ids import uuid7

__all__ = [
    "Candidate",
    "MatchReport",
    "Matcher",
    "ProductInspection",
    "Target",
    "TARGET_PREDICATES",
    "VERSION_UNKNOWN_CODE",
    "VERSION_UNKNOWN_MESSAGE",
    "changed_vulnerabilities",
    "connect",
    "inspect_product_observation",
    "inspect_product_observations",
]

SEARCH_PATH = "SET search_path = aegis, public"
PRODUCER = "M20"
EVENT_TYPE = "vulnerability.matched.v2"
TARGET_PREDICATES = ("service.product", "http.technology")
VERSION_UNKNOWN_CODE = "VERSION_UNKNOWN"
VERSION_UNKNOWN_MESSAGE = "version unknown, not matchable"
#: Confidence of a candidate: an exact-version criterion beats a range, both stay candidates.
CONFIDENCE_EXACT = 0.7
CONFIDENCE_RANGE = 0.6
_VERSION_HINT_RE = re.compile(r"[:/\s]v?\d")

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


@dataclass(frozen=True, slots=True)
class ProductInspection:
    """Extracted matchable CPEs plus versionless products from product/tech observations."""

    cpes: tuple[Cpe, ...]
    skipped: int
    versionless_products: tuple[str, ...] = ()


@dataclass
class MatchReport:
    """Counters of one matcher run; the CLI prints them and the tests assert them."""

    targets: int = 0
    targets_with_cpe: int = 0
    unmatchable_targets: int = 0
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
    coverage: dict[str, Any] = field(default_factory=dict)
    matches: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        document = dict(self.__dict__)
        document.pop("matches")
        return document


class _Catalogue:
    """NVD CPE criteria indexed by `(vendor, product)`, narrowed in PostgreSQL via GIN."""

    def __init__(
        self,
        connection: Connection,
        only: Iterable[str] | None = None,
        product_index_keys: Iterable[str] | None = None,
    ) -> None:
        wanted = None if only is None else sorted(set(only))
        wanted_products = None if product_index_keys is None else sorted(set(product_index_keys))
        if (wanted is not None and not wanted) or (
            wanted_products is not None and not wanted_products
        ):
            self.entries: dict[str, tuple[str, str, tuple[CompiledCpeMatch, ...]]] = {}
            self.by_product: dict[tuple[str, str], tuple[str, ...]] = {}
            return
        rows = self._query_rows(connection, wanted, wanted_products)
        entries: dict[str, tuple[str, str, tuple[CompiledCpeMatch, ...]]] = {}
        by_product_lists: dict[tuple[str, str], list[str]] = {}
        for row in rows:
            matches = _matches_of(row["affected"])
            if not matches:
                continue
            vulnerability_id = str(row["vulnerability_id"])
            entries[vulnerability_id] = (
                str(row["vuln_rev_id"]),
                str(row["snapshot_id"]),
                tuple(matches),
            )
            seen_products: set[tuple[str, str]] = set()
            for compiled in matches:
                key = compiled.target.product_key
                if key not in seen_products:
                    seen_products.add(key)
                    by_product_lists.setdefault(key, []).append(vulnerability_id)
        self.entries = entries
        self.by_product = {key: tuple(vids) for key, vids in by_product_lists.items()}

    def _query_rows(
        self,
        connection: Connection,
        wanted: list[str] | None,
        wanted_products: list[str] | None,
    ) -> list[Any]:
        ready_row = (
            connection.execute(
                "SELECT to_regprocedure('aegis.nvd_cpe_products(jsonb)') IS NOT NULL AS ready"
            ).fetchone()
            if wanted_products is not None
            else None
        )
        has_gin_helper = bool(
            wanted_products is not None and ready_row is not None and ready_row["ready"]
        )
        if has_gin_helper and wanted_products is not None:
            return connection.execute(
                "WITH candidate_ids AS MATERIALIZED ("
                "  SELECT DISTINCT vulnerability_id"
                "    FROM vulnerability_revision"
                "   WHERE source = 'nvd' AND NOT withdrawn AND affected IS NOT NULL"
                "     AND aegis.nvd_cpe_products(affected) && %s::text[]"
                "     AND (%s::text[] IS NULL OR vulnerability_id = ANY(%s::text[]))"
                ")"
                " SELECT latest.vulnerability_id, latest.vuln_rev_id, latest.snapshot_id,"
                "        latest.affected"
                "   FROM candidate_ids c"
                "   CROSS JOIN LATERAL ("
                "     SELECT r.vulnerability_id, r.vuln_rev_id, r.snapshot_id, r.affected,"
                "            r.withdrawn"
                "       FROM vulnerability_revision r"
                "      WHERE r.vulnerability_id = c.vulnerability_id AND r.source = 'nvd'"
                "      ORDER BY r.created_at DESC, r.vuln_rev_id DESC"
                "      LIMIT 1"
                "   ) latest"
                "  WHERE NOT latest.withdrawn AND latest.affected IS NOT NULL"
                "  ORDER BY latest.vulnerability_id",
                (wanted_products, wanted, wanted),
            ).fetchall()
        return connection.execute(
            "SELECT vulnerability_id, vuln_rev_id, snapshot_id, affected"
            "  FROM vulnerability_current"
            " WHERE source = 'nvd' AND NOT withdrawn AND affected IS NOT NULL"
            "   AND (%s::text[] IS NULL OR vulnerability_id = ANY(%s::text[]))"
            " ORDER BY vulnerability_id",
            (wanted, wanted),
        ).fetchall()

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
            try:
                parsed_version = parse_version(cpe.effective_version)
            except CpeError:
                continue
            for vulnerability_id in self.by_product.get(cpe.product_key, ()):
                revision_id, snapshot_id, matches = self.entries[vulnerability_id]
                for compiled in matches:
                    if not compiled.vulnerable or not compiled.matches_parsed(cpe, parsed_version):
                        continue
                    confidence = CONFIDENCE_EXACT if compiled.exact else CONFIDENCE_RANGE
                    previous = best.get(vulnerability_id)
                    if previous is not None and previous.confidence >= confidence:
                        continue
                    best[vulnerability_id] = Candidate(
                        asset_id="",
                        vulnerability_id=vulnerability_id,
                        vuln_rev_id=revision_id,
                        snapshot_id=snapshot_id,
                        confidence=confidence,
                        affected_range=compiled.range_text,
                    )
        return list(best.values())


def _matches_of(affected: object) -> list[CompiledCpeMatch]:
    if not isinstance(affected, dict):
        return []
    entries = affected.get("cpe_match")
    if not isinstance(entries, list):
        return []
    matches: list[CompiledCpeMatch] = []
    for entry in entries:
        try:
            matches.append(CompiledCpeMatch.compile(CpeMatch.from_json(entry)))
        except (CpeError, KeyError):
            continue  # a criterion this matcher cannot read is skipped, not guessed
    return matches


def _dedupe_labels(labels: Iterable[str]) -> tuple[str, ...]:
    ordered: list[str] = []
    seen: set[str] = set()
    for raw in labels:
        cleaned = raw.strip()
        if not cleaned:
            continue
        key = cleaned.lower()
        if key in seen:
            continue
        seen.add(key)
        ordered.append(cleaned)
    return tuple(ordered)


def _targets(
    connection: Connection, campaign_id: str | None
) -> tuple[list[Target], int, dict[str, Any]]:
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
    subject_order: list[str] = []
    has_cpes: dict[str, bool] = {}
    versionless_by_subject: dict[str, list[str]] = {}
    for row in rows:
        subject_key = str(row["canonical_key"])
        if subject_key not in has_cpes:
            has_cpes[subject_key] = False
            subject_order.append(subject_key)
        inspection = inspect_product_observation(str(row["predicate"]), row["value"])
        skipped += inspection.skipped
        if inspection.versionless_products:
            versionless_by_subject.setdefault(subject_key, []).extend(
                inspection.versionless_products
            )
        if not inspection.cpes:
            continue
        has_cpes[subject_key] = True
        targets.append(
            Target(
                asset_id=str(row["subject_asset_id"]),
                canonical_key=subject_key,
                kind=str(row["kind"]),
                campaign_id=str(row["campaign_id"]),
                observation_id=str(row["observation_id"]),
                predicate=str(row["predicate"]),
                cpes=inspection.cpes,
                skipped=inspection.skipped,
            )
        )
    by_subject: dict[str, Any] = {}
    all_versionless: list[str] = []
    affected_subjects: list[str] = []
    unmatchable_subjects: list[str] = []
    for subject_key in subject_order:
        products = _dedupe_labels(versionless_by_subject.get(subject_key, ()))
        matchable = has_cpes[subject_key]
        limitations: list[dict[str, Any]] = []
        if products:
            affected_subjects.append(subject_key)
            all_versionless.extend(products)
            limitations.append(
                {
                    "code": VERSION_UNKNOWN_CODE,
                    "message": VERSION_UNKNOWN_MESSAGE,
                    "products": list(products),
                }
            )
            if not matchable:
                unmatchable_subjects.append(subject_key)
        by_subject[subject_key] = {"matchable": matchable, "limitations": limitations}
    global_limitations: list[dict[str, Any]] = []
    unique_products = list(_dedupe_labels(all_versionless))
    if unique_products:
        global_limitations.append(
            {
                "code": VERSION_UNKNOWN_CODE,
                "message": VERSION_UNKNOWN_MESSAGE,
                "subjects": affected_subjects,
                "products": unique_products,
            }
        )
    coverage = {
        "subjects": len(subject_order),
        "matchable_subjects": sum(1 for key in subject_order if has_cpes[key]),
        "unmatchable_subjects": len(unmatchable_subjects),
        "limitations": global_limitations,
        "by_subject": by_subject,
    }
    return targets, skipped, coverage


def inspect_product_observation(predicate: str, value: object) -> ProductInspection:
    """Extract versioned CPEs and report versionless products without guessing CVEs."""
    found: list[Cpe] = []
    versionless: list[str] = []
    rejected = 0
    if predicate == "service.product":
        if not isinstance(value, dict):
            return ProductInspection((), 1)
        version = value.get("version")
        has_explicit_version = isinstance(version, str) and bool(version.strip())
        product = value.get("product")
        vendor = value.get("vendor")
        if isinstance(value.get("cpe"), str):
            try:
                parsed = parse_cpe(value["cpe"])
            except CpeError:
                return ProductInspection((), 1)
            if has_explicit_version and not parsed.has_version:
                parsed = Cpe(
                    part=parsed.part,
                    vendor=parsed.vendor,
                    product=parsed.product,
                    version=str(version).strip(),
                    update=parsed.update,
                )
            if parsed.has_version:
                return ProductInspection((parsed,), 0)
            label = (
                product.strip()
                if isinstance(product, str) and product.strip()
                else (parsed.product if parsed.product not in {"*", "-", ""} else "")
            )
            return ProductInspection(
                (),
                1,
                _dedupe_labels([label]) if label else (),
            )
        if (
            isinstance(vendor, str)
            and vendor.strip()
            and isinstance(product, str)
            and product.strip()
            and has_explicit_version
        ):
            try:
                parsed = parse_cpe(
                    f"cpe:2.3:a:{vendor}:{product}:{str(version).strip()}:*:*:*:*:*:*:*"
                )
                return ProductInspection((parsed,), 0)
            except CpeError:
                return ProductInspection((), 1)
        if not has_explicit_version and isinstance(product, str) and product.strip():
            return ProductInspection((), 1, _dedupe_labels([product]))
        return ProductInspection((), 1)
    if predicate == "http.technology":
        entries = value if isinstance(value, list) else [value]
        for entry in entries:
            try:
                parsed = parse_cpe(entry)
            except CpeError:
                rejected += 1
                if isinstance(entry, str):
                    text = entry.strip()
                    if text and not _VERSION_HINT_RE.search(text):
                        versionless.append(text)
                continue
            if parsed.has_version:
                found.append(parsed)
            else:
                rejected += 1
                if parsed.product not in {"*", "-", ""}:
                    versionless.append(parsed.product)
        return ProductInspection(tuple(found), rejected, _dedupe_labels(versionless))
    return ProductInspection((), 0)


def inspect_product_observations(rows: Iterable[tuple[str, object]]) -> ProductInspection:
    """Aggregate product/tech observations of one asset for M20 and the M26 read API."""
    cpes: list[Cpe] = []
    skipped = 0
    versionless: list[str] = []
    for predicate, value in rows:
        item = inspect_product_observation(predicate, value)
        cpes.extend(item.cpes)
        skipped += item.skipped
        versionless.extend(item.versionless_products)
    return ProductInspection(tuple(cpes), skipped, _dedupe_labels(versionless))


def _cpes_of(predicate: str, value: object) -> tuple[list[Cpe], int]:
    """CPE + version pairs of one observation value; anything else is counted as skipped."""
    inspection = inspect_product_observation(predicate, value)
    return list(inspection.cpes), inspection.skipped


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
        targets, skipped, coverage = _targets(self._conn, campaign_id)
        report.targets = len(targets)
        report.skipped_values = skipped
        report.targets_with_cpe = sum(1 for target in targets if target.cpes)
        report.unmatchable_targets = int(coverage["unmatchable_subjects"])
        report.coverage = coverage
        product_keys = {cpe.product_index_key for target in targets for cpe in target.cpes}
        catalogue = _Catalogue(self._conn, only_vulnerabilities, product_keys)
        report.catalogue_revisions = catalogue.revisions
        report.catalogue_criteria = catalogue.criteria
        for target in targets:
            candidates = catalogue.candidates(target.cpes)
            if not candidates:
                continue
            report.considered += len(candidates)
            resolved = [
                Candidate(
                    asset_id=target.asset_id,
                    vulnerability_id=candidate.vulnerability_id,
                    vuln_rev_id=candidate.vuln_rev_id,
                    snapshot_id=candidate.snapshot_id,
                    confidence=candidate.confidence,
                    affected_range=candidate.affected_range,
                    match_method=candidate.match_method,
                )
                for candidate in candidates
            ]
            if dry_run:
                for candidate in resolved:
                    report.matches.append(_summary(candidate, target))
                report.new_matches += len(resolved)
                continue
            with self._conn.transaction():
                inserted_by_vuln = self._store_batch(resolved, target)
                report.existing_matches += len(resolved) - len(inserted_by_vuln)
                inserted_pairs = [
                    (candidate, inserted_by_vuln[candidate.vulnerability_id])
                    for candidate in resolved
                    if candidate.vulnerability_id in inserted_by_vuln
                ]
                if inserted_pairs:
                    report.new_matches += len(inserted_pairs)
                    report.events += self._emit_batch(inserted_pairs, target)
                    for candidate, _ in inserted_pairs:
                        report.matches.append(_summary(candidate, target))
        return report

    def _store_batch(self, candidates: Sequence[Candidate], target: Target) -> dict[str, str]:
        rows = [
            {
                "match_id": str(uuid7()),
                "package_asset_id": candidate.asset_id,
                "vulnerability_id": candidate.vulnerability_id,
                "vuln_rev_id": candidate.vuln_rev_id,
                "match_method": candidate.match_method,
                "affected_range": candidate.affected_range,
                "confidence": candidate.confidence,
                "snapshot_id": candidate.snapshot_id,
                "campaign_id": target.campaign_id,
            }
            for candidate in candidates
        ]
        inserted = self._conn.execute(
            "INSERT INTO package_vuln_match ("
            "  match_id, package_asset_id, vulnerability_id, vuln_rev_id,"
            "  match_method, affected_range, matched, confidence, snapshot_id, campaign_id"
            ")"
            " SELECT x.match_id, x.package_asset_id, x.vulnerability_id, x.vuln_rev_id,"
            "        x.match_method, x.affected_range, TRUE, x.confidence, x.snapshot_id,"
            "        x.campaign_id"
            "   FROM jsonb_to_recordset(%s::jsonb) AS x("
            "     match_id uuid, package_asset_id uuid, vulnerability_id text, vuln_rev_id uuid,"
            "     match_method text, affected_range text, confidence double precision,"
            "     snapshot_id uuid, campaign_id uuid"
            "   )"
            " ON CONFLICT (package_asset_id, vulnerability_id, vuln_rev_id, match_method)"
            " DO NOTHING RETURNING match_id, vulnerability_id",
            (json.dumps(rows),),
        ).fetchall()
        return {str(row["vulnerability_id"]): str(row["match_id"]) for row in inserted}

    def _emit_batch(self, pairs: Sequence[tuple[Candidate, str]], target: Target) -> int:
        rows = [
            {
                "event_id": str(uuid7()),
                "type": EVENT_TYPE,
                "producer": PRODUCER,
                "dedup_key": match_id,
                "campaign_id": target.campaign_id,
                "payload": {
                    "match_id": match_id,
                    "asset_id": candidate.asset_id,
                    "canonical_key": target.canonical_key,
                    "vulnerability_id": candidate.vulnerability_id,
                    "campaign_id": target.campaign_id,
                },
                "trace": {"trace_id": uuid4().hex},
            }
            for candidate, match_id in pairs
        ]
        inserted = self._conn.execute(
            "INSERT INTO outbox_event ("
            "  event_id, type, producer, dedup_key, campaign_id, payload, trace"
            ")"
            " SELECT x.event_id, x.type, x.producer, x.dedup_key, x.campaign_id,"
            "        x.payload, x.trace"
            "   FROM jsonb_to_recordset(%s::jsonb) AS x("
            "     event_id uuid, type text, producer text, dedup_key text,"
            "     campaign_id uuid, payload jsonb, trace jsonb"
            "   )"
            " ON CONFLICT (type, dedup_key) DO NOTHING RETURNING event_id",
            (json.dumps(rows),),
        ).fetchall()
        return len(inserted)

    def _store(self, candidate: Candidate, target: Target) -> str | None:
        return self._store_batch([candidate], target).get(candidate.vulnerability_id)

    def _emit(self, match_id: str, candidate: Candidate, target: Target) -> bool:
        return bool(self._emit_batch([(candidate, match_id)], target))


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
