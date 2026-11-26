"""M20-lite CVE matcher (G1.6 slice C): observations -> candidate AFFECTED_BY rows + events.

The matcher reads the *current* state of PostgreSQL, never a payload or the network:

* targets are the newest `service.product` / `http.technology` observation of every asset (one row
  per subject and predicate, `polarity = present`); only a value carrying a CPE and a version is a
  target - a bare product name is not matched by guesswork;
* the catalogue is `vulnerability_current` for `source = nvd` (withdrawn excluded): NVD's
  configurations and their version bounds, indexed by `(vendor, product)` so a target looks at one
  bucket. M20 evaluates the published configuration, not the flattened criteria: an `AND` node that
  requires a platform (a "runs on Windows" CVE) is not satisfied by an httpd banner, a negated node
  never confirms, and a criterion with no version (`-`/`*`, no bound) is not a version match
  (`aegis.m20_vuln.configurations`);
* a hit becomes one `package_vuln_match` row (`cpe_range`, confidence 0.7 for an exact-version
  criterion and 0.6 for a range) and one `vulnerability.matched.v2` outbox event in the same
  transaction, so M23 projects the candidate and the edge from the same commit. A CVE that names
  the observed product but cannot be decided is counted in the report's coverage
  (`VERSION_UNSPECIFIED`, `PLATFORM_UNCONFIRMED`) instead of becoming a candidate.

Candidates only: this module never writes `finding` and never raises a candidate to VERIFIED - that
needs evidence and is G2's decision (AGENTS.md). Idempotency is the database's: migration 0004's
unique `(package_asset_id, vulnerability_id, vuln_rev_id, match_method)` turns a re-run into
`ON CONFLICT DO NOTHING`, and a new intel snapshot is a new `vuln_rev_id`, hence a new candidate.

A candidate is a *decision*, and a new revision can take it back. When the newest decision of an
(asset, vulnerability) pair was a match and this run decides otherwise, M20 stores the opposite
decision at the new revision (`matched = false`, `retraction_reason`, migration 0008) and publishes
the same `vulnerability.matched.v2` event in the same transaction, so M23 drops the AFFECTED_BY
edge and M26's read model stops listing the candidate. History stays: rows are append-only, the
positive decision at the old revision is still there. One retraction is written per pair (the
unique key does not include the campaign: `campaign_id` is the provenance of the run that decided),
and never at that decision's own revision (the key would refuse it): a code change without a new
intel revision leaves the old candidate in place until the next sync, which is what
`report.retractions_blocked` counts.

A delta run (`--changed-since <seq>`) restricts the catalogue to the CVE ids of the
`intel.revision.v2` events after that cursor, which is what "re-run matching when a feed snapshot
loads" means without walking the whole catalogue; such a run only retracts the CVEs it decided,
plus any candidate whose CVE is now withdrawn (a fact about the feed, not a scope of the run).
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

from aegis.m20_vuln.configurations import (
    PLATFORM_UNCONFIRMED_CODE,
    PLATFORM_UNCONFIRMED_MESSAGE,
    VERSION_UNSPECIFIED_CODE,
    VERSION_UNSPECIFIED_MESSAGE,
    Configuration,
    decide,
    observe,
    parse_configurations,
    products,
)
from aegis.m20_vuln.cpe import (
    Cpe,
    CpeError,
    parse_cpe,
)

#: ids.v2 requires UUIDv7; M27 owns the generator today (one shared helper is a G1.4a proposal).
from aegis.m27_ingestion.ids import uuid7

__all__ = [
    "Candidate",
    "MatchReport",
    "Matcher",
    "ProductInspection",
    "RETRACTION_CODES",
    "Retraction",
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
#: The previous decision was a match and the current revision's configuration no longer contains it.
NO_LONGER_MATCHES_CODE = "NO_LONGER_MATCHES"
#: The current NVD revision is Rejected/Withdrawn: it can never be a candidate again.
WITHDRAWN_CODE = "WITHDRAWN"
#: Every `retraction_reason` 0008 accepts; the first two come from the configuration rules.
RETRACTION_CODES = (
    VERSION_UNSPECIFIED_CODE,
    PLATFORM_UNCONFIRMED_CODE,
    NO_LONGER_MATCHES_CODE,
    WITHDRAWN_CODE,
)
#: Confidence of a candidate: an exact-version criterion beats a range, both stay candidates.
CONFIDENCE_EXACT = 0.7
CONFIDENCE_RANGE = 0.6
_VERSION_HINT_RE = re.compile(r"[:/\s]v?\d")
#: How much undecided detail a report keeps (the CLI prints it; the rest is a SQL question).
LIMITATION_IDS = 100
LIMITATION_SUBJECTS = 50

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
class Retraction:
    """One decision that takes a candidate back, before it is stored."""

    asset_id: str
    vulnerability_id: str
    vuln_rev_id: str
    snapshot_id: str
    campaign_id: str
    reason: str
    match_method: str


@dataclass(frozen=True, slots=True)
class PreviousMatch:
    """The newest positive decision of one (asset, vulnerability) pair, with its provenance."""

    vulnerability_id: str
    vuln_rev_id: str
    match_method: str
    campaign_id: str


@dataclass(frozen=True, slots=True)
class CurrentRevision:
    """The newest NVD revision of a CVE: where a retraction is written, and what it now says."""

    vuln_rev_id: str
    snapshot_id: str
    withdrawn: bool
    affected: object


@dataclass(frozen=True, slots=True)
class Decisions:
    """What one catalogue pass decided for one target.

    `matched` are the candidates; `reasons` says why the CVE a target names did not become one;
    `decided` is the set this pass actually evaluated - a delta run narrows the catalogue, and a
    retraction may only be written for a CVE the run looked at.
    """

    matched: tuple[Candidate, ...]
    reasons: Mapping[str, str]
    decided: frozenset[str]


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
    #: Decisions rejected because NVD published the product with no version (`-`/`*`, no bound).
    version_unspecified: int = 0
    #: Decisions rejected because the configuration ANDs a product nobody observed (a platform).
    platform_unconfirmed: int = 0
    #: Candidates this run took back (a `matched = false` row at the new revision).
    retracted: int = 0
    #: Retractions that cannot be written because the previous decision is still the newest
    #: revision of that CVE: the append-only key refuses a second row until a sync lands.
    retractions_blocked: int = 0
    dry_run: bool = False
    cursor: int | None = None
    vulnerabilities_filter: int | None = None
    coverage: dict[str, Any] = field(default_factory=dict)
    matches: list[dict[str, Any]] = field(default_factory=list)
    retractions: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        document = dict(self.__dict__)
        document.pop("matches")
        document.pop("retractions")
        return document


class _Catalogue:
    """NVD configurations indexed by `(vendor, product)`, narrowed in PostgreSQL via GIN."""

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
            self.entries: dict[str, tuple[str, str, tuple[Configuration, ...]]] = {}
            self.by_product: dict[tuple[str, str], tuple[str, ...]] = {}
            return
        rows = self._query_rows(connection, wanted, wanted_products)
        entries: dict[str, tuple[str, str, tuple[Configuration, ...]]] = {}
        by_product_lists: dict[tuple[str, str], list[str]] = {}
        for row in rows:
            configurations = parse_configurations(row["affected"])
            if not configurations:
                continue
            vulnerability_id = str(row["vulnerability_id"])
            entries[vulnerability_id] = (
                str(row["vuln_rev_id"]),
                str(row["snapshot_id"]),
                configurations,
            )
            for key in products(configurations):
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
        return sum(
            _criteria_count(configurations) for _, _, configurations in self.entries.values()
        )

    def decide(self, cpes: Sequence[Cpe]) -> Decisions:
        """The candidate of every CVE the observed CPEs satisfy, plus the undecided reasons.

        The whole target is evaluated at once: one configuration can name the product of one
        observed CPE and require the platform of another, so a per-CPE decision would answer a
        different question than the CVE asks.
        """
        observed = observe(cpes)
        wanted: set[str] = set()
        for cpe in cpes:
            wanted.update(self.by_product.get(cpe.product_key, ()))
        best: dict[str, Candidate] = {}
        reasons: dict[str, str] = {}
        decided: set[str] = set()
        for vulnerability_id in sorted(wanted):
            decided.add(vulnerability_id)
            revision_id, snapshot_id, configurations = self.entries[vulnerability_id]
            decision = decide(configurations, observed)
            criterion = decision.criterion
            if criterion is None:
                if decision.reason is not None:
                    reasons[vulnerability_id] = decision.reason
                continue
            best[vulnerability_id] = Candidate(
                asset_id="",
                vulnerability_id=vulnerability_id,
                vuln_rev_id=revision_id,
                snapshot_id=snapshot_id,
                confidence=CONFIDENCE_EXACT if criterion.exact else CONFIDENCE_RANGE,
                affected_range=criterion.range_text,
            )
        return Decisions(
            matched=tuple(best.values()),
            reasons=reasons,
            decided=frozenset(decided),
        )


def _criteria_count(configurations: Iterable[Configuration]) -> int:
    total = 0
    for configuration in configurations:
        stack = list(configuration.nodes)
        while stack:
            node = stack.pop()
            total += len(node.criteria)
            stack.extend(node.children)
    return total


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
        undecided: dict[str, dict[str, set[str]]] = {
            VERSION_UNSPECIFIED_CODE: {},
            PLATFORM_UNCONFIRMED_CODE: {},
        }
        previous = self._previous_matches([target.asset_id for target in targets])
        retracted: list[dict[str, Any]] = []
        blocked = 0
        for target in targets:
            decisions = catalogue.decide(target.cpes)
            for vulnerability_id, reason in decisions.reasons.items():
                undecided[reason].setdefault(vulnerability_id, set()).add(target.canonical_key)
            candidates = decisions.matched
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
            report.considered += len(resolved)
            taking_back, undecidable = self._retractions(
                target,
                decisions,
                previous.get(target.asset_id, ()),
                full_run=only_vulnerabilities is None,
            )
            blocked += undecidable
            if dry_run:
                for candidate in resolved:
                    report.matches.append(_summary(candidate, target))
                for retraction in taking_back:
                    report.retractions.append(_retraction_summary(retraction, target))
                report.new_matches += len(resolved)
                report.retracted += len(taking_back)
                continue
            with self._conn.transaction():
                inserted_by_vuln = self._store_batch(resolved, target)
                report.existing_matches += len(resolved) - len(inserted_by_vuln)
                inserted_pairs = [
                    (candidate.vulnerability_id, match_id, target.campaign_id)
                    for candidate in resolved
                    if (match_id := inserted_by_vuln.get(candidate.vulnerability_id)) is not None
                ]
                if inserted_pairs:
                    report.new_matches += len(inserted_pairs)
                    report.events += self._emit_batch(inserted_pairs, target)
                    for candidate in resolved:
                        if candidate.vulnerability_id in inserted_by_vuln:
                            report.matches.append(_summary(candidate, target))
                if taking_back:
                    inserted_retractions = self._store_retractions(taking_back)
                    report.retracted += len(inserted_retractions)
                    report.events += self._emit_batch(
                        [
                            (retraction.vulnerability_id, match_id, retraction.campaign_id)
                            for retraction, match_id in inserted_retractions
                        ],
                        target,
                    )
                    for retraction, _ in inserted_retractions:
                        retracted.append(_retraction_summary(retraction, target))
        report.retractions = retracted
        report.retractions_blocked = blocked
        report.version_unspecified = _undecided_count(undecided[VERSION_UNSPECIFIED_CODE])
        report.platform_unconfirmed = _undecided_count(undecided[PLATFORM_UNCONFIRMED_CODE])
        _report_undecided(coverage, undecided)
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

    def _emit_batch(self, pairs: Sequence[tuple[str, str, str]], target: Target) -> int:
        """One `vulnerability.matched.v2` per decision: `(vulnerability, match_id, campaign)`."""
        rows = [
            {
                "event_id": str(uuid7()),
                "type": EVENT_TYPE,
                "producer": PRODUCER,
                "dedup_key": match_id,
                "campaign_id": campaign_id,
                "payload": {
                    "match_id": match_id,
                    "asset_id": target.asset_id,
                    "canonical_key": target.canonical_key,
                    "vulnerability_id": vulnerability_id,
                    "campaign_id": campaign_id,
                },
                "trace": {"trace_id": uuid4().hex},
            }
            for vulnerability_id, match_id, campaign_id in pairs
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
        return bool(
            self._emit_batch([(candidate.vulnerability_id, match_id, target.campaign_id)], target)
        )

    def _previous_matches(self, asset_ids: Sequence[str]) -> dict[str, list[PreviousMatch]]:
        """The newest decision of every (asset, vulnerability) pair, when it is a match.

        `package_vuln_match` is append-only and one row per `(asset, vuln, vuln_rev, method)`, so
        the newest row of a pair is the decision in force: a pair that is already retracted is not
        retracted twice. The campaign on the row is provenance of the decision (migration 0008's
        unique key does not include it), so the newest row's campaign is the one a retraction keeps.
        """
        if not asset_ids:
            return {}
        rows = self._conn.execute(
            "SELECT DISTINCT ON (package_asset_id, vulnerability_id)"
            "       package_asset_id, vulnerability_id, vuln_rev_id, match_method, campaign_id,"
            "       matched"
            "  FROM package_vuln_match"
            " WHERE package_asset_id = ANY(%s::uuid[]) AND campaign_id IS NOT NULL"
            " ORDER BY package_asset_id, vulnerability_id, created_at DESC, match_id DESC",
            (sorted(set(asset_ids)),),
        ).fetchall()
        found: dict[str, list[PreviousMatch]] = {}
        for row in rows:
            if not row["matched"]:
                continue
            found.setdefault(str(row["package_asset_id"]), []).append(
                PreviousMatch(
                    vulnerability_id=str(row["vulnerability_id"]),
                    vuln_rev_id=str(row["vuln_rev_id"]),
                    match_method=str(row["match_method"]),
                    campaign_id=str(row["campaign_id"]),
                )
            )
        return found

    def _retractions(
        self,
        target: Target,
        decisions: Decisions,
        previous: Sequence[PreviousMatch],
        full_run: bool,
    ) -> tuple[list[Retraction], int]:
        """The decisions this run takes back, and how many it could not write.

        A retraction is planned for a CVE the run decided, for a candidate whose current revision is
        withdrawn (a fact about the feed, not a scope), and - on a full run - for a revision that no
        longer mentions any observed product and therefore never reached the narrowed catalogue. A
        delta run only takes back what it decided. The new revision is the current one, so the
        append-only unique key `(asset, vuln, vuln_rev, method)` cannot collide with the decision
        it takes back; when the current revision *is* the previous decision's revision nothing can
        be written and the count says a sync is needed.
        """
        matched = {candidate.vulnerability_id for candidate in decisions.matched}
        revisions = self._current_nvd_revisions(row.vulnerability_id for row in previous)
        planned: list[Retraction] = []
        blocked = 0
        for row in previous:
            if row.vulnerability_id in matched:
                continue
            revision = revisions.get(row.vulnerability_id)
            if revision is None:
                continue  # no NVD revision for it any more: nothing to decide at
            if revision.withdrawn:
                reason = WITHDRAWN_CODE
            elif row.vulnerability_id in decisions.decided:
                reason = decisions.reasons.get(row.vulnerability_id) or NO_LONGER_MATCHES_CODE
            elif not full_run:
                continue  # a delta run only takes back what it decided, plus withdrawals
            else:
                # The current revision no longer mentions any observed product, so the narrowed
                # catalogue never showed it to this run: decide it here instead of leaving it.
                decision = decide(parse_configurations(revision.affected), observe(target.cpes))
                if decision.criterion is not None:
                    continue
                reason = decision.reason or NO_LONGER_MATCHES_CODE
            if revision.vuln_rev_id == row.vuln_rev_id:
                blocked += 1  # same revision: the append-only key refuses a second decision
                continue
            planned.append(
                Retraction(
                    asset_id=target.asset_id,
                    vulnerability_id=row.vulnerability_id,
                    vuln_rev_id=revision.vuln_rev_id,
                    snapshot_id=revision.snapshot_id,
                    campaign_id=row.campaign_id,
                    reason=reason,
                    match_method=row.match_method,
                )
            )
        return planned, blocked

    def _current_nvd_revisions(
        self, vulnerability_ids: Iterable[str]
    ) -> dict[str, CurrentRevision]:
        """The newest NVD revision of each CVE; withdrawn ones are included on purpose."""
        wanted = sorted({value for value in vulnerability_ids})
        if not wanted:
            return {}
        rows = self._conn.execute(
            "SELECT DISTINCT ON (vulnerability_id)"
            "       vulnerability_id, vuln_rev_id, snapshot_id, withdrawn, affected"
            "  FROM vulnerability_current"
            " WHERE source = 'nvd' AND vulnerability_id = ANY(%s::text[])"
            " ORDER BY vulnerability_id, created_at DESC, vuln_rev_id DESC",
            (wanted,),
        ).fetchall()
        return {
            str(row["vulnerability_id"]): CurrentRevision(
                vuln_rev_id=str(row["vuln_rev_id"]),
                snapshot_id=str(row["snapshot_id"]),
                withdrawn=bool(row["withdrawn"]),
                affected=row["affected"],
            )
            for row in rows
        }

    def _store_retractions(self, retractions: Sequence[Retraction]) -> list[tuple[Retraction, str]]:
        """Store `matched = false` decisions; a re-run is `ON CONFLICT DO NOTHING`."""
        rows = [
            {
                "match_id": str(uuid7()),
                "package_asset_id": retraction.asset_id,
                "vulnerability_id": retraction.vulnerability_id,
                "vuln_rev_id": retraction.vuln_rev_id,
                "match_method": retraction.match_method,
                "snapshot_id": retraction.snapshot_id,
                "campaign_id": retraction.campaign_id,
                "retraction_reason": retraction.reason,
            }
            for retraction in retractions
        ]
        inserted = self._conn.execute(
            "INSERT INTO package_vuln_match ("
            "  match_id, package_asset_id, vulnerability_id, vuln_rev_id, match_method,"
            "  matched, snapshot_id, campaign_id, retraction_reason"
            ")"
            " SELECT x.match_id, x.package_asset_id, x.vulnerability_id, x.vuln_rev_id,"
            "        x.match_method, FALSE, x.snapshot_id, x.campaign_id, x.retraction_reason"
            "   FROM jsonb_to_recordset(%s::jsonb) AS x("
            "     match_id uuid, package_asset_id uuid, vulnerability_id text, vuln_rev_id uuid,"
            "     match_method text, snapshot_id uuid, campaign_id uuid, retraction_reason text"
            "   )"
            " ON CONFLICT (package_asset_id, vulnerability_id, vuln_rev_id, match_method)"
            " DO NOTHING RETURNING match_id, vulnerability_id, campaign_id",
            (json.dumps(rows),),
        ).fetchall()
        by_key = {(item.vulnerability_id, item.campaign_id): item for item in retractions}
        stored: list[tuple[Retraction, str]] = []
        for row in inserted:
            retraction = by_key.get((str(row["vulnerability_id"]), str(row["campaign_id"])))
            if retraction is not None:
                stored.append((retraction, str(row["match_id"])))
        return stored


def _undecided_count(undecided: dict[str, set[str]]) -> int:
    """How many (asset, CVE) decisions a reason covers."""
    return sum(len(subjects) for subjects in undecided.values())


def _report_undecided(coverage: dict[str, Any], undecided: dict[str, dict[str, set[str]]]) -> None:
    """Append the CVEs that name an observed product and still cannot be decided to `coverage`.

    A candidate is evidence; a *non*-candidate is not, so the count and a bounded sample of the
    ids go into the run report. That is how an operator sees "11 of the matches on httpd 2.4.49
    are gone because NVD published no version" without reading the feed by hand (item 61).
    """
    messages = {
        VERSION_UNSPECIFIED_CODE: VERSION_UNSPECIFIED_MESSAGE,
        PLATFORM_UNCONFIRMED_CODE: PLATFORM_UNCONFIRMED_MESSAGE,
    }
    limitations = coverage.setdefault("limitations", [])
    for code, message in messages.items():
        decided = undecided.get(code) or {}
        if not decided:
            continue
        subjects = sorted({subject for found in decided.values() for subject in found})
        limitations.append(
            {
                "code": code,
                "message": message,
                "decisions": _undecided_count(decided),
                "vulnerability_ids": sorted(decided)[:LIMITATION_IDS],
                "subjects": subjects[:LIMITATION_SUBJECTS],
            }
        )


def _retraction_summary(retraction: Retraction, target: Target) -> dict[str, Any]:
    return {
        "asset": target.canonical_key,
        "asset_id": retraction.asset_id,
        "campaign_id": retraction.campaign_id,
        "vulnerability_id": retraction.vulnerability_id,
        "reason": retraction.reason,
        "snapshot_id": retraction.snapshot_id,
    }


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
