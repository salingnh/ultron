"""Feed parsers of M18 (G1.6 slice C): NVD CVE JSON 2.0, CISA KEV and FIRST EPSS.

The feeds are public, offline-pinned files: the sync command downloads them (host network is its
only network access, and only in its own command), stores the exact bytes in S3 and records them in
`intel_snapshot`. This module only turns bytes into the normalized rows
`aegis.vulnerability_revision` stores, so it never touches the network, a database or a clock.

One record = one `(vulnerability_id, source)` revision. `content_hash` covers exactly the fields a
revision is made of (never ids, source or snapshot), which is what makes "unchanged content is not
a new revision" true: the same NVD export loaded twice writes nothing.

The parsed shapes are documented next to each field because they are what M20 matches against and
what the read API returns; they are JSONB, so the database does not constrain them:
`cvss` = `{version, vector, base_score, base_severity}`,
`kev` = `{date_added, due_date, required_action, vendor_project, product, vulnerability_name,
known_ransomware, catalog_version}`,
`epss` = `{score, percentile, score_date}`,
`affected` = `{cpe_match: [{criteria, vulnerable, version_start_including, version_start_excluding,
version_end_including, version_end_excluding, match_criteria_id}]}` (NVD configurations flattened,
`vulnerable: false` entries kept because they are the exclusion half of the range).
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any

__all__ = [
    "FEEDS",
    "NVD",
    "KEV",
    "EPSS",
    "FeedError",
    "VulnRecord",
    "content_hash",
    "parse",
    "parse_epss",
    "parse_kev",
    "parse_nvd",
    "snapshot_at_from",
]

NVD = "nvd"
KEV = "kev"
EPSS = "epss"
#: The three feeds this slice syncs; `intel_snapshot.feed` allows osv/ghsa too, not here.
FEEDS = (NVD, KEV, EPSS)

#: Bound on the reference list stored per CVE: enough for a human, not the whole NVD export.
REFERENCE_LIMIT = 50


class FeedError(ValueError):
    """The bytes are not the shape of that feed; nothing is written."""


@dataclass(frozen=True, slots=True)
class VulnRecord:
    """One normalized revision row; `source` is the feed, never the record's own field."""

    vulnerability_id: str
    cvss: dict[str, Any] | None = None
    kev: dict[str, Any] | None = None
    epss: dict[str, Any] | None = None
    affected: dict[str, Any] | None = None
    references: list[dict[str, Any]] = field(default_factory=list)
    aliases: tuple[str, ...] = ()
    published_at: datetime | None = None
    modified_at: datetime | None = None
    withdrawn: bool = False

    def content_hash(self) -> str:
        payload = {
            "cvss": self.cvss,
            "kev": self.kev,
            "epss": self.epss,
            "affected": self.affected,
            "references": self.references,
            "aliases": list(self.aliases),
            "published_at": _iso(self.published_at),
            "modified_at": _iso(self.modified_at),
            "withdrawn": self.withdrawn,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def content_hash(record: VulnRecord) -> str:
    return record.content_hash()


def _iso(moment: datetime | None) -> str | None:
    if moment is None:
        return None
    return moment.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _moment(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as error:
        raise FeedError(f"not an RFC 3339 timestamp: {value!r}") from error
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _date(value: object) -> str | None:
    """A `YYYY-MM-DD` feed field, kept as a string (KEV/EPSS publish calendar dates)."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        date.fromisoformat(value.strip())
    except ValueError as error:
        raise FeedError(f"not a calendar date: {value!r}") from error
    return value.strip()


def _object(value: object, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FeedError(f"{what} must be an object, got {type(value).__name__}")
    return value


def _list(value: object, what: str) -> list[Any]:
    if not isinstance(value, list):
        raise FeedError(f"{what} must be an array, got {type(value).__name__}")
    return value


def _vulnerability_id(value: object) -> str:
    if not isinstance(value, str) or not value.startswith("CVE-") or value.count("-") != 2:
        raise FeedError(f"not a CVE id: {value!r}")
    year, _, number = value.removeprefix("CVE-").partition("-")
    if len(year) != 4 or not year.isdigit() or not number.isdigit() or len(number) < 4:
        raise FeedError(f"not a CVE id: {value!r}")
    return value


# --- NVD ------------------------------------------------------------------------------


def _cvss_from(metrics: dict[str, Any]) -> dict[str, Any] | None:
    """Highest CVSS version NVD publishes for the CVE, in the order v4.0 > v3.1 > v3.0 > v2."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue
        entry = entries[0]
        if not isinstance(entry, dict):
            continue
        data = entry.get("cvssData")
        if not isinstance(data, dict):
            continue
        score = data.get("baseScore")
        if not isinstance(score, (int, float)):
            continue
        severity = data.get("baseSeverity") or entry.get("baseSeverity")
        return {
            "version": str(data.get("version") or key.removeprefix("cvssMetricV").replace("V", "")),
            "vector": data.get("vectorString"),
            "base_score": float(score),
            "base_severity": severity if isinstance(severity, str) else None,
        }
    return None


def _cpe_matches(node: object, found: list[dict[str, Any]]) -> None:
    """Flatten NVD `configurations[].nodes[]` (children included) into one cpe_match list."""
    if not isinstance(node, dict):
        raise FeedError("an NVD configuration node must be an object")
    for match in node.get("cpeMatch") or ():
        match = _object(match, "cpeMatch entry")
        criteria = match.get("criteria")
        if not isinstance(criteria, str):
            raise FeedError("a cpeMatch entry has no criteria string")
        found.append(
            {
                "criteria": criteria,
                "vulnerable": bool(match.get("vulnerable", False)),
                "version_start_including": match.get("versionStartIncluding"),
                "version_start_excluding": match.get("versionStartExcluding"),
                "version_end_including": match.get("versionEndIncluding"),
                "version_end_excluding": match.get("versionEndExcluding"),
                "match_criteria_id": match.get("matchCriteriaId"),
            }
        )
    for child in node.get("children") or ():
        _cpe_matches(child, found)


def _affected(configurations: object) -> dict[str, Any] | None:
    if configurations is None:
        return None
    if not isinstance(configurations, list):
        raise FeedError(f"configurations must be an array, got {type(configurations).__name__}")
    if not configurations:
        return None
    matches: list[dict[str, Any]] = []
    for configuration in configurations:
        for node in _object(configuration, "configuration").get("nodes") or ():
            _cpe_matches(node, matches)
    return {"cpe_match": matches} if matches else None


def _cve_references(references: object) -> list[dict[str, Any]]:
    if not isinstance(references, list):
        return []
    kept: list[dict[str, Any]] = []
    for reference in references[:REFERENCE_LIMIT]:
        reference = _object(reference, "reference")
        url = reference.get("url")
        if not isinstance(url, str):
            continue
        tags = [str(tag) for tag in reference.get("tags") or () if isinstance(tag, str)]
        kept.append({"url": url, "source": reference.get("source"), "tags": tags})
    return kept


def parse_nvd(document: object) -> list[VulnRecord]:
    """NVD CVE JSON 2.0 (`https://nvd.nist.gov/feeds/json/cve/2.0/`)."""
    payload = _object(document, "NVD export")
    entries = _list(payload.get("vulnerabilities"), "NVD vulnerabilities")
    records: list[VulnRecord] = []
    for entry in entries:
        cve = _object(_object(entry, "NVD vulnerability").get("cve"), "cve")
        status = cve.get("vulnStatus")
        records.append(
            VulnRecord(
                vulnerability_id=_vulnerability_id(cve.get("id")),
                cvss=_cvss_from(_object(cve.get("metrics") or {}, "metrics")),
                affected=_affected(cve.get("configurations")),
                references=_cve_references(cve.get("references")),
                published_at=_moment(cve.get("published")),
                modified_at=_moment(cve.get("lastModified")),
                withdrawn=isinstance(status, str) and status.lower() in {"rejected", "withdrawn"},
            )
        )
    return records


# --- CISA KEV -------------------------------------------------------------------------


def parse_kev(document: object) -> list[VulnRecord]:
    """CISA Known Exploited Vulnerabilities catalog JSON."""
    payload = _object(document, "KEV catalog")
    version = payload.get("catalogVersion")
    entries = _list(payload.get("vulnerabilities"), "KEV vulnerabilities")
    # `dateReleased` is a full timestamp in the published catalog ("2022-03-25T00:00:00.000Z").
    released = _moment(payload.get("dateReleased"))
    records: list[VulnRecord] = []
    for entry in entries:
        entry = _object(entry, "KEV vulnerability")
        records.append(
            VulnRecord(
                vulnerability_id=_vulnerability_id(entry.get("cveID")),
                kev={
                    "date_added": _date(entry.get("dateAdded")),
                    "due_date": _date(entry.get("dueDate")),
                    "required_action": entry.get("requiredAction"),
                    "vendor_project": entry.get("vendorProject"),
                    "product": entry.get("product"),
                    "vulnerability_name": entry.get("vulnerabilityName"),
                    "known_ransomware": entry.get("knownRansomwareCampaignUse"),
                    "catalog_version": str(version) if version is not None else None,
                },
                published_at=_moment(entry.get("dateAdded")) if entry.get("dateAdded") else None,
                modified_at=released,
            )
        )
    return records


# --- FIRST EPSS -----------------------------------------------------------------------


def _percentile(value: object) -> float | None:
    if value is None or value == "":
        return None
    if not isinstance(value, (int, float, str)):
        raise FeedError(f"EPSS percentile is not a number: {value!r}")
    try:
        return float(value)
    except (TypeError, ValueError) as error:
        raise FeedError(f"EPSS percentile is not a number: {value!r}") from error


def _score(value: object) -> float:
    if isinstance(value, (int, float)):
        score = float(value)
    elif isinstance(value, str):
        try:
            score = float(value)
        except ValueError as error:
            raise FeedError(f"EPSS score is not a number: {value!r}") from error
    else:
        raise FeedError(f"EPSS score is not a number: {value!r}")
    if not 0.0 <= score <= 1.0:
        raise FeedError(f"EPSS score outside [0, 1]: {score!r}")
    return score


def parse_epss(data: bytes | str, *, score_date: str | None = None) -> list[VulnRecord]:
    """FIRST EPSS `epss_scores-<date>.csv` (or the equivalent JSON export).

    The CSV is `cve,epss,percentile` with a header line. The JSON form is either a list of
    `{cve, epss, percentile}` objects or `{"data": [...]}`. `score_date` is the date the scores
    were computed for (the resource name carries it), never "now": a stored revision must not
    change just because it was fetched on another day.
    """
    text = data.decode("utf-8") if isinstance(data, bytes) else data
    items: list[dict[str, Any]] = []
    stripped = text.lstrip()
    if stripped.startswith("[") or stripped.startswith("{"):
        document = json.loads(text)
        if isinstance(document, dict):
            document = document.get("data") or document.get("scores") or []
        items = [_object(item, "EPSS entry") for item in _list(document, "EPSS entries")]
        rows = [(item.get("cve"), item.get("epss"), item.get("percentile")) for item in items]
    else:
        reader = csv.reader(io.StringIO(text))
        rows = []
        for index, row in enumerate(reader):
            if not row:
                continue
            if index == 0 and row[0].strip().lower() == "cve":
                continue
            if len(row) < 2:
                raise FeedError(f"EPSS row {index + 1} has {len(row)} columns, expected 3")
            rows.append((row[0], row[1], row[2] if len(row) > 2 else None))
    records: list[VulnRecord] = []
    for cve, score, percentile in rows:
        records.append(
            VulnRecord(
                vulnerability_id=_vulnerability_id(cve.strip() if isinstance(cve, str) else cve),
                epss={
                    "score": _score(score),
                    "percentile": _percentile(percentile),
                    "score_date": score_date,
                },
            )
        )
    return records


# --- entry point ----------------------------------------------------------------------


def parse(feed: str, data: bytes, *, version: str) -> list[VulnRecord]:
    """Parse one feed's bytes; `version` is the snapshot version the caller assigned."""
    if feed == NVD:
        return parse_nvd(json.loads(data.decode("utf-8")))
    if feed == KEV:
        return parse_kev(json.loads(data.decode("utf-8")))
    if feed == EPSS:
        return parse_epss(data, score_date=version)
    raise FeedError(f"unknown feed {feed!r}; expected one of {', '.join(FEEDS)}")


def snapshot_at_from(feed: str, data: bytes, *, fallback: datetime) -> datetime:
    """The feed's own publication moment when it publishes one, else the caller's fallback.

    An `intel_snapshot.snapshot_at` is "when the feed says this set is from", not "when this
    process ran": NVD's export carries no such field (the file name/date does), KEV publishes
    `dateReleased`, and EPSS scores carry their score date (the version).
    """
    try:
        if feed == KEV:
            released = _moment(_object(json.loads(data.decode("utf-8")), "KEV").get("dateReleased"))
            if released is not None:
                return released
        if feed == NVD:
            document = _object(json.loads(data.decode("utf-8")), "NVD")
            timestamp = document.get("timestamp")
            moment = _moment(timestamp) if isinstance(timestamp, str) else None
            if moment is not None:
                return moment
    except (FeedError, ValueError, json.JSONDecodeError):
        return fallback
    return fallback
