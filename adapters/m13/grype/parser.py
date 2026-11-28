"""Grype v0.121.3 parser: a vulnerability report -> packages and CVE findings (G2-D, M13).

The core never imports a tool. M06 runs this function in the contained parser child named by the
pinned manifest (`parser.entrypoint: adapters.m13.grype.parser:parse`), so the module is stdlib-only
and has no clock, network, environment or database access:

    parse(output_dir, task, evidence) -> ParsedResults

It reads the JSON Grype writes for `docker-archive:/in/image.tar -o json=/out/result.json`:
`descriptor` (tool name/version and the offline DB's `status.built`), `distro`, `source` and
`matches[]` (`vulnerability` + `artifact`).

Mapping (the manifest's `emits` block):

* the **image** is the job's signed target (`input.targets`); `artifact.digest` is an observation on
  it. Grype only reports *matched* packages, so the parser declares a `package` asset for every
  matched artifact (with `discovered_from` the image), its `package.installed` and `asset.seen`, and
  the `CONTAINS_PACKAGE` edge - a Grype-only finding still has a subject asset M27 can resolve;
* every match becomes a **finding candidate** with `rule_id = cve:<id>` (or `advisory:<id>`), the
  package as subject, the package identity as location (plus installed/fixed version for display),
  the scanner severity as a signal and the raw JSON as evidence. M20 computes the fingerprint,
  merges providers that report the same package+CVE and decides the status; Grype never writes a
  finding or a status;
* `coverage.rule_set` is `grype-db@<descriptor.db.status.built>`: the tool itself names the offline
  database build its verdicts came from. The deployment still pins the DB file's sha256 (M06
  refuses a drifted file before a container exists), so the label and the bytes cannot diverge.

Identity: the same `adapters.artifact.purl` rule as Trivy/Syft (qualifiers/subpath dropped, Debian
epoch folded into the version). Grype reports the same installed package as Trivy for every dpkg
package the lab image has, and `pkg:generic/httpd@2.4.49` for the source-built binary, so a finding
reported by both tools merges on the platform (`finding_source` has one row per provider).

Not emitted: Grype's copied CVSS/EPSS/KEV values (M20 reads the intel catalogue), `matchDetails`
(matcher internals), and matches whose artifact has no purl (a coverage limitation, never a guessed
identity).

A report whose `descriptor.name` is not grype, whose version is not the pinned one, or whose
`matches` is not an array raises `ParserInputError`: a foreign or truncated document is a job error
the runner quarantines, never a quietly smaller result.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from adapters.artifact.purl import normalize_package_purl

__all__ = ["ParserInputError", "RESULT_FILE", "parse"]

RESULT_FILE = "result.json"
#: `local_ref` of the raw file M06 stored and hands to the parser (resolved by the collector).
RAW_REF = "raw"
IMAGE_KEY_PREFIX = "oci:sha256:"
SEVERITIES = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Negligible": "low",
    "Unknown": "unknown",
}
TITLE_LIMIT = 500
DESCRIPTION_LIMIT = 20000
FINDING_CONFIDENCE = 0.9


class ParserInputError(ValueError):
    """The output does not have the shape this pinned tool version writes."""


def parse(output_dir: Path, task: dict[str, Any], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    """Map Grype's JSON in `output_dir` to package assets, observations and finding candidates."""
    document = _document(Path(output_dir))
    _check_tool(document, task)
    image_key = _image_key(task)
    raw_refs = _raw_refs(evidence)
    rule_set = _rule_set(document)

    packages: dict[str, dict[str, Any]] = {}
    findings: dict[tuple[str, str], dict[str, Any]] = {}
    limitations: list[dict[str, Any]] = []
    for match in _matches(document):
        vulnerability = match.get("vulnerability")
        artifact = match.get("artifact")
        if not isinstance(vulnerability, dict) or not isinstance(artifact, dict):
            raise ParserInputError("a match has no vulnerability/artifact object")
        identifier = vulnerability.get("id")
        if not isinstance(identifier, str) or not identifier:
            limitations.append(
                {"code": "GRYPE_MATCH_WITHOUT_ID", "message": "a match has no vulnerability id"}
            )
            continue
        purl = artifact.get("purl")
        if not isinstance(purl, str) or not purl:
            limitations.append(
                {
                    "code": "GRYPE_ARTIFACT_WITHOUT_PURL",
                    "message": (
                        f"{identifier} names {artifact.get('name')!r} without a purl; "
                        "no package identity to attach it to"
                    ),
                }
            )
            continue
        normalized = normalize_package_purl(purl)
        if not normalized:
            limitations.append(
                {
                    "code": "GRYPE_ARTIFACT_WITHOUT_VERSION",
                    "message": f"{identifier} names {artifact.get('name')!r} without a version",
                }
            )
            continue
        location = _location(artifact)
        entry = packages.setdefault(
            normalized,
            {
                "version": normalized.rsplit("@", 1)[-1],
                "ecosystem": normalized[4:].split("/", 1)[0],
                "location": location,
            },
        )
        if location and not entry["location"]:
            entry["location"] = location
        candidates = _candidates(
            identifier, vulnerability, artifact, normalized, location, raw_refs
        )
        for key, candidate in candidates.items():
            existing = findings.get(key)
            findings[key] = candidate if existing is None else _merge(existing, candidate)

    assets: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    for purl in sorted(packages):
        entry = packages[purl]
        package_key = "purl:" + purl
        assets.append(
            {
                "kind": "package",
                "canonical_key": package_key,
                "attributes": {
                    "ecosystem": entry["ecosystem"],
                    "name": purl.rsplit("/", 1)[-1].split("@", 1)[0],
                    "version": entry["version"],
                },
                "discovered_from": [image_key],
            }
        )
        observations.append(
            {
                "subject": package_key,
                "predicate": "package.installed",
                "value": {
                    "version": entry["version"],
                    "ecosystem": entry["ecosystem"],
                    **({"location": entry["location"]} if entry["location"] else {}),
                },
            }
        )
        observations.append({"subject": package_key, "predicate": "asset.seen", "value": True})
        relationships.append(
            {"type": "CONTAINS_PACKAGE", "from": image_key, "to": package_key, "confidence": 1.0}
        )

    observations.insert(
        0,
        {"subject": image_key, "predicate": "artifact.digest", "value": image_key[len("oci:") :]},
    )
    return {
        "assets": assets,
        "observations": observations,
        "relationships": relationships,
        "findings": [findings[key] for key in sorted(findings)],
        "coverage_subjects": [image_key],
        "coverage": {
            "complete": True,
            "rule_set": rule_set,
            **({"limitations": limitations} if limitations else {}),
        },
    }


# --------------------------------------------------------------------------- document


def _document(output_dir: Path) -> dict[str, Any]:
    path = output_dir / RESULT_FILE
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ParserInputError(f"{path} does not exist") from error
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ParserInputError(f"{path} is not readable JSON: {error}") from error
    if not isinstance(document, dict):
        raise ParserInputError(f"{path} is not a JSON object")
    return document


def _check_tool(document: Mapping[str, Any], task: Mapping[str, Any]) -> None:
    descriptor = document.get("descriptor")
    if not isinstance(descriptor, dict) or descriptor.get("name") != "grype":
        raise ParserInputError("the report is not a Grype JSON report")
    found = descriptor.get("version")
    if not isinstance(found, str):
        raise ParserInputError("the report's descriptor has no Grype version")
    pinned = str(task.get("provider_version") or "")
    if pinned and pinned.lstrip("v") != found:
        raise ParserInputError(
            f"the report was written by Grype {found}, the accepted task pins {pinned}"
        )


def _rule_set(document: Mapping[str, Any]) -> str:
    descriptor = document.get("descriptor")
    db = descriptor.get("db") if isinstance(descriptor, dict) else None
    status = db.get("status") if isinstance(db, dict) else None
    built = status.get("built") if isinstance(status, dict) else None
    if not isinstance(built, str) or not built:
        raise ParserInputError("the report does not name the vulnerability database build")
    return "grype-db@" + built


def _matches(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    matches = document.get("matches")
    if not isinstance(matches, list):
        raise ParserInputError("matches is not an array")
    for index, match in enumerate(matches):
        if not isinstance(match, dict):
            raise ParserInputError(f"matches[{index}] is not an object")
    return matches


def _image_key(task: Mapping[str, Any]) -> str:
    raw = (task.get("input") or {}).get("targets") if isinstance(task.get("input"), dict) else None
    if not isinstance(raw, list) or len(raw) != 1 or not isinstance(raw[0], str):
        raise ParserInputError("the task input does not carry exactly one image target")
    value = raw[0].strip().lower()
    if value.startswith("oci:"):
        value = value[4:]
    if not value.startswith("sha256:") or len(value) != 71:
        raise ParserInputError(f"target {raw[0]!r} is not an image digest")
    try:
        int(value[7:], 16)
    except ValueError as error:
        raise ParserInputError(f"target {raw[0]!r} is not a sha256 digest") from error
    return IMAGE_KEY_PREFIX + value[7:]


def _raw_refs(evidence: Iterable[Mapping[str, Any]]) -> list[dict[str, str]]:
    """The contract's single evidence ref for the raw report (M06 resolves `raw`)."""
    del evidence
    return [{"local_ref": RAW_REF}]


# --------------------------------------------------------------------------- matches


def _candidates(
    identifier: str,
    vulnerability: Mapping[str, Any],
    artifact: Mapping[str, Any],
    purl: str,
    location: str,
    raw_refs: list[dict[str, str]],
) -> dict[tuple[str, str], dict[str, Any]]:
    """The finding candidate(s) of one match, keyed by (subject, rule id)."""
    rule_id = _rule_id(identifier)
    name = artifact.get("name")
    fix = vulnerability.get("fix")
    versions = fix.get("versions") if isinstance(fix, dict) else None
    fixed = ""
    if isinstance(versions, list):
        fixed = next((str(item) for item in versions if isinstance(item, str) and item), "")
    installed = vulnerability.get("installedVersion")
    if not isinstance(installed, str) or not installed:
        installed = purl.rsplit("@", 1)[-1]
    place: dict[str, Any] = {"package_purl": purl, "installed_version": installed}
    if fixed:
        place["fixed_version"] = fixed
    description = vulnerability.get("description")
    title = f"{identifier} in {name}" if isinstance(name, str) and name else identifier
    candidate: dict[str, Any] = {
        "subject": "purl:" + purl,
        "rule_id": rule_id,
        "category": "vulnerability",
        "title": title[:TITLE_LIMIT],
        "location": place,
        "vulnerability_ids": [identifier] if _vulnerability_id(identifier) else [],
        "cwe_ids": _cwes(vulnerability),
        "scanner_severity": SEVERITIES.get(str(vulnerability.get("severity")), "unknown"),
        "fingerprint_context": {
            "package": purl.split("@", 1)[0],
            "installed_version": installed,
        },
        "confidence": FINDING_CONFIDENCE,
        "evidence_refs": list(raw_refs),
    }
    if isinstance(description, str) and description:
        candidate["description"] = description[:DESCRIPTION_LIMIT]
    return {(candidate["subject"], rule_id): candidate}


def _merge(existing: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    """Two matches of one package+CVE (two namespaces): keep the strongest, most specific record."""
    rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}
    if rank.get(candidate["scanner_severity"], 0) > rank.get(existing["scanner_severity"], 0):
        existing = dict(existing)
        existing["scanner_severity"] = candidate["scanner_severity"]
    if "fixed_version" in candidate["location"] and "fixed_version" not in existing["location"]:
        existing = dict(existing)
        existing["location"] = {**existing["location"], **candidate["location"]}
    if len(candidate.get("description", "")) > len(existing.get("description", "")):
        existing = dict(existing)
        existing["description"] = candidate["description"]
    return existing


def _location(artifact: Mapping[str, Any]) -> str:
    locations = artifact.get("locations")
    if not isinstance(locations, list):
        return ""
    for item in locations:
        if isinstance(item, dict) and isinstance(item.get("path"), str):
            return str(item["path"])
    return ""


def _rule_id(identifier: str) -> str:
    """`cve:<id>` for a CVE, `advisory:<id>` for anything else (GHSA, vendor advisory)."""
    upper = identifier.upper()
    if upper.startswith("CVE-"):
        return "cve:" + upper
    return "advisory:" + identifier


def _vulnerability_id(identifier: str) -> bool:
    """The contract's `VulnerabilityId` shape (common/ids.v2); anything else stays in rule_id."""
    upper = identifier.upper()
    if upper.startswith("CVE-"):
        parts = upper.split("-")
        return len(parts) == 3 and parts[1].isdigit() and len(parts[1]) == 4 and parts[2].isdigit()
    if upper.startswith("GHSA-"):
        return len(upper) == 19
    return identifier[:1].isalpha() and "-" in identifier


def _cwes(vulnerability: Mapping[str, Any]) -> list[str]:
    cwes = vulnerability.get("cwes")
    found: list[str] = []
    if not isinstance(cwes, list):
        return found
    for item in cwes:
        value = item.get("cwe") if isinstance(item, dict) else item
        if isinstance(value, str) and value.startswith("CWE-") and value[4:].isdigit():
            if value not in found:
                found.append(value)
    return found
