"""Trivy v0.76.2 parser: an image scan -> packages, SBOM, CVE candidate findings (G2-D, M13).

The core never imports a tool. M06 runs this function in the contained parser child named by the
pinned manifest (`parser.entrypoint: adapters.m13.trivy.parser:parse`), so the module is stdlib-only
and has no clock, network, environment or database access:

    parse(output_dir, task, evidence) -> ParsedResults

It reads the JSON Trivy writes for `image --input /in/image.tar --format json --list-all-pkgs
--scanners vuln`: one object with `Trivy.Version`, `Metadata` (image id, OS, repo tags) and
`Results[]` (`Class`, `Type`, `Packages[]`, `Vulnerabilities[]`).

Mapping (the manifest's `emits` block):

* the **image** is the job's signed target (`input.targets`), never a tag or a repository from the
  scanner output: `artifact.digest` (the digest the campaign authorized) and `artifact.sbom`
  (format, tool version, OS family/version, package and vulnerability counts) are observations on
  that asset. The image asset itself is the campaign seed (M01), so the parser does not re-declare
  it - a re-declaration would be a second identity claim for the same bytes;
* every package becomes a `package` asset `purl:pkg:<type>/<ns>/<name>@<version>` plus a
  `package.installed` observation (version, ecosystem, license, path) and an `asset.seen: true`;
  the image -> package `CONTAINS_PACKAGE` edge carries the evidence that the package is installed
  in this image;
* every vulnerable package becomes a **finding candidate** with `rule_id = cve:<id>` (or
  `advisory:<id>` for a non-CVE identifier such as GHSA), the package as subject, the package
  identity as location, the evidence ref of the raw JSON, and the scanner's severity as a *signal*
  only. M20 computes the fingerprint, merges providers that report the same package+CVE into one
  finding and decides the status; the parser never writes a finding or a status.

Identity: the package purl is normalized by `adapters.artifact.purl` (qualifiers and subpath
dropped, installed version kept - Trivy writes Debian epochs as a qualifier), so Trivy, Syft and
Grype agree on the asset key and their findings merge. A package without a version is not an
identity (`asset_package.version` is NOT NULL) and is skipped with a coverage limitation, never
guessed.

Not emitted, on purpose: `InstalledFiles` (a Debian package lists hundreds of paths; it is noise
for identity and blows up the envelope), layer ids, `CVSS` vectors (M20 reads the vulnerability
catalogue, not a scanner's copy of it), and any secret/misconfiguration result - the pinned argv
runs the `vuln` scanner only, so another class in the output means the invocation drifted and the
parser fails loudly.

A line/item whose shape is not the pinned version (`SchemaVersion != 2`, no `Trivy.Version`, a
`Class` the pinned argv cannot produce, a result without packages and vulnerabilities) raises
`ParserInputError`: a corrupt or foreign file is a job error the runner quarantines, never a quietly
partial result. Malformed individual records (a package without a name, a vulnerability without an
id) are skipped and counted in `coverage.limitations`.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from adapters.artifact.purl import normalize_package_purl, purl_without_version

__all__ = ["ParserInputError", "RESULT_FILE", "parse"]

RESULT_FILE = "result.json"
#: `local_ref` of the raw file M06 stored and hands to the parser (collector evidence list).
RAW_REF = "raw"
#: One `docker-archive` file M06 writes into `/in` for `runtime.artifactSource: oci-archive`.
IMAGE_KEY_PREFIX = "oci:sha256:"
#: Trivy's JSON report schema this parser was written against.
SCHEMA_VERSION = 2
#: Result classes the pinned argv (`--scanners vuln`) can produce.
RESULT_CLASSES = frozenset({"os-pkgs", "lang-pkgs"})
#: Trivy result type -> purl type/namespace for an OS package whose `Identifier.PURL` is absent.
OS_PURLS = {
    "debian": ("deb", "debian"),
    "ubuntu": ("deb", "ubuntu"),
    "alpine": ("apk", "alpine"),
    "redhat": ("rpm", "redhat"),
    "centos": ("rpm", "centos"),
    "rocky": ("rpm", "rocky"),
    "alma": ("rpm", "alma"),
    "oracle": ("rpm", "oracle"),
    "amazon": ("rpm", "amazon"),
    "opensuse": ("rpm", "opensuse"),
    "suse": ("rpm", "suse"),
    "photon": ("rpm", "photon"),
}
SEVERITIES = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "unknown",
    "INFO": "info",
}
CVE_ID = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
CWE_ID = re.compile(r"^CWE-[0-9]+$")
GHSA_ID = re.compile(r"^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$")
TITLE_LIMIT = 500
DESCRIPTION_LIMIT = 20000
#: The scanner asserted the package is affected; M20 keeps the finding at CANDIDATE.
FINDING_CONFIDENCE = 0.9


class ParserInputError(ValueError):
    """The output does not have the shape this pinned tool version writes."""


def parse(output_dir: Path, task: dict[str, Any], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    """Map Trivy's image report in `output_dir` to assets, observations, relationships, findings."""
    document = _document(Path(output_dir))
    _check_tool(document, task)
    results = _results(document)
    image_key = _image_key(task)
    raw_refs = _raw_refs(evidence)

    packages: dict[str, dict[str, Any]] = {}
    findings: dict[tuple[str, str], dict[str, Any]] = {}
    limitations: list[dict[str, Any]] = []
    os_family = ""
    os_version = ""
    metadata = document.get("Metadata")
    if isinstance(metadata, dict):
        os_info = metadata.get("OS")
        if isinstance(os_info, dict):
            os_family = str(os_info.get("Family") or "")
            os_version = str(os_info.get("Name") or "")

    for result in results:
        package_class = str(result["Class"])
        package_type = str(result.get("Type") or "")
        for package in _records(result.get("Packages"), "Packages"):
            entry = _package(package, package_class, package_type, limitations)
            if entry is not None:
                packages.setdefault(entry["purl"], entry)
        for vulnerability in _records(result.get("Vulnerabilities"), "Vulnerabilities"):
            candidate = _candidate(
                vulnerability, package_class, package_type, packages, raw_refs, limitations
            )
            if candidate is not None:
                findings.setdefault((candidate["subject"], candidate["rule_id"]), candidate)

    assets: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    for purl in sorted(packages):
        entry = packages[purl]
        key = "purl:" + purl
        assets.append(
            {
                "kind": "package",
                "canonical_key": key,
                "attributes": {
                    "ecosystem": entry["ecosystem"],
                    "name": entry["name"],
                    "version": entry["version"],
                },
                "discovered_from": [image_key],
            }
        )
        observations.append(
            {
                "subject": key,
                "predicate": "package.installed",
                "value": {
                    "version": entry["version"],
                    "ecosystem": entry["ecosystem"],
                    **({"license": entry["license"]} if entry["license"] else {}),
                    **({"location": entry["location"]} if entry["location"] else {}),
                },
            }
        )
        observations.append({"subject": key, "predicate": "asset.seen", "value": True})
        relationships.append(
            {
                "type": "CONTAINS_PACKAGE",
                "from": image_key,
                "to": key,
                "confidence": 1.0,
            }
        )

    observations.insert(
        0,
        {
            "subject": image_key,
            "predicate": "artifact.digest",
            "value": image_key[len("oci:") :],
        },
    )
    observations.insert(
        1,
        {
            "subject": image_key,
            "predicate": "artifact.sbom",
            "value": {
                "format": "trivy-json",
                "schema_version": SCHEMA_VERSION,
                "tool": "trivy",
                "tool_version": _tool_version(document),
                "os_family": os_family,
                "os_version": os_version,
                "packages": len(packages),
                "vulnerabilities": sum(
                    len(result.get("Vulnerabilities") or ()) for result in results
                ),
            },
        },
    )

    return {
        "assets": assets,
        "observations": observations,
        "relationships": relationships,
        "findings": [findings[key] for key in sorted(findings)],
        "coverage_subjects": [image_key],
        "coverage": {"complete": True, **({"limitations": limitations} if limitations else {})},
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
    if document.get("SchemaVersion") != SCHEMA_VERSION:
        raise ParserInputError(
            f"{path}: SchemaVersion {document.get('SchemaVersion')!r} is not "
            f"{SCHEMA_VERSION}, this parser was written against Trivy's schema 2"
        )
    return document


def _tool_version(document: Mapping[str, Any]) -> str:
    tool = document.get("Trivy")
    if not isinstance(tool, dict) or not isinstance(tool.get("Version"), str):
        raise ParserInputError(
            "the report has no Trivy.Version, so the tool that wrote it is unknown"
        )
    return str(tool["Version"])


def _check_tool(document: Mapping[str, Any], task: Mapping[str, Any]) -> None:
    """A report from another tool build is a pin drift, never something to parse anyway."""
    found = _tool_version(document)
    pinned = str(task.get("provider_version") or "")
    if pinned and pinned.lstrip("v") != found:
        raise ParserInputError(
            f"the report was written by Trivy {found}, the accepted task pins {pinned}"
        )
    if not _results(document):
        raise ParserInputError("the report has no Results[] array")


def _results(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    results = document.get("Results")
    if results is None:
        return []
    if not isinstance(results, list):
        raise ParserInputError("Results is not an array")
    checked: list[dict[str, Any]] = []
    for index, result in enumerate(results):
        if not isinstance(result, dict):
            raise ParserInputError(f"Results[{index}] is not an object")
        package_class = result.get("Class")
        if package_class not in RESULT_CLASSES:
            raise ParserInputError(
                f"Results[{index}] has class {package_class!r}; the pinned invocation only "
                "enables the vulnerability scanner"
            )
        packages = result.get("Packages")
        vulnerabilities = result.get("Vulnerabilities")
        if packages is None and vulnerabilities is None:
            raise ParserInputError(f"Results[{index}] has neither Packages nor Vulnerabilities")
        if packages is not None and not isinstance(packages, list):
            raise ParserInputError(f"Results[{index}].Packages is not an array")
        if vulnerabilities is not None and not isinstance(vulnerabilities, list):
            raise ParserInputError(f"Results[{index}].Vulnerabilities is not an array")
        checked.append(result)
    return checked


def _records(items: Any, field: str) -> Iterable[dict[str, Any]]:
    if items is None:
        return ()
    if not isinstance(items, list):
        raise ParserInputError(f"{field} is not an array")
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise ParserInputError(f"{field}[{index}] is not an object")
    return items


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
    """The contract's evidence ref for the tool's report.

    Always `raw`: the collector names the file after its path (`result-json`), and M06 resolves
    this single top-level ref to that name once (interfaces §1, the same rule every adapter
    follows). The `evidence` argument is what the job carries; it is read only to keep the
    signature honest - a job with no raw file is refused by the integration, not guessed here.
    """
    del evidence
    return [{"local_ref": RAW_REF}]


# --------------------------------------------------------------------------- records


def _package(
    package: Mapping[str, Any],
    package_class: str,
    package_type: str,
    limitations: list[dict[str, Any]],
) -> dict[str, Any] | None:
    name = package.get("Name")
    version = package.get("Version")
    if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
        limitations.append(
            {
                "code": "TRIVY_PACKAGE_INCOMPLETE",
                "message": f"package {name!r} has no name/version; skipped (not an identity)",
            }
        )
        return None
    identifier = package.get("Identifier")
    purl = ""
    if isinstance(identifier, dict) and isinstance(identifier.get("PURL"), str):
        purl = str(identifier["PURL"])
    if not purl:
        purl = _os_purl(package_class, package_type, name, version)
        if not purl:
            limitations.append(
                {
                    "code": "TRIVY_PACKAGE_WITHOUT_PURL",
                    "message": (
                        f"package {name}@{version} of type {package_type!r} has no purl and the "
                        "type is not a known OS family"
                    ),
                }
            )
            return None
    normalized = normalize_package_purl(purl)
    if not normalized:
        limitations.append(
            {
                "code": "TRIVY_PACKAGE_WITHOUT_VERSION",
                "message": f"package {name!r} has no version in its purl; skipped",
            }
        )
        return None
    licenses = package.get("Licenses")
    location = package.get("FilePath")
    return {
        "purl": normalized,
        "name": name,
        "version": version,
        "ecosystem": normalized[4:].split("/", 1)[0],
        "license": ", ".join(str(item) for item in licenses) if isinstance(licenses, list) else "",
        "location": location if isinstance(location, str) and location else "",
    }


def _os_purl(package_class: str, package_type: str, name: str, version: str) -> str:
    if package_class != "os-pkgs":
        return ""
    mapped = OS_PURLS.get(package_type.lower())
    if mapped is None:
        return ""
    purl_type, namespace = mapped
    return f"pkg:{purl_type}/{namespace}/{name}@{version}"


def _candidate(
    vulnerability: Mapping[str, Any],
    package_class: str,
    package_type: str,
    packages: Mapping[str, dict[str, Any]],
    raw_refs: list[dict[str, str]],
    limitations: list[dict[str, Any]],
) -> dict[str, Any] | None:
    identifier = vulnerability.get("VulnerabilityID")
    if not isinstance(identifier, str) or not identifier:
        limitations.append(
            {
                "code": "TRIVY_VULNERABILITY_WITHOUT_ID",
                "message": "a vulnerability has no id; skipped",
            }
        )
        return None
    installed = vulnerability.get("InstalledVersion")
    identifier_block = vulnerability.get("PkgIdentifier")
    purl = ""
    if isinstance(identifier_block, dict) and isinstance(identifier_block.get("PURL"), str):
        purl = str(identifier_block["PURL"])
    if not purl:
        for entry in packages.values():
            if entry["name"] == vulnerability.get("PkgName") and entry["version"] == installed:
                purl = entry["purl"]
                break
    if not purl:
        name = vulnerability.get("PkgName")
        if isinstance(name, str) and isinstance(installed, str) and installed:
            purl = _os_purl(package_class, package_type, name, installed)
    if not purl:
        limitations.append(
            {
                "code": "TRIVY_VULNERABILITY_WITHOUT_PACKAGE",
                "message": (
                    f"vulnerability {identifier} names a package this report does not list "
                    "with a purl; its subject cannot be resolved"
                ),
            }
        )
        return None
    normalized = normalize_package_purl(purl)
    if not normalized:
        limitations.append(
            {
                "code": "TRIVY_VULNERABILITY_WITHOUT_VERSION",
                "message": f"vulnerability {identifier} has no installed version; skipped",
            }
        )
        return None
    rule_id = _rule_id(identifier)
    title = vulnerability.get("Title")
    description = vulnerability.get("Description")
    fixed = vulnerability.get("FixedVersion")
    severity = vulnerability.get("Severity")
    cwes = vulnerability.get("CweIDs")
    location: dict[str, Any] = {"package_purl": normalized}
    location["installed_version"] = (
        installed if isinstance(installed, str) and installed else normalized.rsplit("@", 1)[1]
    )
    if isinstance(fixed, str) and fixed:
        location["fixed_version"] = fixed
    candidate = {
        "subject": "purl:" + normalized,
        "rule_id": rule_id,
        "category": "vulnerability",
        "title": (
            f"{identifier}: {title}"
            if isinstance(title, str) and title
            else f"{identifier} in {normalized.rsplit('/', 1)[-1]}"
        )[:TITLE_LIMIT],
        "location": location,
        "vulnerability_ids": [identifier] if _vulnerability_id(identifier) else [],
        "cwe_ids": (
            [str(item) for item in cwes if CWE_ID.fullmatch(str(item))]
            if isinstance(cwes, list)
            else []
        ),
        "scanner_severity": SEVERITIES.get(str(severity).upper(), "unknown"),
        "fingerprint_context": {
            "package": purl_without_version(normalized),
            "installed_version": location["installed_version"],
        },
        "confidence": FINDING_CONFIDENCE,
        "evidence_refs": list(raw_refs),
    }
    if isinstance(description, str) and description:
        candidate["description"] = description[:DESCRIPTION_LIMIT]
    return candidate


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
        return CVE_ID.fullmatch(upper) is not None
    if upper.startswith("GHSA-"):
        return GHSA_ID.fullmatch(upper) is not None
    # Vendor advisories (ALAS-, DSA-, RHSA-, ...): `[A-Z]+-[A-Za-z0-9._:-]+` in the contract.
    return identifier[:1].isalpha() and "-" in identifier
