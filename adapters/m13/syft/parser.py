"""Syft v1.57.1 parser: a CycloneDX SBOM -> packages, licenses and the SBOM record (G2-D, M13).

The core never imports a tool. M06 runs this function in the contained parser child named by the
pinned manifest (`parser.entrypoint: adapters.m13.syft.parser:parse`), so the module is stdlib-only
and has no clock, network, environment or database access:

    parse(output_dir, task, evidence) -> ParsedResults

It reads the CycloneDX JSON Syft writes for `scan docker-archive:/in/image.tar -o
cyclonedx-json=/out/sbom.json`: `bomFormat`/`specVersion`, `metadata.tools` (the tool and its
version), `metadata.component` (the image it analysed) and `components[]` (packages, binaries and
files).

Mapping (the manifest's `emits` block):

* the **image** is the job's signed target (`input.targets`), never the archive path or an image id
  from the SBOM: `artifact.digest` and `artifact.sbom` (format, spec version, tool, component and
  package counts) are observations on that asset. The image asset itself is the campaign seed;
* every component **with a purl** becomes a `package` asset (`purl:` + the normalized purl), a
  `package.installed` observation (version, ecosystem, license, first location) and an
  `asset.seen`; the image -> package `CONTAINS_PACKAGE` edge carries the evidence that the package
  is present in this image. Syft catalogs one component per *file* of a package, so the parser
  deduplicates by purl (httpd: 2 971 components -> 111 packages);
* Syft is SBOM-only: it emits **no findings**. The packages it lists are the independent inventory
  the vulnerability providers' findings attach to; M20 decides findings.

Identity: `adapters.artifact.purl` (qualifiers/subpath dropped, Debian epoch folded into the
version) is the same rule Trivy and Grype use, so one installed package is one asset across all
three tools. A component without a purl is not identity; a non-`file` component in that state is
counted in `coverage.limitations` instead of being guessed.

Not emitted: the per-file component explosion (`file` components without a purl), `syft:package:*`
properties (cataloger internals), and the SBOM document itself except as the raw evidence file.

A report whose `bomFormat` is not CycloneDX, whose tool is not the pinned Syft version, or whose
`components` is not an array raises `ParserInputError`: a foreign or truncated document is a job
error the runner quarantines, never a quietly smaller inventory.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from adapters.artifact.purl import normalize_package_purl

__all__ = ["ParserInputError", "RESULT_FILE", "parse"]

RESULT_FILE = "sbom.json"
IMAGE_KEY_PREFIX = "oci:sha256:"
BOM_FORMAT = "CycloneDX"
TITLE_LIMIT = 500
DESCRIPTION_LIMIT = 20000


class ParserInputError(ValueError):
    """The output does not have the shape this pinned tool version writes."""


def parse(output_dir: Path, task: dict[str, Any], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    """Map Syft's CycloneDX document in `output_dir` to assets, observations and relationships."""
    document = _document(Path(output_dir))
    tool_version = _check_tool(document, task)
    image_key = _image_key(task)
    components = _components(document)

    packages: dict[str, dict[str, Any]] = {}
    limitations: list[dict[str, Any]] = []
    seen_limitations: set[str] = set()

    def limit(code: str, message: str) -> None:
        # One entry per distinct message: Syft repeats the same purl-less component per file.
        if message in seen_limitations:
            return
        seen_limitations.add(message)
        limitations.append({"code": code, "message": message})

    for component in components:
        purl = component.get("purl")
        if not isinstance(purl, str) or not purl:
            # A file, binary or OS component without a purl is not a package identity; only a
            # `library` in that state is unexpected enough to report as a coverage limitation.
            if str(component.get("type") or "") == "library":
                limit(
                    "SYFT_COMPONENT_WITHOUT_PURL",
                    f"library component {component.get('name')!r} has no purl; not an identity",
                )
            continue
        normalized = normalize_package_purl(purl)
        if not normalized:
            limit(
                "SYFT_COMPONENT_WITHOUT_VERSION",
                f"component {component.get('name')!r} has no version in its purl",
            )
            continue
        entry = packages.setdefault(
            normalized,
            {
                "version": normalized.rsplit("@", 1)[-1],
                "ecosystem": normalized[4:].split("/", 1)[0],
                "license": "",
                "location": "",
            },
        )
        license_text = _license(component)
        if license_text and license_text not in entry["license"].split(", "):
            entry["license"] = ", ".join(filter(None, (entry["license"], license_text)))
        location = _location(component)
        if location and not entry["location"]:
            entry["location"] = location

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
                    "name": purl.rsplit("/", 1)[-1].split("@", 1)[0],
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
            {"type": "CONTAINS_PACKAGE", "from": image_key, "to": key, "confidence": 1.0}
        )

    observations.insert(
        0,
        {"subject": image_key, "predicate": "artifact.digest", "value": image_key[len("oci:") :]},
    )
    observations.insert(
        1,
        {
            "subject": image_key,
            "predicate": "artifact.sbom",
            "value": {
                "format": "cyclonedx",
                "spec_version": str(document.get("specVersion") or ""),
                "tool": "syft",
                "tool_version": tool_version,
                "components": len(components),
                "packages": len(packages),
            },
        },
    )
    return {
        "assets": assets,
        "observations": observations,
        "relationships": relationships,
        "findings": [],
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
    if document.get("bomFormat") != BOM_FORMAT:
        raise ParserInputError(
            f"{path}: bomFormat {document.get('bomFormat')!r} is not {BOM_FORMAT}; the pinned "
            "invocation writes a CycloneDX JSON SBOM"
        )
    if not isinstance(document.get("components"), list):
        raise ParserInputError(f"{path}: components is not an array")
    return document


def _check_tool(document: Mapping[str, Any], task: Mapping[str, Any]) -> str:
    metadata = document.get("metadata")
    tools = metadata.get("tools") if isinstance(metadata, dict) else None
    components = tools.get("components") if isinstance(tools, dict) else None
    if not isinstance(components, list):
        raise ParserInputError("the SBOM has no metadata.tools.components[]")
    for component in components:
        if isinstance(component, dict) and component.get("name") == "syft":
            found = component.get("version")
            if not isinstance(found, str):
                break
            pinned = str(task.get("provider_version") or "")
            if pinned and pinned.lstrip("v") != found:
                raise ParserInputError(
                    f"the SBOM was written by Syft {found}, the accepted task pins {pinned}"
                )
            return found
    raise ParserInputError("the SBOM does not name the Syft tool and its version")


def _components(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    components = document.get("components")
    if not isinstance(components, list):
        raise ParserInputError("components is not an array")
    for index, component in enumerate(components):
        if not isinstance(component, dict):
            raise ParserInputError(f"components[{index}] is not an object")
    return components


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


# --------------------------------------------------------------------------- components


def _license(component: Mapping[str, Any]) -> str:
    licenses = component.get("licenses")
    if not isinstance(licenses, list):
        return ""
    found: list[str] = []
    for entry in licenses:
        if not isinstance(entry, dict):
            continue
        license_block = entry.get("license")
        if isinstance(license_block, dict):
            value = license_block.get("id") or license_block.get("name")
        else:
            value = entry.get("expression")
        if isinstance(value, str) and value and value not in found:
            found.append(value)
    return ", ".join(found)


def _location(component: Mapping[str, Any]) -> str:
    properties = component.get("properties")
    if not isinstance(properties, list):
        return ""
    for item in properties:
        if not isinstance(item, dict):
            continue
        if item.get("name") == "syft:location:0:path" and isinstance(item.get("value"), str):
            return str(item["value"])
    return ""
