#!/usr/bin/env python3
"""`make demo-g2d` - the G2-D gate: one image, three tools, merged findings, nothing executed.

What it does, in the order an operator would:

1. takes the operator-supplied image digest from `deploy/lab/images.env` (the lab's own httpd
   target) and refuses to start unless that exact digest is in the local image store - no registry
   is contacted while a scan runs, and there is no fallback tag;
2. `POST /campaigns` with `targets: {images: [<digest>]}` and an objective that names the artifact:
   the scripted policy proposes the SBOM (Syft), then the vulnerability match (Trivy) and the
   independent corroboration (Grype), each on that same canonical key. The campaign runs through
   M02/M03/M05/M06 like any other;
3. asserts each job's sandbox from its own `run.json`: `network: none`, no egress mode, the target
   digest staged as `/in/image.tar`, the pinned scanner image, and **no container of the target
   image exists** in Podman (the image was read as a file, never run);
4. asserts the rule each verdict came from: Trivy's `coverage.rule_set` is `trivy-db@…` and
   Grype's is `grype-db@…`, both from the deployment's verified offline databases;
5. asserts what M27 recorded: Syft's and Trivy's SBOM/package inventory (one `package` asset per
   installed package, `CONTAINS_PACKAGE` from the image, `package.installed` per provider), the same
   rows in Neo4j, and at least one package reported by **all three** tools;
6. runs the M20 producers and asserts findings where **Trivy and Grype** report the same
   package+CVE: one finding, two `finding_source` rows, one fingerprint; `GET /findings` returns the
   same set with the provider list and evidence;
7. writes every number and the sample rows to `.local/demo/g2d-<timestamp>.json`.

Exit codes: 0 = every check passed, 1 = a check failed (the failing line is printed).
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

sys.path.insert(0, str(Path(__file__).resolve().parent))

import support  # noqa: E402 - the demo scripts' shared helpers, a sibling module

REPO = support.REPO
IMAGES_ENV = REPO / "deploy/lab/images.env"
OBJECTIVE = (
    "Analyse the container image artifact for this campaign: build its SBOM, list the installed "
    "packages and match the CVE candidates of those packages with independent scanners so the "
    "graph links the image to every package and finding"
)
CAMPAIGN_TIMEOUT = float(os.environ.get("G2D_CAMPAIGN_TIMEOUT") or 420.0)
#: provider -> (capability, scanner manifest) of the three artifact tools.
TOOLS = {
    "syft": ("sbom.generate", "adapters/m13/syft/manifest.yaml"),
    "trivy": ("vuln.scan_artifact", "adapters/m13/trivy/manifest.yaml"),
    "grype": ("vuln.scan_artifact", "adapters/m13/grype/manifest.yaml"),
}


def main(argv: list[str] | None = None) -> int:
    del argv
    support.load_demo_env()
    _require_environment()
    support.section("0. deployment pins")
    image = _image_reference()
    digest = _image_digest(image)
    support.line("image", image)
    support.line("profile", os.environ["AEGIS_M06_LAB_PROFILE"])
    _require_local_image(image)
    for provider, (_capability, manifest_path) in TOOLS.items():
        digest_pin, network_free = _scanner_pin(manifest_path)
        support.line(
            "scanner",
            provider,
            digest_pin[:23] + "…",
            "| networkAccess none" if network_free else "",
        )
        support.require(network_free, f"{provider}'s manifest is not network-free")
    pinned = _require_database_pins()
    support.line("rule sets", ", ".join(sorted(pinned.values())))

    support.section("1. campaign (POST /campaigns, image seed)")
    campaign_id = support.create_campaign(
        "G2-D artifact chain", OBJECTIVE, targets={"images": [digest]}
    )
    support.line("campaign_id", campaign_id)
    support.line("seed", "oci:" + digest)
    finished = support.wait_campaign(campaign_id, timeout_seconds=CAMPAIGN_TIMEOUT)
    status = str(finished.get("status"))
    support.line("status", status, "|", finished.get("status_reason") or "-")
    support.require(status == "COMPLETED", f"the campaign ended {status}, not COMPLETED")

    support.section("2. the artifact jobs and their sandboxes")
    connection = support.pg()
    try:
        jobs = support.rows(
            connection,
            "SELECT job_id, capability, provider, provider_version, status, envelope_event_id"
            "  FROM scan_job WHERE campaign_id = %s ORDER BY created_at",
            (campaign_id,),
        )
    finally:
        connection.close()
    for job in jobs:
        support.line("job", job["capability"], job["provider"], job["status"])
    support.require(len(jobs) == 3, f"expected three jobs, got {len(jobs)}")
    by_provider = {str(job["provider"]): job for job in jobs}
    support.require(set(by_provider) == set(TOOLS), f"providers are {sorted(by_provider)}")
    for provider, (capability, _manifest) in TOOLS.items():
        job = by_provider[provider]
        support.require(job["capability"] == capability, f"{provider} has the wrong capability")
        support.require(job["status"] == "SUCCEEDED", f"{provider} ended {job['status']}")
        support.require(job["envelope_event_id"] is not None, f"{provider} has no accepted result")
    sandboxes = {}
    for provider, job in by_provider.items():
        run = json.loads((REPO / ".local/m06/jobs" / str(job["job_id"]) / "run.json").read_text())
        sandbox = run.get("spec") or {}
        support.line(
            provider,
            "network",
            sandbox.get("network"),
            "| scratch",
            sandbox.get("scratch_mb"),
            "| image.tar",
            _size(
                (REPO / ".local/m06/jobs" / str(job["job_id"]) / "in" / "image.tar").stat().st_size
            ),
        )
        support.require(sandbox.get("network") == "none", f"{provider} had a network")
        support.require(sandbox.get("egress_mode") in {None, ""}, f"{provider} opened egress")
        support.require(
            sandbox.get("artifact_digest") == digest, f"{provider} staged another image"
        )
        expected, _network_free = _scanner_pin(TOOLS[provider][1])
        support.require(
            sandbox.get("image_digest") == expected, f"{provider} ran another scanner image"
        )
        archive = REPO / ".local/m06/jobs" / str(job["job_id"]) / "in" / "image.tar"
        support.require(archive.is_file() and archive.stat().st_size > 0, "no staged image")
        sandboxes[provider] = sandbox

    support.section("3. none of the tools ran the target image")
    support.line("containers from the target image", _count_target_containers(image))
    support.require(_count_target_containers(image) == 0, "a container of the target image exists")

    support.section("4. the rule each verdict came from")
    connection = support.pg()
    try:
        rule_sets = {
            str(row["provider"]): str((row["coverage"] or {}).get("rule_set") or "")
            for row in support.rows(
                connection,
                "SELECT j.provider, i.coverage FROM scan_job j"
                "  JOIN ingestion_inbox i ON i.event_id = j.envelope_event_id"
                " WHERE j.campaign_id = %s",
                (campaign_id,),
            )
        }
    finally:
        connection.close()
    for provider, label in sorted(rule_sets.items()):
        support.line("rule_set", provider, label or "-")
    support.require(rule_sets.get("trivy", "").startswith("trivy-db@"), "no Trivy DB identity")
    support.require(rule_sets.get("grype", "").startswith("grype-db@"), "no Grype DB identity")
    support.require(rule_sets.get("syft", "") == "", "an SBOM-only job claims a rule set")
    support.require(
        rule_sets["trivy"] != rule_sets["grype"], "both providers report the same DB identity"
    )
    for provider, label in rule_sets.items():
        support.require(pinned.get(provider, label) == label, f"{provider} rule set drifted")

    support.section("5. packages, SBOM and provider inventory (PostgreSQL)")
    connection = support.pg()
    try:
        image_asset = support.one(
            connection, "SELECT asset_id FROM asset WHERE canonical_key = %s", ("oci:" + digest,)
        )
        support.require(image_asset is not None, "the image seed is not an asset")
        image_id = str(cast(dict[str, Any], image_asset)["asset_id"])
        packages = {
            str(row["canonical_key"]): str(row["asset_id"])
            for row in support.rows(
                connection,
                "SELECT a.canonical_key, a.asset_id FROM asset a"
                "  JOIN asset_campaign ac ON ac.asset_id = a.asset_id"
                " WHERE ac.campaign_id = %s AND a.kind = 'package'",
                (campaign_id,),
            )
        }
        distribution = support.rows(
            connection,
            "SELECT providers, count(*) AS packages FROM ("
            "  SELECT subject_asset_id, count(DISTINCT provider) AS providers FROM observation"
            "   WHERE campaign_id = %s AND predicate = 'package.installed'"
            "   GROUP BY subject_asset_id) AS per_subject"
            " GROUP BY providers ORDER BY providers",
            (campaign_id,),
        )
        edges = support.count(
            connection,
            "SELECT count(*) FROM relationship r WHERE r.from_asset_id = %s"
            "   AND r.type = 'CONTAINS_PACKAGE' AND r.valid_to IS NULL",
            (image_id,),
        )
        sboms = support.rows(
            connection,
            "SELECT provider, value FROM observation"
            " WHERE campaign_id = %s AND predicate = 'artifact.sbom'",
            (campaign_id,),
        )
    finally:
        connection.close()
    support.line("packages", len(packages), "| CONTAINS_PACKAGE", edges)
    for row in distribution:
        support.line("providers per package", row["providers"], ":", row["packages"])
    support.line(
        "artifact.sbom",
        ", ".join(
            f"{row['provider']}:{cast(dict[str, Any], row['value']).get('tool')}"
            f"({cast(dict[str, Any], row['value']).get('packages')} packages)"
            for row in sboms
        ),
    )
    support.require(len(packages) >= 100, "the scan recorded implausibly few packages")
    support.require(edges == len(packages), "CONTAINS_PACKAGE does not cover every package")
    three = [row for row in distribution if int(row["providers"]) >= 3]
    support.require(
        bool(three) and int(three[-1]["packages"]) >= 50,
        "no package is reported by all three tools",
    )
    formats = {str(cast(dict[str, Any], row["value"]).get("format")) for row in sboms}
    support.require(
        {"cyclonedx", "trivy-json"} <= formats,
        f"the SBOM records are {sorted(formats)}, expected Syft's CycloneDX and Trivy's inventory",
    )

    support.section("6. the same rows in Neo4j")
    graph_packages = support.neo4j_query(
        "MATCH (img:Image {canonical_key: $key})-[:CONTAINS_PACKAGE]->(p:Package) "
        "RETURN count(p) AS n",
        key="oci:" + digest,
    )
    support.line("graph packages", graph_packages[0]["n"], "| edges", edges)
    support.require(int(graph_packages[0]["n"]) == len(packages), "Neo4j packages != PostgreSQL")
    graph_sboms = support.neo4j_query(
        "MATCH (o:Observation {predicate: 'artifact.sbom', subject: $subject}) "
        "RETURN count(o) AS n",
        subject="oci:" + digest,
    )
    support.line("graph artifact.sbom", graph_sboms[0]["n"])
    support.require(int(graph_sboms[0]["n"]) >= 2, "the SBOM records are not projected")

    support.section("7. findings (M20: same package+CVE from Trivy and Grype = one finding)")
    from aegis.m20_vuln.candidates import CandidateFindingsEngine
    from aegis.m20_vuln.findings import FindingsEngine
    from aegis.m20_vuln.matching import connect_from_env

    producer = connect_from_env()
    try:
        cpe_report = FindingsEngine(producer).run(campaign_id=campaign_id, assess=False)
        report = CandidateFindingsEngine(producer).run(campaign_id=campaign_id, assess=False)
    finally:
        producer.close()
    support.line(
        "producer",
        f"groups={report.groups} created={report.findings_created} sources={report.sources}"
        f" runs={report.runs} events={report.events} cpe={cpe_report.findings_created}",
    )
    support.require(report.groups > 0, "the scanner candidates raised no finding")
    support.require(report.sources > report.findings_created, "no finding has two providers")

    connection = support.pg()
    try:
        findings = support.rows(
            connection,
            "SELECT f.finding_id, f.rule_id, f.status, f.severity, f.asset_id,"
            "       array_agg(DISTINCT fs.provider) AS providers,"
            "       count(DISTINCT fs.scan_id) AS scans"
            "  FROM finding f JOIN finding_source fs ON fs.finding_id = f.finding_id"
            "  JOIN asset_campaign ac ON ac.asset_id = f.asset_id AND ac.campaign_id = %s"
            " GROUP BY f.finding_id ORDER BY f.rule_id",
            (campaign_id,),
        )
        finding_count = support.count(
            connection,
            "SELECT count(*) FROM finding f JOIN asset_campaign ac"
            " ON ac.asset_id = f.asset_id WHERE ac.campaign_id = %s",
            (campaign_id,),
        )
        multi = [row for row in findings if len(set(row["providers"])) >= 2]
        evidence = support.count(
            connection,
            "SELECT count(*) FROM finding_run fr"
            "  JOIN asset_campaign ac ON ac.asset_id = ("
            "        SELECT asset_id FROM finding WHERE finding_id = fr.finding_id)"
            " WHERE ac.campaign_id = %s AND fr.evidence_id IS NOT NULL",
            (campaign_id,),
        )
    finally:
        connection.close()
    support.line("findings", finding_count, "| with two real providers", len(multi))
    for row in multi[:3]:
        support.line("merged", row["rule_id"], row["providers"], f"({row['scans']} scans)")
    support.require(finding_count > 0, "no finding belongs to the campaign")
    support.require(bool(multi), "no finding is reported by both Trivy and Grype")
    support.require(evidence >= finding_count, "a finding has no evidence-bearing run")
    support.require(
        all(set(row["providers"]) <= {"trivy", "grype"} for row in findings),
        "a finding names a provider that did not scan the image",
    )
    package_ids = set(packages.values())
    support.require(
        all(str(row["asset_id"]) in package_ids for row in findings),
        "a finding does not belong to a package of this image",
    )

    support.section("8. GET /findings and the graph")
    page = support.api(
        "GET",
        f"/api/v2/findings?campaign_id={campaign_id}&limit=100",
        token=support.operator_token(),
    )
    items = cast(dict[str, Any], page).get("items") if isinstance(page, dict) else None
    support.require(isinstance(items, list), f"GET /findings answered {page!r}")
    rows = cast(list[dict[str, Any]], items)
    support.line("api findings", len(rows), "of", finding_count)
    support.require(len(rows) == min(finding_count, 100), "the API page is not the same set")
    for item in rows:
        support.require(item.get("evidence"), "a finding page row has no evidence")
    graph_findings = support.neo4j_query(
        "MATCH (p:Package)-[:HAS_FINDING]->(f:Finding) "
        "WHERE p.canonical_key STARTS WITH 'purl:' RETURN count(DISTINCT f) AS n"
    )
    support.line("graph findings", graph_findings[0]["n"])
    support.require(int(graph_findings[0]["n"]) >= min(len(rows), 1), "no package finding")

    support.section("9. evidence")
    directory = REPO / ".local/demo"
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = directory / f"g2d-{stamp}.json"
    path.write_text(
        json.dumps(
            {
                "campaign_id": campaign_id,
                "image": image,
                "digest": digest,
                "jobs": jobs,
                "sandboxes": sandboxes,
                "rule_sets": rule_sets,
                "packages": len(packages),
                "edges": edges,
                "providers_per_package": distribution,
                "sboms": sboms,
                "candidate_findings": report.as_dict(),
                "cpe_findings": cpe_report.as_dict(),
                "findings": [
                    {key: row[key] for key in ("finding_id", "rule_id", "providers", "scans")}
                    for row in findings
                ],
                "multi_provider_findings": len(multi),
            },
            indent=1,
            default=str,
        )
        + "\n",
        encoding="utf-8",
    )
    support.line("evidence file", path)

    print(
        "\nPASS - one image digest -> Syft SBOM + Trivy and Grype findings merged per "
        "package+CVE; no network, the image was never run"
    )
    return 0


# --------------------------------------------------------------------------- deployment pins


def _require_environment() -> None:
    required = ("AEGIS_API_URL", "AEGIS_PG_DSN", "AEGIS_OPERATOR_TOKEN", "AEGIS_M06_LAB_PROFILE")
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        support.fail(f"missing {', '.join(missing)}: run `make run-local` first")


def _images_env() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in IMAGES_ENV.read_text(encoding="utf-8").splitlines():
        name, separator, value = line.strip().partition("=")
        if separator and name.startswith("AEGIS_"):
            values[name] = value
    return values


def _image_reference() -> str:
    override = os.environ.get("G2D_IMAGE", "").strip()
    if override:
        return override
    value = _images_env().get("AEGIS_LAB_HTTPD_IMAGE", "")
    if not value:
        support.fail(f"{IMAGES_ENV} sets no AEGIS_LAB_HTTPD_IMAGE")
    return value


def _image_digest(image: str) -> str:
    return image.rsplit("@", 1)[-1]


def _scanner_pin(manifest_path: str) -> tuple[str, bool]:
    text = (REPO / manifest_path).read_text(encoding="utf-8")
    digest = ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("imageDigest:"):
            digest = stripped.split(":", 1)[1].strip()
            break
    support.require(bool(digest), f"{manifest_path} has no imageDigest")
    return digest, "networkAccess: none" in text


def _require_local_image(image: str) -> None:
    digest = _image_digest(image)
    listed = subprocess.run(
        ["podman", "images", "--format", "json"], capture_output=True, text=True
    )
    if listed.returncode != 0:
        support.fail(f"podman images failed: {listed.stderr.strip()[:500]}")
    for item in json.loads(listed.stdout or "[]"):
        if any(str(value).endswith("@" + digest) for value in item.get("RepoDigests") or ()):
            return
    support.fail(
        f"{image} is not in the local image store; the deployment must provide that exact digest "
        f"(M06 never pulls): podman pull {image}"
    )


def _require_database_pins() -> dict[str, str]:
    """Every manifest with `ruleSet: pinned` needs a mounted, verified deployment rule set."""
    profile = Path(os.environ["AEGIS_M06_LAB_PROFILE"])
    document = json.loads(profile.read_text(encoding="utf-8"))
    jobs = cast(list[dict[str, Any]], document.get("jobs") or [])
    labels: dict[str, str] = {}
    for provider, (_capability, manifest_path) in TOOLS.items():
        text = (REPO / manifest_path).read_text(encoding="utf-8")
        if "ruleSet: pinned" not in text:
            continue
        digest, _network_free = _scanner_pin(manifest_path)
        found = next((job for job in jobs if job.get("imageDigest") == digest), None)
        support.require(found is not None, f"{profile} has no entry for the {provider} image")
        entry = cast(dict[str, Any], found)
        pins = cast(list[dict[str, Any]], entry.get("pinnedInputs") or [])
        support.require(
            bool(pins) and any(pin.get("ruleSet") for pin in pins),
            f"{profile}: the {provider} entry has no pinned vulnerability DB; "
            "run `make lab-artifact-db`",
        )
        mounts = cast(list[dict[str, Any]], entry.get("mounts") or [])
        for pin in pins:
            source = next(
                (
                    mount.get("source")
                    for mount in mounts
                    if mount.get("target") == pin.get("target")
                ),
                None,
            )
            support.require(source is not None, f"{profile}: pin {pin['target']} has no mount")
            path = (profile.parent / str(source)).resolve() / str(pin["file"])
            support.require(path.is_file(), f"the pinned DB file {path} is missing")
            hasher = hashlib.sha256()
            with path.open("rb") as handle:
                for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
                    hasher.update(block)
            support.require(
                hasher.hexdigest() == pin["sha256"],
                f"{path} no longer matches its pin; re-run `make lab-artifact-db`",
            )
            support.line(
                "pin",
                provider,
                pin["target"],
                pin.get("ruleSet") or "-",
                f"({_size(path.stat().st_size)})",
            )
            if pin.get("ruleSet"):
                labels[provider] = str(pin["ruleSet"])
    support.require(set(labels) == {"trivy", "grype"}, f"pinned rule sets are {sorted(labels)}")
    return labels


def _count_target_containers(image: str) -> int:
    result = subprocess.run(
        ["podman", "ps", "-a", "--filter", f"ancestor={image}", "--format", "{{.Id}}"],
        capture_output=True,
        text=True,
    )
    return len([line for line in result.stdout.splitlines() if line.strip()])


def _size(value: int) -> str:
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{value} B"


if __name__ == "__main__":
    sys.exit(main())
