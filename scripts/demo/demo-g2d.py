#!/usr/bin/env python3
"""`make demo-g2d` - the G2-D gate: an image campaign -> packages, SBOM and findings, no execution.

What it does, in the order an operator would:

1. takes the operator-supplied image digest from `deploy/lab/images.env` (the lab's own httpd
   target) and refuses to start unless that exact digest is in the local image store - no registry
   is contacted while a scan runs, and there is no fallback tag;
2. `POST /campaigns` with `targets: {images: [<digest>]}` and an objective that names the artifact:
   the scripted policy reads the image seed from the context bundle and proposes
   `vuln.scan_artifact` (Trivy) with that canonical key. The campaign runs through M02/M03/M05/M06
   like any other;
3. asserts the job's sandbox from its own `run.json`: `network: none`, no egress mode, the target
   digest staged as `/in/image.tar`, the scanner image is the pinned Trivy one, and **no container
   of the target image exists** in Podman (the image was read as a file, never run);
4. asserts what M27 recorded: the image's `artifact.digest`/`artifact.sbom` observations, one
   `package` asset per installed package with `CONTAINS_PACKAGE` edges from the image, and the same
   rows in Neo4j;
5. runs the M20 producers (CPE matching + the scanner-candidate pass) and asserts one finding per
   (package, CVE) with `provider = trivy`, evidence attached, and the `GET /findings` page carrying
   the same rows with the provider list;
6. checks the rule set the scan used is the deployment's pinned one (`coverage.rule_set` on the
   accepted result: `trivy-db@<UpdatedAt>`), so a finding names the advisories behind it;
7. writes every number and the raw rows it printed to `.local/demo/g2d-<timestamp>.json`.

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
PROFILE = REPO / "deploy/lab/runner-profile.json"
OBJECTIVE = (
    "Analyse the container image artifact for this campaign: build its SBOM, list the installed "
    "packages and match the CVE candidates of those packages so the graph links the image to every "
    "package and finding"
)
CAMPAIGN_TIMEOUT = float(os.environ.get("G2D_CAMPAIGN_TIMEOUT") or 300.0)


def main(argv: list[str] | None = None) -> int:
    del argv
    support.load_demo_env()
    _require_environment()
    support.section("0. deployment pins")
    image = _image_reference()
    digest = image.rsplit("@", 1)[-1]
    support.line("image", image)
    support.line("profile", os.environ["AEGIS_M06_LAB_PROFILE"])
    _require_local_image(image)
    _require_database_pins()
    _require_scanner_pin()

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

    support.section("2. the artifact job and its sandbox")
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
    support.require(len(jobs) == 1, f"expected one job, got {len(jobs)}")
    job = jobs[0]
    support.require(job["capability"] == "vuln.scan_artifact", "the job is not the artifact scan")
    support.require(job["provider"] == "trivy", "the job's provider is not trivy")
    support.require(job["status"] == "SUCCEEDED", f"the job ended {job['status']}")
    support.require(job["envelope_event_id"] is not None, "the job has no accepted result")

    run = json.loads((REPO / ".local/m06/jobs" / str(job["job_id"]) / "run.json").read_text())
    sandbox = run.get("spec") or {}
    support.line("network", sandbox.get("network"), "| egress_mode", sandbox.get("egress_mode"))
    support.require(sandbox.get("network") == "none", "the job had a network")
    support.require(sandbox.get("egress_mode") in {None, ""}, "the job opened an egress channel")
    support.require(sandbox.get("artifact_digest") == digest, "the job staged another image")
    support.require(
        sandbox.get("image_digest")
        == "sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb",
        "the scanner container is not the pinned Trivy image",
    )
    archive = REPO / ".local/m06/jobs" / str(job["job_id"]) / "in" / "image.tar"
    support.require(archive.is_file() and archive.stat().st_size > 0, "the image was not staged")
    support.line("staged", "image.tar", _size(archive.stat().st_size))
    assert_no_target_container(image)

    support.section("3. the image was never run")
    support.line("containers from the target image", _count_target_containers(image))
    support.require(_count_target_containers(image) == 0, "a container of the target image exists")
    support.require(
        "image" in str(sandbox.get("args", [])) and "--input" in str(sandbox.get("args", [])),
        "the scanner argv is not the file-based image scan",
    )

    support.section("4. packages, SBOM and observations (PostgreSQL)")
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
        observations = {
            str(row["predicate"]): row["value"]
            for row in support.rows(
                connection,
                "SELECT predicate, value FROM observation"
                " WHERE campaign_id = %s AND subject_asset_id = %s AND polarity = 'present'"
                "   AND predicate IN ('artifact.digest', 'artifact.sbom')",
                (campaign_id, image_id),
            )
        }
        installed = support.count(
            connection,
            "SELECT count(*) FROM observation WHERE campaign_id = %s"
            " AND predicate = 'package.installed'",
            (campaign_id,),
        )
        # One edge per installed package, owned by whichever scan saw it first: the graph is
        # asset identity, not campaign identity, so the edge is counted from the image, not by
        # `relationship.campaign_id` (a second campaign reuses the existing edge).
        edges = support.count(
            connection,
            "SELECT count(*) FROM relationship r"
            " WHERE r.from_asset_id = %s AND r.type = 'CONTAINS_PACKAGE'"
            "   AND r.valid_to IS NULL",
            (image_id,),
        )
        coverage = support.one(
            connection,
            "SELECT coverage FROM ingestion_inbox i JOIN scan_job j"
            " ON j.envelope_event_id = i.event_id WHERE j.job_id = %s",
            (job["job_id"],),
        )
    finally:
        connection.close()
    support.line("packages", len(packages), "| package.installed", installed)
    support.line("artifact.digest", observations.get("artifact.digest"))
    sbom = cast(dict[str, Any], observations.get("artifact.sbom") or {})
    support.line("artifact.sbom", json.dumps(sbom, sort_keys=True))
    coverage_document = coverage["coverage"] if coverage is not None else None
    support.line("coverage", json.dumps(coverage_document, sort_keys=True))
    support.require(len(packages) >= 10, "the scan recorded implausibly few packages")
    support.require(installed == len(packages), "not every package has an installed observation")
    support.require(edges == len(packages), "CONTAINS_PACKAGE does not cover every package")
    support.require(sbom.get("tool") == "trivy", "the SBOM observation does not name the tool")
    support.require(
        sbom.get("packages") == len(packages), "the SBOM count disagrees with the assets"
    )
    coverage_document = coverage_document or {}
    support.require(
        str(coverage_document.get("complete")).lower() == "true",
        "the accepted result does not claim complete coverage",
    )
    rule_set = str(coverage_document.get("rule_set") or "")
    support.line("rule_set", rule_set)
    support.require(
        rule_set.startswith("trivy-db@"), "the result carries no pinned vulnerability DB identity"
    )

    support.section("5. the same rows in Neo4j")
    graph_packages = support.neo4j_query(
        "MATCH (img:Image {canonical_key: $key})-[:CONTAINS_PACKAGE]->(p:Package) "
        "RETURN count(p) AS n",
        key="oci:" + digest,
    )
    support.line("graph packages", graph_packages[0]["n"], "| edges", edges)
    support.require(int(graph_packages[0]["n"]) == len(packages), "Neo4j packages != PostgreSQL")
    # `artifact.sbom` is a graph predicate in the registry; `artifact.digest` is not (the digest
    # is already the image's key), so only the SBOM inventory is expected as an :Observation.
    found = support.neo4j_query(
        "MATCH (o:Observation {predicate: 'artifact.sbom', subject: $subject}) "
        "RETURN count(o) AS n",
        subject="oci:" + digest,
    )
    support.line("graph", "artifact.sbom", found[0]["n"])
    support.require(int(found[0]["n"]) >= 1, "artifact.sbom is not projected")

    support.section("6. findings (M20: scanner candidates -> one finding per package+CVE)")
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
    support.require(
        report.findings_created + report.findings_existing > 0,
        "the scanner candidates raised no finding",
    )
    support.require(report.sources > 0, "the new scan added no finding_source row")

    connection = support.pg()
    try:
        findings = support.rows(
            connection,
            "SELECT f.finding_id, f.rule_id, f.status, f.severity, f.asset_id,"
            "       array_agg(DISTINCT fs.provider) AS providers,"
            "       count(DISTINCT fs.scan_id) AS scans,"
            "       (f.first_campaign_id = %s) AS same_campaign"
            "  FROM finding f JOIN finding_source fs ON fs.finding_id = f.finding_id"
            "  JOIN asset_campaign ac ON ac.asset_id = f.asset_id AND ac.campaign_id = %s"
            " GROUP BY f.finding_id ORDER BY f.rule_id",
            (campaign_id, campaign_id),
        )
        finding_count = support.count(
            connection,
            "SELECT count(*) FROM finding f JOIN asset_campaign ac"
            " ON ac.asset_id = f.asset_id WHERE ac.campaign_id = %s",
            (campaign_id,),
        )
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
    support.line("findings", finding_count, "| with evidence runs", evidence)
    for row in findings[:3]:
        support.line("finding", row["rule_id"], row["status"], row["providers"])
    support.require(finding_count > 0, "no finding belongs to the campaign")
    # Runs accumulate per scan: a demo re-run adds one evidence-bearing run per finding.
    support.require(evidence >= finding_count, "a finding has no evidence-bearing run")
    support.require(
        all("trivy" in set(row["providers"]) for row in findings),
        "a finding does not name Trivy as a source",
    )
    package_ids = set(packages.values())
    support.require(
        all(str(row["asset_id"]) in package_ids for row in findings),
        "a finding does not belong to a package of this image",
    )

    support.section("7. GET /findings and the graph")
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
        support.require(
            "trivy" in item.get("providers", []), "a finding page row lost the provider"
        )
        support.require(item.get("evidence"), "a finding page row has no evidence")
    graph_findings = support.neo4j_query(
        "MATCH (p:Package)-[:HAS_FINDING]->(f:Finding) "
        "WHERE p.canonical_key STARTS WITH 'purl:' RETURN count(DISTINCT f) AS n"
    )
    support.line("graph findings", graph_findings[0]["n"])
    support.require(
        int(graph_findings[0]["n"]) >= min(len(rows), 1),
        "the graph has no package finding",
    )

    support.section("8. evidence")
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
                "job": job,
                "sandbox": sandbox,
                "packages": len(packages),
                "edges": edges,
                "rule_set": rule_set,
                "candidate_findings": report.as_dict(),
                "cpe_findings": cpe_report.as_dict(),
                "findings": [
                    {key: row[key] for key in ("finding_id", "rule_id", "providers", "scans")}
                    for row in findings
                ],
            },
            indent=1,
            default=str,
        )
        + "\n",
        encoding="utf-8",
    )
    support.line("evidence file", path)

    print(
        "\nPASS - image campaign -> packages, SBOM, findings with provider list; "
        "no network, the image was never run"
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


def _require_database_pins() -> None:
    profile = Path(os.environ["AEGIS_M06_LAB_PROFILE"])
    document = json.loads(profile.read_text(encoding="utf-8"))
    scanner = "sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb"
    entry = next(
        (job for job in document.get("jobs") or [] if job.get("imageDigest") == scanner), None
    )
    support.require(entry is not None, f"{profile} has no entry for the Trivy image")
    job_entry = cast(dict[str, Any], entry)
    pins = cast(list[dict[str, Any]], job_entry.get("pinnedInputs") or [])
    support.require(
        bool(pins) and any(pin.get("ruleSet") for pin in pins),
        f"{profile}: the Trivy entry has no pinned vulnerability DB; "
        "run scripts/artifact/trivy-db.sh",
    )
    mounts = cast(list[dict[str, Any]], job_entry.get("mounts") or [])
    for pin in pins:
        source = next(
            (mount.get("source") for mount in mounts if mount.get("target") == pin.get("target")),
            None,
        )
        support.require(source is not None, f"{profile}: pin {pin['target']} has no mount")
        path = (profile.parent / str(source)).resolve() / str(pin["file"])
        support.require(path.is_file(), f"the pinned DB file {path} is missing")
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
                digest.update(block)
        support.require(
            digest.hexdigest() == pin["sha256"],
            f"{path} no longer matches its pin; re-run scripts/artifact/trivy-db.sh",
        )
        support.line(
            "pin", pin["target"], pin.get("ruleSet") or "-", f"({_size(path.stat().st_size)})"
        )


def _require_scanner_pin() -> None:
    manifest = (REPO / "adapters/m13/trivy/manifest.yaml").read_text(encoding="utf-8")
    support.require("imageDigest: sha256:" in manifest, "the Trivy manifest has no image digest")
    support.require("networkAccess: none" in manifest, "the Trivy manifest is not network-free")


def _count_target_containers(image: str) -> int:
    result = subprocess.run(
        ["podman", "ps", "-a", "--filter", f"ancestor={image}", "--format", "{{.Id}}"],
        capture_output=True,
        text=True,
    )
    return len([line for line in result.stdout.splitlines() if line.strip()])


def assert_no_target_container(image: str) -> None:
    support.require(
        _count_target_containers(image) == 0,
        f"a container of the target image exists: the image was run ({image})",
    )


def _size(value: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value = int(value / 1024)
    return f"{value} B"


if __name__ == "__main__":
    sys.exit(main())
