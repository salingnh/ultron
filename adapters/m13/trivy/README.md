# Adapter M13 — Trivy (`vuln.scan_artifact`)

- Capability: [`capabilities/vuln/scan-artifact.v2`](../../../contracts/capabilities/vuln/scan-artifact.v2.schema.json).
- Tool: Trivy **v0.76.2** (release 2026-11-05; Apache-2.0), upstream image `docker.io/aquasec/trivy`,
  unmodified, pinned by registry digest `sha256:8f6bb947…` in `manifest.yaml` and in
  `deploy/lab/images.env` (`AEGIS_LAB_TRIVY_IMAGE`). `sbom.cdx.json` is the CycloneDX inventory of
  that digest (413 components), produced by the pinned tool itself from a `podman save` of the
  image; it is the license/attribution record kept with the adapter, as every adapter package does.
- Run: `image --input /in/image.tar --cache-dir /cache --skip-db-update --skip-java-db-update
  --format json --output /out/result.json --scanners vuln --list-all-pkgs --quiet`, with
  `networkAccess: none`, `artifactSource: oci-archive` and 512 MiB of `/cache` scratch. The **image is
  never run**: M06 writes the campaign's digest into `/in/image.tar` from the runner's local image
  store and the scanner reads it as a file (no registry access, no container of the target image).
- Offline rule set: the vulnerability databases are a deployment dependency, not part of the image.
  `scripts/artifact/trivy-db.sh` downloads `trivy-db` + `trivy-java-db` once, writes them under
  `deploy/lab/.run/artifact/trivy-db/` and pins each file's SHA-256 plus the DB `UpdatedAt` in
  `deploy/lab/runner-profile.json`. M06 verifies those bytes before a container exists and writes the
  label into the accepted result's `coverage.rule_set` (`trivy-db@2026-11-28T01:04:49Z` in the lab),
  so a finding names the advisories behind it. A re-download is a `DEPENDENCY_MISSING`, never a
  silent new rule set.
- Parser: `adapters.m13.trivy.parser:parse` (stdlib only, no clock/network). Packages become
  `package` assets (`purl:` + the purl, qualifiers dropped, Debian epoch folded into the version -
  the same normalisation Syft/Grype use, `adapters/artifact/purl.py`), `package.installed` and
  `asset.seen` observations, and `CONTAINS_PACKAGE` edges from the image. Vulnerabilities become
  **finding candidates** (`rule_id = cve:<id>` or `advisory:<id>`, package subject, location with
  installed/fixed version, the raw JSON as evidence); M20 merges providers and decides the finding.
  The image's `artifact.digest`/`artifact.sbom` observations record what was scanned; the SBOM
  document itself is the raw evidence file.
- Not emitted, on purpose: `InstalledFiles`, layer ids, CVSS copies (M20 reads the intel
  catalogue), and any secret/misconfig result - the pinned argv runs only the `vuln` scanner, so
  another class in the output is an input error.
- Identity rule (learned on the lab image): Trivy's `Packages[].Version` is the **upstream** version
  for several Debian packages (`6.1+20181013` while `6.1+20181013-2+deb10u2` is installed), so the
  parser takes the version from the purl (the installed identity) and never from that field; the
  finding's `location.installed_version` keeps Trivy's own `InstalledVersion` for display.
- Fixture: `fixtures/lab/` is one real run over the digest-pinned `python:3.12-alpine`
  (`sha256:a61cbd76…`, 39 packages, 38 CVE candidates, 286 KB of JSON); `run.json` records the raw
  hash and the independent cross-check list `tests/fixtures/artifact/python-3.12-alpine.json`.
  Regenerate: run the manifest argv with the pinned DBs and the image tar, copy `result.json`, then
  re-run the parser to write `expected.json`.

## Pins and the 14-day rule

| Item | Pin | Released | Notes |
| --- | --- | --- | --- |
| Trivy image | `sha256:8f6bb947…` | 2026-11-05 | 23 days old when adopted; upstream image unmodified |
| `trivy-db` | `trivy-db@2026-11-28T01:04:49Z` (lab) | 2026-11-28 | deployment dependency, bytes pinned in the runner profile |
| `trivy-java-db` | `trivy-java-db@2026-11-28T07:57Z` (lab) | 2026-11-28 | needed for images that ship JARs; pinned the same way |

A new Trivy release is adopted by bumping `manifest.yaml` (digest + `providerVersion`), the contract
copy `contracts/fixtures/valid/manifest.trivy.yaml`, `deploy/lab/images.env`, the runner-profile
entry, and re-recording `fixtures/lab/` and `sbom.cdx.json` - all in one commit; the conformance
test fails on a digest that disagrees with the lab pin.
