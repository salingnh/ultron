# Adapter M13 — Grype (`vuln.scan_artifact`)

- Capability: [`capabilities/vuln/scan-artifact.v2`](../../../contracts/capabilities/vuln/scan-artifact.v2.schema.json)
  (the same capability Trivy serves: the request names the provider, and M20 merges the findings).
- Tool: Grype **v0.121.3** (release 2026-11-09; Apache-2.0), upstream image `docker.io/anchore/grype`,
  unmodified, pinned by registry digest `sha256:13113eec…` in `manifest.yaml` and in
  `deploy/lab/images.env` (`AEGIS_LAB_GRYPE_IMAGE`). `sbom.cdx.json` is the CycloneDX inventory of
  that digest, produced by the pinned Syft tool; it is the license/attribution record.
- Run: `docker-archive:/in/image.tar -o json=/out/result.json -q`, with `networkAccess: none`,
  `artifactSource: oci-archive`, 1024 MiB of `/cache` scratch (`TMPDIR`; Grype unpacks layers) and
  the offline database mounted read-only at `/db` (`GRYPE_DB_CACHE_DIR=/db`,
  `GRYPE_DB_AUTO_UPDATE=false`, `GRYPE_DB_VALIDATE_AGE=false`). The image is never run and no
  registry/DB update is contacted.
- Offline rule set: `scripts/artifact/grype-db.sh` downloads the Grype DB once, pins the sha256 of
  `6/vulnerability.db` and its build time (`grype-db@<built>`) in `deploy/lab/runner-profile.json`;
  M06 verifies the file before a container exists (`DEPENDENCY_MISSING` on drift) and the parser
  records the same label from the tool's own report in `coverage.rule_set`. A re-download is a
  deployment action, never a silent rule-set change.
- Parser: `adapters.m13.grype.parser:parse` (stdlib only). Every match's artifact becomes a
  `package` asset (`purl:` + the shared normalizer), `package.installed`, `asset.seen`, the
  `CONTAINS_PACKAGE` edge and a **finding candidate**: `rule_id = cve:<id>` (or `advisory:<id>`),
  subject the package, location = package identity + installed/fixed version, scanner severity as a
  signal, the raw JSON as evidence. M20 decides the finding, status and severity; a match with the
  same package+CVE as Trivy merges into one finding with one `finding_source` row per provider.
- Not emitted: Grype's copied CVSS/EPSS/KEV values (M20 reads the intel catalogue), matcher
  internals, and artifacts without a purl (a coverage limitation, never a guessed identity).
- Fixture: `fixtures/lab/` is one real offline run over `python:3.12-alpine`
  (`sha256:a61cbd76…`, 79 matches -> 10 package assets), same image as the Trivy/Syft fixtures;
  `run.json` records the raw hash and the independent cross-check
  `tests/fixtures/artifact/python-3.12-alpine-grype.json`. On that image Trivy and Grype report the
  same package+CVE for 32 pairs, which `tests/test_candidate_findings.py` proves through M27 and
  the M20 engine.

## Pins

| Item | Pin | Released | Notes |
| --- | --- | --- | --- |
| Grype image | `sha256:13113eec…` | 2026-11-09 | 19 days old when adopted; upstream image unmodified |
| Grype DB | `grype-db@2026-11-27T06:22:11Z` (lab) | DB build 2026-11-27 | deployment dependency; file sha256 pinned in the runner profile |

A new release is adopted by bumping the manifest (digest + `providerVersion`), the contract copy,
`deploy/lab/images.env`, the runner-profile entry and re-recording `fixtures/lab/` + `sbom.cdx.json`
in one commit; a new DB is `make lab-artifact-db`, which rewrites the pin.
