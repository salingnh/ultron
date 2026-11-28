# Adapter M13 — Syft (`sbom.generate`)

- Capability: [`capabilities/sbom/generate.v2`](../../../contracts/capabilities/sbom/generate.v2.schema.json).
- Tool: Syft **v1.57.1** (release 2026-11-09; Apache-2.0), upstream image `docker.io/anchore/syft`,
  unmodified, pinned by registry digest `sha256:03215d0e…` in `manifest.yaml` and in
  `deploy/lab/images.env` (`AEGIS_LAB_SYFT_IMAGE`). `sbom.cdx.json` is the CycloneDX inventory of
  that digest, produced by the pinned tool itself; it is the license/attribution record kept with
  the adapter.
- Run: `scan docker-archive:/in/image.tar -o cyclonedx-json=/out/sbom.json -q`, with
  `networkAccess: none`, `artifactSource: oci-archive` and 1024 MiB of `/cache` scratch (Syft
  unpacks image layers under `TMPDIR` and caches under `SYFT_CACHE_DIR`; the profile sets both to
  `/cache`). The **image is never run**: M06 writes the campaign's digest into `/in/image.tar` from
  the runner's local image store and Syft reads it as a file (no registry, no container of the
  target image, no vulnerability database).
- Parser: `adapters.m13.syft.parser:parse` (stdlib only, no clock/network). Every CycloneDX
  component with a purl becomes a `package` asset (`purl:` + the normalized purl, the same rule as
  Trivy/Grype), a `package.installed` observation (version, ecosystem, license, first path), an
  `asset.seen`, and a `CONTAINS_PACKAGE` edge from the image; the image gets `artifact.digest` and
  an `artifact.sbom` record (format, spec version, tool, component and package counts). Syft
  produces **no findings**: its packages are the independent inventory the vulnerability
  providers' findings attach to.
- Syft catalogs one component per *file* (httpd: 2 971 components for 111 packages), so the parser
  deduplicates by purl; components without a purl (`file`, binary, OS) are not identities and are
  not invented. A `library` without a purl, a versionless purl, a foreign `bomFormat` or another
  Syft version fails loudly or is counted in `coverage.limitations`.
- Fixture: `fixtures/lab/` is one real run over the digest-pinned `python:3.12-alpine`
  (`sha256:a61cbd76…`, 937 components -> 40 packages); `run.json` records the raw hash and the
  independent cross-check `tests/fixtures/artifact/python-3.12-alpine-syft.json`.

## Pins

| Item | Pin | Released | Notes |
| --- | --- | --- | --- |
| Syft image | `sha256:03215d0e…` | 2026-11-09 | 19 days old when adopted; upstream image unmodified; no DB |

A new release is adopted by bumping the manifest (digest + `providerVersion`), the contract copy,
`deploy/lab/images.env`, the runner-profile entry and re-recording `fixtures/lab/` + `sbom.cdx.json`
in one commit; the conformance suite fails on a digest that disagrees with the lab pin.
