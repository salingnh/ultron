# Pin table (spike G0.2)

Rule: a tool release enters the internal registry only after 14 days (AGENTS.md). Verified 2026-11-24.

| Tool | Pinned version | Release date | Age (days) | Image digest | License | SBOM (packages) |
|---|---|---|---|---|---|---|
| subfinder | v2.17.0 | 2026-10-08 | 47 | `sha256:2f5ddea311db2a8b848e40f1b669fc655d0eb78b74a74ead93d3850e372b12bf` | MIT | [spdx](sbom/subfinder-spdx.json) (134) |
| dnsx | v1.2.2 | 2025-02-01 | 661 | `sha256:8fced0bedf3655e06c9f1805f6277d60d4988a4b13209e24b3d7cde7baa656ec` | MIT | [spdx](sbom/dnsx-spdx.json) (138) |
| bbot | v3.0.2 | 2026-08-24 | 92 | `sha256:40ed0733e0163feee844d49346eb15e40872fa7008f621358eed9b9a7807382e` | AGPL-3.0 | [spdx](sbom/bbot-spdx.json) (277) |
| naabu | v2.7.0 | 2026-10-28 | 27 | `sha256:67c120a669954b768354197fc04328e08027898dc821bc8f276b3e26cd21f6aa` | MIT | [spdx](sbom/naabu-spdx.json) (146) |

## Notes per pin

- **subfinder** (`docker.io/projectdiscovery/subfinder:v2.17.0`): Image built 2026-10-08; labels carry org.opencontainers.image.licenses=MIT.
- **dnsx** (`docker.io/projectdiscovery/dnsx:v1.2.2`): Docker Hub tag lags upstream: latest image tag is v1.2.2 (built 2025-02-01) even though the upstream repo released v1.3.0 (2026-07-16) and v1.3.1 (2026-08-31); no v1.3.x image exists, so the pin is v1.2.2. adapter_version/provider_version must record the gap and G1 must not claim v1.3 behaviour.
- **bbot** (`docker.io/blacklanternsecurity/bbot:3.0.2`): AGPL-3.0: run only as a separate container, never link into core; keep attribution. v3.1.0 (2026-11-12) is 12 days old on 2026-11-24, so the 14-day rule blocks it until 2026-11-26.
- **naabu** (`docker.io/projectdiscovery/naabu:v2.7.0`): Raw-socket test only. -s syn silently downgrades to CONNECT inside rootless Podman even with NET_RAW effective; -proxy takes host:port without a scheme.

## Rejected / deferred versions

- **bbot 3.1.0** (released 2026-11-12): 12 days old on 2026-11-24, blocked by the 14-day rule until 2026-11-26; Docker Hub 3.1.x tags are also `rc` builds.
- **dnsx v1.3.0/v1.3.1**: upstream only; building from source is out of G1 scope.

## SBOM

Generated with `trivy image --format spdx-json` over `podman save` tarballs of the pinned digests; one SPDX 2.3 document per image under `sbom/`, SHA-256 recorded in `pins/pin-table.json`. Regenerate with `scripts/pins.sh`.
