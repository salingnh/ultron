#!/usr/bin/env bash
# Regenerate SBOMs for the pinned images and print the facts the pin table needs.
# The pin table itself (pins/pin-table.json) is edited by hand after review:
# digests, release dates and license must be re-checked against upstream.
set -euo pipefail
cd "$(dirname "$0")/.."

: "${TRIVY:=trivy}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

refs=(
  "projectdiscovery/subfinder:sha256:2f5ddea311db2a8b848e40f1b669fc655d0eb78b74a74ead93d3850e372b12bf"
  "projectdiscovery/dnsx:sha256:8fced0bedf3655e06c9f1805f6277d60d4988a4b13209e24b3d7cde7baa656ec"
  "projectdiscovery/naabu:sha256:67c120a669954b768354197fc04328e08027898dc821bc8f276b3e26cd21f6aa"
  "blacklanternsecurity/bbot:sha256:40ed0733e0163feee844d49346eb15e40872fa7008f621358eed9b9a7807382e"
)

for ref in "${refs[@]}"; do
  name=${ref%%:*}; name=${name##*/}
  image="docker.io/${ref%%:*}@${ref#*:}"
  podman pull -q "$image"
  podman save -o "$WORK/$name.tar" "$image"
  "$TRIVY" image --input "$WORK/$name.tar" --format spdx-json \
    --output "sbom/$name-spdx.json" --quiet
  echo "sbom/$name-spdx.json $(sha256sum "sbom/$name-spdx.json" | cut -d' ' -f1)"
done

echo
echo "Upstream release dates and licenses must be verified separately, e.g.:"
echo "  curl -s https://api.github.com/repos/projectdiscovery/subfinder/releases?per_page=3 | jq -r '.[] | \"\\(.tag_name) \\(.published_at)\"'"
