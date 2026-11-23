#!/usr/bin/env bash
# Download the pinned Temporal CLI into .tools/ and verify its sha256 (deploy/pins.json).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .tools
VERSION=1.10.0
TARBALL="temporal_cli_${VERSION}_linux_amd64.tar.gz"
SHA256=521f461f3d108902763bb71e85cd0fd382dc9357b59604ae03da6ae734d16890
if [ -x .tools/temporal ] && [ "$(.tools/temporal --version 2>/dev/null | head -1)" = "temporal version ${VERSION} (Server 1.32.2, UI 2.56.1)" ]; then
  echo "temporal ${VERSION} already present"
  exit 0
fi
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/$TARBALL" "https://github.com/temporalio/cli/releases/download/v${VERSION}/${TARBALL}"
echo "${SHA256}  $tmp/${TARBALL}" | sha256sum -c -
tar xzf "$tmp/$TARBALL" -C "$tmp" temporal
install -m 0755 "$tmp/temporal" .tools/temporal
.tools/temporal --version
