#!/usr/bin/env bash
# Remove only this spike's container and data volume.
set -euo pipefail
cd "$(dirname "$0")/.."
podman rm -f g01-spike-postgres >/dev/null 2>&1 || true
podman volume rm -f g01-spike-pgdata >/dev/null 2>&1 || true
echo "g01-spike-postgres + g01-spike-pgdata removed"
