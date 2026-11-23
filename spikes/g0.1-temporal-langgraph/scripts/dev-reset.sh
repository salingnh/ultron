#!/usr/bin/env bash
# Clean slate: remove this spike's own container + volume, then recreate and migrate.
set -euo pipefail
cd "$(dirname "$0")/.."
scripts/dev-down.sh
scripts/dev-up.sh
