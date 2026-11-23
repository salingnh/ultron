#!/usr/bin/env bash
# podman-compose wrapper for compose project `aegis-dev`: loads .env and the image pins,
# then passes every argument through. Example: scripts/dev/compose.sh logs -f
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env
compose "$@"
