#!/usr/bin/env bash
# One command for the G0.4a dev environment: PostgreSQL 18, Neo4j 5.26, SeaweedFS (S3) and
# Temporal with its persistence, all from digest-pinned images, followed by the contract
# migrations, the graph constraints and the raw/evidence bucket with Object Lock.
#
# Idempotent: run it again on a running stack and it only applies what is missing.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_cmd podman "install rootless podman 5.x"
require_cmd podman-compose "install with: python3 -m pip install --user podman-compose"
require_cmd curl
require_cmd sha256sum

if [ ! -f "$ENV_FILE" ]; then
  cp "$ENV_EXAMPLE" "$ENV_FILE"
  # .env is the one file that holds secrets (model keys, gateway upstream keys): private from the
  # first write, never after a key was already in it.
  chmod 600 "$ENV_FILE"
  log "created .env from .env.example (local dev values, git-ignored, mode 600)"
fi
load_env

if ! podman info --format '{{.Host.Security.Rootless}}' | grep -qx true; then
  die "podman is not rootless; the dev stack must run as the current user"
fi

check_dev_ports_free

# A project on this host belongs to the checkout that created it: another worker's `make dev-up`
# must not recreate the owner's containers (that is the incident scripts/lib/stack.sh describes).
require_dev_stack_ownership

log "compose project $DEV_PROJECT: starting"
compose up -d

wait_healthy 300 "$PG_CONTAINER" "$SEAWEEDFS_CONTAINER" "$NEO4J_CONTAINER" "$TEMPORAL_CONTAINER"
record_dev_stack_identity

"$DEV_DIR/apply-schema.sh"
"$DEV_DIR/dev-status.sh"
