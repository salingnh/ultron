#!/usr/bin/env bash
# Removes the dev stack - containers, network and named volumes of compose project
# `aegis-dev` only - and verifies nothing of that project is left behind.
# Containers, volumes and databases of anything else on the machine are untouched.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_cmd podman
require_cmd podman-compose

if [ ! -f "$ENV_FILE" ]; then
  cp "$ENV_EXAMPLE" "$ENV_FILE"
  # .env is the one file that holds secrets (model keys, gateway upstream keys): private from the
  # first write, never after a key was already in it.
  chmod 600 "$ENV_FILE"
  log "created .env from .env.example so the compose file can be resolved (mode 600)"
fi
load_env

# Removing a stack is as destructive as starting one: only this checkout's own project is removed
# (AEGIS_STACK_FORCE=1 for a stack known to be disposable, scripts/lib/stack.sh).
require_dev_stack_ownership

log "compose project $DEV_PROJECT: stopping and removing its containers and volumes"
compose down --volumes --remove-orphans --timeout 30

leftovers=$(
  podman ps -a --filter "label=io.podman.compose.project=$DEV_PROJECT" --format '{{.Names}}'
  podman volume ls --filter "label=io.podman.compose.project=$DEV_PROJECT" --format 'volume {{.Name}}'
  podman volume ls --format '{{.Name}}' | grep -E "^${DEV_PROJECT}[_-]" | sed 's/^/volume /' || true
)
if [ -n "$leftovers" ]; then
  printf '%s\n' "$leftovers" >&2
  die "compose project $DEV_PROJECT left resources behind (listed above)"
fi

rm -f "$STACK_IDENTITY"
log "compose project $DEV_PROJECT: removed; nothing outside the project was touched"
