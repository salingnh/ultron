#!/usr/bin/env bash
# Removes this checkout's lab compose project only - its containers, network and (none today)
# volumes - plus stale one-shot run containers of that project, and the throwaway lab CA. The project
# is `aegis-lab` unless `AEGIS_LAB_PROJECT` names another one, and it must be this checkout's
# (scripts/lib/stack.sh); containers and networks of anything else on the machine are untouched.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_cmd podman
require_cmd podman-compose
load_images

# Removing the lab is as destructive as starting it: only this checkout's own project is removed
# (AEGIS_STACK_FORCE=1 for a lab known to be disposable).
require_lab_stack_ownership

log "compose project $LAB_PROJECT: removing its containers and network"
compose_project_resources=$(
  podman ps -a --filter "label=io.podman.compose.project=$LAB_PROJECT" --format '{{.Names}}'
  podman volume ls --filter "label=io.podman.compose.project=$LAB_PROJECT" --format '{{.Name}}'
)
if [ -n "$compose_project_resources" ] || podman network inspect "$LAB_NETWORK" >/dev/null 2>&1; then
  compose down --remove-orphans --timeout 20
else
  log "compose project $LAB_PROJECT: nothing to remove"
fi

mapfile -t stale < <(podman ps -a --filter "label=$RUN_LABEL" --format '{{.Names}}')
for name in "${stale[@]}"; do
  [ -n "$name" ] || continue
  log "removing stale run container $name"
  podman rm -f "$name" >/dev/null
done

leftovers=$(
  podman ps -a --filter "label=io.podman.compose.project=$LAB_PROJECT" --format 'container {{.Names}}'
  podman volume ls --filter "label=io.podman.compose.project=$LAB_PROJECT" --format 'volume {{.Name}}'
  if podman network inspect "$LAB_NETWORK" >/dev/null 2>&1; then printf 'network %s\n' "$LAB_NETWORK"; fi
)
if [ -n "$leftovers" ]; then
  printf '%s\n' "$leftovers" >&2
  die "compose project $LAB_PROJECT left resources behind (listed above)"
fi

rm -rf "$TLS_DIR"
rm -f "$LAB_IDENTITY"
log "compose project $LAB_PROJECT: removed; nothing outside the project was touched"
