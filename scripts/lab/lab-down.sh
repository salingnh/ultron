#!/usr/bin/env bash
# Removes compose project `aegis-lab` only - its containers, network and (none today)
# volumes - plus stale one-shot run containers labelled `aegis.lab=aegis-lab-run`, and the
# throwaway lab CA. Containers and networks of anything else on the machine are untouched.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_cmd podman
require_cmd podman-compose
load_images

log "compose project $LAB_PROJECT: stopping and removing its containers and network"
compose down --remove-orphans --timeout 20

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
log "compose project $LAB_PROJECT: removed; nothing outside the project was touched"
