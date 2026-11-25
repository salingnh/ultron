#!/usr/bin/env bash
# Removes compose project `aegis-vulnlab` only - its containers, its two networks, its stale one-shot
# probe containers and the rendered tunnel ingress. The external lab network `aegis-lab-lab` and
# anything else on the host are untouched.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_cmd podman
require_cmd podman-compose
load_images
load_env
load_ttl

log "compose project $VULNLAB_PROJECT: removing its containers and networks"
if [ -n "$(podman ps -a --filter "label=io.podman.compose.project=$VULNLAB_PROJECT" --format '{{.Names}}')" ] ||
  podman network inspect aegis-vulnlab-net >/dev/null 2>&1 ||
  podman network inspect aegis-vulnlab-egress >/dev/null 2>&1; then
  compose down --remove-orphans --timeout 20
else
  log "compose project $VULNLAB_PROJECT: nothing to remove"
fi

mapfile -t stale < <(podman ps -a --filter "label=$VULNLAB_LABEL" --format '{{.Names}}')
for name in "${stale[@]}"; do
  [ -n "$name" ] || continue
  log "removing stale probe container $name"
  podman rm -f "$name" >/dev/null
done

leftovers=$(
  podman ps -a --filter "label=io.podman.compose.project=$VULNLAB_PROJECT" --format 'container {{.Names}}'
  for network in aegis-vulnlab-net aegis-vulnlab-egress; do
    if podman network inspect "$network" >/dev/null 2>&1; then printf 'network %s\n' "$network"; fi
  done
)
if [ -n "$leftovers" ]; then
  printf '%s\n' "$leftovers" >&2
  die "compose project $VULNLAB_PROJECT left resources behind (listed above)"
fi

rm -rf "$TUNNEL_DIR" "$RUN_DIR/readiness.json"
log "compose project $VULNLAB_PROJECT: removed; the lab network and nothing else was touched"
