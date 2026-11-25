#!/usr/bin/env bash
# One command for the CVE test lab (G1.6 slice E): the known-vulnerable origins on
# `aegis-vulnlab-net` and on the authorized lab network, plus the optional Cloudflare Tunnel.
#
# Idempotent. It arms the podman `--timeout` on every container (VULNLAB_TTL_MINUTES, default 120),
# recreates the project if an existing container was created with a different TTL, and waits until
# every origin answers with the page the catalog documents - a container that is merely "up" is not
# ready (Jenkins takes tens of seconds).
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_cmd podman "install rootless podman 5.x"
require_cmd podman-compose "install with: python3 -m pip install --user podman-compose"
require_cmd python3
load_images
load_env
load_ttl
resolve_tunnel_token
require_rootless
require_lab_network

# The compose file cannot express --timeout (it is a podman run flag), so the compose hash does not
# change when the TTL does: rebuild explicitly instead of leaving a container with a stale/no TTL.
drifted=()
while IFS= read -r container; do
  [ -n "$container" ] || continue
  if [ "$(project_timeout "$container")" != "$VULNLAB_TTL_SECONDS" ]; then
    drifted+=("$container")
  fi
done < <(project_containers)
if ((${#drifted[@]} > 0)); then
  log "TTL drift on ${drifted[*]}: recreating the project so --timeout ${VULNLAB_TTL_SECONDS}s is armed"
  compose down --remove-orphans --timeout 20
fi

if tunnel_enabled; then
  # Remote-managed tunnel: the ingress lives in the Cloudflare dashboard, so there is nothing to
  # render or mount locally. deploy/vulnlab/cloudflared/config.yml.template is the documented
  # mirror of the dashboard rules; `make vulnlab-check PROFILE=internet` proves it serves.
  log "compose project $VULNLAB_PROJECT: starting with the Cloudflare Tunnel (ingress managed in the dashboard)"
else
  log "compose project $VULNLAB_PROJECT: starting lab-only (no tunnel token file)"
fi
log "auto-stop armed: every container stops after ${VULNLAB_TTL_MINUTES} min (podman --timeout ${VULNLAB_TTL_SECONDS}s)"

compose up -d

mkdir -p "$RUN_DIR"
log "waiting for every origin to serve its documented page (probe on $LAB_NETWORK)"
if ! python3 "$VULNLAB_SCRIPTS/check_live.py" --profile lab --wait 300 --json "$RUN_DIR/readiness.json"; then
  podman ps --filter "label=io.podman.compose.project=$VULNLAB_PROJECT" --format '  {{.Names}}  {{.Status}}' >&2
  die "the origins did not become ready; see the failures above and: make vulnlab-status"
fi

if tunnel_enabled; then
  log "waiting for the tunnel to serve the public hostnames (https from this machine)"
  if ! python3 "$VULNLAB_SCRIPTS/check_live.py" --profile internet --wait 180 \
    --json "$RUN_DIR/tunnel-readiness.json"; then
    die "the tunnel did not serve the public hostnames; see the failures above and: make vulnlab-status"
  fi
fi

"$VULNLAB_SCRIPTS/vulnlab-status.sh"
log "vulnlab is up - next: make vulnlab-check (disclosure) or make vulnlab-test PROFILE=lab"
