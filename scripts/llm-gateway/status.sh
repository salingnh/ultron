#!/usr/bin/env bash
# What the gateway is doing right now: `make llm-gateway-status`.
#
# Container state, readiness, the model groups ultron may ask for, and - per endpoint - whether it is
# healthy or cooling down (and how often it was cooled, from the proxy's own counters). No request is
# sent to an upstream, so a status run cannot spend quota or reset anything.
#
# The endpoint table is read from the rendered config the container booted with (`.local/llm-gateway/
# config.yaml`), not from the owner's file: those are only the same thing until the owner edits it,
# and after that the note below says so.
#
# Exit code: 0 when the container is running and ready, 1 otherwise (like dev-status).
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_cmd podman "install rootless podman 5.x"
require_env_file
load_images
export_gateway_env

if ! container_exists "$CONTAINER"; then
  log "project $PROJECT: no container (start it with make llm-gateway-up)"
  exit 1
fi

status=$(podman inspect --format '{{.State.Status}}' "$CONTAINER")
health_state=$(podman inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$CONTAINER")
log "project $PROJECT  container $CONTAINER  state $status  health $health_state"
log "loopback $BASE_URL  image ${AEGIS_LLM_GATEWAY_IMAGE#*:}"

if ! container_running; then
  podman logs --tail 20 "$CONTAINER" >&2 || true
  die "the container is not running"
fi
[ -f "$RENDERED_CONFIG" ] ||
  die "$RENDERED_CONFIG is missing; the running container has a config this checkout did not render
  (start it with make llm-gateway-up)"

readiness=$(health /health/readiness)
liveliness=$(health /health/liveliness)
log "readiness HTTP $readiness  liveliness HTTP $liveliness"
[ "$readiness" = 200 ] || {
  podman logs --tail 30 "$CONTAINER" >&2 || true
  die "the gateway is not ready"
}

# The owner's files may have been edited since the container started; say so, because the running
# router still uses the config it booted with.
report_drift

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
api /model/info >"$tmp/model-info.json" || die "cannot read /model/info"
api /metrics/ >"$tmp/metrics.txt" || die "cannot read /metrics"
api /v1/models |
  python3 -c 'import json,sys; print("[llm-gateway] model groups: " + ", ".join(m["id"] for m in json.load(sys.stdin).get("data",[])))'

python3 "$LLM_GATEWAY_SCRIPTS/status.py" "$RENDERED_CONFIG" "$tmp/model-info.json" "$tmp/metrics.txt"
