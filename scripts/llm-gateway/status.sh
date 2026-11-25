#!/usr/bin/env bash
# What the gateway is doing right now: `make llm-gateway-status`.
#
# Container state, readiness, the model groups ultron may ask for, and - per endpoint - whether it
# is healthy or cooling down (and how often it was cooled, from the proxy's own counters). No
# request is sent to an upstream, so a status run cannot spend quota or reset anything.
#
# Exit code: 0 when the container is running and ready, 1 otherwise (like dev-status).
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_cmd podman "install rootless podman 5.x"
load_images
export AEGIS_LLM_GATEWAY_CONFIG_DIR="$CONFIG_DIR" AEGIS_LLM_GATEWAY_PORT="$PORT" \
  AEGIS_LLM_GATEWAY_PROJECT="$PROJECT"

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
[ -f "$CONFIG_FILE" ] || die "$CONFIG_FILE is missing; the running container keeps its old config"

readiness=$(health /health/readiness)
liveliness=$(health /health/liveliness)
log "readiness HTTP $readiness  liveliness HTTP $liveliness"
[ "$readiness" = 200 ] || {
  podman logs --tail 30 "$CONTAINER" >&2 || true
  die "the gateway is not ready"
}

# The owner's files may have been edited since the container started; say so, because the running
# router still uses the config it booted with.
recorded=$(sed -n 's/^fingerprint=//p' "$IDENTITY_FILE" 2>/dev/null || true)
if [ -n "$recorded" ] && [ "$recorded" != "$(gateway_fingerprint)" ]; then
  log "note: $CONFIG_FILE or $SECRETS_FILE changed since this container started"
  log "      apply it with: make llm-gateway-reload"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
api /model/info >"$tmp/model-info.json" || die "cannot read /model/info"
api /metrics/ >"$tmp/metrics.txt" || die "cannot read /metrics"
api /v1/models |
  python3 -c 'import json,sys; print("[llm-gateway] model groups: " + ", ".join(m["id"] for m in json.load(sys.stdin).get("data",[])))'

python3 "$LLM_GATEWAY_SCRIPTS/status.py" "$CONFIG_FILE" "$tmp/model-info.json" "$tmp/metrics.txt"
