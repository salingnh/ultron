#!/usr/bin/env bash
# Start the owner's LLM gateway (G1.6): `make llm-gateway-up`.
#
# Order matters: the owner's files are validated first (a bad routing order must not start a
# container), then the project is proven to be this checkout's, then the image pin is loaded, and
# only then does a container exist. The gateway is idempotent: a second run with the same
# configuration does nothing, and a changed configuration is refused until it is applied on
# purpose (`AEGIS_STACK_RECREATE=1 make llm-gateway-up`, or `make llm-gateway-reload`).
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_cmd podman "install rootless podman 5.x"
require_cmd podman-compose "install with: python3 -m pip install --user podman-compose"
require_rootless
require_owner_config
load_images
export AEGIS_LLM_GATEWAY_CONFIG_DIR="$CONFIG_DIR" AEGIS_LLM_GATEWAY_PORT="$PORT" \
  AEGIS_LLM_GATEWAY_PROJECT="$PROJECT"
require_gateway_stack_ownership

log "project $PROJECT, loopback $BASE_URL, owner config $CONFIG_DIR (read-only)"

if ! podman image exists "$AEGIS_LLM_GATEWAY_IMAGE"; then
  log "pulling the pinned image (digest-pinned; this is a one-time ~1.3 GB download)"
fi

compose up -d
record_gateway_stack_identity
wait_ready 240

log "ready: $BASE_URL/v1 (OpenAI /v1/chat/completions, Anthropic /v1/messages)"
api /v1/models |
  python3 -c 'import json,sys; models=[m["id"] for m in json.load(sys.stdin).get("data",[])]; print("[llm-gateway] model groups: " + (", ".join(models) or "none"))'
log "ultron: AEGIS_MODEL_GATEWAY=1, AEGIS_MODEL_BASE_URL=$BASE_URL/v1, AEGIS_MODEL_NAME=<group above>"
log "state of every endpoint: make llm-gateway-status"
