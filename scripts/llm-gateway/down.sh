#!/usr/bin/env bash
# Remove this checkout's LLM gateway (G1.6): `make llm-gateway-down`.
#
# The project is checked first, so a gateway another checkout started is never removed from here
# (scripts/lib/stack.sh, the #71 rule). Only containers and the network of `$PROJECT` are removed:
# nothing of the owner's configuration, and no other stack.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_cmd podman "install rootless podman 5.x"
require_cmd podman-compose "install with: python3 -m pip install --user podman-compose"
require_rootless
# `down` must work on a gateway whose config the owner has since edited or removed, so ownership is
# checked against the compose file and the pins alone here.
load_images
export AEGIS_LLM_GATEWAY_CONFIG_DIR="$CONFIG_DIR" AEGIS_LLM_GATEWAY_PORT="$PORT" \
  AEGIS_LLM_GATEWAY_PROJECT="$PROJECT"
# Removing this checkout's own stack must not depend on whether the owner edited their config since
# it started (that is what the reload is for), so the deliberate-recreate flag also covers the
# "configuration changed" verdict here. Another checkout's project is still refused: only
# ownership, not configuration, is what this skips.
AEGIS_STACK_RECREATE=1 require_gateway_stack_ownership

if ! container_exists "$CONTAINER" && ! podman network exists "$NETWORK" 2>/dev/null; then
  log "nothing to remove: project $PROJECT does not exist"
  exit 0
fi
compose down --volumes
log "removed project $PROJECT (the owner's config in $CONFIG_DIR is untouched)"
