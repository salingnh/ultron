#!/usr/bin/env bash
# Apply an edited owner configuration without restarting ultron: `make llm-gateway-reload`.
#
# The proxy reads its config file once at boot (this version has no supported "reload file" route),
# so applying an edit means recreating THIS ONE container. ultron keeps running: its
# AEGIS_MODEL_BASE_URL still points at the same loopback port, and the short window where the
# container is down is a provider_error at worst, not a process restart.
#
# Order: validate the new files first (a typo must not take a working gateway down), then ownership,
# then recreate, then prove the running router serves exactly the groups and endpoints the file
# describes - a reload that "succeeded" but loaded the old file is the failure mode this checks.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_cmd podman "install rootless podman 5.x"
require_cmd podman-compose "install with: python3 -m pip install --user podman-compose"
require_rootless
require_owner_config
load_images
export AEGIS_LLM_GATEWAY_CONFIG_DIR="$CONFIG_DIR" AEGIS_LLM_GATEWAY_PORT="$PORT" \
  AEGIS_LLM_GATEWAY_PROJECT="$PROJECT"
# Recreating this stack with a changed configuration IS the point of a reload, so the same
# deliberate flag the stack helper prints for a config change is set here, for this one call.
AEGIS_STACK_RECREATE=1 require_gateway_stack_ownership

if ! container_running; then
  log "the gateway is not running; start it with make llm-gateway-up"
  exit 1
fi

log "recreating $CONTAINER with the edited configuration (ultron keeps running)"
compose up -d --force-recreate gateway
record_gateway_stack_identity
wait_ready 240

# What the file says must be what the router serves: every group, and every member deployment.
expected=$(python3 - "$CONFIG_FILE" <<'PY'
import sys

import yaml

document = yaml.safe_load(open(sys.argv[1], encoding="utf-8")) or {}
for group in (document.get("router_settings") or {}).get("routing_groups") or []:
    print(group.get("group_name"))
for entry in document.get("model_list") or []:
    print((entry.get("model_info") or {}).get("id") or entry.get("model_name"))
PY
)
# /v1/models names the callable model groups (and the member model_names), /model/info names each
# deployment by its model_info.id; a name is served when either answers to it.
served=$(
  {
    api /v1/models | python3 -c 'import json,sys; [print(m["id"]) for m in json.load(sys.stdin).get("data", [])]'
    api /model/info | python3 -c 'import json,sys
for entry in json.load(sys.stdin).get("data", []):
    print((entry.get("model_info") or {}).get("id") or entry.get("model_name"))'
  } | sort -u
)
for name in $expected; do
  printf '%s\n' "$served" | grep -qx -- "$name" ||
    die "the reloaded gateway does not serve '$name'; the container is running with a stale or partial config"
done
log "reload ok: $(printf '%s\n' "$expected" | wc -l) names served (groups + endpoints)"
log "state of every endpoint: make llm-gateway-status"
