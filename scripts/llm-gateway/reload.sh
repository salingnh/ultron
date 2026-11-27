#!/usr/bin/env bash
# Apply an edited configuration without restarting ultron: `make llm-gateway-reload`.
#
# "Configuration" is now two files: the owner's endpoints (outside the checkout) and the checkout's
# `.env` (the keys, and the fixed base from the repository). The proxy reads its config once at boot
# (this version has no supported "reload file" route), so applying an edit means rendering again and
# recreating THIS ONE container. ultron keeps running: its AEGIS_MODEL_BASE_URL still points at the
# same loopback port, and the short window where the container is down is a provider_error at worst.
#
# Order: validate the new inputs first (a typo must not take a working gateway down), then ownership,
# then recreate, then prove the running router serves exactly the groups and endpoints the file
# describes - a reload that "succeeded" but loaded the old file is the failure mode this checks.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_cmd podman "install rootless podman 5.x"
require_cmd podman-compose "install with: python3 -m pip install --user podman-compose"
require_rootless
require_env_file
ensure_master_key
load_env
require_model_base_url
require_port_free
require_owner_config
render_and_validate
load_images
export_gateway_env
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

# What the rendered file says must be what the router serves: every group, and every member
# deployment (the effective document, so a base change or a default is included too).
expected=$(python3 - "$RENDERED_CONFIG" <<'PY'
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
