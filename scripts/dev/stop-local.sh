#!/usr/bin/env bash
# `make stop-local`: stops exactly what `make run-local` started.
#
#   * every process it recorded in .local/ (`<name>.pid`): the API, the MCP server, the M02 worker
#     and dispatcher, the M23 projector and the M06 runner. A pid is only killed when the process
#     is still the command that was started (stop_bg), so a recycled pid is never taken down;
#   * the dev stack and/or the lab **only when run-local was the one that brought them up**
#     (marker files .local/stack.started, .local/lab.started). A stack that was already running
#     before run-local is left up, printed with the command to remove it explicitly.
#
# It never removes containers, volumes or databases it did not start.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_cmd podman

stop_bg m06 "aegis.m06_runner"
stop_bg m23 "aegis.m23_graph"
stop_bg m02-dispatcher "aegis.m02_orchestrator.dispatcher"
stop_bg m02-worker "aegis.m02_orchestrator.worker"
stop_bg mcp "aegis.m05_registry.mcp"
"$DEV_DIR/stop-api.sh"

if [ -f "$STATE_DIR/stack.started" ]; then
  if [ "$(stack_verdict "$DEV_PROJECT" "$REPO_ROOT/deploy/dev" "$COMPOSE_FILE" \
    "$(dev_stack_fingerprint)" "$STACK_IDENTITY")" != "ours" ]; then
    log "dev stack: not this checkout's any more - left in place (dev-down refuses to remove it)"
    rm -f "$STATE_DIR/stack.started"
    return 0 2>/dev/null || exit 0
  fi
  log "dev stack: started by run-local - removing compose project $DEV_PROJECT"
  make --no-print-directory -C "$REPO_ROOT" dev-down
  rm -f "$STATE_DIR/stack.started"
else
  log "dev stack: left as run-local found it (not started by it) - 'make dev-down' removes it"
fi

if [ -f "$STATE_DIR/lab.started" ]; then
  if [ "$(stack_verdict "$LAB_PROJECT" "$REPO_ROOT/deploy/lab" \
    "$REPO_ROOT/deploy/lab/compose.yaml" \
    "$(stack_config_fingerprint "$REPO_ROOT/deploy/lab/compose.yaml" \
      "$REPO_ROOT/deploy/lab/images.env" "$REPO_ROOT/.env" AEGIS_LAB_PROJECT)" \
    "$REPO_ROOT/deploy/lab/.run/identity")" != "ours" ]; then
    log "lab: not this checkout's any more - left in place (lab-down refuses to remove it)"
    rm -f "$STATE_DIR/lab.started"
    return 0 2>/dev/null || exit 0
  fi
  log "lab: started by run-local - removing compose project $LAB_PROJECT"
  make --no-print-directory -C "$REPO_ROOT" lab-down
  rm -f "$STATE_DIR/lab.started"
else
  log "lab: left as run-local found it (not started by it) - 'make lab-down' removes it"
fi

if [ -f "$STATE_DIR/uplink.started" ]; then
  uplink=$(cat "$STATE_DIR/uplink.started")
  if [ -n "$uplink" ] && podman network exists "$uplink" >/dev/null 2>&1; then
    log "uplink: started by run-local - removing network $uplink"
    podman network rm -f "$uplink" >/dev/null
  fi
  rm -f "$STATE_DIR/uplink.started"
else
  log "uplink: left as run-local found it (not created by it)"
fi

log "stop-local: done; tokens (.local/operator-token, .local/service-token) are kept (NEW_TOKEN=1 rotates)"
