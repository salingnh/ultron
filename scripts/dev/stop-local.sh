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
STATE_DIR="$REPO_ROOT/.local"

stop_bg m06 "aegis.m06_runner"
stop_bg m23 "aegis.m23_graph"
stop_bg m02-dispatcher "aegis.m02_orchestrator.dispatcher"
stop_bg m02-worker "aegis.m02_orchestrator.worker"
stop_bg mcp "aegis.m05_registry.mcp"
"$DEV_DIR/stop-api.sh"

if [ -f "$STATE_DIR/stack.started" ]; then
  log "dev stack: started by run-local - removing compose project $DEV_PROJECT"
  make --no-print-directory -C "$REPO_ROOT" dev-down
  rm -f "$STATE_DIR/stack.started"
else
  log "dev stack: left as run-local found it (not started by it) - 'make dev-down' removes it"
fi

if [ -f "$STATE_DIR/lab.started" ]; then
  log "lab: started by run-local - removing compose project $LAB_PROJECT"
  make --no-print-directory -C "$REPO_ROOT" lab-down
  rm -f "$STATE_DIR/lab.started"
else
  log "lab: left as run-local found it (not started by it) - 'make lab-down' removes it"
fi

log "stop-local: done; tokens (.local/operator-token, .local/service-token) are kept (NEW_TOKEN=1 rotates)"
