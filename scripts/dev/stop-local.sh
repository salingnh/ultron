#!/usr/bin/env bash
# `make stop-local`: stops exactly what `make run-local` started.
#
#   * the API process it recorded in .local/api.pid (stop-api.sh checks the process is ours);
#   * the dev stack and/or the lab **only when run-local was the one that brought them up**
#     (marker files .local/stack.started, .local/lab.started). A stack that was already running
#     before run-local is left up, printed with the command to remove it explicitly.
#
# It never removes containers, volumes or databases it did not start.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_cmd podman
STATE_DIR="$REPO_ROOT/.local"

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

log "stop-local: done; the operator token file .local/operators.json is kept (NEW_TOKEN=1 rotates it)"
