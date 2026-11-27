#!/usr/bin/env bash
# Stops the API process `make run-local` started, after checking that the recorded pid really is
# that process. Refuses to kill anything else instead of guessing.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

API_PID_FILE="$STATE_DIR/api.pid"

[ -f "$API_PID_FILE" ] || {
  log "api: no pid file - nothing to stop"
  exit 0
}
pid=$(cat "$API_PID_FILE")
case $pid in
'' | *[!0-9]*) die "api: .local/api.pid does not hold a pid ($pid); remove it by hand" ;;
esac

if kill -0 "$pid" 2>/dev/null; then
  command_line=$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true)
  if [[ $command_line != *uvicorn* || $command_line != *aegis.m26_api.main* ]]; then
    die "api: pid $pid is not this API ($command_line); refusing to kill it (remove .local/api.pid if it is stale)"
  fi
  log "api: stopping pid $pid"
  kill "$pid"
  for _ in $(seq 1 100); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
  if kill -0 "$pid" 2>/dev/null; then
    log "api: pid $pid ignored SIGTERM, sending SIGKILL"
    kill -9 "$pid"
  fi
else
  log "api: pid $pid is not running (stale pid file)"
fi
rm -f "$API_PID_FILE"
log "api: stopped; log kept at .local/api.log"
