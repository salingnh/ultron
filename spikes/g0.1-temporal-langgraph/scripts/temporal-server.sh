#!/usr/bin/env bash
# Start/stop the standalone Temporal dev server (pinned CLI, SQLite file backend).
# Nothing on the host is touched outside .runtime/.
set -euo pipefail
cd "$(dirname "$0")/.."
ACTION="${1:-start}"
PID_FILE=.runtime/temporal.pid
LOG_FILE=.runtime/temporal.log
mkdir -p .runtime

case "$ACTION" in
  start)
    scripts/fetch-temporal.sh >/dev/null
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
      echo "temporal already running (pid $(cat "$PID_FILE"))"; exit 0
    fi
    nohup .tools/temporal server start-dev \
      --db-filename .runtime/temporal.db \
      --port 7233 --ui-port 8233 --log-level warn \
      >"$LOG_FILE" 2>&1 &
    echo $! >"$PID_FILE"
    for _ in $(seq 1 60); do
      if .tools/temporal operator cluster health --address 127.0.0.1:7233 >/dev/null 2>&1; then
        echo "temporal dev server ready on 127.0.0.1:7233 (pid $(cat "$PID_FILE"))"; exit 0
      fi
      sleep 1
    done
    echo "temporal did not become healthy; see $LOG_FILE" >&2; exit 1
    ;;
  stop)
    if [ -f "$PID_FILE" ]; then kill "$(cat "$PID_FILE")" 2>/dev/null || true; rm -f "$PID_FILE"; fi
    echo "temporal stopped"
    ;;
  *) echo "usage: $0 start|stop" >&2; exit 2 ;;
esac
