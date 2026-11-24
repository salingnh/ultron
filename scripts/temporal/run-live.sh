#!/usr/bin/env bash
# Live M02 workflow gate: real Temporal dev server + throwaway PostgreSQL.
#
# Not part of `make test` (the CI python job has no Temporal server): the default gate replays the
# committed history instead. This script proves the workflow on a real server and refreshes the
# fixture that `tests/test_m02_replay.py` replays.
#
# Owns everything it creates: PostgreSQL container `aegis-live-<pid>-pg` (tmpfs, loopback, random
# password) and a Temporal dev server with a SQLite file under a temporary directory. Both are
# removed on exit. The Temporal CLI is $TEMPORAL_BIN or `temporal` on PATH (1.10.0 is the pinned
# version, deploy/pins.json of the G0.1 spike).
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$REPO_ROOT"

TEMPORAL_BIN=${TEMPORAL_BIN:-$(command -v temporal || true)}
[[ -n $TEMPORAL_BIN && -x $TEMPORAL_BIN ]] || {
  printf 'error: set TEMPORAL_BIN to a Temporal CLI binary (temporal server start-dev)\n' >&2
  exit 1
}
command -v podman >/dev/null 2>&1 || {
  printf 'error: podman is required for the throwaway PostgreSQL\n' >&2
  exit 1
}
command -v uv >/dev/null 2>&1 || {
  printf 'error: uv is required\n' >&2
  exit 1
}

PG_NAME="aegis-live-$$-pg"
RUNTIME=$(mktemp -d "${TMPDIR:-/tmp}/aegis-live-XXXXXX")
PG_PASSWORD=$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | cut -c1-24)
PORTS=$(python3 - <<'PY'
import socket
sockets = []
for _ in range(2):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sockets.append(sock)
print(" ".join(str(sock.getsockname()[1]) for sock in sockets))
for sock in sockets:
    sock.close()
PY
)
set -- $PORTS
TEMPORAL_PORT=$1
PG_PORT=$2

cleanup() {
  local status=$?
  if [[ -n ${TEMPORAL_PID:-} ]]; then
    kill "$TEMPORAL_PID" 2>/dev/null || true
    wait "$TEMPORAL_PID" 2>/dev/null || true
  fi
  podman rm -f "$PG_NAME" >/dev/null 2>&1 || true
  rm -rf "$RUNTIME"
  exit "$status"
}
trap cleanup EXIT

printf '[live] PostgreSQL 16 on 127.0.0.1:%s as %s\n' "$PG_PORT" "$PG_NAME"
podman run -d --name "$PG_NAME" \
  --tmpfs /var/lib/postgresql/data \
  -e POSTGRES_PASSWORD="$PG_PASSWORD" -e POSTGRES_USER=aegis -e POSTGRES_DB=postgres \
  -p "127.0.0.1:$PG_PORT:5432" \
  "$(grep -E '^AEGIS_PG_IMAGE=' deploy/dev/images.env | cut -d= -f2-)" >/dev/null
for _ in $(seq 1 60); do
  podman exec "$PG_NAME" pg_isready -U aegis -d postgres >/dev/null 2>&1 && break
  sleep 1
done
podman exec "$PG_NAME" pg_isready -U aegis -d postgres >/dev/null

printf '[live] Temporal dev server on 127.0.0.1:%s (SQLite under %s)\n' "$TEMPORAL_PORT" "$RUNTIME"
"$TEMPORAL_BIN" server start-dev --headless --port "$TEMPORAL_PORT" --ui-port 0 \
  --db-filename "$RUNTIME/temporal.db" >"$RUNTIME/temporal.log" 2>&1 &
TEMPORAL_PID=$!
for _ in $(seq 1 60); do
  "$TEMPORAL_BIN" operator namespace list --address "127.0.0.1:$TEMPORAL_PORT" >/dev/null 2>&1 && break
  sleep 1
done
"$TEMPORAL_BIN" operator namespace list --address "127.0.0.1:$TEMPORAL_PORT" >/dev/null

export AEGIS_TEST_PG_DSN="postgresql://aegis:${PG_PASSWORD}@127.0.0.1:${PG_PORT}/postgres"
export AEGIS_TEMPORAL_TARGET="127.0.0.1:${TEMPORAL_PORT}"
export AEGIS_NO_SKIPS=1

printf '[live] pytest tests/live (refreshes tests/fixtures/temporal/)\n'
uv run --frozen pytest tests/live -q "$@"
printf '[live] PASS\n'
