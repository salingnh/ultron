#!/usr/bin/env bash
# Live M02 workflow gate: real Temporal dev server + throwaway PostgreSQL.
#
# Not part of `make test` (the CI python job has no Temporal server): the default gate replays the
# committed history instead. This script proves the workflow on a real server and refreshes the
# fixture that `tests/test_m02_replay.py` replays.
#
# Owns everything it creates: PostgreSQL container `aegis-live-<pid>-pg` (tmpfs, loopback, random
# password) and a Temporal dev server container `aegis-live-<pid>-temporal` (SQLite inside the
# container, loopback). Both are removed on exit. The dev server is `temporal server start-dev` of
# the pinned admin-tools image (deploy/dev/images.env), whose CLI embeds the same server release
# the dev stack runs.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$REPO_ROOT"

command -v podman >/dev/null 2>&1 || {
  printf 'error: podman is required for the throwaway PostgreSQL\n' >&2
  exit 1
}
command -v uv >/dev/null 2>&1 || {
  printf 'error: uv is required\n' >&2
  exit 1
}

PG_NAME="aegis-live-$$-pg"
TEMPORAL_NAME="aegis-live-$$-temporal"
pinned_image() { grep -E "^$1=" deploy/dev/images.env | cut -d= -f2-; }
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
# Not `set --`: this script's own arguments are passed on to pytest below.
read -r TEMPORAL_PORT PG_PORT <<<"$PORTS"

cleanup() {
  local status=$?
  if ((status != 0)); then
    podman logs --tail 40 "$TEMPORAL_NAME" >&2 2>&1 || true
  fi
  podman rm -f -v "$TEMPORAL_NAME" "$PG_NAME" >/dev/null 2>&1 || true
  exit "$status"
}
trap 'exit 130' INT
trap 'exit 143' TERM
trap cleanup EXIT

printf '[live] PostgreSQL 18 on 127.0.0.1:%s as %s\n' "$PG_PORT" "$PG_NAME"
podman run -d --name "$PG_NAME" \
  --tmpfs /var/lib/postgresql \
  -e POSTGRES_PASSWORD="$PG_PASSWORD" -e POSTGRES_USER=aegis -e POSTGRES_DB=postgres \
  -p "127.0.0.1:$PG_PORT:5432" \
  "$(grep -E '^AEGIS_PG_IMAGE=' deploy/dev/images.env | cut -d= -f2-)" >/dev/null
for _ in $(seq 1 60); do
  podman exec "$PG_NAME" pg_isready -U aegis -d postgres >/dev/null 2>&1 && break
  sleep 1
done
podman exec "$PG_NAME" pg_isready -U aegis -d postgres >/dev/null

printf '[live] Temporal dev server on 127.0.0.1:%s as %s\n' "$TEMPORAL_PORT" "$TEMPORAL_NAME"
podman run -d --name "$TEMPORAL_NAME" -p "127.0.0.1:$TEMPORAL_PORT:7233" \
  "$(pinned_image AEGIS_TEMPORAL_ADMIN_TOOLS_IMAGE)" \
  temporal server start-dev --headless --ip 0.0.0.0 --port 7233 --db-filename /tmp/temporal.db \
  >/dev/null
temporal_cli() { podman exec "$TEMPORAL_NAME" temporal "$@" --address 127.0.0.1:7233; }
printf '[live] %s\n' "$(podman exec "$TEMPORAL_NAME" temporal --version)"
for _ in $(seq 1 60); do
  temporal_cli operator namespace describe --namespace default >/dev/null 2>&1 && break
  sleep 1
done
temporal_cli operator namespace describe --namespace default >/dev/null

export AEGIS_TEST_PG_DSN="postgresql://aegis:${PG_PASSWORD}@127.0.0.1:${PG_PORT}/postgres"
export AEGIS_TEMPORAL_TARGET="127.0.0.1:${TEMPORAL_PORT}"
export AEGIS_NO_SKIPS=1

printf '[live] pytest tests/live (refreshes tests/fixtures/temporal/)\n'
uv run --frozen pytest tests/live -q "$@"
printf '[live] PASS\n'
