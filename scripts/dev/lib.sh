#!/usr/bin/env bash
# Shared helpers for scripts/dev/*.sh. Source it; do not execute it directly.
#
# All dev scripts operate on one compose project - `aegis-dev` by default, or the name in
# `AEGIS_DEV_PROJECT` (.env) when a checkout runs its own isolated stack on a shared host
# (deploy/dev/compose.yaml). Nothing here inspects or removes containers, volumes or databases
# outside that project, and scripts/lib/stack.sh makes sure the project is this checkout's before
# anything is started or removed.

set -euo pipefail

# The variables below are used by the scripts that source this file, which is why some of
# them look unused here.

DEV_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$DEV_DIR/../.." && pwd)
COMPOSE_FILE="$REPO_ROOT/deploy/dev/compose.yaml"
IMAGES_FILE="$REPO_ROOT/deploy/dev/images.env"
ENV_FILE="$REPO_ROOT/.env"
# shellcheck disable=SC2034 # used by sourcing scripts
ENV_EXAMPLE="$REPO_ROOT/.env.example"
# shellcheck disable=SC2034 # used by sourcing scripts
GRAPH_DIR="$REPO_ROOT/contracts/graph"

# shellcheck source=scripts/lib/stack.sh
. "$(cd "$DEV_DIR/../lib" && pwd)/stack.sh"

# Compose project of this checkout and the container names it implies; `AEGIS_DEV_PROJECT` renames
# it (see set_dev_names, called again after load_env because .env is where it is configured).
DEV_PROJECT=aegis-dev
PG_CONTAINER=
NEO4J_CONTAINER=
# shellcheck disable=SC2034 # used by sourcing scripts
SEAWEEDFS_CONTAINER=
# shellcheck disable=SC2034 # used by sourcing scripts
TEMPORAL_CONTAINER=

# The lab is its own compose project (scripts/lab, which owns these names); scripts/dev only needs
# the project name to tell whether run-local started it. Its network is `<project>-lab`.
LAB_PROJECT=aegis-lab

# The project name and the names it derives; called at source time and again after `load_env`.
set_dev_names() {
  DEV_PROJECT=${AEGIS_DEV_PROJECT:-aegis-dev}
  PG_CONTAINER="$DEV_PROJECT-pg"
  NEO4J_CONTAINER="$DEV_PROJECT-neo4j"
  # shellcheck disable=SC2034 # used by sourcing scripts
  SEAWEEDFS_CONTAINER="$DEV_PROJECT-seaweedfs"
  # shellcheck disable=SC2034 # used by sourcing scripts
  TEMPORAL_CONTAINER="$DEV_PROJECT-temporal"
}
set_dev_names

log() { printf '[dev] %s\n' "$*"; }
die() { printf '[dev] error: %s\n' "$*" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing command '$1'${2:+ - $2}"
}

# Loads local configuration from .env and the image pins from deploy/dev/images.env.
# The pins are repository state, so they are sourced last and win over .env.
load_env() {
  [ -f "$ENV_FILE" ] || die ".env is missing - run 'make dev-up' (it copies .env.example)"
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  # shellcheck disable=SC1090
  . "$IMAGES_FILE"
  set +a
  : "${AEGIS_PG_USER:?.env: AEGIS_PG_USER missing}"
  : "${AEGIS_PG_PASSWORD:?.env: AEGIS_PG_PASSWORD missing}"
  : "${AEGIS_PG_DB:?.env: AEGIS_PG_DB missing}"
  : "${AEGIS_NEO4J_PASSWORD:?.env: AEGIS_NEO4J_PASSWORD missing}"
  : "${AEGIS_S3_PORT:?.env: AEGIS_S3_PORT missing}"
  : "${AEGIS_S3_BUCKET:?.env: AEGIS_S3_BUCKET missing}"
  set_dev_names
}

compose() { podman-compose -p "$DEV_PROJECT" -f "$COMPOSE_FILE" "$@"; }

# Everything one checkout writes for itself lives here (pids, logs, tokens, stack identity).
STATE_DIR="${AEGIS_STATE_DIR:-$REPO_ROOT/.local}"
# What this checkout started, and with which configuration (scripts/lib/stack.sh reads it back).
STACK_IDENTITY="$STATE_DIR/stack.identity"

# The configuration a stack is started from; a change makes dev-up recreate (scripts/lib/stack.sh).
dev_stack_fingerprint() {
  stack_config_fingerprint "$COMPOSE_FILE" "$IMAGES_FILE" "$ENV_FILE" AEGIS_DEV_PROJECT
}

# Refuses when the project exists and is not this checkout's (or not this configuration).
require_dev_stack_ownership() {
  require_stack_ownership dev "$DEV_PROJECT" "$REPO_ROOT/deploy/dev" "$COMPOSE_FILE" \
    "$(dev_stack_fingerprint)" "$STACK_IDENTITY" AEGIS_DEV_PROJECT
}

record_dev_stack_identity() {
  record_stack_identity "$STACK_IDENTITY" "$DEV_PROJECT" "$REPO_ROOT/deploy/dev" \
    "$(dev_stack_fingerprint)"
}

container_exists() { podman container exists "$1" 2>/dev/null; }

# Waits until every named container reports a healthy healthcheck.
# Fails with the container's last log lines when it stops or exits early.
wait_healthy() {
  local timeout=${1:-300}
  shift
  local containers=("$@") deadline=$((SECONDS + timeout)) name status
  while ((SECONDS < deadline)); do
    local pending=0
    for name in "${containers[@]}"; do
      container_exists "$name" || die "container $name is gone (see: make dev-logs)"
      status=$(podman inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$name")
      case $status in
      healthy) ;;
      unhealthy)
        podman logs --tail 30 "$name" >&2 || true
        die "$name is unhealthy (see: make dev-logs)"
        ;;
      *)
        pending=1
        ;;
      esac
    done
    ((pending == 0)) && return 0
    sleep 2
  done
  for name in "$@"; do podman logs --tail 20 "$name" >&2 || true; done
  die "timed out after ${timeout}s waiting for health: $*"
}

psql_run() {
  podman exec -i "$PG_CONTAINER" \
    psql -v ON_ERROR_STOP=1 -q -U "$AEGIS_PG_USER" -d "$AEGIS_PG_DB" "$@"
}

psql_value() { psql_run -tAc "$1" | tr -d '[:space:]'; }

# Fails before anything starts when a published port belongs to another process.
# Ports held by this compose project itself are fine (make dev-up is re-runnable).
check_dev_ports_free() {
  require_cmd ss "install iproute2"
  local ours=0 port
  if podman ps --filter "label=io.podman.compose.project=$DEV_PROJECT" --format '{{.Names}}' | grep -q .; then
    ours=1
  fi
  for port in "$AEGIS_PG_PORT" "$AEGIS_NEO4J_HTTP_PORT" "$AEGIS_NEO4J_BOLT_PORT" \
    "$AEGIS_S3_PORT" "$AEGIS_SEAWEEDFS_FILER_PORT" "$AEGIS_TEMPORAL_PORT"; do
    if ss -ltn "sport = :$port" 2>/dev/null | grep -q LISTEN; then
      ((ours == 1)) && continue
      die "port $port is already in use by another process - set a free port for it in .env and run make dev-up again"
    fi
  done
}

# Runs Cypher from a file inside the Neo4j container (no host mount, no SELinux relabel).
cypher_file() {
  local file=$1
  local remote
  remote="/tmp/$(basename "$file")"
  podman cp "$file" "$NEO4J_CONTAINER:$remote"
  podman exec "$NEO4J_CONTAINER" \
    /var/lib/neo4j/bin/cypher-shell \
    -a bolt://127.0.0.1:7687 -u neo4j -p "$AEGIS_NEO4J_PASSWORD" \
    --fail-fast -f "$remote"
}

# --- background processes of `make run-local` ------------------------------------------------
# Everything run-local starts is a process this repository owns, recorded by name in .local/:
# `<name>.pid` (the pid), `<name>.log` (its output). `stop_bg` only kills a pid that is still the
# command it started, so a recycled pid can never take down something else.

# start_bg <name> <command...>; the caller has already exported the environment it needs.
start_bg() {
  local name=$1
  shift
  local dir="$STATE_DIR"
  mkdir -p "$dir"
  nohup "$@" >"$dir/$name.log" 2>&1 &
  echo $! >"$dir/$name.pid"
}

# wait_bg_alive <name> <seconds>: the process must still be running after this long.
wait_bg_alive() {
  local name=$1 seconds=${2:-3} pid
  pid=$(cat "$STATE_DIR/$name.pid")
  sleep "$seconds"
  if ! kill -0 "$pid" 2>/dev/null; then
    tail -20 "$STATE_DIR/$name.log" >&2 || true
    rm -f "$STATE_DIR/$name.pid"
    die "$name exited during start-up (log above, full log: .local/$name.log)"
  fi
}

# stop_bg <name> <cmdline-needle>: stop the recorded process if it is still that process.
stop_bg() {
  local name=$1 needle=${2:-} pid cmdline
  local file="$STATE_DIR/$name.pid"
  [ -f "$file" ] || {
    log "$name: no pid file - nothing to stop"
    return 0
  }
  pid=$(cat "$file")
  case $pid in
  '' | *[!0-9]*)
    rm -f "$file"
    die "$name: .local/$name.pid does not hold a pid ($pid)"
    ;;
  esac
  if ! kill -0 "$pid" 2>/dev/null; then
    log "$name: pid $pid is not running (stale pid file)"
    rm -f "$file"
    return 0
  fi
  cmdline=$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true)
  if [ -n "$needle" ] && [[ $cmdline != *"$needle"* ]]; then
    rm -f "$file"
    die "$name: pid $pid is not $needle ($cmdline); refusing to kill it"
  fi
  log "$name: stopping pid $pid"
  kill "$pid" 2>/dev/null || true
  for _ in $(seq 1 100); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
  if kill -0 "$pid" 2>/dev/null; then
    log "$name: pid $pid ignored SIGTERM, sending SIGKILL"
    kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$file"
}
