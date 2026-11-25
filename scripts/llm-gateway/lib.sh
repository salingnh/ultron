#!/usr/bin/env bash
# Shared helpers for scripts/llm-gateway/*.sh. Source it; do not execute it directly.
#
# Everything here operates on compose project `aegis-llm-gateway` (deploy/llm-gateway/compose.yaml),
# its network `aegis-llm-gateway-net` and the owner's configuration directory outside the checkout.
# Nothing outside that is inspected, started or removed, and `scripts/lib/stack.sh` refuses a
# project another checkout owns (the #71 rule) or one started with a different configuration.
#
# The owner's files are inputs, never outputs: this repository does not copy, render or rewrite
# them. `require_owner_config` validates them before a container exists and never prints a value.
set -euo pipefail

# shellcheck disable=SC2034 # several of these are used by the sourcing scripts
LLM_GATEWAY_SCRIPTS=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC2034
REPO_ROOT=$(cd "$LLM_GATEWAY_SCRIPTS/../.." && pwd)
GATEWAY_DIR="$REPO_ROOT/deploy/llm-gateway"
COMPOSE_FILE="$GATEWAY_DIR/compose.yaml"
IMAGES_FILE="$GATEWAY_DIR/images.env"
CONFIG_EXAMPLE="$GATEWAY_DIR/config.example.yaml"
SECRETS_EXAMPLE="$GATEWAY_DIR/secrets.env.example"

# The owner's directory: outside every checkout on purpose, so a stack's configuration is not part
# of the repository and one edit serves every checkout that runs this gateway. The override exists
# for `make llm-gateway-test` and for another checkout on a shared host; production uses the default.
CONFIG_DIR=${AEGIS_LLM_GATEWAY_CONFIG_DIR:-/home/admin/.config/ultron/llm-gateway}
CONFIG_FILE="$CONFIG_DIR/config.yaml"
SECRETS_FILE="$CONFIG_DIR/secrets.env"

# Project, container, port and network of this checkout; AEGIS_LLM_GATEWAY_PROJECT renames all of
# them (a second checkout on one host needs its own name and port).
PROJECT=${AEGIS_LLM_GATEWAY_PROJECT:-aegis-llm-gateway}
PORT=${AEGIS_LLM_GATEWAY_PORT:-4000}
CONTAINER="$PROJECT-gateway"
# shellcheck disable=SC2034 # used by down.sh to tell whether anything is left to remove
NETWORK="$PROJECT-net"
BASE_URL="http://127.0.0.1:$PORT"
SCOPE="AEGIS_LLM_GATEWAY_PROJECT"

STATE_DIR="${AEGIS_STATE_DIR:-$REPO_ROOT/.local}"
IDENTITY_FILE="$STATE_DIR/llm-gateway.identity"

log() { printf '[llm-gateway] %s\n' "$*"; }
die() {
  printf '[llm-gateway] error: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing command '$1'${2:+ - $2}"
}

# shellcheck source=scripts/lib/stack.sh
. "$(cd "$LLM_GATEWAY_SCRIPTS/../lib" && pwd)/stack.sh"

# Image pins are repository state (deploy/llm-gateway/images.env), never taken from the owner's
# files. A digest is required: a tag alone can be moved under us.
load_images() {
  [ -f "$IMAGES_FILE" ] || die "missing $IMAGES_FILE"
  set -a
  # shellcheck disable=SC1090
  . "$IMAGES_FILE"
  set +a
  : "${AEGIS_LLM_GATEWAY_IMAGE:?images.env: AEGIS_LLM_GATEWAY_IMAGE missing}"
  case $AEGIS_LLM_GATEWAY_IMAGE in
  *@sha256:*) ;;
  *) die "images.env: $AEGIS_LLM_GATEWAY_IMAGE is not pinned by digest" ;;
  esac
  export AEGIS_LLM_GATEWAY_IMAGE
}

# The owner's configuration is the only input; refuse anything we cannot trust. A file that group
# or other users can read holds an API key, so its mode is part of the contract, not a warning.
require_owner_config() {
  local mode owner name
  [ -d "$CONFIG_DIR" ] ||
    die "the owner's config directory $CONFIG_DIR is missing: mkdir -p $CONFIG_DIR and copy
  $CONFIG_EXAMPLE       -> $CONFIG_FILE
  $SECRETS_EXAMPLE -> $SECRETS_FILE   (then chmod 600 it)"
  [ -f "$CONFIG_FILE" ] ||
    die "$CONFIG_FILE is missing: copy $CONFIG_EXAMPLE there and edit it"
  [ -f "$SECRETS_FILE" ] ||
    die "$SECRETS_FILE is missing: copy $SECRETS_EXAMPLE there, fill in the keys, chmod 600 it"
  for name in "$CONFIG_FILE" "$SECRETS_FILE"; do
    [ -r "$name" ] || die "$name is not readable by $(id -un)"
    owner=$(stat -Lc '%u' "$name")
    [ "$owner" = "$(id -u)" ] || die "refusing $name: owned by uid $owner, not $(id -u)"
  done
  mode=$(stat -Lc '%a' "$SECRETS_FILE")
  if (((8#$mode & 8#077) != 0)); then
    die "refusing $SECRETS_FILE: mode $mode lets group/other read the keys; chmod 600 $SECRETS_FILE"
  fi
  validate_owner_config
}

# Runs the same checks the gateway would discover at call time, before a container exists.
validate_owner_config() {
  require_cmd python3 "install python3"
  python3 -c 'import yaml' 2>/dev/null ||
    die "python3 needs PyYAML to read $CONFIG_FILE (pip install --user pyyaml)"
  python3 "$LLM_GATEWAY_SCRIPTS/validate.py" "$CONFIG_FILE" "$SECRETS_FILE" ||
    die "the owner's configuration did not pass validation - nothing was started"
}

# One value out of the owner's secrets file, for the authenticated status/metrics reads. Never
# printed, and never exported into this process's environment.
secret_value() { # <name>
  local name=$1 line value
  while IFS= read -r line || [ -n "$line" ]; do
    case $line in
    '' | '#'*) continue ;;
    "$name"=*) ;;
    *) continue ;;
    esac
    value=${line#*=}
    value=${value%\"}
    value=${value#\"}
    value=${value%\'}
    value=${value#\'}
    printf '%s' "$value"
    return 0
  done <"$SECRETS_FILE"
  return 1
}

compose() {
  podman-compose -p "$PROJECT" -f "$COMPOSE_FILE" "$@"
}

container_exists() { podman container exists "$CONTAINER" 2>/dev/null; }

container_running() {
  container_exists "$CONTAINER" && [ "$(podman inspect --format '{{.State.Running}}' "$CONTAINER")" = true ]
}

require_rootless() {
  if ! podman info --format '{{.Host.Security.Rootless}}' | grep -qx true; then
    die "podman is not rootless; the gateway must run as the current user"
  fi
}

# The configuration a stack is started from. The owner's files are part of it: a new endpoint, key
# or routing order means the container must be recreated, and `up` says so instead of silently
# keeping the old one. The secrets file contributes its size and mtime, not its bytes, so no hash
# of a key is written anywhere.
gateway_fingerprint() {
  local secrets_stamp
  secrets_stamp=$(stat -Lc '%s:%Y' "$SECRETS_FILE")
  {
    stack_config_fingerprint "$COMPOSE_FILE" "$IMAGES_FILE" "$CONFIG_FILE" \
      AEGIS_LLM_GATEWAY_PROJECT AEGIS_LLM_GATEWAY_PORT
    printf 'secrets=%s\n' "$secrets_stamp"
  } | sha256sum | cut -d' ' -f1
}

require_gateway_stack_ownership() {
  require_stack_ownership llm-gateway "$PROJECT" "$GATEWAY_DIR" "$COMPOSE_FILE" \
    "$(gateway_fingerprint)" "$IDENTITY_FILE" "$SCOPE"
}

record_gateway_stack_identity() {
  record_stack_identity "$IDENTITY_FILE" "$PROJECT" "$GATEWAY_DIR" "$(gateway_fingerprint)"
  chmod 600 "$IDENTITY_FILE"
}

# Authenticated JSON read from the proxy. The master key travels in curl's own config file (a pipe,
# not argv), so it is not in this process's command line for another worker on the host to read.
api() { # <path> [extra curl args...]
  local path=$1 key
  shift
  key=$(secret_value LITELLM_MASTER_KEY) || die "secrets.env: LITELLM_MASTER_KEY is missing"
  curl -sS --max-time 15 -L \
    -K <(printf '%s\n' "header = \"authorization: Bearer $key\"") \
    "$@" "$BASE_URL$path"
}

health() { # <path>
  curl -sS --max-time 5 -o /dev/null -w '%{http_code}' "$BASE_URL$1" 2>/dev/null || true
}

# Waits until the proxy answers its readiness probe; on failure the owner gets the reason the
# container gave, not a timeout.
wait_ready() {
  local timeout=${1:-180}
  local -i deadline
  deadline=$((SECONDS + timeout))
  # Every non-200 is "not yet": the proxy takes ~20-30 s to import and build its router, and the
  # port answers before readiness does. A container that stops is the one case worth failing on
  # immediately, because waiting cannot fix it.
  while ((SECONDS < deadline)); do
    if [ "$(health /health/readiness)" = 200 ]; then
      return 0
    fi
    if ! container_running; then
      podman logs --tail 40 "$CONTAINER" >&2 || true
      die "container $CONTAINER stopped before it was ready (see the log above)"
    fi
    sleep 2
  done
  podman logs --tail 40 "$CONTAINER" >&2 || true
  die "the gateway did not become ready within ${timeout}s"
}
