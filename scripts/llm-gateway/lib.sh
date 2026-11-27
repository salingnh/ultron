#!/usr/bin/env bash
# Shared helpers for scripts/llm-gateway/*.sh. Source it; do not execute it directly.
#
# Two inputs, two places - and neither is rendered by hand:
#   * the checkout's `.env` holds every secret and setting, the same file ultron reads. The gateway
#     gets a generated subset of it: only the variables its config references, never the whole file.
#   * the owner's `~/.config/ultron/llm-gateway/config.yaml` (outside every checkout) lists endpoints
#     and their order only; it is merged with the fixed `deploy/llm-gateway/base.yaml` and never
#     mounted itself.
# `render.py` produces both files the container starts from (`.local/llm-gateway/`), `validate.py`
# checks the effective document, and only then does a container exist.
#
# Everything else here operates on compose project `aegis-llm-gateway`, its network
# `aegis-llm-gateway-net` and nothing else. `scripts/lib/stack.sh` refuses a project another checkout
# owns (the #71 rule) or one started with a different configuration. No script below prints a value
# out of `.env`, and no hash of one is written anywhere.
set -euo pipefail

# shellcheck disable=SC2034 # several of these are used by the sourcing scripts
LLM_GATEWAY_SCRIPTS=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC2034
REPO_ROOT=$(cd "$LLM_GATEWAY_SCRIPTS/../.." && pwd)
GATEWAY_DIR="$REPO_ROOT/deploy/llm-gateway"
COMPOSE_FILE="$GATEWAY_DIR/compose.yaml"
IMAGES_FILE="$GATEWAY_DIR/images.env"
BASE_CONFIG="$GATEWAY_DIR/base.yaml"
CONFIG_EXAMPLE="$GATEWAY_DIR/config.example.yaml"
RENDER_SCRIPT="$LLM_GATEWAY_SCRIPTS/render.py"
VALIDATE_SCRIPT="$LLM_GATEWAY_SCRIPTS/validate.py"

# One file for every secret: the checkout's .env. It must not be readable by group or other, because
# the upstream keys and the gateway's master key live in it. Every setting below comes from it too,
# so `.env` is the one file that describes this deployment.
ENV_FILE="$REPO_ROOT/.env"
# The one credential of this deployment: the key ultron sends and the gateway's master key.
MASTER_KEY_ENV=AEGIS_MODEL_API_KEY
#: What ultron reads to call the gateway; the port it names is the port the gateway publishes.
MODEL_BASE_URL_ENV=AEGIS_MODEL_BASE_URL
GATEWAY_PORT_ENV=AEGIS_LLM_GATEWAY_PORT
GATEWAY_PROJECT_ENV=AEGIS_LLM_GATEWAY_PROJECT

# One value out of `.env`, without sourcing it: the stack's own identity has to be known before
# anything is loaded. Never printed by a caller that handles a secret; this reader is used for the
# project name, the port and the base URL.
env_value() { # <name>
  local name=$1 line value
  [ -f "$ENV_FILE" ] || return 1
  while IFS= read -r line || [ -n "$line" ]; do
    case $line in
    '' | '#'*) continue ;;
    "$name"=*) ;;
    *) continue ;;
    esac
    value=${line#*=}
    value=${value%"${value##*[![:space:]]}"}
    case $value in
    \"*\")
      value=${value#\"}
      value=${value%\"}
      ;;
    \'*\')
      value=${value#\'}
      value=${value%\'}
      ;;
    *)
      # An unquoted ` # ...` is a comment in a sourced file too, so it is not part of the value.
      value=${value%%[[:space:]]#*}
      value=${value%"${value##*[![:space:]]}"}
      ;;
    esac
    printf '%s' "$value"
    return 0
  done <"$ENV_FILE"
  return 1
}

# The port ultron already calls, when `.env` names a loopback gateway URL. Keeping one source of
# truth matters: a gateway published on 14000 while ultron calls 4000 is the failure this removes.
base_url_port() {
  local url
  url=$(env_value "$MODEL_BASE_URL_ENV" || true)
  [ -n "$url" ] || return 1
  printf '%s' "$url" | sed -nE 's#^https?://(127\.0\.0\.1|localhost):([0-9]{1,5})(/.*)?$#\2#p' | head -n 1 | grep -E '^[0-9]+$' || return 1
}

# The owner's directory: outside every checkout on purpose, so a stack's configuration is not part of
# the repository and one edit serves every checkout that runs this gateway. The override exists for
# another checkout on a shared host; production uses the default.
CONFIG_DIR=${AEGIS_LLM_GATEWAY_CONFIG_DIR:-/home/admin/.config/ultron/llm-gateway}
CONFIG_FILE="$CONFIG_DIR/config.yaml"

# What the container is given: the effective config and the environment subset, both generated on
# every start/reload. `.local/` is git-ignored, mode 0700, and never mounted into any other stack.
STATE_DIR="${AEGIS_STATE_DIR:-$REPO_ROOT/.local}"
RENDER_DIR="$STATE_DIR/llm-gateway"
RENDERED_CONFIG="$RENDER_DIR/config.yaml"
GATEWAY_ENV="$RENDER_DIR/gateway.env"
IDENTITY_FILE="$STATE_DIR/llm-gateway.identity"

# Project, container, port and network of this checkout. Both are configuration like any other and
# come from `.env` (AEGIS_LLM_GATEWAY_PROJECT / AEGIS_LLM_GATEWAY_PORT); the shell environment wins,
# so a deliberate one-off run can override them. When the port is not named, the port ultron already
# calls (AEGIS_MODEL_BASE_URL) is used, so the two cannot drift; 4000 is the last resort.
PROJECT=${AEGIS_LLM_GATEWAY_PROJECT:-$(env_value "$GATEWAY_PROJECT_ENV" || true)}
PROJECT=${PROJECT:-aegis-llm-gateway}
PORT=${AEGIS_LLM_GATEWAY_PORT:-$(env_value "$GATEWAY_PORT_ENV" || true)}
if [ -z "$PORT" ]; then
  PORT=$(base_url_port || true)
fi
PORT=${PORT:-4000}
CONTAINER="$PROJECT-gateway"
# shellcheck disable=SC2034 # used by down.sh to tell whether anything is left to remove
NETWORK="$PROJECT-net"
BASE_URL="http://127.0.0.1:$PORT"
SCOPE="AEGIS_LLM_GATEWAY_PROJECT"

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

# The checkout's .env is the only place secrets live now, so its mode is part of the contract: a file
# group or other users can read holds every upstream key.
require_env_file() {
  local mode
  [ -f "$ENV_FILE" ] ||
    die "$ENV_FILE is missing: make dev-up (or make run-local) creates it from .env.example"
  mode=$(stat -Lc '%a' "$ENV_FILE")
  if (((8#$mode & 8#077) != 0)); then
    die "refusing $ENV_FILE: mode $mode lets group/other read the secrets in it; chmod 600 $ENV_FILE"
  fi
}

# The published port is the one thing a compose file cannot negotiate: another process on it means
# the container starts, publishes nothing, and ultron keeps calling someone else. Refuse before a
# container exists, naming the port and the two `.env` lines that fix it. Our own running gateway on
# the same port is the one legitimate holder (an idempotent `up`).
require_port_free() {
  local holder
  if container_running &&
    [ "$(podman port "$CONTAINER" 4000/tcp 2>/dev/null | head -n 1)" = "127.0.0.1:$PORT" ]; then
    return 0
  fi
  require_cmd python3 "install python3"
  if python3 - "$PORT" <<'PY'
import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# SO_REUSEADDR is enough to distinguish "someone listens" from "a socket is in TIME_WAIT"; it
# cannot share a listening port, so a successful bind really means the port is free.
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    sock.bind(("127.0.0.1", int(sys.argv[1])))
except OSError:
    sys.exit(1)
finally:
    sock.close()
PY
  then
    return 0
  fi
  holder=$(ss -ltnp 2>/dev/null | awk -v port=":$PORT" 'NR > 1 && $4 ~ port "$" { print $6; exit }' || true)
  die "port $PORT on 127.0.0.1 is already in use${holder:+ by $holder}:
  this gateway publishes 127.0.0.1:$PORT, so that service would keep the port. Put a free port in
  $ENV_FILE and keep the two lines in step:
    $GATEWAY_PORT_ENV=<free port>
    $MODEL_BASE_URL_ENV=http://127.0.0.1:<free port>/v1
  then run make llm-gateway-up again. Nothing was started."
}

# What ultron reads must be this gateway, on the port it publishes. A mismatch would send every call
# somewhere else, so it is refused before a container exists - never discovered on the first call.
require_model_base_url() {
  local wanted="http://127.0.0.1:$PORT/v1" configured
  configured=$(env_value "$MODEL_BASE_URL_ENV" || true)
  [ -n "$configured" ] || return 0
  case $configured in
  "http://127.0.0.1:$PORT/v1" | "http://127.0.0.1:$PORT/v1/" | \
    "http://localhost:$PORT/v1" | "http://localhost:$PORT/v1/") return 0 ;;
  esac
  die "$MODEL_BASE_URL_ENV=$configured does not point at this gateway ($wanted):
  set either one, so the gateway publishes what ultron calls:
    $MODEL_BASE_URL_ENV=$wanted
    $GATEWAY_PORT_ENV=<the port in that URL>
  in $ENV_FILE. Nothing was started."
}

# Sources .env into this process, so render.py sees the values it must hand to the container. The
# same file and the same rule the dev scripts use; nothing here prints a value.
load_env() {
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
}

# `AEGIS_MODEL_API_KEY` is both the key ultron sends and the gateway's master key, so there is no
# second value to keep in sync. An empty one is generated once and written to .env mode 0600: the
# proxy is loopback-only, so a local key is enough. It is never printed, not even its length.
ensure_master_key() {
  local current
  current=$(env_value "$MASTER_KEY_ENV" || true)
  [ -n "$current" ] && return 0
  require_cmd python3 "install python3"
  python3 - "$ENV_FILE" "$MASTER_KEY_ENV" <<'PY' || die "cannot write $MASTER_KEY_ENV to .env"
import os
import secrets
import sys
import tempfile

path, name = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as stream:
    lines = stream.read().splitlines(keepends=True)
matches = [
    index for index, line in enumerate(lines) if line.lstrip("#").strip().startswith(name + "=")
]
assignment = f"{name}=sk-{secrets.token_urlsafe(32)}\n"
if len(matches) == 1:
    lines[matches[0]] = assignment
else:
    # No line, or several (all empty: a non-empty one returns before this runs). One line wins, last.
    lines = [line for index, line in enumerate(lines) if index not in matches]
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    lines.append(assignment)
# Written private from the first byte and swapped in atomically: a half-written .env would hold a
# key that no longer matches the value ultron read at start-up.
handle, temporary = tempfile.mkstemp(dir=os.path.dirname(path) or ".", prefix=".env.")
try:
    with os.fdopen(handle, "w", encoding="utf-8") as stream:
        stream.writelines(lines)
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
except BaseException:
    os.unlink(temporary)
    raise
PY
  chmod 600 "$ENV_FILE"
  log "generated $MASTER_KEY_ENV in .env (mode 600, not printed) - ultron sends the same value"
}

# The owner's config holds no secrets now, so only its existence and ownership matter.
require_owner_config() {
  local owner
  [ -d "$CONFIG_DIR" ] ||
    die "the owner's config directory $CONFIG_DIR is missing:
  mkdir -p $CONFIG_DIR && cp $CONFIG_EXAMPLE $CONFIG_FILE   (then edit the endpoints)"
  [ -f "$CONFIG_FILE" ] ||
    die "$CONFIG_FILE is missing: cp $CONFIG_EXAMPLE $CONFIG_FILE and edit the endpoints"
  [ -r "$CONFIG_FILE" ] || die "$CONFIG_FILE is not readable by $(id -un)"
  owner=$(stat -Lc '%u' "$CONFIG_FILE")
  [ "$owner" = "$(id -u)" ] || die "refusing $CONFIG_FILE: owned by uid $owner, not $(id -u)"
}

# What the container starts from, regenerated so a stale file can never be mounted: the owner's
# endpoints merged over the fixed base, plus the environment subset that document references (read
# out of .env, which `load_env` sourced). Both files carry variable NAMES; only gateway.env carries
# values, mode 0600.
render_and_validate() {
  local -a arguments=(--config "$CONFIG_FILE" --base "$BASE_CONFIG" --out-dir "$RENDER_DIR")
  if [ -n "${AEGIS_MODEL_NAME:-}" ]; then
    # The group ultron asks for and the group the file defines must be the same one.
    arguments+=(--expect-group "$AEGIS_MODEL_NAME")
  fi
  require_cmd python3 "install python3"
  python3 -c 'import yaml' 2>/dev/null ||
    die "python3 needs PyYAML to read $CONFIG_FILE (uv or pip install pyyaml)"
  mkdir -p "$RENDER_DIR"
  chmod 700 "$RENDER_DIR"
  python3 "$RENDER_SCRIPT" "${arguments[@]}" ||
    die "the owner's config was not rendered - nothing was started"
  python3 "$VALIDATE_SCRIPT" "$RENDERED_CONFIG" "$GATEWAY_ENV" ||
    die "the gateway configuration did not pass validation - nothing was started"
}

# The four compose variables: the render directory and env file are what the container is given.
export_gateway_env() {
  export AEGIS_LLM_GATEWAY_RENDER_DIR="$RENDER_DIR" AEGIS_LLM_GATEWAY_ENV_FILE="$GATEWAY_ENV" \
    AEGIS_LLM_GATEWAY_PORT="$PORT" AEGIS_LLM_GATEWAY_PROJECT="$PROJECT"
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

# The configuration a stack is started from. All inputs are covered: the files in the repository
# (compose, image pin, fixed base), the owner's endpoints, and the .env stamp. A changed input means
# the container must be recreated, and `up` says so instead of silently keeping the old one. The
# stamp is size+mtime, not a hash: no hash of a key is written anywhere.
gateway_fingerprint() {
  {
    stack_config_fingerprint "$COMPOSE_FILE" "$IMAGES_FILE" "$CONFIG_FILE" \
      AEGIS_LLM_GATEWAY_PROJECT AEGIS_LLM_GATEWAY_PORT
    sha256sum "$BASE_CONFIG"
    printf 'env=%s\n' "$(stat -Lc '%s:%Y' "$ENV_FILE" 2>/dev/null || echo absent)"
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
  key=$(env_value "$MASTER_KEY_ENV") ||
    die "$MASTER_KEY_ENV is not set in .env - start the gateway with make llm-gateway-up"
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

# The note a changed input deserves, shared by status and reload.
report_drift() {
  local recorded
  recorded=$(sed -n 's/^fingerprint=//p' "$IDENTITY_FILE" 2>/dev/null || true)
  if [ -n "$recorded" ] && [ "$recorded" != "$(gateway_fingerprint)" ]; then
    log "note: config.yaml, base.yaml or .env changed since this container started"
    log "      apply it with: make llm-gateway-reload"
  fi
}
