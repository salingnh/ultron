#!/usr/bin/env bash
# Shared helpers for scripts/vulnlab/*.sh. Source it; do not execute it directly.
#
# Everything here operates on this checkout's vulnlab compose project (`aegis-vulnlab` by default,
# or `AEGIS_VULNLAB_PROJECT` from .env/environment), its networks `<project>-net` / `<project>-egress`,
# the external lab network `aegis-lab-lab` and one-shot probe containers labelled
# `aegis.vulnlab=<project>-run`. Nothing outside that is inspected, started or removed.
#
# Two rules this file exists for (both learned on a shared host):
#   * a stack belongs to the checkout that created it (scripts/lib/stack.sh); this checkout only
#     starts/removes its own project, and one vulnlab stack exists per host because the origins use
#     fixed addresses on the shared lab network;
#   * publishing the vulnerable origins is an explicit opt-in: the Cloudflare Tunnel starts only
#     with VULNLAB_TUNNEL=1 (or PROFILE=internet), never just because a token file exists, and at
#     most one vulnlab stack on the host may hold the tunnel.
#
# The auto-stop is armed here: every `podman run` podman-compose issues for this project carries
# `--timeout <VULNLAB_TTL_MINUTES * 60>`, so podman (not a shell, not a cron, not somebody's
# memory) stops the containers after the TTL. `vulnlab-status` reads the value back from every
# container and fails when a container was created without it.
set -euo pipefail

# shellcheck disable=SC2034 # several of these are used by the sourcing scripts
VULNLAB_SCRIPTS=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC2034
REPO_ROOT=$(cd "$VULNLAB_SCRIPTS/../.." && pwd)
VULNLAB_DIR="$REPO_ROOT/deploy/vulnlab"
COMPOSE_FILE="$VULNLAB_DIR/compose.yaml"
IMAGES_FILE="$VULNLAB_DIR/images.env"
ENV_EXAMPLE="$VULNLAB_DIR/.env.example"
ENV_FILE="${AEGIS_VULNLAB_ENV:-$VULNLAB_DIR/.env}"
RUN_DIR="$VULNLAB_DIR/.run"
CATALOG_FILE="$REPO_ROOT/tests/vulnlab/cases.yaml"
# The tunnel token is deployment state, not repository state: a 0600 file outside the checkout, or
# AEGIS_VULNLAB_TUNNEL_TOKEN_FILE pointing at one. The default is used only when it exists.
DEFAULT_TUNNEL_TOKEN_FILE=${AEGIS_VULNLAB_TUNNEL_TOKEN_FILE_DEFAULT:-/home/admin/.config/ultron/vulnlab-tunnel.token}
TUNNEL_TOKEN_SOURCE=none
VULNLAB_TUNNEL_REQUESTED=no
# Set by set_vulnlab_names(); declared here so `set -u` is happy on a partial source.
VULNLAB_PROJECT=aegis-vulnlab
VULNLAB_NETWORK=aegis-vulnlab-net
VULNLAB_EGRESS=aegis-vulnlab-egress
VULNLAB_LABEL=aegis.vulnlab=aegis-vulnlab-run
VULNLAB_TUNNEL_CONTAINER=aegis-vulnlab-cloudflared
VULNLAB_IDENTITY="$RUN_DIR/identity"

# shellcheck source=scripts/lib/stack.sh
. "$VULNLAB_SCRIPTS/../lib/stack.sh"
LAB_NETWORK=aegis-lab-lab

log() { printf '[vulnlab] %s\n' "$*"; }
die() {
  printf '[vulnlab] error: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing command '$1'${2:+ - $2}"
}

# Image pins are repository state (deploy/vulnlab/images.env), never taken from .env.
load_images() {
  [ -f "$IMAGES_FILE" ] || die "missing $IMAGES_FILE"
  set -a
  # shellcheck disable=SC1090
  . "$IMAGES_FILE"
  set +a
  : "${AEGIS_VULNLAB_HTTPD_IMAGE:?images.env: AEGIS_VULNLAB_HTTPD_IMAGE missing}"
  : "${AEGIS_VULNLAB_NGINX_IMAGE:?images.env: AEGIS_VULNLAB_NGINX_IMAGE missing}"
  : "${AEGIS_VULNLAB_TOMCAT_IMAGE:?images.env: AEGIS_VULNLAB_TOMCAT_IMAGE missing}"
  : "${AEGIS_VULNLAB_SPRING_IMAGE:?images.env: AEGIS_VULNLAB_SPRING_IMAGE missing}"
  : "${AEGIS_VULNLAB_JENKINS_IMAGE:?images.env: AEGIS_VULNLAB_JENKINS_IMAGE missing}"
  : "${AEGIS_VULNLAB_JETTY_IMAGE:?images.env: AEGIS_VULNLAB_JETTY_IMAGE missing}"
  : "${AEGIS_VULNLAB_STRUTS2_IMAGE:?images.env: AEGIS_VULNLAB_STRUTS2_IMAGE missing}"
  : "${AEGIS_VULNLAB_CLOUDFLARED_IMAGE:?images.env: AEGIS_VULNLAB_CLOUDFLARED_IMAGE missing}"
  : "${AEGIS_VULNLAB_PROBE_IMAGE:?images.env: AEGIS_VULNLAB_PROBE_IMAGE missing}"
}

# The operator's copy of the variables (hostnames, project name, TTL, the publishing switch). It
# never holds the token: that lives in a 0600 file outside the repo (see resolve_tunnel_token).
# Created from the example on first use.
#
# An explicit environment value wins over the file: `VULNLAB_TUNNEL=1 make vulnlab-up` must publish
# even when .env says 0, which is not how a bare `set -a; . .env` behaves.
load_env() {
  if [ ! -f "$ENV_FILE" ]; then
    cp "$ENV_EXAMPLE" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    log "created $ENV_FILE from .env.example (mode 600) - replace the example hostnames; the"
    log "tunnel token belongs in a 0600 file (AEGIS_VULNLAB_TUNNEL_TOKEN_FILE), not in .env"
  fi
  local raw name
  local -a names=()
  local -A saved=()
  while IFS= read -r raw || [ -n "$raw" ]; do
    case $raw in '' | \#*) continue ;; esac
    name=${raw%%=*}
    case $name in '' | *[!A-Za-z0-9_]*) continue ;; esac
    names+=("$name")
    if [ -n "${!name+x}" ]; then saved[$name]=${!name}; fi
  done <"$ENV_FILE"
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
  for name in "${!saved[@]}"; do
    export "$name=${saved[$name]}"
  done
}

# The TTL is the stack's own stop condition: an integer number of minutes, bounded so a typo cannot
# leave vulnerable services running for a week.
load_ttl() {
  local minutes=${VULNLAB_TTL_MINUTES:-120}
  case $minutes in
  '' | *[!0-9]*) die "VULNLAB_TTL_MINUTES must be an integer number of minutes, got '$minutes'" ;;
  esac
  if [ "$minutes" -lt 1 ] || [ "$minutes" -gt 1440 ]; then
    die "VULNLAB_TTL_MINUTES must be between 1 and 1440, got $minutes"
  fi
  VULNLAB_TTL_MINUTES=$minutes
  VULNLAB_TTL_SECONDS=$((minutes * 60))
}

# Resolves the token once, checking the file contract before reading a byte. An explicit path that
# is missing, unreadable, not owned by this user or accessible by group/other is an error - never a
# silent fallback to the environment. Precedence: explicit file > default file (when present) >
# AEGIS_VULNLAB_TUNNEL_TOKEN in the environment (kept for compatibility, discouraged). The value is
# exported for compose interpolation and is never printed by any script here.
resolve_tunnel_token() {
  local file=${AEGIS_VULNLAB_TUNNEL_TOKEN_FILE:-}
  if [ -z "$file" ] && [ -f "$DEFAULT_TUNNEL_TOKEN_FILE" ]; then
    file=$DEFAULT_TUNNEL_TOKEN_FILE
  fi
  if [ -n "$file" ]; then
    [ -f "$file" ] ||
      die "tunnel token file $file does not exist: set AEGIS_VULNLAB_TUNNEL_TOKEN_FILE to a 0600 file"
    [ -r "$file" ] || die "tunnel token file $file is not readable by $(id -un)"
    local mode owner
    mode=$(stat -Lc '%a' "$file")
    if (( (8#$mode & 8#077) != 0 )); then
      die "refusing tunnel token file $file: mode $mode is group/world-readable; chmod 600 $file"
    fi
    owner=$(stat -Lc '%u' "$file")
    if [ "$owner" != "$(id -u)" ]; then
      die "refusing tunnel token file $file: owned by uid $owner, not $(id -u)"
    fi
    AEGIS_VULNLAB_TUNNEL_TOKEN=$(tr -d '\r\n' <"$file")
    TUNNEL_TOKEN_SOURCE="file $file"
  elif [ -n "${AEGIS_VULNLAB_TUNNEL_TOKEN:-}" ]; then
    TUNNEL_TOKEN_SOURCE="environment"
  else
    TUNNEL_TOKEN_SOURCE=none
    return 0
  fi
  case ${AEGIS_VULNLAB_TUNNEL_TOKEN:-} in
  '') die "tunnel token from $TUNNEL_TOKEN_SOURCE is empty" ;;
  *[[:space:]]*) die "tunnel token from $TUNNEL_TOKEN_SOURCE contains whitespace: save it as one line" ;;
  esac
  export AEGIS_VULNLAB_TUNNEL_TOKEN
}

# --- this checkout's stack --------------------------------------------------------------------
# The project name and everything derived from it. `AEGIS_VULNLAB_PROJECT` comes from .env (loaded
# by load_env) or the environment. The prefix is required: the host-wide scans below recognise a
# vulnlab stack by its compose project label whatever checkout named it.
set_vulnlab_names() {
  local project=${AEGIS_VULNLAB_PROJECT:-aegis-vulnlab}
  case $project in
  aegis-vulnlab | aegis-vulnlab-?*) ;;
  *) die "AEGIS_VULNLAB_PROJECT must start with aegis-vulnlab (got '$project')" ;;
  esac
  VULNLAB_PROJECT=$project
  export AEGIS_VULNLAB_PROJECT=$VULNLAB_PROJECT
  VULNLAB_NETWORK="$VULNLAB_PROJECT-net"
  VULNLAB_EGRESS="$VULNLAB_PROJECT-egress"
  VULNLAB_LABEL="aegis.vulnlab=$VULNLAB_PROJECT-run"
  VULNLAB_TUNNEL_CONTAINER="$VULNLAB_PROJECT-cloudflared"
  VULNLAB_IDENTITY="$RUN_DIR/identity"
}

vulnlab_stack_fingerprint() {
  # The files that define the stack plus the project name. Operational values (public hostnames,
  # TTL, the tunnel toggle) are handled explicitly below, so turning the tunnel on or off is not a
  # "configuration changed, recreate with AEGIS_STACK_RECREATE=1" event.
  stack_config_fingerprint "$COMPOSE_FILE" "$IMAGES_FILE" "$RUN_DIR/.no-env-file" \
    AEGIS_VULNLAB_PROJECT
}

vulnlab_stack_verdict() {
  stack_verdict "$VULNLAB_PROJECT" "$VULNLAB_DIR" "$COMPOSE_FILE" \
    "$(vulnlab_stack_fingerprint)" "$VULNLAB_IDENTITY"
}

record_vulnlab_stack_identity() {
  record_stack_identity "$VULNLAB_IDENTITY" "$VULNLAB_PROJECT" "$VULNLAB_DIR" \
    "$(vulnlab_stack_fingerprint)"
}

# A stack belongs to the checkout that created it. Start/remove only our own project; another
# checkout's project may be inspected but never recreated or removed (scripts/lib/stack.sh).
require_vulnlab_stack_ownership() {
  [ -n "$(stack_containers "$VULNLAB_PROJECT" | head -n 1 || true)" ] || return 0
  local verdict
  verdict=$(vulnlab_stack_verdict)
  case $verdict in
  ours | absent) return 0 ;;
  config:*)
    if [ "${AEGIS_STACK_RECREATE:-0}" = 1 ]; then
      log "stack: configuration changed since this stack started - recreating its containers"
      return 0
    fi
    die "compose project $VULNLAB_PROJECT exists with a different configuration (${verdict#config:}).
  This stack was started from the same checkout but other files. Recreate it with:
    AEGIS_STACK_RECREATE=1 make vulnlab-up"
    ;;
  other:*)
    if [ "${AEGIS_STACK_FORCE:-0}" = 1 ]; then
      log "stack: belongs to ${verdict#other:} - AEGIS_STACK_FORCE=1, touching it anyway"
      return 0
    fi
    die "compose project $VULNLAB_PROJECT belongs to another checkout: ${verdict#other:}
  A vulnlab stack belongs to the checkout that created it. Use it read-only (make vulnlab-check) or
  ask its owner to stop it (make vulnlab-down in that checkout). AEGIS_STACK_FORCE=1 overrides this
  only for a stack you know is disposable."
    ;;
  unknown:*)
    if [ "${AEGIS_STACK_FORCE:-0}" = 1 ]; then
      return 0
    fi
    die "compose project $VULNLAB_PROJECT exists but its owner cannot be proven (${verdict#unknown:}).
  Refusing to touch it; AEGIS_STACK_FORCE=1 overrides."
    ;;
  esac
}

# One vulnlab stack per host: every origin joins `aegis-lab-lab` with fixed addresses from the
# catalog (10.114.53.61-.67), so a second stack cannot start even with another project name.
vulnlab_projects_on_host() {
  podman ps -a --format '{{.Label "io.podman.compose.project"}}' |
    grep -E '^aegis-vulnlab(-[a-z0-9-]+)?$' | sort -u
}

require_no_other_vulnlab_stack() {
  local project
  while IFS= read -r project; do
    [ -n "$project" ] || continue
    [ "$project" = "$VULNLAB_PROJECT" ] && continue
    die "another vulnlab stack exists on this host (project $project).
  The origins use fixed addresses on the shared lab network, so only one vulnlab stack may exist
  per host. Use the running one (make vulnlab-status / vulnlab-check) or ask its owner to stop it
  (make vulnlab-down in that checkout)."
  done < <(vulnlab_projects_on_host)
}

# At most one tunnel-enabled stack per host: the Cloudflare Tunnel is a host-wide resource (the
# public hostnames point at one origin set), so refuse to start a second cloudflared.
tunnel_containers_on_host() {
  {
    podman ps --filter status=running --filter label=aegis.vulnlab.role=cloudflared \
      --format '{{.Names}}'
    # Stacks created before the role label existed: the name is still enough to recognise them.
    podman ps --filter status=running --format '{{.Names}}' |
      grep -E '^aegis-vulnlab(-[a-z0-9-]+)?-cloudflared$' || true
  } | sort -u
}

require_tunnel_slot() {
  local name
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    [ "$name" = "$VULNLAB_TUNNEL_CONTAINER" ] && continue
    die "another vulnlab stack already has the Cloudflare Tunnel up ($name).
  Only one tunnel-enabled vulnlab stack may run per host. Stop it there (make vulnlab-down) before
  enabling VULNLAB_TUNNEL here."
  done < <(tunnel_containers_on_host)
}

# --- publishing is explicit -------------------------------------------------------------------
# The tunnel starts only when asked for (VULNLAB_TUNNEL=1, or PROFILE=internet for the campaign
# runner); a token file that merely exists must never publish the origins by itself.
resolve_tunnel_request() {
  local requested=no
  if [ "${PROFILE:-}" = internet ]; then requested=yes; fi
  case ${VULNLAB_TUNNEL:-0} in
  0 | false | no | off | '') ;;
  1 | true | yes | on) requested=yes ;;
  *) die "VULNLAB_TUNNEL must be 1/true/yes/on or 0/false/no/off (got '${VULNLAB_TUNNEL}')" ;;
  esac
  VULNLAB_TUNNEL_REQUESTED=$requested
}

tunnel_requested() { [ "$VULNLAB_TUNNEL_REQUESTED" = yes ]; }

tunnel_enabled() { tunnel_requested && [ "${TUNNEL_TOKEN_SOURCE:-none}" != "none" ]; }

tunnel_token_file_hint() {
  local file=${AEGIS_VULNLAB_TUNNEL_TOKEN_FILE:-}
  [ -n "$file" ] || file=$DEFAULT_TUNNEL_TOKEN_FILE
  if [ -f "$file" ]; then
    printf 'token file present at %s' "$file"
  else
    printf 'no token file at %s' "$file"
  fi
}

tunnel_state() {
  if tunnel_requested; then
    if tunnel_enabled; then
      printf 'ON (project %s; token from %s)' "$VULNLAB_PROJECT" "$TUNNEL_TOKEN_SOURCE"
    else
      printf 'requested but NO TOKEN (%s)' "$(tunnel_token_file_hint)"
    fi
  else
    printf 'OFF (VULNLAB_TUNNEL is not set; %s - set VULNLAB_TUNNEL=1 to publish)' \
      "$(tunnel_token_file_hint)"
  fi
}

# podman-compose with the auto-stop armed. `--podman-run-args` is applied to every `podman run` the
# provider issues for this project; the compose file itself cannot express `--timeout`.
compose() {
  local args=(-p "$VULNLAB_PROJECT" -f "$COMPOSE_FILE" --podman-run-args "--timeout $VULNLAB_TTL_SECONDS")
  if tunnel_enabled; then
    args+=(--profile tunnel)
  fi
  AEGIS_VULNLAB_PROJECT="$VULNLAB_PROJECT" podman-compose "${args[@]}" "$@"
}

container_exists() { podman container exists "$1" 2>/dev/null; }

container_running() {
  container_exists "$1" && [ "$(podman inspect --format '{{.State.Running}}' "$1")" = true ]
}

require_rootless() {
  if ! podman info --format '{{.Host.Security.Rootless}}' | grep -qx true; then
    die "podman is not rootless; the CVE lab must run as the current user"
  fi
}

require_lab_network() {
  podman network inspect "$LAB_NETWORK" >/dev/null 2>&1 ||
    die "lab network $LAB_NETWORK is missing: run 'make lab-up' first (the vulnlab joins it so a lab-profile job can reach the origins)"
}

# Project containers as `name<TAB>timeout-seconds`; used by up (drift) and status.
project_containers() {
  podman ps -a --filter "label=io.podman.compose.project=$VULNLAB_PROJECT" --format '{{.Names}}'
}

project_timeout() { # <container>
  podman inspect --format '{{if .Config.Timeout}}{{.Config.Timeout}}{{else}}0{{end}}' "$1" 2>/dev/null
}

# Case containers of the catalog (bash view), one `id address port path` line per case.
catalog_lab_targets() {
  python3 - "$CATALOG_FILE" <<'PY'
import sys

import yaml

document = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
for case in document["cases"]:
    print(f"{case['id']}\t{case['lab']['address']}\t{case['lab']['port']}\t{case['request']['path']}")
PY
}
