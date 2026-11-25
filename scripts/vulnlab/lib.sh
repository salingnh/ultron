#!/usr/bin/env bash
# Shared helpers for scripts/vulnlab/*.sh. Source it; do not execute it directly.
#
# Everything here operates on compose project `aegis-vulnlab` (deploy/vulnlab/compose.yaml), its
# networks `aegis-vulnlab-net` / `aegis-vulnlab-egress`, the external lab network `aegis-lab-lab`
# and one-shot probe containers labelled `aegis.vulnlab=aegis-vulnlab-run`. Nothing outside that is
# inspected, started or removed.
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
TUNNEL_DIR="$RUN_DIR/cloudflared"
CATALOG_FILE="$REPO_ROOT/tests/vulnlab/cases.yaml"

VULNLAB_PROJECT=aegis-vulnlab
VULNLAB_LABEL=aegis.vulnlab=aegis-vulnlab-run
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

# The operator's copy of the variables. Created from the example on first use (mode 600: it will
# hold the tunnel token) and exported for compose interpolation and the python helpers.
load_env() {
  if [ ! -f "$ENV_FILE" ]; then
    cp "$ENV_EXAMPLE" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    log "created $ENV_FILE from .env.example (mode 600) - replace the example hostnames and add"
    log "AEGIS_VULNLAB_TUNNEL_TOKEN only if the tunnel was created by the owner"
  fi
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
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

tunnel_enabled() {
  [ -n "${AEGIS_VULNLAB_TUNNEL_TOKEN:-}" ]
}

tunnel_state() {
  if tunnel_enabled; then printf 'enabled'; else printf 'disabled (AEGIS_VULNLAB_TUNNEL_TOKEN is empty)'; fi
}

# podman-compose with the auto-stop armed. `--podman-run-args` is applied to every `podman run` the
# provider issues for this project; the compose file itself cannot express `--timeout`.
compose() {
  local args=(-p "$VULNLAB_PROJECT" -f "$COMPOSE_FILE" --podman-run-args "--timeout $VULNLAB_TTL_SECONDS")
  if tunnel_enabled; then
    args+=(--profile tunnel)
  fi
  podman-compose "${args[@]}" "$@"
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
