#!/usr/bin/env bash
# One compose project on a shared host: who created it, with which configuration, and may this
# checkout touch it. Source it; do not execute it directly.
#
# The incident this file exists for: several workers share this machine, each with its own
# worktree of the same repository. A worker ran `make run-local` from its worktree; `dev-up` saw the
# project `aegis-dev` and recreated the containers from *its* compose file (different paths for the
# bind mounts), killing the owner's walkthrough stack. Nothing checked who owned the project.
#
# The rule now: a stack belongs to the checkout that created it, identified by the labels
# `podman-compose` puts on every container (`com.docker.compose.project.working_dir` and
# `...config_files`, also under their `io.podman.compose` names depending on the compose version)
# plus a configuration fingerprint recorded in the checkout when the stack was started
# (`.local/stack.identity`, `deploy/lab/.run/identity`). A checkout may only start or remove a stack
# it owns; to share the host, a checkout gives itself its own project name (`AEGIS_DEV_PROJECT` /
# `AEGIS_LAB_PROJECT`) and free ports in `.env`.
#
# Two explicit escape hatches, both printed in the refusal message:
#   AEGIS_STACK_RECREATE=1  recreate the containers of *our* project after a config change
#                           (volumes kept) - a deliberate action, never a silent one;
#   AEGIS_STACK_FORCE=1     touch a stack another checkout owns - only for a stack known to be
#                           disposable (the owner abandoned it).

set -euo pipefail

STACK_VERDICT_ABSENT=absent
STACK_VERDICT_OURS=ours

# The project's containers, one name per line (empty when the project does not exist).
stack_containers() {
  podman ps -a --filter "label=io.podman.compose.project=$1" --format '{{.Names}}'
}

# One label of one container; empty when podman cannot read it.
stack_label() {
  podman inspect --format "{{index .Config.Labels \"$2\"}}" "$1" 2>/dev/null || true
}

# Fingerprint of the configuration a stack is started from: the files that define it plus the
# values a checkout may vary (project name, ports). A change means "this stack would be recreated".
stack_config_fingerprint() {
  local compose_file=$1 images_file=$2 env_file=$3
  shift 3
  local name
  {
    sha256sum "$compose_file" "$images_file"
    if [ -f "$env_file" ]; then sha256sum "$env_file"; else echo "no-env"; fi
    for name in "$@"; do printf '%s=%s\n' "$name" "${!name:-}"; done
  } | sha256sum | cut -d' ' -f1
}

# stack_verdict <project> <expected working dir> <expected compose file> <fingerprint> \
#               <identity file>
# Prints one of: absent | ours | other:<working dir> | config:<recorded fingerprint>
#               | unknown:<container>
stack_verdict() {
  local project=$1 expected_dir=$2 expected_file=$3 fingerprint=$4 identity=$5
  local container actual_dir actual_files recorded
  container=$(stack_containers "$project" | head -n 1 || true)
  if [ -z "$container" ]; then
    printf '%s\n' "$STACK_VERDICT_ABSENT"
    return 0
  fi
  # podman-compose 1.6 writes the docker-compose label names (config_files is relative to
  # working_dir); other versions write the io.podman ones. Either identifies the checkout.
  actual_dir=$(stack_label "$container" com.docker.compose.project.working_dir)
  [ -n "$actual_dir" ] || actual_dir=$(stack_label "$container" io.podman.compose.project.working_dir)
  actual_files=$(stack_label "$container" com.docker.compose.project.config_files)
  [ -n "$actual_files" ] || actual_files=$(stack_label "$container" io.podman.compose.project.config_files)
  case $actual_files in
  /*) ;;
  *)
    if [ -n "$actual_files" ] && [ -n "$actual_dir" ]; then
      actual_files="$actual_dir/$actual_files"
    fi
    ;;
  esac
  if [ -z "$actual_dir" ] || [ -z "$actual_files" ]; then
    printf 'unknown:%s\n' "$container"
    return 0
  fi
  if [ "$actual_dir" != "$expected_dir" ] || [ "$actual_files" != "$expected_file" ]; then
    printf 'other:%s\n' "$actual_dir"
    return 0
  fi
  if [ -f "$identity" ]; then
    recorded=$(sed -n 's/^fingerprint=//p' "$identity")
    if [ -n "$recorded" ] && [ "$recorded" != "$fingerprint" ]; then
      printf 'config:%s\n' "$recorded"
      return 0
    fi
  fi
  printf '%s\n' "$STACK_VERDICT_OURS"
}

# require_stack_ownership <stack label> <project> <expected working dir> <expected compose file> \
#                         <fingerprint> <identity file> <project-name env var>
# Exits non-zero unless this checkout may start (or remove) the project.
require_stack_ownership() {
  local label=$1 project=$2 expected_dir=$3 expected_file=$4 fingerprint=$5
  local identity=$6 project_env=$7
  [ -n "$(stack_containers "$project" | head -n 1 || true)" ] || return 0
  local verdict
  verdict=$(stack_verdict "$project" "$expected_dir" "$expected_file" "$fingerprint" "$identity")
  case $verdict in
  ours | absent) return 0 ;;
  config:*)
    if [ "${AEGIS_STACK_RECREATE:-0}" = 1 ]; then
      printf '[stack] %s: configuration changed since this stack started - recreating its containers (volumes kept)\n' \
        "$project" >&2
      return 0
    fi
    printf '[stack] error: compose project %s exists with a different configuration (%s)\n' \
      "$project" "$verdict" >&2
    printf '  This stack was started from the same checkout but other files/values. Recreate it with:\n' >&2
    printf '    AEGIS_STACK_RECREATE=1 make %s-up    (containers recreated, volumes kept)\n' "$label" >&2
    printf '    make %s-reset                        (dev only: volumes removed, clean database)\n' "$label" >&2
    exit 1
    ;;
  other:*)
    if [ "${AEGIS_STACK_FORCE:-0}" = 1 ]; then
      printf '[stack] %s: owned by %s - AEGIS_STACK_FORCE=1, touching it anyway\n' \
        "$project" "${verdict#other:}" >&2
      return 0
    fi
    printf '[stack] error: compose project %s belongs to another checkout: %s\n' \
      "$project" "${verdict#other:}" >&2
    printf '  A stack on this host belongs to the checkout that created it; this one must not start\n' >&2
    printf '  or remove it. Give this checkout its own stack, in .env:\n' >&2
    printf '    %s=%s-%s   plus a free port for every published port\n' \
      "$project_env" "$project" "$(basename "$(cd "$expected_dir/../.." && pwd)")" >&2
    printf '  (AEGIS_STACK_FORCE=1 overrides this - only for a stack you know is disposable.)\n' >&2
    exit 1
    ;;
  unknown:*)
    if [ "${AEGIS_STACK_FORCE:-0}" = 1 ]; then
      return 0
    fi
    printf '[stack] error: compose project %s exists but its owner cannot be proven (container %s\n' \
      "$project" "${verdict#unknown:}" >&2
    printf '  carries no compose labels). Refusing to touch it; AEGIS_STACK_FORCE=1 overrides.\n' >&2
    exit 1
    ;;
  esac
}

# record_stack_identity <identity file> <project> <working dir> <fingerprint>
record_stack_identity() {
  local identity=$1 project=$2 dir=$3 fingerprint=$4
  mkdir -p "$(dirname "$identity")"
  {
    printf 'project=%s\n' "$project"
    printf 'working_dir=%s\n' "$dir"
    printf 'fingerprint=%s\n' "$fingerprint"
    printf 'recorded_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >"$identity"
}
