#!/usr/bin/env bash
# Shared helpers for the CI scripts. Source it; do not execute it directly.
#
# The scripts are what .github/workflows/contracts.yml (and, on the integration branch, the
# python/ui workflows) run, and `make ci-local` runs the same code locally. Each job is its own
# suite: containers/volumes/networks are named aegis-ci-<run>-<service> and labelled
# aegis.ci.suite=<GITHUB_JOB> plus aegis.ci.run=<GITHUB_RUN_ID>. scripts/ci/cleanup.sh removes
# only resources carrying BOTH labels, so a finishing job on the shared runner can never delete a
# concurrent job's database or environment. Every password is generated per run - no secret is
# inherited from the host or the workflow.

set -euo pipefail

CI_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$CI_DIR/../.." && pwd)
IMAGES_FILE="$REPO_ROOT/deploy/dev/images.env"

# shellcheck disable=SC1090
set -a
# shellcheck disable=SC1090
. "$IMAGES_FILE"
set +a

# Suite = the workflow job that owns the resources. `contracts`, `python` and `ui` are distinct
# suites, so their always() cleanup steps cannot touch each other; a manual run gets `local`.
# AEGIS_CI_SUITE overrides it for a caller that is not a GitHub job (tests, manual cleanup).
CI_SUITE=${AEGIS_CI_SUITE:-${GITHUB_JOB:-local}}
CI_RUN=${GITHUB_RUN_ID:-local-$$}
CI_SUITE_LABEL="aegis.ci.suite=$CI_SUITE"
CI_RUN_LABEL="aegis.ci.run=$CI_RUN"
CI_JOB=${AEGIS_CI_JOB:-${CI_SUITE}-${CI_RUN}-${GITHUB_RUN_ATTEMPT:-1}}
CI_JOB_LABEL="aegis.ci-job=$CI_JOB"
AEGIS_CI_JOB="$CI_JOB"
AEGIS_CI_VOLUME_LOG=${AEGIS_CI_VOLUME_LOG:-${TMPDIR:-/tmp}/aegis-ci-volumes-${CI_JOB}.txt}
export AEGIS_CI_JOB AEGIS_CI_VOLUME_LOG

[[ -n $CI_SUITE && $CI_SUITE =~ ^[A-Za-z0-9_.-]+$ ]] || {
  printf '[ci] error: invalid CI suite %q (expected A-Za-z0-9_.-)\n' "$CI_SUITE" >&2
  exit 1
}
[[ -n $CI_RUN ]] || {
  printf '[ci] error: empty CI run id\n' >&2
  exit 1
}
[[ -n $CI_JOB && $CI_JOB =~ ^[A-Za-z0-9_.-]+$ ]] || {
  printf '[ci] error: invalid CI job id %q (expected A-Za-z0-9_.-)\n' "$CI_JOB" >&2
  exit 1
}

log() { printf '[ci] %s\n' "$*"; }
die() {
  printf '[ci] error: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing command '$1'${2:+ - $2}"
}

random_password() {
  head -c 32 /dev/urandom | base64 | tr -d '/+=' | cut -c1-24
}

ci_container() { printf 'aegis-ci-%s-%s' "$CI_RUN" "$1"; }

start_container() {
  local name=$1 image=$2
  shift 2
  podman run -d --name "$name" \
    --label "$CI_SUITE_LABEL" --label "$CI_RUN_LABEL" --label "$CI_JOB_LABEL" \
    "$@" "$image" >/dev/null
  log "started $name ($image)"
}

record_container_volumes() {
  local target=$1 vol
  [ -n "$target" ] || return 0
  while IFS= read -r vol; do
    [ -n "$vol" ] || continue
    printf '%s\n' "$vol" >>"$AEGIS_CI_VOLUME_LOG"
  done < <(podman container inspect "$target" \
    --format '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}{{"\n"}}{{end}}{{end}}' 2>/dev/null || true)
}

remove_container() {
  local name=$1
  [ -n "$name" ] || return 0
  record_container_volumes "$name"
  podman rm -f -v "$name" >/dev/null 2>&1 || true
}

check_job_volume_leaks() {
  local label=${1:-ci}
  local -a leaked=()
  local -a containers=()
  local vol ctr
  mapfile -t containers < <(podman ps -aq --filter "label=$CI_JOB_LABEL" 2>/dev/null || true)
  for ctr in "${containers[@]}"; do
    [ -n "$ctr" ] || continue
    record_container_volumes "$ctr"
    leaked+=("container:$ctr")
  done
  while IFS= read -r vol; do
    [ -n "$vol" ] || continue
    leaked+=("labelled:$vol")
  done < <(podman volume ls -q --filter "label=$CI_JOB_LABEL" 2>/dev/null || true)
  if [ -f "$AEGIS_CI_VOLUME_LOG" ]; then
    while IFS= read -r vol; do
      [ -n "$vol" ] || continue
      if podman volume exists "$vol" >/dev/null 2>&1; then
        leaked+=("container-volume:$vol")
      fi
    done < <(sort -u "$AEGIS_CI_VOLUME_LOG")
  fi
  if ((${#leaked[@]})); then
    printf '[ci] error: %s leaked podman volume(s) for %s:\n' "$label" "$CI_JOB_LABEL" >&2
    printf '  - %s\n' "${leaked[@]}" >&2
    return 1
  fi
  log "$label: 0 leaked podman volumes for $CI_JOB_LABEL"
}

# Dumps the last log lines of a container; used from failure traps.
dump_logs() {
  local name=$1
  [ -n "$name" ] || return 0
  printf -- '--- last 40 log lines of %s ---\n' "$name" >&2
  podman logs --tail 40 "$name" >&2 2>&1 || true
}
