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

[[ -n $CI_SUITE && $CI_SUITE =~ ^[A-Za-z0-9_.-]+$ ]] || {
  printf '[ci] error: invalid CI suite %q (expected A-Za-z0-9_.-)\n' "$CI_SUITE" >&2
  exit 1
}
[[ -n $CI_RUN ]] || {
  printf '[ci] error: empty CI run id\n' >&2
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
    --label "$CI_SUITE_LABEL" --label "$CI_RUN_LABEL" \
    "$@" "$image" >/dev/null
  log "started $name ($image)"
}

remove_container() {
  local name=$1
  podman rm -f "$name" >/dev/null 2>&1 || true
}

# Dumps the last log lines of a container; used from failure traps.
dump_logs() {
  local name=$1
  [ -n "$name" ] || return 0
  printf -- '--- last 40 log lines of %s ---\n' "$name" >&2
  podman logs --tail 40 "$name" >&2 2>&1 || true
}
