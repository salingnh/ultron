#!/usr/bin/env bash
# Shared helpers for the CI scripts. Source it; do not execute it directly.
#
# The scripts are what .github/workflows/contracts.yml runs, and `make ci-local` runs the
# same code locally. Each one owns its containers: they are named aegis-ci-<run>-<service>,
# labelled aegis.ci.suite=contracts (scripts/ci/cleanup.sh removes them), and every
# password is generated per run - no secret is inherited from the host or the workflow.

set -euo pipefail

CI_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$CI_DIR/../.." && pwd)
IMAGES_FILE="$REPO_ROOT/deploy/dev/images.env"

# shellcheck disable=SC1090
set -a
# shellcheck disable=SC1090
. "$IMAGES_FILE"
set +a

CI_RUN=${GITHUB_RUN_ID:-local-$$}
CI_SUITE_LABEL=aegis.ci.suite=contracts

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
    --label "$CI_SUITE_LABEL" --label "aegis.ci.run=$CI_RUN" \
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
