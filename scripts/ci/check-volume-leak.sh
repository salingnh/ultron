#!/usr/bin/env bash
# CI guard against leaked anonymous/dangling Podman volumes.
#
#   scripts/ci/check-volume-leak.sh --record   record baseline dangling count into GITHUB_ENV
#   scripts/ci/check-volume-leak.sh [BEFORE]   fail if `podman volume ls -q --filter dangling=true` grew
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_cmd podman

case ${1:-} in
--record)
  count=$(dangling_volume_count)
  if [[ -n ${GITHUB_ENV:-} ]]; then
    printf 'DANGLING_VOLUMES_BEFORE=%s\n' "$count" >>"$GITHUB_ENV"
  fi
  log "recorded dangling podman volumes baseline: $count"
  ;;
*)
  before=${1:-${DANGLING_VOLUMES_BEFORE:-}}
  [[ $before =~ ^[0-9]+$ ]] ||
    die "DANGLING_VOLUMES_BEFORE is missing or non-numeric (got '$before'); run --record first"
  check_dangling_volume_growth "$before" "ci job"
  ;;
esac
