#!/usr/bin/env bash
# Job-scoped CI guard against leaked Podman volumes.
#
#   scripts/ci/check-volume-leak.sh --record   export AEGIS_CI_JOB and volume log path into GITHUB_ENV
#   scripts/ci/check-volume-leak.sh            fail if any volume/container of AEGIS_CI_JOB survived
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_cmd podman

case ${1:-} in
--record)
  : >"$AEGIS_CI_VOLUME_LOG"
  if [[ -n ${GITHUB_ENV:-} ]]; then
    printf 'AEGIS_CI_JOB=%s\n' "$AEGIS_CI_JOB" >>"$GITHUB_ENV"
    printf 'AEGIS_CI_VOLUME_LOG=%s\n' "$AEGIS_CI_VOLUME_LOG" >>"$GITHUB_ENV"
  fi
  log "recorded job-scoped volume guard: $CI_JOB_LABEL"
  ;;
"")
  status=0
  check_job_volume_leaks "ci job" || status=$?
  rm -f "$AEGIS_CI_VOLUME_LOG"
  exit "$status"
  ;;
*)
  die "usage: check-volume-leak.sh [--record]"
  ;;
esac
