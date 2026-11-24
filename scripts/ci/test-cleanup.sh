#!/usr/bin/env bash
# Regression check for run-scoped CI cleanup.
#
# The runner is shared, so cleanup.sh must remove only the resources of the same suite AND run.
# This creates throwaway containers/volumes/networks under two suites and two runs, runs the real
# cleanup for one (suite, run), and proves the others survive; then it removes the rest itself.
#
# Run from the contracts workflow before the gate, and by hand: `scripts/ci/test-cleanup.sh`.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_cmd podman

SUFFIX="scope-$$"
SUITE_A="cleanup-test-a"
SUITE_B="cleanup-test-b"
RUN_X="x-$SUFFIX"
RUN_Y="y-$SUFFIX"

CTR_A_X="ctr-$SUITE_A-$RUN_X"
CTR_A_Y="ctr-$SUITE_A-$RUN_Y"
VOL_A_X="vol-$SUITE_A-$RUN_X"
VOL_A_Y="vol-$SUITE_A-$RUN_Y"
VOL_B_X="vol-$SUITE_B-$RUN_X"
NET_A_X="net-$SUITE_A-$RUN_X"
NET_A_Y="net-$SUITE_A-$RUN_Y"

teardown() {
  podman rm -f "$CTR_A_X" "$CTR_A_Y" >/dev/null 2>&1 || true
  podman volume rm -f "$VOL_A_X" "$VOL_A_Y" "$VOL_B_X" >/dev/null 2>&1 || true
  podman network rm -f "$NET_A_X" "$NET_A_Y" >/dev/null 2>&1 || true
}
trap teardown EXIT

create_volume() {
  podman volume create --label "aegis.ci.suite=$1" --label "aegis.ci.run=$2" "$3" >/dev/null
}
create_network() {
  podman network create --label "aegis.ci.suite=$1" --label "aegis.ci.run=$2" "$3" >/dev/null
}
create_container() {
  podman create --name "$3" --label "aegis.ci.suite=$1" --label "aegis.ci.run=$2" \
    "$AEGIS_PG_IMAGE" >/dev/null
}

resource_exists() {
  case $1 in
  container) podman container exists "$2" ;;
  volume) podman volume exists "$2" ;;
  network) podman network exists "$2" ;;
  *)
    printf '[ci] error: unknown resource type %s\n' "$1" >&2
    return 2
    ;;
  esac
}
expect_present() {
  resource_exists "$1" "$2" || die "$1 $2 was removed by another run's cleanup"
}
expect_gone() {
  if resource_exists "$1" "$2"; then
    die "$1 $2 survived cleanup of its own suite+run"
  fi
}

log "cleanup scope: creating suite=$SUITE_A/run=$RUN_X, $SUITE_A/run=$RUN_Y and $SUITE_B/run=$RUN_X"
create_volume "$SUITE_A" "$RUN_X" "$VOL_A_X"
create_volume "$SUITE_A" "$RUN_Y" "$VOL_A_Y"
create_volume "$SUITE_B" "$RUN_X" "$VOL_B_X"
create_network "$SUITE_A" "$RUN_X" "$NET_A_X"
create_network "$SUITE_A" "$RUN_Y" "$NET_A_Y"
create_container "$SUITE_A" "$RUN_X" "$CTR_A_X"
create_container "$SUITE_A" "$RUN_Y" "$CTR_A_Y"

AEGIS_CI_SUITE="$SUITE_A" GITHUB_RUN_ID="$RUN_X" "$CI_DIR/cleanup.sh"

expect_gone container "$CTR_A_X"
expect_gone volume "$VOL_A_X"
expect_gone network "$NET_A_X"
expect_present container "$CTR_A_Y"
expect_present volume "$VOL_A_Y"
expect_present network "$NET_A_Y"
expect_present volume "$VOL_B_X"

# The explicit suite wins over GITHUB_JOB (the workflow sets AEGIS_CI_SUITE), so a run Y cleanup
# under suite A removes A/Y and leaves suite B alone.
AEGIS_CI_SUITE="$SUITE_A" GITHUB_JOB="$SUITE_B" GITHUB_RUN_ID="$RUN_Y" "$CI_DIR/cleanup.sh"

expect_gone container "$CTR_A_Y"
expect_gone volume "$VOL_A_Y"
expect_gone network "$NET_A_Y"
expect_present volume "$VOL_B_X"

# Without an explicit suite, the job id is the suite (how the python/UI gates inherit theirs).
AEGIS_CI_SUITE="" GITHUB_JOB="$SUITE_B" GITHUB_RUN_ID="$RUN_X" "$CI_DIR/cleanup.sh"
expect_gone volume "$VOL_B_X"

log "cleanup scope: PASS (a cleanup removes only its own suite+run)"
