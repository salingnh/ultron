#!/usr/bin/env bash
# Ephemeral self-hosted runner loop for this repository (label `ultron-local`).
#
# Each iteration registers a one-job runner with a fresh work folder, runs exactly one job
# and lets the registration expire, so no job can read the workspace, env or git refs left
# by another job. The registration token is fetched with the operator's `gh` login at run
# time; no token, PAT or other secret is stored in the unit or in this repository.
#
# Started by ultron-runner.service (scripts/ci/install-runner.sh); run it directly only for
# debugging, from the runner directory.
set -uo pipefail

RUNNER_DIR=${ULTRON_RUNNER_DIR:-$HOME/ultron-runner}
REPO=${ULTRON_REPO:-salingnh/ultron}
LABEL=${ULTRON_RUNNER_LABEL:-ultron-local}
RETRY_TOKEN=${ULTRON_RUNNER_TOKEN_RETRY:-60}
RETRY_REGISTER=${ULTRON_RUNNER_REGISTER_RETRY:-30}

log() { printf '[runner %s] %s\n' "$(date -u +%FT%TZ)" "$*" >&2; }

cd "$RUNNER_DIR" 2>/dev/null || {
  log "runner directory $RUNNER_DIR is missing - run scripts/ci/install-runner.sh"
  exit 1
}

runner_pid=
stop() {
  trap - TERM INT
  log "stopping"
  [ -n "$runner_pid" ] && kill -TERM "$runner_pid" 2>/dev/null
  [ -n "$runner_pid" ] && wait "$runner_pid" 2>/dev/null
  exit 0
}
trap stop TERM INT

while :; do
  if ! token=$(gh api -X POST "repos/$REPO/actions/runners/registration-token" --jq .token 2>/dev/null); then
    log "cannot get a registration token for $REPO (is 'gh auth login' still valid?); retry in ${RETRY_TOKEN}s"
    sleep "$RETRY_TOKEN"
    continue
  fi

  # A runner directory must never adopt another repository's registration: on a shared
  # machine ~/actions-runner can already belong to a different repo.
  if [ -f "$RUNNER_DIR/.runner" ]; then
    configured_url=$(sed -n 's/.*"gitHubUrl": "\([^"]*\)".*/\1/p' "$RUNNER_DIR/.runner" | head -1)
    if [ -n "$configured_url" ] && [ "$configured_url" != "https://github.com/$REPO" ]; then
      log "refusing to use $RUNNER_DIR: it is registered for $configured_url, not https://github.com/$REPO"
      exit 1
    fi
    # A previous run was interrupted between config.sh and run.sh (or a job killed the
    # runner): config.sh refuses to run again until the stale registration is removed.
    log "clearing the stale registration left in $RUNNER_DIR"
    ./config.sh remove --token "$token" >/dev/null 2>&1 ||
      log "config.sh remove failed; dropping the local credentials instead"
    rm -f "$RUNNER_DIR/.runner" "$RUNNER_DIR/.credentials" "$RUNNER_DIR/.credentials_rsaparams"
  fi

  # A fresh work folder per registration: nothing from the previous job survives.
  rm -rf "$RUNNER_DIR/_work"

  if ! ./config.sh --unattended \
    --url "https://github.com/$REPO" \
    --token "$token" \
    --name "ultron-local-$(date -u +%s)-$RANDOM" \
    --labels "$LABEL" \
    --ephemeral \
    --work _work; then
    log "runner registration failed; retry in ${RETRY_REGISTER}s"
    sleep "$RETRY_REGISTER"
    continue
  fi

  log "registered a one-job runner; waiting for a job"
  ./run.sh &
  runner_pid=$!
  wait "$runner_pid"
  status=$?
  runner_pid=
  log "job finished (exit $status); registering the next runner"
  sleep 5
done
