#!/usr/bin/env bash
# Removes the runner installed by scripts/ci/install-runner.sh:
#   1. disables and stops ultron-runner.service and removes its unit file;
#   2. deletes any `ultron-local-*` runner still registered on the repository;
#   3. deletes ~/actions-runner (pass --keep to leave the binaries in place).
#
# It touches nothing else on the host: no system unit, no package, no dev containers.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

REPO_SLUG=${ULTRON_REPO:-salingnh/ultron}
RUNNER_DIR=${ULTRON_RUNNER_DIR:-$HOME/actions-runner}
UNIT_NAME=ultron-runner.service
UNIT_PATH=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/$UNIT_NAME
KEEP=0
[ "${1:-}" = --keep ] && KEEP=1

require_cmd systemctl

if systemctl --user cat "$UNIT_NAME" >/dev/null 2>&1; then
  log "stopping and disabling $UNIT_NAME"
  systemctl --user disable --now "$UNIT_NAME" >/dev/null 2>&1 || true
fi
rm -f "$UNIT_PATH"
systemctl --user daemon-reload

if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  mapfile -t runner_ids < <(gh api "repos/$REPO_SLUG/actions/runners?per_page=100" \
    --jq '.runners[] | select(.name | startswith("ultron-local-")) | .id' 2>/dev/null || true)
  for id in "${runner_ids[@]}"; do
    gh api -X DELETE "repos/$REPO_SLUG/actions/runners/$id" >/dev/null &&
      log "removed registered runner id $id"
  done
else
  log "gh is not logged in - skipped removing runner registrations on $REPO_SLUG"
fi

if ((KEEP == 0)); then
  log "removing $RUNNER_DIR"
  rm -rf "$RUNNER_DIR"
else
  log "kept $RUNNER_DIR (--keep)"
fi

log "runner removed"
