#!/usr/bin/env bash
# Installs the GitHub Actions self-hosted runner for this repository as an ephemeral,
# user-level systemd service (systemd --user, no sudo, no system account).
#
#   scripts/ci/install-runner.sh             install or update
#   scripts/ci/install-runner.sh --status    service, linger and registration state
#   scripts/ci/uninstall-runner.sh           remove it again
#
# Steps: check the gh login, verify and unpack actions/runner (pinned version and sha256)
# into ~/actions-runner, install runner-loop.sh and ultron-runner.service, enable linger so
# it starts without an interactive login, then start the service.
#
# The runner registers ephemeral one-job runners with label `ultron-local` (fresh work
# folder per job) and receives no secret in its environment; it fetches a one-hour
# registration token with the operator's gh login. Fork pull requests never reach it: the
# job guard in .github/workflows/contracts.yml plus the repository setting "require approval
# for all outside collaborators".
set -euo pipefail
. "$(dirname "$0")/lib.sh"

RUNNER_VERSION=2.338.2
RUNNER_SHA256_LINUX_X64=baebf204307bac6193480852732f0aba2ae97b6c5597c244f4d5558390147c40
RUNNER_URL="https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz"

REPO_SLUG=${ULTRON_REPO:-salingnh/ultron}
RUNNER_DIR=${ULTRON_RUNNER_DIR:-$HOME/actions-runner}
UNIT_NAME=ultron-runner.service
UNIT_DIR=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user
UNIT_PATH="$UNIT_DIR/$UNIT_NAME"

show_status() {
  printf 'repository     %s\n' "$REPO_SLUG"
  printf 'runner dir     %s\n' "$RUNNER_DIR"
  printf 'unit           %s\n' "$UNIT_PATH"
  printf 'unit installed %s\n' "$(systemctl --user list-unit-files "$UNIT_NAME" --no-legend 2>/dev/null | awk '{print $1}' | grep -qx "$UNIT_NAME" && echo yes || echo no)"
  printf 'enabled        %s\n' "$(systemctl --user is-enabled "$UNIT_NAME" 2>/dev/null || echo no)"
  printf 'active         %s\n' "$(systemctl --user is-active "$UNIT_NAME" 2>/dev/null || echo no)"
  printf 'linger         %s\n' "$(loginctl show-user "$USER" -p Linger --value 2>/dev/null || echo unknown)"
  local registered
  registered=$(gh api "repos/$REPO_SLUG/actions/runners" --jq \
    '[.runners[] | select(.name | startswith("ultron-local-"))] | length' 2>/dev/null) ||
    registered="unknown (gh has no admin rights on $REPO_SLUG?)"
  printf 'registered     %s\n' "$registered"
}

if [ "${1:-}" = --status ]; then
  require_cmd gh
  require_cmd systemctl
  show_status
  exit 0
fi

require_cmd gh
require_cmd curl
require_cmd tar
require_cmd sha256sum
require_cmd systemctl

gh auth status >/dev/null 2>&1 || die "gh is not logged in - run: gh auth login"
gh api "repos/$REPO_SLUG/actions/runners" >/dev/null 2>&1 ||
  die "the current gh login cannot manage runners of $REPO_SLUG (needs admin on the repository)"

archive=$(mktemp -t actions-runner-XXXXXX.tar.gz)
trap 'rm -f "$archive"' EXIT

log "downloading actions/runner $RUNNER_VERSION"
curl -fsSL -o "$archive" "$RUNNER_URL"
printf '%s  %s\n' "$RUNNER_SHA256_LINUX_X64" "$archive" | sha256sum -c - >/dev/null ||
  die "sha256 mismatch for $RUNNER_URL - refusing to install"

log "unpacking into $RUNNER_DIR"
mkdir -p "$RUNNER_DIR"
tar -xzf "$archive" -C "$RUNNER_DIR"
install -m 0755 "$CI_DIR/runner-loop.sh" "$RUNNER_DIR/run-loop.sh"

log "installing the user unit $UNIT_NAME"
mkdir -p "$UNIT_DIR"
install -m 0644 "$REPO_ROOT/deploy/ci/ultron-runner.service" "$UNIT_PATH"
systemctl --user daemon-reload
systemctl --user enable "$UNIT_NAME" >/dev/null
systemctl --user restart "$UNIT_NAME"

if [ "$(loginctl show-user "$USER" -p Linger --value 2>/dev/null || true)" != yes ]; then
  if loginctl enable-linger "$USER" >/dev/null 2>&1; then
    log "enabled linger for $USER (the runner starts without an interactive login)"
  else
    log "warning: could not enable linger - run 'loginctl enable-linger $USER' once as an admin, otherwise the runner stops at logout"
  fi
fi

sleep 3
show_status
printf -- '--- systemctl --user status %s ---\n' "$UNIT_NAME"
systemctl --user --no-pager status "$UNIT_NAME" | head -15 || true
printf -- '------------------------------------------------------------------------\n'
printf 'Remove it again with scripts/ci/uninstall-runner.sh\n'
