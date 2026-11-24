#!/usr/bin/env bash
# Installs one GitHub Actions self-hosted runner instance for this repository as an
# ephemeral, user-level systemd service (systemd --user, no sudo, no system account).
#
#   scripts/ci/install-runner.sh --instance 2     install or update instance 2
#   scripts/ci/install-runner.sh --status         state of every installed instance
#   scripts/ci/uninstall-runner.sh --instance 2   remove instance 2 (see that script)
#
# An instance is its own directory (~/ultron-runner-<n>), its own unit
# (ultron-runner-<n>.service) and its own work folder. All instances share the label
# `ultron-local`, so the jobs of one workflow run - or of several - execute in parallel on
# different instances instead of queueing behind one another.
#
# Every instance keeps the same hardening as before: ephemeral one-job registration, fresh
# work folder per job, no secret in the unit environment (the registration token is fetched
# with the operator's `gh` login while registering), rootless podman for services.
#
# Two instances are enough to overlap two jobs; three lets a G1 wave of five workers keep two
# slots free while one job runs long. Use as many as the host can carry: each job uses one
# PostgreSQL, one Neo4j and one python container at a time.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

RUNNER_VERSION=2.338.2
RUNNER_SHA256_LINUX_X64=baebf204307bac6193480852732f0aba2ae97b6c5597c244f4d5558390147c40
RUNNER_URL="https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz"

REPO_SLUG=${ULTRON_REPO:-salingnh/ultron}
LABEL=${ULTRON_RUNNER_LABEL:-ultron-local}
UNIT_DIR=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user
TEMPLATE="$REPO_ROOT/deploy/ci/ultron-runner.service"
LEGACY_UNIT="$UNIT_DIR/ultron-runner.service"
LEGACY_DIR="$HOME/ultron-runner"

# shellcheck disable=SC2034 # used by runner_dir/unit_name below
INSTANCE=
MODE=install

usage() {
  cat <<'TXT'
usage: install-runner.sh [--instance N] [--status]

  --instance N   runner instance to install or update (1..9, default 1)
  --status       show every installed instance and the legacy single-instance setup
TXT
}

while (($#)); do
  case $1 in
  --instance)
    INSTANCE=${2:?--instance needs a number}
    shift 2
    ;;
  --instance=*)
    INSTANCE=${1#*=}
    shift
    ;;
  --status)
    MODE=status
    shift
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    die "unknown argument '$1' (see --help)"
    ;;
  esac
done

[[ ${INSTANCE:-1} =~ ^[1-9]$ ]] || die "instance must be a single digit 1..9, got '${INSTANCE:-}'"
INSTANCE=${INSTANCE:-1}
RUNNER_DIR="$HOME/ultron-runner-$INSTANCE"
RUNNER_DIR_NAME="ultron-runner-$INSTANCE"
UNIT_NAME="ultron-runner-$INSTANCE.service"
UNIT_PATH="$UNIT_DIR/$UNIT_NAME"

registered_count() { # registered_count <name prefix>
  gh api "repos/$REPO_SLUG/actions/runners?per_page=100" --jq \
    "[.runners[] | select(.name | startswith(\"$1\"))] | length" 2>/dev/null ||
    echo "unknown (gh has no admin rights on $REPO_SLUG?)"
}

show_status() {
  local unit dir instance
  printf 'repository %s   label %s\n' "$REPO_SLUG" "$LABEL"
  printf '%-9s %-28s %-10s %-8s %s\n' INSTANCE DIRECTORY ENABLED ACTIVE REGISTERED
  for instance in 1 2 3 4 5 6 7 8 9; do
    unit="$UNIT_DIR/ultron-runner-$instance.service"
    dir="$HOME/ultron-runner-$instance"
    if [ -f "$unit" ] || [ -d "$dir" ]; then
      printf '%-9s %-28s %-10s %-8s %s\n' "$instance" "$dir" \
        "$(systemctl --user is-enabled "ultron-runner-$instance.service" 2>/dev/null || echo no)" \
        "$(systemctl --user is-active "ultron-runner-$instance.service" 2>/dev/null || echo no)" \
        "$(registered_count "ultron-local-$instance-")"
    fi
  done
  if [ -f "$LEGACY_UNIT" ] || [ -d "$LEGACY_DIR" ]; then
    printf '\nlegacy single-instance setup found (%s / %s): remove it with scripts/ci/uninstall-runner.sh --legacy\n' \
      "$LEGACY_UNIT" "$LEGACY_DIR"
  fi
}

if [ "$MODE" = status ]; then
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
[ -f "$TEMPLATE" ] || die "missing unit template $TEMPLATE"
if [ -f "$LEGACY_UNIT" ]; then
  log "warning: the legacy single-instance unit is still installed - remove it with scripts/ci/uninstall-runner.sh --legacy"
fi

archive=$(mktemp -t actions-runner-XXXXXX.tar.gz)
trap 'rm -f "$archive"' EXIT

log "instance $INSTANCE: downloading actions/runner $RUNNER_VERSION"
curl -fsSL -o "$archive" "$RUNNER_URL"
printf '%s  %s\n' "$RUNNER_SHA256_LINUX_X64" "$archive" | sha256sum -c - >/dev/null ||
  die "sha256 mismatch for $RUNNER_URL - refusing to install"

log "instance $INSTANCE: unpacking into $RUNNER_DIR"
mkdir -p "$RUNNER_DIR"
tar -xzf "$archive" -C "$RUNNER_DIR"
install -m 0755 "$CI_DIR/runner-loop.sh" "$RUNNER_DIR/run-loop.sh"

log "instance $INSTANCE: installing the user unit $UNIT_NAME"
mkdir -p "$UNIT_DIR"
sed -e "s|@INSTANCE@|$INSTANCE|g" -e "s|@RUNNER_DIR@|$RUNNER_DIR_NAME|g" "$TEMPLATE" >"$UNIT_PATH"
chmod 0644 "$UNIT_PATH"
systemctl --user daemon-reload
systemctl --user enable "$UNIT_NAME" >/dev/null
systemctl --user restart "$UNIT_NAME"

if [ "$(loginctl show-user "$USER" -p Linger --value 2>/dev/null || true)" != yes ]; then
  if loginctl enable-linger "$USER" >/dev/null 2>&1; then
    log "enabled linger for $USER (runners start without an interactive login)"
  else
    log "warning: could not enable linger - run 'loginctl enable-linger $USER' once as an admin, otherwise runners stop at logout"
  fi
fi

sleep 3
show_status
printf -- '------------------------------------------------------------------------\n'
printf 'The service log (journalctl --user -u %s) carries a one-hour, single-use\n' "$UNIT_NAME"
printf 'registration token in its command line; the runner needs it only while it registers.\n'
printf 'Remove instance %s with scripts/ci/uninstall-runner.sh --instance %s\n' "$INSTANCE" "$INSTANCE"
