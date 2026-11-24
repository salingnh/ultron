#!/usr/bin/env bash
# Removes runner instances installed by scripts/ci/install-runner.sh:
#
#   scripts/ci/uninstall-runner.sh --instance 2   remove instance 2
#   scripts/ci/uninstall-runner.sh --all          remove instances 1..9
#   scripts/ci/uninstall-runner.sh --legacy       remove the old single-instance setup
#                                                 (~/ultron-runner + ultron-runner.service)
#
# For each instance: stop and disable its unit, delete the unit file, delete its
# `ultron-local-<n>-*` registrations and its directory (pass --keep to leave the binaries).
# It touches nothing else on the host: no system unit, no package, no dev containers.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

REPO_SLUG=${ULTRON_REPO:-salingnh/ultron}
UNIT_DIR=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user
KEEP=0
TARGETS=()

usage() {
  cat <<'TXT'
usage: uninstall-runner.sh (--instance N | --all | --legacy) [--keep]

  --instance N   remove runner instance N (1..9)
  --all          remove runner instances 1..9
  --legacy       remove the old single-instance setup (~/ultron-runner, ultron-runner.service)
  --keep         keep the runner directory (binaries) instead of deleting it
TXT
}

while (($#)); do
  case $1 in
  --instance)
    TARGETS+=("${2:?--instance needs a number}")
    shift 2
    ;;
  --instance=*)
    TARGETS+=("${1#*=}")
    shift
    ;;
  --all)
    TARGETS+=(1 2 3 4 5 6 7 8 9)
    shift
    ;;
  --legacy)
    TARGETS+=(legacy)
    shift
    ;;
  --keep)
    KEEP=1
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

((${#TARGETS[@]})) || { usage; exit 1; }
require_cmd systemctl

registered_runners() { # prints "id name" for every runner of this repository
  command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1 || return 0
  gh api "repos/$REPO_SLUG/actions/runners?per_page=100" \
    --jq '.runners[] | "\(.id) \(.name)"' 2>/dev/null || true
}

remove_registrations() { # remove_registrations <prefix|legacy> <value>
  local mode=$1 value=$2 id name
  while read -r id name; do
    [ -n "$id" ] || continue
    case $mode in
    prefix) [[ $name == "$value"* ]] || continue ;;
    # legacy names are ultron-local-<epoch>-<random>; instance names add the instance number
    legacy) [[ $name =~ ^ultron-local-[0-9]+-[0-9]+$ ]] || continue ;;
    esac
    gh api -X DELETE "repos/$REPO_SLUG/actions/runners/$id" >/dev/null &&
      log "removed registered runner $name (id $id)"
  done < <(registered_runners)
}

for target in "${TARGETS[@]}"; do
  if [[ $target == legacy ]]; then
    unit_name=ultron-runner.service
    runner_dir=$HOME/ultron-runner
    mode=legacy
  else
    [[ $target =~ ^[1-9]$ ]] || die "instance must be a single digit 1..9, got '$target'"
    unit_name="ultron-runner-$target.service"
    runner_dir="$HOME/ultron-runner-$target"
    mode=prefix
    prefix="ultron-local-$target-"
  fi

  if systemctl --user cat "$unit_name" >/dev/null 2>&1; then
    log "$unit_name: stopping and disabling"
    systemctl --user disable --now "$unit_name" >/dev/null 2>&1 || true
  fi
  rm -f "$UNIT_DIR/$unit_name"
  systemctl --user daemon-reload

  remove_registrations "$mode" "${prefix:-}"

  if ((KEEP == 0)); then
    log "removing $runner_dir"
    rm -rf "$runner_dir"
  else
    log "kept $runner_dir (--keep)"
  fi
done

log "done; remaining instances:"
