#!/usr/bin/env bash
# Removes what the contracts CI suite created on this runner: containers, volumes and
# networks labelled aegis.ci.suite=contracts. Runs as an always() step so a failed or
# cancelled job leaves nothing behind. The dev stack (compose project aegis-dev) and
# anything else on the machine are not touched.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_cmd podman

removed=0

mapfile -t containers < <(podman ps -aq --filter "label=$CI_SUITE_LABEL")
if ((${#containers[@]})); then
  podman rm -f "${containers[@]}" >/dev/null
  log "cleanup: removed ${#containers[@]} container(s)"
  removed=$((removed + ${#containers[@]}))
fi

mapfile -t volumes < <(podman volume ls -q --filter "label=$CI_SUITE_LABEL")
if ((${#volumes[@]})); then
  podman volume rm -f "${volumes[@]}" >/dev/null
  log "cleanup: removed ${#volumes[@]} volume(s)"
  removed=$((removed + ${#volumes[@]}))
fi

mapfile -t networks < <(podman network ls -q --filter "label=$CI_SUITE_LABEL")
if ((${#networks[@]})); then
  podman network rm -f "${networks[@]}" >/dev/null
  log "cleanup: removed ${#networks[@]} network(s)"
  removed=$((removed + ${#networks[@]}))
fi

((removed > 0)) || log "cleanup: nothing to remove"
