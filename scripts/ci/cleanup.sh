#!/usr/bin/env bash
# Removes what THIS CI job created on the runner: containers, volumes and networks carrying both
# `aegis.ci.suite=<GITHUB_JOB>` and `aegis.ci.run=<GITHUB_RUN_ID>`.
#
# The runner is shared by every workflow of the repository, and several runs may be in flight at
# once. A cleanup that filtered only by suite would delete another run's PostgreSQL container, venv
# volume or Neo4j mid-check (observed on G1.4a: the contracts job lost its volume and database while
# a python job finished). The run label is therefore part of the filter; suite keeps a python run
# from touching contracts resources even if run ids ever collide (manual runs use `local-<pid>`).
#
# AEGIS_CI_SUITE overrides the suite outside a GitHub job (tests, manual cleanup). The dev stack
# (compose project aegis-dev) and anything else on the machine are not touched.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_cmd podman

log "cleanup: suite=$CI_SUITE run=$CI_RUN"

removed=0
filters=("--filter" "label=$CI_SUITE_LABEL" "--filter" "label=$CI_RUN_LABEL")

mapfile -t containers < <(podman ps -aq "${filters[@]}")
if ((${#containers[@]})); then
  for ctr in "${containers[@]}"; do
    record_container_volumes "$ctr"
  done
  podman rm -f -v "${containers[@]}" >/dev/null
  log "cleanup: removed ${#containers[@]} container(s)"
  removed=$((removed + ${#containers[@]}))
fi

mapfile -t job_containers < <(podman ps -aq --filter "label=$CI_JOB_LABEL")
if ((${#job_containers[@]})); then
  for ctr in "${job_containers[@]}"; do
    record_container_volumes "$ctr"
  done
  podman rm -f -v "${job_containers[@]}" >/dev/null
  log "cleanup: removed ${#job_containers[@]} job-scoped container(s)"
  removed=$((removed + ${#job_containers[@]}))
fi

mapfile -t volumes < <(podman volume ls -q "${filters[@]}")
if ((${#volumes[@]})); then
  podman volume rm -f "${volumes[@]}" >/dev/null
  log "cleanup: removed ${#volumes[@]} volume(s)"
  removed=$((removed + ${#volumes[@]}))
fi

mapfile -t job_volumes < <(podman volume ls -q --filter "label=$CI_JOB_LABEL")
if ((${#job_volumes[@]})); then
  podman volume rm -f "${job_volumes[@]}" >/dev/null
  log "cleanup: removed ${#job_volumes[@]} job-scoped volume(s)"
  removed=$((removed + ${#job_volumes[@]}))
fi

mapfile -t networks < <(podman network ls -q "${filters[@]}")
if ((${#networks[@]})); then
  podman network rm -f "${networks[@]}" >/dev/null
  log "cleanup: removed ${#networks[@]} network(s)"
  removed=$((removed + ${#networks[@]}))
fi

((removed > 0)) || log "cleanup: nothing to remove"
