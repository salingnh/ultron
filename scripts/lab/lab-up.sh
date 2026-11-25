#!/usr/bin/env bash
# One command for the authorized lab (G0.4c): the authoritative DNS for the lab zone and the
# local passive-source stub, on an internal network with no route off this host.
#
# Idempotent: run it again on a running lab and it only waits for the existing services.
# Readiness is not assumed from "container is up": the DNS answer is fetched with the pinned
# DNSx image over the lab network, which is the same path the acceptance run uses.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_cmd podman "install rootless podman 5.x"
require_cmd podman-compose "install with: python3 -m pip install --user podman-compose"
require_cmd python3
load_images

if ! podman info --format '{{.Host.Security.Rootless}}' | grep -qx true; then
  die "podman is not rootless; the lab must run as the current user"
fi

# A lab project on this host belongs to the checkout that created it (scripts/lib/stack.sh): another
# worker's `make lab-up` must not recreate the owner's lab containers. One lab serves the whole host
# (fixed subnet and addresses), so another checkout uses the running lab as it is - no `compose up`,
# the owner's CA adopted for its own scanner jobs - and never recreates or removes it.
lab_verdict=$(lab_stack_verdict)
case $lab_verdict in
other:*)
  adopt_running_lab "${lab_verdict#other:}"
  ;;
*)
  generate_lab_tls
  log "compose project $LAB_PROJECT: starting (network $LAB_NETWORK, internal only, no published ports)"
  compose up -d
  ;;
esac

wait_passive_healthy 180
wait_dns_ready 180 ||
  die "lab DNS did not answer www.lab.aegis.test with A 203.0.113.10 within 180s"
if ! wait_services_ready 180; then
  die "the G1.6a lab services did not accept a connection within 180s (see: make lab-status)"
fi

case $lab_verdict in
other:*) ;;
*) record_lab_stack_identity ;;
esac

"$LAB_SCRIPTS/lab-status.sh"
log "lab is healthy - next: make lab-check (Subfinder + DNSx against the lab)"
