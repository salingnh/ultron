#!/usr/bin/env bash
# Boundary, ownership, publishing and auto-stop status of the CVE test lab (G1.6 slice E). Non-zero
# when any check fails, so `make vulnlab-up` and the checks can gate on it.
#
# It reads the containers, not their environment: the tunnel token is never printed, only where it
# came from. The publishing line is deliberately loud: "tunnel: OFF" is the normal state, and a
# cloudflared container running while publishing is not requested is an error this checkout must not
# leave behind. "TTL armed" means podman's own `--timeout` is set and has not expired - the stack
# stops itself even if nobody runs `make vulnlab-down`.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_cmd podman
require_cmd python3
load_images
load_env
load_ttl
resolve_tunnel_request
set_vulnlab_names
if tunnel_requested; then
  # Validate the token here too (a missing/loose explicit file is an error); the value is not used.
  resolve_tunnel_token
fi

status=0

log "compose project $VULNLAB_PROJECT ($VULNLAB_DIR)"

# Ownership is read-only here: this checkout may look at another checkout's stack, never recreate
# or remove it (scripts/lib/stack.sh).
verdict=$(vulnlab_stack_verdict)
case $verdict in
absent) log "ownership: no $VULNLAB_PROJECT containers on this host" ;;
ours) log "ownership: this checkout" ;;
other:*) log "ownership: ANOTHER CHECKOUT (${verdict#other:}) - read-only; this checkout will not start or remove it" ;;
config:*) log "ownership: this checkout, but the stack was started with another configuration (recreate with AEGIS_STACK_RECREATE=1)" ;;
unknown:*) log "ownership: unknown (${verdict#unknown:})" ;;
esac

other_projects=$(vulnlab_projects_on_host | grep -vx "$VULNLAB_PROJECT" || true)
if [ -n "$other_projects" ]; then
  log "other vulnlab stacks on this host: $(printf '%s ' $other_projects)(only one may exist; the origins use fixed lab addresses)"
fi

log "containers:"
podman ps --filter "label=io.podman.compose.project=$VULNLAB_PROJECT" \
  --format '  {{.Names}}  {{.Status}}'

# Origins come from the catalog (compose service names); the container is <project>-<service>.
catalog_services=$(python3 - "$CATALOG_FILE" <<'PY'
import sys

import yaml

document = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
print("\n".join(case["service"] for case in document["cases"]))
PY
)
mapfile -t expected_services <<< "$catalog_services"
expected=()
for service in "${expected_services[@]}"; do
  [ -n "$service" ] || continue
  expected+=("$VULNLAB_PROJECT-$service")
done
if tunnel_enabled; then
  expected+=("$VULNLAB_TUNNEL_CONTAINER")
fi
for container in "${expected[@]}"; do
  if container_running "$container"; then
    log "$container: running"
  else
    log "$container: NOT running"
    status=1
  fi
done

# Auto-stop: every container the project started must carry the current TTL, and it must not have
# been created outside make vulnlab-up (which would have left it without --timeout).
while IFS= read -r container; do
  [ -n "$container" ] || continue
  timeout=$(project_timeout "$container")
  if [ "$timeout" = 0 ]; then
    log "ttl: $container has no podman --timeout (created outside make vulnlab-up?)"
    status=1
    continue
  fi
  if [ "$timeout" != "$VULNLAB_TTL_SECONDS" ]; then
    log "ttl: $container carries ${timeout}s, expected ${VULNLAB_TTL_SECONDS}s"
    status=1
    continue
  fi
  remaining=$(python3 - "$container" <<'PY'
import re
import subprocess
import sys
from datetime import UTC, datetime

name = sys.argv[1]
# podman prints Go's default time layout ("2026-11-25 07:53:04.837760045 +0700 +07"), which is not
# ISO; keep the seconds and the numeric offset, drop the fraction and the zone abbreviation.
raw = subprocess.run(
    ["podman", "inspect", "--format", "{{.State.StartedAt}}", name],
    capture_output=True, text=True, check=True,
).stdout.strip()
match = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)? ([+-]\d{4})", raw)
if not match:
    print(0)
    raise SystemExit(0)
started = datetime.strptime(f"{match.group(1)} {match.group(2)}", "%Y-%m-%d %H:%M:%S %z")
timeout = int(
    subprocess.run(
        ["podman", "inspect", "--format", "{{.Config.Timeout}}", name],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
)
remaining = started.timestamp() + timeout - datetime.now(UTC).timestamp()
print(max(0, int(remaining)))
PY
)
  log "ttl: $container stops in $((remaining / 60))m$((remaining % 60))s (podman --timeout ${VULNLAB_TTL_SECONDS}s)"
done < <(project_containers)

if internal=$(podman network inspect "$VULNLAB_NETWORK" --format '{{.Internal}}' 2>/dev/null); then
  log "network $VULNLAB_NETWORK: internal=$internal"
  [ "$internal" = true ] || status=1
else
  log "network $VULNLAB_NETWORK: missing"
  status=1
fi

# Origins: no published port, no host mount (tmpfs only), and they do not sit on the egress network.
for container in "${expected[@]}"; do
  case "$container" in
  "$VULNLAB_TUNNEL_CONTAINER") continue ;;
  esac
  container_exists "$container" || continue
  bindings=$(podman inspect --format '{{json .HostConfig.PortBindings}}' "$container")
  if [ "$bindings" != "{}" ] && [ "$bindings" != "null" ]; then
    log "ports: $container publishes $bindings"
    status=1
  fi
  mount_types=$(podman inspect --format '{{range .Mounts}}{{.Type}}{{"\n"}}{{end}}' "$container")
  if [ -n "$mount_types" ] && printf '%s\n' "$mount_types" | grep -qvx tmpfs; then
    log "mounts: $container has a non-tmpfs mount: $(printf '%s ' $mount_types)"
    status=1
  fi
  networks=$(podman inspect --format '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{"\n"}}{{end}}' "$container" | sort)
  if [ "$networks" != "$(printf 'aegis-lab-lab\n%s' "$VULNLAB_NETWORK" | sort)" ]; then
    log "networks: $container is on '$(printf '%s ' $networks)', expected only aegis-lab-lab and $VULNLAB_NETWORK"
    status=1
  fi
done
if ((status == 0)); then
  log "origins: no published port, tmpfs-only mounts, internal + lab networks only"
fi

# Publishing: loud, and truthful about what is actually running rather than only about intent.
if container_running "$VULNLAB_TUNNEL_CONTAINER"; then
  log "tunnel: ON ($VULNLAB_TUNNEL_CONTAINER running)"
  if podman logs --tail 200 "$VULNLAB_TUNNEL_CONTAINER" 2>&1 | grep -q "Registered tunnel connection"; then
    log "cloudflared: registered connection present in its log"
  else
    log "cloudflared: no 'Registered tunnel connection' in its log yet"
    status=1
  fi
  if [ -n "$(podman inspect --format '{{range .Mounts}}{{.Destination}}{{"\n"}}{{end}}' "$VULNLAB_TUNNEL_CONTAINER")" ]; then
    log "cloudflared: unexpected local mount (a remote-managed tunnel needs no ingress file)"
    status=1
  fi
  if ! tunnel_requested; then
    log "tunnel: note - publishing is ON in the running stack although VULNLAB_TUNNEL is not set in this shell (make vulnlab-up removes cloudflared when publishing is off; another checkout may own this stack)"
  fi
else
  if tunnel_requested; then
    if tunnel_enabled; then
      log "tunnel: ON expected but $VULNLAB_TUNNEL_CONTAINER is NOT running"
    else
      log "tunnel: requested but NO TOKEN ($(tunnel_token_file_hint))"
    fi
    status=1
  else
    log "tunnel: $(tunnel_state)"
  fi
fi

if ((status != 0)); then
  die "vulnlab is not healthy"
fi
if container_running "$VULNLAB_TUNNEL_CONTAINER"; then
  log "vulnlab is healthy (tunnel ON)"
else
  log "vulnlab is healthy (lab-only, publishing OFF)"
fi
