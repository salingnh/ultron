#!/usr/bin/env bash
# Boundary and auto-stop status of the CVE test lab (G1.6 slice E). Non-zero when any check fails,
# so `make vulnlab-up` and the checks can gate on it.
#
# It reads the containers, not their environment: the tunnel token is never printed. "TTL armed"
# means podman's own `--timeout` is set on the container and has not expired - the stack stops itself
# even if nobody runs `make vulnlab-down`.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_cmd podman
require_cmd python3
load_images
load_env
load_ttl

status=0

catalog_containers=$(python3 - "$CATALOG_FILE" <<'PY'
import sys

import yaml

document = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
print("\n".join(case["container"] for case in document["cases"]))
PY
)

log "compose project $VULNLAB_PROJECT:"
podman ps --filter "label=io.podman.compose.project=$VULNLAB_PROJECT" \
  --format '  {{.Names}}  {{.Status}}'

mapfile -t expected <<< "$catalog_containers"
if tunnel_enabled; then
  expected+=("aegis-vulnlab-cloudflared")
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

if internal=$(podman network inspect aegis-vulnlab-net --format '{{.Internal}}' 2>/dev/null); then
  log "network aegis-vulnlab-net: internal=$internal"
  [ "$internal" = true ] || status=1
else
  log "network aegis-vulnlab-net: missing"
  status=1
fi

# Origins: no published port, no host mount (tmpfs only), and they do not sit on the egress network.
for container in "${expected[@]}"; do
  case "$container" in
  aegis-vulnlab-cloudflared) continue ;;
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
  if [ "$networks" != "$(printf 'aegis-lab-lab\naegis-vulnlab-net')" ]; then
    log "networks: $container is on '$(printf '%s ' $networks)', expected only aegis-lab-lab and aegis-vulnlab-net"
    status=1
  fi
done
if ((status == 0)); then
  log "origins: no published port, tmpfs-only mounts, internal + lab networks only"
fi

log "tunnel: $(tunnel_state)"
if tunnel_enabled; then
  if container_running aegis-vulnlab-cloudflared; then
    if podman logs --tail 200 aegis-vulnlab-cloudflared 2>&1 | grep -q "Registered tunnel connection"; then
      log "cloudflared: registered connection present in its log"
    else
      log "cloudflared: no 'Registered tunnel connection' in its log yet"
      status=1
    fi
  else
    log "cloudflared: NOT running"
    status=1
  fi
fi

if ((status != 0)); then
  die "vulnlab is not healthy"
fi
log "vulnlab is healthy (auto-stop armed, $(tunnel_state))"
