#!/usr/bin/env bash
# Health and boundary of the running lab (G0.4c): both services up, the resolver answers the
# zone, the passive stub is healthy, the network is internal and no port is published.
# Exits non-zero when any check fails, so it can gate lab-up and lab-check.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_cmd podman
require_cmd python3
load_images

status=0

log "compose project $LAB_PROJECT:"
podman ps --filter "label=io.podman.compose.project=$LAB_PROJECT" \
  --format '  {{.Names}}  {{.Status}}'

for container in "$DNS_CONTAINER" "$PASSIVE_CONTAINER"; do
  if container_running "$container"; then
    log "$container: running"
  else
    log "$container: NOT running"
    status=1
  fi
done

if container_running "$DNS_CONTAINER"; then
  if ! line=$(probe_dns www.lab.aegis.test); then
    log "dns: probe failed (www.lab.aegis.test expected A 203.0.113.10)"
    status=1
  elif ! dns_answer_is_expected "$line"; then
    log "dns: unexpected answer: $(describe_dns "$line")"
    status=1
  else
    log "dns: $(describe_dns "$line")"
  fi
else
  log "dns: probe skipped"
  status=1
fi

if container_running "$PASSIVE_CONTAINER"; then
  health=$(podman inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$PASSIVE_CONTAINER")
  log "passive: health=$health"
  [ "$health" = healthy ] || status=1
else
  log "passive: health skipped"
  status=1
fi

if internal=$(podman network inspect "$LAB_NETWORK" --format '{{.Internal}}' 2>/dev/null); then
  log "network $LAB_NETWORK: internal=$internal"
  [ "$internal" = true ] || status=1
else
  log "network $LAB_NETWORK: missing"
  status=1
fi

for container in "${SERVICE_CONTAINERS[@]}"; do
  if container_running "$container"; then
    log "$container: running"
  else
    log "$container: NOT running"
    status=1
  fi
done
if ((status == 0)); then
  if services_ready; then
    log "services: ${SERVICE_ENDPOINTS[*]}"
  else
    log "services: at least one endpoint did not accept a connection"
    status=1
  fi
fi

# `.Ports` in `podman ps` also lists ports the image merely exposes; only a host binding is a
# published port, so read the container's port bindings instead.
published=""
for container in "$DNS_CONTAINER" "$PASSIVE_CONTAINER" "${SERVICE_CONTAINERS[@]}"; do
  container_exists "$container" || continue
  bindings=$(podman inspect --format '{{json .HostConfig.PortBindings}}' "$container")
  [ "$bindings" = "{}" ] || [ "$bindings" = "null" ] || published="$published $container=$bindings"
done
if [ -n "$published" ]; then
  log "published ports: unexpected -$published"
  status=1
else
  log "published ports: none"
fi

if ((status != 0)); then
  die "lab is not healthy"
fi
log "lab is healthy"
