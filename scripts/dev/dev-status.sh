#!/usr/bin/env bash
# Prints the health and endpoints of the dev stack; exits non-zero when anything is
# missing or not healthy. Used by make dev-up (final gate) and for manual checks.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env

require_cmd podman

status=0
printf '%-26s %-11s %s\n' CONTAINER HEALTH PORTS
for container in "$PG_CONTAINER" "$NEO4J_CONTAINER" "$SEAWEEDFS_CONTAINER" "$TEMPORAL_CONTAINER"; do
  if container_exists "$container"; then
    health=$(podman inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$container")
    ports=$(podman port "$container" | tr '\n' ' ')
    printf '%-26s %-11s %s\n' "$container" "$health" "${ports:-none}"
    [ "$health" = healthy ] || status=1
  else
    printf '%-26s %-11s %s\n' "$container" missing - || true
    status=1
  fi
done

cat <<EOF

postgres  127.0.0.1:$AEGIS_PG_PORT  db=$AEGIS_PG_DB user=$AEGIS_PG_USER
neo4j     http://127.0.0.1:$AEGIS_NEO4J_HTTP_PORT  bolt://127.0.0.1:$AEGIS_NEO4J_BOLT_PORT
s3        http://127.0.0.1:$AEGIS_S3_PORT  bucket=$AEGIS_S3_BUCKET (Object Lock enabled)
temporal  127.0.0.1:$AEGIS_TEMPORAL_PORT
EOF

exit "$status"
