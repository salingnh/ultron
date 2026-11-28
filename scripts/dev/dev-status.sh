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

# The evidence store stops accepting writes when its filesystem is nearly full (SeaweedFS
# minFreeSpace 1%), and the failure surfaces only as HTTP 500 on a job's evidence upload.
# g2-p0: 34 jobs failed this way while the host sat at 0.5-1.0% free.
storage_root=$(podman_storage_root)
free_percent=$(disk_free_percent "${storage_root:-/}")
need=${AEGIS_DEV_MIN_FREE_PERCENT:-$MIN_FREE_PERCENT_DEFAULT}
printf '%-26s %-11s %s\n' "host disk" \
  "${free_percent:-unknown}%" "${storage_root:-/} needs >= $need% (SeaweedFS needs >= 1%)"
if [ -z "$free_percent" ] || awk -v free="$free_percent" -v need="$need" \
  'BEGIN { if (free + 0 < need + 0) exit 0; exit 1 }'; then
  status=1
fi

exit "$status"
