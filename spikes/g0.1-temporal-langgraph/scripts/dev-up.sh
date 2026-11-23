#!/usr/bin/env bash
# Start the throwaway Postgres for this spike and load the real contract migrations.
# Own resources only: container g01-spike-postgres, volume g01-spike-pgdata.
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGE="docker.io/library/postgres@sha256:3950ad7c3148ca2175ef1b6c36c9efbf78957ae8fbe8b3a5d7c35af50500382f"
CONTAINER=g01-spike-postgres
VOLUME=g01-spike-pgdata
DSN="postgresql://spike:spike@127.0.0.1:58101/aegis"
MIGRATIONS=../../contracts/db/postgres

podman volume exists "$VOLUME" || podman volume create "$VOLUME" >/dev/null
# Only ever replaces this spike's own container.
podman rm -f "$CONTAINER" >/dev/null 2>&1 || true
podman run -d --name "$CONTAINER" \
  --publish 127.0.0.1:58101:5432 \
  --env POSTGRES_USER=spike --env POSTGRES_PASSWORD=spike --env POSTGRES_DB=aegis \
  --volume "$VOLUME:/var/lib/postgresql/data:Z" \
  --shm-size 256m \
  "$IMAGE" >/dev/null

echo -n "waiting for postgres"
for _ in $(seq 1 60); do
  if podman exec "$CONTAINER" pg_isready -U spike -d aegis >/dev/null 2>&1; then echo " ready"; break; fi
  echo -n .; sleep 1
done
podman exec "$CONTAINER" pg_isready -U spike -d aegis >/dev/null

# Real product migrations, unmodified, in order (contracts/db/postgres/README list).
# Applied once per data volume: the volume survives container recreations.
if [ "$(podman exec -i "$CONTAINER" psql -tAc "SELECT to_regclass('aegis.scan_job') IS NOT NULL" -U spike -d aegis)" = "t" ]; then
  echo "product migrations already applied on volume $VOLUME (use scripts/dev-reset.sh for a clean run)"
else
  for f in 0001_init.sql 0002_tool_orchestration.sql 0003_task_manifest_binding.sql 0004_usage_nonnegative.sql; do
    echo "applying $f"
    podman exec -i "$CONTAINER" psql -q -v ON_ERROR_STOP=1 -U spike -d aegis < "$MIGRATIONS/$f" >/dev/null
  done
fi

# LangGraph checkpointer schema (named by contracts/db/postgres/0001_init.sql:17) + spike fakes.
podman exec -i "$CONTAINER" psql -q -v ON_ERROR_STOP=1 -U spike -d aegis \
  -c 'CREATE SCHEMA IF NOT EXISTS langgraph; CREATE SCHEMA IF NOT EXISTS spike;' >/dev/null
podman exec -i "$CONTAINER" psql -q -v ON_ERROR_STOP=1 -U spike -d aegis < deploy/spike-schema.sql >/dev/null

echo "postgres ready on 127.0.0.1:58101 (aegis schema 0001-0004 + spike + langgraph)"
echo "$DSN"
