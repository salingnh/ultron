#!/usr/bin/env bash
# Applies the contract schema to a running dev stack:
#   1. every contracts/db/postgres/0*.sql migration, once each, recorded with its sha256;
#   2. contracts/graph/constraints.cypher (idempotent, safe on every run);
#   3. the S3 bucket for raw/evidence objects, with Object Lock enabled.
#
# Idempotent. State is kept in schema `aegis_dev` so a second run only applies what is
# missing; a migration that was already applied and then edited fails loudly instead of
# silently diverging from the database that recorded it.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env

require_cmd sha256sum

# --- PostgreSQL migrations ---------------------------------------------------
psql_run -c "CREATE SCHEMA IF NOT EXISTS aegis_dev;" \
  -c "CREATE TABLE IF NOT EXISTS aegis_dev.applied_migration (
        filename text PRIMARY KEY,
        sha256 text NOT NULL,
        applied_at timestamptz NOT NULL DEFAULT now());" >/dev/null

shopt -s nullglob
migrations=("$REPO_ROOT"/contracts/db/postgres/0*.sql)
((${#migrations[@]} > 0)) || die "no migrations found under contracts/db/postgres"

for migration in "${migrations[@]}"; do
  filename=$(basename "$migration")
  sha256=$(sha256sum "$migration" | cut -d' ' -f1)
  applied=$(psql_value "SELECT sha256 FROM aegis_dev.applied_migration WHERE filename = '$filename'")
  if [[ -n $applied ]]; then
    [[ $applied == "$sha256" ]] ||
      die "$filename was applied with sha256 $applied but the file is now $sha256 - applied migrations are immutable, add a new migration instead"
    log "migration $filename: already applied"
    continue
  fi
  log "migration $filename: applying"
  psql_run -f - <"$migration" >/dev/null
  psql_run -c "INSERT INTO aegis_dev.applied_migration (filename, sha256) VALUES ('$filename', '$sha256');" >/dev/null
done

log "postgres schema version: $(psql_value "SELECT coalesce(max(filename), 'none') FROM aegis_dev.applied_migration")"

# --- Neo4j constraints -------------------------------------------------------
log "neo4j constraints: applying (idempotent)"
cypher_file "$GRAPH_DIR/constraints.cypher"

# --- S3 bucket with Object Lock ---------------------------------------------
endpoint="http://127.0.0.1:$AEGIS_S3_PORT"
bucket_url="$endpoint/$AEGIS_S3_BUCKET"
status=$(curl -s -o /dev/null -w '%{http_code}' "$bucket_url") || die "S3 endpoint $endpoint is not reachable"
case $status in
200) log "s3 bucket $AEGIS_S3_BUCKET: exists" ;;
404)
  log "s3 bucket $AEGIS_S3_BUCKET: creating with Object Lock"
  curl -fsS -X PUT -H 'x-amz-bucket-object-lock-enabled: true' "$bucket_url" >/dev/null ||
    die "creating bucket $AEGIS_S3_BUCKET failed"
  ;;
*) die "unexpected S3 response $status for $bucket_url" ;;
esac

lock=$(curl -fsS "$bucket_url?object-lock") || die "reading Object Lock configuration of $AEGIS_S3_BUCKET failed"
grep -q '<ObjectLockEnabled>Enabled</ObjectLockEnabled>' <<<"$lock" ||
  die "bucket $AEGIS_S3_BUCKET does not have Object Lock enabled: $lock"
log "s3 bucket $AEGIS_S3_BUCKET: Object Lock enabled"
