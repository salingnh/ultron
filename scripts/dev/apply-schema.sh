#!/usr/bin/env bash
# Applies the contract schema to a running dev stack:
#   1. every contracts/db/postgres/0*.sql migration through `python -m aegis.migrations` (the one
#      runner: contracts/README.md order, per-file sha256, one advisory lock);
#   2. contracts/graph/constraints.cypher (idempotent, safe on every run);
#   3. the S3 bucket for raw/evidence objects, with Object Lock enabled.
#
# Idempotent, and the same bookkeeper as `make migrate`: a second run applies only what is missing,
# and a migration that was already applied and then edited fails loudly.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env

# --- PostgreSQL migrations ---------------------------------------------------
# One bookkeeper: `python -m aegis.migrations` (contracts/README.md order, per-file sha256, an
# advisory lock, loud refusals on drift or an interrupted attempt). A database built by the replaced
# chain is reset (`make dev-reset`), never adopted.
require_cmd uv "install uv (https://docs.astral.sh/uv/)"
export AEGIS_PG_DSN="postgresql://$AEGIS_PG_USER:$AEGIS_PG_PASSWORD@127.0.0.1:$AEGIS_PG_PORT/$AEGIS_PG_DB"

# A brand-new database has no bookkeeping table yet: that is "nothing applied", not a psql error
# (a first-time `make run-local` used to print `ERROR: relation "aegis_migrations.contract_migration"
# does not exist` and an empty version here, which reads like a broken stack).
if [ "$(psql_value "SELECT to_regclass('aegis_migrations.contract_migration') IS NULL")" = t ]; then
  log "postgres schema: no migrations applied yet"
else
  log "postgres schema version: $(psql_value "SELECT coalesce(max(version), 'none') FROM aegis_migrations.contract_migration")"
fi

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
