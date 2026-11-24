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

require_cmd sha256sum

# --- PostgreSQL migrations ---------------------------------------------------
# One bookkeeper: `python -m aegis.migrations` (contracts/README.md order, per-file sha256, an
# advisory lock, loud refusals on drift or an interrupted attempt). The dev stack used to keep its
# own table in schema `aegis_dev`; that state is adopted once (sha256 checked) and the old schema is
# removed, so `make dev-up` and `make migrate` can never disagree about the chain.
require_cmd uv "install uv (https://docs.astral.sh/uv/)"
export AEGIS_PG_DSN="postgresql://$AEGIS_PG_USER:$AEGIS_PG_PASSWORD@127.0.0.1:$AEGIS_PG_PORT/$AEGIS_PG_DB"

legacy=$(psql_value "SELECT to_regclass('aegis_dev.applied_migration') IS NOT NULL")
if [ "$legacy" = t ]; then
  # A missing relation in a scalar subquery is a parse error even inside CASE, so ask separately.
  runner_rows=0
  if [ "$(psql_value "SELECT to_regclass('aegis_migrations.contract_migration') IS NOT NULL")" = t ]; then
    runner_rows=$(psql_value "SELECT count(*) FROM aegis_migrations.contract_migration")
  fi
  recorded=$(psql_value "SELECT count(*) FROM aegis_dev.applied_migration")
  if [ "$runner_rows" = 0 ] && [ "$recorded" != 0 ]; then
    log "postgres: adopting $recorded migration(s) recorded by the old dev bookkeeper"
    while IFS='|' read -r filename sha; do
      [ -n "$filename" ] || continue
      (cd "$REPO_ROOT" && uv run --frozen python -m aegis.migrations mark-applied \
        "contracts/db/postgres/$filename" --sha256 "$sha")
    done < <(psql_run -tAc "SELECT filename || '|' || sha256 FROM aegis_dev.applied_migration ORDER BY filename")
  fi
fi

log "postgres: applying the contract chain (python -m aegis.migrations)"
(cd "$REPO_ROOT" && uv run --frozen python -m aegis.migrations)

if [ "$legacy" = t ]; then
  other_tables=$(psql_value "SELECT count(*) FROM information_schema.tables
                              WHERE table_schema = 'aegis_dev' AND table_name <> 'applied_migration'")
  if [ "$other_tables" = 0 ]; then
    psql_run -c "DROP SCHEMA aegis_dev CASCADE;" >/dev/null
    log "postgres: removed the old aegis_dev bookkeeping schema (the runner now records the chain)"
  else
    log "postgres: the aegis_dev schema holds other objects; left it in place"
  fi
fi

log "postgres schema version: $(psql_value "SELECT coalesce(max(version), 'none') FROM aegis_migrations.contract_migration")"

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
