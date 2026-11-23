#!/usr/bin/env bash
# The contract gate of contracts/README.md section "Kiểm tra", driven by the content of the
# checked-out branch instead of a list kept in this file:
#
#   * python  - validate_contracts.py and every contracts/tests/test_*.py, on Python 3.12 in
#               a container, with AEGIS_TEST_PG_DSN pointing at this script's own throwaway
#               PostgreSQL 16. A test file that skips (or does not finish with unittest's
#               "OK") fails the job: a skipped harness is not evidence.
#   * postgres - every contracts/db/postgres/0*.sql migration on an empty database, then
#               every tests/*.sql test, plus the documented upgrade chain from the v1
#               fixture. Fixture positions and the two clean-database-only tests are the
#               only lists here, and each is guarded so a new file cannot be ignored.
#
# Everything runs in rootless podman as the current user; passwords are generated per run.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_cmd podman

DB_DIR="$REPO_ROOT/contracts/db/postgres"
TESTS_DIR="$DB_DIR/tests"

NETWORK=$(ci_container net)
PG=$(ci_container pg)
VENV=$(ci_container venv)
PY=
PG_PASSWORD=$(random_password)
DSN="postgresql://aegis:${PG_PASSWORD}@${PG}:5432/postgres"

# Fixture position in the upgrade chain: the migration number the fixture runs after.
# A new fixture must be placed here, otherwise the upgrade chain would silently not run it.
declare -A FIXTURES_AFTER=(
  [v1-upgrade.sql]=0001
  [pre-usage-upgrade.sql]=0003
)
# Tests that seed fixed v2 rows and therefore only run on a freshly migrated database.
CLEAN_ONLY_TESTS="smoke.sql tool_orchestration.sql"

cleanup() {
  local status=$?
  if ((status != 0)); then
    dump_logs "$PG"
    dump_logs "$PY"
  fi
  remove_container "$PY"
  remove_container "$PG"
  podman volume rm -f "$VENV" >/dev/null 2>&1 || true
  podman network rm -f "$NETWORK" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

# --- what the branch contains -------------------------------------------------
shopt -s nullglob
MIGRATIONS=("$DB_DIR"/0*.sql)
((${#MIGRATIONS[@]} > 0)) || die "no migrations under contracts/db/postgres"

for fixture in "$TESTS_DIR"/fixtures/*.sql; do
  name=$(basename "$fixture")
  [[ -v FIXTURES_AFTER[$name] ]] ||
    die "fixture $name has no position in the upgrade chain - add it to FIXTURES_AFTER in scripts/ci/contracts-gate.sh"
done

CLEAN_TESTS=()
UPGRADE_TESTS=()
for test_file in "$TESTS_DIR"/*.sql; do
  name=$(basename "$test_file")
  [ "$name" = upgrade_assertions.sql ] && continue
  CLEAN_TESTS+=("$test_file")
  case " $CLEAN_ONLY_TESTS " in
  *" $name "*) ;;
  *) UPGRADE_TESTS+=("$test_file") ;;
  esac
done
((${#CLEAN_TESTS[@]} > 0)) || die "no SQL tests under contracts/db/postgres/tests"

mapfile -t FIXTURE_NAMES < <(printf '%s\n' "${!FIXTURES_AFTER[@]}" | sort)
UPGRADE_CHAIN=()
for migration in "${MIGRATIONS[@]}"; do
  number=$(basename "$migration")
  number=${number%%_*}
  UPGRADE_CHAIN+=("$migration")
  for fixture in "${FIXTURE_NAMES[@]}"; do
    if [ "${FIXTURES_AFTER[$fixture]}" = "$number" ]; then
      UPGRADE_CHAIN+=("$TESTS_DIR/fixtures/$fixture")
    fi
  done
done

PYTHON_TESTS=()
for test_file in "$REPO_ROOT"/contracts/tests/test_*.py; do
  PYTHON_TESTS+=("${test_file#"$REPO_ROOT"/}")
done
((${#PYTHON_TESTS[@]} > 0)) || die "no python tests under contracts/tests"

# --- throwaway PostgreSQL 16 + python 3.12 ------------------------------------
log "network $NETWORK + postgres $PG (throwaway)"
podman network create --label "$CI_SUITE_LABEL" --label "aegis.ci.run=$CI_RUN" "$NETWORK" >/dev/null
podman run -d --name "$PG" --network "$NETWORK" --network-alias pg \
  --label "$CI_SUITE_LABEL" --label "aegis.ci.run=$CI_RUN" \
  -e POSTGRES_PASSWORD="$PG_PASSWORD" -e POSTGRES_USER=aegis -e POSTGRES_DB=postgres \
  --tmpfs /var/lib/postgresql/data "$AEGIS_PG_IMAGE" >/dev/null

for _ in $(seq 1 60); do
  podman exec "$PG" pg_isready -U aegis -d postgres >/dev/null 2>&1 && break
  sleep 1
done
podman exec "$PG" pg_isready -U aegis -d postgres >/dev/null 2>&1 || die "PostgreSQL did not become ready"
log "postgres $(podman exec "$PG" psql -tAc 'SHOW server_version' -U aegis -d postgres)"

log "python 3.12 environment (pinned image, throwaway volume)"
PY=$(ci_container pip)
podman volume create --label "$CI_SUITE_LABEL" --label "aegis.ci.run=$CI_RUN" "$VENV" >/dev/null
status=0
output=$(podman run --rm --name "$PY" --label "$CI_SUITE_LABEL" --label "aegis.ci.run=$CI_RUN" \
  -v "$VENV:/opt/venv" -v "$REPO_ROOT:/src:ro" -w /src --security-opt label=disable \
  "$AEGIS_PYTHON_IMAGE" sh -c '
    set -eu
    echo "[ci] $(python3 -V 2>&1)"
    python3 -m venv /opt/venv
    /opt/venv/bin/pip install --quiet --disable-pip-version-check --root-user-action=ignore \
      -r contracts/tests/requirements.txt
    if [ -f contracts/tests/requirements-db.txt ]; then
      /opt/venv/bin/pip install --quiet --disable-pip-version-check --root-user-action=ignore \
        -r contracts/tests/requirements-db.txt
    fi' 2>&1) || status=$?
printf '%s\n' "$output" | sed 's/^/    /' >&2
((status == 0)) || die "installing contracts/tests/requirements*.txt failed (exit $status)"
PY=

python_run() { # prints the command output, returns its exit status
  local script=$1
  podman run --rm --network "$NETWORK" \
    -v "$VENV:/opt/venv:ro" -v "$REPO_ROOT:/src:ro" -w /src \
    --security-opt label=disable -e AEGIS_TEST_PG_DSN="$DSN" -e PYTHONDONTWRITEBYTECODE=1 \
    "$AEGIS_PYTHON_IMAGE" /opt/venv/bin/python -I "$script" 2>&1
}

# --- python checks ------------------------------------------------------------
log "python: contracts/tests/validate_contracts.py"
output=$(python_run contracts/tests/validate_contracts.py) || {
  printf '%s\n' "$output" | sed 's/^/    /' >&2
  die "validate_contracts.py failed"
}
printf '%s\n' "$output" | sed 's/^/    /' >&2

for test_file in "${PYTHON_TESTS[@]}"; do
  log "python: $test_file"
  status=0
  output=$(python_run "$test_file") || status=$?
  printf '%s\n' "$output" | sed 's/^/    /' >&2
  ((status == 0)) || die "$test_file failed (exit $status)"
  grep -qE '^OK$' <<<"$output" || die "$test_file did not finish with unittest's OK"
  if grep -qE 'skipped=' <<<"$output"; then
    die "$test_file skipped tests - a skipped harness must fail this job"
  fi
done

# --- SQL chains ---------------------------------------------------------------
psql_file() {
  local database=$1 file=$2
  podman exec -i "$PG" psql -v ON_ERROR_STOP=1 -q -U aegis -d "$database" -f - <"$file"
}

run_chain() {
  local database=$1
  shift
  local file status=0 output
  output=$(for file in "$@"; do psql_file "$database" "$file" || exit 1; done 2>&1) || status=$?
  printf '%s\n' "$output" | sed 's/^/    /' >&2
  ((status == 0)) || die "SQL chain failed on database $database"
}

podman exec "$PG" psql -q -U aegis -d postgres -c "CREATE DATABASE aegis_clean" >/dev/null
podman exec "$PG" psql -q -U aegis -d postgres -c "CREATE DATABASE aegis_upgrade" >/dev/null

log "clean chain: $(basename "${MIGRATIONS[0]}") -> $(basename "${MIGRATIONS[-1]}") (${#MIGRATIONS[@]} migrations) + ${#CLEAN_TESTS[@]} SQL tests"
run_chain aegis_clean "${MIGRATIONS[@]}" "${CLEAN_TESTS[@]}"

log "upgrade chain: $(basename "${UPGRADE_CHAIN[0]}") -> fixtures -> assertions + ${#UPGRADE_TESTS[@]} SQL tests"
run_chain aegis_upgrade "${UPGRADE_CHAIN[@]}" \
  "$TESTS_DIR/upgrade_assertions.sql" \
  "${UPGRADE_TESTS[@]}"

log "contracts gate: PASS (${#MIGRATIONS[@]} migrations, ${#CLEAN_TESTS[@]} clean tests, ${#UPGRADE_TESTS[@]} upgrade tests, $((${#PYTHON_TESTS[@]} + 1)) python checks)"
