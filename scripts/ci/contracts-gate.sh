#!/usr/bin/env bash
# The contract gate of contracts/README.md section "Kiểm tra".
#
# That README section is the single source of truth: scripts/ci/read-contract-gate.py reads
# the python suites, the PostgreSQL clean chain and the upgrade-chain order from it, and the
# gate fails loudly when any of them cannot be parsed or when a file on disk is not covered
# by it. Nothing in this script keeps a second copy of those lists.
#
#   * python   - every suite the README lists, on Python 3.12 in a container, with
#                AEGIS_TEST_PG_DSN pointing at this script's own throwaway PostgreSQL 16.
#                A suite named test_*.py that skips, or that does not end with unittest's
#                "OK", fails the job: a skipped harness is not evidence.
#   * postgres - the README's clean chain on an empty database, then its upgrade chain on a
#                second database.
#
# Everything runs in rootless podman as the current user; passwords are generated per run.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_cmd podman
require_cmd python3

NETWORK=$(ci_container net)
PG=$(ci_container pg)
VENV=$(ci_container venv)
PY=
PLAN=$(mktemp -t aegis-contract-gate-XXXXXX)
PG_PASSWORD=$(random_password)
DSN="postgresql://aegis:${PG_PASSWORD}@${PG}:5432/postgres"

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
  rm -f "$PLAN"
  exit "$status"
}
trap cleanup EXIT

# --- the plan, read from contracts/README.md ----------------------------------
python3 "$CI_DIR/read-contract-gate.py" "$REPO_ROOT" >"$PLAN" ||
  die "cannot read the contract gate plan from contracts/README.md section \"Kiểm tra\""

mapfile -t REQUIREMENTS < <(awk '$1 == "requirement" { print $2 }' "$PLAN")
mapfile -t PYTHON_CHECKS < <(awk '$1 == "python" { print $2 }' "$PLAN")
mapfile -t CLEAN_CHAIN < <(awk '$1 == "clean" { print $2 }' "$PLAN")
mapfile -t UPGRADE_CHAIN < <(awk '$1 == "upgrade" { print $2 }' "$PLAN")

((${#REQUIREMENTS[@]})) || die "the plan has no requirements file"
((${#PYTHON_CHECKS[@]})) || die "the plan has no python suites"
((${#CLEAN_CHAIN[@]})) || die "the plan has no clean chain"
((${#UPGRADE_CHAIN[@]})) || die "the plan has no upgrade chain"

absolute() {
  local path
  for path in "$@"; do printf '%s/%s\n' "$REPO_ROOT" "$path"; done
}
mapfile -t CLEAN_FILES < <(absolute "${CLEAN_CHAIN[@]}")
mapfile -t UPGRADE_FILES < <(absolute "${UPGRADE_CHAIN[@]}")

log "plan from contracts/README.md: ${#PYTHON_CHECKS[@]} python checks, clean chain ${#CLEAN_CHAIN[@]} files, upgrade chain ${#UPGRADE_CHAIN[@]} files"

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
    for requirement in "$@"; do
      echo "[ci] requirements: $requirement"
      /opt/venv/bin/pip install --quiet --disable-pip-version-check --root-user-action=ignore \
        -r "$requirement"
    done' sh "${REQUIREMENTS[@]}" 2>&1) || status=$?
printf '%s\n' "$output" | sed 's/^/    /' >&2
((status == 0)) || die "installing the contract requirements failed (exit $status)"
PY=

python_run() { # prints the command output, returns its exit status
  local script=$1
  podman run --rm --network "$NETWORK" \
    -v "$VENV:/opt/venv:ro" -v "$REPO_ROOT:/src:ro" -w /src \
    --security-opt label=disable -e AEGIS_TEST_PG_DSN="$DSN" -e PYTHONDONTWRITEBYTECODE=1 \
    "$AEGIS_PYTHON_IMAGE" /opt/venv/bin/python -I "$script" 2>&1
}

# --- python checks ------------------------------------------------------------
for check in "${PYTHON_CHECKS[@]}"; do
  log "python: $check"
  status=0
  output=$(python_run "$check") || status=$?
  printf '%s\n' "$output" | sed 's/^/    /' >&2
  ((status == 0)) || die "$check failed (exit $status)"
  case $(basename "$check") in
  test_*.py)
    grep -qE '^OK$' <<<"$output" || die "$check did not finish with unittest's OK"
    if grep -qE 'skipped=' <<<"$output"; then
      die "$check skipped tests - a skipped harness must fail this job"
    fi
    ;;
  esac
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

log "clean chain: ${#CLEAN_FILES[@]} files from contracts/README.md"
run_chain aegis_clean "${CLEAN_FILES[@]}"

log "upgrade chain: ${#UPGRADE_FILES[@]} files from contracts/README.md"
run_chain aegis_upgrade "${UPGRADE_FILES[@]}"

log "contract gate: PASS (${#PYTHON_CHECKS[@]} python checks, ${#CLEAN_FILES[@]} clean files, ${#UPGRADE_FILES[@]} upgrade files)"
