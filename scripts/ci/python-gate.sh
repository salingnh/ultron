#!/usr/bin/env bash
# The Python gate of the `python` workflow (G1.1a): exactly `make lint test codegen-check`.
#
# Differences from a plain `make` run on the host:
#   * uv is required and resolved even when the runner service did not inherit ~/.local/bin in
#     PATH; `uv sync --frozen` installs the committed lockfile for Python 3.12 (uv downloads the
#     interpreter when the host only has another version);
#   * a throwaway PostgreSQL 16 container is published on a random loopback port and its DSN is
#     exported as AEGIS_TEST_PG_DSN, so the migration-runner database tests really run instead of
#     being skipped;
#   * AEGIS_NO_SKIPS=1 turns every skip into a failure: a check that did not run is not evidence
#     (tests/conftest.py implements the rule).
#
# The container is named/labelled like the contract gate's (`aegis.ci.suite=contracts`), so
# scripts/ci/cleanup.sh removes it too if this script is killed before its own trap.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

UV=${UV:-$(command -v uv || true)}
if [[ -z $UV && -x $HOME/.local/bin/uv ]]; then
  UV=$HOME/.local/bin/uv
fi
[[ -n $UV ]] || die "uv is not installed - install uv (https://docs.astral.sh/uv/) and re-run"
export PATH="$(dirname "$UV"):$PATH"

require_cmd podman

PG=$(ci_container pg-python)
PG_PASSWORD=$(random_password)

cleanup() {
  local status=$?
  if ((status != 0)); then
    dump_logs "$PG"
  fi
  remove_container "$PG"
  exit "$status"
}
trap cleanup EXIT

log "python gate: $("$UV" --version), $(python3 -V 2>&1 || true)"
log "locked environment (uv sync --frozen --python 3.12)"
"$UV" sync --frozen --python 3.12
log "project interpreter: $(uv run --frozen python -V 2>&1)"

log "throwaway PostgreSQL 16 as $PG (loopback port, random password)"
start_container "$PG" "$AEGIS_PG_IMAGE" \
  -e POSTGRES_PASSWORD="$PG_PASSWORD" -e POSTGRES_USER=aegis -e POSTGRES_DB=postgres \
  --tmpfs /var/lib/postgresql/data -p 127.0.0.1::5432

for _ in $(seq 1 60); do
  podman exec "$PG" pg_isready -U aegis -d postgres >/dev/null 2>&1 && break
  sleep 1
done
podman exec "$PG" pg_isready -U aegis -d postgres >/dev/null 2>&1 || die "PostgreSQL did not become ready"
PG_PORT=$(podman port "$PG" 5432/tcp | head -1 | sed 's/.*://')
[[ -n $PG_PORT ]] || die "cannot read the published PostgreSQL port"
log "postgres $(podman exec "$PG" psql -tAc 'SHOW server_version' -U aegis -d postgres) on 127.0.0.1:$PG_PORT"

export AEGIS_TEST_PG_DSN="postgresql://aegis:${PG_PASSWORD}@127.0.0.1:${PG_PORT}/postgres"
export AEGIS_NO_SKIPS=1

log "make lint test codegen-check"
make --no-print-directory -C "$REPO_ROOT" lint test codegen-check

log "python gate: PASS"
