#!/usr/bin/env bash
# The Python gate of the `python` workflow (G1.1a): `make lint test codegen-check`.
#
# Differences from a plain `make` run on the host:
#   * nothing of the host's uv or python is used: every run installs the checksum-verified uv
#     release of scripts/ci/uv.env, and that uv provides the exact Python in .python-version
#     itself (uv-managed only; it fails when it cannot) before `uv sync --frozen` installs the
#     committed lockfile;
#   * a throwaway PostgreSQL 18 container is published on a random loopback port and its DSN is
#     exported as AEGIS_TEST_PG_DSN, so the migration-runner database tests really run instead of
#     being skipped;
#   * pytest runs in PYTEST_WORKERS parallel workers (pytest-xdist). Each worker that runs the M23
#     projector tests (G1.4b) starts its own throwaway Neo4j 2026.10 (the pinned image the contract
#     gate uses), so the committed Cypher runs against a real graph; AEGIS_TEST_NEO4J_URI is unset;
#   * AEGIS_NO_SKIPS=1 turns every skip into a failure: a check that did not run is not evidence
#     (tests/conftest.py implements the rule).
#
# The container is named/labelled like the contract gate's (`aegis.ci.suite=contracts`), so
# scripts/ci/cleanup.sh removes it too if this script is killed before its own trap.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_cmd podman
require_cmd curl

: >"$AEGIS_CI_VOLUME_LOG"
PG=$(ci_container pg-python)
PG_PASSWORD=$(random_password)
UV_DIR=$(mktemp -d -t aegis-ci-uv-XXXXXX)

cleanup() {
  local status=$?
  if ((status != 0)); then
    dump_logs "$PG"
  fi
  remove_container "$PG"
  rm -rf "$UV_DIR"
  if ! check_job_volume_leaks "python gate" && ((status == 0)); then
    status=1
  fi
  rm -f "$AEGIS_CI_VOLUME_LOG"
  exit "$status"
}
trap 'exit 130' INT
trap 'exit 143' TERM
trap cleanup EXIT

UV=$("$CI_DIR/install-uv.sh" "$UV_DIR")
export PATH="$UV_DIR:$PATH"
export UV_PYTHON_PREFERENCE=only-managed UV_PYTHON_DOWNLOADS=automatic
log "python gate: $("$UV" --version) installed for this run"
PYTHON_VERSION=$(<"$REPO_ROOT/.python-version")
log "locked environment (uv sync --frozen --python $PYTHON_VERSION)"
"$UV" sync --frozen --python "$PYTHON_VERSION"
log "project interpreter: $("$UV" run --frozen python -c \
  'import platform, sys; print("Python", platform.python_version(), "from", sys.base_prefix)')"

log "throwaway PostgreSQL 18 as $PG (loopback port, random password)"
start_container "$PG" "$AEGIS_PG_IMAGE" \
  -e POSTGRES_PASSWORD="$PG_PASSWORD" -e POSTGRES_USER=aegis -e POSTGRES_DB=postgres \
  --tmpfs /var/lib/postgresql -p 127.0.0.1::5432

# Over TCP: the image's init server answers on the unix socket only and is stopped again, so a
# socket probe can report ready just before the database goes away.
for _ in $(seq 1 60); do
  podman exec "$PG" pg_isready -h 127.0.0.1 -U aegis -d postgres >/dev/null 2>&1 && break
  sleep 1
done
podman exec "$PG" pg_isready -h 127.0.0.1 -U aegis -d postgres >/dev/null 2>&1 || die "PostgreSQL did not become ready"
PG_PORT=$(podman port "$PG" 5432/tcp | head -1 | sed 's/.*://')
[[ -n $PG_PORT ]] || die "cannot read the published PostgreSQL port"
log "postgres $(podman exec "$PG" psql -tAc 'SHOW server_version' -U aegis -d postgres) on 127.0.0.1:$PG_PORT"

# Neo4j Community has one graph and the M23 tests wipe it, so the workers cannot share one: each
# pytest worker that needs a graph starts, labels and removes its own container
# (tests/graph_support.py). Pull the pinned image once, before the workers could race for it.
if ! podman image exists "$AEGIS_NEO4J_IMAGE" >/dev/null 2>&1; then
  log "pulling the pinned Neo4j image"
  podman pull "$AEGIS_NEO4J_IMAGE" >/dev/null || die "cannot pull $AEGIS_NEO4J_IMAGE"
fi

# The LLM gateway rotation test (G1.6) runs the digest-pinned LiteLLM proxy
# (deploy/llm-gateway/images.env) against two fake upstreams: no real provider, no key, no spend.
# Pull it once per runner; a missing image would otherwise turn the test into a silent skip, and
# AEGIS_NO_SKIPS rightly treats a check that did not run as a failure.
GATEWAY_IMAGE=$(sed -n 's/^AEGIS_LLM_GATEWAY_IMAGE=//p' "$REPO_ROOT/deploy/llm-gateway/images.env")
[[ -n $GATEWAY_IMAGE ]] || die "deploy/llm-gateway/images.env: AEGIS_LLM_GATEWAY_IMAGE missing"
if ! podman image exists "$GATEWAY_IMAGE" >/dev/null 2>&1; then
  log "pulling the pinned LLM gateway image (one-time, ~1.3 GB)"
  podman pull "$GATEWAY_IMAGE" >/dev/null || die "cannot pull $GATEWAY_IMAGE"
fi
export AEGIS_TEST_LLM_GATEWAY=1

export AEGIS_TEST_PG_DSN="postgresql://aegis:${PG_PASSWORD}@127.0.0.1:${PG_PORT}/postgres"
export AEGIS_NO_SKIPS=1
unset AEGIS_TEST_NEO4J_URI AEGIS_TEST_NEO4J_PASSWORD

# A fixed worker count, not `-n auto`: the host has 56 cores and five runners, and every worker
# that runs a graph test holds a Neo4j of up to ~1.5 GB. loadgroup keeps tests/xdist_support.LANES.
PYTEST_WORKERS=8
log "make lint test codegen-check (pytest: $PYTEST_WORKERS workers)"
make --no-print-directory -C "$REPO_ROOT" lint test codegen-check \
  PYTEST_ARGS="-n $PYTEST_WORKERS --dist loadgroup --durations=15"

log "python gate: PASS"
