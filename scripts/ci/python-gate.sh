#!/usr/bin/env bash
# The Python gate of the `python` workflow (G1.1a): exactly `make lint test codegen-check`.
#
# Differences from a plain `make` run on the host:
#   * uv is required and resolved even when the runner service did not inherit ~/.local/bin in
#     PATH; `uv sync --frozen` installs the committed lockfile for Python 3.14 (uv downloads the
#     interpreter when the host only has another version);
#   * a throwaway PostgreSQL 16 container is published on a random loopback port and its DSN is
#     exported as AEGIS_TEST_PG_DSN, so the migration-runner database tests really run instead of
#     being skipped;
#   * a throwaway Neo4j 5.26 (the same pinned image the contract gate uses) is published on a
#     random loopback bolt port and exported as AEGIS_TEST_NEO4J_URI/AEGIS_TEST_NEO4J_PASSWORD, so
#     the M23 projector tests (G1.4b) execute the committed Cypher against a real graph instead of
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

: >"$AEGIS_CI_VOLUME_LOG"
PG=$(ci_container pg-python)
PG_PASSWORD=$(random_password)
NEO4J=$(ci_container neo4j-python)
NEO4J_PASSWORD=$(random_password)

cleanup() {
  local status=$?
  if ((status != 0)); then
    dump_logs "$PG"
    dump_logs "$NEO4J"
  fi
  remove_container "$PG"
  remove_container "$NEO4J"
  if ! check_job_volume_leaks "python gate" && ((status == 0)); then
    status=1
  fi
  rm -f "$AEGIS_CI_VOLUME_LOG"
  exit "$status"
}
trap 'exit 130' INT
trap 'exit 143' TERM
trap cleanup EXIT

log "python gate: $("$UV" --version), $(python3 -V 2>&1 || true)"
log "locked environment (uv sync --frozen --python 3.14)"
"$UV" sync --frozen --python 3.14
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

log "throwaway Neo4j 5.26 as $NEO4J (loopback bolt port, random password)"
# The `aegis.test.graph=1` label marks this Neo4j as disposable: the M23 tests wipe the graph they
# run against, so they accept only a container carrying it (tests/graph_support.py). A dev-stack or
# hand-started Neo4j never has it, which is what stops a gate run from wiping a shared graph.
start_container "$NEO4J" "$AEGIS_NEO4J_IMAGE" \
  --label aegis.test.graph=1 \
  --tmpfs /data:rw,size=1g,mode=1777 \
  --tmpfs /logs:rw,size=64m,mode=1777 \
  -e NEO4J_AUTH="neo4j/$NEO4J_PASSWORD" \
  -e NEO4J_server_memory_heap_initial__size=512m \
  -e NEO4J_server_memory_heap_max__size=1g \
  -e NEO4J_server_memory_pagecache_size=512m \
  -p 127.0.0.1::7687
for _ in $(seq 1 120); do
  podman exec "$NEO4J" cypher-shell -u neo4j -p "$NEO4J_PASSWORD" 'RETURN 1' >/dev/null 2>&1 && break
  sleep 2
done
podman exec "$NEO4J" cypher-shell -u neo4j -p "$NEO4J_PASSWORD" 'RETURN 1' >/dev/null 2>&1 \
  || die "Neo4j did not become ready"
NEO4J_PORT=$(podman port "$NEO4J" 7687/tcp | head -1 | sed 's/.*://')
[[ -n $NEO4J_PORT ]] || die "cannot read the published Neo4j bolt port"
log "neo4j $(podman exec "$NEO4J" cypher-shell -u neo4j -p "$NEO4J_PASSWORD" \
  'CALL dbms.components() YIELD versions RETURN versions' 2>/dev/null | tail -1) on 127.0.0.1:$NEO4J_PORT"

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
export AEGIS_TEST_NEO4J_URI="bolt://127.0.0.1:${NEO4J_PORT}"
export AEGIS_TEST_NEO4J_PASSWORD="$NEO4J_PASSWORD"
export AEGIS_NO_SKIPS=1

log "make lint test codegen-check"
make --no-print-directory -C "$REPO_ROOT" lint test codegen-check

log "python gate: PASS"
