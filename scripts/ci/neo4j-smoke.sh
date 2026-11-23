#!/usr/bin/env bash
# CI step 3: Neo4j Cypher smoke on a throwaway container. The assertions live in
# contracts/graph/tests/cypher_smoke.py and run the committed constraint and projector
# templates; this script only provides the database.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

require_cmd podman
require_cmd python3

NEO4J=$(ci_container neo4j)
NEO4J_PASSWORD=$(random_password)

cleanup() {
  local status=$?
  ((status == 0)) || dump_logs "$NEO4J"
  remove_container "$NEO4J"
}
trap cleanup EXIT

start_container "$NEO4J" "$AEGIS_NEO4J_IMAGE" \
  -e NEO4J_AUTH="neo4j/$NEO4J_PASSWORD" \
  -e NEO4J_server_memory_heap_initial__size=512m \
  -e NEO4J_server_memory_heap_max__size=512m \
  -e NEO4J_server_memory_pagecache_size=256m \
  -p 127.0.0.1::7474

address=$(podman port "$NEO4J" 7474/tcp)
[ -n "$address" ] || die "no published HTTP address for $NEO4J"
log "neo4j http: $address"

NEO4J_URI="http://$address" \
  NEO4J_PASSWORD="$NEO4J_PASSWORD" \
  NEO4J_READY_TIMEOUT=240 \
  python3 "$REPO_ROOT/contracts/graph/tests/cypher_smoke.py"

log "neo4j smoke: PASS"
