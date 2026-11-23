# G0.3b — graph concurrency and rebuild spike

Throwaway spike code for card G0.3b (item #51). Not product code, not imported by the
contract tests, not merged into the contracts bundle. The conclusions are in
`contracts/graph/model.md` §C04/§Dựng lại and in the worker report.

## What it measures

1. **100 concurrent writers, one `canonical_key`** — executes
   `contracts/graph/projector-upserts.cypher` statement 1 verbatim, first with exactly one
   attempt per writer (raw conflict rate), then with the retry policy a projector needs.
   Acceptance: one node, correct `asset_id`/`kind`/`campaign_ids`/`last_seen` (NFR-03).
   Also 100 distinct keys as the parallel-work upper bound.
2. **Outbox → graph end to end** — 100 pg writers commit real contract rows (asset,
   asset_campaign, relationship, finding, evidence, graph_revision, outbox_event) in one
   transaction per event, taking publication numbers from
   `0008_outbox_publication_order.sql`; one projector consumes `aegis.outbox_batch` at or
   below the published watermark and applies the same template (properties read from
   PostgreSQL, as `graph/model.md` specifies). Measures producer rate, publication lag,
   watermark refresh outcomes, drain time and end-to-end events/s.
3. **Crash-window redelivery** — deletes the last 100 `consumer_inbox` rows of generation
   `m23-projector#g1` and rewinds its cursor, then re-applies the same events: the graph
   must be unchanged (idempotent MERGE plus inbox dedup).
4. **Rebuild** — wipes the graph, replays the whole outbox under
   `m23-projector#g2` from cursor 0, and compares node/edge properties with the original
   snapshot (metadata, `pg_revision`, finding/evidence fields) plus a PostgreSQL
   reconciliation. Acceptance: equal, not just the same node count.
5. **Allocator choice** — the same writer transactions with the 0008 transactional counter
   and with the spike-only `nextval` variant under the same publication lock
   (`sql/allocator_nextval.sql`); plus the try-lock watermark of 0008 against a blocking
   exclusive lock (`sql/watermark_blocking.sql`, spike-only) to measure whether the
   watermark starves under 100 writers.
6. **Writer commit latency (G0.3b-0013)** — every producer transaction is timed from BEGIN to
   commit and reported as p50/p90/p99/max; the projector reports the distribution of the
   watermark refresh wait (the exclusive waiter queues behind active writers) and any
   bounded-wait timeouts. The blocking arm can run the real `0013_outbox_watermark_blocking.sql`
   instead of the spike-only SQL by setting `G03B_BLOCKING_WATERMARK_SQL=<path to that file>`;
   the harness verifies the resolved function definition (blocking vs try-lock) before writing.

## Run

```sh
python3.12 -m venv /tmp/g03b-venv
/tmp/g03b-venv/bin/pip install -r spikes/g0.3-graph/requirements.txt

# own throwaway containers (digests from PR #14 deploy/dev/images.env)
podman run -d --name g03b-pg -e POSTGRES_USER=aegis -e POSTGRES_PASSWORD=... -e POSTGRES_DB=aegis \
  -p 127.0.0.1:55471:5432 -v g03b-pgdata:/var/lib/postgresql/data \
  docker.io/library/postgres:16@sha256:3950ad7c3148ca2175ef1b6c36c9efbf78957ae8fbe8b3a5d7c35af50500382f \
  postgres -c max_connections=300 -c shared_buffers=512MB
podman run -d --name g03b-neo4j -e NEO4J_AUTH=neo4j/... \
  -e NEO4J_server_memory_heap_max__size=512m -e NEO4J_server_memory_pagecache_size=256m \
  -p 127.0.0.1:57474:7474 -p 127.0.0.1:57687:7687 -v g03b-neo4jdata:/data \
  docker.io/library/neo4j:5.26.33-community@sha256:51d0314ef86074f519003da8dd4daaa9fff72b8479672b742d7cab7f3064e3ed

# template database `spike`: apply contracts/db/postgres/0001..0009 in order (see README
# "Kiểm tra"), then:
G03B_PG_DSN=postgresql://aegis:...@127.0.0.1:55471/spike \
G03B_NEO4J_URI=bolt://127.0.0.1:57687 G03B_NEO4J_AUTH=neo4j/... \
/tmp/g03b-venv/bin/python spikes/g0.3-graph/run_spike.py all

# individual scenarios
... run_spike.py concurrent-upsert --writers 100
... run_spike.py alloc --allocator counter --writers 100 --events 1000 --runs 3
... run_spike.py pipeline --allocator counter --watermark try --writers 100 --events-per-writer 20

# rebuild the template database after a crash of a run
... run_spike.py pipeline ...     # each run drops its own g03b_* database again
```

Every scenario creates a database `g03b_*` from `TEMPLATE_DB` and drops it at the end, so
runs do not contaminate each other and the template stays clean. `out/` holds the JSON
results and snapshots (git-ignored).

## Spike-only files

- `sql/allocator_nextval.sql` — replaces `outbox_publication_alloc/reserve` and
  `outbox_watermark_refresh` with nextval versions. **Not** a proposed migration.
- `sql/last_counter.sql` — read-only `aegis.spike_publication_last()` helper for lag
  observation.
- `sql/watermark_blocking.sql` — replaces the watermark refresh with a blocking
  exclusive lock. **Not** a proposed migration; superseded by
  `contracts/db/postgres/0013_outbox_watermark_blocking.sql`, which the latency run applies via
  `G03B_BLOCKING_WATERMARK_SQL`.

The spike never edits migrations 0001–0009 or the product projector: the template file and
`constraints.cypher` are read from `contracts/` and executed verbatim.
