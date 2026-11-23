# Spike G0.3a — MCP Streamable HTTP, `_meta`, idempotent `tools/call`, latency

Throwaway spike for plan card **G0.3a**. Code lives on branch `spike/g0.3-mcp`
and is **not** merged; the conclusions that matter for G1.2b are rolled into
[`contracts/mcp/README.md`](../../contracts/mcp/README.md) (docs-only PR to main).
Fake registry only: no PostgreSQL, no sandbox, no scanner.

Acceptance from the card:

| Card criterion | Evidence |
| --- | --- |
| Streamable HTTP MCP server + client with a chosen SDK | `aegis_mcp/server.py`, `aegis_mcp/client.py`, `tests/test_transport.py` (raw wire) |
| Read `params._meta` keys (contracts/mcp/README.md table) | `aegis_mcp/meta.py`, `tests/test_meta.py` |
| `tools/list` with wrapped schemas | `aegis_mcp/contracts.py`, `tests/test_tools_list.py` |
| Missing/wrong `_meta` → `-32602` + `INPUT_INVALID` | `tests/test_meta.py`, `tests/test_transport.py::test_raw_missing_meta_is_jsonrpc_minus_32602_with_input_invalid` |
| Same `idempotency_key` ×100 → one job (fake registry) | `tests/test_idempotency.py` (all three burst cases) |
| Latency numbers (NFR-04 registry P95 < 300 ms @ 100 providers) | `bench/bench_latency.py` → `benchmarks/latency.json` |

## Stack and why

* Python 3.12.13 (uv-managed), [`mcp` 2.3.0](https://pypi.org/project/mcp/2.3.0/)
  (released 2026-10-02, past the 14-day rule), MCP protocol `2025-11-25`
  negotiated by the SDK, `uvicorn` 0.54.0, `jsonschema` 4.26.0 (the version in
  `contracts/tests/requirements.txt`), `httpx2` only as the transport client of
  the SDK.
* Lowlevel `mcp.server.lowlevel.Server` with `on_list_tools` / `on_call_tool`
  plus `server.streamable_http_app(...)`: the decorator-style helpers derive
  input schemas from Python signatures, which cannot express the contract's
  wrapped `capability-request.v2` schema.
* `ctx.params.meta` is the raw `_meta` map (`typings`-level open `TypedDict`), so
  `aegis.io/*` keys round-trip untouched. `ctx.request` is the Starlette
  request, so the transport session id (`Mcp-Session-Id` header) is available to
  bind the server-side session context.

## Layout

```
aegis_mcp/contracts.py   contract loading, $ref bundling, wrapped tool schemas, shared format checker
aegis_mcp/meta.py        the four aegis.io/* keys: parsing, format checks, JSON pointers
aegis_mcp/registry.py    fake registry: 100 providers, jobs, per-key idempotency, fake session directory
aegis_mcp/service.py     transport-free tools/list + tools/call logic (the part that is measured)
aegis_mcp/server.py      lowlevel Server + Streamable HTTP app; `python -m aegis_mcp.server`
aegis_mcp/client.py      SDK client helper + raw JSON-RPC helpers for wire assertions
tests/                   42 tests
bench/bench_latency.py           NFR-04 scenarios
bench/bench_session_concurrency.py  one session vs many sessions vs stateless
benchmarks/*.json        recorded runs (environment, n, p50/p90/p95/p99/max)
```

## Run

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r requirements.txt
.venv/bin/python -m pytest -q
.venv/bin/python -m bench.bench_latency            # writes benchmarks/latency.json
.venv/bin/python -m bench.bench_session_concurrency --out benchmarks/session-concurrency.json
.venv/bin/python -m bench.bench_session_concurrency --stateless --out benchmarks/stateless-concurrency.json
```

## Implementation notes (the decisions G1.2b should reuse)

1. **Schemas must be self-contained on the wire.** Contract schemas use relative
   `$ref`s (`../../common/ids.v2.schema.json#/$defs/DomainTarget`) that only
   resolve against the bundle's `$id`s. `contracts.bundle()` resolves every ref
   and hoists it into the tool schema's own `$defs` (`ids.v2.DomainTarget`, …).
   An MCP client never sees the bundle, so an unbundled schema is unusable.
2. **Compile the JSON Schema validators once.** A naive
   `Draft202012Validator(schema)` per call (which re-runs `check_schema`) costs
   ~18 ms per call here; after caching it is 0.52 ms. This is the difference
   between failing and passing NFR-04.
3. **Defaults are merged before validation** (`apply_defaults`), exactly like
   M05 merges manifest `inputDefaults`: request-level `priority=50`,
   `depends_on=[]`, plus capability-level defaults (`recursive`, `max_results`,
   `record_types`). The fingerprinted input must be the merged one.
4. **Two error channels, deliberately split.** Missing/wrong `_meta` and
   argument/schema violations are protocol errors: JSON-RPC `-32602` whose
   `error.data` is a full `error.v2` object (`code=INPUT_INVALID`, `field` =
   RFC 6901 pointer, `next_action=FIX_INPUT`, `trace_id`). Registry/policy
   decisions (no provider, idempotency conflict) are tool results:
   `isError=true` with `capability-response.v2` (`decision=denied`, `error`).
5. **Session context is bound server-side, never taken from `_meta`.** The fake
   session directory holds the known campaign/agent-session pairs; the first
   call on a transport session binds `Mcp-Session-Id` → context, and any later
   `_meta` pair that differs is `INPUT_INVALID` (tested for same-campaign other
   session and other campaign). A real implementation binds at initialize from
   the `campaign`/`agent_session` rows.
6. **Idempotency is a registry property, not a transport one.** One job per
   `(campaign_id, idempotency_key)` under a per-key lock; same fingerprint →
   `duplicate` + same `job_id`; different input/provider pin/`scan_cycle` →
   conflict; different `priority`/`depends_on` → conflict (scheduling never
   identifies a scan). The key is treated as opaque (8..128 of
   `[A-Za-z0-9._:-]`); the README's `<session_id>:step:<n>` form is a client
   convention only.
7. **`isError` results still validate.** Every `structuredContent` is validated
   against `capability-response.v2` before it leaves the server, so a decision
   shape bug fails loudly in tests instead of reaching the agent.

## Measured results

Environment: Xeon E5-2680 v4, 56 vCPU, 125 GiB, Fedora 44, loopback only,
100 providers, 3 capabilities, Python 3.12.13, `mcp` 2.3.0. Full data:
`benchmarks/latency.json` (500 iterations per HTTP scenario, 5000 handler
iterations), `benchmarks/session-concurrency.json`,
`benchmarks/stateless-concurrency.json`.

| Scenario | p50 | p95 | p99 | max | NFR-04 P95 < 300 ms |
| --- | --- | --- | --- | --- | --- |
| `tools/list` (HTTP JSON, 3 wrapped tools) | 4.05 ms | 4.32 ms | 4.46 ms | 110.6 ms¹ | pass |
| `tools/call` handler (no HTTP) | 0.52 ms | 0.62 ms | 0.91 ms | 2.26 ms | pass |
| `tools/call` handler + 5 ms simulated registry write | 5.77 ms | 6.14 ms | 6.36 ms | 109.6 ms¹ | pass |
| `tools/call` HTTP JSON | 3.39 ms | 3.64 ms | 3.73 ms | 4.42 ms | pass |
| `tools/call` HTTP SSE | 5.01 ms | 5.54 ms | 5.87 ms | 6.54 ms | pass |
| `tools/call` HTTP, 16 concurrent, distinct keys | 53.0 ms | 67.3 ms | 135.4 ms | 156.7 ms | pass (272.7 calls/s) |

¹ single first-call outlier (cold import/pydantic compile), not the steady state.

Idempotency burst (`same_idempotency_key_burst_100`): 100 concurrent
`tools/call` with one key → **1 job**, `approved`=1, `duplicate`=99, 68.6 ms
wall. The negative control (`tests/test_idempotency.py::
test_without_the_idempotency_lock_duplicates_appear`) disables the lock and gets
more than one job, so the burst test does detect a missing unique index.

Transport concurrency (200 requests, 50 concurrent POSTs, raw wire):

| Shape | Throughput | p50 | p95 |
| --- | --- | --- | --- |
| one MCP session, sequential | 367 req/s | 2.49 ms | 3.73 ms |
| one MCP session, 50 concurrent | 275 req/s | 151.9 ms | 207.7 ms |
| 200 separate sessions, 50 concurrent | 136 req/s | 81.5 ms | 99.9 ms |
| stateless transport, 50 concurrent | 244 req/s | 133.0 ms | 351.1 ms |

**Conclusion for NFR-04**: the 300 ms registry P95 target is comfortably met by
the MCP boundary itself with the fake registry, with or without a simulated
5 ms registry write. It does **not** yet prove NFR-04 for the real M05: that
number needs a PostgreSQL-backed registry measured in G1.1c/G1.2b with the same
harness. The table also shows this handler is CPU-bound (concurrency raises
per-call latency without raising throughput; ~250–370 `tools/call`/s per
process), so NFR-04 sizing must assume a few worker processes, not one.

## Open items handed to the plan/leader

1. `error.v2` has no `CONFLICT` code for "same idempotency key, different scan";
   the spike returns `INPUT_INVALID` + `FIX_INPUT` and points `field` at the key.
   S1.2a (hash/receipt/idempotency) owns the final decision.
2. `scan_cycle` is not in the `_meta` table; the spike takes it from the
   server-side session context. G1.1c must define where a new scan cycle starts
   (session step vs explicit operator action).
3. `capability-response.v2` has no field for "which idempotency key produced this
   job"; the agent can only correlate via `job_id`. Probably fine, worth a look.
4. Wire behaviour chosen here (`-32602` for schema violations, `isError` for
   policy/registry decisions) should be written into `contracts/mcp/README.md`
   by G1.2b if it diverges; the spike kept the README's explicit rule for
   `_meta` only.
