# Spike G0.1 — Temporal/LangGraph nesting, cancel, replay, ready-job query

Throwaway spike code for card **G0.1** (TASK.md G0, item #51). Nothing here is product code;
the conclusion lives in [`DECISION.md`](DECISION.md) and in
`docs/living/dac-ta-ky-thuat/02-nen-tang.md` §Phiên agent.

Status: **all acceptance scenarios pass on a fresh run** — `10 passed in 62.88s`
(`evidence/pytest-20261123T191222Z.txt`), Postgres 16 with the real contract migrations
0001–0004, standalone Temporal dev server, fake model/MCP clients (no API key).

## What is proven

| Acceptance (card G0.1) | Test | Evidence |
| --- | --- | --- |
| Kill worker mid-activity → resumes from checkpoint, no duplicate MCP job (idempotency key reused) | `tests/test_resume.py` | node log attempt 1 = `plan, select_tool, dispatch, await_result`; attempt 2 starts at `await_result`; 1 job row, `dispatch_calls = 1`; `plan`/`analyze` model calls not repeated |
| Same, when the checkpoint itself is lost | `tests/test_resume.py::test_idempotency_key_prevents_duplicate_job_when_checkpoint_is_lost` | graph starts over, dispatch runs twice, **one** job row, `dispatch_calls = 2`, same `job_id` |
| Temporal replay is deterministic | `tests/test_replay.py` | `Replayer` accepts the recorded history (`evidence/replay.json`) |
| The replay gate can fail | `tests/test_replay.py::test_incompatible_code_change_is_rejected_by_replay` | same workflow type + different first command → `TMPRL1100 Nondeterminism error` (`evidence/replay-negative.json`) |
| Cancel signal stops the session and the in-flight activity/job | `tests/test_cancel.py` | cancel→result in < 20 s with a 120 s job; job `CANCELLED`; session `canceled`; no `analyze`/`decide_next` nodes |
| Continue-As-New carries the cursor | `tests/test_continue_as_new.py` | 2 Temporal runs, second starts with `cursor_in = 2`, `cycle_in = 2`, `continued_from_run_id` = run 1 |
| Ready-job query: dependency/priority/order, failed predecessor | `tests/test_ready_query.py` | `SUCCEEDED` releases, `FAILED`/`CANCELLED` leave the dependent waiting with a reason; p95 **1.09 ms** over 5 000 QUEUED jobs, index `scan_job_ready_order` used (`evidence/ready-query.json`) |
| Nesting decision (activity-hosted vs workflow-per-session) | `tests/test_nesting_comparison.py` | variant A: 29 events / 19.4 KB / max payload 380 B; variant B: 41 events / 32.2 KB / max payload 1.4 KB (`evidence/nesting-comparison.json`) |

The ready-job query runs against the real `aegis.scan_job` / `aegis.job_dependency` DDL
(`src/aegis_spike/ready.py`), not a spike copy.

## Reproduce

Requires: rootless Podman, `uv`, network access for the pinned images/packages.

```sh
cd spikes/g0.1-temporal-langgraph
uv venv --python 3.12 .venv && uv pip install -r requirements.txt
scripts/run-scenarios.sh --fresh     # own Postgres container + Temporal dev server + pytest
scripts/temporal-server.sh stop && scripts/dev-down.sh   # remove only this spike's resources
```

`--fresh` removes this spike's own volume (`g01-spike-pgdata`) and the Temporal SQLite file.
Without it the existing state is reused.

Pins and hashes: [`deploy/pins.json`](deploy/pins.json). Containers/tools created by this spike
and nothing else: container `g01-spike-postgres`, volume `g01-spike-pgdata`, `127.0.0.1:58101`,
`127.0.0.1:7233` (Temporal dev server, `.tools/temporal`, SQLite under `.runtime/`).

## Layout

```
deploy/pins.json            pinned toolchain + sha256
deploy/spike-schema.sql     spike fakes (schema spike.*); aegis.* = real migrations
src/aegis_spike/
  workflows.py              CampaignWorkflow: signals pause/resume/cancel/job_completed,
                            query status(), Continue-As-New with cursor
  activities.py             fetch_delta, run_agent_session, run_graph_node, cancel_jobs, publish_snapshot
  agent_graph.py            LangGraph graph (plan→select_tool→dispatch→await_result→analyze→decide_next)
                            hosted by run_agent_session, Postgres checkpointer keyed by session_id
  session_workflow.py       variant B (workflow per session) used only for the comparison
  changed_workflow.py       replay negative control (same workflow type, incompatible commands)
  fakes.py                  FakeModelClient + FakeMcpRegistry (idempotency_key UNIQUE)
  ready.py                  M02 ready-job query + wait reasons on the real DDL
  worker.py                 two task queues: aegis-orchestrator, aegis-agent
tests/                      the acceptance scenarios above
evidence/                   captured runs (pytest log, replay, ready query, nesting comparison)
```

## Limits (do not read as product evidence)

- Fakes only: no real MCP transport (G0.3a), no real model driver (S1.4/G1.2a), no scanner.
- One worker process, one campaign at a time; no multi-worker/concurrency measurements.
- Temporal dev server with SQLite is a test fixture, not a durability/RPO test of Temporal persistence.
- Budget, step limit ≤ 30, idle cycles, ledger and context-window rules are G1.2c; this spike only
  enforces a step counter and a bounded single round.
- `manifest_unpinned` wait reason is unreachable for new jobs because 0003 requires the pin on INSERT;
  it only applies to legacy rows.
