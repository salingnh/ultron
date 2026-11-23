# G0.1 decision memo — Temporal/LangGraph nesting, cancel, replay, scheduling

Scope: card G0.1. Decides (a) how the LangGraph agent session is nested inside Temporal,
(b) how cancel propagates, (c) whether Temporal replay is a usable gate, (d) the M02
ready-job query and its wait reasons. Evidence: `tests/`, `evidence/`, README table.

## Decision 1 — the agent session is hosted by the `run_agent_session` activity (variant A)

`CampaignWorkflow` stays the long-lived Temporal workflow per campaign. Each cycle it runs
`fetch_delta` and then one `run_agent_session` activity; that activity hosts the LangGraph
graph and writes LangGraph checkpoints to PostgreSQL (`langgraph` schema, thread_id = session_id).
The workflow never sees graph nodes, model calls or tool outputs — only `session_id`, cursor and
the small `AgentSessionResult` (job ids, stop reason, steps).

Rejected alternative (variant B, implemented for measurement only in `session_workflow.py`):
one Temporal workflow per session with one activity per graph node.

| Measured, identical one-round session | A: activity-hosted (1 campaign cycle incl. session) | B: workflow per session |
| --- | --- | --- |
| Temporal history events | 29 | 41 |
| Temporal history bytes | 19 467 | 32 208 |
| Largest single payload | 380 B | 1 396 B |
| Still needs a campaign parent workflow | no | yes |

Why B loses beyond the numbers: the graph topology (node order, stop conditions) would live in
workflow code, so any node/edge change is a replay-breaking change that needs patching/versioning;
each node's inputs/outputs (plan, observation, tool results) enter Temporal history, which
contradicts `02-nen-tang.md` "Temporal chứa ID/reference, không raw lớn"; LLM/scanner I/O still has to
be activities; and cancellation gains a layer (parent → child workflow → node activity) while a
cancelled workflow cannot reliably run cleanup activities. Variant B restart also works
(`tests/test_nesting_comparison.py`), so this is a design decision, not a capability gap.

## Decision 2 — cancel propagates signal → activity task cancel → `cancel_jobs`

Proven path (`tests/test_cancel.py`, 120 s fake job cancelled in < 20 s):

1. `cancel` signal handler sets the flag **and** cancels the in-flight activity task
   (`asyncio.create_task` around `execute_activity`, cancelled from the handler — deterministic,
   unlike `asyncio.wait`, which the Temporal sandbox rejects as non-deterministic).
2. The session activity is scheduled with
   `cancellation_type=ActivityCancellationType.WAIT_CANCELLATION_COMPLETED` and
   `heartbeat_timeout=3 s`; `await_result` heartbeats every 400 ms, so cancellation is delivered
   quickly and the activity writes its `canceled` session state before re-raising.
3. The workflow then runs the `cancel_jobs` activity (in-flight jobs → `CANCELLED`) and completes
   with `status=CANCELED`; the query reports `state=CANCELED`.

Implementation gotcha worth carrying into G1.1d: an activity cancelled while the workflow awaits it
raises `temporalio.exceptions.ActivityError` whose cause is a cancelled failure — **not**
`asyncio.CancelledError`. Catch it with `temporalio.exceptions.is_cancelled_exception(exc)` and only
when `self._cancel_requested` is set, so real activity failures still propagate.

The activity-side cleanup (marking the session cancelled) runs after catching
`asyncio.CancelledError` inside the activity and is bounded by `WAIT_CANCELLATION_COMPLETED`.
`cancel_jobs` is the authoritative job-level stop; it also covers a session that dies before
finishing its cleanup.

## Decision 3 — restart/idempotency: checkpoint first, idempotency key second

- Worker SIGKILLed inside `await_result`: the retried activity resumes at the next uncompleted
  LangGraph node (attempt 2 starts at `await_result`), `dispatch_calls = 1`, one job, model calls not
  repeated (`tests/test_resume.py`).
- Even with every LangGraph checkpoint deleted, the retry re-runs the session from the first node and
  the MCP idempotency key returns the **same** job (`dispatch_calls = 2`, 1 row). The key is
  `sha256(g0.1|<session_id>|step=<n>|<capability>|<input_hash>)` — stable across retries, independent
  of Temporal history.
- Both layers are needed: the checkpoint avoids repeated model/tool work, the idempotency key keeps
  "one job per logical request" true when checkpoints are lost or a container is recreated.
- Feed-forward for G1.1c: the job idempotency key must be derivable outside the workflow (session +
  step + capability + canonical input hash), not from Temporal run ids.

## Decision 4 — replay is a usable gate, with one caveat

`Replayer(workflows=[CampaignWorkflow]).replay_workflow(history)` accepts real recorded history
(29 events). The negative control is a workflow with the **same workflow type** but a different first
command (`changed_workflow.py`): replay fails with `TMPRL1100 Nondeterminism error` — that is the
regression a CI gate must catch.

Caveat: the Temporal sandbox blocks `random`, `uuid4` and wall-clock calls inside workflow code, so a
"nondeterministic workflow" cannot be built from those; command-sequence changes are the realistic
control. G1.1d should run this replay step in CI against histories recorded by the smoke demo.

## Decision 5 — Continue-As-New and the campaign shell

`Continue-As-New` after N cycles carries `cursor`, `cycle` and execution settings; proven with 4 cycles
split 2+2: two Temporal runs, the second starting with `cursor_in = 2`, `cycle_in = 2`, same
`first_execution_run_id` (`tests/test_continue_as_new.py`). Workflow ID stays `campaign-<campaign_id>`;
task queues `aegis-orchestrator` / `aegis-agent` as in `interfaces/README.md` §7.

## Scheduling query (G0 scheduling gate)

`src/aegis_spike/ready.py` runs on the real `aegis.scan_job` / `aegis.job_dependency` DDL:

- ready = `status='QUEUED'` + pinned manifest + **every** dependency `SUCCEEDED`
  (`p.status <> 'SUCCEEDED'` blocks, so FAILED/CANCELLED never release);
- order = `priority DESC, created_at ASC, job_id ASC` + `LIMIT`;
- 5 000-job backlog, 10 % blocked by a dependency: p50 0.88 ms, p95 1.09 ms, limit 32, plan is
  `Limit → Nested Loop → Index Scan (scan_job_ready_order)` with no Sort node.

Proposed wait-reason enum for the X-4 contract gap (for S1.2b `job.v2` + flow API):
`dependency_pending`, `dependency_failed`, `dependency_cancelled`, `manifest_unpinned`
(legacy rows only — 0003's trigger requires the pin for every new job), plus the later
budget/window/concurrency reasons owned by G1.1d. The query already returns these reasons; only the
contract field is missing.

## Consequences / risks handed to G1

- G1.1d: `CampaignWorkflow` skeleton, signals/query as tested, `heartbeat_timeout` 3 s and a ≤ 1 s
  job-status poll inside the session activity, `cancel` handler cancelling the activity task.
- G1.2c: the session runs *inside* an activity; LangGraph stays the graph runtime and the Postgres
  checkpointer binds `thread_id = session_id`. Budget, ≤ 30 steps, idle-cycle pause and ledger writes
  remain to be built there (this spike only has a step counter and a bounded single round).
- Checkpoint tables belong in schema `langgraph` (already named by 0001_init.sql:17); the campaign
  workflow must not read them.
- Not covered here: multi-worker/concurrent campaigns, Temporal persistence durability/RPO, real MCP
  transport (G0.3a), real model drivers (G1.2a), budget enforcement.
