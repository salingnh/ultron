-- G0.1 spike fakes. NOT product DDL:
--   * aegis.*        = real migrations 0001-0004 (unchanged, used by the ready-job query)
--   * spike.*        = fake MCP registry + observations used to prove idempotency/recovery
--   * langgraph.*    = tables created by langgraph-checkpoint-postgres (schema named by 0001_init.sql:17)
SET search_path = spike, public;

-- One row per Temporal run of CampaignWorkflow: proves Continue-As-New carries the cursor.
CREATE TABLE IF NOT EXISTS workflow_run (
  id                    bigserial PRIMARY KEY,
  workflow_id           text        NOT NULL,
  run_id                text        NOT NULL,
  first_run_id          text        NOT NULL,
  continued_from_run_id text,
  cursor_in             integer     NOT NULL,
  cycle_in              integer     NOT NULL,
  started_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (run_id)
);

-- Node entries per activity attempt: proves a restarted activity resumes at the
-- LangGraph checkpoint instead of replaying the graph from the first node.
CREATE TABLE IF NOT EXISTS node_log (
  id               bigserial PRIMARY KEY,
  session_id       text        NOT NULL,
  activity_attempt integer     NOT NULL,
  node             text        NOT NULL,
  ts               timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- Model calls (fake client): a resumed session must not repeat completed model calls.
CREATE TABLE IF NOT EXISTS model_call (
  id          bigserial PRIMARY KEY,
  session_id  text        NOT NULL,
  attempt     integer     NOT NULL,
  node        text        NOT NULL,
  tokens_in   integer     NOT NULL,
  tokens_out  integer     NOT NULL,
  ts          timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- Fake MCP registry / job store (stands in for M05+M06 dispatch).
-- idempotency_key is UNIQUE: the second dispatch of the same key returns the same
-- job_id (product rule: same key + same request => same job, never a second job).
CREATE TABLE IF NOT EXISTS mcp_job (
  job_id             uuid        PRIMARY KEY,
  campaign_id        text        NOT NULL,
  idempotency_key    text        NOT NULL UNIQUE,
  capability         text        NOT NULL,
  input_hash         text        NOT NULL,
  status             text        NOT NULL DEFAULT 'RUNNING'
                     CHECK (status IN ('QUEUED','RUNNING','SUCCEEDED','FAILED','CANCELLED')),
  dispatch_calls     integer     NOT NULL DEFAULT 1,
  complete_at        timestamptz NOT NULL DEFAULT now(),
  first_dispatched_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_dispatch_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
  finished_at        timestamptz
);

-- Last result written by a session activity attempt (also survives a worker kill).
CREATE TABLE IF NOT EXISTS session_state (
  session_id   text        PRIMARY KEY,
  campaign_id  text        NOT NULL,
  status       text        NOT NULL,          -- completed | canceled
  stop_reason  text,
  steps        integer     NOT NULL,
  cursor       integer     NOT NULL,
  attempts     integer     NOT NULL DEFAULT 1,
  result       jsonb       NOT NULL,
  updated_at   timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- Ordered evidence trail of what the spike did (used by tests and the report).
CREATE TABLE IF NOT EXISTS event (
  id      bigserial PRIMARY KEY,
  kind    text        NOT NULL,
  payload jsonb       NOT NULL,
  ts      timestamptz NOT NULL DEFAULT clock_timestamp()
);
