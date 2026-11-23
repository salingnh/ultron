-- S1 re-review @d4526b6 (R-1, R-2, R-3): 0012 stated two rules as row constraints, so they were
-- evaluated again on every UPDATE of a row that predates them, and one of them could not even be
-- created over history. Migration 0014 turns both into INSERT-time rules, holds the legacy rows it
-- finds, and binds the fields a job actually executes.
-- Apply after 0013 (and therefore after 0012).
BEGIN;
SET LOCAL search_path = aegis, public;

-- ---------------------------------------------------------------------------
-- 1. R-1 — clearing the cancel intent is not a cancel.
--
-- C06 (0007) says a terminal job reopens as generation+1/attempt=1/QUEUED *with the cancel intent
-- cleared*; 0011's reopen guard requires exactly that. 0012's trigger validated `cancel_requested_by`
-- whenever it changed, so the reopen cleared it to NULL and `is_actor(NULL)` failed: no job that ever
-- had a cancel intent could be reopened. Clearing is the absence of an intent, not a bad one.
CREATE OR REPLACE FUNCTION aegis.require_cancel_actor() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.cancel_requested_by IS NULL THEN
    RETURN NEW;   -- a reopen clears the intent (0007/0011); there is no actor to validate
  END IF;
  IF NEW.cancel_requested_by IS NOT DISTINCT FROM OLD.cancel_requested_by THEN
    RETURN NEW;   -- not this statement's change
  END IF;
  IF NOT aegis.is_actor(NEW.cancel_requested_by) THEN
    RAISE EXCEPTION 'cancel_requested_by must be an Actor {kind: operator|module|agent, id}'
      USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.cancel_requested_by->>'kind' = 'agent'
     AND (NEW.proposed_by IS NULL OR NEW.proposed_by->>'id' <> NEW.cancel_requested_by->>'id') THEN
    RAISE EXCEPTION 'an agent may only cancel a job it proposed (proposer %)', NEW.proposed_by
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
COMMENT ON FUNCTION aegis.require_cancel_actor() IS
  'OI-9/R-1: the cancel intent names a shape-checked Actor and an agent cannot cancel work it did not propose. Clearing the intent (reopen) is always allowed; the rule applies when it is set.';

-- ---------------------------------------------------------------------------
-- 2. R-2a — the proposer rule applies to new rows, not to history.
--
-- 0012 tightened `aegis.is_proposer` (id must be an agent_session UUID) but the CHECK that calls it
-- came from 0010, and PostgreSQL does not revalidate a CHECK when the function changes: a row with a
-- label proposer (`{"agent","session-1"}`, the shape 0010's own fixture used) got through 0012 and
-- then failed on *every* UPDATE. It could not be dispatched, cancelled or finalised, contradicting
-- README §Dữ liệu và migration ("kết quả terminal và hủy vẫn ghi bình thường"). The rule now lives
-- only in 0012's INSERT triggers (`proposer_session_required`), so history stays updatable.
ALTER TABLE scan_job DROP CONSTRAINT IF EXISTS proposed_by_is_agent_session;
ALTER TABLE policy_decision DROP CONSTRAINT IF EXISTS proposed_by_is_agent_session;
COMMENT ON COLUMN scan_job.proposed_by IS
  'C05/OI-8 proposer: the agent session that proposed the job (id = agent_session.session_id). Enforced on INSERT by aegis.require_job_proposer_session (kind agent, UUIDv7 session, same campaign); a row predating 0012 keeps its recorded value, is held for dispatch (LEGACY_PROPOSER_LABEL) and stays cancellable/finalisable. Immutable after acceptance.';
COMMENT ON COLUMN policy_decision.proposed_by IS
  'C05/OI-8 proposer of the request: the agent session (id = agent_session.session_id), enforced on INSERT by aegis.require_decision_proposer_session. A row predating 0012 keeps its recorded value; the table is append-only.';

-- ---------------------------------------------------------------------------
-- 3. R-2b — the projection rule applies to new rows, not to history.
--
-- 0012 added `targets` ⊆ canonical_key(target_refs) as a validated CHECK. A 0005–0011 row whose
-- `targets` held the seed's own canonical key (a legal shape for 0005, and the shape of the then
-- fixtures) makes that ALTER abort, so 0012 could not be applied over such a database at all; a
-- `NOT VALID` constraint would not help either, because it is still re-checked when the legacy row is
-- updated (cancel/finalise). The rule is therefore an INSERT trigger from here on, and 0012 no longer
-- creates the constraints (see its comment): history is held for dispatch instead of being locked.
ALTER TABLE scan_job DROP CONSTRAINT IF EXISTS scan_job_targets_canonical;
ALTER TABLE policy_decision DROP CONSTRAINT IF EXISTS policy_decision_targets_canonical;

CREATE FUNCTION aegis.require_canonical_projection() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.target_refs IS NOT NULL
     AND NOT aegis.is_canonical_projection(NEW.targets, NEW.target_refs) THEN
    RAISE EXCEPTION '% targets % contains a key that no TargetRef in target_refs resolves',
      TG_TABLE_NAME, NEW.targets
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
COMMENT ON FUNCTION aegis.require_canonical_projection() IS
  'OI-6/R-2b: `targets` may only project canonical_key entries of `target_refs` (it is never the identity source). Enforced on INSERT only, so a row that predates the rule keeps working.';
CREATE TRIGGER targets_projection_required BEFORE INSERT ON scan_job
  FOR EACH ROW EXECUTE FUNCTION aegis.require_canonical_projection();
CREATE TRIGGER targets_projection_required BEFORE INSERT ON policy_decision
  FOR EACH ROW EXECUTE FUNCTION aegis.require_canonical_projection();
-- `targets_…` sorts after `target_refs_required`, so an unknown seed is still reported as a seed
-- problem rather than as an unexplainable projection (that precedence existed before 0014).

-- ---------------------------------------------------------------------------
-- 4. The two legacy shapes are held for dispatch, not locked.
--
-- README §Dữ liệu và migration: a held row can still record its terminal result and be cancelled; it
-- just cannot be started. That is what these reasons buy: the row stays readable and closable, and the
-- scheduler's "dispatchable" filter (dispatch_block_reasons IS NULL) skips it.
CREATE OR REPLACE FUNCTION aegis.is_dispatch_block_reasons(v text[]) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT v IS NOT NULL
     AND cardinality(v) > 0
     AND NOT EXISTS (SELECT 1 FROM unnest(v) c
                      WHERE c NOT IN ('LEGACY_POLICY_V1','LEGACY_MISSING_MANIFEST_PIN',
                                      'LEGACY_MISSING_TARGET_REFS','LEGACY_ACTOR',
                                      'LEGACY_PROPOSER_LABEL','LEGACY_TARGET_PROJECTION'))
     AND cardinality(v) = (SELECT count(DISTINCT c) FROM unnest(v) c);
$$;
COMMENT ON FUNCTION aegis.is_dispatch_block_reasons(text[]) IS
  'True for a non-empty, duplicate-free subset of the six legacy dispatch-block reasons.';

CREATE OR REPLACE FUNCTION aegis.legacy_dispatch_block(j scan_job) RETURNS text[] LANGUAGE sql STABLE AS $$
  SELECT array_agg(t.code ORDER BY t.code)
    FROM (VALUES
      ('LEGACY_ACTOR',                NOT aegis.is_initiator(j.requested_by)),
      ('LEGACY_POLICY_V1',            NOT coalesce(
         (SELECT aegis.is_roe_policy_v2(p.policy) FROM policy_snapshot p
           WHERE p.policy_version = j.policy_version), false)),
      ('LEGACY_MISSING_MANIFEST_PIN', j.manifest_sha256 IS NULL),
      ('LEGACY_MISSING_TARGET_REFS',  j.target_refs IS NULL),
      ('LEGACY_PROPOSER_LABEL',       j.proposed_by IS NOT NULL AND NOT aegis.is_proposer(j.proposed_by)),
      ('LEGACY_TARGET_PROJECTION',    NOT aegis.is_canonical_projection(j.targets, j.target_refs))
    ) AS t(code, blocked)
   WHERE t.blocked;
$$;
COMMENT ON FUNCTION aegis.legacy_dispatch_block(scan_job) IS
  'Dispatch-block reasons of a job row against the current contract: an actor that is not a server-derived initiator, v1 configuration, missing manifest pin (pre-0003), missing TargetRefs (pre-0005), a proposer label instead of a session (pre-0012) and a `targets` projection its refs cannot explain (pre-0012). NULL means no block. Materialized once into scan_job.dispatch_block_reasons, which the dispatch guard enforces.';

-- dispatch_block_reasons stays immutable through cols_only, so the backfill runs while it is dropped
-- and the trigger is recreated with the same whitelist (0011's list).
DROP TRIGGER cols_only ON scan_job;
UPDATE scan_job
   SET dispatch_block_reasons = aegis.legacy_dispatch_block(scan_job)
 WHERE aegis.legacy_dispatch_block(scan_job) IS DISTINCT FROM dispatch_block_reasons;
CREATE TRIGGER cols_only BEFORE UPDATE ON scan_job FOR EACH ROW EXECUTE FUNCTION aegis.forbid_value_update(
  'status','error','envelope_event_id','started_at','finished_at',
  'attempt','generation','cancel_requested_at','cancel_requested_by','cancel_reason','wait_reason');

COMMENT ON COLUMN scan_job.dispatch_block_reasons IS
  'Dispatch hold. NULL = dispatchable. Non-NULL is the sorted list of LEGACY_ACTOR, LEGACY_MISSING_MANIFEST_PIN, LEGACY_MISSING_TARGET_REFS, LEGACY_POLICY_V1, LEGACY_PROPOSER_LABEL and LEGACY_TARGET_PROJECTION; written once by the migration, immutable (not in the cols_only whitelist), and enforced by aegis.guard_dispatch_block, which refuses to start such a job (attempt bump or a move to VALIDATING/DISPATCHED/RUNNING). Its terminal result and cancel stay unaffected. Dispatchable queue: status = ''QUEUED'' AND dispatch_block_reasons IS NULL.';

-- ---------------------------------------------------------------------------
-- 5. R-3 — the job is the job its decision approved, down to the fields that run.
--
-- 0012 compared campaign, actors and target_refs; `input`, `capability`, `provider`, `policy_version`
-- and `scope_id` could still differ, and `input` is exactly what the runner executes. M05 derives the
-- task and the job from one decision, so any difference is a bug or a forged row.
CREATE OR REPLACE FUNCTION aegis.require_job_decision_consistency() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE d policy_decision;
BEGIN
  SELECT * INTO d FROM policy_decision WHERE decision_id = NEW.decision_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'job % references unknown policy_decision %', NEW.job_id, NEW.decision_id
      USING ERRCODE = 'check_violation';
  END IF;
  IF d.campaign_id <> NEW.campaign_id THEN
    RAISE EXCEPTION 'job % is in campaign % but its decision % belongs to campaign %',
      NEW.job_id, NEW.campaign_id, NEW.decision_id, d.campaign_id
      USING ERRCODE = 'check_violation';
  END IF;
  IF d.requested_by IS DISTINCT FROM NEW.requested_by THEN
    RAISE EXCEPTION 'job % requested_by (%) differs from its decision (%)',
      NEW.job_id, NEW.requested_by, d.requested_by
      USING ERRCODE = 'check_violation';
  END IF;
  IF d.proposed_by IS DISTINCT FROM NEW.proposed_by THEN
    RAISE EXCEPTION 'job % proposed_by (%) differs from its decision (%)',
      NEW.job_id, NEW.proposed_by, d.proposed_by
      USING ERRCODE = 'check_violation';
  END IF;
  IF d.target_refs IS NOT NULL AND d.target_refs IS DISTINCT FROM NEW.target_refs THEN
    RAISE EXCEPTION 'job % target_refs differ from the targets its decision resolved (% vs %)',
      NEW.job_id, NEW.target_refs, d.target_refs
      USING ERRCODE = 'check_violation';
  END IF;
  IF d.capability IS DISTINCT FROM NEW.capability THEN
    RAISE EXCEPTION 'job % capability % differs from its decision %',
      NEW.job_id, NEW.capability, d.capability USING ERRCODE = 'check_violation';
  END IF;
  IF d.provider IS DISTINCT FROM NEW.provider THEN
    RAISE EXCEPTION 'job % provider % differs from its decision %',
      NEW.job_id, NEW.provider, d.provider USING ERRCODE = 'check_violation';
  END IF;
  IF d.policy_version IS DISTINCT FROM NEW.policy_version THEN
    RAISE EXCEPTION 'job % policy_version % differs from its decision %',
      NEW.job_id, NEW.policy_version, d.policy_version USING ERRCODE = 'check_violation';
  END IF;
  IF d.scope_id IS DISTINCT FROM NEW.scope_id THEN
    RAISE EXCEPTION 'job % scope_id % differs from its decision %',
      NEW.job_id, NEW.scope_id, d.scope_id USING ERRCODE = 'check_violation';
  END IF;
  IF d.input IS DISTINCT FROM NEW.input THEN
    RAISE EXCEPTION 'job % input differs from the input its decision approved (% vs %)',
      NEW.job_id, NEW.input, d.input USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
COMMENT ON FUNCTION aegis.require_job_decision_consistency() IS
  'C05/OI-8/R-3: one decision, one job: same campaign, actors, resolved target_refs and the executed fields (capability, provider, policy_version, scope_id, input). M05 derives both from the same decision, so a difference is a bug or a forged job.';

-- ---------------------------------------------------------------------------
-- 6. Pin what this migration created or replaced (CREATE OR REPLACE resets proconfig). The catalog
--    test (tests/search_path_pinning.sql) fails on any unpinned function of the schema.
DO $$
DECLARE
  fn record;
  pinned int := 0;
BEGIN
  FOR fn IN
    SELECT p.oid::regprocedure AS signature
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'aegis'
       AND NOT EXISTS (SELECT 1 FROM unnest(coalesce(p.proconfig, '{}'::text[])) AS cfg
                        WHERE cfg LIKE 'search_path=%')
     ORDER BY 1::text
  LOOP
    EXECUTE format('ALTER FUNCTION %s SET search_path = aegis, pg_temp', fn.signature);
    pinned := pinned + 1;
  END LOOP;
  RAISE NOTICE '0014: % aegis function(s) got search_path = aegis, pg_temp', pinned;
END $$;

COMMIT;
