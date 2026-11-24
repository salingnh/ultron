-- S1 follow-up (gate review OI-1, OI-2, OI-18). Three contract defects closed in one migration:
--   * a job whose requested_by is not a server-derived initiator is held with LEGACY_ACTOR, which is
--     what 0010 already claimed for history (section 1);
--   * a held job cannot be reopened into a new generation it could never dispatch (section 2);
--   * every aegis function pins its own search_path, so a caller's search_path (including a TEMP
--     shadow table) can never redirect a guard or a history write (section 3, last).
-- Apply after 0009 and 0010: it reads scan_job.dispatch_block_reasons and aegis.is_initiator.
BEGIN;
SET LOCAL search_path = aegis, public;

-- ---------------------------------------------------------------------------
-- 1. OI-2 — LEGACY_ACTOR: a row 0010 could not have accepted is not dispatchable.
--
-- 0010 enforces the initiator rule on INSERT only, so a job inserted between 0009 and 0010 keeps its
-- self-declared actor (often the agent itself) and passed 0009's hold, because it had a v2 policy, a
-- manifest pin and TargetRefs. It was therefore dispatchable, which contradicts 0010's and 04's claim
-- that pre-0010 rows are never dispatched/replayed. The reason set gains LEGACY_ACTOR, defined as
-- "requested_by is not a server-derived initiator" — exactly the class 0010 refuses. A pre-0010 row
-- whose self-declared actor happens to have operator shape is indistinguishable from a post-0010 row;
-- it is not given a reason, because inventing one would freeze legitimate jobs, and the contract text
-- now states the narrower, enforced rule instead of the wider claim.
CREATE OR REPLACE FUNCTION aegis.is_dispatch_block_reasons(v text[]) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT v IS NOT NULL
     AND cardinality(v) > 0
     AND NOT EXISTS (SELECT 1 FROM unnest(v) c
                      WHERE c NOT IN ('LEGACY_POLICY_V1','LEGACY_MISSING_MANIFEST_PIN',
                                      'LEGACY_MISSING_TARGET_REFS','LEGACY_ACTOR'))
     AND cardinality(v) = (SELECT count(DISTINCT c) FROM unnest(v) c);
$$;
COMMENT ON FUNCTION aegis.is_dispatch_block_reasons(text[]) IS
  'True for a non-empty, duplicate-free subset of the four legacy dispatch-block reasons (LEGACY_ACTOR, LEGACY_MISSING_MANIFEST_PIN, LEGACY_MISSING_TARGET_REFS, LEGACY_POLICY_V1).';

-- One definition of "which job the contract cannot dispatch". Every reason is kept: repairing one
-- does not hide the others. Imports aegis.is_initiator from 0010 for the actor reason.
CREATE OR REPLACE FUNCTION aegis.legacy_dispatch_block(j scan_job) RETURNS text[] LANGUAGE sql STABLE AS $$
  SELECT array_agg(t.code ORDER BY t.code)
    FROM (VALUES
      ('LEGACY_ACTOR',                NOT aegis.is_initiator(j.requested_by)),
      ('LEGACY_POLICY_V1',            NOT coalesce(
         (SELECT aegis.is_roe_policy_v2(p.policy) FROM policy_snapshot p
           WHERE p.policy_version = j.policy_version), false)),
      ('LEGACY_MISSING_MANIFEST_PIN', j.manifest_sha256 IS NULL),
      ('LEGACY_MISSING_TARGET_REFS',  j.target_refs IS NULL)
    ) AS t(code, blocked)
   WHERE t.blocked;
$$;
COMMENT ON FUNCTION aegis.legacy_dispatch_block(scan_job) IS
  'Dispatch-block reasons of a job row against the current contract: an actor that is not a server-derived initiator (0010 could not have accepted it), v1 configuration, missing manifest pin (pre-0003) and missing TargetRefs (pre-0005). NULL means no block. Materialized once into scan_job.dispatch_block_reasons, which the dispatch guard enforces.';

-- dispatch_block_reasons is immutable through cols_only (0009), so the backfill runs while that
-- trigger is dropped; the recreated trigger is the exact 0009 whitelist, with dispatch_block_reasons
-- deliberately out of it.
DROP TRIGGER cols_only ON scan_job;
UPDATE scan_job
   SET dispatch_block_reasons = aegis.legacy_dispatch_block(scan_job)
 WHERE aegis.legacy_dispatch_block(scan_job) IS DISTINCT FROM dispatch_block_reasons;
CREATE TRIGGER cols_only BEFORE UPDATE ON scan_job FOR EACH ROW EXECUTE FUNCTION aegis.forbid_value_update(
  'status','error','envelope_event_id','started_at','finished_at',
  'attempt','generation','cancel_requested_at','cancel_requested_by','cancel_reason','wait_reason');

-- 0010's COMMENT promises that a pre-0010 row "is not dispatchable" for every actor it refused; that was
-- only true for rows 0011 holds. This supersedes it with the rule that is enforced.
COMMENT ON COLUMN scan_job.requested_by IS
  'C05 server-derived initiator: aegis.require_job_initiator enforces {kind: operator|module, id} on INSERT. A row whose actor predates 0010 keeps that value as history and is never rewritten; when 0010 could not have accepted it (kind agent or malformed) it is held with LEGACY_ACTOR and is not dispatchable or replayable, and it cannot be reopened.';

COMMENT ON COLUMN scan_job.dispatch_block_reasons IS
  'Dispatch hold. NULL = dispatchable. Non-NULL is the sorted list of LEGACY_ACTOR (requested_by is not a server-derived initiator: a row 0010 could not have accepted), LEGACY_POLICY_V1, LEGACY_MISSING_MANIFEST_PIN and LEGACY_MISSING_TARGET_REFS; written once by the migration, immutable (not in the cols_only whitelist), and enforced by aegis.guard_dispatch_block, which refuses to start such a job (attempt bump or a move to VALIDATING/DISPATCHED/RUNNING). Its terminal result and cancel stay unaffected. Dispatchable queue: status = ''QUEUED'' AND dispatch_block_reasons IS NULL.';

-- The hold already stopped every dispatch; its message still said "accepted before the v2 contract",
-- which is not true of LEGACY_ACTOR. Only the wording changes here.
CREATE OR REPLACE FUNCTION aegis.guard_dispatch_block() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.dispatch_block_reasons IS NOT NULL
     AND (NEW.attempt IS DISTINCT FROM OLD.attempt
          OR (NEW.status IS DISTINCT FROM OLD.status
              AND NEW.status IN ('VALIDATING','DISPATCHED','RUNNING','COLLECTING'))) THEN
    RAISE EXCEPTION 'job % is not dispatchable (%): the contract does not allow starting it; create a new v2 job instead of replaying it',
      NEW.job_id, array_to_string(OLD.dispatch_block_reasons, ',')
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

-- ---------------------------------------------------------------------------
-- 2. OI-18 — a held job cannot be reopened.
--
-- 0007 lets a terminal job reopen as generation+1/attempt=1/QUEUED; on a held job that produced a
-- QUEUED row the dispatch guard refuses forever, so the state change was noise that also implied a
-- dispatch. Reopening is now refused for a held row: its only forward paths are its terminal result
-- and cancel, and re-running the work means a new v2 job (README §Dữ liệu và migration). The rest of
-- the function is unchanged from 0007.
CREATE OR REPLACE FUNCTION aegis.guard_scan_job_lifecycle() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE terminal text[] := ARRAY['SUCCEEDED', 'FAILED', 'CANCELLED'];
BEGIN
  IF OLD.status = ANY(terminal) THEN
    IF NEW.status = ANY(terminal) THEN
      IF NEW.status <> OLD.status THEN
        RAISE EXCEPTION 'terminal result is final; % cannot become %', OLD.status, NEW.status
          USING ERRCODE = 'check_violation';
      END IF;
    ELSE
      IF OLD.dispatch_block_reasons IS NOT NULL THEN
        RAISE EXCEPTION 'job % is held (%) and cannot be reopened: it could never be dispatched; create a new v2 job instead',
          NEW.job_id, array_to_string(OLD.dispatch_block_reasons, ',')
          USING ERRCODE = 'check_violation';
      END IF;
      -- Reopening is an explicit, fenced re-execution: a new generation with a clean result.
      IF NEW.generation <> OLD.generation + 1 OR NEW.attempt <> 1 OR NEW.status <> 'QUEUED'
         OR NEW.started_at IS NOT NULL OR NEW.finished_at IS NOT NULL
         OR NEW.envelope_event_id IS NOT NULL OR NEW.error IS NOT NULL
         OR NEW.cancel_requested_at IS NOT NULL THEN
        RAISE EXCEPTION 'reopening a terminal job needs generation+1, attempt=1, status QUEUED and a cleared result (started_at/finished_at/error/envelope_event_id/cancel intent)'
          USING ERRCODE = 'check_violation';
      END IF;
      RETURN NEW;
    END IF;
  ELSE
    IF NEW.generation <> OLD.generation THEN
      RAISE EXCEPTION 'generation changes only when a terminal job is reopened'
        USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.attempt NOT IN (OLD.attempt, OLD.attempt + 1) THEN
      RAISE EXCEPTION 'attempt increases by at most 1 per dispatch (% -> %)', OLD.attempt, NEW.attempt
        USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  IF OLD.cancel_requested_at IS NOT NULL THEN
    IF NEW.cancel_requested_at IS DISTINCT FROM OLD.cancel_requested_at
       OR NEW.cancel_requested_by IS DISTINCT FROM OLD.cancel_requested_by
       OR NEW.cancel_reason IS DISTINCT FROM OLD.cancel_reason THEN
      RAISE EXCEPTION 'cancel intent is written once; only a new generation clears it'
        USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  RETURN NEW;
END $$;
COMMENT ON FUNCTION aegis.guard_scan_job_lifecycle() IS
  'C06 + OI-18: terminal results are final, reopening a terminal job needs generation+1/attempt=1/QUEUED with a cleared result, a held job (dispatch_block_reasons non-NULL) cannot be reopened at all, and the cancel intent is written once.';

-- ---------------------------------------------------------------------------
-- 3. OI-1 — search_path pinning on every function of this schema.
--
-- A trigger function is resolved in the caller's search_path, not in the schema of the table it
-- guards: with the default `"$user", public`, 0007's history trigger cannot even see
-- job_lifecycle_change, and a session that creates TEMP TABLE campaign_target shadows the seed guard
-- of 0005 (pg_temp is searched before any schema not named in search_path). Pinning each function is
-- what makes the guard independent of the caller. 0008 already does this for its SECURITY DEFINER
-- functions; this sweep covers the rest and skips what is already pinned. The invariant is tested
-- from the catalog: every function in schema aegis carries a search_path
-- (tests/search_path_pinning.sql), so a future function cannot quietly reintroduce the hole.
--
-- `aegis` first, `pg_temp` last: a TEMP table cannot stand in for a table of this schema. pg_catalog
-- keeps its implicit precedence, so built-ins are unaffected.
--
-- Keep this sweep last in the file: CREATE OR REPLACE resets proconfig, so a function replaced above
-- loses its pin until this sweep runs. A later migration that replaces an aegis function must pin it
-- again (the catalog test fails loudly if it does not).
DO $$
DECLARE
  fn record;
  pinned int := 0;
BEGIN
  FOR fn IN
    SELECT p.oid::regprocedure AS signature
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'aegis'
       AND NOT EXISTS (SELECT 1 FROM unnest(coalesce(p.proconfig, '{}'::text[])) AS cfg
                        WHERE cfg LIKE 'search_path=%')
     ORDER BY 1::text
  LOOP
    EXECUTE format('ALTER FUNCTION %s SET search_path = aegis, pg_temp', fn.signature);
    pinned := pinned + 1;
  END LOOP;
  RAISE NOTICE '0011: % aegis function(s) got search_path = aegis, pg_temp', pinned;
END $$;

COMMIT;
