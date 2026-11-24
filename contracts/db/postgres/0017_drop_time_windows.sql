-- G1 (owner decision 2026-11-24): the RoE time windows are dropped from the contract.
--
-- `roe-policy.v2` no longer has `allowed_windows`/`blackout_windows`, `job.v2` no longer has the
-- `WINDOW_CLOSED` wait reason, and the dispatch path no longer reads a clock for a window. This
-- migration makes the *storage* say the same thing for new rows, without rewriting history:
--
--   * a `policy_snapshot` written from now on may not carry either window key - the insert trigger
--     uses `aegis.is_roe_policy_v2_current`, which is `aegis.is_roe_policy_v2` (0009, unchanged) plus
--     "no window keys". `aegis.is_roe_policy_v2` keeps validating the window *shape* on purpose:
--     `aegis.legacy_dispatch_block` (0014) uses it to classify stored rows, so a snapshot written
--     before this migration that still carries well-formed windows stays a v2 snapshot (its jobs
--     keep running under the current contract, which ignores the window) instead of being
--     misclassified as v1 and blocked;
--   * a job keeps running on any *stored* v2 snapshot: the windows of a snapshot written before
--     0017 are ignored by the code, and `aegis.require_job_v2_policy` stays on `aegis.is_roe_policy_v2`
--     so a campaign whose adopted v2 candidate predates 0017 can still accept new work (the history
--     stays valid, only new *policy snapshots* are restricted);
--   * `aegis.is_wait_reason` no longer accepts `WINDOW_CLOSED`. A CHECK constraint is not
--     revalidated when the function it calls is replaced, so `scan_job.wait_reason` rows that still
--     say `WINDOW_CLOSED` (queued before this migration) stay valid and readable; they are history
--     and the scheduler rewrites them with its next decision;
--   * the v1 -> v2 conversion tool (`aegis.convert_legacy_policy`, 0009) can no longer map the two
--     window keys, so it drops them and `aegis.migrate_legacy_policy_snapshots` records them in
--     `policy_snapshot_migration.dropped_keys/dropped_values` under mapping version `aegis-roe/2`
--     (records written by 0009 keep `aegis-roe/1`). Nothing is dropped silently, and a converted row
--     can be inserted because it no longer has the keys.
--
-- Applied migrations are not edited; this file is the cutover. Apply after 0016.
BEGIN;
SET LOCAL search_path = aegis, public;

-- ---------------------------------------------------------------------------
-- 1. What a *new* snapshot/job may contain: the v2 shape without the window keys.
-- ---------------------------------------------------------------------------
CREATE FUNCTION aegis.is_roe_policy_v2_current(policy jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE
  SET search_path = aegis, pg_temp AS $$
  SELECT aegis.is_roe_policy_v2(policy)
     AND NOT (policy ? 'allowed_windows')
     AND NOT (policy ? 'blackout_windows');
$$;
COMMENT ON FUNCTION aegis.is_roe_policy_v2_current(jsonb) IS
  'True for a roe-policy.v2 object as this contract accepts it for a NEW row: the 0009 shape and no allowed_windows/blackout_windows (dropped 2026-11-24). Stored rows are classified with aegis.is_roe_policy_v2, which still knows the window shape, so history is never rewritten or reclassified as v1.';

-- The two write guards of 0009, now on the current shape.
CREATE OR REPLACE FUNCTION aegis.require_v2_policy_snapshot() RETURNS trigger LANGUAGE plpgsql
  SET search_path = aegis, pg_temp AS $$
BEGIN
  IF NOT aegis.is_roe_policy_v2_current(NEW.policy) THEN
    RAISE EXCEPTION 'new policy_snapshot % must be roe-policy.v2 configuration without time windows',
      NEW.policy_version USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

COMMENT ON COLUMN policy_snapshot.policy IS
  'roe-policy.v2 configuration: from 0017 on without time windows (aegis.is_roe_policy_v2_current). Rows written before 0017 keep their windows as history, are never execution configuration for a new job, and are not rewritten. Rows written before 0009 keep the roe-policy.v1 JSON byte-identically.';

-- ---------------------------------------------------------------------------
-- 2. `WINDOW_CLOSED` leaves the wait-reason shape for new writes.
--    Existing rows keep it: replacing the function does not revalidate the CHECK.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION aegis.is_wait_reason(reason jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE
  SET search_path = aegis, pg_temp AS $$
  SELECT CASE
    WHEN jsonb_typeof(reason) <> 'object' THEN false
    WHEN EXISTS (SELECT 1 FROM jsonb_object_keys(reason) AS k
                  WHERE k NOT IN ('code', 'detail', 'blocking_job_ids', 'since')) THEN false
    WHEN coalesce(reason->>'code', '') NOT IN (
      'DEPENDENCY_PENDING', 'DEPENDENCY_FAILED', 'CAMPAIGN_PAUSED', 'BUDGET_EXHAUSTED',
      'CONCURRENCY_LIMIT', 'RATE_LIMITED', 'PROVIDER_UNAVAILABLE', 'MANUAL_HOLD') THEN false
    WHEN reason ? 'detail' AND (jsonb_typeof(reason->'detail') <> 'string'
                                OR length(reason->>'detail') > 500) THEN false
    WHEN reason ? 'blocking_job_ids' AND (
      jsonb_typeof(reason->'blocking_job_ids') <> 'array'
      OR jsonb_array_length(reason->'blocking_job_ids') > 100
      OR EXISTS (SELECT 1 FROM jsonb_array_elements(reason->'blocking_job_ids') AS e
                  WHERE jsonb_typeof(e) <> 'string'
                     OR e #>> '{}' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')) THEN false
    WHEN coalesce(reason->>'since', '') !~
      '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$' THEN false
    ELSE true
  END
$$;
COMMENT ON FUNCTION aegis.is_wait_reason(jsonb) IS
  'True for a job.v2 WaitReason object: known code, ISO-8601 since, known keys only. 0017 removed WINDOW_CLOSED (the RoE time windows are gone); rows that still carry it were queued before 0017 and are not revalidated.';

-- ---------------------------------------------------------------------------
-- 3. The v1 -> v2 conversion drops the two window keys and records them.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION aegis.convert_legacy_policy(legacy jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path = aegis, pg_temp AS $$
DECLARE
  v1_keys constant text[] := ARRAY['scan_profile','max_impact_tier','max_parallel_jobs',
    'max_duration_hours','rate_limits','allowed_windows','blackout_windows',
    'approval_required_tiers','budget','capability_denylist'];
  v1_only constant text[] := ARRAY['scan_profile','max_impact_tier','approval_required_tiers',
    'allowed_windows','blackout_windows'];
  unmapped text[];
  converted jsonb;
BEGIN
  IF jsonb_typeof(legacy) <> 'object' THEN
    RAISE EXCEPTION 'legacy policy must be a JSON object, got %', jsonb_typeof(legacy)
      USING ERRCODE = 'check_violation';
  END IF;
  SELECT array_agg(k ORDER BY k) INTO unmapped
    FROM jsonb_object_keys(legacy) k WHERE k <> ALL (v1_keys);
  IF unmapped IS NOT NULL THEN
    RAISE EXCEPTION 'legacy policy has no roe-policy.v2 place for %; refusing to drop a setting silently',
      unmapped USING ERRCODE = 'check_violation';
  END IF;

  converted := legacy - v1_only;
  IF NOT aegis.is_roe_policy_v2(converted) THEN
    RAISE EXCEPTION 'legacy policy cannot be represented as roe-policy.v2: %', converted
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN converted;
END $$;
COMMENT ON FUNCTION aegis.convert_legacy_policy(jsonb) IS
  'Deterministic roe-policy.v1 -> v2 mapping: keeps max_parallel_jobs, max_duration_hours, rate_limits, budget and capability_denylist verbatim; removes scan_profile, max_impact_tier and approval_required_tiers (v2 has no impact taxonomy or approval step) and, from 0017, allowed_windows/blackout_windows (dropped from the contract 2026-11-24; the caller records them in policy_snapshot_migration). Any other key, or a value outside the v2 shape, raises instead of being discarded.';

CREATE OR REPLACE FUNCTION aegis.migrate_legacy_policy_snapshots(p_actor jsonb)
RETURNS TABLE (source_policy_version text, new_policy_version text, campaign_id uuid, dropped_keys text[])
LANGUAGE plpgsql SET search_path = aegis, pg_temp AS $$
DECLARE
  r record;
  v_policy jsonb;
  v_dropped_keys text[];
  v_new_version text;
  dropped constant text[] := ARRAY['scan_profile','max_impact_tier','approval_required_tiers',
                                   'allowed_windows','blackout_windows'];
BEGIN
  IF p_actor IS NULL THEN
    RAISE EXCEPTION 'legacy policy migration needs an actor' USING ERRCODE = 'check_violation';
  END IF;
  FOR r IN
    SELECT s.policy_version, s.campaign_id, s.policy
      FROM policy_snapshot s
     WHERE NOT aegis.is_roe_policy_v2(s.policy)
       AND NOT EXISTS (SELECT 1 FROM policy_snapshot_migration m
                        WHERE m.source_policy_version = s.policy_version)
     ORDER BY s.policy_version
  LOOP
    BEGIN
      v_policy := aegis.convert_legacy_policy(r.policy);
    EXCEPTION WHEN OTHERS THEN
      RAISE EXCEPTION 'legacy policy_snapshot % cannot be migrated: %', r.policy_version, SQLERRM
        USING ERRCODE = 'check_violation';
    END;
    v_new_version := aegis.next_policy_version();
    SELECT coalesce(array_agg(k ORDER BY k), '{}'::text[]) INTO v_dropped_keys
      FROM jsonb_object_keys(r.policy) k
     WHERE k = ANY (dropped);
    INSERT INTO policy_snapshot (policy_version, campaign_id, policy, policy_hash, created_by)
      VALUES (v_new_version, r.campaign_id, v_policy, aegis.policy_hash(v_policy), p_actor);
    INSERT INTO policy_snapshot_migration
      (source_policy_version, new_policy_version, campaign_id, mapping_version,
       dropped_keys, dropped_values, converted_by)
    VALUES (r.policy_version, v_new_version, r.campaign_id, 'aegis-roe/2', v_dropped_keys,
            (SELECT coalesce(jsonb_object_agg(k, r.policy->k), '{}'::jsonb)
               FROM jsonb_object_keys(r.policy) k
              WHERE k = ANY (dropped)),
            p_actor);
    source_policy_version := r.policy_version;
    new_policy_version := v_new_version;
    campaign_id := r.campaign_id;
    dropped_keys := v_dropped_keys;
    RETURN NEXT;
  END LOOP;
END $$;
COMMENT ON FUNCTION aegis.migrate_legacy_policy_snapshots(jsonb) IS
  'S1.6 tool. For each policy_snapshot that is not roe-policy.v2 yet and has no conversion record: create a new v2 row (new policy_version, same campaign) and record the mapping. Idempotent: a second call converts nothing. Never updates the source row and never sets campaign.current_policy_version; adopting the new snapshot is an explicit M01 operation. From 0017 the mapping version is aegis-roe/2 and the two time-window keys are dropped and recorded (the contract dropped them on 2026-11-24); rows converted by 0009 keep aegis-roe/1 and their windows.';

COMMENT ON COLUMN policy_snapshot_migration.dropped_keys IS
  'v1 keys removed by the mapping: scan_profile, max_impact_tier, approval_required_tiers, and from 0017 allowed_windows/blackout_windows (dropped from the contract 2026-11-24). Empty when the source had none of them.';

COMMIT;
