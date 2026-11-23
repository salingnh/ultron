-- S1.6: the legacy configuration path. Apply after 0008, in a maintenance window.
--
-- An existing database may hold roe-policy.v1 rows in policy_snapshot and jobs accepted by the v1
-- contract. Nothing here rewrites them: every v1 snapshot gets a NEW, structurally valid v2 row
-- (the old row stays byte-identical), campaign.current_policy_version is never promoted, and every
-- job that cannot run under v2 gets an explicit, immutable dispatch hold with its reasons. A legacy
-- campaign cannot run again until an operator adopts the v2 snapshot: the migration pauses it, and
-- nothing here resumes a campaign, a job or an event.
--
-- "v2 configuration" is a policy object that is valid against campaign/roe-policy.v2.schema.json.
-- aegis.is_roe_policy_v2 mirrors that schema structurally (closed key set, types, ranges) so the
-- database can refuse a legacy or malformed snapshot on its own; semantic formats (IANA timezone)
-- still come from contracts/validation.py, which every consumer must enable. No valid v1 policy can
-- pass the v2 shape (v1 requires scan_profile and v2 is additionalProperties:false), so the shape is
-- also the v1/v2 discriminator for rows written before this migration.
BEGIN;
SET LOCAL search_path = aegis, public;
LOCK TABLE policy_snapshot, campaign, scan_job IN ACCESS EXCLUSIVE MODE;

-- ---------------------------------------------------------------------------
-- 1. Shape helpers. They only cover what roe-policy.v2.schema.json publishes; the timezone value
--    is checked for length here and for a real IANA name by contracts/validation.py.
-- ---------------------------------------------------------------------------
CREATE FUNCTION aegis.is_json_int(v jsonb, lo numeric DEFAULT NULL, hi numeric DEFAULT NULL)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT v IS NOT NULL
     AND jsonb_typeof(v) = 'number'
     AND (v #>> '{}')::numeric = trunc((v #>> '{}')::numeric)   -- JSON Schema counts 10.0 as an integer
     AND (lo IS NULL OR (v #>> '{}')::numeric >= lo)
     AND (hi IS NULL OR (v #>> '{}')::numeric <= hi)
$$;

CREATE FUNCTION aegis.is_json_number(v jsonb, lo numeric DEFAULT NULL, hi numeric DEFAULT NULL,
                                     lo_exclusive boolean DEFAULT false)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT v IS NOT NULL
     AND jsonb_typeof(v) = 'number'
     AND (lo IS NULL OR (CASE WHEN lo_exclusive
                              THEN (v #>> '{}')::numeric > lo
                              ELSE (v #>> '{}')::numeric >= lo END))
     AND (hi IS NULL OR (v #>> '{}')::numeric <= hi);
$$;

CREATE FUNCTION aegis.is_json_strings(v jsonb, max_items integer DEFAULT NULL,
                                      pattern text DEFAULT NULL, min_length integer DEFAULT 0)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT v IS NOT NULL
     AND jsonb_typeof(v) = 'array'
     AND (max_items IS NULL OR jsonb_array_length(v) <= max_items)
     AND NOT EXISTS (
       SELECT 1 FROM jsonb_array_elements(v) e
        WHERE jsonb_typeof(e) <> 'string'
           OR length(e #>> '{}') < min_length
           OR (pattern IS NOT NULL AND (e #>> '{}') !~ pattern))
     AND jsonb_array_length(v) = (SELECT count(DISTINCT e) FROM jsonb_array_elements(v) e);
$$;

CREATE FUNCTION aegis.is_time_window(v jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN v IS NULL OR jsonb_typeof(v) <> 'object' THEN false
    WHEN EXISTS (SELECT 1 FROM jsonb_object_keys(v) k
                  WHERE k NOT IN ('days','start','end','timezone')) THEN false
    WHEN NOT (v ? 'days' AND v ? 'start' AND v ? 'end' AND v ? 'timezone') THEN false
    WHEN NOT aegis.is_json_strings(v->'days', NULL, NULL, 1) THEN false
    WHEN jsonb_array_length(v->'days') = 0 THEN false
    WHEN EXISTS (SELECT 1 FROM jsonb_array_elements(v->'days') e
                  WHERE (e #>> '{}') NOT IN ('mon','tue','wed','thu','fri','sat','sun')) THEN false
    WHEN coalesce(v->>'start','') !~ '^([01][0-9]|2[0-3]):[0-5][0-9]$' THEN false
    WHEN coalesce(v->>'end','')  !~ '^(([01][0-9]|2[0-3]):[0-5][0-9]|24:00)$' THEN false
    WHEN length(coalesce(v->>'timezone','')) NOT BETWEEN 1 AND 255 THEN false
    ELSE true
  END
$$;

CREATE FUNCTION aegis.is_time_windows(v jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT v IS NOT NULL
     AND jsonb_typeof(v) = 'array'
     AND jsonb_array_length(v) <= 50
     AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(v) e WHERE NOT aegis.is_time_window(e));
$$;

CREATE FUNCTION aegis.is_rate_limits(v jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN v IS NULL OR jsonb_typeof(v) <> 'object' THEN false
    WHEN EXISTS (SELECT 1 FROM jsonb_object_keys(v) k
                  WHERE k NOT IN ('requests_per_second_per_host','packets_per_second','jobs_per_minute')) THEN false
    WHEN v ? 'requests_per_second_per_host'
         AND NOT aegis.is_json_number(v->'requests_per_second_per_host', 0, 1000, true) THEN false
    WHEN v ? 'packets_per_second' AND NOT aegis.is_json_int(v->'packets_per_second', 1, 100000) THEN false
    WHEN v ? 'jobs_per_minute'    AND NOT aegis.is_json_int(v->'jobs_per_minute', 1, 600) THEN false
    ELSE true
  END
$$;

CREATE FUNCTION aegis.is_budget(v jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN v IS NULL OR jsonb_typeof(v) <> 'object' THEN false
    WHEN EXISTS (SELECT 1 FROM jsonb_object_keys(v) k
                  WHERE k NOT IN ('max_llm_cost_usd','max_llm_tokens','max_jobs',
                                  'max_agent_sessions','idle_cycles_before_pause')) THEN false
    WHEN v ? 'max_llm_cost_usd' AND NOT aegis.is_json_number(v->'max_llm_cost_usd', 0) THEN false
    WHEN v ? 'max_llm_tokens'   AND NOT aegis.is_json_int(v->'max_llm_tokens', 0) THEN false
    WHEN v ? 'max_jobs'         AND NOT aegis.is_json_int(v->'max_jobs', 1) THEN false
    WHEN v ? 'max_agent_sessions' AND NOT aegis.is_json_int(v->'max_agent_sessions', 1) THEN false
    WHEN v ? 'idle_cycles_before_pause'
         AND NOT aegis.is_json_int(v->'idle_cycles_before_pause', 3, 5) THEN false
    ELSE true
  END
$$;

CREATE FUNCTION aegis.is_roe_policy_v2(policy jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN jsonb_typeof(policy) <> 'object' THEN false
    WHEN EXISTS (SELECT 1 FROM jsonb_object_keys(policy) k WHERE k NOT IN (
      'target_denylist','max_parallel_jobs','max_duration_hours','rate_limits',
      'allowed_windows','blackout_windows','budget','capability_denylist')) THEN false
    WHEN NOT aegis.is_json_int(policy->'max_parallel_jobs', 1, 50) THEN false
    WHEN NOT aegis.is_json_int(policy->'max_duration_hours', 1, 168) THEN false
    WHEN policy ? 'target_denylist'
         AND NOT aegis.is_json_strings(policy->'target_denylist', 10000, NULL, 1) THEN false
    WHEN policy ? 'rate_limits' AND NOT aegis.is_rate_limits(policy->'rate_limits') THEN false
    WHEN policy ? 'allowed_windows' AND NOT aegis.is_time_windows(policy->'allowed_windows') THEN false
    WHEN policy ? 'blackout_windows' AND NOT aegis.is_time_windows(policy->'blackout_windows') THEN false
    WHEN policy ? 'budget' AND NOT aegis.is_budget(policy->'budget') THEN false
    WHEN policy ? 'capability_denylist'
         AND NOT aegis.is_json_strings(policy->'capability_denylist', NULL,
                                       '^[a-z][a-z0-9]*\.[a-z][a-z0-9_]*$', 1) THEN false
    ELSE true
  END
$$;
COMMENT ON FUNCTION aegis.is_roe_policy_v2(jsonb) IS
  'Structural mirror of campaign/roe-policy.v2.schema.json for snapshots written in the database: closed key set, required integer limits, ranges and window shapes. IANA timezone names are validated by contracts/validation.py. A valid roe-policy.v1 object never passes (v1 requires scan_profile, v2 allows no unknown key), so this is the v1/v2 discriminator for historical rows.';

-- policy_hash had no defined projection before S1.6. It is the storage fingerprint of the row's own
-- policy value (PostgreSQL canonical jsonb text), not a C03 content hash: the C03 canonicalizer
-- (aegis-c14n/1, RFC 8785) has no SQL implementation, so a SHA-256 over the RFC 8785 form would be a
-- claim the migration cannot verify. Producers do not reproduce this text form; they call this
-- function (M01 G1.1b) or let it run in the conversion below.
CREATE FUNCTION aegis.policy_hash(policy jsonb) RETURNS char(64) LANGUAGE sql IMMUTABLE AS $$
  SELECT encode(sha256(convert_to(policy::text, 'UTF8')), 'hex')::char(64);
$$;
COMMENT ON FUNCTION aegis.policy_hash(jsonb) IS
  'sha256 over the row''s canonical jsonb text (aegis.policy_hash(policy)). A storage/audit fingerprint so an out-of-band change of a snapshot is detectable; it is not aegis-c14n/1. Validate content with campaign/roe-policy.v2.schema.json, not with this hash.';

-- ---------------------------------------------------------------------------
-- 2. v1 -> v2 mapping. One function, strict, fail-loud: a setting that has no v2 place is never
--    dropped silently. The three taxonomy/approval keys are recorded by the caller instead.
-- ---------------------------------------------------------------------------
CREATE FUNCTION aegis.convert_legacy_policy(legacy jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  v1_keys constant text[] := ARRAY['scan_profile','max_impact_tier','max_parallel_jobs',
    'max_duration_hours','rate_limits','allowed_windows','blackout_windows',
    'approval_required_tiers','budget','capability_denylist'];
  v1_only constant text[] := ARRAY['scan_profile','max_impact_tier','approval_required_tiers'];
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
  'Deterministic roe-policy.v1 -> v2 mapping: keeps max_parallel_jobs, max_duration_hours, rate_limits, allowed_windows, blackout_windows, budget and capability_denylist verbatim; removes scan_profile, max_impact_tier and approval_required_tiers (v2 has no impact taxonomy or approval step). Any other key, or a value outside the v2 shape, raises instead of being discarded.';

-- ---------------------------------------------------------------------------
-- 3. One conversion record per legacy snapshot. Append-only: a re-run of the tool never converts a
--    snapshot twice and never overwrites what it already recorded.
-- ---------------------------------------------------------------------------
CREATE TABLE policy_snapshot_migration (
  source_policy_version text   PRIMARY KEY REFERENCES policy_snapshot,
  new_policy_version    text   NOT NULL UNIQUE REFERENCES policy_snapshot,
  campaign_id           uuid   NOT NULL REFERENCES campaign,
  mapping_version       text   NOT NULL CHECK (mapping_version ~ '^aegis-roe/[1-9][0-9]*$'),
  dropped_keys          text[] NOT NULL,
  dropped_values        jsonb  NOT NULL DEFAULT '{}'::jsonb,
  converted_by          jsonb  NOT NULL,             -- Actor
  converted_at          timestamptz NOT NULL DEFAULT now()
);
SELECT aegis.protect('policy_snapshot_migration'::regclass, true);
COMMENT ON TABLE policy_snapshot_migration IS
  'S1.6 append-only record: which legacy v1 policy_snapshot became which new v2 row, and which v1-only settings were left behind with their original values. Never used as execution configuration; the campaign keeps its current_policy_version until an operator adopts the new row explicitly.';
COMMENT ON COLUMN policy_snapshot_migration.dropped_keys IS
  'v1 keys removed by the mapping (scan_profile, max_impact_tier, approval_required_tiers). Empty when the source had none of them.';

-- policy_version is allocated by the database: policy_version_seq existed since 0001 but historical
-- rows were written with hand-picked numbers, so the sequence is first aligned past the highest one.
CREATE FUNCTION aegis.next_policy_version() RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  v_next bigint;
  v_high bigint;
BEGIN
  SELECT coalesce(max(substring(policy_version from 5)::bigint), 0) INTO v_high FROM policy_snapshot;
  v_next := nextval('policy_version_seq');
  IF v_next <= v_high THEN
    PERFORM setval('policy_version_seq', v_high + 1);
    v_next := v_high + 1;
  END IF;
  RETURN 'roe-' || v_next;
END $$;
COMMENT ON FUNCTION aegis.next_policy_version() IS
  'Next free roe-<n> for a new snapshot, advancing policy_version_seq past hand-picked historical numbers. Called under the migration table lock; a concurrent writer that skips it still loses on the primary key, never on a reused version.';

-- ---------------------------------------------------------------------------
-- 4. The migration/tool itself: every v1 snapshot becomes one new v2 snapshot row. The source row is
--    not touched and the campaign's current_policy_version is not changed (no automatic promotion).
-- ---------------------------------------------------------------------------
CREATE FUNCTION aegis.migrate_legacy_policy_snapshots(p_actor jsonb)
RETURNS TABLE (source_policy_version text, new_policy_version text, campaign_id uuid, dropped_keys text[])
LANGUAGE plpgsql AS $$
DECLARE
  r record;
  v_policy jsonb;
  v_dropped_keys text[];
  v_new_version text;
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
     WHERE k IN ('scan_profile','max_impact_tier','approval_required_tiers');
    INSERT INTO policy_snapshot (policy_version, campaign_id, policy, policy_hash, created_by)
      VALUES (v_new_version, r.campaign_id, v_policy, aegis.policy_hash(v_policy), p_actor);
    INSERT INTO policy_snapshot_migration
      (source_policy_version, new_policy_version, campaign_id, mapping_version,
       dropped_keys, dropped_values, converted_by)
    VALUES (r.policy_version, v_new_version, r.campaign_id, 'aegis-roe/1', v_dropped_keys,
            (SELECT coalesce(jsonb_object_agg(k, r.policy->k), '{}'::jsonb)
               FROM jsonb_object_keys(r.policy) k
              WHERE k IN ('scan_profile','max_impact_tier','approval_required_tiers')),
            p_actor);
    source_policy_version := r.policy_version;
    new_policy_version := v_new_version;
    campaign_id := r.campaign_id;
    dropped_keys := v_dropped_keys;
    RETURN NEXT;
  END LOOP;
END $$;
COMMENT ON FUNCTION aegis.migrate_legacy_policy_snapshots(jsonb) IS
  'S1.6 tool. For each policy_snapshot that is not roe-policy.v2 yet and has no conversion record: create a new v2 row (new policy_version, same campaign) and record the mapping. Idempotent: a second call converts nothing. Never updates the source row and never sets campaign.current_policy_version; adopting the new snapshot is an explicit M01 operation. A source policy that cannot be expressed in v2 fails the whole call with its policy_version.';

-- New snapshots are v2. This is the "lock the creation step" half of the migration: a legacy-format
-- policy can only exist as history from here on, so the conversion cannot fall behind new writes.
CREATE FUNCTION aegis.require_v2_policy_snapshot() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT aegis.is_roe_policy_v2(NEW.policy) THEN
    RAISE EXCEPTION 'new policy_snapshot % must be roe-policy.v2 configuration; a v1 policy is history only',
      NEW.policy_version USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER v2_config_required BEFORE INSERT ON policy_snapshot
  FOR EACH ROW EXECUTE FUNCTION aegis.require_v2_policy_snapshot();
COMMENT ON COLUMN policy_snapshot.policy IS
  'roe-policy.v2 configuration from 0009 on: closed key set and ranges are enforced by aegis.is_roe_policy_v2 (validate the full schema with contracts/validation.py). Rows written before 0009 keep roe-policy.v1 JSON byte-identically as history and are never execution configuration; each has a v2 candidate recorded in policy_snapshot_migration.';

-- ---------------------------------------------------------------------------
-- 5. Jobs from the v1 contract are explicitly non-dispatchable. The hold is a stored state (not a
--    comment) so the scheduler, the API and an operator all see the same answer, and it is immutable:
--    no UPDATE can clear it, so nothing resumes by itself.
-- ---------------------------------------------------------------------------
CREATE FUNCTION aegis.is_dispatch_block_reasons(v text[]) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT v IS NOT NULL
     AND cardinality(v) > 0
     AND NOT EXISTS (SELECT 1 FROM unnest(v) c
                      WHERE c NOT IN ('LEGACY_POLICY_V1','LEGACY_MISSING_MANIFEST_PIN',
                                      'LEGACY_MISSING_TARGET_REFS'))
     AND cardinality(v) = (SELECT count(DISTINCT c) FROM unnest(v) c);
$$;

-- One place defines "which job the v2 contract cannot dispatch": its configuration is not v2, or it
-- was accepted before 0003 (no manifest pin) / 0005 (no TargetRefs). Every such reason is kept, since
-- an operator repairing one of them later still has to see the others.
CREATE FUNCTION aegis.legacy_dispatch_block(j scan_job) RETURNS text[] LANGUAGE sql STABLE AS $$
  SELECT array_agg(t.code ORDER BY t.code)
    FROM (VALUES
      ('LEGACY_POLICY_V1', NOT coalesce(
         (SELECT aegis.is_roe_policy_v2(p.policy) FROM policy_snapshot p
           WHERE p.policy_version = j.policy_version), false)),
      ('LEGACY_MISSING_MANIFEST_PIN', j.manifest_sha256 IS NULL),
      ('LEGACY_MISSING_TARGET_REFS',  j.target_refs IS NULL)
    ) AS t(code, blocked)
   WHERE t.blocked;
$$;
COMMENT ON FUNCTION aegis.legacy_dispatch_block(scan_job) IS
  'Dispatch-block reasons of a job row against the v2 contract: legacy v1 configuration, missing manifest pin (pre-0003) and missing TargetRefs (pre-0005). NULL means no block. 0009 materializes this value once into scan_job.dispatch_block_reasons, which the dispatch guard enforces.';

ALTER TABLE scan_job ADD COLUMN dispatch_block_reasons text[]
  CONSTRAINT scan_job_dispatch_block_shape
    CHECK (dispatch_block_reasons IS NULL OR aegis.is_dispatch_block_reasons(dispatch_block_reasons));

-- cols_only keeps the new column immutable, so the backfill has to run while it is dropped; the
-- recreated trigger is the exact 0007 whitelist (dispatch_block_reasons deliberately stays out).
DROP TRIGGER cols_only ON scan_job;
UPDATE scan_job SET dispatch_block_reasons = aegis.legacy_dispatch_block(scan_job)
 WHERE aegis.legacy_dispatch_block(scan_job) IS NOT NULL;
CREATE TRIGGER cols_only BEFORE UPDATE ON scan_job FOR EACH ROW EXECUTE FUNCTION aegis.forbid_value_update(
  'status','error','envelope_event_id','started_at','finished_at',
  'attempt','generation','cancel_requested_at','cancel_requested_by','cancel_reason','wait_reason');

-- Dispatch means leaving QUEUED/VALIDATING for a running state (validating, dispatched, running,
-- collecting) or a new attempt. A held job may still receive its terminal result (evidence collected
-- by an in-flight v1 container is not dropped) or be cancelled; it just cannot be started again.
CREATE FUNCTION aegis.guard_dispatch_block() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.dispatch_block_reasons IS NOT NULL
     AND (NEW.attempt IS DISTINCT FROM OLD.attempt
          OR (NEW.status IS DISTINCT FROM OLD.status
              AND NEW.status IN ('VALIDATING','DISPATCHED','RUNNING','COLLECTING'))) THEN
    RAISE EXCEPTION 'job % is not dispatchable (%): it was accepted before the v2 contract; create a new v2 job instead of replaying it',
      NEW.job_id, array_to_string(OLD.dispatch_block_reasons, ',')
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER dispatch_block_guard BEFORE UPDATE ON scan_job
  FOR EACH ROW EXECUTE FUNCTION aegis.guard_dispatch_block();

-- A v2 job may not be accepted on v1 configuration either: it could never be dispatched, and its
-- fingerprint would mix contracts. M05 still checks campaign state; this is the storage backstop.
CREATE FUNCTION aegis.require_job_v2_policy() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT coalesce((SELECT aegis.is_roe_policy_v2(p.policy) FROM policy_snapshot p
                    WHERE p.policy_version = NEW.policy_version), false) THEN
    RAISE EXCEPTION 'new job % must run on roe-policy.v2 configuration; policy_snapshot % is v1',
      NEW.job_id, NEW.policy_version USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER v2_policy_required BEFORE INSERT ON scan_job
  FOR EACH ROW EXECUTE FUNCTION aegis.require_job_v2_policy();

COMMENT ON COLUMN scan_job.dispatch_block_reasons IS
  'S1.6 dispatch hold. NULL = dispatchable. Non-NULL is the sorted list of LEGACY_POLICY_V1, LEGACY_MISSING_MANIFEST_PIN, LEGACY_MISSING_TARGET_REFS for a job accepted before the v2 contract; written once by 0009, immutable (not in the cols_only whitelist), and enforced by aegis.guard_dispatch_block, which refuses to start such a job (attempt bump or a move to VALIDATING/DISPATCHED/RUNNING). Its terminal result and cancel stay unaffected. Dispatchable queue: status = ''QUEUED'' AND dispatch_block_reasons IS NULL.';

-- ---------------------------------------------------------------------------
-- 6. Campaigns. A legacy campaign is paused with its reason and history; its v2 candidate is ready
--    but not adopted. Nothing resumes it, and the guard makes a v1 campaign unable to run at all.
-- ---------------------------------------------------------------------------
WITH held AS (
  SELECT c.campaign_id, c.status
    FROM campaign c
    JOIN policy_snapshot p ON p.policy_version = c.current_policy_version
   WHERE c.status IN ('RUNNING','WAITING')
     AND NOT aegis.is_roe_policy_v2(p.policy)
), paused AS (
  UPDATE campaign c
     SET status = 'PAUSED', status_reason = 'LEGACY_POLICY_V1'
    FROM held h
   WHERE c.campaign_id = h.campaign_id
  RETURNING c.campaign_id, h.status AS from_status
)
INSERT INTO campaign_status_change (campaign_id, seq, from_status, to_status, reason, actor)
SELECT campaign_id,
       (SELECT coalesce(max(seq), 0) + 1 FROM campaign_status_change s
         WHERE s.campaign_id = paused.campaign_id),
       from_status, 'PAUSED', 'LEGACY_POLICY_V1: campaign runs on v1 configuration; adopt the new v2 policy_snapshot before resuming',
       '{"kind":"module","id":"migration/0009"}'::jsonb
  FROM paused;

CREATE FUNCTION aegis.guard_campaign_v2_config() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  v2 boolean;
BEGIN
  SELECT aegis.is_roe_policy_v2(p.policy) INTO v2
    FROM policy_snapshot p WHERE p.policy_version = NEW.current_policy_version;
  IF v2 IS NULL THEN
    RETURN NEW;   -- snapshot not inserted yet in this transaction: the deferred FK decides
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NOT v2 THEN
      RAISE EXCEPTION 'new campaign % must start on roe-policy.v2 configuration; % is v1',
        NEW.campaign_id, NEW.current_policy_version USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.current_policy_version IS DISTINCT FROM OLD.current_policy_version AND NOT v2 THEN
    RAISE EXCEPTION 'campaign % cannot adopt %: not roe-policy.v2 configuration',
      NEW.campaign_id, NEW.current_policy_version USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status AND NEW.status IN ('RUNNING','WAITING') AND NOT v2 THEN
    RAISE EXCEPTION 'campaign % cannot become % on v1 configuration %; adopt the v2 snapshot first',
      NEW.campaign_id, NEW.status, NEW.current_policy_version USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER v2_config_guard BEFORE INSERT OR UPDATE ON campaign
  FOR EACH ROW EXECUTE FUNCTION aegis.guard_campaign_v2_config();
COMMENT ON COLUMN campaign.current_policy_version IS
  'The adopted policy_snapshot. From 0009 on it must be roe-policy.v2 configuration: creating a campaign, promoting a snapshot and moving to RUNNING/WAITING are refused for a v1 snapshot, so a legacy campaign cannot run again until an operator adopts its v2 candidate (policy_snapshot_migration) explicitly. 0009 never promotes it.';

-- ---------------------------------------------------------------------------
-- 7. Run the conversion. Every legacy snapshot gets its v2 candidate now; adopting it stays an
--    explicit operator action, and a policy that cannot be mapped aborts the migration here.
-- ---------------------------------------------------------------------------
DO $$
DECLARE converted int;
BEGIN
  SELECT count(*) INTO converted
    FROM aegis.migrate_legacy_policy_snapshots('{"kind":"module","id":"migration/0009"}'::jsonb);
  RAISE NOTICE '0009: % legacy policy_snapshot row(s) got a v2 candidate; current_policy_version not promoted', converted;
END $$;

COMMIT;
