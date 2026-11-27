-- G1.6 internet network profile: roe-policy.v2 `network_profile` and the per-host connection cap.
--
-- 0001_baseline.sql is immutable once applied (owner decision 2026-11-25 after G1 merged): a shape
-- change is a new migration. This one is independent of the other G1.6 slice migrations (0002 slice
-- A, 0003 slice B, 0004 slice C): it only replaces two predicate functions the baseline defines and
-- touches no table, no column, no policy row.
--
-- The two functions are the database mirror of campaign/roe-policy.v2.schema.json:
--   * `network_profile` is the closed enum lab|internet of the campaign's execution settings;
--   * `rate_limits.max_concurrent_connections_per_host` is the per-host connection cap the internet
--     broker enforces (1..100), next to the existing per-host request rate.
-- Both bodies keep the baseline rule: a closed key set, types and ranges checked here; semantic
-- formats stay in contracts/validation.py.
BEGIN;

CREATE OR REPLACE FUNCTION aegis.is_rate_limits(v jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
  SELECT CASE
    WHEN v IS NULL OR jsonb_typeof(v) <> 'object' THEN false
    WHEN EXISTS (SELECT 1 FROM jsonb_object_keys(v) k
                  WHERE k NOT IN ('requests_per_second_per_host','packets_per_second','jobs_per_minute',
                                  'max_concurrent_connections_per_host')) THEN false
    WHEN v ? 'requests_per_second_per_host'
         AND NOT aegis.is_json_number(v->'requests_per_second_per_host', 0, 1000, true) THEN false
    WHEN v ? 'max_concurrent_connections_per_host'
         AND NOT aegis.is_json_int(v->'max_concurrent_connections_per_host', 1, 100) THEN false
    WHEN v ? 'packets_per_second' AND NOT aegis.is_json_int(v->'packets_per_second', 1, 100000) THEN false
    WHEN v ? 'jobs_per_minute'    AND NOT aegis.is_json_int(v->'jobs_per_minute', 1, 600) THEN false
    ELSE true
  END
$$;

CREATE OR REPLACE FUNCTION aegis.is_roe_policy_v2(policy jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'aegis', 'pg_temp'
    AS $_$
  SELECT CASE
    WHEN jsonb_typeof(policy) <> 'object' THEN false
    WHEN EXISTS (SELECT 1 FROM jsonb_object_keys(policy) k WHERE k NOT IN (
      'target_denylist','max_parallel_jobs','max_duration_hours','rate_limits',
      'budget','capability_denylist','network_profile')) THEN false
    WHEN NOT aegis.is_json_int(policy->'max_parallel_jobs', 1, 50) THEN false
    WHEN NOT aegis.is_json_int(policy->'max_duration_hours', 1, 168) THEN false
    WHEN policy ? 'network_profile'
         AND NOT (jsonb_typeof(policy->'network_profile') = 'string'
                  AND policy->>'network_profile' IN ('lab', 'internet')) THEN false
    WHEN policy ? 'target_denylist'
         AND NOT aegis.is_json_strings(policy->'target_denylist', 10000, NULL, 1) THEN false
    WHEN policy ? 'rate_limits' AND NOT aegis.is_rate_limits(policy->'rate_limits') THEN false
    WHEN policy ? 'budget' AND NOT aegis.is_budget(policy->'budget') THEN false
    WHEN policy ? 'capability_denylist'
         AND NOT aegis.is_json_strings(policy->'capability_denylist', NULL,
                                       '^[a-z][a-z0-9]*\.[a-z][a-z0-9_]*$', 1) THEN false
    ELSE true
  END
$_$;

COMMENT ON FUNCTION aegis.is_roe_policy_v2(policy jsonb) IS 'Structural mirror of campaign/roe-policy.v2.schema.json for a snapshot written in the database: closed key set (no RoE time windows), required integer limits and ranges, the network profile (lab|internet), budget, rate limits (incl. the per-host connection cap the internet broker enforces) and denylist shapes. IANA timezone names and the like are validated by contracts/validation.py. A valid roe-policy.v1 object never passes (v1 requires scan_profile, v2 allows no unknown key).';

COMMENT ON FUNCTION aegis.is_rate_limits(v jsonb) IS 'Structural mirror of roe-policy.v2 rate_limits: the per-host request rate the broker throttles, the per-host connection cap of the internet profile, the port-scan packet rate and the job acceptance rate.';

COMMIT;
