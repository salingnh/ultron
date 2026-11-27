-- G1.6 safety review (F5): the internet profile needs a structured authorization in the RoE.
--
-- `network_profile` defaults to internet, so a campaign without the field is an internet
-- campaign: its `authorization` object (owner, reference, date, authorized_suffixes) is required.
-- The function is the database mirror of campaign/roe-policy.v2.schema.json; the full semantic
-- validation stays in contracts/validation.py. Independent of the other G1.6 slice migrations: it
-- replaces one predicate function and touches no table.
BEGIN;

CREATE OR REPLACE FUNCTION aegis.is_roe_authorization(v jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
  SELECT CASE
    WHEN v IS NULL OR jsonb_typeof(v) <> 'object' THEN false
    WHEN EXISTS (SELECT 1 FROM jsonb_object_keys(v) k
                  WHERE k NOT IN ('owner','reference','date','authorized_suffixes')) THEN false
    WHEN v->'owner' IS NULL OR jsonb_typeof(v->'owner') <> 'string'
         OR length(btrim(v->>'owner')) NOT BETWEEN 1 AND 200 THEN false
    WHEN v->'reference' IS NULL OR jsonb_typeof(v->'reference') <> 'string'
         OR length(btrim(v->>'reference')) NOT BETWEEN 3 AND 300 THEN false
    WHEN v->'date' IS NULL OR jsonb_typeof(v->'date') <> 'string'
         OR (v->>'date') !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' THEN false
    WHEN jsonb_typeof(v->'authorized_suffixes') <> 'array'
         OR jsonb_array_length(v->'authorized_suffixes') < 1 THEN false
    WHEN NOT aegis.is_json_strings(v->'authorized_suffixes', 100, NULL, 1) THEN false
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
      'budget','capability_denylist','network_profile','authorization')) THEN false
    WHEN NOT aegis.is_json_int(policy->'max_parallel_jobs', 1, 50) THEN false
    WHEN NOT aegis.is_json_int(policy->'max_duration_hours', 1, 168) THEN false
    WHEN policy ? 'network_profile'
         AND NOT (jsonb_typeof(policy->'network_profile') = 'string'
                  AND policy->>'network_profile' IN ('lab', 'internet')) THEN false
    WHEN policy ? 'authorization'
         AND NOT aegis.is_roe_authorization(policy->'authorization') THEN false
    WHEN (NOT policy ? 'network_profile' OR policy->>'network_profile' = 'internet')
         AND NOT policy ? 'authorization' THEN false
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

COMMENT ON FUNCTION aegis.is_roe_policy_v2(policy jsonb) IS 'Structural mirror of campaign/roe-policy.v2.schema.json: closed key set (no RoE time windows), integer limits, network profile (lab|internet), a required structured authorization for internet campaigns, budget, rate limits and denylist shapes. Semantic validation (dates, domain suffixes) stays in contracts/validation.py.';

COMMENT ON FUNCTION aegis.is_roe_authorization(v jsonb) IS 'Structure of roe-policy.v2 authorization: owner, reference, a YYYY-MM-DD date and at least one authorized domain suffix, closed key set.';

COMMIT;
