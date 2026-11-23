-- OI-1 / gate-review probe P9: a guard must not depend on the caller's search_path.
-- Run after 0011 on the clean chain and on the upgrade chain. One session, rolled back.
--
-- The shape of the bypass this test pins down: a trigger function is resolved in the caller's
-- search_path, and a session with the default `"$user", public` searches pg_temp first. Before 0011,
-- `CREATE TEMP TABLE campaign_target` made 0005's seed guard read the attacker's table and accept a
-- job whose seed belongs to no campaign; `CREATE TEMP TABLE job_lifecycle_change` made 0007's history
-- write land in the temp table and disappear with the session. Both functions are now pinned to
-- `aegis, pg_temp` (pg_temp last), so the shadow table is inert.
RESET search_path;
BEGIN;
DO $$
DECLARE
  bad text;
  total int;
BEGIN
  -- 1. Catalog invariant: every function of the schema carries the pin. The count guard keeps the
  --    test from passing vacuously.
  SELECT string_agg(p.oid::regprocedure::text || ' [' || coalesce(array_to_string(p.proconfig, ' '), '-') || ']', ', ')
    INTO bad
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'aegis'
     AND NOT (coalesce(p.proconfig, '{}'::text[]) @> ARRAY['search_path=aegis, pg_temp']);
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'aegis function(s) without pinned search_path: %', bad;
  END IF;
  SELECT count(*) INTO total FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'aegis';
  IF total < 40 THEN
    RAISE EXCEPTION 'only % aegis function(s) found; the pinning sweep has nothing to check', total;
  END IF;
  RAISE NOTICE 'OI-1 pinning: %/aegis function(s) pin search_path = aegis, pg_temp', total;
END $$;

-- 2. Fixture: a campaign with one real seed and one valid job of its own (used for the history probe).
INSERT INTO aegis.policy_snapshot VALUES
  ('roe-191', '01900000-0000-7000-8000-000000005f10', '{"max_parallel_jobs":10,"max_duration_hours":168}',
   repeat('f',64), '{"kind":"operator","id":"soc-1"}');
INSERT INTO aegis.scope_snapshot VALUES
  ('01900000-0000-7000-8000-000000005f11', '01900000-0000-7000-8000-000000005f10', '{"domains":["pin.example"]}');
INSERT INTO aegis.campaign (campaign_id,name,objective,current_policy_version,scope_id,created_by) VALUES
  ('01900000-0000-7000-8000-000000005f10','Search path pinning','OI-1','roe-191',
   '01900000-0000-7000-8000-000000005f11','{"kind":"operator","id":"soc-1"}');
INSERT INTO aegis.campaign_target VALUES
  ('01900000-0000-7000-8000-000000005f21','01900000-0000-7000-8000-000000005f11',
   'domain','pin.example','dns:pin.example');
INSERT INTO aegis.policy_decision (decision_id,campaign_id,capability,provider,targets,input,decision,rationale,requested_by,policy_version,scope_id,idempotency_key,trace_id) VALUES
  ('01900000-0000-7000-8000-000000005f31','01900000-0000-7000-8000-000000005f10','dns.enumerate_subdomains','subfinder','{dns:pin.example}','{"targets":["pin.example"]}','approved','OI-1','{"kind":"operator","id":"soc-1"}','roe-191','01900000-0000-7000-8000-000000005f11','s1f-pin:1',repeat('f',32));
INSERT INTO aegis.scan_job (job_id,campaign_id,decision_id,capability,provider,provider_version,adapter_version,image_digest,manifest_sha256,scan_cycle,job_fingerprint,policy_version,scope_id,input,targets,target_refs,requested_by,rationale,trace_id) VALUES
  ('01900000-0000-7000-8000-000000005f41','01900000-0000-7000-8000-000000005f10','01900000-0000-7000-8000-000000005f31','dns.enumerate_subdomains','subfinder','v2.6.6','1.0.0','sha256:'||repeat('a',64),repeat('d',64),'01900000-0000-7000-8000-000000005f51',repeat('5f',32),'roe-191','01900000-0000-7000-8000-000000005f11','{"targets":["pin.example"]}','{dns:pin.example}','[{"seed_id":"01900000-0000-7000-8000-000000005f21"}]','{"kind":"operator","id":"soc-1"}','OI-1 history probe',repeat('f',32));

-- 3. The exploit precondition is real: a TEMP table of the same name wins an unqualified reference
--    in this session. The guard must not care.
CREATE TEMP TABLE campaign_target (
  target_id uuid, scope_id uuid, kind text, value text, canonical_key text);
INSERT INTO campaign_target VALUES
  ('01900000-0000-7000-8000-000000005f2f','01900000-0000-7000-8000-000000005f11',
   'domain','attacker.example','dns:attacker.example');

DO $$
DECLARE
  foreign_seed uuid := '01900000-0000-7000-8000-000000005f2f';
  blocked int := 0;
  shadow_rows int;
  probe_job jsonb;
BEGIN
  SELECT count(*) INTO shadow_rows FROM campaign_target;
  IF shadow_rows <> 1 THEN
    RAISE EXCEPTION 'the TEMP shadow table is not visible under this search_path (% rows); the probe proves nothing', shadow_rows;
  END IF;

  -- 4. A job whose seed is not a campaign_target of its campaign is still refused, although the
  --    attacker's table says otherwise.
  probe_job := (SELECT to_jsonb(j) || jsonb_build_object(
                  'job_id','01900000-0000-7000-8000-000000005f42',
                  'decision_id','01900000-0000-7000-8000-000000005f31',
                  'job_fingerprint',repeat('af',32),
                  'target_refs',jsonb_build_array(jsonb_build_object('seed_id', foreign_seed))
                ) FROM aegis.scan_job j WHERE job_id = '01900000-0000-7000-8000-000000005f41');
  BEGIN
    INSERT INTO aegis.scan_job SELECT (jsonb_populate_record(NULL::aegis.scan_job, probe_job)).*;
    RAISE EXCEPTION 'seed guard was bypassed by a TEMP campaign_target shadow table';
  EXCEPTION WHEN foreign_key_violation THEN blocked := blocked + 1;
  END;

  -- 5. Control: without the shadow table the same insert is also refused, so step 4 is not green
  --    because of an unrelated error.
  DROP TABLE campaign_target;
  BEGIN
    INSERT INTO aegis.scan_job SELECT (jsonb_populate_record(NULL::aegis.scan_job, probe_job)).*;
    RAISE EXCEPTION 'seed guard accepted a seed outside the campaign';
  EXCEPTION WHEN foreign_key_violation THEN blocked := blocked + 1;
  END;
  IF blocked <> 2 THEN
    RAISE EXCEPTION 'seed guard: % / 2 probes blocked', blocked;
  END IF;
  RAISE NOTICE 'OI-1 seed guard: 2/2 refused with and without a TEMP campaign_target shadow';
END $$;

-- 6. The lifecycle history cannot be redirected either. Before 0011 this UPDATE failed outright with
--    the default search_path (the trigger could not see aegis.job_lifecycle_change); with a TEMP table
--    of that name it wrote into the temp table and the row vanished.
CREATE TEMP TABLE job_lifecycle_change (
  job_id uuid, seq integer, field text, old_value jsonb, new_value jsonb, at timestamptz);
UPDATE aegis.scan_job SET attempt = 2 WHERE job_id = '01900000-0000-7000-8000-000000005f41';
DO $$
DECLARE real_rows int; shadow_rows int;
BEGIN
  SELECT count(*) INTO shadow_rows FROM job_lifecycle_change;
  SELECT count(*) INTO real_rows FROM aegis.job_lifecycle_change
   WHERE job_id = '01900000-0000-7000-8000-000000005f41' AND field = 'attempt';
  IF shadow_rows <> 0 THEN
    RAISE EXCEPTION 'lifecycle history was written into the TEMP shadow table (% rows)', shadow_rows;
  END IF;
  IF real_rows <> 1 THEN
    RAISE EXCEPTION 'lifecycle history for the attempt bump is missing (aegis rows = %)', real_rows;
  END IF;
  RAISE NOTICE 'OI-1 history: attempt bump recorded in aegis.job_lifecycle_change, TEMP shadow stayed empty';
END $$;

ROLLBACK;
