-- OI-2 / OI-18: LEGACY_ACTOR is a real dispatch hold, and a held job cannot be reopened.
-- Run after 0011 on the clean chain and on the upgrade chain; ROLLBACK leaves the database unchanged.
--
-- The upgrade chain creates the held rows the way history did (a post-0009 row with a self-declared
-- agent actor, tests/fixtures/post-0009-agent-actor.sql, then 0011 backfills it). Here the hold is
-- written at INSERT, which is what 0011 does to such a row, so the guard itself is exercised on a
-- clean database too.
SET search_path=aegis,public;
BEGIN;
DO $$
DECLARE
  scope_a  uuid := '01900000-0000-7000-8000-000000006f11';
  camp_a   uuid := '01900000-0000-7000-8000-000000006f10';
  seed_a   uuid := '01900000-0000-7000-8000-000000006f21';
  dec_a    uuid := '01900000-0000-7000-8000-000000006f31';
  dec_b    uuid := '01900000-0000-7000-8000-000000006f32';
  dec_c    uuid := '01900000-0000-7000-8000-000000006f33';
  job_free uuid := '01900000-0000-7000-8000-000000006f41';
  job_held uuid := '01900000-0000-7000-8000-000000006f42';
  job_done uuid := '01900000-0000-7000-8000-000000006f43';
  job_new  uuid := '01900000-0000-7000-8000-000000006f44';
  reasons text[];
  blocked int := 0;
  out text;
BEGIN
  INSERT INTO policy_snapshot VALUES
    ('roe-193','01900000-0000-7000-8000-000000006f10','{"max_parallel_jobs":10,"max_duration_hours":168}',
     repeat('6',64),'{"kind":"operator","id":"soc-1"}');
  INSERT INTO scope_snapshot VALUES
    (scope_a,camp_a,'{"domains":["hold.example"]}');
  INSERT INTO campaign (campaign_id,name,objective,current_policy_version,scope_id,created_by) VALUES
    (camp_a,'Dispatch hold','OI-2/OI-18','roe-193',scope_a,'{"kind":"operator","id":"soc-1"}');
  INSERT INTO campaign_target VALUES
    (seed_a,scope_a,'domain','hold.example','dns:hold.example');
  INSERT INTO policy_decision (decision_id,campaign_id,capability,provider,targets,input,decision,rationale,requested_by,policy_version,scope_id,idempotency_key,trace_id) VALUES
    (dec_a,camp_a,'dns.enumerate_subdomains','subfinder','{dns:hold.example}','{"targets":["hold.example"]}','approved','OI-2','{"kind":"operator","id":"soc-1"}','roe-193',scope_a,'s1f-hold:1',repeat('6',32)),
    (dec_b,camp_a,'dns.resolve','dnsx','{dns:hold.example}','{"targets":["hold.example"]}','approved','OI-2 held in flight','{"kind":"operator","id":"soc-1"}','roe-193',scope_a,'s1f-hold:2',repeat('6',32)),
    (dec_c,camp_a,'dns.resolve','dnsx','{dns:hold.example}','{"targets":["hold.example"]}','approved','OI-2 held terminal','{"kind":"operator","id":"soc-1"}','roe-193',scope_a,'s1f-hold:3',repeat('6',32));

  -- 1. A job whose actor 0010 accepts carries no hold by itself; a stored hold passes the shape CHECK.
  INSERT INTO scan_job (job_id,campaign_id,decision_id,capability,provider,provider_version,adapter_version,image_digest,manifest_sha256,scan_cycle,job_fingerprint,policy_version,scope_id,input,targets,target_refs,requested_by,rationale,trace_id) VALUES
    (job_free,camp_a,dec_a,'dns.enumerate_subdomains','subfinder','v2.6.6','1.0.0','sha256:'||repeat('a',64),repeat('d',64),'01900000-0000-7000-8000-000000006f51',repeat('61',32),'roe-193',scope_a,'{"targets":["hold.example"]}','{dns:hold.example}','[{"seed_id":"01900000-0000-7000-8000-000000006f21"}]','{"kind":"operator","id":"soc-1"}','dispatchable',repeat('6',32));
  IF NOT EXISTS (SELECT 1 FROM scan_job WHERE job_id=job_free AND dispatch_block_reasons IS NULL) THEN
    RAISE EXCEPTION 'a job with a server-derived initiator was held';
  END IF;
  INSERT INTO scan_job (job_id,campaign_id,decision_id,capability,provider,provider_version,adapter_version,image_digest,manifest_sha256,scan_cycle,job_fingerprint,policy_version,scope_id,input,targets,target_refs,requested_by,rationale,status,started_at,dispatch_block_reasons,trace_id) VALUES
    (job_held,camp_a,dec_b,'dns.enumerate_subdomains','subfinder','v2.6.6','1.0.0','sha256:'||repeat('a',64),repeat('d',64),'01900000-0000-7000-8000-000000006f52',repeat('62',32),'roe-193',scope_a,'{"targets":["hold.example"]}','{dns:hold.example}','[{"seed_id":"01900000-0000-7000-8000-000000006f21"}]','{"kind":"operator","id":"soc-1"}','held in flight','RUNNING',now()-interval '1 hour','{LEGACY_ACTOR}',repeat('6',32)),
    (job_done,camp_a,dec_c,'dns.enumerate_subdomains','subfinder','v2.6.6','1.0.0','sha256:'||repeat('a',64),repeat('d',64),'01900000-0000-7000-8000-000000006f53',repeat('63',32),'roe-193',scope_a,'{"targets":["hold.example"]}','{dns:hold.example}','[{"seed_id":"01900000-0000-7000-8000-000000006f21"}]','{"kind":"operator","id":"soc-1"}','held terminal','QUEUED',NULL,'{LEGACY_ACTOR}',repeat('6',32));
  UPDATE scan_job SET status='SUCCEEDED', started_at=now()-interval '2 hours', finished_at=now()-interval '1 hour',
      envelope_event_id='01900000-0000-7000-8000-000000006f61' WHERE job_id=job_done;

  -- 2. The reason set: LEGACY_ACTOR is a known code, an unknown code and a duplicate are not.
  IF NOT aegis.is_dispatch_block_reasons(ARRAY['LEGACY_ACTOR']) THEN
    RAISE EXCEPTION 'LEGACY_ACTOR is not an accepted dispatch-block reason';
  END IF;
  BEGIN
    INSERT INTO scan_job (SELECT (jsonb_populate_record(NULL::scan_job, to_jsonb(j) || jsonb_build_object(
        'job_id',job_new,'job_fingerprint',repeat('64',32),'dispatch_block_reasons','{LEGACY_WHATEVER}'))).* FROM scan_job j WHERE job_id=job_free);
    RAISE EXCEPTION 'an unknown dispatch-block reason was accepted';
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;
  BEGIN
    INSERT INTO scan_job (SELECT (jsonb_populate_record(NULL::scan_job, to_jsonb(j) || jsonb_build_object(
        'job_id',job_new,'job_fingerprint',repeat('64',32),'dispatch_block_reasons','{LEGACY_ACTOR,LEGACY_ACTOR}'))).* FROM scan_job j WHERE job_id=job_free);
    RAISE EXCEPTION 'a duplicated dispatch-block reason was accepted';
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;

  -- 3. The definition (aegis.legacy_dispatch_block) reads the actor, not a label: a row 0010 could not
  --    have accepted is held, whatever its configuration. Evaluated as a row value, never inserted.
  SELECT aegis.legacy_dispatch_block(r) INTO reasons
    FROM jsonb_populate_record(NULL::scan_job, jsonb_build_object(
      'job_id',job_free,'requested_by','{"kind":"agent","id":"legacy-session"}'::jsonb,
      'policy_version','roe-193','manifest_sha256',repeat('d',64),
      'target_refs','[{"seed_id":"01900000-0000-7000-8000-000000006f21"}]'::jsonb)) AS r;
  IF reasons IS DISTINCT FROM ARRAY['LEGACY_ACTOR']::text[] THEN
    RAISE EXCEPTION 'an agent actor with valid configuration got reasons % instead of {LEGACY_ACTOR}', reasons;
  END IF;
  SELECT aegis.legacy_dispatch_block(r) INTO reasons
    FROM jsonb_populate_record(NULL::scan_job, jsonb_build_object(
      'job_id',job_free,'requested_by','{"kind":"agent","id":"legacy-session"}'::jsonb,
      'policy_version','roe-absent','manifest_sha256',NULL,'target_refs',NULL)) AS r;
  IF reasons IS DISTINCT FROM ARRAY['LEGACY_ACTOR','LEGACY_MISSING_MANIFEST_PIN','LEGACY_MISSING_TARGET_REFS','LEGACY_POLICY_V1']::text[] THEN
    RAISE EXCEPTION 'a fully legacy row got reasons %', reasons;
  END IF;

  -- 4. Dispatch is refused on a held job, in every form a dispatcher can try, while a terminal result
  --    still goes through: the hold stops a new dispatch, it traps nothing.
  BEGIN
    UPDATE scan_job SET status='VALIDATING' WHERE job_id=job_held;
    RAISE EXCEPTION 'a held job moved to VALIDATING';
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;
  BEGIN
    UPDATE scan_job SET attempt=attempt+1 WHERE job_id=job_held;
    RAISE EXCEPTION 'a held job bumped its attempt';
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;
  out := aegis.record_job_callback(job_held,1,1,'SUCCEEDED','01900000-0000-7000-8000-000000006f62',NULL,repeat('e',64));
  IF out <> 'terminalized' THEN
    RAISE EXCEPTION 'a held job could not record its terminal result: %', out;
  END IF;

  -- 5. OI-18: a held terminal job cannot be reopened into a generation it could never dispatch.
  BEGIN
    UPDATE scan_job SET generation=2, attempt=1, status='QUEUED', started_at=NULL, finished_at=NULL,
        envelope_event_id=NULL, error=NULL WHERE job_id=job_done;
    RAISE EXCEPTION 'a held terminal job was reopened';
  EXCEPTION WHEN check_violation THEN
    IF SQLERRM NOT LIKE '%held%' THEN
      RAISE EXCEPTION 'the reopen of a held job was refused for another reason: %', SQLERRM;
    END IF;
    blocked := blocked + 1;
  END;
  -- The same reopen on an unheld terminal job still works: the rule is the hold, not reopening.
  UPDATE scan_job SET status='SUCCEEDED', started_at=now()-interval '1 hour', finished_at=now()
   WHERE job_id=job_free;
  UPDATE scan_job SET generation=2, attempt=1, status='QUEUED', started_at=NULL, finished_at=NULL
   WHERE job_id=job_free;
  IF NOT EXISTS (SELECT 1 FROM scan_job WHERE job_id=job_free AND generation=2 AND status='QUEUED') THEN
    RAISE EXCEPTION 'an unheld terminal job could not be reopened';
  END IF;
  out := aegis.request_job_cancel(job_free,'{"kind":"operator","id":"soc-1"}','not needed');
  IF out <> 'requested' THEN
    RAISE EXCEPTION 'cancel intent was refused on a dispatchable job: %', out;
  END IF;

  -- 6. The hold is not something a caller can add or clear.
  BEGIN
    UPDATE scan_job SET dispatch_block_reasons=NULL WHERE job_id=job_done;
    RAISE EXCEPTION 'the dispatch hold was clearable';
  EXCEPTION WHEN insufficient_privilege THEN blocked := blocked + 1;
  END;
  BEGIN
    UPDATE scan_job SET dispatch_block_reasons='{LEGACY_POLICY_V1}' WHERE job_id=job_free;
    RAISE EXCEPTION 'a dispatch hold could be added by a caller';
  EXCEPTION WHEN insufficient_privilege THEN blocked := blocked + 1;
  END;

  -- 7. A new row with an agent actor is refused outright (0010): the hold describes history only.
  BEGIN
    INSERT INTO scan_job (SELECT (jsonb_populate_record(NULL::scan_job, to_jsonb(j) || jsonb_build_object(
        'job_id',job_new,'job_fingerprint',repeat('65',32),
        'requested_by','{"kind":"agent","id":"legacy-session"}'::jsonb))).* FROM scan_job j WHERE job_id=job_free);
    RAISE EXCEPTION 'a new job with an agent actor was accepted';
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;

  IF blocked <> 8 THEN
    RAISE EXCEPTION 'OI-2/OI-18: % / 8 checks blocked', blocked;
  END IF;
  RAISE NOTICE 'OI-2 dispatch hold: 8/8 blocked (reason shape, dispatch, reopen, immutable hold, agent actor on INSERT), held job still finalizes and an unheld one still reopens/cancels';
END $$;
ROLLBACK;
