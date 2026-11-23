-- C06 lifecycle: cancel vs complete in both orders, terminal finality, attempt/generation fencing,
-- late-result quarantine, wait reason and re-execution. Run after 0007 on the clean and the upgrade
-- chain; ROLLBACK leaves the test database unchanged. Two live connections are covered by
-- tests/test_job_lifecycle_race.py.
SET search_path=aegis,public;
BEGIN;
DO $$
DECLARE
  scope uuid := '01900000-0000-7000-8000-000000000312';
  camp  uuid := '01900000-0000-7000-8000-000000000302';
  seed  uuid := '01900000-0000-7000-8000-000000000321';
  job_main uuid := '01900000-0000-7000-8000-000000000341';  -- complete then cancel
  job_cancel uuid := '01900000-0000-7000-8000-000000000342'; -- cancel then complete
  job_stale uuid := '01900000-0000-7000-8000-000000000343';  -- late attempt callback
  job_partial uuid := '01900000-0000-7000-8000-000000000344'; -- timeout with partial evidence
  job_reopen uuid := '01900000-0000-7000-8000-000000000345';  -- generation re-execution
  ev_success uuid := '01900000-0000-7000-8000-000000000351';
  ev_partial uuid := '01900000-0000-7000-8000-000000000352';
  scan uuid := '01900000-0000-7000-8000-000000000391';
  hash char(64) := repeat('a',64);
  blocked int := 0; shape int := 0;
  out text; terminals int; changes int; evidence_rows int;
  wait_json jsonb := '{"code":"DEPENDENCY_FAILED","since":"2026-11-24T02:00:00Z","blocking_job_ids":["01900000-0000-7000-8000-000000000341"]}';
BEGIN
  INSERT INTO policy_snapshot VALUES ('roe-7',camp,'{"max_parallel_jobs":10,"max_duration_hours":168}',repeat('7',64),'{"kind":"operator","id":"fixture"}');
  INSERT INTO scope_snapshot VALUES (scope,camp,'{"domains":["lifecycle.example"]}');
  INSERT INTO campaign (campaign_id,name,objective,current_policy_version,scope_id,created_by)
    VALUES (camp,'Job lifecycle','C06 fixture','roe-7',scope,'{"kind":"operator","id":"fixture"}');
  INSERT INTO campaign_target VALUES (seed,scope,'domain','lifecycle.example','dns:lifecycle.example');

  -- One decision + accepted job per case; fingerprints stay unique.
  INSERT INTO policy_decision (decision_id,campaign_id,capability,provider,targets,input,decision,rationale,requested_by,policy_version,scope_id,idempotency_key,trace_id) VALUES
    ('01900000-0000-7000-8000-0000000003a1',camp,'dns.enumerate_subdomains','subfinder','{dns:lifecycle.example}','{"targets":["lifecycle.example"]}','approved','C06 complete then cancel','{"kind":"agent","id":"fixture"}','roe-7',scope,'c06:1',repeat('7',32)),
    ('01900000-0000-7000-8000-0000000003a2',camp,'dns.enumerate_subdomains','subfinder','{dns:lifecycle.example}','{"targets":["lifecycle.example"]}','approved','C06 cancel then complete','{"kind":"agent","id":"fixture"}','roe-7',scope,'c06:2',repeat('7',32)),
    ('01900000-0000-7000-8000-0000000003a3',camp,'dns.enumerate_subdomains','subfinder','{dns:lifecycle.example}','{"targets":["lifecycle.example"]}','approved','C06 stale attempt','{"kind":"agent","id":"fixture"}','roe-7',scope,'c06:3',repeat('7',32)),
    ('01900000-0000-7000-8000-0000000003a4',camp,'dns.enumerate_subdomains','subfinder','{dns:lifecycle.example}','{"targets":["lifecycle.example"]}','approved','C06 partial timeout','{"kind":"agent","id":"fixture"}','roe-7',scope,'c06:4',repeat('7',32)),
    ('01900000-0000-7000-8000-0000000003a5',camp,'dns.enumerate_subdomains','subfinder','{dns:lifecycle.example}','{"targets":["lifecycle.example"]}','approved','C06 re-execution','{"kind":"agent","id":"fixture"}','roe-7',scope,'c06:5',repeat('7',32));
  INSERT INTO scan_job (job_id,campaign_id,decision_id,capability,provider,provider_version,adapter_version,image_digest,manifest_sha256,scan_cycle,job_fingerprint,policy_version,scope_id,input,targets,target_refs,requested_by,rationale,trace_id) VALUES
    (job_main,   camp,'01900000-0000-7000-8000-0000000003a1','dns.enumerate_subdomains','subfinder','v2.6.6','1.0.0','sha256:'||repeat('5',64),repeat('6',64),scan,repeat('1',64),'roe-7',scope,'{"targets":["lifecycle.example"]}','{dns:lifecycle.example}',jsonb_build_array(jsonb_build_object('seed_id',seed)),'{"kind":"agent","id":"fixture"}','C06 complete then cancel',repeat('7',32)),
    (job_cancel, camp,'01900000-0000-7000-8000-0000000003a2','dns.enumerate_subdomains','subfinder','v2.6.6','1.0.0','sha256:'||repeat('5',64),repeat('6',64),scan,repeat('2',64),'roe-7',scope,'{"targets":["lifecycle.example"]}','{dns:lifecycle.example}',jsonb_build_array(jsonb_build_object('seed_id',seed)),'{"kind":"agent","id":"fixture"}','C06 cancel then complete',repeat('7',32)),
    (job_stale,  camp,'01900000-0000-7000-8000-0000000003a3','dns.enumerate_subdomains','subfinder','v2.6.6','1.0.0','sha256:'||repeat('5',64),repeat('6',64),scan,repeat('3',64),'roe-7',scope,'{"targets":["lifecycle.example"]}','{dns:lifecycle.example}',jsonb_build_array(jsonb_build_object('seed_id',seed)),'{"kind":"agent","id":"fixture"}','C06 stale attempt',repeat('7',32)),
    (job_partial,camp,'01900000-0000-7000-8000-0000000003a4','dns.enumerate_subdomains','subfinder','v2.6.6','1.0.0','sha256:'||repeat('5',64),repeat('6',64),scan,repeat('4',64),'roe-7',scope,'{"targets":["lifecycle.example"]}','{dns:lifecycle.example}',jsonb_build_array(jsonb_build_object('seed_id',seed)),'{"kind":"agent","id":"fixture"}','C06 partial timeout',repeat('7',32)),
    (job_reopen, camp,'01900000-0000-7000-8000-0000000003a5','dns.enumerate_subdomains','subfinder','v2.6.6','1.0.0','sha256:'||repeat('5',64),repeat('6',64),scan,repeat('5',64),'roe-7',scope,'{"targets":["lifecycle.example"]}','{dns:lifecycle.example}',jsonb_build_array(jsonb_build_object('seed_id',seed)),'{"kind":"agent","id":"fixture"}','C06 re-execution',repeat('7',32));

  IF EXISTS (SELECT 1 FROM scan_job WHERE campaign_id = camp AND attempt <> 1) THEN
    RAISE EXCEPTION 'new job must start on attempt 1';
  END IF;
  IF EXISTS (SELECT 1 FROM scan_job WHERE campaign_id = camp AND (generation <> 1 OR wait_reason IS NOT NULL
             OR cancel_requested_at IS NOT NULL)) THEN
    RAISE EXCEPTION 'new job must start on generation 1 with no wait reason and no cancel intent';
  END IF;

  -- 1. Wait reason (X-4): valid while QUEUED, invalid shape, unknown code, and never outside QUEUED.
  UPDATE scan_job SET wait_reason = wait_json WHERE job_id = job_main;
  IF NOT EXISTS (SELECT 1 FROM job_lifecycle_change WHERE job_id = job_main AND field = 'wait_reason'
                  AND new_value = wait_json) THEN
    RAISE EXCEPTION 'wait reason change was not recorded in job_lifecycle_change';
  END IF;
  FOR out IN SELECT jsonb_build_object('code','WHATEVER','since','2026-11-24T02:00:00Z')::text
             UNION ALL SELECT jsonb_build_object('code','DEPENDENCY_FAILED','since','2026-11-24 02:00:00')::text
             UNION ALL SELECT (wait_json || '{"extra":1}')::text
  LOOP
    BEGIN
      UPDATE scan_job SET wait_reason = out::jsonb WHERE job_id = job_main;
    EXCEPTION WHEN check_violation THEN shape := shape + 1;
    END;
  END LOOP;
  -- Dispatch: attempt +1 and the reason is cleared in the same UPDATE (a stale reason cannot survive).
  UPDATE scan_job SET status = 'DISPATCHED', attempt = attempt + 1, started_at = now(), wait_reason = NULL
   WHERE job_id = job_main AND status = 'QUEUED';
  IF NOT EXISTS (SELECT 1 FROM scan_job WHERE job_id = job_main AND attempt = 2 AND wait_reason IS NULL) THEN
    RAISE EXCEPTION 'dispatch did not advance attempt or clear the wait reason';
  END IF;
  BEGIN
    UPDATE scan_job SET wait_reason = wait_json WHERE job_id = job_main;
  EXCEPTION WHEN check_violation THEN shape := shape + 1;
  END;
  BEGIN
    UPDATE scan_job SET attempt = attempt + 2 WHERE job_id = job_main;
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;

  -- 2. Cancel vs complete, order A: the result wins, the later cancel is refused and never rewrites state.
  UPDATE scan_job SET status = 'RUNNING' WHERE job_id = job_main;
  out := aegis.record_job_callback(job_main, 1, 2, 'SUCCEEDED', ev_success, NULL, hash);
  IF out <> 'terminalized' THEN RAISE EXCEPTION 'order A: callback returned %', out; END IF;
  out := aegis.request_job_cancel(job_main, '{"kind":"operator","id":"soc"}', 'window closed');
  IF out <> 'terminal' THEN RAISE EXCEPTION 'order A: cancel after terminal returned %', out; END IF;
  IF NOT EXISTS (SELECT 1 FROM scan_job WHERE job_id = job_main AND status = 'SUCCEEDED'
                  AND finished_at IS NOT NULL AND envelope_event_id = ev_success AND cancel_requested_at IS NULL) THEN
    RAISE EXCEPTION 'order A: terminal result was not recorded as expected';
  END IF;
  out := aegis.record_job_callback(job_main, 1, 2, 'SUCCEEDED', ev_success, NULL, hash);
  IF out <> 'duplicate' THEN RAISE EXCEPTION 'duplicate callback returned %', out; END IF;
  SELECT count(*) INTO terminals FROM job_status_change WHERE job_id = job_main AND to_status = 'SUCCEEDED';
  IF terminals <> 1 THEN RAISE EXCEPTION 'duplicate callback wrote % status rows', terminals; END IF;
  -- Same status but a different envelope is not a replay: the first result stays, the second is kept as audit.
  out := aegis.record_job_callback(job_main, 1, 2, 'SUCCEEDED', '01900000-0000-7000-8000-000000000359', NULL, hash);
  IF out <> 'quarantined' THEN RAISE EXCEPTION 'second envelope with the same status returned %', out; END IF;
  IF (SELECT envelope_event_id FROM scan_job WHERE job_id = job_main) IS DISTINCT FROM ev_success THEN
    RAISE EXCEPTION 'second envelope overwrote the recorded result';
  END IF;
  out := aegis.record_job_callback(job_main, 1, 2, 'CANCELLED', NULL, NULL, NULL);
  IF out <> 'quarantined' THEN RAISE EXCEPTION 'order A: late cancel returned %', out; END IF;
  BEGIN
    UPDATE scan_job SET status = 'FAILED', error = '{"code":"INTERNAL_ERROR","message":"x","next_action":"ESCALATE"}'::jsonb
     WHERE job_id = job_main;
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;

  -- 3. Cancel vs complete, order B: the intent wins only through terminalization; the later result is
  --    quarantined and keeps its audit instead of overwriting the terminal state.
  UPDATE scan_job SET status = 'RUNNING', attempt = attempt + 1, started_at = now() WHERE job_id = job_cancel;
  out := aegis.request_job_cancel(job_cancel, '{"kind":"operator","id":"soc"}', 'stop');
  IF out <> 'requested' THEN RAISE EXCEPTION 'order B: first cancel returned %', out; END IF;
  IF (SELECT status FROM scan_job WHERE job_id = job_cancel) <> 'RUNNING' THEN
    RAISE EXCEPTION 'order B: cancel intent changed the status';
  END IF;
  out := aegis.request_job_cancel(job_cancel, '{"kind":"operator","id":"soc"}', 'stop again');
  IF out <> 'already_requested' THEN RAISE EXCEPTION 'order B: repeated cancel returned %', out; END IF;
  BEGIN
    UPDATE scan_job SET cancel_reason = 'rewritten' WHERE job_id = job_cancel;
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;
  out := aegis.record_job_callback(job_cancel, 1, 2, 'CANCELLED', NULL, NULL, NULL);
  IF out <> 'terminalized' THEN RAISE EXCEPTION 'order B: cancel terminal returned %', out; END IF;
  out := aegis.record_job_callback(job_cancel, 1, 2, 'SUCCEEDED', ev_success, NULL, hash);
  IF out <> 'quarantined' THEN RAISE EXCEPTION 'order B: late result returned %', out; END IF;
  IF (SELECT status FROM scan_job WHERE job_id = job_cancel) <> 'CANCELLED' THEN
    RAISE EXCEPTION 'order B: late result overwrote the terminal state';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM job_callback_quarantine WHERE job_id = job_cancel
                  AND reason = 'terminal_already_recorded' AND payload_hash = hash) THEN
    RAISE EXCEPTION 'order B: late result left no quarantine record';
  END IF;
  SELECT count(*) INTO terminals FROM job_status_change WHERE job_id = job_cancel AND to_status IN ('SUCCEEDED','FAILED','CANCELLED');
  IF terminals <> 1 THEN RAISE EXCEPTION 'order B: % terminal status rows', terminals; END IF;

  -- 4. A callback from an earlier attempt is quarantined: dispatch #2 exists, attempt #1 may not win.
  UPDATE scan_job SET status = 'DISPATCHED', attempt = attempt + 1, started_at = now() WHERE job_id = job_stale;
  UPDATE scan_job SET status = 'RUNNING' WHERE job_id = job_stale;
  out := aegis.record_job_callback(job_stale, 1, 1, 'SUCCEEDED', ev_success, NULL, hash);
  IF out <> 'quarantined' THEN RAISE EXCEPTION 'stale attempt callback returned %', out; END IF;
  IF (SELECT status FROM scan_job WHERE job_id = job_stale) <> 'RUNNING' THEN
    RAISE EXCEPTION 'stale attempt callback changed the job';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM job_callback_quarantine WHERE job_id = job_stale AND reason = 'stale_attempt') THEN
    RAISE EXCEPTION 'stale attempt callback left no quarantine record';
  END IF;

  -- 5. Timeout with a partial result keeps what was collected: evidence rows stay, the job records
  --    the partial envelope, and only a later callback is quarantined.
  UPDATE scan_job SET status = 'RUNNING', attempt = attempt + 1, started_at = now() WHERE job_id = job_partial;
  INSERT INTO evidence (evidence_id,sha256,storage_uri,campaign_id,job_id,size_bytes,media_type,classification,source_tool) VALUES
    ('01900000-0000-7000-8000-0000000004a1',repeat('1',64),
     's3://evidence/'||camp||'/'||job_partial||'/'||repeat('1',64), camp, job_partial, 10,
     'text/plain','INTERNAL','subfinder'),
    ('01900000-0000-7000-8000-0000000004a2',repeat('2',64),
     's3://evidence/'||camp||'/'||job_partial||'/'||repeat('2',64), camp, job_partial, 20,
     'text/plain','INTERNAL','subfinder');
  out := aegis.record_job_callback(job_partial, 1, 2, 'FAILED', ev_partial,
           '{"code":"EXECUTION_TIMEOUT","message":"timeout","next_action":"RETRY"}'::jsonb, hash);
  IF out <> 'terminalized' THEN RAISE EXCEPTION 'timeout finalization returned %', out; END IF;
  SELECT count(*) INTO evidence_rows FROM evidence WHERE job_id = job_partial;
  IF evidence_rows <> 2 THEN RAISE EXCEPTION 'timeout lost partial evidence (% rows)', evidence_rows; END IF;
  IF (SELECT envelope_event_id FROM scan_job WHERE job_id = job_partial) IS DISTINCT FROM ev_partial THEN
    RAISE EXCEPTION 'timeout did not keep the partial envelope reference';
  END IF;
  out := aegis.record_job_callback(job_partial, 1, 2, 'SUCCEEDED', ev_success, NULL, hash);
  IF out <> 'quarantined' THEN RAISE EXCEPTION 'late full result after timeout returned %', out; END IF;
  SELECT count(*) INTO evidence_rows FROM evidence WHERE job_id = job_partial;
  IF evidence_rows <> 2 THEN RAISE EXCEPTION 'late result removed partial evidence'; END IF;

  -- 6. Re-execution is a new generation, never a quiet reset: the old generation's callback is quarantined.
  UPDATE scan_job SET status = 'RUNNING', attempt = attempt + 1, started_at = now() WHERE job_id = job_reopen;
  out := aegis.record_job_callback(job_reopen, 1, 2, 'FAILED', NULL,
           '{"code":"TOOL_UNAVAILABLE","message":"runner lost","next_action":"RETRY"}'::jsonb, NULL);
  IF out <> 'terminalized' THEN RAISE EXCEPTION 're-execution setup returned %', out; END IF;
  BEGIN
    UPDATE scan_job SET status = 'QUEUED', finished_at = NULL WHERE job_id = job_reopen;
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;
  UPDATE scan_job
     SET status = 'QUEUED', generation = generation + 1, attempt = 1, started_at = NULL,
         finished_at = NULL, error = NULL, envelope_event_id = NULL
   WHERE job_id = job_reopen;
  IF NOT EXISTS (SELECT 1 FROM scan_job WHERE job_id = job_reopen AND generation = 2 AND attempt = 1 AND status = 'QUEUED') THEN
    RAISE EXCEPTION 're-execution did not move to generation 2 attempt 1';
  END IF;
  SELECT count(*) INTO changes FROM job_lifecycle_change WHERE job_id = job_reopen AND field = 'generation';
  IF changes <> 1 THEN RAISE EXCEPTION 'generation change left % history rows', changes; END IF;
  out := aegis.record_job_callback(job_reopen, 1, 2, 'SUCCEEDED', ev_success, NULL, hash);
  IF out <> 'quarantined' THEN RAISE EXCEPTION 'old generation callback returned %', out; END IF;
  IF NOT EXISTS (SELECT 1 FROM job_callback_quarantine WHERE job_id = job_reopen AND reason = 'stale_generation') THEN
    RAISE EXCEPTION 'old generation callback left no quarantine record';
  END IF;
  BEGIN
    UPDATE scan_job SET generation = generation + 1 WHERE job_id = job_reopen;
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;

  -- 7. A job can only be CANCELLED after an explicit intent; a queued job needs no container.
  out := aegis.record_job_callback(job_stale, 1, 2, 'CANCELLED', NULL, NULL, NULL);
  IF out <> 'quarantined' THEN RAISE EXCEPTION 'cancel without intent returned %', out; END IF;
  IF NOT EXISTS (SELECT 1 FROM job_callback_quarantine WHERE job_id = job_stale AND reason = 'cancel_not_requested') THEN
    RAISE EXCEPTION 'cancel without intent left no quarantine record';
  END IF;

  -- 8. The lifecycle tables are append-only.
  BEGIN UPDATE job_lifecycle_change SET field = 'attempt' WHERE job_id = job_main;
  EXCEPTION WHEN insufficient_privilege THEN blocked := blocked + 1; END;
  BEGIN DELETE FROM job_callback_quarantine;
  EXCEPTION WHEN insufficient_privilege THEN blocked := blocked + 1; END;

  IF shape <> 4 THEN RAISE EXCEPTION 'only % / 4 wait-reason shape/status rules blocked', shape; END IF;
  IF blocked <> 7 THEN RAISE EXCEPTION 'only % / 7 lifecycle immutability/finality guards blocked', blocked; END IF;
  RAISE NOTICE 'lifecycle: complete-before-cancel and cancel-before-complete each leave exactly one terminal result';
  RAISE NOTICE 'lifecycle: stale attempt/generation and cancelled-without-intent callbacks quarantined; timeout keeps partial evidence';
  RAISE NOTICE 'lifecycle: 4/4 wait-reason shape/status rules, 7/7 immutability/finality guards PASS';
END $$;
ROLLBACK;
