-- 0017 acceptance (G1, owner decision 2026-11-24): the time-window cutover on new writes.
--
-- The clean chain runs this right after 0017. Everything here is about what may be written *after*
-- the cutover: a window key is refused on a new policy snapshot, `WINDOW_CLOSED` is refused on a new
-- wait reason while the other codes still work, and the 0009 predicates keep their historical
-- meaning (`is_roe_policy_v2` still says true for a stored object that carries windows, so
-- `legacy_dispatch_block` cannot reclassify history as v1 and a job may still run on a stored
-- snapshot whose windows are now ignored).
SET search_path = aegis, public;
BEGIN;

DO $$
DECLARE
  camp uuid := '01900000-0000-7000-8000-0000000e1701';
  scope uuid := '01900000-0000-7000-8000-0000000e1702';
  target uuid := '01900000-0000-7000-8000-0000000e1703';
  decision uuid := '01900000-0000-7000-8000-0000000e1704';
  job uuid := '01900000-0000-7000-8000-0000000e1705';
  windowed constant jsonb := '{"max_parallel_jobs":10,"max_duration_hours":24,
    "allowed_windows":[{"days":["mon"],"start":"08:00","end":"18:00","timezone":"Asia/Ho_Chi_Minh"}]}'::jsonb;
  plain constant jsonb := '{"max_parallel_jobs":10,"max_duration_hours":24}'::jsonb;
  rejected int := 0;
  accepted int := 0;
BEGIN
  -- 1. The predicates: the current shape refuses windows, the stored-shape predicate still accepts
  --    them (history must stay classifiable as v2, not fall back to "v1").
  IF NOT aegis.is_roe_policy_v2(windowed) THEN
    RAISE EXCEPTION 'is_roe_policy_v2 no longer recognizes a stored window policy as v2';
  END IF;
  IF aegis.is_roe_policy_v2_current(windowed) THEN
    RAISE EXCEPTION 'is_roe_policy_v2_current accepted allowed_windows';
  END IF;
  IF NOT aegis.is_roe_policy_v2_current(plain) THEN
    RAISE EXCEPTION 'is_roe_policy_v2_current rejected a policy without windows';
  END IF;

  -- 2. A campaign on a current policy, so a job insert has something to point at.
  INSERT INTO policy_snapshot VALUES ('roe-1200', camp, plain, repeat('e1',32),
                                      '{"kind":"operator","id":"cutover-test"}');
  INSERT INTO scope_snapshot VALUES (scope, camp, '{"domains":["cutover.example"]}');
  INSERT INTO campaign (campaign_id,name,objective,current_policy_version,scope_id,created_by)
    VALUES (camp, 'Window cutover', 'Cutover test', 'roe-1200', scope,
            '{"kind":"operator","id":"cutover-test"}');
  INSERT INTO campaign_target VALUES (target, scope, 'domain', 'cutover.example', 'dns:cutover.example');

  -- 3. A new snapshot that still carries a window key is refused.
  BEGIN
    INSERT INTO policy_snapshot VALUES ('roe-1201', camp, windowed, repeat('e2',32),
                                        '{"kind":"operator","id":"cutover-test"}');
    RAISE EXCEPTION 'a new policy_snapshot with allowed_windows was accepted';
  EXCEPTION WHEN check_violation THEN rejected := rejected + 1;
  END;

  -- 4. A new job may run on a current policy, and also on a stored snapshot whose windows are now
  --    ignored (the windowed policy is seeded with the insert guard off: it only exists as history
  --    in an upgraded database).
  INSERT INTO policy_decision (decision_id,campaign_id,capability,provider,targets,input,decision,rationale,requested_by,target_refs,policy_version,scope_id,idempotency_key,trace_id)
    VALUES (decision, camp, 'dns.enumerate_subdomains', 'subfinder', '{dns:cutover.example}',
            '{"targets":["cutover.example"]}', 'approved', 'Cutover job',
            '{"kind":"operator","id":"cutover-test"}',
            jsonb_build_array(jsonb_build_object('seed_id', target),
                              jsonb_build_object('canonical_key', 'dns:cutover.example')),
            'roe-1200', scope, 'cutover:1', repeat('e3',16));
  INSERT INTO scan_job (job_id,campaign_id,decision_id,capability,provider,provider_version,adapter_version,image_digest,manifest_sha256,scan_cycle,job_fingerprint,policy_version,scope_id,input,targets,target_refs,requested_by,rationale,trace_id)
    VALUES (job, camp, decision, 'dns.enumerate_subdomains', 'subfinder', 'v2.17.0', '1.0.0',
            'sha256:'||repeat('a',64), repeat('e4',32), '01900000-0000-7000-8000-0000000e1706',
            repeat('e5',32), 'roe-1200', scope, '{"targets":["cutover.example"]}',
            '{dns:cutover.example}',
            jsonb_build_array(jsonb_build_object('seed_id', target),
                              jsonb_build_object('canonical_key', 'dns:cutover.example')),
            '{"kind":"operator","id":"cutover-test"}', 'Cutover job', repeat('e6',16));
  accepted := accepted + 1;

  -- The seed of a pre-0017 row needs the insert guard off; the campaign FK is deferrable, so its
  -- pending checks are flushed first (DDL is refused while trigger events are pending).
  SET CONSTRAINTS ALL IMMEDIATE;
  ALTER TABLE policy_snapshot DISABLE TRIGGER v2_config_required;
  INSERT INTO policy_snapshot VALUES ('roe-1202', camp, windowed, repeat('e7',32),
                                      '{"kind":"operator","id":"cutover-test"}');
  ALTER TABLE policy_snapshot ENABLE TRIGGER v2_config_required;
  INSERT INTO policy_decision (decision_id,campaign_id,capability,provider,targets,input,decision,rationale,requested_by,target_refs,policy_version,scope_id,idempotency_key,trace_id)
    VALUES ('01900000-0000-7000-8000-0000000e1707', camp, 'dns.resolve', 'dnsx',
            '{dns:cutover.example}', '{"targets":["cutover.example"]}', 'approved',
            'Job on a stored window policy', '{"kind":"operator","id":"cutover-test"}',
            jsonb_build_array(jsonb_build_object('seed_id', target),
                              jsonb_build_object('canonical_key', 'dns:cutover.example')),
            'roe-1202', scope, 'cutover:2', repeat('e8',16));
  INSERT INTO scan_job (job_id,campaign_id,decision_id,capability,provider,provider_version,adapter_version,image_digest,manifest_sha256,scan_cycle,job_fingerprint,policy_version,scope_id,input,targets,target_refs,requested_by,rationale,trace_id)
    VALUES ('01900000-0000-7000-8000-0000000e1708', camp,
            '01900000-0000-7000-8000-0000000e1707', 'dns.resolve', 'dnsx', 'v1.2.2', '1.0.0',
            'sha256:'||repeat('a',64), repeat('e9',32),
            '01900000-0000-7000-8000-0000000e1709', repeat('ea',32), 'roe-1202', scope,
            '{"targets":["cutover.example"]}', '{dns:cutover.example}',
            jsonb_build_array(jsonb_build_object('seed_id', target),
                              jsonb_build_object('canonical_key', 'dns:cutover.example')),
            '{"kind":"operator","id":"cutover-test"}', 'Job on a stored window policy',
            repeat('eb',16));
  accepted := accepted + 1;

  -- 5. `WINDOW_CLOSED` is refused for a new wait reason; a remaining code is still accepted.
  BEGIN
    UPDATE scan_job SET wait_reason = '{"code":"WINDOW_CLOSED","since":"2026-11-24T03:00:00Z"}'::jsonb
     WHERE job_id = job;
    RAISE EXCEPTION 'WINDOW_CLOSED was accepted as a new wait reason';
  EXCEPTION WHEN check_violation THEN rejected := rejected + 1;
  END;
  UPDATE scan_job SET wait_reason = '{"code":"RATE_LIMITED","since":"2026-11-24T03:00:00Z"}'::jsonb
   WHERE job_id = job;
  UPDATE scan_job SET wait_reason = NULL WHERE job_id = job;

  IF accepted <> 2 THEN RAISE EXCEPTION 'the positive controls were not written'; END IF;
  IF rejected <> 2 THEN
    RAISE EXCEPTION 'expected 2 window writes rejected, got %', rejected;
  END IF;
  RAISE NOTICE '0017 drop_time_windows: 2/2 new-write window shapes rejected, jobs accepted on current and stored snapshots, WINDOW_CLOSED gone from new wait reasons';
END $$;

COMMIT;
