-- roe-policy.v2 shape: one function, one closed key set (no RoE time windows).
--
-- The contract dropped `allowed_windows`/`blackout_windows` (owner decision 2026-11-24) and the
-- schema has one baseline migration, so this is not a cutover test: a window key is simply not part
-- of a snapshot, and `WINDOW_CLOSED` is not part of a wait reason. Everything is rolled back.
SET search_path = aegis, public;
BEGIN;
DO $$
DECLARE
  camp uuid := '01900000-0000-7000-8000-0000000e1701';
  scope uuid := '01900000-0000-7000-8000-0000000e1702';
  target uuid := '01900000-0000-7000-8000-0000000e1703';
  decision uuid := '01900000-0000-7000-8000-0000000e1704';
  job uuid := '01900000-0000-7000-8000-0000000e1705';
  plain constant jsonb := '{"network_profile":"lab","max_parallel_jobs":10,"max_duration_hours":24}'::jsonb;
  auth constant jsonb := '{"owner":"owner","reference":"owner, item 61, 2026-11-25","date":"2026-11-25","authorized_suffixes":["icomm.vn"]}'::jsonb;
  windowed constant jsonb := '{"network_profile":"lab","max_parallel_jobs":10,"max_duration_hours":24,
    "allowed_windows":[{"days":["mon"],"start":"08:00","end":"18:00","timezone":"Asia/Ho_Chi_Minh"}]}'::jsonb;
  rejected int := 0;
BEGIN
  -- 1. The window keys are not in the shape: a policy that carries one is not v2.
  IF aegis.is_roe_policy_v2(windowed) THEN
    RAISE EXCEPTION 'is_roe_policy_v2 accepted allowed_windows';
  END IF;
  IF aegis.is_roe_policy_v2(plain || '{"blackout_windows":[]}'::jsonb) THEN
    RAISE EXCEPTION 'is_roe_policy_v2 accepted blackout_windows';
  END IF;
  IF NOT aegis.is_roe_policy_v2(plain) THEN
    RAISE EXCEPTION 'is_roe_policy_v2 rejected a policy without windows';
  END IF;

  -- 1b. The network profile is a closed enum and the internet per-host connection cap is an int
  --     in range; a snapshot that carries either in the wrong shape is not v2 configuration.
  IF aegis.is_roe_policy_v2(plain || jsonb_build_object('network_profile','internet',
                                                          'authorization', auth)) IS NOT TRUE
     OR aegis.is_roe_policy_v2(plain) IS NOT TRUE THEN
    RAISE EXCEPTION 'is_roe_policy_v2 rejected a valid network_profile';
  END IF;
  IF aegis.is_roe_policy_v2(plain || '{"network_profile":"dmz"}'::jsonb)
     OR aegis.is_roe_policy_v2(plain || '{"network_profile":1}'::jsonb) THEN
    RAISE EXCEPTION 'is_roe_policy_v2 accepted an unknown network_profile';
  END IF;

  -- 1c. Internet is the default profile, so an internet campaign needs a structured
  --     authorization; a lab campaign does not. The object shape is closed.
  IF aegis.is_roe_policy_v2(plain || '{"network_profile":"internet"}'::jsonb) THEN
    RAISE EXCEPTION 'is_roe_policy_v2 accepted internet without authorization';
  END IF;
  IF NOT aegis.is_roe_policy_v2(plain || jsonb_build_object('network_profile','internet',
                                                             'authorization', auth)) THEN
    RAISE EXCEPTION 'is_roe_policy_v2 rejected a valid internet authorization';
  END IF;
  IF aegis.is_roe_policy_v2(plain || jsonb_build_object('network_profile','internet',
        'authorization', auth - 'owner'))
     OR aegis.is_roe_policy_v2(plain || jsonb_build_object('network_profile','internet',
        'authorization', jsonb_set(auth, '{date}', '"25/11/2026"'::jsonb)))
     OR aegis.is_roe_policy_v2(plain || jsonb_build_object('network_profile','internet',
        'authorization', jsonb_set(auth, '{authorized_suffixes}', '[]'::jsonb)))
     OR aegis.is_roe_policy_v2(plain || '{"network_profile":"internet","authorization":{"owner":"o","reference":"r1","date":"2026-11-25","authorized_suffixes":["x.test"],"extra":1}}'::jsonb) THEN
    RAISE EXCEPTION 'is_roe_policy_v2 accepted a broken authorization';
  END IF;
  IF aegis.is_roe_policy_v2(plain ||
       '{"rate_limits":{"max_concurrent_connections_per_host":1}}'::jsonb) IS NOT TRUE
     OR aegis.is_roe_policy_v2(plain ||
       '{"rate_limits":{"max_concurrent_connections_per_host":0}}'::jsonb) THEN
    RAISE EXCEPTION 'is_roe_policy_v2 mis-validated max_concurrent_connections_per_host';
  END IF;

  INSERT INTO policy_snapshot VALUES ('roe-1200', camp, plain, repeat('e1',32),
                                      '{"kind":"operator","id":"shape-test"}');
  INSERT INTO scope_snapshot VALUES (scope, camp, '{"domains":["shape.example"]}');
  INSERT INTO campaign (campaign_id,name,objective,current_policy_version,scope_id,created_by)
    VALUES (camp, 'Policy shape', 'Shape test', 'roe-1200', scope,
            '{"kind":"operator","id":"shape-test"}');
  INSERT INTO campaign_target VALUES (target, scope, 'domain', 'shape.example', 'dns:shape.example');

  -- 2. A snapshot that carries a window key is refused by the insert guard.
  BEGIN
    INSERT INTO policy_snapshot VALUES ('roe-1201', camp, windowed, repeat('e2',32),
                                        '{"kind":"operator","id":"shape-test"}');
    RAISE EXCEPTION 'a policy_snapshot with allowed_windows was accepted';
  EXCEPTION WHEN check_violation THEN rejected := rejected + 1;
  END;

  -- 3. A job on the current policy is accepted, so the rest of the row rules still work.
  INSERT INTO policy_decision (decision_id,campaign_id,capability,provider,targets,input,decision,rationale,requested_by,target_refs,policy_version,scope_id,idempotency_key,trace_id)
    VALUES (decision, camp, 'dns.enumerate_subdomains', 'subfinder', '{dns:shape.example}',
            '{"targets":["shape.example"]}', 'approved', 'Shape job',
            '{"kind":"operator","id":"shape-test"}',
            jsonb_build_array(jsonb_build_object('seed_id', target),
                              jsonb_build_object('canonical_key', 'dns:shape.example')),
            'roe-1200', scope, 'shape:1', repeat('e3',16));
  INSERT INTO scan_job (job_id,campaign_id,decision_id,capability,provider,provider_version,adapter_version,image_digest,manifest_sha256,scan_cycle,job_fingerprint,policy_version,scope_id,input,targets,target_refs,requested_by,rationale,trace_id)
    VALUES (job, camp, decision, 'dns.enumerate_subdomains', 'subfinder', 'v2.17.0', '1.0.0',
            'sha256:'||repeat('a',64), repeat('e4',32), '01900000-0000-7000-8000-0000000e1706',
            repeat('e5',32), 'roe-1200', scope, '{"targets":["shape.example"]}',
            '{dns:shape.example}',
            jsonb_build_array(jsonb_build_object('seed_id', target),
                              jsonb_build_object('canonical_key', 'dns:shape.example')),
            '{"kind":"operator","id":"shape-test"}', 'Shape job', repeat('e6',16));

  -- 4. `WINDOW_CLOSED` is not a wait reason any more; a remaining code is still accepted.
  BEGIN
    UPDATE scan_job SET wait_reason = '{"code":"WINDOW_CLOSED","since":"2026-11-24T03:00:00Z"}'::jsonb
     WHERE job_id = job;
    RAISE EXCEPTION 'WINDOW_CLOSED was accepted as a wait reason';
  EXCEPTION WHEN check_violation THEN rejected := rejected + 1;
  END;
  UPDATE scan_job SET wait_reason = '{"code":"RATE_LIMITED","since":"2026-11-24T03:00:00Z"}'::jsonb
   WHERE job_id = job;
  UPDATE scan_job SET wait_reason = NULL WHERE job_id = job;

  IF rejected <> 2 THEN
    RAISE EXCEPTION 'expected 2 window shapes rejected, got %', rejected;
  END IF;
  RAISE NOTICE 'roe-policy.v2 shape: no window keys, 2/2 window writes rejected, WINDOW_CLOSED gone from wait reasons';
END $$;
ROLLBACK;
