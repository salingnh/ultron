-- 0014_verification_run.sql: the M21 decision row is append-only, one per job, and cannot store
-- a run the owner decision forbids (L1/C1 outside the lab, VERIFIED without both negative controls
-- and the transition it wrote, more requests than the registry cap).
--
-- Everything is rolled back: the fixture only proves the constraints.
SET search_path = aegis, public;
BEGIN;
DO $$
DECLARE
  scope  uuid := '01900000-0000-7000-8000-000000400001';
  camp   uuid := '01900000-0000-7000-8000-000000400002';
  seed   uuid := '01900000-0000-7000-8000-000000400003';
  asset  uuid := '01900000-0000-7000-8000-000000400005';
  find   uuid := '01900000-0000-7000-8000-000000400006';
  ev_pos uuid := '01900000-0000-7000-8000-000000400007';
  ev_a   uuid := '01900000-0000-7000-8000-000000400008';
  ev_b   uuid := '01900000-0000-7000-8000-000000400009';
  run_id uuid := '01900000-0000-7000-8000-00000040000a';
  other  uuid := '01900000-0000-7000-8000-00000040000b';
  job1   uuid := '01900000-0000-7000-8000-000000400101';
  job2   uuid := '01900000-0000-7000-8000-000000400102';
  job3   uuid := '01900000-0000-7000-8000-000000400103';
  job4   uuid := '01900000-0000-7000-8000-000000400104';
  target jsonb := '{"asset_id": "01900000-0000-7000-8000-000000400005",
                    "canonical_key": "service:10.114.60.31:80/tcp",
                    "address": "10.114.60.31", "port": 80}'::jsonb;
  controls jsonb := '[{"role": "patched_twin", "address": "10.114.60.32", "port": 80,
                       "asset_id": null},
                      {"role": "benign", "address": "10.114.60.31", "port": 80,
                       "asset_id": null}]'::jsonb;
  matched jsonb := '{"positive": true, "control_a": false, "control_b": false,
                     "discriminating": true, "reason": "0014 fixture"}'::jsonb;
  refused int := 0;
BEGIN
  INSERT INTO policy_snapshot
    VALUES ('roe-14', camp, '{"network_profile":"lab","max_parallel_jobs":10,"max_duration_hours":168}',
            repeat('7', 64), '{"kind":"operator","id":"fixture"}');
  INSERT INTO scope_snapshot VALUES (scope, camp, '{"domains":["verify.example"]}');
  INSERT INTO campaign (campaign_id, name, objective, current_policy_version, scope_id, created_by)
    VALUES (camp, 'Verification run', '0014 fixture', 'roe-14', scope,
            '{"kind":"operator","id":"fixture"}');
  INSERT INTO campaign_target VALUES (seed, scope, 'ip', '10.114.60.31', 'ip:10.114.60.31');
  INSERT INTO asset (asset_id, canonical_key, kind, first_seen, last_seen, normalization_version)
    VALUES (asset, 'service:10.114.60.31:80/tcp', 'service', now(), now(), 'aegis-norm/1');
  INSERT INTO policy_decision (decision_id, campaign_id, capability, provider, targets, input,
                               decision, rationale, requested_by, target_refs, policy_version,
                               scope_id, idempotency_key, trace_id)
    SELECT ('01900000-0000-7000-8000-0000004002' || lpad(i::text, 2, '0'))::uuid, camp,
           'verify.check', 'nuclei-verify', '{service:10.114.60.31:80/tcp}',
           '{"check_id":"cve-2021-41773-traversal"}', 'approved', '0014 job',
           '{"kind":"operator","id":"fixture"}',
           jsonb_build_array(jsonb_build_object('seed_id', seed),
                             jsonb_build_object('canonical_key', 'service:10.114.60.31:80/tcp')),
           'roe-14', scope, '0014:' || i, repeat('7', 32)
      FROM generate_series(1, 4) AS series(i);
  INSERT INTO scan_job (job_id, campaign_id, decision_id, capability, provider, provider_version,
                        adapter_version, image_digest, manifest_sha256, scan_cycle, job_fingerprint,
                        policy_version, scope_id, input, targets, target_refs, requested_by,
                        rationale, trace_id, status, started_at, finished_at)
    SELECT ('01900000-0000-7000-8000-0000004001' || lpad(i::text, 2, '0'))::uuid, camp,
           ('01900000-0000-7000-8000-0000004002' || lpad(i::text, 2, '0'))::uuid, 'verify.check',
           'nuclei-verify', 'v3.11.1', '1.0.0', 'sha256:' || repeat('5', 64), repeat('7', 64),
           '01900000-0000-7000-8000-00000040000d', repeat(lpad(i::text, 2, '0'), 32), 'roe-14', scope,
           '{"check_id":"cve-2021-41773-traversal"}', '{service:10.114.60.31:80/tcp}',
           jsonb_build_array(jsonb_build_object('seed_id', seed),
                             jsonb_build_object('canonical_key', 'service:10.114.60.31:80/tcp')),
           '{"kind":"operator","id":"fixture"}', '0014 job', repeat('8', 32), 'SUCCEEDED',
           now(), now()
      FROM generate_series(1, 4) AS series(i);
  INSERT INTO finding (finding_id, fingerprint, asset_id, rule_id, category, title,
                       vulnerability_ids, status, first_seen, last_seen, first_job_id,
                       first_campaign_id)
    VALUES (find, repeat('b', 64), asset, 'cve:CVE-2021-41773', 'vulnerability', '0014 fixture',
            '{CVE-2021-41773}', 'CANDIDATE', now(), now(), job1, camp);
  INSERT INTO evidence (evidence_id, sha256, storage_uri, campaign_id, job_id, size_bytes,
                        media_type, classification, source_tool, verified_at)
    VALUES (ev_pos, repeat('1', 64), 's3://evidence/0014/positive', camp, job1, 10,
            'application/json', 'INTERNAL', 'nuclei-verify', now()),
           (ev_a, repeat('2', 64), 's3://evidence/0014/twin', camp, job1, 10,
            'application/json', 'INTERNAL', 'nuclei-verify', now()),
           (ev_b, repeat('3', 64), 's3://evidence/0014/benign', camp, job1, 10,
            'application/json', 'INTERNAL', 'nuclei-verify', now());

  -- 1. A VERIFIED lab run with both controls' evidence and the transition it wrote is accepted.
  INSERT INTO verification_run (verification_id, finding_id, campaign_id, job_id, check_id,
                                check_class, network_profile, check_pack_sha256, outcome,
                                requests_sent, request_cap, target_ref, controls, canary_sha256,
                                positive_evidence_id, control_a_evidence_id, control_b_evidence_id,
                                matched, requested_by, transition_seq, started_at, finished_at)
    VALUES (run_id, find, camp, job1, 'cve-2021-41773-traversal', 'L1', 'lab', repeat('9', 64),
            'VERIFIED', 4, 4, target, controls, repeat('4', 64), ev_pos, ev_a, ev_b, matched,
            '{"kind":"operator","id":"fixture"}', 2, now(), now());

  -- 2. One row per job: a replay of the same job is a duplicate, not a second decision.
  BEGIN
    INSERT INTO verification_run (verification_id, finding_id, campaign_id, job_id, check_id,
                                  check_class, network_profile, check_pack_sha256, outcome,
                                  requests_sent, request_cap, target_ref, controls, matched,
                                  requested_by, started_at, finished_at)
      VALUES (other, find, camp, job1, 'cve-2021-41773-traversal', 'L1', 'lab', repeat('9', 64),
              'INCONCLUSIVE', 0, 4, target, controls, matched,
              '{"kind":"operator","id":"fixture"}', now(), now());
  EXCEPTION WHEN unique_violation THEN refused := refused + 1;
  END;

  -- 3. VERIFIED without a control's evidence, or without the transition, is refused.
  BEGIN
    INSERT INTO verification_run (verification_id, finding_id, campaign_id, job_id, check_id,
                                  check_class, network_profile, check_pack_sha256, outcome,
                                  requests_sent, request_cap, target_ref, controls, matched,
                                  requested_by, transition_seq, started_at, finished_at)
      VALUES (other, find, camp, job2, 'cve-2021-41773-traversal', 'L1', 'lab',
              repeat('9', 64), 'VERIFIED', 4, 4, target, controls, matched,
              '{"kind":"operator","id":"fixture"}', 2, now(), now());
  EXCEPTION WHEN check_violation THEN refused := refused + 1;
  END;

  -- 4. An L1/C1 check on the internet profile cannot exist (the internet pack has no L1).
  BEGIN
    INSERT INTO verification_run (verification_id, finding_id, campaign_id, job_id, check_id,
                                  check_class, network_profile, check_pack_sha256, outcome,
                                  requests_sent, request_cap, target_ref, controls, canary_sha256,
                                  positive_evidence_id, control_a_evidence_id,
                                  control_b_evidence_id, matched, requested_by, transition_seq,
                                  started_at, finished_at)
      VALUES (other, find, camp, job3, 'cve-2021-41773-traversal', 'L1', 'internet',
              repeat('9', 64), 'VERIFIED', 4, 4, target, controls, repeat('4', 64), ev_pos, ev_a,
              ev_b, matched, '{"kind":"operator","id":"fixture"}', 2, now(), now());
  EXCEPTION WHEN check_violation THEN refused := refused + 1;
  END;

  -- 5. OBSERVED is internet-only and changes no status, so it needs no control evidence.
  INSERT INTO verification_run (verification_id, finding_id, campaign_id, job_id, check_id,
                                check_class, network_profile, check_pack_sha256, outcome,
                                requests_sent, request_cap, target_ref, controls,
                                positive_evidence_id, matched, requested_by, started_at,
                                finished_at)
    VALUES (other, find, camp, job4, 'config.tls.certificate', 'E1', 'internet',
            repeat('9', 64), 'OBSERVED', 1, 3, target, '[]'::jsonb, ev_pos, matched,
            '{"kind":"operator","id":"fixture"}', now(), now());

  -- 6. More requests than the registry cap is refused.
  BEGIN
    INSERT INTO verification_run (verification_id, finding_id, campaign_id, job_id, check_id,
                                  check_class, network_profile, check_pack_sha256, outcome,
                                  requests_sent, request_cap, target_ref, controls, matched,
                                  requested_by, started_at, finished_at)
      VALUES (gen_random_uuid(), find, camp, job2, 'cve-2021-41773-traversal', 'L1', 'lab',
              repeat('9', 64), 'INCONCLUSIVE', 5, 4, target, controls, matched,
              '{"kind":"operator","id":"fixture"}', now(), now());
  EXCEPTION WHEN check_violation THEN refused := refused + 1;
  END;

  -- 7. Append-only: the decision row cannot be updated or deleted.
  BEGIN
    UPDATE verification_run SET outcome = 'VERIFIED' WHERE verification_id = run_id;
  EXCEPTION WHEN insufficient_privilege THEN refused := refused + 1;
  END;
  BEGIN
    DELETE FROM verification_run WHERE verification_id = run_id;
  EXCEPTION WHEN insufficient_privilege THEN refused := refused + 1;
  END;

  IF refused <> 6 THEN
    RAISE EXCEPTION 'verification_run constraints: expected 6 refusals, got %', refused;
  END IF;
  SELECT count(*) INTO refused FROM verification_run;
  IF refused <> 2 THEN
    RAISE EXCEPTION 'verification_run should hold the two accepted runs, found %', refused;
  END IF;
  RAISE NOTICE '0014 verification_run: OK';
END $$;
ROLLBACK;
