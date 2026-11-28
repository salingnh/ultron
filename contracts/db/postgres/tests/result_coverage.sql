-- 0009_result_coverage.sql: the accepted envelope's coverage is stored with the result, and its
-- shape is enforced by the column itself.
--
-- The column is what M02 reads to decide whether a completed campaign may claim `objective_met`:
-- a job whose current result says `complete = false` could not conclude its surface. Writing it in
-- the same INSERT that claims the dedup key keeps the row append-only (the `cols_only` trigger
-- still refuses every later value change), and the join on `scan_job.envelope_event_id` keeps a
-- superseded result out of the verdict. Everything is rolled back.
SET search_path = aegis, public;
BEGIN;
DO $$
DECLARE
  scope uuid := '01900000-0000-7000-8000-000000090001';
  camp  uuid := '01900000-0000-7000-8000-000000090002';
  seed  uuid := '01900000-0000-7000-8000-000000090003';
  job   uuid := '01900000-0000-7000-8000-000000090004';
  first uuid := '01900000-0000-7000-8000-000000090005';
  second uuid := '01900000-0000-7000-8000-000000090006';
  refused int := 0;
  complete_value text;
  incomplete int;
BEGIN
  INSERT INTO policy_snapshot
    VALUES ('roe-9', camp, '{"network_profile":"lab","max_parallel_jobs":10,"max_duration_hours":168}',
            repeat('6', 64), '{"kind":"operator","id":"fixture"}');
  INSERT INTO scope_snapshot VALUES (scope, camp, '{"domains":["coverage.example"]}');
  INSERT INTO campaign (campaign_id, name, objective, current_policy_version, scope_id, created_by)
    VALUES (camp, 'Result coverage', '0009 fixture', 'roe-9', scope,
            '{"kind":"operator","id":"fixture"}');
  INSERT INTO campaign_target VALUES (seed, scope, 'domain', 'coverage.example',
                                      'dns:coverage.example');
  INSERT INTO policy_decision (decision_id, campaign_id, capability, provider, targets, input,
                               decision, rationale, requested_by, target_refs, policy_version,
                               scope_id, idempotency_key, trace_id)
    VALUES ('01900000-0000-7000-8000-000000090007', camp, 'dns.enumerate_subdomains', 'subfinder',
            '{dns:coverage.example}', '{"targets":["coverage.example"]}', 'approved',
            '0009 job', '{"kind":"operator","id":"fixture"}',
            jsonb_build_array(jsonb_build_object('seed_id', seed),
                              jsonb_build_object('canonical_key', 'dns:coverage.example')),
            'roe-9', scope, '0009:1', repeat('6', 32));
  INSERT INTO scan_job (job_id, campaign_id, decision_id, capability, provider, provider_version,
                        adapter_version, image_digest, manifest_sha256, scan_cycle, job_fingerprint,
                        policy_version, scope_id, input, targets, target_refs, requested_by,
                        rationale, trace_id)
    VALUES (job, camp, '01900000-0000-7000-8000-000000090007', 'dns.enumerate_subdomains',
            'subfinder', 'v2.17.0', '1.0.2', 'sha256:' || repeat('5', 64), repeat('6', 64),
            '01900000-0000-7000-8000-000000090008', repeat('7', 64), 'roe-9', scope,
            '{"targets":["coverage.example"]}', '{dns:coverage.example}',
            jsonb_build_array(jsonb_build_object('seed_id', seed),
                              jsonb_build_object('canonical_key', 'dns:coverage.example')),
            '{"kind":"operator","id":"fixture"}', '0009 job', repeat('6', 32));

  -- 1. An incomplete result is stored with the envelope that produced it: complete = false and
  --    the port-level limitation M06 writes for a paced probe.
  INSERT INTO ingestion_inbox
    (event_id, dedup_key, job_id, payload_hash, hash_version, coverage, status)
    VALUES (first, 'job:' || job || ':envelope', job, repeat('a', 64), 'aegis-c14n/1',
            '{"subjects":["ip:192.0.2.10"],"complete":false,'
            '"limitations":[{"code":"EGRESS_PACED","message":"unprobed, not closed",'
            '"subjects":["ip:192.0.2.10"]}]}'::jsonb, 'received');
  SELECT coverage->>'complete' INTO complete_value FROM ingestion_inbox WHERE event_id = first;
  IF complete_value IS DISTINCT FROM 'false' THEN
    RAISE EXCEPTION 'the stored coverage lost its complete flag (%)', complete_value;
  END IF;

  -- 2. NULL is the not-yet-decided state (and every pre-0009 row) and stays valid.
  INSERT INTO ingestion_inbox
    (event_id, dedup_key, job_id, payload_hash, hash_version, coverage, status)
    VALUES ('01900000-0000-7000-8000-000000090009', 'job:' || job || ':envelope:null', job,
            repeat('c', 64), 'aegis-c14n/1', NULL, 'received');

  -- 3. Four malformed documents, each refused by the column's check.
  BEGIN
    INSERT INTO ingestion_inbox
      (event_id, dedup_key, job_id, payload_hash, hash_version, coverage, status)
      VALUES ('01900000-0000-7000-8000-000000090010', 'job:' || job || ':bad:1', job,
              repeat('d', 64), 'aegis-c14n/1', '[]'::jsonb, 'received');
  EXCEPTION WHEN check_violation THEN refused := refused + 1;
  END;
  BEGIN
    INSERT INTO ingestion_inbox
      (event_id, dedup_key, job_id, payload_hash, hash_version, coverage, status)
      VALUES ('01900000-0000-7000-8000-000000090011', 'job:' || job || ':bad:2', job,
              repeat('e', 64), 'aegis-c14n/1', '{"complete":true}'::jsonb, 'received');
  EXCEPTION WHEN check_violation THEN refused := refused + 1;
  END;
  BEGIN
    INSERT INTO ingestion_inbox
      (event_id, dedup_key, job_id, payload_hash, hash_version, coverage, status)
      VALUES ('01900000-0000-7000-8000-000000090012', 'job:' || job || ':bad:3', job,
              repeat('f', 64), 'aegis-c14n/1',
              '{"subjects":["ip:192.0.2.10"],"complete":"yes"}'::jsonb, 'received');
  EXCEPTION WHEN check_violation THEN refused := refused + 1;
  END;
  BEGIN
    INSERT INTO ingestion_inbox
      (event_id, dedup_key, job_id, payload_hash, hash_version, coverage, status)
      VALUES ('01900000-0000-7000-8000-000000090013', 'job:' || job || ':bad:4', job,
              repeat('1', 64), 'aegis-c14n/1',
              '{"subjects":["ip:192.0.2.10"],"complete":false,"limitations":{}}'::jsonb,
              'received');
  EXCEPTION WHEN check_violation THEN refused := refused + 1;
  END;
  IF refused <> 4 THEN
    RAISE EXCEPTION 'the coverage shape accepted % of 4 malformed documents', 4 - refused;
  END IF;

  -- 4. The row is append-only: once written, coverage cannot be changed (the 0001 cols_only
  --    trigger keeps its allow-list, so a later silent rewrite is impossible).
  BEGIN
    UPDATE ingestion_inbox SET coverage = '{"subjects":[],"complete":true}'::jsonb
     WHERE event_id = first;
  EXCEPTION WHEN insufficient_privilege THEN refused := refused + 1;
  END;
  IF refused <> 5 THEN
    RAISE EXCEPTION 'a later coverage rewrite was accepted';
  END IF;

  -- 5. The campaign verdict reads only the job's *current* result: a re-run's new envelope that
  --    says complete hides the superseded incomplete one, without a timestamp race.
  INSERT INTO ingestion_inbox
    (event_id, dedup_key, job_id, payload_hash, hash_version, coverage, status)
    VALUES (second, 'job:' || job || ':envelope:2', job, repeat('b', 64), 'aegis-c14n/1',
            '{"subjects":["ip:192.0.2.10"],"complete":true}'::jsonb, 'received');
  UPDATE scan_job SET envelope_event_id = second WHERE job_id = job;

  SELECT count(*) INTO incomplete
    FROM scan_job j
    JOIN ingestion_inbox i ON i.event_id = j.envelope_event_id
   WHERE j.campaign_id = camp AND i.coverage->>'complete' = 'false';
  IF incomplete <> 0 THEN
    RAISE EXCEPTION 'a superseded incomplete result still counts (% job(s))', incomplete;
  END IF;

  UPDATE scan_job SET envelope_event_id = first WHERE job_id = job;
  SELECT count(*) INTO incomplete
    FROM scan_job j
    JOIN ingestion_inbox i ON i.event_id = j.envelope_event_id
   WHERE j.campaign_id = camp AND i.coverage->>'complete' = 'false';
  IF incomplete <> 1 THEN
    RAISE EXCEPTION 'the current incomplete result was not counted (% job(s))', incomplete;
  END IF;

  RAISE NOTICE 'result coverage: shape enforced, write-once, superseded results excluded';
END $$;
ROLLBACK;
