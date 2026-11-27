-- OI-6 / OI-8 / OI-9: the values that the contract says are bound to each other, checked in the DDL.
-- Run after 0012 on the clean chain and on the upgrade chain; ROLLBACK leaves the database unchanged.
SET search_path=aegis,public;
BEGIN;
DO $$
DECLARE
  scope_a uuid := '01900000-0000-7000-8000-000000007001';
  scope_a2 uuid := '01900000-0000-7000-8000-000000007003';
  scope_b uuid := '01900000-0000-7000-8000-000000007002';
  camp_a  uuid := '01900000-0000-7000-8000-000000007010';
  camp_b  uuid := '01900000-0000-7000-8000-000000007020';
  seed_a  uuid := '01900000-0000-7000-8000-000000007021';
  seed_b  uuid := '01900000-0000-7000-8000-000000007022';
  sess_a  uuid := '01900000-0000-7000-8000-000000007031';
  sess_b  uuid := '01900000-0000-7000-8000-000000007032';
  dec_ok  uuid := '01900000-0000-7000-8000-000000007041';
  job_ok  uuid := '01900000-0000-7000-8000-000000007051';
  job_free uuid := '01900000-0000-7000-8000-000000007052';
  dec_free uuid := '01900000-0000-7000-8000-000000007048';
  i int;
  blocked int := 0;
  cancel_blocked int := 0;
  out text;
BEGIN
  INSERT INTO policy_snapshot VALUES
    ('roe-18',camp_a,'{"network_profile":"lab","max_parallel_jobs":10,"max_duration_hours":168}',repeat('1',64),'{"kind":"operator","id":"soc-1"}'),
    ('roe-20',camp_a,'{"network_profile":"lab","max_parallel_jobs":5,"max_duration_hours":24}',repeat('3',64),'{"kind":"operator","id":"soc-1"}'),
    ('roe-19',camp_b,'{"network_profile":"lab","max_parallel_jobs":10,"max_duration_hours":168}',repeat('2',64),'{"kind":"operator","id":"soc-1"}');
  INSERT INTO scope_snapshot VALUES
    (scope_a,camp_a,'{"domains":["bind-a.example"]}'),
    (scope_a2,camp_a,'{"domains":["bind-a2.example"]}'),
    (scope_b,camp_b,'{"domains":["bind-b.example"]}');
  INSERT INTO campaign (campaign_id,name,objective,current_policy_version,scope_id,created_by) VALUES
    (camp_a,'Binding A','OI-6/8/9','roe-18',scope_a,'{"kind":"operator","id":"soc-1"}'),
    (camp_b,'Binding B','OI-6/8/9','roe-19',scope_b,'{"kind":"operator","id":"soc-1"}');
  INSERT INTO campaign_target VALUES
    (seed_a,scope_a,'domain','bind-a.example','dns:bind-a.example'),
    (seed_b,scope_b,'domain','bind-b.example','dns:bind-b.example');
  INSERT INTO agent_session (session_id,campaign_id,policy_version,revision_from,status) VALUES
    (sess_a,camp_a,'roe-18',0,'RUNNING'),
    (sess_b,camp_b,'roe-19',0,'RUNNING');

  -- 1. Happy path: session in the same campaign, refs on the decision, job copies them.
  INSERT INTO policy_decision (decision_id,campaign_id,session_id,capability,provider,targets,input,decision,rationale,requested_by,proposed_by,target_refs,policy_version,scope_id,idempotency_key,trace_id)
    VALUES (dec_ok,camp_a,sess_a,'dns.enumerate_subdomains','subfinder','{dns:bind-a.example}','{"targets":["bind-a.example"]}','approved','OI-6/8/9 ok','{"kind":"operator","id":"soc-1"}',
      jsonb_build_object('kind','agent','id',sess_a),
      jsonb_build_array(jsonb_build_object('seed_id',seed_a),jsonb_build_object('canonical_key','dns:bind-a.example')),
      'roe-18',scope_a,'bind:1',repeat('1',32));
  INSERT INTO scan_job (job_id,campaign_id,decision_id,capability,provider,provider_version,adapter_version,image_digest,manifest_sha256,scan_cycle,job_fingerprint,policy_version,scope_id,input,targets,target_refs,requested_by,proposed_by,rationale,trace_id)
    VALUES (job_ok,camp_a,dec_ok,'dns.enumerate_subdomains','subfinder','v2.6.6','1.0.0','sha256:'||repeat('a',64),repeat('b',64),
      '01900000-0000-7000-8000-000000007061',repeat('c1',32),'roe-18',scope_a,'{"targets":["bind-a.example"]}','{dns:bind-a.example}',
      jsonb_build_array(jsonb_build_object('seed_id',seed_a),jsonb_build_object('canonical_key','dns:bind-a.example')),
      '{"kind":"operator","id":"soc-1"}',jsonb_build_object('kind','agent','id',sess_a),'OI-6/8/9 ok',repeat('1',32));
  INSERT INTO policy_decision (SELECT (jsonb_populate_record(NULL::policy_decision, to_jsonb(p) || jsonb_build_object(
      'decision_id',dec_free,'idempotency_key','bind:1b'))).* FROM policy_decision p WHERE decision_id = dec_ok);
  INSERT INTO scan_job (job_id,campaign_id,decision_id,capability,provider,provider_version,adapter_version,image_digest,manifest_sha256,scan_cycle,job_fingerprint,policy_version,scope_id,input,targets,target_refs,requested_by,proposed_by,rationale,trace_id)
    SELECT job_free,campaign_id,dec_free,capability,provider,provider_version,adapter_version,image_digest,manifest_sha256,scan_cycle,repeat('c2',32),
           policy_version,scope_id,input,targets,target_refs,requested_by,proposed_by,rationale,trace_id
      FROM scan_job WHERE job_id = job_ok;
  IF NOT EXISTS (SELECT 1 FROM scan_job WHERE job_id IN (job_ok, job_free)
                  AND requested_by = '{"kind":"operator","id":"soc-1"}'::jsonb
                  AND proposed_by->>'id' = sess_a::text) THEN
    RAISE EXCEPTION 'accepted job lost the decision actors';
  END IF;

  -- 2. OI-8: a proposer is a session of the same campaign, never a label or another campaign's session.
  --    A decision without target_refs is refused by the column's NOT NULL, the rest by their triggers.
  FOR out IN SELECT unnest(ARRAY[
      format('INSERT INTO policy_decision (decision_id,campaign_id,capability,provider,targets,input,decision,rationale,requested_by,proposed_by,target_refs,policy_version,scope_id,idempotency_key,trace_id) VALUES (%L,%L,%L,%L,%L,%L,%L,%L,%L,%L,%L,%L,%L,%L,%L)',
        '01900000-0000-7000-8000-000000007042', camp_a, 'dns.resolve','dnsx','{dns:bind-a.example}','{}','approved','label proposer','{"kind":"operator","id":"soc-1"}','{"kind":"agent","id":"planner"}',
        jsonb_build_array(jsonb_build_object('seed_id',seed_a)),'roe-18',scope_a,'bind:2',repeat('1',32)),
      format('INSERT INTO policy_decision (decision_id,campaign_id,capability,provider,targets,input,decision,rationale,requested_by,proposed_by,target_refs,policy_version,scope_id,idempotency_key,trace_id) VALUES (%L,%L,%L,%L,%L,%L,%L,%L,%L,%L,%L,%L,%L,%L,%L)',
        '01900000-0000-7000-8000-000000007043', camp_a, 'dns.resolve','dnsx','{dns:bind-a.example}','{}','approved','foreign session','{"kind":"operator","id":"soc-1"}',jsonb_build_object('kind','agent','id',sess_b),
        jsonb_build_array(jsonb_build_object('seed_id',seed_a)),'roe-18',scope_a,'bind:3',repeat('1',32)),
      format('INSERT INTO policy_decision (decision_id,campaign_id,capability,provider,targets,input,decision,rationale,requested_by,proposed_by,target_refs,policy_version,scope_id,idempotency_key,trace_id) VALUES (%L,%L,%L,%L,%L,%L,%L,%L,%L,%L,%L,%L,%L,%L,%L)',
        '01900000-0000-7000-8000-000000007044', camp_a, 'dns.resolve','dnsx','{dns:bind-a.example}','{}','approved','missing refs','{"kind":"operator","id":"soc-1"}',NULL,
        NULL,'roe-18',scope_a,'bind:4',repeat('1',32)),
      format('INSERT INTO policy_decision (decision_id,campaign_id,capability,provider,targets,input,decision,rationale,requested_by,target_refs,policy_version,scope_id,idempotency_key,trace_id) VALUES (%L,%L,%L,%L,%L,%L,%L,%L,%L,%L,%L,%L,%L,%L)',
        '01900000-0000-7000-8000-000000007045', camp_a, 'dns.resolve','dnsx','{dns:bind-a.example}','{}','approved','foreign seed','{"kind":"operator","id":"soc-1"}',
        jsonb_build_array(jsonb_build_object('seed_id',seed_b)),'roe-18',scope_a,'bind:5',repeat('1',32)),
      format('INSERT INTO policy_decision (decision_id,campaign_id,capability,provider,targets,input,decision,rationale,requested_by,target_refs,policy_version,scope_id,idempotency_key,trace_id) VALUES (%L,%L,%L,%L,%L,%L,%L,%L,%L,%L,%L,%L,%L,%L)',
        '01900000-0000-7000-8000-000000007046', camp_a, 'dns.resolve','dnsx','{dns:bind-a.example}','{}','approved','unexplained projection','{"kind":"operator","id":"soc-1"}',
        jsonb_build_array(jsonb_build_object('seed_id',seed_a)),'roe-18',scope_a,'bind:6',repeat('1',32))]) LOOP
    BEGIN
      EXECUTE out;
      RAISE EXCEPTION 'not blocked: %', out;
    EXCEPTION
      WHEN check_violation OR foreign_key_violation OR not_null_violation THEN blocked := blocked + 1;
    END;
  END LOOP;

  -- 3. OI-8/R-3: a decision and its job cannot be relabelled, moved between campaigns or made to run
  --    something the decision did not approve (the executed fields are input, capability, provider,
  --    policy_version and scope_id).
  FOR i IN 1 .. 9 LOOP
    BEGIN
      INSERT INTO scan_job (job_id,campaign_id,decision_id,capability,provider,provider_version,adapter_version,image_digest,manifest_sha256,scan_cycle,job_fingerprint,policy_version,scope_id,input,targets,target_refs,requested_by,proposed_by,rationale,trace_id)
      SELECT ('01900000-0000-7000-8000-00000000705' || i)::uuid,
             CASE WHEN i = 3 THEN camp_b ELSE campaign_id END,
             decision_id,
             CASE WHEN i = 6 THEN 'dns.resolve' ELSE capability END,
             CASE WHEN i = 7 THEN 'dnsx' ELSE provider END,
             provider_version,adapter_version,image_digest,manifest_sha256,scan_cycle,
             repeat('d' || i,32),
             CASE WHEN i = 8 THEN 'roe-20' ELSE policy_version END,
             CASE WHEN i = 3 THEN scope_b WHEN i = 9 THEN scope_a2 ELSE scope_id END,
             CASE WHEN i = 5 THEN '{"targets":["bind-a.example"],"recursive":true}'::jsonb ELSE input END,
             targets,
             CASE WHEN i = 1 THEN '{"kind":"module","id":"M26"}'::jsonb ELSE requested_by END,
             CASE WHEN i = 2 THEN NULL ELSE proposed_by END,
             CASE WHEN i = 4 THEN jsonb_build_array(jsonb_build_object('seed_id',seed_a)) ELSE target_refs END,
             rationale,trace_id
        FROM scan_job WHERE job_id = job_ok;
      RAISE EXCEPTION 'a job inconsistent with its decision was accepted (case %)', i;
    EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
    END;
  END LOOP;

  -- 4. OI-6: `targets` is a projection of the refs, not a second identity source.
  BEGIN
    INSERT INTO scan_job (SELECT (jsonb_populate_record(NULL::scan_job, to_jsonb(j) || jsonb_build_object(
        'job_id','01900000-0000-7000-8000-000000007055','job_fingerprint',repeat('e1',32),
        'targets','{dns:not-in-refs.example}'))).* FROM scan_job j WHERE job_id = job_ok);
    RAISE EXCEPTION 'a job target that no TargetRef resolves was accepted';
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;
  BEGIN
    INSERT INTO policy_decision (SELECT (jsonb_populate_record(NULL::policy_decision, to_jsonb(p) || jsonb_build_object(
        'decision_id','01900000-0000-7000-8000-000000007047','idempotency_key','bind:7',
        'targets','{dns:not-in-refs.example}'))).* FROM policy_decision p WHERE decision_id = dec_ok);
    RAISE EXCEPTION 'a decision target that no TargetRef resolves was accepted';
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;

  -- 5. OI-9: the cancel actor is an Actor, and an agent may only cancel its own job.
  BEGIN
    PERFORM aegis.request_job_cancel(job_free, '"anything"'::jsonb, 'junk actor');
    RAISE EXCEPTION 'cancel accepted a non-Actor';
  EXCEPTION WHEN check_violation THEN cancel_blocked := cancel_blocked + 1;
  END;
  BEGIN
    PERFORM aegis.request_job_cancel(job_free, jsonb_build_object('kind','agent','id',sess_b), 'other session');
    RAISE EXCEPTION 'an agent cancelled a job it did not propose';
  EXCEPTION WHEN check_violation THEN cancel_blocked := cancel_blocked + 1;
  END;
  BEGIN
    UPDATE scan_job SET cancel_requested_at = now(), cancel_requested_by = '"junk"'::jsonb WHERE job_id = job_free;
    RAISE EXCEPTION 'a direct cancel write accepted a non-Actor';
  EXCEPTION WHEN check_violation THEN cancel_blocked := cancel_blocked + 1;
  END;
  BEGIN
    UPDATE scan_job SET cancel_requested_at = now(), cancel_requested_by = jsonb_build_object('kind','agent','id',sess_b)
     WHERE job_id = job_free;
    RAISE EXCEPTION 'a direct cancel write let another session cancel the job';
  EXCEPTION WHEN check_violation THEN cancel_blocked := cancel_blocked + 1;
  END;
  out := aegis.request_job_cancel(job_free, jsonb_build_object('kind','agent','id',sess_a), 'own job');
  IF out <> 'requested' THEN RAISE EXCEPTION 'the proposing session could not cancel its own job: %', out; END IF;
  out := aegis.request_job_cancel(job_ok, '{"kind":"operator","id":"soc-1"}', 'operator');
  IF out <> 'requested' THEN RAISE EXCEPTION 'an operator could not cancel: %', out; END IF;
  out := aegis.request_job_cancel(job_ok, '{"kind":"module","id":"M02"}', 'scheduler');
  IF out <> 'already_requested' THEN RAISE EXCEPTION 'cancel intent was not idempotent: %', out; END IF;

  IF blocked <> 16 THEN RAISE EXCEPTION 'OI-6/8: % / 16 binding checks blocked', blocked; END IF;
  IF cancel_blocked <> 4 THEN RAISE EXCEPTION 'OI-9: % / 4 cancel-actor checks blocked', cancel_blocked; END IF;
  RAISE NOTICE 'OI-6/8 decision binding: 16/16 (label/foreign/missing proposer, missing/foreign refs, unexplained projection on decision and job, 9 job-vs-decision relabels incl. input/capability/provider/policy_version/scope) blocked';
  RAISE NOTICE 'OI-9 cancel actor: 4/4 invalid or foreign cancels blocked; proposing session, operator and module cancel accepted, intent idempotent';
END $$;
ROLLBACK;
