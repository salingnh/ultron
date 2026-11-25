-- C05/S1.5a actor attribution: requested_by is the server-derived initiator, proposed_by the agent session.
-- Run after 0010 on the clean chain and on the upgrade chain; ROLLBACK leaves the test database unchanged.
SET search_path=aegis,public;
BEGIN;
DO $$
DECLARE
  scope_a uuid := '01900000-0000-7000-8000-000000000411';
  camp_a  uuid := '01900000-0000-7000-8000-000000000401';
  seed_domain uuid := '01900000-0000-7000-8000-000000000421';
  dec_ok uuid := '01900000-0000-7000-8000-000000000431';
  job_ok uuid := '01900000-0000-7000-8000-000000000441';
  job_direct uuid := '01900000-0000-7000-8000-000000000442';
  dec_agent uuid := '01900000-0000-7000-8000-000000000432';
  dec_proposer uuid := '01900000-0000-7000-8000-000000000433';
  dec_direct uuid := '01900000-0000-7000-8000-000000000434';
  scan uuid := '01900000-0000-7000-8000-000000000491';
  sess uuid := '01900000-0000-7000-8000-0000000004a1';
  blocked int := 0;
BEGIN
  INSERT INTO policy_snapshot VALUES
    ('roe-10',camp_a,'{"network_profile":"lab","max_parallel_jobs":10,"max_duration_hours":168}',repeat('a',64),'{"kind":"operator","id":"soc-1"}');
  INSERT INTO scope_snapshot VALUES
    (scope_a,camp_a,'{"domains":["actor.example"]}');
  INSERT INTO campaign (campaign_id,name,objective,current_policy_version,scope_id,created_by) VALUES
    (camp_a,'Actor attribution','C05 fixture','roe-10',scope_a,'{"kind":"operator","id":"soc-1"}');
  INSERT INTO campaign_target VALUES
    (seed_domain, scope_a,'domain','actor.example','dns:actor.example');
  -- 0012: a proposer must be a real agent session of the same campaign.
  INSERT INTO agent_session (session_id,campaign_id,policy_version,revision_from,status)
    VALUES (sess,camp_a,'roe-10',0,'RUNNING');

  -- 1. Agent-proposed job: initiator is the operator that owns the campaign, proposer is the session.
  INSERT INTO policy_decision (decision_id,campaign_id,session_id,capability,provider,targets,input,decision,rationale,requested_by,proposed_by,target_refs,policy_version,scope_id,idempotency_key,trace_id)
    VALUES (dec_ok,camp_a,sess,'dns.enumerate_subdomains','subfinder','{dns:actor.example}','{"targets":["actor.example"]}','approved','C05 agent-proposed','{"kind":"operator","id":"soc-1"}','{"kind":"agent","id":"01900000-0000-7000-8000-0000000004a1"}','[{"seed_id":"01900000-0000-7000-8000-000000000421"},{"canonical_key":"dns:actor.example"}]','roe-10',scope_a,'c05:1',repeat('a',32));
  INSERT INTO scan_job (job_id,campaign_id,decision_id,capability,provider,provider_version,adapter_version,image_digest,manifest_sha256,scan_cycle,job_fingerprint,policy_version,scope_id,input,targets,target_refs,requested_by,proposed_by,rationale,trace_id)
    VALUES (job_ok,camp_a,dec_ok,'dns.enumerate_subdomains','subfinder','v2.6.6','1.0.0','sha256:'||repeat('5',64),repeat('6',64),scan,repeat('1',64),'roe-10',scope_a,'{"targets":["actor.example"]}','{dns:actor.example}',
      jsonb_build_array(jsonb_build_object('seed_id',seed_domain),jsonb_build_object('canonical_key','dns:actor.example')),'{"kind":"operator","id":"soc-1"}','{"kind":"agent","id":"01900000-0000-7000-8000-0000000004a1"}','C05 agent-proposed',repeat('a',32));

  -- 2. Direct operator submission: a proposer must not be invented.
  INSERT INTO policy_decision (decision_id,campaign_id,capability,provider,targets,input,decision,rationale,requested_by,target_refs,policy_version,scope_id,idempotency_key,trace_id)
    VALUES (dec_direct,camp_a,'dns.enumerate_subdomains','subfinder','{dns:actor.example}','{"targets":["actor.example"]}','approved','C05 direct submit','{"kind":"module","id":"M26"}','[{"seed_id":"01900000-0000-7000-8000-000000000421"},{"canonical_key":"dns:actor.example"}]','roe-10',scope_a,'c05:4',repeat('d',32));
  INSERT INTO scan_job (job_id,campaign_id,decision_id,capability,provider,provider_version,adapter_version,image_digest,manifest_sha256,scan_cycle,job_fingerprint,policy_version,scope_id,input,targets,target_refs,requested_by,rationale,trace_id)
    VALUES (job_direct,camp_a,dec_direct,'dns.enumerate_subdomains','subfinder','v2.6.6','1.0.0','sha256:'||repeat('5',64),repeat('6',64),scan,repeat('2',64),'roe-10',scope_a,'{"targets":["actor.example"]}','{dns:actor.example}',
      jsonb_build_array(jsonb_build_object('seed_id',seed_domain),jsonb_build_object('canonical_key','dns:actor.example')),'{"kind":"module","id":"M26"}','C05 direct submit',repeat('a',32));

  IF NOT EXISTS (SELECT 1 FROM scan_job WHERE job_id=job_ok
                   AND requested_by->>'kind'='operator' AND requested_by->>'id'='soc-1'
                   AND proposed_by->>'kind'='agent' AND proposed_by->>'id'='01900000-0000-7000-8000-0000000004a1') THEN
    RAISE EXCEPTION 'job is not traceable to both its initiator and its proposer';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM scan_job WHERE job_id=job_direct AND proposed_by IS NULL) THEN
    RAISE EXCEPTION 'direct operator submission was given an invented proposer';
  END IF;

  -- 3. An agent cannot be the initiator (the LLM declaring itself never creates attribution).
  BEGIN
    INSERT INTO policy_decision (decision_id,campaign_id,capability,provider,targets,input,decision,rationale,requested_by,proposed_by,target_refs,policy_version,scope_id,idempotency_key,trace_id)
      VALUES (dec_agent,camp_a,'dns.enumerate_subdomains','subfinder','{dns:actor.example}','{"targets":["actor.example"]}','approved','C05 self-declared','{"kind":"agent","id":"01900000-0000-7000-8000-0000000004a1"}','{"kind":"agent","id":"01900000-0000-7000-8000-0000000004a1"}','[{"seed_id":"01900000-0000-7000-8000-000000000421"}]','roe-10',scope_a,'c05:2',repeat('b',32));
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;
  BEGIN
    INSERT INTO scan_job (SELECT (jsonb_populate_record(NULL::scan_job, to_jsonb(j) || jsonb_build_object(
        'job_id','01900000-0000-7000-8000-000000000443','decision_id',dec_agent,
        'job_fingerprint',repeat('3',64),'requested_by','{"kind":"agent","id":"01900000-0000-7000-8000-0000000004a1"}'::jsonb))).* FROM scan_job j WHERE job_id=job_ok);
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;

  -- 4. A proposer is an agent session; an operator or module there is a role error.
  BEGIN
    INSERT INTO policy_decision (decision_id,campaign_id,capability,provider,targets,input,decision,rationale,requested_by,proposed_by,target_refs,policy_version,scope_id,idempotency_key,trace_id)
      VALUES (dec_proposer,camp_a,'dns.enumerate_subdomains','subfinder','{dns:actor.example}','{"targets":["actor.example"]}','approved','C05 wrong proposer','{"kind":"operator","id":"soc-1"}','{"kind":"module","id":"M26"}','[{"seed_id":"01900000-0000-7000-8000-000000000421"}]','roe-10',scope_a,'c05:3',repeat('c',32));
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;
  BEGIN
    INSERT INTO scan_job (SELECT (jsonb_populate_record(NULL::scan_job, to_jsonb(j) || jsonb_build_object(
        'job_id','01900000-0000-7000-8000-000000000444','decision_id',dec_ok,
        'job_fingerprint',repeat('4',64),'proposed_by','{"kind":"operator","id":"soc-1"}'::jsonb))).* FROM scan_job j WHERE job_id=job_ok);
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;

  -- 5. Actors are immutable: attribution cannot be rewritten after acceptance.
  BEGIN
    UPDATE scan_job SET proposed_by='{"kind":"agent","id":"other"}' WHERE job_id=job_ok;
    RAISE EXCEPTION 'proposer was rewritable after acceptance';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    UPDATE scan_job SET requested_by='{"kind":"module","id":"M02"}' WHERE job_id=job_ok;
    RAISE EXCEPTION 'initiator was rewritable after acceptance';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  -- 6. Shape errors: extra keys, blank id, and the pre-0010 self-declared actor for a new row.
  BEGIN
    INSERT INTO scan_job (SELECT (jsonb_populate_record(NULL::scan_job, to_jsonb(j) || jsonb_build_object(
        'job_id','01900000-0000-7000-8000-000000000445','decision_id',dec_ok,
        'job_fingerprint',repeat('5',64),'requested_by','{"kind":"operator","id":"soc-1","name":"SOC"}'::jsonb))).* FROM scan_job j WHERE job_id=job_ok);
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;
  BEGIN
    INSERT INTO scan_job (SELECT (jsonb_populate_record(NULL::scan_job, to_jsonb(j) || jsonb_build_object(
        'job_id','01900000-0000-7000-8000-000000000446','decision_id',dec_ok,
        'job_fingerprint',repeat('6',64),'proposed_by','{"kind":"agent","id":"  "}'::jsonb))).* FROM scan_job j WHERE job_id=job_ok);
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;

  IF blocked <> 6 THEN
    RAISE EXCEPTION 'C05 actor rule: chỉ % / 6 kiểm tra bị chặn', blocked;
  END IF;
  RAISE NOTICE 'C05 actors: 6/6 bị chặn, initiator+proposer truy được, actor bất biến sau khi nhận';
END $$;
ROLLBACK;
