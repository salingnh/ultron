-- Historical input for the 0011 upgrade test only. Not an active contract, not execution configuration.
-- Apply after 0009 and before 0010: these rows were accepted by 0009 (v2 configuration, manifest pin,
-- TargetRefs) with a self-declared agent actor, which 0010's INSERT-only rule no longer accepts. The
-- defect this fixture reproduces is gate-review probe P1: without LEGACY_ACTOR such a row was
-- dispatchable, although 0010 and 04 say a pre-0010 row is never dispatched or replayed.
SET search_path = aegis, public;
BEGIN;

INSERT INTO policy_snapshot VALUES
  ('roe-170', '01900000-0000-7000-8000-0000000d1710',
   '{"max_parallel_jobs":10,"max_duration_hours":168}', repeat('7',64),
   '{"kind":"operator","id":"soc-legacy"}');
INSERT INTO scope_snapshot VALUES
  ('01900000-0000-7000-8000-0000000d1711', '01900000-0000-7000-8000-0000000d1710',
   '{"domains":["agent-actor.example"]}');
INSERT INTO campaign (campaign_id,name,objective,current_policy_version,scope_id,created_by) VALUES
  ('01900000-0000-7000-8000-0000000d1710','Post-0009 agent actor','P1 fixture','roe-170',
   '01900000-0000-7000-8000-0000000d1711','{"kind":"operator","id":"soc-legacy"}');
INSERT INTO campaign_target VALUES
  ('01900000-0000-7000-8000-0000000d1721','01900000-0000-7000-8000-0000000d1711',
   'domain','agent-actor.example','dns:agent-actor.example');

INSERT INTO policy_decision (decision_id,campaign_id,capability,provider,targets,input,decision,rationale,requested_by,policy_version,scope_id,idempotency_key,trace_id) VALUES
  ('01900000-0000-7000-8000-0000000d1731','01900000-0000-7000-8000-0000000d1710','dns.enumerate_subdomains','subfinder','{dns:agent-actor.example}','{"targets":["agent-actor.example"]}','approved','Post-0009 agent actor, queued','{"kind":"agent","id":"legacy-session"}','roe-170','01900000-0000-7000-8000-0000000d1711','s1f:1',repeat('7',32)),
  ('01900000-0000-7000-8000-0000000d1732','01900000-0000-7000-8000-0000000d1710','dns.resolve','dnsx','{dns:agent-actor.example}','{"targets":["agent-actor.example"]}','approved','Post-0009 agent actor, finished','{"kind":"agent","id":"legacy-session"}','roe-170','01900000-0000-7000-8000-0000000d1711','s1f:2',repeat('7',32));

-- The queued one must be held and undispatched; the finished one must stay finished but not reopen
-- into a generation that could never be dispatched.
INSERT INTO scan_job (job_id,campaign_id,decision_id,capability,provider,provider_version,adapter_version,image_digest,manifest_sha256,scan_cycle,job_fingerprint,policy_version,scope_id,input,targets,target_refs,requested_by,rationale,status,envelope_event_id,started_at,finished_at,trace_id) VALUES
  ('01900000-0000-7000-8000-0000000d1741','01900000-0000-7000-8000-0000000d1710','01900000-0000-7000-8000-0000000d1731','dns.enumerate_subdomains','subfinder','v2.6.6','1.0.0','sha256:'||repeat('a',64),repeat('d',64),'01900000-0000-7000-8000-0000000d1751',repeat('71',32),'roe-170','01900000-0000-7000-8000-0000000d1711','{"targets":["agent-actor.example"]}','{dns:agent-actor.example}','[{"seed_id":"01900000-0000-7000-8000-0000000d1721"}]','{"kind":"agent","id":"legacy-session"}','Post-0009 agent actor, queued','QUEUED',NULL,NULL,NULL,repeat('7',32)),
  ('01900000-0000-7000-8000-0000000d1742','01900000-0000-7000-8000-0000000d1710','01900000-0000-7000-8000-0000000d1732','dns.resolve','dnsx','v1.2.3','1.0.0','sha256:'||repeat('a',64),repeat('d',64),'01900000-0000-7000-8000-0000000d1752',repeat('72',32),'roe-170','01900000-0000-7000-8000-0000000d1711','{"targets":["agent-actor.example"]}','{dns:agent-actor.example}','[{"seed_id":"01900000-0000-7000-8000-0000000d1721"}]','{"kind":"agent","id":"legacy-session"}','Post-0009 agent actor, finished','SUCCEEDED','01900000-0000-7000-8000-0000000d1762',now() - interval '2 hours',now() - interval '1 hour',repeat('7',32));

COMMIT;
