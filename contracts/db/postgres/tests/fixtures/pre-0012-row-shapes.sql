-- Historical input for the 0014 upgrade test only. Not an active contract, not execution configuration.
-- Apply after 0011 and before 0012: both rows were accepted by the 0005-0011 rules and, at the time,
-- were legal — a label proposer (0012 had not yet required a session) and a `targets` projection that
-- carries the seed's own canonical key with only the seed in `target_refs`.
-- 0012 makes both shapes illegal for new rows; 0014 must hold these rows for dispatch without locking
-- them, so they can still be cancelled and finalised (gate re-review R-2).
SET search_path = aegis, public;
BEGIN;

INSERT INTO policy_snapshot VALUES
  ('roe-190', '01900000-0000-7000-8000-0000000d1910',
   '{"max_parallel_jobs":10,"max_duration_hours":168}', repeat('9',64),
   '{"kind":"operator","id":"soc-legacy"}');
INSERT INTO scope_snapshot VALUES
  ('01900000-0000-7000-8000-0000000d1911', '01900000-0000-7000-8000-0000000d1910',
   '{"domains":["pre12.example"]}');
INSERT INTO campaign (campaign_id,name,objective,current_policy_version,scope_id,created_by) VALUES
  ('01900000-0000-7000-8000-0000000d1910','Pre-0012 row shapes','R-2 fixture','roe-190',
   '01900000-0000-7000-8000-0000000d1911','{"kind":"operator","id":"soc-legacy"}');
INSERT INTO campaign_target VALUES
  ('01900000-0000-7000-8000-0000000d1921','01900000-0000-7000-8000-0000000d1911',
   'domain','pre12.example','dns:pre12.example');

INSERT INTO policy_decision (decision_id,campaign_id,capability,provider,targets,input,decision,rationale,requested_by,proposed_by,policy_version,scope_id,idempotency_key,trace_id) VALUES
  ('01900000-0000-7000-8000-0000000d1931','01900000-0000-7000-8000-0000000d1910','dns.enumerate_subdomains','subfinder','{}','{"targets":["pre12.example"]}','approved','Label proposer','{"kind":"operator","id":"soc-legacy"}','{"kind":"agent","id":"session-1"}','roe-190','01900000-0000-7000-8000-0000000d1911','r2:1',repeat('9',32)),
  ('01900000-0000-7000-8000-0000000d1932','01900000-0000-7000-8000-0000000d1910','dns.resolve','dnsx','{dns:pre12.example}','{"targets":["pre12.example"]}','approved','Seed canonical key in targets','{"kind":"operator","id":"soc-legacy"}',NULL,'roe-190','01900000-0000-7000-8000-0000000d1911','r2:2',repeat('9',32));

INSERT INTO scan_job (job_id,campaign_id,decision_id,capability,provider,provider_version,adapter_version,image_digest,manifest_sha256,scan_cycle,job_fingerprint,policy_version,scope_id,input,targets,target_refs,requested_by,proposed_by,rationale,status,started_at,trace_id) VALUES
  ('01900000-0000-7000-8000-0000000d1941','01900000-0000-7000-8000-0000000d1910','01900000-0000-7000-8000-0000000d1931','dns.enumerate_subdomains','subfinder','v2.6.6','1.0.0','sha256:'||repeat('a',64),repeat('d',64),'01900000-0000-7000-8000-0000000d1951',repeat('91',32),'roe-190','01900000-0000-7000-8000-0000000d1911','{"targets":["pre12.example"]}','{}','[{"seed_id":"01900000-0000-7000-8000-0000000d1921"}]','{"kind":"operator","id":"soc-legacy"}','{"kind":"agent","id":"session-1"}','Label proposer','QUEUED',NULL,repeat('9',32)),
  ('01900000-0000-7000-8000-0000000d1942','01900000-0000-7000-8000-0000000d1910','01900000-0000-7000-8000-0000000d1932','dns.resolve','dnsx','v1.2.3','1.0.0','sha256:'||repeat('a',64),repeat('d',64),'01900000-0000-7000-8000-0000000d1952',repeat('92',32),'roe-190','01900000-0000-7000-8000-0000000d1911','{"targets":["pre12.example"]}','{dns:pre12.example}','[{"seed_id":"01900000-0000-7000-8000-0000000d1921"}]','{"kind":"operator","id":"soc-legacy"}',NULL,'Seed canonical key in targets','RUNNING',now() - interval '1 hour',repeat('9',32));

COMMIT;
