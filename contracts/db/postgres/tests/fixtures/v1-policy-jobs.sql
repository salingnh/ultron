-- Historical input for the S1.6 upgrade test only. Not an active contract, not execution configuration.
-- Apply after 0008 and before 0009: rows here were accepted by the v1 contract (roe-policy.v1 JSON)
-- and, for some jobs, by the v2 job rules (manifest pin 0003, TargetRefs 0005). The migration must
-- leave every row byte-identical, pause the running campaign and hold the jobs instead of running them.
SET search_path = aegis, public;
BEGIN;

-- Campaign L: running legacy campaign whose policy uses every v1-only and every carried-over setting.
INSERT INTO policy_snapshot VALUES ('roe-101','01900000-0000-7000-8000-0000000d1601',
  '{"scan_profile":"standard","max_impact_tier":"T1","approval_required_tiers":["T2"],"max_parallel_jobs":25,"max_duration_hours":72,"rate_limits":{"requests_per_second_per_host":5.5,"packets_per_second":200,"jobs_per_minute":30},"allowed_windows":[{"days":["mon","tue","wed","thu","fri"],"start":"08:00","end":"18:00","timezone":"Asia/Ho_Chi_Minh"}],"blackout_windows":[{"days":["sat","sun"],"start":"00:00","end":"24:00","timezone":"Asia/Ho_Chi_Minh"}],"budget":{"max_llm_cost_usd":25.5,"max_llm_tokens":100000,"max_jobs":500,"max_agent_sessions":50,"idle_cycles_before_pause":3},"capability_denylist":["network.discover_services"]}',
  repeat('b',64),'{"kind":"operator","id":"soc-legacy"}');
INSERT INTO scope_snapshot VALUES ('01900000-0000-7000-8000-0000000d1602','01900000-0000-7000-8000-0000000d1601','{"domains":["legacy.example"]}');
INSERT INTO campaign (campaign_id,name,objective,status,current_policy_version,scope_id,created_by,started_at)
  VALUES ('01900000-0000-7000-8000-0000000d1601','Legacy running campaign','Inventory','RUNNING','roe-101','01900000-0000-7000-8000-0000000d1602','{"kind":"operator","id":"soc-legacy"}',now() - interval '2 days');
INSERT INTO campaign_target VALUES
  ('01900000-0000-7000-8000-0000000d1621','01900000-0000-7000-8000-0000000d1602','domain','legacy.example','dns:legacy.example');

-- Campaign C: a legacy campaign that was never started; the migration must leave its status alone.
INSERT INTO policy_snapshot VALUES ('roe-102','01900000-0000-7000-8000-0000000d1611',
  '{"scan_profile":"passive","max_parallel_jobs":10,"max_duration_hours":168}',
  repeat('c',64),'{"kind":"operator","id":"soc-legacy"}');
INSERT INTO scope_snapshot VALUES ('01900000-0000-7000-8000-0000000d1612','01900000-0000-7000-8000-0000000d1611','{"domains":["legacy-created.example"]}');
INSERT INTO campaign (campaign_id,name,objective,current_policy_version,scope_id,created_by)
  VALUES ('01900000-0000-7000-8000-0000000d1611','Legacy created campaign','Inventory','roe-102','01900000-0000-7000-8000-0000000d1612','{"kind":"operator","id":"soc-legacy"}');
INSERT INTO campaign_target VALUES
  ('01900000-0000-7000-8000-0000000d1622','01900000-0000-7000-8000-0000000d1612','domain','legacy-created.example','dns:legacy-created.example');

-- Three jobs of campaign L: queued, in flight, and already terminal. All three carry the v2 pins, so
-- LEGACY_POLICY_V1 is the only reason they are held.
INSERT INTO policy_decision (decision_id,campaign_id,capability,provider,targets,input,decision,rationale,requested_by,policy_version,scope_id,idempotency_key,trace_id) VALUES
  ('01900000-0000-7000-8000-0000000d1631','01900000-0000-7000-8000-0000000d1601','dns.enumerate_subdomains','subfinder','{dns:legacy.example}','{"targets":["legacy.example"]}','approved','Legacy queued job','{"kind":"agent","id":"legacy-planner"}','roe-101','01900000-0000-7000-8000-0000000d1602','s16:1',repeat('9',32)),
  ('01900000-0000-7000-8000-0000000d1632','01900000-0000-7000-8000-0000000d1601','dns.resolve','dnsx','{dns:legacy.example}','{"targets":["legacy.example"]}','approved','Legacy in-flight job','{"kind":"agent","id":"legacy-planner"}','roe-101','01900000-0000-7000-8000-0000000d1602','s16:2',repeat('9',32)),
  ('01900000-0000-7000-8000-0000000d1633','01900000-0000-7000-8000-0000000d1601','dns.enumerate_subdomains','subfinder','{dns:legacy.example}','{"targets":["legacy.example"]}','approved','Legacy finished job','{"kind":"agent","id":"legacy-planner"}','roe-101','01900000-0000-7000-8000-0000000d1602','s16:3',repeat('9',32));
INSERT INTO scan_job (job_id,campaign_id,decision_id,capability,provider,provider_version,adapter_version,image_digest,manifest_sha256,scan_cycle,job_fingerprint,policy_version,scope_id,input,targets,target_refs,requested_by,rationale,status,envelope_event_id,started_at,finished_at,trace_id) VALUES
  ('01900000-0000-7000-8000-0000000d1641','01900000-0000-7000-8000-0000000d1601','01900000-0000-7000-8000-0000000d1631','dns.enumerate_subdomains','subfinder','v2.6.6','1.0.0','sha256:'||repeat('a',64),repeat('d',64),'01900000-0000-7000-8000-0000000d1651',repeat('f1',32),'roe-101','01900000-0000-7000-8000-0000000d1602','{"targets":["legacy.example"]}','{dns:legacy.example}','[{"seed_id":"01900000-0000-7000-8000-0000000d1621"}]','{"kind":"agent","id":"legacy-planner"}','Legacy queued job','QUEUED',NULL,NULL,NULL,repeat('9',32)),
  ('01900000-0000-7000-8000-0000000d1642','01900000-0000-7000-8000-0000000d1601','01900000-0000-7000-8000-0000000d1632','dns.resolve','dnsx','v1.2.3','1.0.0','sha256:'||repeat('a',64),repeat('d',64),'01900000-0000-7000-8000-0000000d1652',repeat('f2',32),'roe-101','01900000-0000-7000-8000-0000000d1602','{"targets":["legacy.example"]}','{dns:legacy.example}','[{"seed_id":"01900000-0000-7000-8000-0000000d1621"}]','{"kind":"agent","id":"legacy-planner"}','Legacy in-flight job','RUNNING',NULL,now() - interval '1 hour',NULL,repeat('9',32)),
  ('01900000-0000-7000-8000-0000000d1643','01900000-0000-7000-8000-0000000d1601','01900000-0000-7000-8000-0000000d1633','dns.enumerate_subdomains','subfinder','v2.6.6','1.0.0','sha256:'||repeat('a',64),repeat('d',64),'01900000-0000-7000-8000-0000000d1653',repeat('f3',32),'roe-101','01900000-0000-7000-8000-0000000d1602','{"targets":["legacy.example"]}','{dns:legacy.example}','[{"seed_id":"01900000-0000-7000-8000-0000000d1621"}]','{"kind":"agent","id":"legacy-planner"}','Legacy finished job','SUCCEEDED','01900000-0000-7000-8000-0000000d1663',now() - interval '2 days',now() - interval '1 day',repeat('9',32));

COMMIT;
