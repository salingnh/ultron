-- Historical input for the 0017 upgrade test only. Apply after 0016 and before 0017.
--
-- This row was accepted by the contract *before* 0017: a roe-policy.v2 snapshot that still carries
-- the allowed/blackout time windows, a campaign on it, and a queued job whose wait reason is
-- `WINDOW_CLOSED`. 0017 drops the windows for new writes; this fixture is what a database upgraded
-- from 0016 already holds, so the upgrade test can prove that 0017 neither rewrites it nor
-- reclassifies it as v1 (its job stays dispatchable and its wait reason stays readable).
SET search_path = aegis, public;
BEGIN;

INSERT INTO policy_snapshot VALUES ('roe-1301', '01900000-0000-7000-8000-0000000d1901',
  '{"max_parallel_jobs":10,"max_duration_hours":168,
    "allowed_windows":[{"days":["mon","tue","wed","thu","fri"],"start":"08:00","end":"18:00","timezone":"Asia/Ho_Chi_Minh"}],
    "blackout_windows":[{"days":["sat","sun"],"start":"00:00","end":"24:00","timezone":"Asia/Ho_Chi_Minh"}]}',
  repeat('f1',32), '{"kind":"operator","id":"soc-legacy"}');
INSERT INTO scope_snapshot VALUES
  ('01900000-0000-7000-8000-0000000d1902', '01900000-0000-7000-8000-0000000d1901',
   '{"domains":["window-history.example"]}');
INSERT INTO campaign (campaign_id,name,objective,current_policy_version,scope_id,created_by) VALUES
  ('01900000-0000-7000-8000-0000000d1901','Pre-0017 window campaign','History fixture','roe-1301',
   '01900000-0000-7000-8000-0000000d1902','{"kind":"operator","id":"soc-legacy"}');
INSERT INTO campaign_target VALUES
  ('01900000-0000-7000-8000-0000000d1903','01900000-0000-7000-8000-0000000d1902',
   'domain','window-history.example','dns:window-history.example');
INSERT INTO policy_decision (decision_id,campaign_id,capability,provider,targets,input,decision,rationale,requested_by,target_refs,policy_version,scope_id,idempotency_key,trace_id) VALUES
  ('01900000-0000-7000-8000-0000000d1904','01900000-0000-7000-8000-0000000d1901','dns.enumerate_subdomains','subfinder','{dns:window-history.example}','{"targets":["window-history.example"]}','approved','Queued while the window was closed','{"kind":"operator","id":"soc-legacy"}','[{"seed_id":"01900000-0000-7000-8000-0000000d1903"},{"canonical_key":"dns:window-history.example"}]','roe-1301','01900000-0000-7000-8000-0000000d1902','pre-0017:1',repeat('f2',16));
INSERT INTO scan_job (job_id,campaign_id,decision_id,capability,provider,provider_version,adapter_version,image_digest,manifest_sha256,scan_cycle,job_fingerprint,policy_version,scope_id,input,targets,target_refs,requested_by,rationale,status,wait_reason,trace_id) VALUES
  ('01900000-0000-7000-8000-0000000d1905','01900000-0000-7000-8000-0000000d1901','01900000-0000-7000-8000-0000000d1904','dns.enumerate_subdomains','subfinder','v2.17.0','1.0.0','sha256:'||repeat('a',64),repeat('f3',32),'01900000-0000-7000-8000-0000000d1906',repeat('9f',32),'roe-1301','01900000-0000-7000-8000-0000000d1902','{"targets":["window-history.example"]}','{dns:window-history.example}','[{"seed_id":"01900000-0000-7000-8000-0000000d1903"},{"canonical_key":"dns:window-history.example"}]','{"kind":"operator","id":"soc-legacy"}','Queued while the window was closed','QUEUED','{"code":"WINDOW_CLOSED","since":"2026-11-23T09:00:00Z"}',repeat('f5',16));

COMMIT;
