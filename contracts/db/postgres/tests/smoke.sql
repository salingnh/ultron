-- Smoke test cho 0001_init.sql: luồng tối thiểu chiến dịch -> job -> envelope -> asset/observation/cạnh -> finding,
-- và kiểm các bảo vệ chỉ-ghi-thêm. Chạy trên DB trống: psql -v ON_ERROR_STOP=1 -f 0001_init.sql -f tests/smoke.sql
SET search_path = aegis, public;
BEGIN;
INSERT INTO policy_snapshot VALUES ('roe-1','01900000-0000-7000-8000-000000000001','{"scan_profile":"low-impact","max_parallel_jobs":10,"max_duration_hours":168}',repeat('a',64),'{"kind":"operator","id":"soc-1"}');
INSERT INTO scope_snapshot VALUES ('01900000-0000-7000-8000-0000000000a1','01900000-0000-7000-8000-000000000001','{"domains":["internal.example"]}');
INSERT INTO campaign (campaign_id,name,objective,current_policy_version,scope_id,created_by)
  VALUES ('01900000-0000-7000-8000-000000000001','Internal baseline','Inventory','roe-1','01900000-0000-7000-8000-0000000000a1','{"kind":"operator","id":"soc-1"}');
COMMIT;
INSERT INTO campaign_target VALUES ('01900000-0000-7000-8000-0000000000b1','01900000-0000-7000-8000-0000000000a1','domain','internal.example','dns:internal.example');
INSERT INTO policy_decision (decision_id,campaign_id,capability,provider,targets,input,decision,rationale,requested_by,policy_version,scope_id,impact_tier,idempotency_key,trace_id)
  VALUES ('01900000-0000-7000-8000-0000000000c1','01900000-0000-7000-8000-000000000001','dns.enumerate_subdomains','subfinder','{dns:internal.example}','{"targets":["internal.example"]}','approved','Mở rộng domain hạt giống','{"kind":"agent","id":"planner"}','roe-1','01900000-0000-7000-8000-0000000000a1','T0','s1:1:1',repeat('0',32));
INSERT INTO scan_job (job_id,campaign_id,decision_id,capability,provider,provider_version,adapter_version,image_digest,scan_cycle,job_fingerprint,policy_version,scope_id,impact_tier,profile,input,targets,requested_by,rationale,trace_id)
  VALUES ('01900000-0000-7000-8000-0000000000d1','01900000-0000-7000-8000-000000000001','01900000-0000-7000-8000-0000000000c1','dns.enumerate_subdomains','subfinder','v2.6.6','1.0.0','sha256:'||repeat('a',64),'01900000-0000-7000-8000-0000000000f1',repeat('f',64),'roe-1','01900000-0000-7000-8000-0000000000a1','T0','passive','{}','{dns:internal.example}','{"kind":"agent","id":"planner"}','Mở rộng domain hạt giống',repeat('0',32));
INSERT INTO ingestion_inbox (event_id,dedup_key,job_id,payload_hash,status) VALUES ('01900000-0000-7000-8000-0000000000e1','job:01900000-0000-7000-8000-0000000000d1:envelope','01900000-0000-7000-8000-0000000000d1',repeat('b',64),'received');
INSERT INTO graph_revision (campaign_id,causal_job_id,envelope_event_id) VALUES ('01900000-0000-7000-8000-000000000001','01900000-0000-7000-8000-0000000000d1','01900000-0000-7000-8000-0000000000e1');
INSERT INTO asset (asset_id,canonical_key,kind,first_seen,last_seen) VALUES
  ('01900000-0000-7000-8000-0000000000f1','dns:internal.example','domain',now(),now()),
  ('01900000-0000-7000-8000-0000000000f2','dns:www.internal.example','domain',now(),now());
INSERT INTO relationship (relationship_id,type,from_asset_id,to_asset_id,observed_at,valid_from,source_job_id,confidence,campaign_id)
  VALUES ('01900000-0000-7000-8000-000000000101','SUBDOMAIN_OF','01900000-0000-7000-8000-0000000000f2','01900000-0000-7000-8000-0000000000f1',now(),now(),'01900000-0000-7000-8000-0000000000d1',0.9,'01900000-0000-7000-8000-000000000001');
INSERT INTO observation (observation_id,campaign_id,scan_id,envelope_event_id,revision,subject_asset_id,predicate,value,value_hash,provider,provider_version,observed_at)
  VALUES ('01900000-0000-7000-8000-000000000201','01900000-0000-7000-8000-000000000001','01900000-0000-7000-8000-0000000000d1','01900000-0000-7000-8000-0000000000e1',1,'01900000-0000-7000-8000-0000000000f2','asset.seen','true',repeat('c',64),'subfinder','v2.6.6',now());

-- Kỳ vọng lỗi: DELETE, UPDATE bảng append-only, mở lại cạnh đã đóng.
DO $$
DECLARE ok int := 0;
BEGIN
  BEGIN DELETE FROM asset; EXCEPTION WHEN insufficient_privilege THEN ok := ok + 1; END;
  BEGIN UPDATE observation SET confidence = 0.1; EXCEPTION WHEN insufficient_privilege THEN ok := ok + 1; END;
  BEGIN UPDATE relationship SET confidence = 0.1; EXCEPTION WHEN insufficient_privilege THEN ok := ok + 1; END;
  UPDATE relationship SET valid_to = now() + interval '1 second', closed_by_job_id = '01900000-0000-7000-8000-0000000000d1';
  BEGIN UPDATE relationship SET valid_to = NULL; EXCEPTION WHEN insufficient_privilege THEN ok := ok + 1; END;
  BEGIN TRUNCATE audit_log; EXCEPTION WHEN insufficient_privilege THEN ok := ok + 1; END;
  -- Cạnh đã đóng thì mở khoảng hiệu lực mới được (partial unique index chỉ trên valid_to IS NULL)
  INSERT INTO relationship (relationship_id,type,from_asset_id,to_asset_id,observed_at,valid_from,source_job_id,confidence,campaign_id)
    VALUES ('01900000-0000-7000-8000-000000000102','SUBDOMAIN_OF','01900000-0000-7000-8000-0000000000f2','01900000-0000-7000-8000-0000000000f1',now(),now(),'01900000-0000-7000-8000-0000000000d1',0.9,'01900000-0000-7000-8000-000000000001');
  BEGIN
    INSERT INTO relationship (relationship_id,type,from_asset_id,to_asset_id,observed_at,valid_from,source_job_id,confidence,campaign_id)
      VALUES ('01900000-0000-7000-8000-000000000103','SUBDOMAIN_OF','01900000-0000-7000-8000-0000000000f2','01900000-0000-7000-8000-0000000000f1',now(),now(),'01900000-0000-7000-8000-0000000000d1',0.9,'01900000-0000-7000-8000-000000000001');
  EXCEPTION WHEN unique_violation THEN ok := ok + 1; END;
  -- Trùng job_fingerprint bị chặn (dùng decision_id mới để vi phạm rơi đúng vào job_fingerprint, không phải decision_id)
  INSERT INTO policy_decision (decision_id,campaign_id,capability,provider,targets,input,decision,rationale,requested_by,policy_version,scope_id,impact_tier,idempotency_key,trace_id)
    VALUES ('01900000-0000-7000-8000-0000000000c2','01900000-0000-7000-8000-000000000001','dns.enumerate_subdomains','subfinder','{dns:internal.example}','{"targets":["internal.example"]}','approved','Quét lại','{"kind":"agent","id":"planner"}','roe-1','01900000-0000-7000-8000-0000000000a1','T0','s1:1:2',repeat('1',32));
  BEGIN
    INSERT INTO scan_job (job_id,campaign_id,decision_id,capability,provider,provider_version,adapter_version,image_digest,scan_cycle,job_fingerprint,policy_version,scope_id,impact_tier,profile,input,targets,requested_by,rationale,trace_id)
      SELECT '01900000-0000-7000-8000-0000000000d2',campaign_id,'01900000-0000-7000-8000-0000000000c2',capability,provider,provider_version,adapter_version,image_digest,scan_cycle,job_fingerprint,policy_version,scope_id,impact_tier,profile,input,targets,requested_by,rationale,trace_id FROM scan_job WHERE job_id='01900000-0000-7000-8000-0000000000d1';
  EXCEPTION WHEN unique_violation THEN ok := ok + 1; END;
  -- D26: UPDATE cột giá trị/định danh bị chặn trên bảng trạng thái
  BEGIN UPDATE scan_job SET targets = '{dns:evil.example}' WHERE job_id='01900000-0000-7000-8000-0000000000d1'; EXCEPTION WHEN insufficient_privilege THEN ok := ok + 1; END;
  BEGIN UPDATE asset SET canonical_key = 'dns:evil.example' WHERE asset_id='01900000-0000-7000-8000-0000000000f1'; EXCEPTION WHEN insufficient_privilege THEN ok := ok + 1; END;
  -- D26: UPDATE cột trạng thái phải thành công (không ném lỗi)
  UPDATE scan_job SET status='RUNNING', started_at=now() WHERE job_id='01900000-0000-7000-8000-0000000000d1';
  IF ok <> 9 THEN RAISE EXCEPTION 'smoke: chỉ % / 9 kiểm tra bảo vệ đạt', ok; END IF;
  RAISE NOTICE 'smoke: 9/9 kiểm tra bảo vệ đạt';
END $$;
