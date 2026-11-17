-- After v2 smoke. Query-level readiness checks, not a runtime scheduler implementation.
SET search_path=aegis,public;
BEGIN;
DO $$
DECLARE n integer; ids uuid[]; blocked integer:=0; pin_blocked integer:=0;
BEGIN
 IF EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='aegis' AND table_name IN ('scan_job','policy_decision','model_usage') AND column_name IN ('impact_tier','profile')) THEN RAISE EXCEPTION 'retired columns still operational'; END IF;
 INSERT INTO policy_decision SELECT (jsonb_populate_record(NULL::policy_decision,to_jsonb(p)||jsonb_build_object('decision_id','01900000-0000-7000-8000-0000000000c3','idempotency_key','v2:schedule:3'))).* FROM policy_decision p LIMIT 1;
 INSERT INTO policy_decision SELECT (jsonb_populate_record(NULL::policy_decision,to_jsonb(p)||jsonb_build_object('decision_id','01900000-0000-7000-8000-0000000000c4','idempotency_key','v2:schedule:4'))).* FROM policy_decision p LIMIT 1;
 INSERT INTO scan_job SELECT (jsonb_populate_record(NULL::scan_job,to_jsonb(j)||jsonb_build_object('job_id','01900000-0000-7000-8000-0000000000d3','decision_id','01900000-0000-7000-8000-0000000000c3','job_fingerprint',repeat('3',64),'priority',100,'status','QUEUED','started_at',NULL))).* FROM scan_job j LIMIT 1;
 INSERT INTO scan_job SELECT (jsonb_populate_record(NULL::scan_job,to_jsonb(j)||jsonb_build_object('job_id','01900000-0000-7000-8000-0000000000d4','decision_id','01900000-0000-7000-8000-0000000000c4','job_fingerprint',repeat('4',64),'priority',10,'status','QUEUED','started_at',NULL))).* FROM scan_job j LIMIT 1;
 INSERT INTO job_dependency(campaign_id,job_id,depends_on_job_id) VALUES('01900000-0000-7000-8000-000000000001','01900000-0000-7000-8000-0000000000d3','01900000-0000-7000-8000-0000000000d1');
 SELECT array_agg(job_id ORDER BY priority DESC,created_at,job_id) INTO ids FROM scan_job j WHERE status='QUEUED' AND manifest_sha256 IS NOT NULL AND NOT EXISTS(SELECT 1 FROM job_dependency d JOIN scan_job predecessor ON predecessor.job_id=d.depends_on_job_id WHERE d.job_id=j.job_id AND predecessor.status<>'SUCCEEDED');
 IF ids IS DISTINCT FROM ARRAY['01900000-0000-7000-8000-0000000000d4'::uuid] THEN RAISE EXCEPTION 'high priority bypassed dependency: %',ids; END IF;
 UPDATE scan_job SET status='SUCCEEDED' WHERE job_id='01900000-0000-7000-8000-0000000000d1';
 SELECT array_agg(job_id ORDER BY priority DESC,created_at,job_id) INTO ids FROM scan_job j WHERE status='QUEUED' AND manifest_sha256 IS NOT NULL AND NOT EXISTS(SELECT 1 FROM job_dependency d JOIN scan_job predecessor ON predecessor.job_id=d.depends_on_job_id WHERE d.job_id=j.job_id AND predecessor.status<>'SUCCEEDED');
 IF ids IS DISTINCT FROM ARRAY['01900000-0000-7000-8000-0000000000d3'::uuid,'01900000-0000-7000-8000-0000000000d4'::uuid] THEN RAISE EXCEPTION 'priority order invalid: %',ids; END IF;
 BEGIN INSERT INTO job_dependency(campaign_id,job_id,depends_on_job_id) VALUES('01900000-0000-7000-8000-000000000001','01900000-0000-7000-8000-0000000000d4','01900000-0000-7000-8000-0000000000d4'); EXCEPTION WHEN check_violation THEN blocked:=blocked+1; END;
 BEGIN INSERT INTO job_dependency(campaign_id,job_id,depends_on_job_id) VALUES('01900000-0000-7000-8000-000000000099','01900000-0000-7000-8000-0000000000d4','01900000-0000-7000-8000-0000000000d1'); EXCEPTION WHEN foreign_key_violation THEN blocked:=blocked+1; END;
 BEGIN UPDATE scan_job SET priority=101 WHERE job_id='01900000-0000-7000-8000-0000000000d4'; EXCEPTION WHEN insufficient_privilege THEN blocked:=blocked+1; END;
 BEGIN DELETE FROM job_dependency; EXCEPTION WHEN insufficient_privilege THEN blocked:=blocked+1; END;
 IF blocked<>4 THEN RAISE EXCEPTION 'only % / 4 constraints blocked',blocked; END IF;
 INSERT INTO policy_decision SELECT (jsonb_populate_record(NULL::policy_decision,to_jsonb(p)||jsonb_build_object('decision_id','01900000-0000-7000-8000-0000000000c5','idempotency_key','manifest:5'))).* FROM policy_decision p LIMIT 1;
 BEGIN
  INSERT INTO scan_job SELECT (jsonb_populate_record(NULL::scan_job,to_jsonb(j)||jsonb_build_object('job_id','01900000-0000-7000-8000-0000000000d5','decision_id','01900000-0000-7000-8000-0000000000c5','job_fingerprint',repeat('5',64),'manifest_sha256',NULL))).* FROM scan_job j LIMIT 1;
 EXCEPTION WHEN check_violation THEN pin_blocked:=pin_blocked+1; END;
 BEGIN
  INSERT INTO scan_job SELECT (jsonb_populate_record(NULL::scan_job,to_jsonb(j)||jsonb_build_object('job_id','01900000-0000-7000-8000-0000000000d5','decision_id','01900000-0000-7000-8000-0000000000c5','job_fingerprint',repeat('5',64),'manifest_sha256',repeat('X',64)))).* FROM scan_job j LIMIT 1;
 EXCEPTION WHEN check_violation THEN pin_blocked:=pin_blocked+1; END;
 BEGIN UPDATE scan_job SET manifest_sha256=repeat('8',64) WHERE job_id='01900000-0000-7000-8000-0000000000d4'; EXCEPTION WHEN insufficient_privilege THEN pin_blocked:=pin_blocked+1; END;
 IF pin_blocked<>3 THEN RAISE EXCEPTION 'only % / 3 manifest constraints blocked',pin_blocked; END IF;
 RAISE NOTICE 'v2: retired columns absent; dependency readiness and priority order PASS; 4/4 immutability/reference constraints PASS';
 RAISE NOTICE 'manifest binding: 3/3 missing/hash-format/immutability constraints PASS';
END $$;
ROLLBACK;
