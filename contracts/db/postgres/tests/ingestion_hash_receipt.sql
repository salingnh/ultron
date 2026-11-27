-- C03: hash version is mandatory and versioned, the accepted receipt is written once, and every
-- submission is audited. Run after 0006 on the clean and on the upgrade chain; ROLLBACK leaves the
-- test database unchanged. Two live connections are covered by tests/test_ingestion_concurrency.py.
SET search_path=aegis,public;
BEGIN;
DO $$
DECLARE
  scope uuid := '01900000-0000-7000-8000-000000000212';
  camp  uuid := '01900000-0000-7000-8000-000000000202';
  seed  uuid := '01900000-0000-7000-8000-000000000221';
  job   uuid := '01900000-0000-7000-8000-000000000242';
  ev1   uuid := '01900000-0000-7000-8000-000000000251';
  ev2   uuid := '01900000-0000-7000-8000-000000000252';
  ev3   uuid := '01900000-0000-7000-8000-000000000253';
  key   text := 'job:01900000-0000-7000-8000-000000000242:envelope';
  hash  char(64) := repeat('a',64);
  other char(64) := repeat('b',64);
  blocked int := 0; shape int := 0; unversioned int := 0;
  stored_event text; stored_hash text; stored_version text; stored_revision text;
BEGIN
  INSERT INTO policy_snapshot VALUES ('roe-6',camp,'{"network_profile":"lab","max_parallel_jobs":10,"max_duration_hours":168}',repeat('6',64),'{"kind":"operator","id":"fixture"}');
  INSERT INTO scope_snapshot VALUES (scope,camp,'{"domains":["hash.example"]}');
  INSERT INTO campaign (campaign_id,name,objective,current_policy_version,scope_id,created_by)
    VALUES (camp,'Hash and receipt','C03 fixture','roe-6',scope,'{"kind":"operator","id":"fixture"}');
  INSERT INTO campaign_target VALUES (seed,scope,'domain','hash.example','dns:hash.example');
  INSERT INTO policy_decision (decision_id,campaign_id,capability,provider,targets,input,decision,rationale,requested_by,target_refs,policy_version,scope_id,idempotency_key,trace_id)
    VALUES ('01900000-0000-7000-8000-000000000231',camp,'dns.enumerate_subdomains','subfinder','{dns:hash.example}','{"targets":["hash.example"]}','approved','C03 job','{"kind":"operator","id":"fixture"}',jsonb_build_array(jsonb_build_object('seed_id',seed),jsonb_build_object('canonical_key','dns:hash.example')),'roe-6',scope,'c03:1',repeat('6',32));
  INSERT INTO scan_job (job_id,campaign_id,decision_id,capability,provider,provider_version,adapter_version,image_digest,manifest_sha256,scan_cycle,job_fingerprint,policy_version,scope_id,input,targets,target_refs,requested_by,rationale,trace_id)
    VALUES (job,camp,'01900000-0000-7000-8000-000000000231','dns.enumerate_subdomains','subfinder','v2.6.6','1.0.0','sha256:'||repeat('5',64),repeat('6',64),'01900000-0000-7000-8000-000000000291',repeat('7',64),'roe-6',scope,'{"targets":["hash.example"]}','{dns:hash.example}',
      jsonb_build_array(jsonb_build_object('seed_id',seed),jsonb_build_object('canonical_key','dns:hash.example')),'{"kind":"operator","id":"fixture"}','C03 job',repeat('6',32));

  -- 1. A new inbox row without a canonicalization version is rejected: an unversioned hash can
  --    never be compared with a versioned one.
  BEGIN
    INSERT INTO ingestion_inbox (event_id,dedup_key,job_id,payload_hash,status) VALUES (ev1,key,job,hash,'received');
  EXCEPTION WHEN not_null_violation THEN blocked := blocked + 1;
  END;
  -- 2. A version label outside aegis-c14n/<n> is rejected, so the column cannot hold free text.
  BEGIN
    INSERT INTO ingestion_inbox (event_id,dedup_key,job_id,payload_hash,hash_version,status) VALUES (ev1,key,job,hash,'jcs-1','received');
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;

  INSERT INTO ingestion_inbox (event_id,dedup_key,job_id,payload_hash,hash_version,status)
    VALUES (ev1,key,job,hash,'aegis-c14n/1','received');

  -- 3. The receipt must describe its own row and then never change.
  BEGIN
    UPDATE ingestion_inbox SET receipt = jsonb_build_object('event_id',ev2,'payload_hash',hash,'hash_version','aegis-c14n/1')
     WHERE event_id = ev1;
  EXCEPTION WHEN check_violation THEN shape := shape + 1;
  END;
  BEGIN
    UPDATE ingestion_inbox SET receipt = jsonb_build_object('event_id',ev1,'payload_hash',other,'hash_version','aegis-c14n/1')
     WHERE event_id = ev1;
  EXCEPTION WHEN check_violation THEN shape := shape + 1;
  END;
  UPDATE ingestion_inbox
     SET receipt = jsonb_build_object('event_id',ev1,'dedup_key',key,'accepted',true,'duplicate',false,
                                      'revision',1,'quarantined','[]'::jsonb,'payload_hash',hash,
                                      'hash_version','aegis-c14n/1','decided_at',now()),
         status = 'accepted', revision = 1, processed_at = now()
   WHERE event_id = ev1;
  BEGIN
    UPDATE ingestion_inbox
       SET receipt = jsonb_build_object('event_id',ev1,'dedup_key',key,'accepted',true,'duplicate',false,
                                        'revision',2,'quarantined','[]'::jsonb,'payload_hash',hash,
                                        'hash_version','aegis-c14n/1','decided_at',now())
     WHERE event_id = ev1;
  EXCEPTION WHEN insufficient_privilege THEN blocked := blocked + 1;
  END;

  -- 4. The content hash and its version are immutable; a conflicting hash never overwrites.
  BEGIN UPDATE ingestion_inbox SET payload_hash = other WHERE event_id = ev1;
  EXCEPTION WHEN insufficient_privilege THEN blocked := blocked + 1; END;
  BEGIN UPDATE ingestion_inbox SET hash_version = 'aegis-c14n/2' WHERE event_id = ev1;
  EXCEPTION WHEN insufficient_privilege THEN blocked := blocked + 1; END;
  BEGIN
    INSERT INTO ingestion_inbox (event_id,dedup_key,job_id,payload_hash,hash_version,status)
      VALUES (ev2,key,job,other,'aegis-c14n/1','received');
  EXCEPTION WHEN unique_violation THEN blocked := blocked + 1;
  END;

  -- 5. Every submission is audited: first, duplicate replay and conflicting content.
  INSERT INTO ingestion_attempt (event_id,dedup_key,inbox_event_id,payload_hash,hash_version,outcome)
    VALUES (ev1,key,ev1,hash,'aegis-c14n/1','first');
  INSERT INTO ingestion_attempt (event_id,dedup_key,inbox_event_id,payload_hash,hash_version,outcome)
    VALUES (ev2,key,ev1,hash,'aegis-c14n/1','duplicate');
  INSERT INTO ingestion_attempt (event_id,dedup_key,inbox_event_id,payload_hash,hash_version,outcome)
    VALUES (ev3,key,ev1,other,'aegis-c14n/1','conflict');
  -- At most one first acceptance per dedup_key, even across racing connections.
  BEGIN
    INSERT INTO ingestion_attempt (event_id,dedup_key,inbox_event_id,payload_hash,hash_version,outcome)
      VALUES ('01900000-0000-7000-8000-000000000254',key,'01900000-0000-7000-8000-000000000254',hash,'aegis-c14n/1','first');
  EXCEPTION WHEN unique_violation THEN blocked := blocked + 1;
  END;
  -- A non-first attempt always points at the committed inbox row.
  BEGIN
    INSERT INTO ingestion_attempt (event_id,dedup_key,payload_hash,hash_version,outcome)
      VALUES ('01900000-0000-7000-8000-000000000255',key,hash,'aegis-c14n/1','conflict');
  EXCEPTION WHEN check_violation THEN shape := shape + 1;
  END;
  BEGIN
    INSERT INTO ingestion_attempt (event_id,dedup_key,inbox_event_id,payload_hash,hash_version,outcome)
      VALUES ('01900000-0000-7000-8000-000000000256',key,ev1,hash,'aegis-c14n/1','first');
  EXCEPTION WHEN check_violation THEN shape := shape + 1;
  END;
  BEGIN UPDATE ingestion_attempt SET outcome = 'conflict' WHERE event_id = ev1;
  EXCEPTION WHEN insufficient_privilege THEN blocked := blocked + 1; END;
  BEGIN DELETE FROM ingestion_attempt;
  EXCEPTION WHEN insufficient_privilege THEN blocked := blocked + 1; END;

  -- 6. Rows that predate 0006 keep NULL hash_version and no invented receipt (upgrade chain only).
  SELECT count(*) INTO unversioned FROM ingestion_inbox WHERE hash_version IS NULL;
  IF unversioned > 0 AND EXISTS (SELECT 1 FROM ingestion_inbox WHERE hash_version IS NULL AND receipt IS NOT NULL) THEN
    RAISE EXCEPTION 'historical inbox row gained a versioned receipt';
  END IF;

  -- 7. The committed receipt is still the first one and still describes the committed content.
  SELECT receipt->>'event_id', payload_hash, hash_version, receipt->>'revision'
    INTO stored_event, stored_hash, stored_version, stored_revision
    FROM ingestion_inbox WHERE event_id = ev1;
  IF stored_event IS DISTINCT FROM ev1::text OR stored_hash IS DISTINCT FROM hash::text
     OR stored_version IS DISTINCT FROM 'aegis-c14n/1' OR stored_revision IS DISTINCT FROM '1' THEN
    RAISE EXCEPTION 'committed receipt changed: % % % %', stored_event, stored_hash, stored_version, stored_revision;
  END IF;

  IF shape <> 4 THEN RAISE EXCEPTION 'only % / 4 receipt/attempt shape rules blocked', shape; END IF;
  IF blocked <> 9 THEN RAISE EXCEPTION 'only % / 9 hash-version/receipt-immutability/attempt guards blocked', blocked; END IF;
  RAISE NOTICE 'hash/receipt: 2 unversioned/bad-version inserts blocked; 4 receipt/attempt shape rules PASS';
  RAISE NOTICE 'hash/receipt: 9/9 unversioned/bad-version inserts, hash immutability, receipt write-once, dedup conflict and attempt audit guards PASS';
END $$;
ROLLBACK;
