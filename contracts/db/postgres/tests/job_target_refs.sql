-- C02 seed reference: TargetRef on accepted jobs and on asset provenance.
-- Run after 0005 on a clean chain and on the upgrade chain; ROLLBACK leaves the test database unchanged.
SET search_path=aegis,public;
BEGIN;
DO $$
DECLARE
  scope_a uuid := '01900000-0000-7000-8000-000000000111';
  scope_b uuid := '01900000-0000-7000-8000-000000000112';
  camp_a  uuid := '01900000-0000-7000-8000-000000000101';
  camp_b  uuid := '01900000-0000-7000-8000-000000000102';
  seed_domain  uuid := '01900000-0000-7000-8000-000000000121';
  seed_cidr    uuid := '01900000-0000-7000-8000-000000000122';
  seed_keyword uuid := '01900000-0000-7000-8000-000000000123';
  seed_other   uuid := '01900000-0000-7000-8000-000000000124';
  job_main uuid := '01900000-0000-7000-8000-000000000141';
  job_assets uuid := '01900000-0000-7000-8000-000000000142';
  asset_ip uuid := '01900000-0000-7000-8000-000000000171';
  scan uuid := '01900000-0000-7000-8000-000000000191';
  blocked int := 0; shape_blocked int := 0; provenance_blocked int := 0;
  seed_list text; queued_legacy int;
BEGIN
  INSERT INTO policy_snapshot VALUES
    ('roe-4',camp_a,'{"max_parallel_jobs":10,"max_duration_hours":168}',repeat('4',64),'{"kind":"operator","id":"fixture"}'),
    ('roe-5',camp_b,'{"max_parallel_jobs":10,"max_duration_hours":168}',repeat('5',64),'{"kind":"operator","id":"fixture"}');
  INSERT INTO scope_snapshot VALUES
    (scope_a,camp_a,'{"domains":["seed.example"],"ips":["10.20.0.0/24"],"keywords":["acme corp"]}'),
    (scope_b,camp_b,'{"domains":["other.example"]}');
  INSERT INTO campaign (campaign_id,name,objective,current_policy_version,scope_id,created_by) VALUES
    (camp_a,'Seed reference A','C02 fixture','roe-4',scope_a,'{"kind":"operator","id":"fixture"}'),
    (camp_b,'Seed reference B','C02 fixture','roe-5',scope_b,'{"kind":"operator","id":"fixture"}');
  -- campaign_target keeps the seed kind and raw value; keyword and CIDR have no canonical_key.
  INSERT INTO campaign_target VALUES
    (seed_domain, scope_a,'domain','seed.example','dns:seed.example'),
    (seed_cidr,   scope_a,'cidr','10.20.0.0/24',NULL),
    (seed_keyword,scope_a,'keyword','acme corp',NULL),
    (seed_other,  scope_b,'domain','other.example','dns:other.example');

  -- 1. Accepted job: keyword/CIDR/domain seeds plus one known asset key; canonical projection empty.
  -- 0012: the decision carries the same refs, and its `targets` is only the canonical projection.
  INSERT INTO policy_decision (decision_id,campaign_id,capability,provider,targets,input,decision,rationale,requested_by,target_refs,policy_version,scope_id,idempotency_key,trace_id)
    VALUES ('01900000-0000-7000-8000-000000000131',camp_a,'dns.enumerate_subdomains','subfinder','{}','{"targets":["seed.example"]}','approved','C02 seed refs','{"kind":"operator","id":"fixture"}',
      jsonb_build_array(jsonb_build_object('seed_id',seed_domain),jsonb_build_object('seed_id',seed_cidr),jsonb_build_object('seed_id',seed_keyword),jsonb_build_object('canonical_key','dns:www.seed.example')),'roe-4',scope_a,'c02:1',repeat('4',32));
  INSERT INTO scan_job (job_id,campaign_id,decision_id,capability,provider,provider_version,adapter_version,image_digest,manifest_sha256,scan_cycle,job_fingerprint,policy_version,scope_id,input,targets,target_refs,requested_by,rationale,trace_id)
    VALUES (job_main,camp_a,'01900000-0000-7000-8000-000000000131','dns.enumerate_subdomains','subfinder','v2.6.6','1.0.0','sha256:'||repeat('5',64),repeat('6',64),scan,repeat('7',64),'roe-4',scope_a,'{"targets":["seed.example"]}','{}',
      jsonb_build_array(jsonb_build_object('seed_id',seed_domain),jsonb_build_object('seed_id',seed_cidr),jsonb_build_object('seed_id',seed_keyword),jsonb_build_object('canonical_key','dns:www.seed.example')),
      '{"kind":"operator","id":"fixture"}','C02 seed refs',repeat('4',32));

  -- 2. A job whose targets are all known assets may still fill the canonical-key projection.
  INSERT INTO policy_decision (decision_id,campaign_id,capability,provider,targets,input,decision,rationale,requested_by,target_refs,policy_version,scope_id,idempotency_key,trace_id)
    VALUES ('01900000-0000-7000-8000-000000000132',camp_a,'dns.resolve','dnsx','{dns:seed.example}','{"targets":["seed.example"]}','approved','C02 asset refs','{"kind":"operator","id":"fixture"}','[{"canonical_key":"dns:seed.example"}]','roe-4',scope_a,'c02:2',repeat('4',32));
  INSERT INTO scan_job (job_id,campaign_id,decision_id,capability,provider,provider_version,adapter_version,image_digest,manifest_sha256,scan_cycle,job_fingerprint,policy_version,scope_id,input,targets,target_refs,requested_by,rationale,trace_id)
    VALUES (job_assets,camp_a,'01900000-0000-7000-8000-000000000132','dns.resolve','dnsx','v1.2.3','1.0.0','sha256:'||repeat('5',64),repeat('6',64),scan,repeat('8',64),'roe-4',scope_a,'{"targets":["seed.example"]}','{dns:seed.example}',
      '[{"canonical_key":"dns:seed.example"}]','{"kind":"operator","id":"fixture"}','C02 asset refs',repeat('4',32));

  -- 3. A new job without target_refs is rejected: no accepted job without seed provenance. Since 0012
  --    the job must also carry exactly the refs its decision resolved, so the omission is caught either way.
  INSERT INTO policy_decision (decision_id,campaign_id,capability,provider,targets,input,decision,rationale,requested_by,target_refs,policy_version,scope_id,idempotency_key,trace_id)
    VALUES ('01900000-0000-7000-8000-000000000133',camp_a,'dns.resolve','dnsx','{dns:seed.example}','{"targets":["seed.example"]}','approved','C02 missing refs','{"kind":"operator","id":"fixture"}','[{"seed_id":"01900000-0000-7000-8000-000000000121"},{"canonical_key":"dns:seed.example"}]','roe-4',scope_a,'c02:3',repeat('4',32));
  BEGIN
    INSERT INTO scan_job (job_id,campaign_id,decision_id,capability,provider,provider_version,adapter_version,image_digest,manifest_sha256,scan_cycle,job_fingerprint,policy_version,scope_id,input,targets,requested_by,rationale,trace_id)
      VALUES ('01900000-0000-7000-8000-000000000143',camp_a,'01900000-0000-7000-8000-000000000133','dns.resolve','dnsx','v1.2.3','1.0.0','sha256:'||repeat('5',64),repeat('6',64),scan,repeat('9',64),'roe-4',scope_a,'{"targets":["seed.example"]}','{dns:seed.example}','{"kind":"operator","id":"fixture"}','C02 missing refs',repeat('4',32));
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;

  -- 4. A seed of another campaign cannot be a target of this campaign's job. Since 0012 the decision
  --    is refused first, so the job cannot even be described.
  BEGIN
    INSERT INTO policy_decision (decision_id,campaign_id,capability,provider,targets,input,decision,rationale,requested_by,target_refs,policy_version,scope_id,idempotency_key,trace_id)
      VALUES ('01900000-0000-7000-8000-000000000134',camp_a,'dns.resolve','dnsx','{dns:other.example}','{"targets":["other.example"]}','approved','C02 cross campaign','{"kind":"operator","id":"fixture"}',
        jsonb_build_array(jsonb_build_object('seed_id',seed_other)),'roe-4',scope_a,'c02:4',repeat('4',32));
    INSERT INTO scan_job (job_id,campaign_id,decision_id,capability,provider,provider_version,adapter_version,image_digest,manifest_sha256,scan_cycle,job_fingerprint,policy_version,scope_id,input,targets,target_refs,requested_by,rationale,trace_id)
      VALUES ('01900000-0000-7000-8000-000000000144',camp_a,'01900000-0000-7000-8000-000000000134','dns.resolve','dnsx','v1.2.3','1.0.0','sha256:'||repeat('5',64),repeat('6',64),scan,repeat('a',64),'roe-4',scope_a,'{"targets":["other.example"]}','{dns:other.example}',
        jsonb_build_array(jsonb_build_object('seed_id',seed_other)),'{"kind":"operator","id":"fixture"}','C02 cross campaign',repeat('4',32));
  EXCEPTION WHEN foreign_key_violation THEN blocked := blocked + 1;
  END;

  -- 5. Shape errors: ambiguous ref, empty object, non-v7 seed id, fabricated keyword asset, empty list.
  DECLARE
    shapes jsonb[] := ARRAY[
      jsonb_build_array(jsonb_build_object('seed_id',seed_domain,'canonical_key','dns:seed.example')),
      jsonb_build_array(jsonb_build_object()),
      jsonb_build_array(jsonb_build_object('seed_id','acme corp')),
      jsonb_build_array(jsonb_build_object('canonical_key','keyword:acme corp')),
      '[]'::jsonb
    ];
    i int;
  BEGIN
    FOR i IN 1 .. array_length(shapes,1) LOOP
      BEGIN
        INSERT INTO policy_decision (decision_id,campaign_id,capability,provider,targets,input,decision,rationale,requested_by,target_refs,policy_version,scope_id,idempotency_key,trace_id)
          VALUES (('01900000-0000-7000-8000-00000000015' || i)::uuid,camp_a,'dns.resolve','dnsx','{}','{}','approved','C02 shape','{"kind":"operator","id":"fixture"}',shapes[i],'roe-4',scope_a,'c02:shape:'||i,repeat('4',32));
        INSERT INTO scan_job (job_id,campaign_id,decision_id,capability,provider,provider_version,adapter_version,image_digest,manifest_sha256,scan_cycle,job_fingerprint,policy_version,scope_id,input,targets,target_refs,requested_by,rationale,trace_id)
          VALUES (('01900000-0000-7000-8000-00000000016' || i)::uuid,camp_a,('01900000-0000-7000-8000-00000000015' || i)::uuid,'dns.resolve','dnsx','v1.2.3','1.0.0','sha256:'||repeat('5',64),repeat('6',64),scan,repeat('b',64),'roe-4',scope_a,'{}','{}',
            shapes[i],'{"kind":"operator","id":"fixture"}','C02 shape',repeat('4',32));
      EXCEPTION WHEN check_violation THEN shape_blocked := shape_blocked + 1;
      END;
    END LOOP;
  END;

  -- 6. An accepted job's seed chain is immutable: dispatch/replay cannot rewrite target_refs.
  BEGIN
    UPDATE scan_job SET target_refs = jsonb_build_array(jsonb_build_object('seed_id',seed_other)) WHERE job_id = job_main;
  EXCEPTION WHEN insufficient_privilege THEN blocked := blocked + 1;
  END;

  -- 7. Replay of the same result is rejected (one logical job per fingerprint) and keeps the seed.
  BEGIN
    INSERT INTO policy_decision (decision_id,campaign_id,capability,provider,targets,input,decision,rationale,requested_by,target_refs,policy_version,scope_id,idempotency_key,trace_id)
      VALUES ('01900000-0000-7000-8000-000000000135',camp_a,'dns.enumerate_subdomains','subfinder','{}','{"targets":["seed.example"]}','approved','C02 replay','{"kind":"operator","id":"fixture"}','[{"seed_id":"01900000-0000-7000-8000-000000000121"}]','roe-4',scope_a,'c02:5',repeat('4',32));
    INSERT INTO scan_job (job_id,campaign_id,decision_id,capability,provider,provider_version,adapter_version,image_digest,manifest_sha256,scan_cycle,job_fingerprint,policy_version,scope_id,input,targets,target_refs,requested_by,rationale,trace_id)
      VALUES ('01900000-0000-7000-8000-000000000145',camp_a,'01900000-0000-7000-8000-000000000135','dns.enumerate_subdomains','subfinder','v2.6.6','1.0.0','sha256:'||repeat('5',64),repeat('6',64),scan,repeat('7',64),'roe-4',scope_a,'{"targets":["seed.example"]}','{}',
        jsonb_build_array(jsonb_build_object('seed_id',seed_domain)),'{"kind":"operator","id":"fixture"}','C02 replay',repeat('4',32));
  EXCEPTION WHEN unique_violation THEN blocked := blocked + 1;
  END;
  SELECT string_agg(DISTINCT e->>'seed_id', ',' ORDER BY e->>'seed_id') INTO seed_list
    FROM scan_job j, jsonb_array_elements(j.target_refs) e
   WHERE j.job_id = job_main AND e ? 'seed_id';
  IF seed_list IS DISTINCT FROM concat_ws(',',seed_domain,seed_cidr,seed_keyword) THEN
    RAISE EXCEPTION 'accepted job lost its seeds after the replay attempt: %', seed_list;
  END IF;

  -- 8. CIDR -> IP: the ip asset keeps the CIDR seed as its origin in the provenance row.
  INSERT INTO asset (asset_id,canonical_key,kind,first_seen,last_seen,first_job_id,normalization_version)
    VALUES (asset_ip,'ip:10.20.0.5','ip',now(),now(),job_main,'aegis-norm/1');
  INSERT INTO asset_provenance (provenance_id,asset_id,campaign_id,from_target_id,source_job_id,provider,observed_at)
    VALUES ('01900000-0000-7000-8000-000000000181',asset_ip,camp_a,seed_cidr,job_main,'subfinder',now());
  IF NOT EXISTS (SELECT 1 FROM asset_provenance WHERE asset_id = asset_ip AND from_target_id = seed_cidr AND campaign_id = camp_a) THEN
    RAISE EXCEPTION 'expanded ip asset lost its CIDR seed origin';
  END IF;
  BEGIN
    INSERT INTO asset_provenance (provenance_id,asset_id,campaign_id,from_target_id,source_job_id,provider,observed_at)
      VALUES ('01900000-0000-7000-8000-000000000182',asset_ip,camp_a,seed_other,job_main,'subfinder',now());
  EXCEPTION WHEN foreign_key_violation THEN provenance_blocked := provenance_blocked + 1;
  END;

  -- 9. A job row without target_refs (history predating 0005) is never eligible for dispatch.
  SELECT count(*) INTO queued_legacy FROM scan_job j
   WHERE j.status = 'QUEUED' AND j.manifest_sha256 IS NOT NULL AND j.target_refs IS NULL
     AND NOT EXISTS (SELECT 1 FROM job_dependency d JOIN scan_job p ON p.job_id = d.depends_on_job_id
                      WHERE d.job_id = j.job_id AND p.status <> 'SUCCEEDED');
  IF queued_legacy <> 0 THEN
    RAISE EXCEPTION '% job(s) without target_refs would be dispatched', queued_legacy;
  END IF;

  IF blocked <> 4 THEN RAISE EXCEPTION 'only % / 4 missing-refs/cross-campaign/immutability/replay guards blocked', blocked; END IF;
  IF shape_blocked <> 5 THEN RAISE EXCEPTION 'only % / 5 malformed TargetRef lists rejected', shape_blocked; END IF;
  IF provenance_blocked <> 1 THEN RAISE EXCEPTION 'cross-campaign provenance seed not blocked'; END IF;
  RAISE NOTICE 'target refs: seed+canonical-key job accepted; 4/4 missing-refs/cross-campaign/immutability/replay guards PASS';
  RAISE NOTICE 'target refs: 5/5 malformed lists rejected; CIDR->IP provenance keeps seed, cross-campaign provenance seed blocked';
END $$;
ROLLBACK;
