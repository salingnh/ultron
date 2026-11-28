-- 0012_severity_input_revision.sql: the dedup key of a severity assessment is a database
-- guarantee, not a JSON member a writer may skip.
--
-- The two columns are generated from the stored record (the contract requires them there), the
-- CHECK ties dedup_key to finding_id + input_revision, and the unique index makes the retry rule
-- true even when two callers race: one (finding, input revision) pair, one row. Everything is
-- rolled back.
SET search_path = aegis, public;
BEGIN;
DO $$
DECLARE
  scope uuid := '01900000-0000-7000-8000-000000200001';
  camp  uuid := '01900000-0000-7000-8000-000000200002';
  seed  uuid := '01900000-0000-7000-8000-000000200003';
  job   uuid := '01900000-0000-7000-8000-000000200004';
  asset uuid := '01900000-0000-7000-8000-000000200005';
  find  uuid := '01900000-0000-7000-8000-000000200006';
  first uuid := '01900000-0000-7000-8000-000000200007';
  other uuid := '01900000-0000-7000-8000-000000200008';
  stored bigint;
  stored_key text;
  refused int := 0;
BEGIN
  INSERT INTO policy_snapshot
    VALUES ('roe-9', camp, '{"network_profile":"lab","max_parallel_jobs":10,"max_duration_hours":168}',
            repeat('6', 64), '{"kind":"operator","id":"fixture"}');
  INSERT INTO scope_snapshot VALUES (scope, camp, '{"domains":["severity.example"]}');
  INSERT INTO campaign (campaign_id, name, objective, current_policy_version, scope_id, created_by)
    VALUES (camp, 'Severity input revision', '0012 fixture', 'roe-9', scope,
            '{"kind":"operator","id":"fixture"}');
  INSERT INTO campaign_target VALUES (seed, scope, 'domain', 'severity.example',
                                      'dns:severity.example');
  INSERT INTO policy_decision (decision_id, campaign_id, capability, provider, targets, input,
                               decision, rationale, requested_by, target_refs, policy_version,
                               scope_id, idempotency_key, trace_id)
    VALUES ('01900000-0000-7000-8000-000000200009', camp, 'dns.enumerate_subdomains', 'subfinder',
            '{dns:severity.example}', '{"targets":["severity.example"]}', 'approved',
            '0012 job', '{"kind":"operator","id":"fixture"}',
            jsonb_build_array(jsonb_build_object('seed_id', seed),
                              jsonb_build_object('canonical_key', 'dns:severity.example')),
            'roe-9', scope, '0012:1', repeat('6', 32));
  INSERT INTO scan_job (job_id, campaign_id, decision_id, capability, provider, provider_version,
                        adapter_version, image_digest, manifest_sha256, scan_cycle, job_fingerprint,
                        policy_version, scope_id, input, targets, target_refs, requested_by,
                        rationale, trace_id)
    VALUES (job, camp, '01900000-0000-7000-8000-000000200009', 'dns.enumerate_subdomains',
            'subfinder', 'v2.17.0', '1.0.2', 'sha256:' || repeat('5', 64), repeat('6', 64),
            '01900000-0000-7000-8000-00000020000a', repeat('7', 64), 'roe-9', scope,
            '{"targets":["severity.example"]}', '{dns:severity.example}',
            jsonb_build_array(jsonb_build_object('seed_id', seed),
                              jsonb_build_object('canonical_key', 'dns:severity.example')),
            '{"kind":"operator","id":"fixture"}', '0012 job', repeat('6', 32));
  INSERT INTO asset (asset_id, canonical_key, kind, first_seen, last_seen, normalization_version)
    VALUES (asset, 'dns:severity.example', 'domain', now(), now(), 'aegis-norm/1');
  INSERT INTO finding (finding_id, fingerprint, asset_id, rule_id, category, title,
                       vulnerability_ids, status, first_seen, last_seen, first_job_id,
                       first_campaign_id)
    VALUES (find, repeat('a', 64), asset, 'cve:CVE-2099-0001', 'vulnerability', '0012 fixture',
            '{CVE-2099-0001}', 'CANDIDATE', now(), now(), job, camp);

  -- 1. The columns are read out of the record, not supplied by the writer.
  INSERT INTO severity_assessment (assessment_id, finding_id, severity, assessment, kind, trigger)
    VALUES (first, find, 'UNRATED',
            jsonb_build_object(
              'severity', 'UNRATED',
              'reasons', jsonb_build_array('fixture'),
              'uncertainty', jsonb_build_array(),
              'recommended_actions', jsonb_build_array(),
              'assessed_by', jsonb_build_object('kind', 'rule'),
              'inputs', '{}'::jsonb,
              'trigger', 'scan',
              'input_revision', 42,
              'dedup_key', 'severity:' || find || ':42',
              'raw_signals', jsonb_build_array(jsonb_build_object('kind', 'finding', 'ref', find)),
              'failure', jsonb_build_object('code', 'DEPENDENCY_MISSING',
                                            'message', 'fixture', 'attempt', 1)),
            'rule', 'scan');
  SELECT input_revision, dedup_key INTO stored, stored_key
    FROM severity_assessment WHERE assessment_id = first;
  IF stored <> 42 OR stored_key <> 'severity:' || find || ':42' THEN
    RAISE EXCEPTION 'the generated columns do not mirror the record (%, %)', stored, stored_key;
  END IF;

  -- 2. The same finding at the same revision is one row, even for a different trigger: that is the
  --    retry rule the unique index enforces.
  BEGIN
    INSERT INTO severity_assessment (assessment_id, finding_id, severity, assessment, kind, trigger)
      VALUES ('01900000-0000-7000-8000-00000020000b', find, 'UNRATED',
              jsonb_build_object(
                'severity', 'UNRATED',
                'reasons', jsonb_build_array('retry'),
                'uncertainty', jsonb_build_array(),
                'recommended_actions', jsonb_build_array(),
                'assessed_by', jsonb_build_object('kind', 'rule'),
                'inputs', '{}'::jsonb,
                'trigger', 'operator_request',
                'input_revision', 42,
                'dedup_key', 'severity:' || find || ':42',
                'raw_signals', jsonb_build_array(jsonb_build_object('kind', 'finding', 'ref', find)),
                'failure', jsonb_build_object('code', 'DEPENDENCY_MISSING',
                                              'message', 'retry', 'attempt', 1)),
              'rule', 'operator_request');
  EXCEPTION WHEN unique_violation THEN refused := refused + 1;
  END;

  -- 3. A new input revision is a new row: this is what an intel change or a new scan buys.
  INSERT INTO severity_assessment (assessment_id, finding_id, severity, assessment, kind, trigger)
    VALUES (other, find, 'UNRATED',
            jsonb_build_object(
              'severity', 'UNRATED',
              'reasons', jsonb_build_array('new revision'),
              'uncertainty', jsonb_build_array(),
              'recommended_actions', jsonb_build_array(),
              'assessed_by', jsonb_build_object('kind', 'rule'),
              'inputs', '{}'::jsonb,
              'trigger', 'intel_revision',
              'input_revision', 43,
              'dedup_key', 'severity:' || find || ':43',
              'raw_signals', jsonb_build_array(jsonb_build_object('kind', 'finding', 'ref', find)),
              'failure', jsonb_build_object('code', 'DEPENDENCY_MISSING',
                                            'message', 'new revision', 'attempt', 1)),
            'rule', 'intel_revision');

  -- 4. A record with no revision, or a dedup_key that names another one, is refused by the
  --    generated column / the check.
  BEGIN
    INSERT INTO severity_assessment (assessment_id, finding_id, severity, assessment, kind, trigger)
      VALUES ('01900000-0000-7000-8000-00000020000c', find, 'UNRATED', '{"severity":"UNRATED"}',
              'rule', 'scan');
  EXCEPTION WHEN not_null_violation THEN refused := refused + 1;
  END;
  BEGIN
    INSERT INTO severity_assessment (assessment_id, finding_id, severity, assessment, kind, trigger)
      VALUES ('01900000-0000-7000-8000-00000020000d', find, 'UNRATED',
              jsonb_build_object(
                'severity', 'UNRATED',
                'reasons', jsonb_build_array('mismatch'),
                'uncertainty', jsonb_build_array(),
                'recommended_actions', jsonb_build_array(),
                'assessed_by', jsonb_build_object('kind', 'rule'),
                'inputs', '{}'::jsonb,
                'trigger', 'scan',
                'input_revision', 44,
                'dedup_key', 'severity:' || find || ':45',
                'raw_signals', jsonb_build_array(jsonb_build_object('kind', 'finding', 'ref', find)),
                'failure', jsonb_build_object('code', 'DEPENDENCY_MISSING',
                                              'message', 'mismatch', 'attempt', 1)),
              'rule', 'scan');
  EXCEPTION WHEN check_violation THEN refused := refused + 1;
  END;

  IF refused <> 3 THEN
    RAISE EXCEPTION 'the dedup constraints accepted % of 3 malformed writes', 3 - refused;
  END IF;

  RAISE NOTICE 'severity input revision: generated mirror, unique per (finding, revision), key shape';
END $$;
ROLLBACK;
