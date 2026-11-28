-- 0013_artifact_findings.sql: image seeds and the scanner candidate record.
--
-- Two properties are the point of this migration:
--   * an `oci_image` campaign seed is accepted (and only a canonical digest key), while the old
--     seed kinds keep working and an invented kind is still refused;
--   * `finding_candidate` keeps what M27 validated: it cannot lose its evidence, cannot carry a
--     status/severity outside the contract's closed sets, refuses a duplicate report of the same
--     candidate by the same scan/provider, and is append-only (a candidate is what a scan said).
-- Everything is rolled back.
SET search_path = aegis, public;
BEGIN;
DO $$
DECLARE
  scope uuid := '01900000-0000-7000-8000-0000000d0001';
  camp  uuid := '01900000-0000-7000-8000-0000000d0002';
  image uuid := '01900000-0000-7000-8000-0000000d0003';
  decision uuid := '01900000-0000-7000-8000-0000000d0004';
  job   uuid := '01900000-0000-7000-8000-0000000d0005';
  event uuid := '01900000-0000-7000-8000-0000000d0006';
  pkg   uuid := '01900000-0000-7000-8000-0000000d0007';
  revision_id bigint;
  candidate uuid := '01900000-0000-7000-8000-0000000d0008';
  location_hash text := repeat('a', 64);
  refused int := 0;
  image_digest text := 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
  image_key text := 'oci:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
  kind text;
BEGIN
  INSERT INTO policy_snapshot
    VALUES ('roe-13', camp, '{"network_profile":"lab","max_parallel_jobs":10,"max_duration_hours":168}',
            repeat('5', 64), '{"kind":"operator","id":"fixture"}');
  INSERT INTO scope_snapshot
    VALUES (scope, camp, jsonb_build_object('images', jsonb_build_array(image_digest)));
  INSERT INTO campaign (campaign_id, name, objective, current_policy_version, scope_id, created_by)
    VALUES (camp, 'Artifact findings', '0013 fixture', 'roe-13', scope,
            '{"kind":"operator","id":"fixture"}');
  INSERT INTO campaign_target VALUES (image, scope, 'oci_image', image_digest, image_key);
  INSERT INTO asset (asset_id, canonical_key, kind, first_seen, last_seen, first_job_id,
                     normalization_version)
    VALUES (pkg, 'purl:pkg:apk/alpine/krb5-libs@1.22.2-r1', 'package', now(), now(), NULL,
            'aegis-norm/1');
  INSERT INTO policy_decision (decision_id, campaign_id, capability, provider, targets, input,
                               decision, rationale, requested_by, target_refs, policy_version,
                               scope_id, idempotency_key, trace_id)
    VALUES (decision, camp, 'vuln.scan_artifact', 'trivy',
            '{}'::text[],
            jsonb_build_object('targets', jsonb_build_array(image_digest)), 'approved', '0013 fixture',
            '{"kind":"operator","id":"fixture"}',
            jsonb_build_array(jsonb_build_object('seed_id', image)), 'roe-13', scope,
            '0013:1', repeat('c', 32));
  INSERT INTO scan_job (job_id, campaign_id, decision_id, capability, provider, provider_version,
                        adapter_version, image_digest, manifest_sha256, scan_cycle, job_fingerprint,
                        policy_version, scope_id, input, targets, target_refs, requested_by,
                        rationale, trace_id)
    VALUES (job, camp, decision, 'vuln.scan_artifact', 'trivy', 'v0.76.2', '1.0.0',
            'sha256:' || repeat('d', 64), repeat('6', 64),
            '01900000-0000-7000-8000-0000000d0009', repeat('7', 64), 'roe-13', scope,
            jsonb_build_object('targets', jsonb_build_array(image_digest)),
            '{}'::text[],
            jsonb_build_array(jsonb_build_object('seed_id', image)),
            '{"kind":"operator","id":"fixture"}', '0013 fixture', repeat('c', 32));
  INSERT INTO ingestion_inbox (event_id, dedup_key, job_id, payload_hash, hash_version, status)
    VALUES (event, 'job:' || job || ':envelope', job, repeat('8', 64), 'aegis-c14n/1', 'received');
  INSERT INTO graph_revision (campaign_id, causal_job_id, envelope_event_id)
    VALUES (camp, job, event) RETURNING revision INTO revision_id;

  -- 1. The image seed is a row; its canonical key is the identity the artifact job points at.
  SELECT canonical_key INTO kind FROM campaign_target WHERE target_id = image;
  IF kind IS DISTINCT FROM image_key THEN
    RAISE EXCEPTION 'the image seed lost its canonical key (%)', kind;
  END IF;

  -- 2. The old kinds still pass, and a made-up kind is still refused.
  INSERT INTO campaign_target VALUES ('01900000-0000-7000-8000-0000000d0010', scope, 'domain',
                                      'seed.example', 'dns:seed.example');
  BEGIN
    INSERT INTO campaign_target VALUES ('01900000-0000-7000-8000-0000000d0011', scope, 'image',
                                        'sha256:' || repeat('b', 64), NULL);
  EXCEPTION WHEN check_violation THEN refused := refused + 1;
  END;

  -- 3. A validated candidate is stored with its evidence and its source location.
  INSERT INTO finding_candidate
    (candidate_id, campaign_id, scan_id, envelope_event_id, revision, subject_asset_id, provider,
     provider_version, rule_id, category, title, location, location_hash, vulnerability_ids,
     cwe_ids, scanner_severity, fingerprint_context, confidence, evidence_ids, observed_at)
    VALUES (candidate, camp, job, event, revision_id, pkg, 'trivy', 'v0.76.2',
            'cve:CVE-2026-107364', 'vulnerability', 'krb5 DoS',
            '{"package_purl":"pkg:apk/alpine/krb5-libs@1.22.2-r1"}', location_hash,
            '{CVE-2026-107364}', '{CWE-125}', 'high', '{"package":"pkg:apk/alpine/krb5-libs"}',
            0.9, ARRAY['01900000-0000-7000-8000-0000000d0012']::uuid[], now());

  -- 4. No evidence is not a candidate (the column refuses it, not a convention).
  BEGIN
    INSERT INTO finding_candidate
      (candidate_id, campaign_id, scan_id, envelope_event_id, revision, subject_asset_id, provider,
       provider_version, rule_id, title, location_hash, evidence_ids, observed_at)
      VALUES ('01900000-0000-7000-8000-0000000d0013', camp, job, event, revision_id, pkg, 'trivy',
              'v0.76.2', 'cve:CVE-1', 'no evidence', repeat('b', 64), '{}', now());
  EXCEPTION WHEN check_violation THEN refused := refused + 1;
  END;

  -- 5. The closed sets hold: no invented category, no invented scanner severity.
  BEGIN
    INSERT INTO finding_candidate
      (candidate_id, campaign_id, scan_id, envelope_event_id, revision, subject_asset_id, provider,
       provider_version, rule_id, category, title, location_hash, evidence_ids, observed_at)
      VALUES ('01900000-0000-7000-8000-0000000d0014', camp, job, event, revision_id, pkg, 'trivy',
              'v0.76.2', 'cve:CVE-2', 'exploit', 'bad category', repeat('c', 64),
              ARRAY['01900000-0000-7000-8000-0000000d0012']::uuid[], now());
  EXCEPTION WHEN check_violation THEN refused := refused + 1;
  END;
  BEGIN
    INSERT INTO finding_candidate
      (candidate_id, campaign_id, scan_id, envelope_event_id, revision, subject_asset_id, provider,
       provider_version, rule_id, title, location_hash, scanner_severity, evidence_ids, observed_at)
      VALUES ('01900000-0000-7000-8000-0000000d0015', camp, job, event, revision_id, pkg, 'trivy',
              'v0.76.2', 'cve:CVE-3', 'bad severity', repeat('d', 64), 'catastrophic',
              ARRAY['01900000-0000-7000-8000-0000000d0012']::uuid[], now());
  EXCEPTION WHEN check_violation THEN refused := refused + 1;
  END;

  -- 6. The same scan+provider cannot report the same candidate twice; a second path is another
  --    location and therefore another row (the parser dedupes, this is the database's guard).
  BEGIN
    INSERT INTO finding_candidate
      (candidate_id, campaign_id, scan_id, envelope_event_id, revision, subject_asset_id, provider,
       provider_version, rule_id, title, location_hash, evidence_ids, observed_at)
      VALUES ('01900000-0000-7000-8000-0000000d0016', camp, job, event, revision_id, pkg, 'trivy',
              'v0.76.2', 'cve:CVE-2026-107364', 'duplicate', location_hash,
              ARRAY['01900000-0000-7000-8000-0000000d0012']::uuid[], now());
  EXCEPTION WHEN unique_violation THEN refused := refused + 1;
  END;
  INSERT INTO finding_candidate
    (candidate_id, campaign_id, scan_id, envelope_event_id, revision, subject_asset_id, provider,
     provider_version, rule_id, title, location_hash, evidence_ids, observed_at)
    VALUES ('01900000-0000-7000-8000-0000000d0017', camp, job, event, revision_id, pkg, 'trivy',
            'v0.76.2', 'cve:CVE-2026-107364', 'second path', repeat('e', 64),
            ARRAY['01900000-0000-7000-8000-0000000d0012']::uuid[], now());

  -- 7. Append-only: a stored candidate cannot be rewritten or deleted.
  BEGIN
    UPDATE finding_candidate SET title = 'rewritten' WHERE candidate_id = candidate;
  EXCEPTION WHEN insufficient_privilege THEN refused := refused + 1;
  END;
  BEGIN
    DELETE FROM finding_candidate WHERE candidate_id = candidate;
  EXCEPTION WHEN insufficient_privilege THEN refused := refused + 1;
  END;

  IF refused <> 7 THEN
    RAISE EXCEPTION 'artifact findings migration accepted % of 7 malformed writes', 7 - refused;
  END IF;

  RAISE NOTICE 'artifact findings: image seed, candidate shape, dedup and append-only enforced';
END $$;
ROLLBACK;
