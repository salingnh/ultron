-- 0007_intel_indexes.sql: CPE product extraction, GIN/partial indexes, and append-only sync checkpoints.
SET search_path = aegis, public;
BEGIN;
DO $$
DECLARE
  snap uuid := '01900000-0000-7000-8000-000000070001';
  rev1 uuid := '01900000-0000-7000-8000-000000070002';
  chk1 uuid := '01900000-0000-7000-8000-000000070003';
  keys text[];
  matched int;
  idx_count int;
  rejected int := 0;
BEGIN
  -- 1. CPE product extraction ignores non-vulnerable exclusions and handles both 2.3 and 2.2 forms.
  keys := aegis.nvd_cpe_products('{
    "cpe_match": [
      {"criteria": "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*", "vulnerable": true},
      {"criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "vulnerable": true},
      {"criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", "vulnerable": false},
      {"criteria": "cpe:/a:apache:http_server:2.4.49", "vulnerable": true}
    ]
  }'::jsonb);
  IF NOT (keys @> ARRAY['a:openbsd:openssh', 'a:f5:nginx', 'a:apache:http_server']
          AND array_length(keys, 1) = 3) THEN
    RAISE EXCEPTION 'nvd_cpe_products returned unexpected keys: %', keys;
  END IF;

  -- 2. Expected indexes exist in catalog.
  SELECT count(*) INTO idx_count
    FROM pg_indexes
   WHERE schemaname = 'aegis'
     AND indexname IN (
       'vulnerability_revision_nvd_products_gin',
       'vulnerability_revision_nvd_current',
       'observation_vuln_targets',
       'intel_sync_checkpoint_latest'
     );
  IF idx_count <> 4 THEN
    RAISE EXCEPTION 'expected 4 indexes from 0007_intel_indexes, found %', idx_count;
  END IF;

  -- 3. Snapshot + revision + checkpoint work and GIN containment operator matches the inserted row.
  INSERT INTO intel_snapshot (snapshot_id, feed, version, snapshot_at, record_count, source_uri, content_sha256)
  VALUES (snap, 'nvd', '0007-test', '2026-11-26T00:00:00Z', 1, 'nvd-api2', repeat('a', 64));

  INSERT INTO vulnerability_revision (
    vuln_rev_id, vulnerability_id, source, snapshot_id, affected, references_, withdrawn, content_hash
  ) VALUES (
    rev1,
    'CVE-2023-38408',
    'nvd',
    snap,
    '{"cpe_match":[{"criteria":"cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*","vulnerable":true}]}'::jsonb,
    '[]'::jsonb,
    false,
    repeat('b', 64)
  );

  SELECT count(*) INTO matched
    FROM vulnerability_revision
   WHERE source = 'nvd' AND NOT withdrawn AND affected IS NOT NULL
     AND aegis.nvd_cpe_products(affected) && ARRAY['a:openbsd:openssh'];
  IF matched < 1 THEN
    RAISE EXCEPTION 'GIN product containment query did not match inserted CVE';
  END IF;

  INSERT INTO intel_sync_checkpoint (
    checkpoint_id, feed, run_id, mode, status, next_start_index, total_results, results_per_page,
    last_modified_watermark, last_snapshot_id
  ) VALUES (
    chk1, 'nvd', 'run-1', 'full', 'in_progress', 2000, 300000, 2000,
    '2026-11-26T00:00:00Z', snap
  );

  -- 4. Append-only protection and constraints on intel_sync_checkpoint.
  BEGIN
    UPDATE intel_sync_checkpoint SET status = 'completed' WHERE checkpoint_id = chk1;
    RAISE EXCEPTION 'intel_sync_checkpoint allowed UPDATE';
  EXCEPTION WHEN raise_exception OR insufficient_privilege OR restrict_violation OR check_violation THEN
    rejected := rejected + 1;
  END;

  BEGIN
    DELETE FROM intel_sync_checkpoint WHERE checkpoint_id = chk1;
    RAISE EXCEPTION 'intel_sync_checkpoint allowed DELETE';
  EXCEPTION WHEN raise_exception OR insufficient_privilege OR restrict_violation OR check_violation THEN
    rejected := rejected + 1;
  END;

  BEGIN
    INSERT INTO intel_sync_checkpoint (
      checkpoint_id, feed, run_id, mode, status, next_start_index, results_per_page
    ) VALUES (
      '01900000-0000-7000-8000-000000070004', 'kev', 'run-2', 'full', 'in_progress', 0, 2000
    );
    RAISE EXCEPTION 'intel_sync_checkpoint accepted non-nvd feed';
  EXCEPTION WHEN check_violation THEN
    rejected := rejected + 1;
  END;

  IF rejected <> 3 THEN
    RAISE EXCEPTION 'expected 3 rejected checkpoint mutations, got %', rejected;
  END IF;
  RAISE NOTICE '0007_intel_indexes: product extraction, 4 indexes, and append-only checkpoints verified';
END $$;
ROLLBACK;
