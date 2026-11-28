-- 0010_distro_fix_data.sql: the distro feed and its retraction reason are accepted, nothing else.
--
-- A distro revision is a CVE on one release; a distro retraction says the distro shipped the fix
-- and is written with its own match method. Everything is rolled back.
SET search_path = aegis, public;
BEGIN;
DO $$
DECLARE
  snap uuid := '01900000-0000-7000-8000-000000100001';
  rev uuid := '01900000-0000-7000-8000-000000100002';
  rev_nvd uuid := '01900000-0000-7000-8000-000000100003';
  nvd_snap uuid := '01900000-0000-7000-8000-000000100004';
  svc uuid := '01900000-0000-7000-8000-000000100005';
  blocked int := 0;
BEGIN
  -- 1. The distro feed is a snapshot/revision source.
  INSERT INTO intel_snapshot (snapshot_id, feed, version, snapshot_at, record_count, source_uri)
  VALUES (snap, 'distro', 'ubuntu-jammy-2026-12-01', '2026-12-01T00:00:00Z', 1, 'fixture');

  INSERT INTO vulnerability_revision (
    vuln_rev_id, vulnerability_id, source, snapshot_id, affected, references_, withdrawn, content_hash
  ) VALUES (
    rev, 'CVE-2024-6387', 'distro', snap,
    '{"distro":{"id":"ubuntu","release":"jammy","codename":"22.04"},
      "packages":{"openssh":{"fixed":"1:8.9p1-3ubuntu0.10","status":"fixed"}}}'::jsonb,
    '[]'::jsonb, false, repeat('f', 64)
  );

  -- 2. A distro retraction uses the distro reason and its own method, so it can sit at the same
  --    NVD revision as the candidate it takes back.
  INSERT INTO intel_snapshot (snapshot_id, feed, version, snapshot_at, record_count, source_uri)
  VALUES (nvd_snap, 'nvd', 'nvd-test', '2026-12-01T00:00:00Z', 1, 'fixture');
  INSERT INTO vulnerability_revision (
    vuln_rev_id, vulnerability_id, source, snapshot_id, affected, references_, withdrawn, content_hash
  ) VALUES (
    rev_nvd, 'CVE-2024-6387', 'nvd', nvd_snap,
    '{"cpe_match":[{"criteria":"cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*","vulnerable":true}]}'::jsonb,
    '[]'::jsonb, false, repeat('a', 64)
  );
  INSERT INTO asset (asset_id, canonical_key, kind, first_seen, last_seen, normalization_version)
  VALUES (svc, 'service:203.0.113.10:22/tcp', 'service', now(), now(), 'aegis-norm/1');
  INSERT INTO package_vuln_match (
    match_id, package_asset_id, vulnerability_id, vuln_rev_id, match_method,
    matched, confidence, snapshot_id
  ) VALUES ('01900000-0000-7000-8000-000000100006', svc, 'CVE-2024-6387', rev_nvd, 'cpe_range',
            TRUE, 0.6, nvd_snap);
  INSERT INTO package_vuln_match (
    match_id, package_asset_id, vulnerability_id, vuln_rev_id, match_method,
    matched, snapshot_id, retraction_reason
  ) VALUES ('01900000-0000-7000-8000-000000100007', svc, 'CVE-2024-6387', rev_nvd,
            'distro_fixed', FALSE, nvd_snap, 'FIXED_BY_DISTRO');

  -- 3. The vocabulary is still closed: an unknown reason is refused.
  BEGIN
    INSERT INTO package_vuln_match (
      match_id, package_asset_id, vulnerability_id, vuln_rev_id, match_method,
      matched, snapshot_id, retraction_reason
    ) VALUES ('01900000-0000-7000-8000-000000100008', svc, 'CVE-2024-6387', rev_nvd,
              'cpe_range', FALSE, nvd_snap, 'BECAUSE');
    RAISE EXCEPTION 'package_vuln_match accepted an unknown retraction_reason';
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;

  -- 4. A match still cannot carry a reason.
  BEGIN
    INSERT INTO package_vuln_match (
      match_id, package_asset_id, vulnerability_id, vuln_rev_id, match_method,
      matched, snapshot_id, retraction_reason
    ) VALUES ('01900000-0000-7000-8000-000000100009', svc, 'CVE-2024-6387', rev_nvd,
              'distro_fixed', TRUE, nvd_snap, 'FIXED_BY_DISTRO');
    RAISE EXCEPTION 'package_vuln_match accepted a reason on a match';
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;

  IF blocked <> 2 THEN
    RAISE EXCEPTION 'expected 2 refused rows, counted %', blocked;
  END IF;
END $$;
ROLLBACK;
