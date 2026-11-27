-- 0008_match_retraction.sql: a decision row is a match or a retraction with a reason, never both.
--
-- The retraction is how "the intel changed and this candidate is gone" enters the append-only
-- decision table: M20 writes `matched = false` at the new `vuln_rev_id` with a `retraction_reason`,
-- so the newest row of an (asset, vulnerability) pair is what the read model and the projector
-- follow. Everything is rolled back.
SET search_path = aegis, public;
BEGIN;
DO $$
DECLARE
  snap uuid := '01900000-0000-7000-8000-000000080001';
  rev_old uuid := '01900000-0000-7000-8000-000000080002';
  rev_new uuid := '01900000-0000-7000-8000-000000080003';
  svc uuid := '01900000-0000-7000-8000-000000080004';
  matched_row uuid := '01900000-0000-7000-8000-000000080005';
  retracted uuid := '01900000-0000-7000-8000-000000080006';
  blocked int := 0;
  newest_reason text;
  rows int;
BEGIN
  INSERT INTO intel_snapshot (snapshot_id, feed, version, snapshot_at, record_count, source_uri, content_sha256)
  VALUES (snap, 'nvd', '0008-test', '2026-11-27T00:00:00Z', 1, 'nvd-api2', repeat('c', 64));

  INSERT INTO vulnerability_revision (
    vuln_rev_id, vulnerability_id, source, snapshot_id, affected, references_, withdrawn, content_hash
  ) VALUES
    (rev_old, 'CVE-2024-40898', 'nvd', snap,
     '{"cpe_match":[{"criteria":"cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*","vulnerable":true}]}'::jsonb,
     '[]'::jsonb, false, repeat('d', 64)),
    (rev_new, 'CVE-2024-40898', 'nvd', snap,
     '{"cpe_match":[{"criteria":"cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*","vulnerable":true}]}'::jsonb,
     '[]'::jsonb, false, repeat('e', 64));

  INSERT INTO asset (asset_id, canonical_key, kind, first_seen, last_seen, normalization_version)
  VALUES (svc, 'service:10.114.53.215:80/tcp', 'service', now(), now(), 'aegis-norm/1');

  -- 1. A match carries no reason; the old rows keep validating after the new constraint.
  INSERT INTO package_vuln_match (
    match_id, package_asset_id, vulnerability_id, vuln_rev_id, match_method,
    matched, confidence, snapshot_id
  ) VALUES (matched_row, svc, 'CVE-2024-40898', rev_old, 'cpe_range', true, 0.6, snap);

  -- 2. A retraction at the next revision, with its reason, is a second row for the same pair.
  INSERT INTO package_vuln_match (
    match_id, package_asset_id, vulnerability_id, vuln_rev_id, match_method,
    matched, snapshot_id, retraction_reason
  ) VALUES (retracted, svc, 'CVE-2024-40898', rev_new, 'cpe_range', false, snap,
            'PLATFORM_UNCONFIRMED');

  SELECT count(*) INTO rows
    FROM package_vuln_match m
   WHERE m.package_asset_id = svc AND m.vulnerability_id = 'CVE-2024-40898';
  IF rows <> 2 THEN
    RAISE EXCEPTION 'expected the match and the retraction to coexist, found % row(s)', rows;
  END IF;

  -- 3. The newest row of the pair is the retraction, which is what the read model follows.
  SELECT m.retraction_reason INTO newest_reason
    FROM package_vuln_match m
   WHERE m.package_asset_id = svc AND m.vulnerability_id = 'CVE-2024-40898'
   ORDER BY m.created_at DESC, m.match_id DESC
   LIMIT 1;
  IF newest_reason IS DISTINCT FROM 'PLATFORM_UNCONFIRMED' THEN
    RAISE EXCEPTION 'the newest row of the pair is not the retraction: reason %', newest_reason;
  END IF;

  -- 4. A retraction without a reason is refused: the history must say why the candidate is gone.
  BEGIN
    INSERT INTO package_vuln_match (
      match_id, package_asset_id, vulnerability_id, vuln_rev_id, match_method, matched, snapshot_id
    ) VALUES ('01900000-0000-7000-8000-000000080007', svc, 'CVE-2024-40898', rev_new, 'purl_range',
              false, snap);
    RAISE EXCEPTION 'package_vuln_match accepted a retraction without a reason';
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;

  -- 5. An unknown reason is refused (the vocabulary is M20's, mirrored by the constraint).
  BEGIN
    INSERT INTO package_vuln_match (
      match_id, package_asset_id, vulnerability_id, vuln_rev_id, match_method,
      matched, snapshot_id, retraction_reason
    ) VALUES ('01900000-0000-7000-8000-000000080008', svc, 'CVE-2024-40898', rev_new, 'purl_range',
              false, snap, 'BECAUSE');
    RAISE EXCEPTION 'package_vuln_match accepted an unknown retraction_reason';
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;

  -- 6. A match cannot carry a reason.
  BEGIN
    INSERT INTO package_vuln_match (
      match_id, package_asset_id, vulnerability_id, vuln_rev_id, match_method,
      matched, snapshot_id, retraction_reason
    ) VALUES ('01900000-0000-7000-8000-000000080009', svc, 'CVE-2024-40898', rev_new, 'purl_range',
              true, snap, 'WITHDRAWN');
    RAISE EXCEPTION 'package_vuln_match accepted a reason on a match';
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;

  IF blocked <> 3 THEN
    RAISE EXCEPTION 'expected 3 refused rows, counted %', blocked;
  END IF;
END $$;
ROLLBACK;
