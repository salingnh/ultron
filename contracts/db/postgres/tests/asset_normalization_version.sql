-- G1.4a / 0015: an asset names the aegis-norm rules version that minted its canonical key.
-- New rows are refused without the tag, the tag shape is enforced, and the tag is written once.
-- The historical-row rule (rows predating 0015 stay NULL, never relabelled) is checked by the
-- upgrade test in src/tests (tests/test_ingestion_db.py), which applies the chain in two steps.
-- Run after 0015 on the clean and on the upgrade chain; ROLLBACK leaves the database unchanged.
SET search_path=aegis,public;
BEGIN;
DO $$
DECLARE
  a_plain uuid := '01900000-0000-7000-8000-000000001501';
  a_good  uuid := '01900000-0000-7000-8000-000000001502';
  blocked int := 0;
  shape   int := 0;
  fixed   int := 0;
BEGIN
  -- 1. A new canonical key without a rules version has no row: it could not be re-keyed safely.
  BEGIN
    INSERT INTO asset (asset_id,canonical_key,kind,first_seen,last_seen)
      VALUES (a_plain,'dns:normalization-untagged.example','domain',now(),now());
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;
  -- 2. The version label is aegis-norm/<n>, never free text.
  BEGIN
    INSERT INTO asset (asset_id,canonical_key,kind,first_seen,last_seen,normalization_version)
      VALUES (a_plain,'dns:normalization-untagged.example','domain',now(),now(),'jcs-1');
  EXCEPTION WHEN check_violation THEN shape := shape + 1;
  END;

  INSERT INTO asset (asset_id,canonical_key,kind,first_seen,last_seen,normalization_version)
    VALUES (a_good,'dns:normalization-tagged.example','domain',now(),now(),'aegis-norm/1');

  -- 3. Relabelling a stored key would claim a rules version it was not minted with.
  BEGIN
    UPDATE asset SET normalization_version = 'aegis-norm/2' WHERE asset_id = a_good;
  EXCEPTION WHEN insufficient_privilege THEN fixed := fixed + 1;
  END;
  -- The ordinary buffer columns still update.
  UPDATE asset SET last_seen = last_seen + interval '1 second' WHERE asset_id = a_good;

  IF (blocked,shape,fixed) IS DISTINCT FROM (1,1,1) THEN
    RAISE EXCEPTION '0015 guards: expected 1/1/1, got %/%/%', blocked, shape, fixed;
  END IF;
  RAISE NOTICE '0015 asset normalization_version: 3/3 guards, buffer update allowed';
END $$;
ROLLBACK;
