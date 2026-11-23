-- R-1 / R-2 (S1 gate re-review): a rule added by 0012 must not lock the rows that predate it.
--
-- Upgrade chain only: the fixture tests/fixtures/pre-0012-row-shapes.sql loads the two shapes that
-- 0012 made illegal (a label proposer, and a `targets` projection that carries the seed's own
-- canonical key) before 0012 runs. 0014 must hold both rows for dispatch and leave them cancellable
-- and finalisable, which is what README §Dữ liệu và migration promises for history.
-- ROLLBACK leaves the test database unchanged.
SET search_path=aegis,public;
BEGIN;
DO $$
DECLARE
  job_label uuid := '01900000-0000-7000-8000-0000000d1941';
  job_proj  uuid := '01900000-0000-7000-8000-0000000d1942';
  blocked int := 0;
  out text;
BEGIN
  -- 1. Both rows exist and are held exactly for their own shape; nothing else is claimed.
  IF NOT EXISTS (SELECT 1 FROM scan_job WHERE job_id = job_label
                  AND dispatch_block_reasons = ARRAY['LEGACY_PROPOSER_LABEL']::text[]) THEN
    RAISE EXCEPTION 'a label-proposer row is not held exactly for LEGACY_PROPOSER_LABEL (%)',
      (SELECT dispatch_block_reasons FROM scan_job WHERE job_id = job_label);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM scan_job WHERE job_id = job_proj
                  AND dispatch_block_reasons = ARRAY['LEGACY_TARGET_PROJECTION']::text[]) THEN
    RAISE EXCEPTION 'a row whose targets exceed its refs is not held exactly for LEGACY_TARGET_PROJECTION (%)',
      (SELECT dispatch_block_reasons FROM scan_job WHERE job_id = job_proj);
  END IF;

  -- 2. Held means "not startable", not "locked": the same probes 0011 uses for the other reasons.
  BEGIN
    UPDATE scan_job SET status = 'VALIDATING' WHERE job_id = job_label;
    RAISE EXCEPTION 'a held label-proposer job moved to VALIDATING';
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;
  BEGIN
    UPDATE scan_job SET attempt = attempt + 1 WHERE job_id = job_label;
    RAISE EXCEPTION 'a held label-proposer job bumped its attempt';
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;

  -- 3. R-2a: the row is still cancellable (the 0012 CHECK used to fail here, so it could not be closed).
  out := aegis.request_job_cancel(job_label, '{"kind":"operator","id":"r2-test"}', 'legacy shape');
  IF out <> 'requested' THEN
    RAISE EXCEPTION 'a held label-proposer row could not be cancelled: %', out;
  END IF;
  out := aegis.record_job_callback(job_label, 1, 1, 'CANCELLED', NULL, NULL, NULL);
  IF out <> 'terminalized' THEN
    RAISE EXCEPTION 'a held label-proposer row could not record its cancel: %', out;
  END IF;

  -- 4. R-2b: the in-flight row still finalises; the old CHECK made every UPDATE fail.
  out := aegis.record_job_callback(job_proj, 1, 1, 'SUCCEEDED', '01900000-0000-7000-8000-0000000d1962', NULL, repeat('e',64));
  IF out <> 'terminalized' THEN
    RAISE EXCEPTION 'a row whose targets exceed its refs could not finalise: %', out;
  END IF;

  -- 5. The rule stays for new rows: both shapes are refused at INSERT (0012/0014 triggers), so
  --    "history keeps its shape" does not become "the rule is gone".
  BEGIN
    INSERT INTO scan_job (SELECT (jsonb_populate_record(NULL::scan_job, to_jsonb(j) || jsonb_build_object(
        'job_id','01900000-0000-7000-8000-0000000d1943','job_fingerprint',repeat('93',32),
        'status','QUEUED','started_at',NULL,'finished_at',NULL,'envelope_event_id',NULL,
        'attempt',1,'generation',1,'dispatch_block_reasons',NULL))).* FROM scan_job j WHERE job_id = job_label);
    RAISE EXCEPTION 'a new row with a label proposer was accepted';
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;
  BEGIN
    INSERT INTO scan_job (SELECT (jsonb_populate_record(NULL::scan_job, to_jsonb(j) || jsonb_build_object(
        'job_id','01900000-0000-7000-8000-0000000d1944','job_fingerprint',repeat('94',32),
        'status','QUEUED','started_at',NULL,'finished_at',NULL,'envelope_event_id',NULL,
        'attempt',1,'generation',1,'dispatch_block_reasons',NULL,
        'input','{"targets":["pre12.example"]}'::jsonb))).* FROM scan_job j WHERE job_id = job_proj);
    RAISE EXCEPTION 'a new row whose targets exceed its refs was accepted';
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;

  IF blocked <> 4 THEN
    RAISE EXCEPTION 'R-2: % / 4 checks blocked', blocked;
  END IF;
  RAISE NOTICE 'R-2 legacy rows: 2 held for their own shape only, cancel + terminal still work, 4/4 dispatch and new-row probes blocked';
END $$;
ROLLBACK;
