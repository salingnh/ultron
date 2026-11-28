-- 0009_intel_sync_runs.sql: a run is RUNNING until it finished, and a finished run has a time.
--
-- The schedule needs an auditable attempt record: a failed leg writes no snapshot, so without this
-- row the operator cannot tell a quiet feed from a broken one. Everything is rolled back.
SET search_path = aegis, public;
BEGIN;
DO $$
DECLARE
  running uuid := '01900000-0000-7000-8000-000000090001';
  succeeded uuid := '01900000-0000-7000-8000-000000090002';
  blocked int := 0;
  stored_legs jsonb;
BEGIN
  -- 1. A running attempt has no finish time.
  INSERT INTO intel_sync_run (run_id, trigger, status, started_at)
  VALUES (running, 'schedule', 'RUNNING', '2026-12-01T03:00:00Z');

  -- 2. A finished attempt carries its time, legs and (on failure) the error.
  INSERT INTO intel_sync_run (run_id, trigger, status, started_at, finished_at, legs, error)
  VALUES (succeeded, 'manual', 'SUCCEEDED', '2026-12-01T04:00:00Z', '2026-12-01T04:30:00Z',
          '{"nvd":{"records":1},"kev":{"status":"skipped"}}'::jsonb, NULL);

  SELECT i.legs INTO stored_legs FROM intel_sync_run i WHERE i.run_id = succeeded;
  IF stored_legs ->> 'nvd' IS NULL THEN
    RAISE EXCEPTION 'the legs document was not stored';
  END IF;

  -- 3. A finished row without a finish time is refused (three-valued: the missing time must fail).
  BEGIN
    INSERT INTO intel_sync_run (run_id, trigger, status)
    VALUES ('01900000-0000-7000-8000-000000090003', 'schedule', 'SUCCEEDED');
    RAISE EXCEPTION 'a finished run without finished_at was accepted';
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;

  -- 4. A RUNNING row cannot already have a finish time.
  BEGIN
    INSERT INTO intel_sync_run (run_id, trigger, status, finished_at)
    VALUES ('01900000-0000-7000-8000-000000090004', 'schedule', 'RUNNING', now());
    RAISE EXCEPTION 'a running run with finished_at was accepted';
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;

  -- 5. The vocabulary is closed on both axes.
  BEGIN
    INSERT INTO intel_sync_run (run_id, trigger, status)
    VALUES ('01900000-0000-7000-8000-000000090005', 'timer', 'RUNNING');
    RAISE EXCEPTION 'an unknown trigger was accepted';
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;
  BEGIN
    INSERT INTO intel_sync_run (run_id, trigger, status)
    VALUES ('01900000-0000-7000-8000-000000090006', 'schedule', 'PARTIAL');
    RAISE EXCEPTION 'an unknown status was accepted';
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;

  IF blocked <> 4 THEN
    RAISE EXCEPTION 'expected 4 refused rows, counted %', blocked;
  END IF;
END $$;
ROLLBACK;
