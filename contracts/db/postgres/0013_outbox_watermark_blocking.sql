-- G0.3b / C04 follow-up: watermark refresh waits for the publication lock instead of skipping
-- its publication step whenever a writer is in flight.
--
-- 0008 used pg_try_advisory_xact_lock: an open writer transaction makes the try fail and the
-- watermark keeps its previous value. Under sustained write load that instant never occurs, so
-- the watermark (and every consumer behind it) can starve for the whole write phase. G0.3b
-- measured it at 100 concurrent writers: 936-2 331 blocked refreshes of 1 150-2 483 attempts,
-- watermark advanced once, no event projected for 11-12 s of continuous writing. nextval instead
-- of the counter did not change that, so it is a property of the try-lock.
--
-- Waiting is still a proof, not an optimisation: the exclusive lock queues behind the writer
-- transactions that already hold the shared lock, and new writer requests queue behind this
-- waiter, so it is acquired after those transactions end and before new allocations start. Every
-- publication number at or below the counter is then final (committed or rolled back), and gaps
-- stay legal exactly as 0008 requires.
--
-- The wait is bounded. aegis.outbox_watermark_lock_timeout (default 5s; session GUC) is applied
-- as lock_timeout for this function only, so a timeout raises SQLSTATE 55P03 (loud: no watermark
-- change, no silent skip) and the dispatcher retries on a fresh transaction. A zero, negative or
-- unparsable bound is rejected instead of becoming an unbounded wait. The caller must still use
-- its own short transaction: the exclusive lock is transaction-scoped and holds new writers
-- until commit.
--
-- Independent of 0011/0012: it only needs 0008 and replaces one function body. The dependency is
-- checked, so applying 0013 before 0008 fails instead of creating a broken function.
BEGIN;
SET LOCAL search_path = aegis, public;

DO $$ BEGIN
  IF to_regprocedure('aegis.outbox_watermark_refresh(text,bigint)') IS NULL
     OR to_regclass('aegis.outbox_watermark') IS NULL THEN
    RAISE EXCEPTION '0013 requires 0008_outbox_publication_order.sql';
  END IF;
END $$;

CREATE OR REPLACE FUNCTION aegis.outbox_watermark_refresh(p_dispatcher text, p_fence bigint)
RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = aegis, pg_temp AS $$
DECLARE
  v bigint;
  bound text;
BEGIN
  PERFORM aegis.outbox_fence_check(p_dispatcher, p_fence);
  bound := coalesce(nullif(current_setting('aegis.outbox_watermark_lock_timeout', true), ''), '5s');
  IF bound::interval <= interval '0' THEN
    RAISE EXCEPTION 'aegis.outbox_watermark_lock_timeout must be a positive interval, got %', bound
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  PERFORM set_config('lock_timeout', bound, true);
  BEGIN
    PERFORM pg_advisory_xact_lock(aegis.outbox_publication_lock_key());
  EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'watermark refresh for dispatcher % could not acquire the publication lock within % (writers active); retry on a fresh transaction', p_dispatcher, bound
      USING ERRCODE = 'lock_not_available';
  END;
  UPDATE outbox_watermark
     SET published_upto = greatest(published_upto, (SELECT next_seq - 1 FROM outbox_publication)),
         updated_at = now()
   WHERE id;
  SELECT published_upto INTO v FROM outbox_watermark;
  RETURN v;
END $$;

COMMENT ON FUNCTION aegis.outbox_watermark_refresh(text,bigint) IS
  'C04/0013: advance and return the publication watermark. Waits (blocking, not polling) for the exclusive publication lock, so new writer requests queue behind this waiter and the watermark cannot starve under continuous write load; the wait is bounded by aegis.outbox_watermark_lock_timeout (default 5s) and a timeout raises SQLSTATE 55P03 without changing the watermark (loud; the caller retries). Must run in its own short transaction: the exclusive lock is transaction-scoped and holds new writers until commit. Fence-checked; only the dispatcher role can call it.';

COMMIT;
