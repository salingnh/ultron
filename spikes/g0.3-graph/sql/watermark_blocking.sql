-- G0.3b spike-only: watermark refresh with a blocking exclusive lock.
--
-- 0008 uses pg_try_advisory_xact_lock: it publishes only when no writer transaction is
-- in flight, and backs off when one is. With many concurrent writers that instant can
-- never happen, so the watermark (and therefore every consumer) can starve under load.
-- This variant waits for the exclusive lock instead: PostgreSQL queues new shared
-- requests behind the waiter, so the refresh is guaranteed to run once the current
-- writers commit, at the cost of pausing new writer transactions for that instant.
--
-- It must be applied after one of the allocator variant files, which define
-- aegis.spike_publication_last(). It is a measurement of an alternative contract,
-- not a proposed migration.
BEGIN;
SET LOCAL search_path = aegis, public;

CREATE OR REPLACE FUNCTION aegis.outbox_watermark_refresh(p_dispatcher text, p_fence bigint) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = aegis, pg_temp AS $$
DECLARE v bigint;
BEGIN
  PERFORM aegis.outbox_fence_check(p_dispatcher, p_fence);
  PERFORM pg_advisory_xact_lock(aegis.outbox_publication_lock_key());
  UPDATE outbox_watermark
     SET published_upto = greatest(published_upto, aegis.spike_publication_last()), updated_at = now()
   WHERE id;
  SELECT published_upto INTO v FROM outbox_watermark;
  RETURN v;
END $$;

COMMIT;
