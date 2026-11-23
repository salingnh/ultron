-- G0.3b spike-only: nextval variant of the C04 allocator.
--
-- This is NOT a proposed migration. It replaces the three functions whose body changes
-- when publication numbers come from a sequence instead of the single-row counter:
--
--   outbox_publication_alloc()    nextval under the same shared publication lock
--   outbox_publication_reserve()  nextval + setval block reservation
--   outbox_watermark_refresh()    reads the sequence instead of outbox_publication.next_seq
--
-- The safety argument is unchanged: a writer holds pg_advisory_xact_lock_shared from
-- allocation until commit/rollback, so the dispatcher's exclusive lock still proves that
-- every number it can see has finished (committed or rolled back). Rollbacks become
-- permanent gaps instead of returning their number. Watermark/fence/consumer functions
-- are otherwise untouched.
BEGIN;
SET LOCAL search_path = aegis, public;

CREATE SEQUENCE IF NOT EXISTS outbox_publication_seq AS bigint;
SELECT setval('aegis.outbox_publication_seq', (SELECT next_seq FROM outbox_publication), false);

CREATE OR REPLACE FUNCTION aegis.outbox_publication_alloc() RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = aegis, pg_temp AS $$
BEGIN
  PERFORM pg_advisory_xact_lock_shared(aegis.outbox_publication_lock_key());
  RETURN nextval('aegis.outbox_publication_seq')::bigint;
END $$;

CREATE OR REPLACE FUNCTION aegis.outbox_publication_reserve(p_count bigint) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = aegis, pg_temp AS $$
DECLARE v bigint;
BEGIN
  IF p_count IS NULL OR p_count < 1 OR p_count > 10000 THEN
    RAISE EXCEPTION 'reserve count must be between 1 and 10000, got %', p_count USING ERRCODE = 'invalid_parameter_value';
  END IF;
  PERFORM pg_advisory_xact_lock_shared(aegis.outbox_publication_lock_key());
  v := nextval('aegis.outbox_publication_seq')::bigint;
  PERFORM setval('aegis.outbox_publication_seq', v + p_count - 1, true);
  RETURN v;
END $$;

CREATE OR REPLACE FUNCTION aegis.spike_publication_last() RETURNS bigint
LANGUAGE sql SECURITY DEFINER SET search_path = aegis, pg_temp AS $$
  SELECT CASE WHEN is_called THEN last_value ELSE last_value - 1 END
    FROM aegis.outbox_publication_seq
$$;

CREATE OR REPLACE FUNCTION aegis.outbox_watermark_refresh(p_dispatcher text, p_fence bigint) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = aegis, pg_temp AS $$
DECLARE v bigint;
BEGIN
  PERFORM aegis.outbox_fence_check(p_dispatcher, p_fence);
  IF pg_try_advisory_xact_lock(aegis.outbox_publication_lock_key()) THEN
    UPDATE outbox_watermark
       SET published_upto = greatest(published_upto, aegis.spike_publication_last()), updated_at = now()
     WHERE id;
  END IF;
  SELECT published_upto INTO v FROM outbox_watermark;
  RETURN v;
END $$;

COMMIT;
