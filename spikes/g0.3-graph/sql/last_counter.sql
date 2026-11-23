-- G0.3b spike-only: counter variant helper.
--
-- 0008's outbox_watermark_refresh reads outbox_publication.next_seq directly, so this
-- file only adds one read-only helper the spike uses to observe the allocator's high
-- water mark (publication lag). It does not replace any 0008 function.
BEGIN;
SET LOCAL search_path = aegis, public;

CREATE OR REPLACE FUNCTION aegis.spike_publication_last() RETURNS bigint
LANGUAGE sql SECURITY DEFINER SET search_path = aegis, pg_temp AS $$
  SELECT next_seq - 1 FROM outbox_publication WHERE id
$$;
COMMENT ON FUNCTION aegis.spike_publication_last() IS
  'G0.3b spike only: highest publication number handed out by the transactional counter. Not part of the C04 contract.';

COMMIT;
