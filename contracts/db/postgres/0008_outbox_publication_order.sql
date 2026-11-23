-- S1.3 / C04: publication ordering for outbox_event and graph_revision.
--
-- One shared publication lock plus one transactional counter give writers a total publication
-- order: outbox_event.seq and graph_revision.revision are drawn from the counter inside the
-- writer transaction, so commit order equals sequence order and a rollback returns its number.
-- The dispatcher publishes only up to a watermark it reads while holding the publication lock
-- exclusively, i.e. with no writer transaction in flight, so a sequence number that never commits
-- cannot stall delivery and no late commit can be skipped. Gaps stay legal.
--
-- Independent of 0005..0007: this file only relies on 0001/0002 objects and may land before them
-- (the integrator renumbers migrations at integration if needed). It creates two NOLOGIN group
-- roles, so it must run as the schema owner/superuser that applies the other migrations; the role
-- block is idempotent for clusters that already ran it (tests reuse one cluster for many databases).
BEGIN;
SET LOCAL search_path = aegis, public;
LOCK TABLE outbox_event, graph_revision, consumer_cursor IN ACCESS EXCLUSIVE MODE;

-- ---------------------------------------------------------------------------
-- C04: publication lock, counter, watermark, dispatcher lease
-- ---------------------------------------------------------------------------
CREATE FUNCTION aegis.outbox_publication_lock_key() RETURNS bigint
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$ SELECT 2803754796350008::bigint $$;
COMMENT ON FUNCTION aegis.outbox_publication_lock_key() IS
  'C04 publication lock advisory key. Writers take it shared and keep it until commit/rollback; the dispatcher tries it exclusively to read a publishable watermark. 2803754796350008 = 0x4145474953 (AEGIS) * 10000 + 0008.';

CREATE TABLE outbox_publication (
  id         boolean     PRIMARY KEY DEFAULT true CHECK (id),
  next_seq   bigint      NOT NULL DEFAULT 1 CHECK (next_seq >= 1),
  updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO outbox_publication (id) VALUES (true);
COMMENT ON TABLE outbox_publication IS
  'C04: single-row transactional counter shared by outbox_event and graph_revision, so events and revisions have one total publication order. A writer allocates inside its own transaction while holding the publication lock, so the number is committed or returned with the transaction. Event/revision rows stay append-only; this row is state and only next_seq/updated_at may change (D26).';

CREATE TABLE outbox_watermark (
  id             boolean     PRIMARY KEY DEFAULT true CHECK (id),
  published_upto bigint      NOT NULL DEFAULT 0 CHECK (published_upto >= 0),
  updated_at     timestamptz NOT NULL DEFAULT now()
);
INSERT INTO outbox_watermark (id) VALUES (true);
COMMENT ON TABLE outbox_watermark IS
  'C04/D25: publication watermark. published_upto is the highest sequence for which every earlier allocation has committed or been rolled back, proved by taking the publication lock exclusively (no writer transaction in flight). Consumers may read and checkpoint only at or below it.';

CREATE TABLE outbox_dispatcher (
  name         text        PRIMARY KEY,
  fence        bigint      NOT NULL DEFAULT 0,
  holder       text,
  leased_until timestamptz,
  updated_at   timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE outbox_dispatcher IS
  'C04/D25: dispatcher lease with a fencing token. Taking a lease increments fence; every dispatcher write presents its fence, so a superseded or expired holder is rejected instead of publishing or checkpointing out of order.';

-- ---------------------------------------------------------------------------
-- Writer side: the allocator is the only way to obtain a publication sequence
-- ---------------------------------------------------------------------------
CREATE FUNCTION aegis.outbox_publication_alloc() RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = aegis, pg_temp AS $$
DECLARE v bigint;
BEGIN
  PERFORM pg_advisory_xact_lock_shared(aegis.outbox_publication_lock_key());
  UPDATE outbox_publication SET next_seq = next_seq + 1, updated_at = now()
   WHERE id RETURNING next_seq - 1 INTO v;
  IF v IS NULL THEN RAISE EXCEPTION 'outbox_publication single row is missing'; END IF;
  RETURN v;
END $$;
COMMENT ON FUNCTION aegis.outbox_publication_alloc() IS
  'C04: take the publication lock (shared, held until commit/rollback), take the next publication sequence. Called by the INSERT triggers of outbox_event/graph_revision; short transactions only, no network/LLM work inside the lock. SECURITY DEFINER so writers need no privilege on outbox_publication.';

CREATE FUNCTION aegis.outbox_publication_reserve(p_count bigint) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = aegis, pg_temp AS $$
DECLARE v bigint;
BEGIN
  IF p_count IS NULL OR p_count < 1 OR p_count > 10000 THEN
    RAISE EXCEPTION 'reserve count must be between 1 and 10000, got %', p_count USING ERRCODE = 'invalid_parameter_value';
  END IF;
  PERFORM pg_advisory_xact_lock_shared(aegis.outbox_publication_lock_key());
  UPDATE outbox_publication SET next_seq = next_seq + p_count, updated_at = now()
   WHERE id RETURNING next_seq - p_count INTO v;
  IF v IS NULL THEN RAISE EXCEPTION 'outbox_publication single row is missing'; END IF;
  RETURN v;
END $$;
COMMENT ON FUNCTION aegis.outbox_publication_reserve(bigint) IS
  'C04: reserve a block of publication sequences for a batch writer, returning the first number. Numbers that are never used stay permanently absent; the dispatcher advances to the watermark and never waits for a specific number, so reserved-but-empty blocks cannot stall consumers.';

-- Historical rows keep their bigserial values; the counter starts above them so new allocations
-- are ordered after everything already visible.
UPDATE outbox_publication SET next_seq = 1 + greatest(
  (SELECT coalesce(max(seq), 0) FROM outbox_event),
  (SELECT coalesce(max(revision), 0) FROM graph_revision));
UPDATE outbox_watermark SET published_upto = (SELECT next_seq - 1 FROM outbox_publication);

ALTER TABLE outbox_event   ALTER COLUMN seq      DROP DEFAULT;
ALTER TABLE graph_revision ALTER COLUMN revision DROP DEFAULT;
-- The old bigserial sequences stay, inert: no column default uses them any more and no runtime
-- role has USAGE on them (a writer cannot draw a number from them, and the allocate_seq trigger
-- rejects any seq the writer supplies). They are not dropped because nothing in this migration
-- should depend on, or silently cascade into, other objects that may reference them (views, copy
-- tables, defaults in another schema).

CREATE FUNCTION aegis.outbox_event_allocate_seq() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.seq IS NOT NULL THEN
    RAISE EXCEPTION 'outbox_event.seq is assigned by aegis.outbox_publication_alloc() while the publication lock is held (C04); writers must not supply it'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  NEW.seq := aegis.outbox_publication_alloc();
  RETURN NEW;
END $$;
CREATE FUNCTION aegis.graph_revision_allocate_seq() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.revision IS NOT NULL THEN
    RAISE EXCEPTION 'graph_revision.revision is assigned by aegis.outbox_publication_alloc() while the publication lock is held (C04); writers must not supply it'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  NEW.revision := aegis.outbox_publication_alloc();
  RETURN NEW;
END $$;
CREATE TRIGGER allocate_seq BEFORE INSERT ON outbox_event   FOR EACH ROW EXECUTE FUNCTION aegis.outbox_event_allocate_seq();
CREATE TRIGGER allocate_seq BEFORE INSERT ON graph_revision FOR EACH ROW EXECUTE FUNCTION aegis.graph_revision_allocate_seq();

-- ---------------------------------------------------------------------------
-- Dispatcher side: lease/fencing, watermark, consumer checkpoint
-- ---------------------------------------------------------------------------
CREATE FUNCTION aegis.outbox_fence_check(p_dispatcher text, p_fence bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = aegis, pg_temp AS $$
BEGIN
  IF p_fence IS NULL OR NOT EXISTS (
    SELECT 1 FROM outbox_dispatcher
     WHERE name = p_dispatcher AND fence = p_fence AND leased_until > now()) THEN
    RAISE EXCEPTION 'dispatcher % fence % is stale, expired or unknown; it must not publish or checkpoint', p_dispatcher, p_fence
      USING ERRCODE = 'object_not_in_prerequisite_state';
  END IF;
END $$;
COMMENT ON FUNCTION aegis.outbox_fence_check(text,bigint) IS
  'C04/D25 fencing: raise 55000 unless the caller still holds a live lease with exactly this fence.';

CREATE FUNCTION aegis.outbox_dispatch_lease(p_dispatcher text, p_holder text, p_ttl_seconds integer DEFAULT 15) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = aegis, pg_temp AS $$
DECLARE v bigint;
BEGIN
  INSERT INTO outbox_dispatcher (name) VALUES (p_dispatcher) ON CONFLICT (name) DO NOTHING;
  UPDATE outbox_dispatcher
     SET fence = fence + 1, holder = p_holder,
         leased_until = now() + make_interval(secs => greatest(coalesce(p_ttl_seconds, 15), 1)),
         updated_at = now()
   WHERE name = p_dispatcher
     AND (holder = p_holder OR leased_until IS NULL OR leased_until <= now())
  RETURNING fence INTO v;
  RETURN v;   -- NULL = another holder owns a live lease; the caller must not dispatch
END $$;
COMMENT ON FUNCTION aegis.outbox_dispatch_lease(text,text,integer) IS
  'C04: take or renew a dispatcher lease and return the new fencing token (NULL when another live holder owns it). Every renewal returns a new fence, so an old token stops working immediately.';

CREATE FUNCTION aegis.outbox_watermark_refresh(p_dispatcher text, p_fence bigint) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = aegis, pg_temp AS $$
DECLARE v bigint;
BEGIN
  PERFORM aegis.outbox_fence_check(p_dispatcher, p_fence);
  -- Exclusive try-lock: succeeds only when no writer transaction is in flight, so every sequence
  -- at or below the counter is already final. Never blocks, so a slow writer delays only itself.
  IF pg_try_advisory_xact_lock(aegis.outbox_publication_lock_key()) THEN
    UPDATE outbox_watermark
       SET published_upto = greatest(published_upto, (SELECT next_seq - 1 FROM outbox_publication)),
           updated_at = now()
     WHERE id;
  END IF;
  SELECT published_upto INTO v FROM outbox_watermark;
  RETURN v;
END $$;
COMMENT ON FUNCTION aegis.outbox_watermark_refresh(text,bigint) IS
  'C04/D25: advance and return the publication watermark. Run in its own short transaction: the exclusive publication lock (xact-scoped) is held until commit, and holding it blocks writers.';

CREATE FUNCTION aegis.outbox_batch(p_consumer text, p_limit integer DEFAULT 100)
RETURNS TABLE (seq bigint, event_id uuid, type text, producer text, dedup_key text,
               campaign_id uuid, payload jsonb, trace jsonb, occurred_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = aegis, pg_temp AS $$
DECLARE wm bigint; cur bigint;
BEGIN
  SELECT published_upto INTO wm FROM outbox_watermark;
  SELECT last_seq INTO cur FROM consumer_cursor WHERE consumer = p_consumer;
  RETURN QUERY
    SELECT e.seq, e.event_id, e.type, e.producer, e.dedup_key, e.campaign_id, e.payload, e.trace, e.occurred_at
      FROM outbox_event e
     WHERE e.seq > coalesce(cur, 0) AND e.seq <= wm
     ORDER BY e.seq
     LIMIT greatest(coalesce(p_limit, 100), 0);
END $$;
COMMENT ON FUNCTION aegis.outbox_batch(text,integer) IS
  'C04: next published events after a consumer cursor, in publication order, never beyond the watermark. A missing consumer row starts at 0, which is also how a new consumer generation rebuilds.';

CREATE FUNCTION aegis.consumer_advance(p_consumer text, p_upto bigint, p_dispatcher text, p_fence bigint) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = aegis, pg_temp AS $$
DECLARE wm bigint; v bigint;
BEGIN
  PERFORM aegis.outbox_fence_check(p_dispatcher, p_fence);
  SELECT published_upto INTO wm FROM outbox_watermark;
  IF p_upto > wm THEN
    RAISE EXCEPTION 'consumer % cannot checkpoint % past the published watermark % (D25)', p_consumer, p_upto, wm
      USING ERRCODE = 'object_not_in_prerequisite_state';
  END IF;
  INSERT INTO consumer_cursor (consumer, last_seq, updated_at) VALUES (p_consumer, p_upto, now())
  ON CONFLICT (consumer) DO UPDATE
     SET last_seq = greatest(consumer_cursor.last_seq, EXCLUDED.last_seq), updated_at = now()
  RETURNING last_seq INTO v;
  RETURN v;
END $$;
COMMENT ON FUNCTION aegis.consumer_advance(text,bigint,text,bigint) IS
  'C04/D25: checkpoint a consumer after a successful apply, with the dispatcher fence. A checkpoint may never pass the published watermark, so adding a consumer cannot skip unpublished data.';

-- ---------------------------------------------------------------------------
-- Protection, privileges
-- ---------------------------------------------------------------------------
SELECT aegis.protect('outbox_publication'::regclass, false);
SELECT aegis.protect('outbox_watermark'::regclass, false);
SELECT aegis.protect('outbox_dispatcher'::regclass, false);
CREATE TRIGGER cols_only BEFORE UPDATE ON outbox_publication FOR EACH ROW EXECUTE FUNCTION aegis.forbid_value_update('next_seq','updated_at');
CREATE TRIGGER cols_only BEFORE UPDATE ON outbox_watermark   FOR EACH ROW EXECUTE FUNCTION aegis.forbid_value_update('published_upto','updated_at');
CREATE TRIGGER cols_only BEFORE UPDATE ON outbox_dispatcher  FOR EACH ROW EXECUTE FUNCTION aegis.forbid_value_update('fence','holder','leased_until','updated_at');

-- Least privilege: writers may only append events/revisions and let the trigger allocate; they
-- cannot touch the counter, the watermark or the lease. Dispatchers may only read events and go
-- through the fenced functions. Roles are NOLOGIN group roles; G1 attaches service users to them.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_outbox_writer') THEN
    CREATE ROLE aegis_outbox_writer NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_outbox_dispatcher') THEN
    CREATE ROLE aegis_outbox_dispatcher NOLOGIN;
  END IF;
END $$;
REVOKE ALL ON FUNCTION aegis.outbox_publication_alloc() FROM PUBLIC;
REVOKE ALL ON FUNCTION aegis.outbox_publication_reserve(bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION aegis.outbox_dispatch_lease(text,text,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION aegis.outbox_watermark_refresh(text,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION aegis.outbox_batch(text,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION aegis.consumer_advance(text,bigint,text,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION aegis.outbox_fence_check(text,bigint) FROM PUBLIC;
GRANT USAGE ON SCHEMA aegis TO aegis_outbox_writer, aegis_outbox_dispatcher;
GRANT INSERT ON outbox_event, graph_revision TO aegis_outbox_writer;
GRANT SELECT ON outbox_event, graph_revision TO aegis_outbox_writer;   -- INSERT ... RETURNING seq
GRANT EXECUTE ON FUNCTION aegis.outbox_publication_alloc(), aegis.outbox_publication_reserve(bigint),
  aegis.outbox_publication_lock_key(), aegis.outbox_event_allocate_seq(), aegis.graph_revision_allocate_seq()
  TO aegis_outbox_writer;
REVOKE ALL ON outbox_publication, outbox_watermark, outbox_dispatcher, consumer_cursor FROM aegis_outbox_writer;
GRANT SELECT ON outbox_event, graph_revision, consumer_cursor, outbox_watermark, outbox_dispatcher TO aegis_outbox_dispatcher;
GRANT INSERT ON consumer_inbox TO aegis_outbox_dispatcher;
GRANT EXECUTE ON FUNCTION aegis.outbox_dispatch_lease(text,text,integer), aegis.outbox_watermark_refresh(text,bigint),
  aegis.outbox_batch(text,integer), aegis.consumer_advance(text,bigint,text,bigint),
  aegis.outbox_fence_check(text,bigint), aegis.outbox_publication_lock_key()
  TO aegis_outbox_dispatcher;
REVOKE ALL ON outbox_publication FROM aegis_outbox_dispatcher;
REVOKE ALL ON outbox_publication, outbox_watermark, outbox_dispatcher FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- Contract text (supersedes the "open design item" comments left by 0002)
-- ---------------------------------------------------------------------------
COMMENT ON TABLE outbox_event IS
  'Append-only event log, written in the same transaction as the state change. seq is the publication sequence from aegis.outbox_publication (C04), not a bigserial: a writer INSERTS without seq and the allocate_seq trigger draws it under the shared publication lock, so commit order equals seq order and a rollback returns its number. Gaps stay legal (reserve() blocks, historical bigserial rows) and must never block dispatch: consumers read by aegis.outbox_batch up to the published watermark, never by waiting for a specific number, and dedup with consumer_inbox (at-least-once).';
COMMENT ON COLUMN outbox_event.seq IS
  'C04 publication sequence: assigned by the allocate_seq trigger from aegis.outbox_publication inside the writer transaction while holding the publication lock; writers must not supply it. Shared with graph_revision.revision, so events and revisions have one order.';
COMMENT ON TABLE graph_revision IS
  'Append-only knowledge revision. revision comes from the same aegis.outbox_publication counter as outbox_event.seq (C04), so a revision and the events of the same transaction are published in one order under the same watermark; the projector uses aegis.outbox_batch style watermark rules and a new consumer generation for rebuilds.';
COMMENT ON COLUMN graph_revision.revision IS
  'C04 publication sequence, same allocator/counter as outbox_event.seq; assigned by the allocate_seq trigger, writers must not supply it.';
COMMENT ON TABLE consumer_cursor IS
  'Read position per consumer. last_seq is the highest publication sequence applied, and may only advance through aegis.consumer_advance inside the publication watermark, so a consumer can never skip data that was not published yet. Sequence gaps do not stall it.';
COMMIT;
