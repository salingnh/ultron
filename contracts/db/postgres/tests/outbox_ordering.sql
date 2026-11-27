-- S1.3 / C04: publication ordering after 0001 -> 0002 -> 0003 -> 0004 -> 0008 -> 0013 on a fresh
-- PostgreSQL 16. Single-session properties only; multi-connection blocking/timeout races (slow
-- writer, inverted commit, crash mid-transaction, bounded wait) are in
-- contracts/tests/test_outbox_ordering.py against the same schema.
-- Everything runs in one transaction and is rolled back, so the script can run on any DB that has
-- the migrations applied.
SET search_path = aegis, public;
BEGIN;

-- Minimal campaign/scope rows: graph_revision has a campaign FK. Distinct ids/version, no clash
-- with tests/smoke.sql (which uses roe-1 and 01900000-...-0001).
INSERT INTO policy_snapshot VALUES ('roe-8','01900000-0000-7000-8000-000000000880','{"network_profile":"lab","max_parallel_jobs":10,"max_duration_hours":168}',repeat('a',64),'{"kind":"operator","id":"soc-8"}');
INSERT INTO scope_snapshot VALUES ('01900000-0000-7000-8000-000000000881','01900000-0000-7000-8000-000000000882','{"domains":["internal.example"]}');
INSERT INTO campaign (campaign_id,name,objective,current_policy_version,scope_id,created_by)
  VALUES ('01900000-0000-7000-8000-000000000882','C04 ordering','Publication order','roe-8','01900000-0000-7000-8000-000000000881','{"kind":"operator","id":"soc-8"}');

DO $$
DECLARE
  seq1 bigint; seq2 bigint; rev1 bigint; wm bigint; fence bigint; picked bigint[];
  wm0 bigint; blocked int := 0;
BEGIN
  -- Start this consumer at the watermark the DB already has, like a real consumer that was
  -- deployed here: the script must not assume an empty event log (upgrade DBs have history).
  SELECT published_upto INTO wm0 FROM outbox_watermark;
  -- Allocator assigns seq; two rows in one transaction are consecutive.
  INSERT INTO outbox_event (event_id,type,producer,dedup_key,campaign_id,payload,trace)
    VALUES ('01900000-0000-7000-8000-000000000801','job.started.v2','M02','c04:1','01900000-0000-7000-8000-000000000882','{"step":1}','{}')
    RETURNING seq INTO seq1;
  INSERT INTO outbox_event (event_id,type,producer,dedup_key,campaign_id,payload,trace)
    VALUES ('01900000-0000-7000-8000-000000000802','job.completed.v2','M02','c04:2','01900000-0000-7000-8000-000000000882','{"step":2}','{}')
    RETURNING seq INTO seq2;
  IF seq2 <> seq1 + 1 THEN
    RAISE EXCEPTION 'C04 allocator is not consecutive inside one transaction: % then %', seq1, seq2;
  END IF;

  -- graph_revision draws from the same counter, so events and revisions share one order.
  INSERT INTO graph_revision (campaign_id) VALUES ('01900000-0000-7000-8000-000000000882') RETURNING revision INTO rev1;
  IF rev1 <> seq2 + 1 THEN
    RAISE EXCEPTION 'C04 counter is not shared with graph_revision: event % / revision %', seq2, rev1;
  END IF;

  -- Writers cannot choose or rewrite the publication sequence.
  BEGIN
    INSERT INTO outbox_event (seq,event_id,type,producer,dedup_key,payload,trace)
      VALUES (999999,'01900000-0000-7000-8000-000000000803','job.started.v2','M02','c04:3','{}','{}');
  EXCEPTION WHEN insufficient_privilege THEN blocked := blocked + 1; END;
  BEGIN
    INSERT INTO graph_revision (revision,campaign_id) VALUES (999999,'01900000-0000-7000-8000-000000000882');
  EXCEPTION WHEN insufficient_privilege THEN blocked := blocked + 1; END;
  BEGIN UPDATE outbox_event SET seq = seq WHERE event_id = '01900000-0000-7000-8000-000000000801';
  EXCEPTION WHEN insufficient_privilege THEN blocked := blocked + 1; END;
  BEGIN DELETE FROM outbox_publication;
  EXCEPTION WHEN insufficient_privilege THEN blocked := blocked + 1; END;
  -- hedge against a silent no-op: the counter row really is still readable and untouched
  IF (SELECT next_seq FROM outbox_publication) < rev1 + 1 THEN
    RAISE EXCEPTION 'counter moved backwards: next_seq=% last allocated=%', (SELECT next_seq FROM outbox_publication), rev1;
  END IF;

  -- Dispatcher lease + fencing token.
  fence := aegis.outbox_dispatch_lease('c04-test','holder-a',30);
  IF fence IS NULL THEN RAISE EXCEPTION 'first lease was not granted'; END IF;

  -- Watermark advances over every committed allocation and stops there.
  wm := aegis.outbox_watermark_refresh('c04-test', fence);
  IF wm <> rev1 THEN RAISE EXCEPTION 'watermark % should equal last allocation %', wm, rev1; END IF;

  -- Consumer reads in publication order, capped at the watermark, starting where it was deployed.
  PERFORM aegis.consumer_advance('m23-projector', wm0, 'c04-test', fence);
  SELECT array_agg(seq) INTO picked FROM aegis.outbox_batch('m23-projector', 100) b;
  IF picked IS DISTINCT FROM ARRAY[seq1, seq2] THEN
    RAISE EXCEPTION 'batch order/cap wrong: % (expected %)', picked, ARRAY[seq1, seq2];
  END IF;

  -- A checkpoint may not pass the watermark.
  BEGIN PERFORM aegis.consumer_advance('m23-projector', rev1 + 1, 'c04-test', fence);
  EXCEPTION WHEN object_not_in_prerequisite_state THEN blocked := blocked + 1; END;
  IF aegis.consumer_advance('m23-projector', seq2, 'c04-test', fence) <> seq2 THEN
    RAISE EXCEPTION 'consumer checkpoint did not advance to %', seq2;
  END IF;

  -- Reserved-but-unused numbers are a permanent gap: the watermark passes them, so no consumer
  -- waits for a sequence that will never commit (D25: no stall on never-committed seq).
  PERFORM aegis.outbox_publication_reserve(3);
  wm := aegis.outbox_watermark_refresh('c04-test', fence);
  IF wm <> rev1 + 3 THEN RAISE EXCEPTION 'watermark % did not pass the 3 reserved numbers (%)', wm, rev1 + 3; END IF;
  INSERT INTO outbox_event (event_id,type,producer,dedup_key,payload,trace)
    VALUES ('01900000-0000-7000-8000-000000000804','policy.denied.v2','M05','c04:4','{}','{}') RETURNING seq INTo seq1;
  wm := aegis.outbox_watermark_refresh('c04-test', fence);
  IF seq1 <> rev1 + 4 OR wm <> seq1 THEN
    RAISE EXCEPTION 'after the gap: event % / watermark % (expected %)', seq1, wm, rev1 + 4;
  END IF;
  SELECT array_agg(seq) INTO picked FROM aegis.outbox_batch('m23-projector', 100) b;
  IF picked IS DISTINCT FROM ARRAY[seq1] THEN
    RAISE EXCEPTION 'consumer stalled on the reserved gap: %', picked;
  END IF;
  PERFORM aegis.consumer_advance('m23-projector', wm, 'c04-test', fence);

  -- 0013: the wait must stay bounded. A non-positive bound is rejected before the lock is taken
  -- instead of silently becoming an unbounded wait (the blocking/timeout race itself is multi-
  -- connection, so it lives in the Python harness).
  PERFORM set_config('aegis.outbox_watermark_lock_timeout', '0', true);
  BEGIN PERFORM aegis.outbox_watermark_refresh('c04-test', fence);
  EXCEPTION WHEN invalid_parameter_value THEN blocked := blocked + 1; END;
  PERFORM set_config('aegis.outbox_watermark_lock_timeout', '5s', true);

  -- Failover: the holder dies without releasing (lease expires), a new holder takes over with a
  -- higher fence, and the old holder is rejected everywhere.
  UPDATE outbox_dispatcher SET leased_until = now() - interval '1 second' WHERE name = 'c04-test';
  IF aegis.outbox_dispatch_lease('c04-test','holder-b',30) <> fence + 1 THEN
    RAISE EXCEPTION 'failover did not increment the fence';
  END IF;
  BEGIN PERFORM aegis.outbox_watermark_refresh('c04-test', fence);
  EXCEPTION WHEN object_not_in_prerequisite_state THEN blocked := blocked + 1; END;
  BEGIN PERFORM aegis.consumer_advance('m23-projector', wm, 'c04-test', fence);
  EXCEPTION WHEN object_not_in_prerequisite_state THEN blocked := blocked + 1; END;
  IF aegis.outbox_watermark_refresh('c04-test', fence + 1) <> wm THEN
    RAISE EXCEPTION 'new holder could not read the watermark';
  END IF;

  IF blocked <> 8 THEN
    RAISE EXCEPTION 'C04: only % / 8 protections blocked (expected: explicit seq x2, seq update, counter delete, checkpoint past watermark, non-positive lock bound, stale fence x2)', blocked;
  END IF;
  RAISE NOTICE 'C04 single-session: allocator consecutive, revision shares counter, 8/8 protections blocked, watermark/fence/checkpoint semantics PASS';
END $$;

-- Writer group role: append-only access; the allocator runs as SECURITY DEFINER, so the role needs
-- no privilege on outbox_publication.
SET ROLE aegis_outbox_writer;
DO $$
DECLARE s1 bigint; s2 bigint; blocked int := 0;
BEGIN
  INSERT INTO outbox_event (event_id,type,producer,dedup_key,payload,trace)
    VALUES ('01900000-0000-7000-8000-000000000805','job.started.v2','M02','c04:writer-1','{}','{}') RETURNING seq INTO s1;
  INSERT INTO outbox_event (event_id,type,producer,dedup_key,payload,trace)
    VALUES ('01900000-0000-7000-8000-000000000806','job.completed.v2','M02','c04:writer-2','{}','{}') RETURNING seq INTO s2;
  IF s1 IS NULL OR s2 <> s1 + 1 THEN
    RAISE EXCEPTION 'writer role did not get consecutive allocator sequences: % then %', s1, s2;
  END IF;
  PERFORM aegis.outbox_publication_reserve(2);
  BEGIN INSERT INTO outbox_event (seq,event_id,type,producer,dedup_key,payload,trace)
        VALUES (999999,'01900000-0000-7000-8000-000000000807','job.started.v2','M02','c04:writer-3','{}','{}');
  EXCEPTION WHEN insufficient_privilege THEN blocked := blocked + 1; END;
  BEGIN UPDATE outbox_publication SET next_seq = 999999;
  EXCEPTION WHEN insufficient_privilege THEN blocked := blocked + 1; END;
  BEGIN INSERT INTO outbox_watermark (id, published_upto) VALUES (true, 999999);
  EXCEPTION WHEN insufficient_privilege OR unique_violation THEN blocked := blocked + 1; END;
  BEGIN DELETE FROM graph_revision;
  EXCEPTION WHEN insufficient_privilege THEN blocked := blocked + 1; END;
  IF blocked <> 4 THEN RAISE EXCEPTION 'writer role: only % / 4 forbidden writes blocked', blocked; END IF;
  RAISE NOTICE 'C04 writer role: allocator-only append (consecutive seq, reserve) PASS; 4/4 bypass attempts blocked';
END $$;
RESET ROLE;

-- Dispatcher group role: fenced functions only, no direct event or cursor writes.
SET ROLE aegis_outbox_dispatcher;
DO $$
DECLARE blocked int := 0; wm bigint; fence bigint;
BEGIN
  fence := (SELECT f.fence FROM outbox_dispatcher f WHERE f.name='c04-test');
  wm := aegis.outbox_watermark_refresh('c04-test', fence);
  IF wm IS NULL THEN RAISE EXCEPTION 'dispatcher role cannot read the watermark'; END IF;
  BEGIN UPDATE consumer_cursor SET last_seq = last_seq WHERE consumer = 'm23-projector';
  EXCEPTION WHEN insufficient_privilege THEN blocked := blocked + 1; END;
  BEGIN INSERT INTO outbox_event (event_id,type,producer,dedup_key,payload,trace)
        VALUES ('01900000-0000-7000-8000-000000000806','job.started.v2','M02','c04:dispatcher','{}','{}');
  EXCEPTION WHEN insufficient_privilege THEN blocked := blocked + 1; END;
  BEGIN UPDATE outbox_publication SET next_seq = next_seq + 1;
  EXCEPTION WHEN insufficient_privilege THEN blocked := blocked + 1; END;
  BEGIN UPDATE outbox_dispatcher SET fence = 100 WHERE name = 'c04-test';
  EXCEPTION WHEN insufficient_privilege THEN blocked := blocked + 1; END;
  IF blocked <> 4 THEN RAISE EXCEPTION 'dispatcher role: only % / 4 direct writes blocked', blocked; END IF;
  RAISE NOTICE 'C04 dispatcher role: fenced functions allowed, 4/4 direct writes blocked PASS';
END $$;
RESET ROLE;

ROLLBACK;
