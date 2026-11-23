-- C03: canonical hash version, accepted-receipt semantics and the single job fingerprint composition (X-1).
-- Apply after 0005. Prior rows are preserved: no historical hash is re-interpreted as versioned.
BEGIN;
SET LOCAL search_path = aegis, public;

-- 1. Every new inbox row names the canonicalization version that produced payload_hash.
--    Rows predating 0006 keep NULL: their hash came from no versioned canonicalization, so it is
--    never compared as equal to a versioned hash; a re-submission against them is a conflict.
ALTER TABLE ingestion_inbox ADD COLUMN hash_version text
  CHECK (hash_version ~ '^aegis-c14n/[0-9]+$');

CREATE FUNCTION aegis.require_inbox_hash_version() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.hash_version IS NULL THEN
    RAISE EXCEPTION 'new ingestion requires hash_version (aegis-c14n/<n>); an unversioned hash is not comparable'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER hash_version_required BEFORE INSERT ON ingestion_inbox
  FOR EACH ROW EXECUTE FUNCTION aegis.require_inbox_hash_version();

-- 2. The receipt is the first committed decision for its dedup_key, written once, and it must
--    describe its own row. Duplicate submissions replay it verbatim instead of writing a new one,
--    so a retry after a crash can never produce a second, different receipt.
CREATE FUNCTION aegis.receipt_once() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.receipt IS NOT NULL THEN
    IF NEW.receipt->>'event_id' IS DISTINCT FROM NEW.event_id::text
       OR NEW.receipt->>'payload_hash' IS DISTINCT FROM NEW.payload_hash
       OR NEW.receipt->>'hash_version' IS DISTINCT FROM NEW.hash_version THEN
      RAISE EXCEPTION 'receipt must describe its own inbox row (event_id, payload_hash, hash_version)'
        USING ERRCODE = 'check_violation';
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.receipt IS NOT NULL AND NEW.receipt IS DISTINCT FROM OLD.receipt THEN
      RAISE EXCEPTION 'accepted receipt is immutable; a duplicate submission returns the first committed receipt'
        USING ERRCODE = 'insufficient_privilege';
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER receipt_once BEFORE INSERT OR UPDATE ON ingestion_inbox
  FOR EACH ROW EXECUTE FUNCTION aegis.receipt_once();

-- 3. One row per received submission, written in the same transaction as the decision it took:
--    first acceptance, duplicate replay or conflicting content. ingestion_inbox keeps one row per
--    logical result; this table is the audit trail that makes a re-submission impossible to drop.
CREATE TABLE ingestion_attempt (
  attempt_seq    bigserial   PRIMARY KEY,
  event_id       uuid        NOT NULL UNIQUE,
  dedup_key      text        NOT NULL,
  inbox_event_id uuid        REFERENCES ingestion_inbox(event_id),
  payload_hash   char(64)    NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
  hash_version   text        NOT NULL CHECK (hash_version ~ '^aegis-c14n/[0-9]+$'),
  outcome        text        NOT NULL CHECK (outcome IN ('first','duplicate','conflict')),
  detail         jsonb       NOT NULL DEFAULT '{}'::jsonb,
  received_at    timestamptz NOT NULL DEFAULT now(),
  -- first: this submission owns the inbox row; duplicate/conflict: it points at the committed one.
  -- CASE keeps a NULL inbox_event_id a violation instead of a passing NULL CHECK.
  CHECK (CASE WHEN outcome = 'first' THEN inbox_event_id IS NOT DISTINCT FROM event_id
              ELSE inbox_event_id IS NOT NULL AND inbox_event_id <> event_id END)
);
-- At most one first acceptance per logical result, even if two submissions race.
CREATE UNIQUE INDEX ingestion_attempt_first_once ON ingestion_attempt (dedup_key) WHERE outcome = 'first';
CREATE INDEX ingestion_attempt_key ON ingestion_attempt (dedup_key, attempt_seq);
SELECT aegis.protect('ingestion_attempt'::regclass, true);

-- 4. X-1: one fingerprint composition everywhere, aligned to AGENTS.md:54 plus the TargetRef list.
--    Replaces the 0002/0003 wording without editing those applied migrations.
COMMENT ON COLUMN scan_job.job_fingerprint IS
  'X-1/C03 fingerprint, aegis-c14n/1: sha256 of {campaign_id,capability,policy_version,provider,provider_version,adapter_version,image_digest,manifest_sha256,target_refs,input,scan_cycle}. It hashes target_refs (the TargetRef list), never the targets canonical-key projection: two keyword/CIDR seeds would otherwise share a fingerprint. priority, depends_on, actor/rationale/trace, job_id/decision_id, status and execution timestamps are excluded because they do not identify the scanned data. Conflicting scheduling for an existing fingerprint is rejected, not silently merged. Canonicalization and field lists: contracts/ingestion/canonicalization.v2.yaml.';

COMMENT ON COLUMN ingestion_inbox.payload_hash IS
  'sha256 of the business content under aegis-c14n/1: ResultEnvelope minus event_id, dedup_key and trace. Execution timestamps (provenance.started_at/finished_at) are part of the hash; the collector freezes them with the snapshot so a retry hashes identically.';
COMMENT ON COLUMN ingestion_inbox.hash_version IS
  'Canonicalization version that produced payload_hash (aegis-c14n/<n>). Required for new rows; NULL only for rows predating 0006, whose hash is never equal to a versioned one.';
COMMENT ON COLUMN ingestion_inbox.receipt IS
  'First committed IngestReceipt for this dedup_key. Written once and returned verbatim (duplicate=true) to later submissions of the same payload_hash; a conflicting payload_hash changes nothing.';
COMMENT ON TABLE ingestion_inbox IS
  'M27. One row per logical result: the first committed decision for a dedup_key. status only leaves received once; the receipt is immutable after it is set; a duplicate submission returns that receipt and writes ingestion_attempt instead.';
COMMENT ON TABLE ingestion_attempt IS
  'M27. Append-only per-submission audit: every received envelope, including duplicate replays and conflicting content (409), written in the same transaction as the decision. It never overrides ingestion_inbox.';
COMMENT ON COLUMN ingestion_attempt.detail IS
  'Decision context for a non-first submission, e.g. {"existing_payload_hash": "...", "reason": "hash_mismatch"|"legacy_unversioned_hash"|"hash_version_mismatch"}.';

COMMIT;
