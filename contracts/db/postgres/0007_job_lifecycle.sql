-- C06: attempt/generation fencing, cancel intent, terminal CAS, late-result quarantine and the
-- job wait reason (X-4). Apply after 0006. Prior rows keep generation/attempt 1 and no history.
BEGIN;
SET LOCAL search_path = aegis, public;

-- 1. Lifecycle columns on the current-state row. attempt fences re-dispatch of a non-terminal job,
--    generation fences re-execution of a terminal one; a callback may only terminalize the exact
--    (generation, attempt) the job is on.
ALTER TABLE scan_job
  ADD COLUMN attempt integer NOT NULL DEFAULT 1 CHECK (attempt >= 1),
  ADD COLUMN generation integer NOT NULL DEFAULT 1 CHECK (generation >= 1),
  ADD COLUMN cancel_requested_at timestamptz,
  ADD COLUMN cancel_requested_by jsonb,
  ADD COLUMN cancel_reason text,
  ADD COLUMN wait_reason jsonb,
  ADD CONSTRAINT scan_job_cancel_intent_complete
    CHECK ((cancel_requested_at IS NULL) = (cancel_requested_by IS NULL));

-- X-4: why a QUEUED job has not been dispatched. Shape mirrors job.v2#/$defs/WaitReason; the code
-- list below is the same one the schema publishes (contract test keeps them equal).
CREATE FUNCTION aegis.is_wait_reason(reason jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN jsonb_typeof(reason) <> 'object' THEN false
    WHEN EXISTS (SELECT 1 FROM jsonb_object_keys(reason) AS k
                  WHERE k NOT IN ('code', 'detail', 'blocking_job_ids', 'since')) THEN false
    WHEN coalesce(reason->>'code', '') NOT IN (
      'DEPENDENCY_PENDING', 'DEPENDENCY_FAILED', 'CAMPAIGN_PAUSED', 'BUDGET_EXHAUSTED',
      'WINDOW_CLOSED', 'CONCURRENCY_LIMIT', 'RATE_LIMITED', 'PROVIDER_UNAVAILABLE', 'MANUAL_HOLD') THEN false
    WHEN reason ? 'detail' AND (jsonb_typeof(reason->'detail') <> 'string'
                                OR length(reason->>'detail') > 500) THEN false
    WHEN reason ? 'blocking_job_ids' AND (
      jsonb_typeof(reason->'blocking_job_ids') <> 'array'
      OR jsonb_array_length(reason->'blocking_job_ids') > 100
      OR EXISTS (SELECT 1 FROM jsonb_array_elements(reason->'blocking_job_ids') AS e
                  WHERE jsonb_typeof(e) <> 'string'
                     OR e #>> '{}' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')) THEN false
    WHEN coalesce(reason->>'since', '') !~
      '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$' THEN false
    ELSE true
  END
$$;
COMMENT ON FUNCTION aegis.is_wait_reason(jsonb) IS
  'True for a job.v2 WaitReason object: known code, ISO-8601 since, known keys only. Full timestamp validation stays in contracts/validation.py.';

ALTER TABLE scan_job
  ADD CONSTRAINT scan_job_wait_reason_shape
    CHECK (wait_reason IS NULL OR aegis.is_wait_reason(wait_reason)),
  ADD CONSTRAINT scan_job_wait_reason_queued
    CHECK (wait_reason IS NULL OR status = 'QUEUED');

-- 2. D26 history for the new dimensions: every change of attempt/generation/cancel intent/wait
--    reason writes one append-only row, so a job's re-dispatch, re-execution and cancel order stay
--    reconstructable even though the current-state row only keeps the latest value.
CREATE TABLE job_lifecycle_change (
  job_id    uuid        NOT NULL REFERENCES scan_job,
  seq       integer     NOT NULL,
  field     text        NOT NULL CHECK (field IN ('attempt', 'generation', 'cancel_request', 'wait_reason')),
  old_value jsonb,
  new_value jsonb,
  at        timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (job_id, seq)
);
SELECT aegis.protect('job_lifecycle_change'::regclass, true);

CREATE FUNCTION aegis.record_job_lifecycle() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE next_seq integer;
BEGIN
  IF NEW.attempt IS NOT DISTINCT FROM OLD.attempt
     AND NEW.generation IS NOT DISTINCT FROM OLD.generation
     AND NEW.cancel_requested_at IS NOT DISTINCT FROM OLD.cancel_requested_at
     AND NEW.cancel_requested_by IS NOT DISTINCT FROM OLD.cancel_requested_by
     AND NEW.cancel_reason IS NOT DISTINCT FROM OLD.cancel_reason
     AND NEW.wait_reason IS NOT DISTINCT FROM OLD.wait_reason THEN
    RETURN NULL;
  END IF;
  SELECT coalesce(max(seq), 0) INTO next_seq FROM job_lifecycle_change WHERE job_id = NEW.job_id;
  IF NEW.attempt IS DISTINCT FROM OLD.attempt THEN
    next_seq := next_seq + 1;
    INSERT INTO job_lifecycle_change (job_id, seq, field, old_value, new_value)
      VALUES (NEW.job_id, next_seq, 'attempt', to_jsonb(OLD.attempt), to_jsonb(NEW.attempt));
  END IF;
  IF NEW.generation IS DISTINCT FROM OLD.generation THEN
    next_seq := next_seq + 1;
    INSERT INTO job_lifecycle_change (job_id, seq, field, old_value, new_value)
      VALUES (NEW.job_id, next_seq, 'generation', to_jsonb(OLD.generation), to_jsonb(NEW.generation));
  END IF;
  IF (NEW.cancel_requested_at, NEW.cancel_requested_by, NEW.cancel_reason)
       IS DISTINCT FROM (OLD.cancel_requested_at, OLD.cancel_requested_by, OLD.cancel_reason) THEN
    next_seq := next_seq + 1;
    INSERT INTO job_lifecycle_change (job_id, seq, field, old_value, new_value)
      VALUES (NEW.job_id, next_seq, 'cancel_request',
              jsonb_build_object('requested_at', OLD.cancel_requested_at,
                                 'requested_by', OLD.cancel_requested_by,
                                 'reason', OLD.cancel_reason),
              jsonb_build_object('requested_at', NEW.cancel_requested_at,
                                 'requested_by', NEW.cancel_requested_by,
                                 'reason', NEW.cancel_reason));
  END IF;
  IF NEW.wait_reason IS DISTINCT FROM OLD.wait_reason THEN
    next_seq := next_seq + 1;
    INSERT INTO job_lifecycle_change (job_id, seq, field, old_value, new_value)
      VALUES (NEW.job_id, next_seq, 'wait_reason', OLD.wait_reason, NEW.wait_reason);
  END IF;
  RETURN NULL;
END $$;
CREATE TRIGGER lifecycle_history AFTER UPDATE ON scan_job
  FOR EACH ROW EXECUTE FUNCTION aegis.record_job_lifecycle();

-- 3. Terminal result is final; reopening is an explicit, fenced re-execution, never a silent reset.
CREATE FUNCTION aegis.guard_scan_job_lifecycle() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE terminal text[] := ARRAY['SUCCEEDED', 'FAILED', 'CANCELLED'];
BEGIN
  IF OLD.status = ANY(terminal) THEN
    IF NEW.status = ANY(terminal) THEN
      IF NEW.status <> OLD.status THEN
        RAISE EXCEPTION 'terminal result is final; % cannot become %', OLD.status, NEW.status
          USING ERRCODE = 'check_violation';
      END IF;
    ELSE
      -- Reopening is an explicit, fenced re-execution: a new generation with a clean result.
      IF NEW.generation <> OLD.generation + 1 OR NEW.attempt <> 1 OR NEW.status <> 'QUEUED'
         OR NEW.started_at IS NOT NULL OR NEW.finished_at IS NOT NULL
         OR NEW.envelope_event_id IS NOT NULL OR NEW.error IS NOT NULL
         OR NEW.cancel_requested_at IS NOT NULL THEN
        RAISE EXCEPTION 'reopening a terminal job needs generation+1, attempt=1, status QUEUED and a cleared result (started_at/finished_at/error/envelope_event_id/cancel intent)'
          USING ERRCODE = 'check_violation';
      END IF;
      RETURN NEW;
    END IF;
  ELSE
    IF NEW.generation <> OLD.generation THEN
      RAISE EXCEPTION 'generation changes only when a terminal job is reopened'
        USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.attempt NOT IN (OLD.attempt, OLD.attempt + 1) THEN
      RAISE EXCEPTION 'attempt increases by at most 1 per dispatch (% -> %)', OLD.attempt, NEW.attempt
        USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  IF OLD.cancel_requested_at IS NOT NULL THEN
    IF NEW.cancel_requested_at IS DISTINCT FROM OLD.cancel_requested_at
       OR NEW.cancel_requested_by IS DISTINCT FROM OLD.cancel_requested_by
       OR NEW.cancel_reason IS DISTINCT FROM OLD.cancel_reason THEN
      RAISE EXCEPTION 'cancel intent is written once; only a new generation clears it'
        USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER lifecycle_guard BEFORE UPDATE ON scan_job
  FOR EACH ROW EXECUTE FUNCTION aegis.guard_scan_job_lifecycle();

-- 4. Late results keep their audit instead of overwriting a terminal result. The payload stays where
--    it already is (raw evidence + C03 payload_hash); this row records why it was not applied.
CREATE TABLE job_callback_quarantine (
  quarantine_id uuid        PRIMARY KEY,
  job_id        uuid        NOT NULL REFERENCES scan_job,
  generation    integer     NOT NULL CHECK (generation >= 1),
  attempt       integer     NOT NULL CHECK (attempt >= 1),
  callback      text        NOT NULL CHECK (callback IN ('started', 'completed')),
  reason        text        NOT NULL CHECK (reason IN (
                              'stale_generation', 'stale_attempt', 'attempt_not_started',
                              'terminal_already_recorded', 'cancel_not_requested')),
  claimed       jsonb       NOT NULL DEFAULT '{}'::jsonb,
  payload_hash  char(64)    CHECK (payload_hash IS NULL OR payload_hash ~ '^[0-9a-f]{64}$'),
  evidence_refs jsonb       NOT NULL DEFAULT '[]'::jsonb,
  recorded_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (job_id, generation, attempt, callback, reason)
);
SELECT aegis.protect('job_callback_quarantine'::regclass, true);

-- 5. Cancel writes intent only. It never changes status and never rewrites a terminal result; M06
--    stops the container and calls record_job_callback(status => 'CANCELLED').
CREATE FUNCTION aegis.request_job_cancel(p_job_id uuid, p_actor jsonb, p_reason text DEFAULT NULL)
RETURNS text LANGUAGE plpgsql AS $$
DECLARE j scan_job;
BEGIN
  SELECT * INTO j FROM scan_job WHERE job_id = p_job_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'job % not found', p_job_id USING ERRCODE = 'no_data_found';
  END IF;
  IF j.status IN ('SUCCEEDED', 'FAILED', 'CANCELLED') THEN
    RETURN 'terminal';
  END IF;
  IF j.cancel_requested_at IS NOT NULL THEN
    RETURN 'already_requested';
  END IF;
  UPDATE scan_job
     SET cancel_requested_at = now(), cancel_requested_by = p_actor, cancel_reason = p_reason
   WHERE job_id = p_job_id;
  RETURN 'requested';
END $$;
COMMENT ON FUNCTION aegis.request_job_cancel(uuid, jsonb, text) IS
  'M02/M26. Returns requested | already_requested | terminal. Idempotent: the first who asks records the intent, a terminal job is left untouched.';

-- 6. The one terminal CAS. The row lock plus the (generation, attempt) fence decide which concurrent
--    result wins; the loser is quarantined, never applied. Exactly one terminal result exists.
CREATE FUNCTION aegis.record_job_callback(
  p_job_id uuid,
  p_generation integer,
  p_attempt integer,
  p_status text,
  p_envelope_event_id uuid DEFAULT NULL,
  p_error jsonb DEFAULT NULL,
  p_payload_hash char(64) DEFAULT NULL,
  p_claimed jsonb DEFAULT '{}'::jsonb,
  p_evidence_refs jsonb DEFAULT '[]'::jsonb,
  p_quarantine_id uuid DEFAULT NULL)
RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  j scan_job;
  v_reason text;
  v_next_seq integer;
BEGIN
  IF p_status NOT IN ('SUCCEEDED', 'FAILED', 'CANCELLED') THEN
    RAISE EXCEPTION 'record_job_callback records a terminal result, got %', p_status
      USING ERRCODE = 'check_violation';
  END IF;
  SELECT * INTO j FROM scan_job WHERE job_id = p_job_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'job % not found', p_job_id USING ERRCODE = 'no_data_found';
  END IF;

  IF p_generation < j.generation THEN
    v_reason := 'stale_generation';
  ELSIF p_attempt < j.attempt THEN
    v_reason := 'stale_attempt';
  ELSIF p_attempt > j.attempt THEN
    v_reason := 'attempt_not_started';
  ELSIF j.status IN ('SUCCEEDED', 'FAILED', 'CANCELLED') THEN
    IF j.status = p_status AND j.envelope_event_id IS NOT DISTINCT FROM p_envelope_event_id THEN
      RETURN 'duplicate';  -- idempotent replay of the exact result that is already recorded
    END IF;
    v_reason := 'terminal_already_recorded';
  ELSIF j.status IN ('QUEUED', 'VALIDATING') AND p_status <> 'CANCELLED' THEN
    v_reason := 'attempt_not_started';
  ELSIF p_status = 'CANCELLED' AND j.cancel_requested_at IS NULL THEN
    v_reason := 'cancel_not_requested';
  END IF;

  IF v_reason IS NOT NULL THEN
    INSERT INTO job_callback_quarantine
      (quarantine_id, job_id, generation, attempt, callback, reason, claimed, payload_hash, evidence_refs)
    VALUES (coalesce(p_quarantine_id, gen_random_uuid()), p_job_id, p_generation, p_attempt,
            'completed', v_reason, p_claimed, p_payload_hash, p_evidence_refs)
    ON CONFLICT (job_id, generation, attempt, callback, reason) DO NOTHING;
    RETURN 'quarantined';
  END IF;

  UPDATE scan_job
     SET status = p_status, finished_at = now(), envelope_event_id = p_envelope_event_id, error = p_error
   WHERE job_id = p_job_id AND status = j.status AND generation = p_generation AND attempt = p_attempt;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'terminal CAS lost for job % on generation % attempt %', p_job_id, p_generation, p_attempt
      USING ERRCODE = 'serialization_failure';
  END IF;
  SELECT coalesce(max(seq), 0) + 1 INTO v_next_seq FROM job_status_change WHERE job_id = p_job_id;
  INSERT INTO job_status_change (job_id, seq, from_status, to_status, error)
    VALUES (p_job_id, v_next_seq, j.status, p_status, p_error);
  RETURN 'terminalized';
END $$;
COMMENT ON FUNCTION aegis.record_job_callback(uuid, integer, integer, text, uuid, jsonb, char, jsonb, jsonb, uuid) IS
  'M06. Returns terminalized | duplicate | quarantined. Only the current (generation, attempt) may terminalize; a duplicate of the recorded result is idempotent; a stale or conflicting callback leaves a job_callback_quarantine row. Evidence already collected stays linked to the job.';

-- 7. The D26 column whitelist now includes the new mutable lifecycle columns.
DROP TRIGGER cols_only ON scan_job;
CREATE TRIGGER cols_only BEFORE UPDATE ON scan_job FOR EACH ROW EXECUTE FUNCTION aegis.forbid_value_update(
  'status','error','envelope_event_id','started_at','finished_at',
  'attempt','generation','cancel_requested_at','cancel_requested_by','cancel_reason','wait_reason');

COMMENT ON COLUMN scan_job.attempt IS
  'Dispatch attempt within the current generation, 1 on insert, +1 per re-dispatch of a non-terminal job. A callback from another attempt is quarantined.';
COMMENT ON COLUMN scan_job.generation IS
  'Re-execution generation, 1 on insert, +1 only when a terminal job is reopened (attempt back to 1, result columns cleared). Different from scan_cycle (a new scan is a new job) and from an envelope retry.';
COMMENT ON COLUMN scan_job.cancel_requested_at IS
  'Cancel intent, written once by aegis.request_job_cancel and immutable afterwards; the job only becomes CANCELLED through aegis.record_job_callback. Cleared only by generation+1.';
COMMENT ON COLUMN scan_job.wait_reason IS
  'X-4 wait reason (job.v2#/$defs/WaitReason) while status=QUEUED: dependency, campaign pause, budget, window, concurrency, rate, provider or operator hold. NULL means dispatchable. Every change is kept in job_lifecycle_change.';
COMMENT ON TABLE job_lifecycle_change IS
  'C06 append-only history of attempt, generation, cancel intent and wait reason. Written by the scan_job trigger; status history stays in job_status_change.';
COMMENT ON TABLE job_callback_quarantine IS
  'C06 append-only record of a late or conflicting result callback: which generation/attempt claimed what, and why it was not applied. The payload itself stays with its evidence and C03 payload_hash.';

COMMIT;
