-- S1 follow-up (gate review OI-6, OI-8, OI-9). The contract said these values are bound to each other;
-- the database only checked their shape. Apply after 0011.
--   OI-8: proposed_by names an agent_session of the same campaign, and the job is the decision's job
--         (same campaign, same actors, same resolved targets); ProposedBy.id is a session id, not text.
--   OI-6: policy_decision carries target_refs (so a denied keyword/CIDR request keeps its seed), and
--         the `targets` projection of both rows must be canonical keys of those refs.
--   OI-9: cancel_requested_by is an Actor, validated when it is written; an agent may only cancel a
--         job it proposed.
BEGIN;
SET LOCAL search_path = aegis, public;

-- ---------------------------------------------------------------------------
-- 1. OI-8 / D-3 — ProposedBy.id is the session_id (UUIDv7), the same type as agent_session.session_id
--    and TraceContext.session_id. A free-text proposer could never be joined to a session, so "the
--    session that proposed this" was unverifiable.
CREATE OR REPLACE FUNCTION aegis.is_proposer(actor jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN jsonb_typeof(actor) <> 'object' THEN false
    WHEN jsonb_typeof(actor->'kind') <> 'string' OR jsonb_typeof(actor->'id') <> 'string' THEN false
    WHEN actor->>'kind' <> 'agent' THEN false
    WHEN actor->>'id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN
      (SELECT count(*) FROM jsonb_object_keys(actor)) = 2
    ELSE false
  END
$$;
COMMENT ON FUNCTION aegis.is_proposer(jsonb) IS
  'True for a proposer: exactly {kind: agent, id} where id is the agent_session.session_id (UUIDv7). A label is not a session.';

-- The proposer must be an existing session of the same campaign: proposed_by is what makes a job
-- traceable to the agent that asked for it (C05), and a dangling session made that claim empty.
-- policy_decision also carries session_id; when both are present they must be the same session.
CREATE FUNCTION aegis.require_job_proposer_session() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.proposed_by IS NULL THEN
    RETURN NEW;
  END IF;
  IF NOT aegis.is_proposer(NEW.proposed_by) THEN
    RAISE EXCEPTION 'proposed_by must be {kind: agent, id: <session_id>}; a label is not a session'
      USING ERRCODE = 'check_violation';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM agent_session s
                  WHERE s.session_id = (NEW.proposed_by->>'id')::uuid
                    AND s.campaign_id = NEW.campaign_id) THEN
    RAISE EXCEPTION 'proposed_by names session % which is not an agent_session of campaign %',
      NEW.proposed_by->>'id', NEW.campaign_id
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
COMMENT ON FUNCTION aegis.require_job_proposer_session() IS
  'C05/OI-8: a proposer is a real agent session of the same campaign; a label or a session from another campaign is refused.';

CREATE FUNCTION aegis.require_decision_proposer_session() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.proposed_by IS NULL THEN
    RETURN NEW;
  END IF;
  IF NOT aegis.is_proposer(NEW.proposed_by) THEN
    RAISE EXCEPTION 'proposed_by must be {kind: agent, id: <session_id>}; a label is not a session'
      USING ERRCODE = 'check_violation';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM agent_session s
                  WHERE s.session_id = (NEW.proposed_by->>'id')::uuid
                    AND s.campaign_id = NEW.campaign_id) THEN
    RAISE EXCEPTION 'proposed_by names session % which is not an agent_session of campaign %',
      NEW.proposed_by->>'id', NEW.campaign_id
      USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.session_id IS DISTINCT FROM (NEW.proposed_by->>'id')::uuid THEN
    RAISE EXCEPTION 'policy_decision.session_id (%) must be the proposing session (proposed_by.id %)',
      NEW.session_id, NEW.proposed_by->>'id'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER proposer_session_required BEFORE INSERT ON scan_job
  FOR EACH ROW EXECUTE FUNCTION aegis.require_job_proposer_session();
CREATE TRIGGER proposer_session_required BEFORE INSERT ON policy_decision
  FOR EACH ROW EXECUTE FUNCTION aegis.require_decision_proposer_session();
COMMENT ON FUNCTION aegis.require_decision_proposer_session() IS
  'C05/OI-8: the decision proposer is an agent_session of the same campaign, and session_id is that session (one session per proposal, not two).';

-- ---------------------------------------------------------------------------
-- 2. OI-6 — TargetRefs on the decision, and `targets` is the canonical-key projection of them.
--
-- 0005 bound the job to its seed but left the decision with only `targets text[]`, so a denied
-- keyword/CIDR request (no canonical key) had no seed reference at all, and nothing tied the job's
-- refs to the decision that approved it.
CREATE FUNCTION aegis.is_canonical_projection(targets text[], refs jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
  SELECT refs IS NULL
     OR NOT EXISTS (
       SELECT 1 FROM unnest(targets) AS t
        WHERE NOT EXISTS (
          SELECT 1 FROM jsonb_array_elements(refs) AS e
           WHERE aegis.is_target_ref(e) AND e ? 'canonical_key' AND e->>'canonical_key' = t));
$$;
COMMENT ON FUNCTION aegis.is_canonical_projection(text[], jsonb) IS
  'True when every element of `targets` is the canonical_key of a TargetRef in `refs` (targets is a projection, never the identity source). NULL refs = row predating the rule.';

ALTER TABLE policy_decision ADD COLUMN target_refs jsonb;
ALTER TABLE policy_decision
  ADD CONSTRAINT policy_decision_target_refs_shape
    CHECK (target_refs IS NULL OR aegis.is_target_refs(target_refs));

-- The projection rule (`targets` ⊆ canonical_key(target_refs)) is deliberately NOT a CHECK here: a
-- validated CHECK cannot be added over a 0005-0011 database whose `targets` holds the seed's own
-- canonical key, and a NOT VALID one would still re-check that legacy row on its next cancel or
-- terminal update. It is an INSERT-only trigger from 0014, which also holds such rows for dispatch
-- (LEGACY_TARGET_PROJECTION). Rule of this bundle: a tightened rule over history is an insert-time
-- rule, never a row constraint (see 0010 on requested_by, 0014 on this one).

CREATE FUNCTION aegis.require_decision_target_refs() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE foreign_seed uuid;
BEGIN
  IF NEW.target_refs IS NULL THEN
    RAISE EXCEPTION 'new policy_decision requires target_refs (TargetRef list); a decision is not attributable to a seed without it'
      USING ERRCODE = 'check_violation';
  END IF;
  IF jsonb_typeof(NEW.target_refs) = 'array' THEN
    SELECT (e->>'seed_id')::uuid INTO foreign_seed
      FROM jsonb_array_elements(NEW.target_refs) AS e
     WHERE aegis.is_target_ref(e) AND e ? 'seed_id'
       AND NOT EXISTS (
         SELECT 1
           FROM campaign_target ct
           JOIN campaign c ON c.campaign_id = NEW.campaign_id
          WHERE ct.target_id = (e->>'seed_id')::uuid
            AND ct.scope_id = NEW.scope_id
            AND c.scope_id = ct.scope_id)
     LIMIT 1;
    IF foreign_seed IS NOT NULL THEN
      RAISE EXCEPTION 'decision seed % is not a campaign_target of campaign % (scope %)',
        foreign_seed, NEW.campaign_id, NEW.scope_id
        USING ERRCODE = 'foreign_key_violation';
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER target_refs_required BEFORE INSERT ON policy_decision
  FOR EACH ROW EXECUTE FUNCTION aegis.require_decision_target_refs();
COMMENT ON COLUMN policy_decision.target_refs IS
  'C02/OI-6 TargetRef list of the decided request ({seed_id} of a campaign_target in the same campaign/scope, or {canonical_key}); required for new rows, NULL only for rows predating 0012, which stay read-only. Immutable: policy_decision is append-only.';
COMMENT ON FUNCTION aegis.require_decision_target_refs() IS
  'OI-6: mirrors 0005 on the decision, so the seed a job will inherit is checked before the job exists.';
COMMENT ON COLUMN policy_decision.targets IS
  'Legacy canonical-key projection of the request (authoritative only for rows predating 0012). For newer rows it is the canonical_key subset of target_refs and may be empty when every target is a keyword/CIDR seed.';
COMMENT ON COLUMN scan_job.targets IS
  'Legacy canonical-key projection: authoritative for rows predating 0005. For newer jobs it is the canonical_key subset of target_refs (enforced on INSERT by aegis.require_canonical_projection, 0014) and may be empty when every target is a keyword/CIDR seed. Never the source of identity or provenance for new jobs.';

-- ---------------------------------------------------------------------------
-- 3. OI-8 — the job is the job of its decision.
--
-- M05 derives the request and the job from one policy decision; the database only had an FK on
-- decision_id, so a writer could pair a decision with another campaign's job, or relabel the actors
-- on the way from the decision to the job. Both rows now have to agree.
CREATE FUNCTION aegis.require_job_decision_consistency() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE d policy_decision;
BEGIN
  SELECT * INTO d FROM policy_decision WHERE decision_id = NEW.decision_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'job % references unknown policy_decision %', NEW.job_id, NEW.decision_id
      USING ERRCODE = 'check_violation';
  END IF;
  IF d.campaign_id <> NEW.campaign_id THEN
    RAISE EXCEPTION 'job % is in campaign % but its decision % belongs to campaign %',
      NEW.job_id, NEW.campaign_id, NEW.decision_id, d.campaign_id
      USING ERRCODE = 'check_violation';
  END IF;
  IF d.requested_by IS DISTINCT FROM NEW.requested_by THEN
    RAISE EXCEPTION 'job % requested_by (%) differs from its decision (%)',
      NEW.job_id, NEW.requested_by, d.requested_by
      USING ERRCODE = 'check_violation';
  END IF;
  IF d.proposed_by IS DISTINCT FROM NEW.proposed_by THEN
    RAISE EXCEPTION 'job % proposed_by (%) differs from its decision (%)',
      NEW.job_id, NEW.proposed_by, d.proposed_by
      USING ERRCODE = 'check_violation';
  END IF;
  IF d.target_refs IS NOT NULL AND d.target_refs IS DISTINCT FROM NEW.target_refs THEN
    RAISE EXCEPTION 'job % target_refs differ from the targets its decision resolved (% vs %)',
      NEW.job_id, NEW.target_refs, d.target_refs
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER decision_consistency_required BEFORE INSERT ON scan_job
  FOR EACH ROW EXECUTE FUNCTION aegis.require_job_decision_consistency();
COMMENT ON FUNCTION aegis.require_job_decision_consistency() IS
  'C05/OI-8: one decision, one job: same campaign, same requested_by/proposed_by, same resolved target_refs. M05 derives both from the same decision, so a difference is a bug or a forged job.';

-- ---------------------------------------------------------------------------
-- 4. OI-9 — the cancel actor.
--
-- 0007 wrote cancel_requested_by as free JSON, so any string was accepted and then broke the read
-- model (CancelIntent.requested_by is an Actor). Who may cancel: an operator or a module, and an
-- agent only for a job it proposed. A cancel is still an intent, not a terminal state.
CREATE FUNCTION aegis.is_actor(actor jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN jsonb_typeof(actor) <> 'object' THEN false
    WHEN jsonb_typeof(actor->'kind') <> 'string' OR jsonb_typeof(actor->'id') <> 'string' THEN false
    WHEN actor->>'kind' NOT IN ('operator', 'module', 'agent') THEN false
    WHEN length(btrim(actor->>'id')) BETWEEN 1 AND 200 THEN
      (SELECT count(*) FROM jsonb_object_keys(actor)) = 2
    ELSE false
  END
$$;
COMMENT ON FUNCTION aegis.is_actor(jsonb) IS
  'True for the audit Actor shape: exactly {kind: operator|module|agent, id non-empty}. is_initiator/is_proposer stay stricter where the role matters.';

ALTER TABLE scan_job ADD CONSTRAINT scan_job_cancel_actor_shape
  CHECK (cancel_requested_by IS NULL OR aegis.is_actor(cancel_requested_by));

CREATE FUNCTION aegis.require_cancel_actor() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.cancel_requested_by IS NOT DISTINCT FROM OLD.cancel_requested_by THEN
    RETURN NEW;
  END IF;
  IF NOT aegis.is_actor(NEW.cancel_requested_by) THEN
    RAISE EXCEPTION 'cancel_requested_by must be an Actor {kind: operator|module|agent, id}'
      USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.cancel_requested_by->>'kind' = 'agent'
     AND (NEW.proposed_by IS NULL OR NEW.proposed_by->>'id' <> NEW.cancel_requested_by->>'id') THEN
    RAISE EXCEPTION 'an agent may only cancel a job it proposed (proposer %)', NEW.proposed_by
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER cancel_actor_required BEFORE UPDATE ON scan_job
  FOR EACH ROW EXECUTE FUNCTION aegis.require_cancel_actor();
COMMENT ON FUNCTION aegis.require_cancel_actor() IS
  'OI-9: the cancel intent names a shape-checked Actor; an agent cannot cancel work it did not propose.';

CREATE OR REPLACE FUNCTION aegis.request_job_cancel(p_job_id uuid, p_actor jsonb, p_reason text DEFAULT NULL)
RETURNS text LANGUAGE plpgsql AS $$
DECLARE j scan_job;
BEGIN
  IF NOT aegis.is_actor(p_actor) THEN
    RAISE EXCEPTION 'cancel actor must be an Actor {kind: operator|module|agent, id}'
      USING ERRCODE = 'check_violation';
  END IF;
  SELECT * INTO j FROM scan_job WHERE job_id = p_job_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'job % not found', p_job_id USING ERRCODE = 'no_data_found';
  END IF;
  IF p_actor->>'kind' = 'agent'
     AND (j.proposed_by IS NULL OR j.proposed_by->>'id' <> p_actor->>'id') THEN
    RAISE EXCEPTION 'an agent may only cancel a job it proposed (proposer %)', j.proposed_by
      USING ERRCODE = 'check_violation';
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
  'M02/M26 (and the proposing session for its own job). Returns requested | already_requested | terminal. Idempotent: the first who asks records the intent; a terminal job is left untouched; the actor must be an Actor and an agent may only cancel a job it proposed.';
COMMENT ON COLUMN scan_job.cancel_requested_by IS
  'OI-9 cancel actor: an Actor (operator|module|agent), shape-checked; an agent may only cancel a job whose proposed_by is its own session. Written once by aegis.request_job_cancel and immutable afterwards.';

-- ---------------------------------------------------------------------------
-- 5. Pin what this migration created.
--
-- 0011's sweep runs once, at its own position, so anything created here starts unpinned. The catalog
-- test (tests/search_path_pinning.sql) fails on that, and this is the fix it points at.
DO $$
DECLARE
  fn record;
  pinned int := 0;
BEGIN
  FOR fn IN
    SELECT p.oid::regprocedure AS signature
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'aegis'
       AND NOT EXISTS (SELECT 1 FROM unnest(coalesce(p.proconfig, '{}'::text[])) AS cfg
                        WHERE cfg LIKE 'search_path=%')
     ORDER BY 1::text
  LOOP
    EXECUTE format('ALTER FUNCTION %s SET search_path = aegis, pg_temp', fn.signature);
    pinned := pinned + 1;
  END LOOP;
  RAISE NOTICE '0012: % aegis function(s) got search_path = aegis, pg_temp', pinned;
END $$;

COMMIT;
