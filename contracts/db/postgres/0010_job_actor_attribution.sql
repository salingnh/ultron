-- C05/S1.5a: actor attribution for the decision and the job.
-- requested_by is the server-verified initiator (operator|module); proposed_by is the agent session that
-- proposed the request. Both are assigned by M05 from its own context, never from request or LLM input.
-- Apply after 0008. Prior rows keep their self-declared actor and carry no proposed_by: history is not
-- reinterpreted and no operator is invented for it.
BEGIN;
SET LOCAL search_path = aegis, public;

-- Shape helpers. The kind is what the database can decide: an initiator is a principal or a platform
-- module, a proposer is an agent session. Who those identifiers are belongs to the identity source (open,
-- see docs/living/dac-ta-ky-thuat/04-module-ket-noi-oss.md §C05 / OD-5), not to this row.
CREATE FUNCTION aegis.is_initiator(actor jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN jsonb_typeof(actor) <> 'object' THEN false
    WHEN jsonb_typeof(actor->'kind') <> 'string' OR jsonb_typeof(actor->'id') <> 'string' THEN false
    WHEN actor->>'kind' NOT IN ('operator', 'module') THEN false
    WHEN length(btrim(actor->>'id')) BETWEEN 1 AND 200 THEN
      (SELECT count(*) FROM jsonb_object_keys(actor)) = 2
    ELSE false
  END
$$;
COMMENT ON FUNCTION aegis.is_initiator(jsonb) IS
  'True for a server-derived initiator: exactly {kind, id} with kind operator|module and a non-empty opaque id. An agent cannot be the initiator of a job (C05).';

CREATE FUNCTION aegis.is_proposer(actor jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN jsonb_typeof(actor) <> 'object' THEN false
    WHEN jsonb_typeof(actor->'kind') <> 'string' OR jsonb_typeof(actor->'id') <> 'string' THEN false
    WHEN actor->>'kind' <> 'agent' THEN false
    WHEN length(btrim(actor->>'id')) BETWEEN 1 AND 200 THEN
      (SELECT count(*) FROM jsonb_object_keys(actor)) = 2
    ELSE false
  END
$$;
COMMENT ON FUNCTION aegis.is_proposer(jsonb) IS
  'True for a proposer: exactly {kind, id} with kind agent (id = agent session). An operator or module is an initiator, not a proposer.';

-- history: v1 rows carry a self-declared actor (often the agent itself). A CHECK would also be
-- re-evaluated when such a row is updated, and a held legacy job must still record its terminal result
-- (0007, S1.6), so the initiator rule is an INSERT-only trigger: new rows must pass, old rows stay usable.
CREATE FUNCTION aegis.require_job_initiator() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT aegis.is_initiator(NEW.requested_by) THEN
    RAISE EXCEPTION 'new row requires a server-derived initiator in requested_by (kind operator|module, opaque id); an agent or a self-declared label cannot start a job'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
COMMENT ON FUNCTION aegis.require_job_initiator() IS
  'C05: M05 writes requested_by from its own verified principal. Enforced on INSERT only so pre-0010 rows remain updatable for terminal results and cancel (they are never dispatched).';

CREATE TRIGGER initiator_required BEFORE INSERT ON policy_decision
  FOR EACH ROW EXECUTE FUNCTION aegis.require_job_initiator();
CREATE TRIGGER initiator_required BEFORE INSERT ON scan_job
  FOR EACH ROW EXECUTE FUNCTION aegis.require_job_initiator();

ALTER TABLE policy_decision ADD COLUMN proposed_by jsonb;
ALTER TABLE scan_job ADD COLUMN proposed_by jsonb;

ALTER TABLE policy_decision ADD CONSTRAINT proposed_by_is_agent_session
  CHECK (proposed_by IS NULL OR aegis.is_proposer(proposed_by));
ALTER TABLE scan_job ADD CONSTRAINT proposed_by_is_agent_session
  CHECK (proposed_by IS NULL OR aegis.is_proposer(proposed_by));

-- policy_decision is append-only (see 0001 grants); the scan_job cols_only trigger already keeps every
-- non-status column immutable, so neither actor can be rewritten after acceptance.
COMMENT ON COLUMN policy_decision.proposed_by IS
  'C05 agent session that proposed the request. NULL when an operator or module submitted it directly; never a fabricated session. Assigned by M05 from the session context, not from request input.';
COMMENT ON COLUMN scan_job.proposed_by IS
  'C05 agent session that proposed the job. NULL for direct operator/module submissions and for rows predating 0010 (which stay ineligible for dispatch/replay). Immutable after acceptance.';
COMMENT ON COLUMN scan_job.requested_by IS
  'C05 server-derived initiator: aegis.require_job_initiator enforces {kind: operator|module, id} on INSERT. A row whose actor predates 0010 keeps that value as history and is not dispatchable.';

COMMIT;
