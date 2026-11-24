-- C02: seed reference across request -> task -> job -> provenance.
-- Apply after 0004. Prior rows keep the canonical-key-only `targets` and no invented refs;
-- a job without target_refs stays ineligible for dispatch/replay until separately migrated.
BEGIN;
SET LOCAL search_path = aegis, public;

-- Shape helpers. Full canonical-key/IP/domain conformance stays in contracts/validation.py and M07;
-- these are the structural and namespace guards the database can enforce on its own.
CREATE FUNCTION aegis.is_target_ref(item jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN jsonb_typeof(item) <> 'object' THEN false
    WHEN (SELECT count(*) FROM jsonb_object_keys(item)) <> 1 THEN false
    WHEN item ? 'seed_id' THEN
      jsonb_typeof(item->'seed_id') = 'string'
      AND item->>'seed_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    WHEN item ? 'canonical_key' THEN
      jsonb_typeof(item->'canonical_key') = 'string'
      AND length(item->>'canonical_key') BETWEEN 3 AND 2048
      AND item->>'canonical_key' ~ '^(dns|ip|service|app|url|email|oci|repo|git|artifact|purl|cloud|k8s):[^[:space:]]+$'
    ELSE false
  END
$$;
COMMENT ON FUNCTION aegis.is_target_ref(jsonb) IS
  'True for exactly one of {seed_id} or {canonical_key}. seed_id is a target_id of campaign_target; a keyword/CIDR seed has no canonical key, so fabricating one is a shape error.';

CREATE FUNCTION aegis.is_target_refs(refs jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN jsonb_typeof(refs) <> 'array' THEN false
    WHEN jsonb_array_length(refs) NOT BETWEEN 1 AND 1000 THEN false
    ELSE NOT EXISTS (SELECT 1 FROM jsonb_array_elements(refs) AS e WHERE NOT aegis.is_target_ref(e))
  END
$$;
COMMENT ON FUNCTION aegis.is_target_refs(jsonb) IS
  'True for a non-empty TargetRef array; mirrors approved-task/job/result-envelope targets.';

ALTER TABLE scan_job ADD COLUMN target_refs jsonb;
ALTER TABLE scan_job ADD CONSTRAINT scan_job_target_refs_shape
  CHECK (target_refs IS NULL OR aegis.is_target_refs(target_refs));

-- A new job may have an empty canonical-key projection when all its targets are keyword/CIDR seeds;
-- rows predating 0005 keep the original non-empty `targets` guarantee.
ALTER TABLE scan_job DROP CONSTRAINT scan_job_targets_check;
ALTER TABLE scan_job ADD CONSTRAINT scan_job_targets_legacy_projection
  CHECK (target_refs IS NOT NULL OR cardinality(targets) > 0);

CREATE FUNCTION aegis.require_job_target_refs() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE foreign_seed uuid;
BEGIN
  IF NEW.target_refs IS NULL THEN
    RAISE EXCEPTION 'new job requires target_refs (TargetRef list); a job is not dispatchable without seed provenance'
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
      RAISE EXCEPTION 'target seed % is not a campaign_target of campaign % (scope %)',
        foreign_seed, NEW.campaign_id, NEW.scope_id
        USING ERRCODE = 'foreign_key_violation';
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER target_refs_required BEFORE INSERT ON scan_job
  FOR EACH ROW EXECUTE FUNCTION aegis.require_job_target_refs();

-- G5 at the provenance row: a seed may only be recorded as the origin of an asset in its own campaign.
CREATE FUNCTION aegis.require_provenance_seed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.from_target_id IS NOT NULL
     AND NOT EXISTS (
       SELECT 1
         FROM campaign_target ct
         JOIN campaign c ON c.campaign_id = NEW.campaign_id
        WHERE ct.target_id = NEW.from_target_id
          AND c.scope_id = ct.scope_id)
  THEN
    RAISE EXCEPTION 'provenance seed % is not a campaign_target of campaign %',
      NEW.from_target_id, NEW.campaign_id
      USING ERRCODE = 'foreign_key_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER seed_in_campaign BEFORE INSERT ON asset_provenance
  FOR EACH ROW EXECUTE FUNCTION aegis.require_provenance_seed();

-- The existing cols_only trigger already keeps target_refs immutable after INSERT: it is not one of
-- the status columns, so a dispatch/replay cannot rewrite the seed chain of an accepted job.
COMMENT ON COLUMN scan_job.target_refs IS
  'C02 TargetRef list: {seed_id} for a campaign_target of the same campaign/scope (keeps keyword/CIDR seeds without inventing an asset) or {canonical_key} for a known asset. Required for new jobs; NULL only on rows predating 0005, which stay ineligible for dispatch/replay. Immutable after acceptance.';
COMMENT ON COLUMN scan_job.targets IS
  'Legacy canonical-key projection: authoritative for rows predating 0005. For newer jobs it is only the canonical_key subset of target_refs and may be empty when every target is a keyword/CIDR seed. Never the source of identity or provenance for new jobs.';

COMMIT;
