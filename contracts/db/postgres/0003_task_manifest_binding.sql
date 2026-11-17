-- Pin the immutable manifest used by each newly accepted job.
-- Apply after 0002. Prior rows keep NULL: no invented hash for historical jobs.
BEGIN;
SET LOCAL search_path = aegis, public;
ALTER TABLE scan_job ADD COLUMN manifest_sha256 char(64)
  CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$');

CREATE FUNCTION aegis.require_job_manifest() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.manifest_sha256 IS NULL THEN
    RAISE EXCEPTION 'new job requires manifest_sha256'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER manifest_required BEFORE INSERT ON scan_job
  FOR EACH ROW EXECUTE FUNCTION aegis.require_job_manifest();

-- Existing cols_only trigger also protects this new value from UPDATE.
COMMENT ON COLUMN scan_job.manifest_sha256 IS
  'SHA-256 of exact immutable manifest bytes; required for new jobs, NULL only for prior history. A job without a pin is ineligible for dispatch/replay until separately migrated.';
COMMENT ON COLUMN scan_job.job_fingerprint IS
  'Current contract: hash(campaign,policy_version,provider,provider_version,adapter_version,image_digest,manifest_sha256,targets,input,scan_cycle). Scheduling is excluded; conflicting scheduling for an existing job is rejected. Prior hashes remain historical.';
COMMIT;
