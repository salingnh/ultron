-- G1.1c: the immutable manifest registry and the record of the signed task (OI-7, E-1).
--
-- M05 has to answer four questions with durable evidence:
--   * which manifest bytes did a job run, so M06 can fetch *that* version and never "latest" (0003 pins
--     the hash; until now nothing stored the bytes the hash names);
--   * what exactly did the policy decision approve, so a retry/replay can prove it is the same request
--     (0014 already requires decision.input = the merged input the job runs);
--   * which network targets the signature allowed the broker to open (E-1);
--   * which request body an Idempotency-Key was first used for, so the same key with a different body
--     is a 409 instead of a silently different job.
--
-- Apply after 0014. Independent of 0015 (G1.4a) and 0017/0018: it only adds objects.
BEGIN;
SET LOCAL search_path = aegis, public;

-- ---------------------------------------------------------------------------
-- 1. The registry: one row per exact manifest byte string, keyed by its SHA-256.
--
-- The contract is explicit that the hash is taken over the bytes the registry accepted, never over a
-- re-serialised parse (interfaces/README.md §Manifest bất biến). The CHECK below enforces that at the
-- storage layer: a row whose hash does not describe its own bytes cannot exist. The derived columns
-- are what resolution indexes on; M05 re-parses `manifest_utf8` and re-derives them on read, so a
-- disagreement is a loud error instead of a quiet wrong pin.
CREATE TABLE provider_manifest (
  manifest_sha256  char(64)    PRIMARY KEY,
  capability       text        NOT NULL,
  provider         text        NOT NULL,
  provider_version text        NOT NULL,
  adapter_version  text        NOT NULL,
  image_digest     text        NOT NULL,
  input_schema_ref text        NOT NULL,
  manifest_utf8    bytea       NOT NULL,
  registered_at    timestamptz NOT NULL DEFAULT now(),
  registered_by    jsonb       NOT NULL,
  CONSTRAINT provider_manifest_sha256_shape
    CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT provider_manifest_sha256_describes_bytes
    CHECK (manifest_sha256 = encode(sha256(manifest_utf8), 'hex')),
  CONSTRAINT provider_manifest_bytes_present
    CHECK (length(manifest_utf8) > 0),
  CONSTRAINT provider_manifest_capability_shape
    CHECK (capability ~ '^[a-z][a-z0-9]*\.[a-z][a-z0-9_]*$'),
  CONSTRAINT provider_manifest_provider_present
    CHECK (length(btrim(provider)) BETWEEN 1 AND 200),
  CONSTRAINT provider_manifest_provider_version_present
    CHECK (length(btrim(provider_version)) BETWEEN 1 AND 128),
  CONSTRAINT provider_manifest_adapter_version_semver
    CHECK (adapter_version ~ '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$'),
  CONSTRAINT provider_manifest_image_digest_shape
    CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
  CONSTRAINT provider_manifest_input_schema_ref_shape
    CHECK (input_schema_ref ~ '^schema://[a-z0-9-]+/[a-z0-9-]+/v[0-9]+$'),
  CONSTRAINT provider_manifest_registered_by_actor
    CHECK (aegis.is_actor(registered_by)),
  -- One build of one adapter version. Re-registering unchanged bytes is the same row (the primary key
  -- answers it); registering *different* bytes as the same version would make resolution ambiguous, so
  -- it is refused instead of becoming a second "1.0.0".
  CONSTRAINT provider_manifest_version_unique
    UNIQUE (capability, provider, provider_version, adapter_version)
);
CREATE INDEX provider_manifest_resolve
  ON provider_manifest (capability, provider, registered_at DESC, manifest_sha256);
-- Append-only: an accepted manifest can never be edited or removed; a fix is a new adapter_version.
SELECT aegis.protect('provider_manifest'::regclass, true);
COMMENT ON TABLE provider_manifest IS
  'M05 immutable manifest registry (G1.1c). Key = SHA-256 of the exact bytes the registry accepted; a CHECK proves the hash describes the stored bytes, and accepted rows are append-only, so a job pin (scan_job.manifest_sha256) always resolves to the same document. Resolution ("latest") is a query over this table; a job never re-resolves, it fetches by hash (interfaces/README.md §Manifest bất biến).';
COMMENT ON COLUMN provider_manifest.manifest_utf8 IS
  'The exact bytes hashed for manifest_sha256 (UTF-8 YAML as published by the adapter package). Never re-serialised: M06 re-hashes these bytes to verify the pin.';
COMMENT ON COLUMN provider_manifest.provider_version IS
  'spec.providerVersion of the manifest: the upstream tool build (e.g. v2.17.0), not the adapter package version.';
COMMENT ON COLUMN provider_manifest.adapter_version IS
  'metadata.version of the manifest: the adapter package version pinned by ApprovedTask.adapter_version.';

-- ---------------------------------------------------------------------------
-- 2. The signed task, stored with the job it authorises.
--
-- E-1/OI-7: the task carries the egress binding and the signing key id, and both are inside the HMAC.
-- Keeping the exact accepted task next to the job is what lets M06 verify the signature and recover
-- the pinned binding without recomputing either. Not a dispatch-block reason and not required by a
-- trigger: rows that predate this migration (and rows written by contract test fixtures) have no task,
-- and inventing one would be worse than the NULL. M05 always writes it for a job it accepts.
ALTER TABLE scan_job ADD COLUMN approved_task jsonb;
ALTER TABLE scan_job ADD CONSTRAINT scan_job_approved_task_shape
  CHECK (approved_task IS NULL
         OR (jsonb_typeof(approved_task) = 'object'
             AND approved_task ? 'signature'
             AND approved_task ? 'signature_key_id'
             AND approved_task ? 'egress_binding'
             AND approved_task->>'manifest_sha256' = manifest_sha256));
COMMENT ON COLUMN scan_job.approved_task IS
  'The exact ApprovedTask M05 signed and accepted for this job (OI-7/E-1): merged input, TargetRefs, manifest pin, egress binding and signature. Immutable via cols_only; M06 verifies the HMAC with the key named by signature_key_id and uses egress_binding as the broker allow-set instead of recomputing it. NULL only for rows that did not come through M05 (history and contract fixtures), which are not dispatchable by M06 without a task.';

-- ---------------------------------------------------------------------------
-- 3. What an Idempotency-Key was first used for.
--
-- OpenAPI: POST /jobs with the same key and the same body returns the job it already created; the same
-- key with a different body is 409, never a second decision. Comparing the stored decision's fields
-- would not answer it: the request is merged with inputDefaults and resolved against the registry
-- before it becomes a decision, and re-resolving on a retry is exactly what the contract forbids
-- ("không resolve manifest mới cho retry"). The hash of the submitted body answers the question where
-- it is asked.
ALTER TABLE policy_decision ADD COLUMN request_hash char(64)
  CHECK (request_hash IS NULL OR request_hash ~ '^[0-9a-f]{64}$');
COMMENT ON COLUMN policy_decision.request_hash IS
  'sha256(utf8(aegis-c14n/1(submitted JobSubmit body))) written by M05 (G1.1c) for REST submissions. The unique (campaign_id, idempotency_key) row is the accepted request: a retry hashes its body and replays the stored decision/job only when the hash matches, otherwise 409 IDEMPOTENCY_CONFLICT. NULL for rows predating the column and for non-REST callers.';
COMMIT;
