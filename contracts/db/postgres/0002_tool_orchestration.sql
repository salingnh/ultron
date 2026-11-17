-- D29: contract v2, tool/input/priority/dependency. Apply after 0001, in a maintenance window.
-- 0001 remains immutable migration history, not the current product model.
BEGIN;
SET LOCAL search_path = aegis, public;
LOCK TABLE policy_decision, scan_job, model_usage, outbox_event IN ACCESS EXCLUSIVE MODE;
CREATE TABLE legacy_contract_snapshot (
  source_table text NOT NULL,
  source_id uuid NOT NULL,
  payload jsonb NOT NULL,
  archived_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(source_table, source_id)
);
INSERT INTO legacy_contract_snapshot(source_table,source_id,payload)
  SELECT 'policy_decision',decision_id,to_jsonb(p) FROM policy_decision p;
INSERT INTO legacy_contract_snapshot(source_table,source_id,payload)
  SELECT 'scan_job',job_id,to_jsonb(j) FROM scan_job j;
INSERT INTO legacy_contract_snapshot(source_table,source_id,payload)
  SELECT 'model_usage',usage_id,to_jsonb(m) FROM model_usage m;
SELECT aegis.protect('legacy_contract_snapshot'::regclass,true);
COMMENT ON TABLE legacy_contract_snapshot IS 'D29 migration archive: preserves full prior rows; never used as execution configuration.';
ALTER TABLE policy_decision DROP COLUMN impact_tier;
ALTER TABLE scan_job DROP COLUMN impact_tier, DROP COLUMN profile;
ALTER TABLE model_usage DROP COLUMN profile;
ALTER TABLE scan_job ADD COLUMN priority integer NOT NULL DEFAULT 50 CHECK(priority BETWEEN 0 AND 100);
ALTER TABLE scan_job ADD CONSTRAINT scan_job_id_campaign_unique UNIQUE(job_id,campaign_id);
CREATE INDEX scan_job_ready_order ON scan_job(campaign_id,priority DESC,created_at,job_id) WHERE status='QUEUED';
CREATE TABLE job_dependency (
  campaign_id uuid NOT NULL,
  job_id uuid NOT NULL,
  depends_on_job_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(job_id,depends_on_job_id),
  FOREIGN KEY(job_id,campaign_id) REFERENCES scan_job(job_id,campaign_id),
  FOREIGN KEY(depends_on_job_id,campaign_id) REFERENCES scan_job(job_id,campaign_id),
  CHECK(job_id <> depends_on_job_id)
);
SELECT aegis.protect('job_dependency'::regclass,true);
COMMENT ON TABLE job_dependency IS 'M02/M05. Immutable dependencies in same campaign. Insert with new job in one transaction; M05 rejects cycles before dispatch. Only SUCCEEDED predecessors release a job. Failed/cancelled predecessor leaves dependent waiting with a reason.';
COMMENT ON COLUMN scan_job.priority IS 'Higher value first among ready jobs; dependencies and resource limits take precedence. Immutable after acceptance.';
COMMENT ON COLUMN scan_job.job_fingerprint IS 'v2 hash(campaign,policy_version,provider,provider_version,image_digest,targets,input,scan_cycle). Scheduling is excluded; conflicting scheduling for an existing job is rejected, not silently merged. Prior hashes remain historical.';
ALTER TABLE outbox_event DROP CONSTRAINT outbox_event_type_check;
ALTER TABLE outbox_event ADD CONSTRAINT outbox_event_type_check CHECK(type IN (
 'job.started.v1','job.completed.v1','policy.denied.v1','asset.discovered.v1','observation.changed.v1','artifact.ready.v1','knowledge.delta.v1','intel.revision.v1','finding.changed.v1',
 'job.started.v2','job.completed.v2','policy.denied.v2','asset.discovered.v2','observation.changed.v2','artifact.ready.v2','knowledge.delta.v2','intel.revision.v2','finding.changed.v2'
));
COMMENT ON TABLE outbox_event IS 'Append-only event log. v1 records preserved; v2 producers/consumers use v2 schemas. Delivery ordering/watermark algorithm remains an open design item; sequence gaps are legal and must not block dispatch.';
COMMENT ON TABLE consumer_cursor IS 'Consumer checkpoint after successful delivery. Ordering algorithm must handle rollback gaps and late commits; do not assume contiguous sequence values.';
COMMENT ON TABLE graph_revision IS 'Append-only knowledge revision. Its publication ordering must handle rollback gaps and late commits; allocator/dispatcher remains an open design item.';
COMMIT;
