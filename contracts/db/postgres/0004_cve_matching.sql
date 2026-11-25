-- 0004_cve_matching.sql
--
-- CVE/CTI enrichment (G1.6 slice C): the candidate matches M20 records and the outbox event M23
-- projects them from. The vulnerability catalogue itself already exists in 0001
-- (`intel_snapshot`, `vulnerability_revision`, `vulnerability_current`), and `package_vuln_match`
-- is already the M20 candidate table ("Ứng viên AFFECTED_BY (chưa phải finding)"); this migration
-- only adds what matching against a feed snapshot needs:
--
--   * `confidence` and `snapshot_id` on a candidate, so the AFFECTED_BY edge carries the certainty
--     of the CPE range match and the intel snapshot it was decided on (model.md: :Vulnerability
--     and AFFECTED_BY are candidates, never findings);
--   * `campaign_id`, because the observation that produced the candidate belongs to a campaign and
--     the projection must not invent one;
--   * one unique index over the decision itself: re-running matching against the same intel
--     revision is an ON CONFLICT DO NOTHING, not a second candidate row (M20 is re-run whenever a
--     feed snapshot loads, and a crash must be recoverable by running it again);
--   * `vulnerability.matched.v2`, the outbox event type M20 emits and M23 consumes.
--
-- Append-only stays: 0001 protects `package_vuln_match` with no UPDATE and no DELETE, so the
-- "current" match of an (asset, vulnerability) pair is its newest row.

ALTER TABLE aegis.outbox_event
    DROP CONSTRAINT outbox_event_type_check;

ALTER TABLE aegis.outbox_event
    ADD CONSTRAINT outbox_event_type_check CHECK ((type = ANY (ARRAY[
        'job.started.v1'::text, 'job.completed.v1'::text, 'policy.denied.v1'::text,
        'asset.discovered.v1'::text, 'observation.changed.v1'::text, 'artifact.ready.v1'::text,
        'knowledge.delta.v1'::text, 'intel.revision.v1'::text, 'finding.changed.v1'::text,
        'job.started.v2'::text, 'job.completed.v2'::text, 'policy.denied.v2'::text,
        'asset.discovered.v2'::text, 'observation.changed.v2'::text, 'artifact.ready.v2'::text,
        'knowledge.delta.v2'::text, 'intel.revision.v2'::text, 'finding.changed.v2'::text,
        'vulnerability.matched.v2'::text
    ])));

ALTER TABLE aegis.package_vuln_match
    ADD COLUMN confidence numeric(4, 3),
    ADD COLUMN snapshot_id uuid,
    ADD COLUMN campaign_id uuid;

ALTER TABLE aegis.package_vuln_match
    ADD CONSTRAINT package_vuln_match_confidence_check
        CHECK ((confidence IS NULL) OR ((confidence >= (0)::numeric) AND (confidence <= (1)::numeric)));

ALTER TABLE aegis.package_vuln_match
    ADD CONSTRAINT package_vuln_match_snapshot_id_fkey
        FOREIGN KEY (snapshot_id) REFERENCES aegis.intel_snapshot(snapshot_id);

ALTER TABLE aegis.package_vuln_match
    ADD CONSTRAINT package_vuln_match_campaign_id_fkey
        FOREIGN KEY (campaign_id) REFERENCES aegis.campaign(campaign_id);

COMMENT ON COLUMN aegis.package_vuln_match.confidence IS
    'M20. Độ tin cậy của khớp CPE (1 = phiên bản trùng đúng, thấp hơn = khớp khoảng).';
COMMENT ON COLUMN aegis.package_vuln_match.snapshot_id IS
    'M20. Bản intel (intel_snapshot) quyết định khớp này; đổi snapshot = hàng ứng viên mới.';

-- Idempotency of matching: the same asset against the same vulnerability revision through the same
-- method is one decision, whatever the number of runs or retries.
CREATE UNIQUE INDEX package_vuln_match_once
    ON aegis.package_vuln_match (package_asset_id, vulnerability_id, vuln_rev_id, match_method);

CREATE INDEX package_vuln_match_vulnerability
    ON aegis.package_vuln_match (vulnerability_id, created_at DESC);
