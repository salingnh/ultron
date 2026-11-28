-- 0013_artifact_findings.sql
--
-- G2-D (item 89): the artifact analysis chain. Two gaps needed a migration, nothing else:
--
-- 1. **`oci_image` campaign seeds.** An image can only be analysed when the campaign is
--    authorized for it: the operator supplies a digest (`campaign-create.v2` `targets.images`),
--    M01 writes one `campaign_target` row and the seed asset `oci:sha256:...`, and every artifact
--    job names that seed in its `TargetRefs`. The 0001 check constraint only knew the five seed
--    kinds of G1, so the row was impossible to store. The digest is the whole identity: no
--    registry, tag or repository is crawled at scan time.
--
-- 2. **`finding_candidate`.** Scanner-reported findings used to be quarantined
--    (`finding_candidates_deferred_to_m20`) because G1 had no producer for a `finding` row. M20 now
--    owns that decision (`aegis.m20_vuln.candidates`): M27 validates a candidate exactly like an
--    observation (subject asset known, evidence stored, category/severity closed sets, no free
--    status/severity) and stores the row here; M20 computes the fingerprint, merges providers that
--    report the same `(asset, rule, location)` into one finding and writes the `finding`,
--    `finding_run`, `finding_source`, `finding_transition` and `finding.changed.v2` records.
--
-- The table is an ingestion record, not a finding: it has no status column on purpose. Duplicate
-- submissions are already blocked by `ingestion_inbox` (dedup key + payload hash); the unique key
-- here is the safety net for a second envelope of the same scan that carries the same candidate
-- (`location_hash` is the `aegis-c14n/1` digest of the candidate's `location` object, so two paths
-- of the same package are two candidates and one path is one).
--
-- Append-only like every other ingestion table: a candidate is what a scan reported, never edited.

BEGIN;

-- --- 1. image seeds ---------------------------------------------------------

ALTER TABLE aegis.campaign_target DROP CONSTRAINT campaign_target_kind_check;
ALTER TABLE aegis.campaign_target
    ADD CONSTRAINT campaign_target_kind_check
        CHECK (
            kind = ANY (
                ARRAY[
                    'domain'::text, 'ip'::text, 'cidr'::text, 'url'::text, 'email'::text,
                    'keyword'::text, 'oci_image'::text
                ]
            )
        );

COMMENT ON CONSTRAINT campaign_target_kind_check ON aegis.campaign_target IS
    'Seed kinds the campaign contract can express. `oci_image` (0013) is an operator-supplied digest, canonical_key oci:sha256:<64 hex>; M06 stages that exact image from local storage into the sandbox, it never pulls one.';

-- --- 2. finding_candidate ---------------------------------------------------

CREATE TABLE aegis.finding_candidate (
    candidate_id uuid NOT NULL,
    campaign_id uuid NOT NULL,
    scan_id uuid NOT NULL,
    envelope_event_id uuid NOT NULL,
    revision bigint NOT NULL,
    subject_asset_id uuid NOT NULL,
    provider text NOT NULL,
    provider_version text NOT NULL,
    rule_id text NOT NULL,
    category text DEFAULT 'vulnerability'::text NOT NULL,
    title text NOT NULL,
    description text,
    location jsonb DEFAULT '{}'::jsonb NOT NULL,
    location_hash character(64) NOT NULL,
    vulnerability_ids text[] DEFAULT '{}'::text[] NOT NULL,
    cwe_ids text[] DEFAULT '{}'::text[] NOT NULL,
    scanner_severity text,
    fingerprint_context jsonb DEFAULT '{}'::jsonb NOT NULL,
    confidence numeric(4,3),
    evidence_ids uuid[] NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    ingested_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT finding_candidate_category_check CHECK (
        category = ANY (
            ARRAY[
                'vulnerability'::text, 'misconfiguration'::text, 'exposure'::text,
                'secret'::text, 'weak_crypto'::text, 'other'::text
            ]
        )
    ),
    CONSTRAINT finding_candidate_scanner_severity_check CHECK (
        scanner_severity IS NULL
        OR scanner_severity = ANY (
            ARRAY['critical'::text, 'high'::text, 'medium'::text, 'low'::text, 'info'::text,
                  'unknown'::text]
        )
    ),
    CONSTRAINT finding_candidate_confidence_check CHECK (
        confidence IS NULL OR (confidence >= (0)::numeric AND confidence <= (1)::numeric)
    ),
    CONSTRAINT finding_candidate_evidence_check CHECK (cardinality(evidence_ids) > 0),
    CONSTRAINT finding_candidate_rule_check CHECK (
        length(rule_id) > 0 AND length(rule_id) <= 500
    ),
    CONSTRAINT finding_candidate_title_check CHECK (length(title) <= 500)
);

ALTER TABLE aegis.finding_candidate
    ADD CONSTRAINT finding_candidate_pkey PRIMARY KEY (candidate_id);

CREATE UNIQUE INDEX finding_candidate_once
    ON aegis.finding_candidate (scan_id, provider, subject_asset_id, rule_id, location_hash);

CREATE INDEX finding_candidate_group
    ON aegis.finding_candidate (subject_asset_id, rule_id, observed_at DESC);

COMMENT ON TABLE aegis.finding_candidate IS
    'M27 (cổng G4/G6). Finding ứng viên của scanner, đã validate và giữ nguyên vs evidence: subject là asset đã biết, evidence_ids phải trỏ tới evidence đã lưu. Apprend-only; KHÔNG có status/severity cuối — M20 tính fingerprint, hợp nhất provider và quyết định finding.';

COMMENT ON COLUMN aegis.finding_candidate.location_hash IS
    'sha256(aegis-c14n/1(location)) do M27 tính; cùng (scan, provider, subject, rule) + cùng vị trí là một hàng, hai vị trí (hai path của cùng package) là hai hàng.';

COMMENT ON COLUMN aegis.finding_candidate.fingerprint_context IS
    'Ngữ cảnh fingerprint scanner gửi (package/path/detector). M20 chỉ dùng location của nó cho fingerprint; cột này giữ nguyên văn để truy vết.';

COMMENT ON COLUMN aegis.finding_candidate.campaign_id IS
    'Chiến dịch của job đã báo ứng viên. Finding hợp nhất dùng provenance của hàng mới nhất; asset dùng chung toàn hệ thống nên đây là first_campaign_id, không phải ranh giới đọc.';

SELECT aegis.protect('aegis.finding_candidate'::regclass, true);

-- --- 3. foreign keys (same shape as observation) ----------------------------

ALTER TABLE ONLY aegis.finding_candidate
    ADD CONSTRAINT finding_candidate_campaign_id_fkey
        FOREIGN KEY (campaign_id) REFERENCES aegis.campaign(campaign_id);

ALTER TABLE ONLY aegis.finding_candidate
    ADD CONSTRAINT finding_candidate_scan_id_fkey
        FOREIGN KEY (scan_id) REFERENCES aegis.scan_job(job_id);

ALTER TABLE ONLY aegis.finding_candidate
    ADD CONSTRAINT finding_candidate_envelope_event_id_fkey
        FOREIGN KEY (envelope_event_id) REFERENCES aegis.ingestion_inbox(event_id);

ALTER TABLE ONLY aegis.finding_candidate
    ADD CONSTRAINT finding_candidate_revision_fkey
        FOREIGN KEY (revision) REFERENCES aegis.graph_revision(revision);

ALTER TABLE ONLY aegis.finding_candidate
    ADD CONSTRAINT finding_candidate_subject_asset_id_fkey
        FOREIGN KEY (subject_asset_id) REFERENCES aegis.asset(asset_id);

ALTER TABLE ONLY aegis.finding_candidate
    ADD CONSTRAINT finding_candidate_candidate_id_key UNIQUE (candidate_id);

COMMIT;
