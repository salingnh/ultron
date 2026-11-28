-- 0014_verification_run.sql
--
-- G2-B (item 87): one append-only row per dynamic verification run (M21), the record the finding
-- read API returns and the decision the browser "Yêu cầu xác minh" flow is about.
--
-- A run is a `verify.check` job that completed with an accepted envelope; M21 decides from the
-- evidence and writes exactly one row, unique by `job_id`, so a Temporal retry (or a second
-- dispatcher tick) can never decide the same job twice. The outcome is the decision, not the job
-- state: a FAILED/CANCELLED job has no row and is read from `scan_job`, and the outcome set is
-- closed (VERIFIED | NOT_REPRODUCED | INCONCLUSIVE | OBSERVED).
--
-- Three constraints carry the owner decision (D29, OD-B) into the database, so no writer can store
-- a row the product forbids:
--
--   * `verification_run_lab_only_check`: an L1/C1 check (behaviour/credential) only exists on the
--     lab profile; the internet pack has no such check at all;
--   * `verification_run_verified_check`: VERIFIED needs the lab profile, both negative controls'
--     evidence and the transition it wrote - the "positive and both controls negative" rule of the
--     M21 table, restated where a row cannot evade it;
--   * `verification_run_cap_check`: `requests_sent` never exceeds the registry's hard cap.
--
-- The table is append-only like the rest of the finding spine (`protect(true)`): a decision is
-- history, a later run is a new row (another job). `matched` holds the oracle's own inputs/outputs
-- summary (which role matched, why) - never a response body and never the canary value, only its
-- sha256. Controls and target are the *signed* roles the job ran with, written here so the read
-- model does not depend on a job row that may be regenerated.

BEGIN;

CREATE TABLE aegis.verification_run (
    verification_id uuid NOT NULL,
    finding_id uuid NOT NULL,
    campaign_id uuid NOT NULL,
    job_id uuid NOT NULL,
    check_id text NOT NULL,
    check_class text NOT NULL,
    network_profile text NOT NULL,
    check_pack_sha256 character(64) NOT NULL,
    outcome text NOT NULL,
    requests_sent integer NOT NULL,
    request_cap integer NOT NULL,
    target_ref jsonb NOT NULL,
    controls jsonb DEFAULT '[]'::jsonb NOT NULL,
    canary_sha256 character(64),
    canary_name_sha256 character(64),
    positive_evidence_id uuid,
    control_a_evidence_id uuid,
    control_b_evidence_id uuid,
    matched jsonb NOT NULL,
    requested_by jsonb NOT NULL,
    decided_by jsonb DEFAULT '{"kind": "module", "id": "M21"}'::jsonb NOT NULL,
    transition_seq integer,
    started_at timestamp with time zone NOT NULL,
    finished_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT verification_run_pkey PRIMARY KEY (verification_id),
    CONSTRAINT verification_run_job_key UNIQUE (job_id),
    CONSTRAINT verification_run_class_check CHECK ((check_class = ANY (ARRAY['E1'::text, 'L1'::text, 'C1'::text]))),
    CONSTRAINT verification_run_profile_check CHECK ((network_profile = ANY (ARRAY['lab'::text, 'internet'::text]))),
    CONSTRAINT verification_run_outcome_check CHECK ((outcome = ANY (ARRAY['VERIFIED'::text, 'NOT_REPRODUCED'::text, 'INCONCLUSIVE'::text, 'OBSERVED'::text]))),
    CONSTRAINT verification_run_lab_only_check CHECK (((check_class = 'E1'::text) OR (network_profile = 'lab'::text))),
    CONSTRAINT verification_run_verified_check CHECK (((outcome <> 'VERIFIED'::text) OR ((network_profile = 'lab'::text) AND (positive_evidence_id IS NOT NULL) AND (control_a_evidence_id IS NOT NULL) AND (control_b_evidence_id IS NOT NULL) AND (transition_seq IS NOT NULL)))),
    CONSTRAINT verification_run_cap_check CHECK (((requests_sent >= 0) AND (requests_sent <= request_cap))),
    CONSTRAINT verification_run_target_shape CHECK ((jsonb_typeof(target_ref) = 'object'::text)),
    CONSTRAINT verification_run_controls_shape CHECK ((jsonb_typeof(controls) = 'array'::text)),
    CONSTRAINT verification_run_matched_shape CHECK ((jsonb_typeof(matched) = 'object'::text)),
    CONSTRAINT verification_run_requested_by_shape CHECK (aegis.is_actor(requested_by)),
    CONSTRAINT verification_run_decided_by_shape CHECK (aegis.is_actor(decided_by)),
    CONSTRAINT verification_run_sha256_check CHECK (((check_pack_sha256 ~ '^[0-9a-f]{64}$'::text) AND ((canary_sha256 IS NULL) OR (canary_sha256 ~ '^[0-9a-f]{64}$'::text)) AND ((canary_name_sha256 IS NULL) OR (canary_name_sha256 ~ '^[0-9a-f]{64}$'::text)))),
    CONSTRAINT verification_run_transition_seq_check CHECK (((transition_seq IS NULL) OR (transition_seq >= 1)))
);

COMMENT ON TABLE aegis.verification_run IS 'M21. Mỗi job verify.check đã COMPLETED và được nhận envelope có đúng một hàng; outcome là quyết định (VERIFIED cần lab + cả hai đối chứng âm), không phải trạng thái job. Append-only.';
COMMENT ON COLUMN aegis.verification_run.check_pack_sha256 IS 'Băm pack đã mount (registry + template) mà job đã chạy; khớp profile triển khai và ApprovedTask đã ký.';
COMMENT ON COLUMN aegis.verification_run.target_ref IS 'Asset của finding do server phân giải ({asset_id, canonical_key, address, port}); không có target nào đến từ request body.';
COMMENT ON COLUMN aegis.verification_run.controls IS 'Đối chứng âm đã cấu hình cho lần chạy ({role, address, port, asset_id}); rỗng với E1 trên internet.';
COMMENT ON COLUMN aegis.verification_run.matched IS 'Đầu vào/kết quả tóm tắt của bảng quyết định M21 (positive/control_a/control_b/discriminating/reason); không có body response, không có giá trị canary.';
COMMENT ON COLUMN aegis.verification_run.transition_seq IS 'transition_seq sau lần chạy khi VERIFIED, NULL khi không đổi trạng thái (OBSERVED/NOT_REPRODUCED/INCONCLUSIVE).';
COMMENT ON COLUMN aegis.verification_run.started_at IS 'started_at của job (thời điểm bắt đầu lần chạy); hàng này chỉ được ghi sau khi job kết thúc.';
COMMENT ON COLUMN aegis.verification_run.finished_at IS 'finished_at của job; quyết định được ghi sau mốc này.';

CREATE INDEX verification_run_finding ON aegis.verification_run USING btree (finding_id, created_at DESC, verification_id DESC);
CREATE INDEX verification_run_campaign ON aegis.verification_run USING btree (campaign_id, created_at DESC);

ALTER TABLE ONLY aegis.verification_run
    ADD CONSTRAINT verification_run_finding_fkey FOREIGN KEY (finding_id) REFERENCES aegis.finding(finding_id),
    ADD CONSTRAINT verification_run_campaign_fkey FOREIGN KEY (campaign_id) REFERENCES aegis.campaign(campaign_id),
    ADD CONSTRAINT verification_run_job_fkey FOREIGN KEY (job_id) REFERENCES aegis.scan_job(job_id),
    ADD CONSTRAINT verification_run_positive_evidence_fkey FOREIGN KEY (positive_evidence_id) REFERENCES aegis.evidence(evidence_id),
    ADD CONSTRAINT verification_run_control_a_evidence_fkey FOREIGN KEY (control_a_evidence_id) REFERENCES aegis.evidence(evidence_id),
    ADD CONSTRAINT verification_run_control_b_evidence_fkey FOREIGN KEY (control_b_evidence_id) REFERENCES aegis.evidence(evidence_id);

SELECT aegis.protect('aegis.verification_run'::regclass, true);

COMMIT;
