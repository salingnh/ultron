-- 0012_severity_input_revision.sql
--
-- G2-C (item 88): one severity assessment per finding and input revision, guaranteed by the
-- database instead of by a JSON member.
--
-- `finding/severity-assessment.v2` already requires `dedup_key` of the form
-- `severity:<finding_id>:<input_revision>` in the record, but the table kept it only inside the
-- `assessment` document: a reader had to parse JSON, and nothing stopped a second row for the same
-- (finding, revision) - two API calls racing, or a consumer that retried after a crash, could pay
-- for and store a second model call. The plan for V4 is exactly this migration: the two columns
-- plus the unique index the retry rule ("same input, same record, no second model call") relies on.
--
-- Both columns are GENERATED from the record, never written separately:
--
--   * the contract makes them required members of the stored document, so they are the one source
--     of truth and cannot drift from it;
--   * a normal column would have needed a backfill UPDATE, and `severity_assessment` is append-only
--     (0001 `no_update`), so a rewrite through DDL is the only honest way to add them;
--   * the CHECK ties `dedup_key` to `finding_id` and `input_revision` in the shape the schema's
--     pattern publishes, so a hand-built row cannot claim one revision and hash another.
--
-- `input_revision` is content-addressed by M20: a digest of the finding row, its evidence runs,
-- the newest intel revision of each source for its CVEs and its current match decision. A feed
-- revision therefore changes it even when `graph_revision` does not, and an intel change that does
-- not name the finding's CVEs leaves it - and the stored assessment - alone.

BEGIN;

ALTER TABLE aegis.severity_assessment
    ADD COLUMN input_revision bigint
        GENERATED ALWAYS AS ((assessment ->> 'input_revision')::bigint) STORED,
    ADD COLUMN dedup_key text
        GENERATED ALWAYS AS (assessment ->> 'dedup_key') STORED;

ALTER TABLE aegis.severity_assessment
    ALTER COLUMN input_revision SET NOT NULL,
    ALTER COLUMN dedup_key SET NOT NULL;

ALTER TABLE aegis.severity_assessment
    ADD CONSTRAINT severity_assessment_dedup_key_check
        CHECK (dedup_key = 'severity:' || finding_id::text || ':' || input_revision::text);

-- The contract fixes dedup_key = 'severity:<finding_id>:<input_revision>', so uniqueness of the
-- pair is uniqueness of the key; the finding-scoped index answers both the retry lookup
-- (`finding_id, input_revision`) and the history read (`finding_id`, 0001's index).
CREATE UNIQUE INDEX severity_assessment_input_revision_uniq
    ON aegis.severity_assessment USING btree (finding_id, input_revision);

COMMENT ON COLUMN aegis.severity_assessment.input_revision IS
    'M20. Bản ghi đầu vào của lần đánh giá, sao từ assessment->>''input_revision''. Nội dung, không phải bộ đếm: M20 băm hàng finding, các finding_run, revision intel mới nhất của từng nguồn cho CVE của finding và quyết định khớp hiện hành, nên một revision feed đổi làm đổi số này dù graph_revision không đổi.';

COMMENT ON COLUMN aegis.severity_assessment.dedup_key IS
    'M20. Khóa chống trùng ''severity:<finding_id>:<input_revision>'', sao từ assessment->>''dedup_key''. Unique cùng finding_id qua severity_assessment_input_revision_uniq: cùng đầu vào chỉ có một bản ghi, nên retry không thêm dòng và không gọi model lần nữa.';

COMMIT;
