-- 0009_result_coverage.sql
--
-- G1.6 Decision A follow-up (item 83 trial): a scan that could not conclude a port must say so,
-- and the campaign must not report `objective_met` as if the surface had been fully scanned.
--
-- The envelope already says it (`coverage.complete` / `coverage.limitations`,
-- ingestion/result-envelope.v2), but nothing persisted that verdict: `ingestion_inbox` kept the
-- receipt and the payload hash only, so a reader of PostgreSQL (M02 finalising the campaign, the
-- API, an operator) had no way to tell a completed run from a partial one. The UI campaign's
-- status_reason is written by M02, which had no coverage input at all.
--
-- `coverage` is the accepted envelope's own `coverage` object, stored verbatim in the same
-- transaction that decides the envelope. Two properties are duplicated here on purpose, because
-- they are what a reader filters on and a stored document must not be queried by shape alone:
--
--   * `complete` is a boolean, not a string, so `coverage->'complete' = 'false'` is one operator;
--   * `limitations` stays an array of `{code, message, subjects?}` (the contract's shape).
--
-- A row with coverage is the current result of its job only while `scan_job.envelope_event_id`
-- still points at it: a re-run (generation+1) writes a new envelope and a new inbox row, and the
-- old one drops out of the campaign's coverage view by that join rather than by a timestamp race.
--
-- No index: the campaign's coverage read starts at `scan_job_campaign_status`
-- (`campaign_id, status`, 0001) and joins the inbox by primary key, which is one row per result.

BEGIN;

ALTER TABLE aegis.ingestion_inbox
    ADD COLUMN coverage jsonb;

ALTER TABLE aegis.ingestion_inbox
    ADD CONSTRAINT ingestion_inbox_coverage_shape_check
        CHECK (
            coverage IS NULL OR (
                jsonb_typeof(coverage) = 'object'
                AND coverage ? 'subjects'
                AND jsonb_typeof(coverage->'subjects') = 'array'
                AND coverage ? 'complete'
                AND jsonb_typeof(coverage->'complete') = 'boolean'
                AND (
                    NOT coverage ? 'limitations'
                    OR jsonb_typeof(coverage->'limitations') = 'array'
                )
            )
        );

COMMENT ON COLUMN aegis.ingestion_inbox.coverage IS
    'M27. Đối tượng coverage của envelope đã nhận (result-envelope.v2): complete + limitations, nguyên văn. NULL là envelope cũ chưa lưu; false nghĩa là job không kết luận được toàn bộ bề mặt nên chiến dịch không được coi là objective_met.';

COMMIT;
