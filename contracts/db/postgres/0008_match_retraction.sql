-- 0008_match_retraction.sql
--
-- Item 61 retraction (owner decision after #100): a candidate is a *decision* about an
-- (asset, vulnerability) pair, and the decision can change when the intel changes. Today
-- `package_vuln_match` only records the positive direction, so a CVE the new revision no longer
-- matches keeps its old row as "the newest row" and stays visible in the read model and in the
-- graph forever. M20 now writes the same decision table with `matched = false` at the new
-- revision, and the row has to say *why*, otherwise the history says "not this" without saying
-- how it got there.
--
--   * `retraction_reason` is that why: the matcher's own vocabulary, mirrored here so a decision
--     row cannot be half-written. `VERSION_UNSPECIFIED` and `PLATFORM_UNCONFIRMED` are the two
--     values `aegis.m20_vuln.configurations` already reports for a decision it could not make;
--     `NO_LONGER_MATCHES` is a configuration that no longer contains the observed version;
--     `WITHDRAWN` is the current NVD revision being Rejected/Withdrawn.
--   * `package_vuln_match_retraction_reason_check` keeps the two halves consistent: a match has no
--     reason, a retraction must have one. Every existing row is `matched = true` (0001 has no other
--     writer), so the constraint validates without a backfill. `retraction_reason IS NOT NULL` is
--     not redundant: `NULL = ANY(...)` is NULL, and a CHECK that evaluates to NULL passes, which is
--     how a missing reason slipped through until `tests/match_retraction.sql` caught it.
--
-- No index: the read model already walks `(package_asset_id, vulnerability_id, created_at DESC)`
-- (`package_vuln_match_pkg`, 0001) and a retraction is read through that same path.

BEGIN;

ALTER TABLE aegis.package_vuln_match
    ADD COLUMN retraction_reason text;

ALTER TABLE aegis.package_vuln_match
    ADD CONSTRAINT package_vuln_match_retraction_reason_check
        CHECK (
            (matched AND retraction_reason IS NULL)
            OR (
                NOT matched
                AND retraction_reason IS NOT NULL
                AND retraction_reason = ANY (ARRAY[
                    'VERSION_UNSPECIFIED'::text,
                    'PLATFORM_UNCONFIRMED'::text,
                    'NO_LONGER_MATCHES'::text,
                    'WITHDRAWN'::text
                ])
            )
        );

COMMENT ON COLUMN aegis.package_vuln_match.retraction_reason IS
    'M20. Lý do một ứng viên đã có ở bản intel trước không còn khớp ở bản hiện tại; chỉ có khi matched = false.';

COMMIT;
