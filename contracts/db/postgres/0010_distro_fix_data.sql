-- 0010_distro_fix_data.sql
--
-- Distro-aware matching (item 80). Upstream NVD cannot tell a patched distro package from an
-- unpatched one: `OpenSSH_8.9p1` is in CVE-2024-6387's range, while Ubuntu's
-- `1:8.9p1-3ubuntu0.18` already contains the backport. M18 now loads per-release fix data as a
-- fourth feed (`distro`, from Ubuntu OVAL and the Debian security tracker) and M20 suppresses or
-- retracts a candidate the distro has fixed.
--
--   * `intel_snapshot.feed` / `vulnerability_revision.source` gain `distro`: one record is one CVE
--     on one release (`affected.distro.release`), which is why M20 reads the newest revision per
--     release instead of `vulnerability_current`;
--   * `package_vuln_match.retraction_reason` gains `FIXED_BY_DISTRO`. The retraction is written
--     with `match_method = 'distro_fixed'` (added to the method vocabulary in the same migration) -
--     the decision does not come from an NVD revision, and the append-only unique key includes the
--     method, so a fixed host can be retracted at the revision its NVD candidate used;
--   * the GIN index on `affected->'packages'` narrows the matcher's distro lookup to the observed
--     package like `nvd_cpe_products` narrows NVD.

BEGIN;

ALTER TABLE aegis.intel_snapshot DROP CONSTRAINT intel_snapshot_feed_check;
ALTER TABLE aegis.intel_snapshot
    ADD CONSTRAINT intel_snapshot_feed_check
        CHECK (feed = ANY (ARRAY['nvd'::text, 'osv'::text, 'kev'::text, 'epss'::text,
                                 'ghsa'::text, 'distro'::text]));

ALTER TABLE aegis.vulnerability_revision DROP CONSTRAINT vulnerability_revision_source_check;
ALTER TABLE aegis.vulnerability_revision
    ADD CONSTRAINT vulnerability_revision_source_check
        CHECK (source = ANY (ARRAY['nvd'::text, 'osv'::text, 'kev'::text, 'epss'::text,
                                   'ghsa'::text, 'distro'::text]));

ALTER TABLE aegis.package_vuln_match
    DROP CONSTRAINT package_vuln_match_retraction_reason_check;
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
                    'WITHDRAWN'::text,
                    'FIXED_BY_DISTRO'::text
                ])
            )
        );

ALTER TABLE aegis.package_vuln_match
    DROP CONSTRAINT package_vuln_match_match_method_check;
ALTER TABLE aegis.package_vuln_match
    ADD CONSTRAINT package_vuln_match_match_method_check
        CHECK (match_method = ANY (ARRAY['purl_range'::text, 'cpe_range'::text,
                                         'scanner_direct'::text, 'distro_fixed'::text]));

CREATE INDEX vulnerability_revision_distro_packages
    ON aegis.vulnerability_revision
    USING gin ((affected -> 'packages'))
    WHERE source = 'distro';

COMMENT ON COLUMN aegis.package_vuln_match.retraction_reason IS
    'M20. Lý do một ứng viên đã có ở bản intel trước không còn khớp ở bản hiện tại; chỉ có khi matched = false. FIXED_BY_DISTRO là bản vá của distro, không phải NVD.';

COMMIT;
