-- 0007_intel_indexes.sql
--
-- Full NVD CVE 2.0 corpus + fast M20 matching (item 61, G1.6):
--
--   * `aegis.nvd_cpe_products(affected)` + GIN index on `vulnerability_revision`: lets M20 ask
--     PostgreSQL for only the NVD CVEs whose vulnerable criteria match the observed
--     `(part, vendor, product)` triples instead of loading and parsing 300k+ NVD rows on every run.
--   * `vulnerability_revision_nvd_current`: partial index for `source = 'nvd'`, so LATERAL/latest
--     lookups do not scan 400k+ EPSS rows.
--   * `observation_vuln_targets`: partial index for `service.product` / `http.technology` lookups.
--   * `intel_sync_checkpoint`: append-only checkpoint log for resumable paged NVD API 2.0 bulk and
--     incremental (`lastModified`) sync runs.

BEGIN;

CREATE FUNCTION aegis.nvd_cpe_products(affected jsonb) RETURNS text[]
    LANGUAGE sql IMMUTABLE STRICT
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
  SELECT coalesce(
    array_agg(DISTINCT product_key),
    '{}'::text[]
  )
  FROM (
    SELECT CASE
      WHEN criteria LIKE 'cpe:2.3:%' THEN
        replace(replace(lower(split_part(clean23, ':', 3)), chr(1), ':'), chr(2), '\') || ':' ||
        replace(replace(lower(split_part(clean23, ':', 4)), chr(1), ':'), chr(2), '\') || ':' ||
        replace(replace(lower(split_part(clean23, ':', 5)), chr(1), ':'), chr(2), '\')
      WHEN criteria LIKE 'cpe:/%' THEN
        lower(split_part(clean22, ':', 1)) || ':' ||
        lower(split_part(clean22, ':', 2)) || ':' ||
        lower(split_part(clean22, ':', 3))
      ELSE NULL
    END AS product_key
    FROM (
      SELECT entry->>'criteria' AS criteria,
             replace(replace(entry->>'criteria', '\\', chr(2)), '\:', chr(1)) AS clean23,
             substr(entry->>'criteria', 6) AS clean22
        FROM jsonb_array_elements(
               CASE
                 WHEN jsonb_typeof(affected->'cpe_match') = 'array' THEN affected->'cpe_match'
                 ELSE '[]'::jsonb
               END
             ) AS entry
       WHERE coalesce((entry->>'vulnerable')::boolean, false)
    ) raw
  ) keys
  WHERE product_key IS NOT NULL
    AND split_part(product_key, ':', 1) <> ''
    AND split_part(product_key, ':', 2) <> ''
    AND split_part(product_key, ':', 3) <> '';
$$;

COMMENT ON FUNCTION aegis.nvd_cpe_products(jsonb) IS
    'M20. Extracts distinct lower(part:vendor:product) keys from vulnerable NVD cpe_match criteria for GIN indexing.';

CREATE INDEX vulnerability_revision_nvd_products_gin
    ON aegis.vulnerability_revision
    USING gin (aegis.nvd_cpe_products(affected))
    WHERE source = 'nvd' AND NOT withdrawn AND affected IS NOT NULL;

CREATE INDEX vulnerability_revision_nvd_current
    ON aegis.vulnerability_revision (vulnerability_id, created_at DESC, vuln_rev_id DESC)
    WHERE source = 'nvd';

CREATE INDEX observation_vuln_targets
    ON aegis.observation (campaign_id, subject_asset_id, predicate, observed_at DESC, ingested_at DESC)
    WHERE polarity = 'present' AND predicate IN ('service.product', 'http.technology');

CREATE TABLE aegis.intel_sync_checkpoint (
    checkpoint_id uuid NOT NULL,
    feed text NOT NULL,
    run_id text NOT NULL,
    mode text NOT NULL,
    status text NOT NULL,
    next_start_index integer NOT NULL,
    total_results integer,
    results_per_page integer NOT NULL,
    window_start timestamp with time zone,
    window_end timestamp with time zone,
    last_modified_watermark timestamp with time zone,
    last_snapshot_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT intel_sync_checkpoint_pkey PRIMARY KEY (checkpoint_id),
    CONSTRAINT intel_sync_checkpoint_feed_check CHECK ((feed = 'nvd'::text)),
    CONSTRAINT intel_sync_checkpoint_mode_check CHECK ((mode = ANY (ARRAY['full'::text, 'incremental'::text]))),
    CONSTRAINT intel_sync_checkpoint_status_check CHECK ((status = ANY (ARRAY['in_progress'::text, 'completed'::text]))),
    CONSTRAINT intel_sync_checkpoint_next_start_check CHECK ((next_start_index >= 0)),
    CONSTRAINT intel_sync_checkpoint_total_check CHECK (((total_results IS NULL) OR (total_results >= 0))),
    CONSTRAINT intel_sync_checkpoint_per_page_check CHECK ((results_per_page >= 1)),
    CONSTRAINT intel_sync_checkpoint_snapshot_fkey FOREIGN KEY (last_snapshot_id) REFERENCES aegis.intel_snapshot(snapshot_id)
);

COMMENT ON TABLE aegis.intel_sync_checkpoint IS
    'M18. Append-only checkpoint log for resumable paged NVD API 2.0 bulk and incremental syncs.';

CREATE INDEX intel_sync_checkpoint_latest
    ON aegis.intel_sync_checkpoint (feed, created_at DESC, checkpoint_id DESC);

SELECT aegis.protect('aegis.intel_sync_checkpoint'::regclass, true);

COMMIT;
