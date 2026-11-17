-- Run 0001 + v1-upgrade fixture + 0002 + 0003 + pre-usage-upgrade fixture + 0004, then this test.
SET search_path=aegis,public;
DO $$ BEGIN
 IF (SELECT count(*) FROM legacy_contract_snapshot) <> 4 THEN RAISE EXCEPTION 'archive row count mismatch'; END IF;
 IF NOT EXISTS(SELECT 1 FROM legacy_contract_snapshot WHERE source_table='scan_job' AND payload->>'impact_tier'='T0' AND payload->>'profile'='passive') THEN RAISE EXCEPTION 'job history lost'; END IF;
 IF NOT EXISTS(SELECT 1 FROM legacy_contract_snapshot WHERE source_table='model_usage' AND payload->>'profile'='MID') THEN RAISE EXCEPTION 'model history lost'; END IF;
 IF EXISTS(SELECT 1 FROM scan_job WHERE priority<>50) THEN RAISE EXCEPTION 'wrong priority backfill'; END IF;
 IF NOT EXISTS(SELECT 1 FROM outbox_event WHERE type='job.started.v1') THEN RAISE EXCEPTION 'old event lost'; END IF;
 IF NOT EXISTS(SELECT 1 FROM scan_job WHERE manifest_sha256 IS NULL) THEN RAISE EXCEPTION 'historical job was assigned an invented manifest hash'; END IF;
 IF NOT EXISTS(SELECT 1 FROM model_usage WHERE usage_id='01900000-0000-7000-8000-000000009905'
    AND input_tokens=-1 AND output_tokens=-2 AND cost_usd=-1 AND latency_ms=-1) THEN
   RAISE EXCEPTION 'historical invalid usage row missing or changed';
 END IF;
 RAISE NOTICE 'upgrade: archived rows, prior values, default priority and historical events PASS';
END $$;
