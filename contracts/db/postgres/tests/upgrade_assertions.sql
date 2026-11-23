-- Run 0001 + v1-upgrade fixture + 0002 + 0003 + pre-usage-upgrade fixture + 0004 + 0005 + 0006, then this test.
SET search_path=aegis,public;
DO $$ BEGIN
 IF (SELECT count(*) FROM legacy_contract_snapshot) <> 4 THEN RAISE EXCEPTION 'archive row count mismatch'; END IF;
 IF NOT EXISTS(SELECT 1 FROM legacy_contract_snapshot WHERE source_table='scan_job' AND payload->>'impact_tier'='T0' AND payload->>'profile'='passive') THEN RAISE EXCEPTION 'job history lost'; END IF;
 IF NOT EXISTS(SELECT 1 FROM legacy_contract_snapshot WHERE source_table='model_usage' AND payload->>'profile'='MID') THEN RAISE EXCEPTION 'model history lost'; END IF;
 IF EXISTS(SELECT 1 FROM scan_job WHERE priority<>50) THEN RAISE EXCEPTION 'wrong priority backfill'; END IF;
 IF NOT EXISTS(SELECT 1 FROM outbox_event WHERE type='job.started.v1') THEN RAISE EXCEPTION 'old event lost'; END IF;
 IF NOT EXISTS(SELECT 1 FROM scan_job WHERE manifest_sha256 IS NULL) THEN RAISE EXCEPTION 'historical job was assigned an invented manifest hash'; END IF;
 IF NOT EXISTS(SELECT 1 FROM scan_job WHERE job_id='01900000-0000-7000-8000-0000000000d1'
    AND target_refs IS NULL AND cardinality(targets) > 0 AND targets[1] = 'dns:internal.example') THEN
   RAISE EXCEPTION 'historical job was given invented target refs or lost its canonical targets';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM model_usage WHERE usage_id='01900000-0000-7000-8000-000000009905'
    AND input_tokens=-1 AND output_tokens=-2 AND cost_usd=-1 AND latency_ms=-1) THEN
   RAISE EXCEPTION 'historical invalid usage row missing or changed';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM ingestion_inbox WHERE event_id='01900000-0000-7000-8000-0000000000e1'
    AND payload_hash=repeat('b',64) AND hash_version IS NULL AND receipt IS NULL) THEN
   RAISE EXCEPTION 'historical inbox row was given a hash version or an invented receipt';
 END IF;
 RAISE NOTICE 'upgrade: archived rows, prior values, default priority, legacy targets and historical events PASS';
END $$;
