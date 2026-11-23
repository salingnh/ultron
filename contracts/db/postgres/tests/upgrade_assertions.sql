-- Run 0001 + v1-upgrade fixture + 0002 + 0003 + pre-usage-upgrade fixture + 0004 + 0005 + 0006 +
-- 0007 + 0008 + v1-policy-jobs fixture + 0009 + post-0009-agent-actor fixture + 0010 + 0011, then this
-- test. Proves the upgrade kept every prior value, that S1.6 moved the legacy configuration path
-- without resuming anything, and that 0011 holds the rows 0010 could not have accepted.
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
 IF NOT EXISTS(SELECT 1 FROM scan_job WHERE job_id='01900000-0000-7000-8000-0000000000d1'
    AND requested_by->>'kind'='agent' AND requested_by->>'id'='planner' AND proposed_by IS NULL) THEN
   RAISE EXCEPTION 'historical job actor was rewritten or given an invented proposer';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM policy_decision WHERE decision_id='01900000-0000-7000-8000-0000000000c1'
    AND requested_by->>'kind'='agent' AND proposed_by IS NULL) THEN
   RAISE EXCEPTION 'historical decision actor was rewritten or given an invented proposer';
 END IF;
 RAISE NOTICE 'upgrade: archived rows, prior values, default priority, legacy targets and historical events PASS';
END $$;

-- S1.6: the legacy configuration path. The v1 snapshots stay byte-identical, each gets one new v2
-- row that validates structurally, no campaign is promoted or left running, and every legacy job is
-- held with its reasons and cannot be dispatched, while its collected evidence still finalizes.
-- Rolled back: the block adopts a snapshot and runs a job to prove the guard is not a dead end.
BEGIN;
DO $$
DECLARE
  camp_l uuid := '01900000-0000-7000-8000-0000000d1601';
  camp_c uuid := '01900000-0000-7000-8000-0000000d1611';
  job_queued uuid := '01900000-0000-7000-8000-0000000d1641';
  job_running uuid := '01900000-0000-7000-8000-0000000d1642';
  job_terminal uuid := '01900000-0000-7000-8000-0000000d1643';
  job_v1 uuid := '01900000-0000-7000-8000-0000000000d1';
  job_agent_queued uuid := '01900000-0000-7000-8000-0000000d1741';
  job_agent_done uuid := '01900000-0000-7000-8000-0000000d1742';
  new_l text;
  new_c text;
  blocked int := 0;
  actor_blocked int := 0;
  shape int := 0;
  converted int;
  out text;
BEGIN
  -- 1. The source snapshot rows are untouched: same value bytes, same hash, same author.
  IF NOT EXISTS (SELECT 1 FROM policy_snapshot WHERE policy_version = 'roe-101'
      AND policy = '{"scan_profile":"standard","max_impact_tier":"T1","approval_required_tiers":["T2"],"max_parallel_jobs":25,"max_duration_hours":72,"rate_limits":{"requests_per_second_per_host":5.5,"packets_per_second":200,"jobs_per_minute":30},"allowed_windows":[{"days":["mon","tue","wed","thu","fri"],"start":"08:00","end":"18:00","timezone":"Asia/Ho_Chi_Minh"}],"blackout_windows":[{"days":["sat","sun"],"start":"00:00","end":"24:00","timezone":"Asia/Ho_Chi_Minh"}],"budget":{"max_llm_cost_usd":25.5,"max_llm_tokens":100000,"max_jobs":500,"max_agent_sessions":50,"idle_cycles_before_pause":3},"capability_denylist":["network.discover_services"]}'::jsonb
      AND policy_hash = repeat('b',64)
      AND created_by = '{"kind":"operator","id":"soc-legacy"}'::jsonb) THEN
    RAISE EXCEPTION 'legacy policy_snapshot roe-101 was modified by the migration';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM policy_snapshot WHERE policy_version = 'roe-102'
      AND policy::text = '{"scan_profile": "passive", "max_parallel_jobs": 10, "max_duration_hours": 168}'
      AND policy_hash = repeat('c',64)) THEN
    RAISE EXCEPTION 'legacy policy_snapshot roe-102 was modified by the migration';
  END IF;

  -- 2. One conversion record per legacy snapshot, one new v2 row each, nothing promoted.
  SELECT count(*) INTO converted FROM policy_snapshot_migration;
  IF converted <> 3 THEN RAISE EXCEPTION '% conversion record(s), expected 3 (roe-1, roe-101, roe-102)', converted; END IF;
  IF (SELECT count(*) FROM policy_snapshot) <> 7 THEN
    RAISE EXCEPTION 'policy_snapshot row count % after 0009, expected 3 historical + 3 v2 candidates + the post-0009 v2 fixture',
      (SELECT count(*) FROM policy_snapshot);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM policy_snapshot_migration m
                  WHERE m.source_policy_version = 'roe-1'
                    AND m.campaign_id = '01900000-0000-7000-8000-000000000001') THEN
    RAISE EXCEPTION 'the v1-upgrade fixture snapshot roe-1 got no v2 candidate';
  END IF;
  IF EXISTS (SELECT 1 FROM policy_snapshot_migration m JOIN policy_snapshot n ON n.policy_version = m.new_policy_version
              WHERE m.mapping_version <> 'aegis-roe/1'
                 OR n.campaign_id <> m.campaign_id
                 OR n.policy_version = m.source_policy_version
                 OR NOT aegis.is_roe_policy_v2(n.policy)
                 OR n.policy_hash <> aegis.policy_hash(n.policy)
                 OR n.created_by <> '{"kind":"module","id":"migration/0009"}'::jsonb) THEN
    RAISE EXCEPTION 'a v2 candidate row is not a new, v2-shaped, same-campaign snapshot';
  END IF;
  SELECT new_policy_version INTO new_l FROM policy_snapshot_migration WHERE source_policy_version = 'roe-101';
  SELECT new_policy_version INTO new_c FROM policy_snapshot_migration WHERE source_policy_version = 'roe-102';
  IF new_l = new_c THEN RAISE EXCEPTION 'both legacy snapshots received the same policy_version'; END IF;
  IF EXISTS (SELECT 1 FROM campaign WHERE campaign_id IN (camp_l, camp_c)
              AND current_policy_version NOT IN ('roe-101','roe-102')) THEN
    RAISE EXCEPTION 'the migration promoted current_policy_version by itself';
  END IF;
  IF (SELECT dropped_keys FROM policy_snapshot_migration WHERE source_policy_version = 'roe-101')
       IS DISTINCT FROM ARRAY['approval_required_tiers','max_impact_tier','scan_profile']::text[] THEN
    RAISE EXCEPTION 'dropped-key audit for roe-101 is wrong';
  END IF;

  -- 3. The mapping carried every executable setting over and left the taxonomy behind.
  IF NOT EXISTS (SELECT 1 FROM policy_snapshot n
                  WHERE n.policy_version = new_l
                    AND n.policy->'max_parallel_jobs' = '25'::jsonb
                    AND n.policy->'max_duration_hours' = '72'::jsonb
                    AND n.policy->'rate_limits' = '{"requests_per_second_per_host":5.5,"packets_per_second":200,"jobs_per_minute":30}'::jsonb
                    AND n.policy->'allowed_windows' = (SELECT p.policy->'allowed_windows' FROM policy_snapshot p WHERE p.policy_version = 'roe-101')
                    AND n.policy->'blackout_windows' = (SELECT p.policy->'blackout_windows' FROM policy_snapshot p WHERE p.policy_version = 'roe-101')
                    AND n.policy->'budget' = (SELECT p.policy->'budget' FROM policy_snapshot p WHERE p.policy_version = 'roe-101')
                    AND n.policy->'capability_denylist' = (SELECT p.policy->'capability_denylist' FROM policy_snapshot p WHERE p.policy_version = 'roe-101')
                    AND NOT (n.policy ? 'scan_profile' OR n.policy ? 'max_impact_tier' OR n.policy ? 'approval_required_tiers')) THEN
    RAISE EXCEPTION 'v2 candidate for roe-101 lost or invented a setting';
  END IF;
  IF (SELECT dropped_values FROM policy_snapshot_migration WHERE source_policy_version = 'roe-101')
       IS DISTINCT FROM '{"scan_profile":"standard","max_impact_tier":"T1","approval_required_tiers":["T2"]}'::jsonb THEN
    RAISE EXCEPTION 'the dropped v1 settings were not recorded with their values';
  END IF;

  -- 4. Campaigns: the running one is paused with reason and history, the pending one is untouched,
  --    and no campaign is left running on v1 configuration.
  IF NOT EXISTS (SELECT 1 FROM campaign WHERE campaign_id = camp_l
                  AND status = 'PAUSED' AND status_reason = 'LEGACY_POLICY_V1'
                  AND current_policy_version = 'roe-101') THEN
    RAISE EXCEPTION 'legacy running campaign was not paused on its v1 snapshot';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM campaign WHERE campaign_id = camp_c
                  AND status = 'CREATED' AND status_reason IS NULL AND current_policy_version = 'roe-102') THEN
    RAISE EXCEPTION 'legacy pending campaign changed status without running';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM campaign_status_change WHERE campaign_id = camp_l AND seq = 1
                  AND from_status = 'RUNNING' AND to_status = 'PAUSED'
                  AND actor = '{"kind":"module","id":"migration/0009"}'::jsonb) THEN
    RAISE EXCEPTION 'the pause of the legacy campaign left no history row';
  END IF;
  IF EXISTS (SELECT 1 FROM campaign_status_change WHERE campaign_id = camp_c) THEN
    RAISE EXCEPTION 'the migration wrote history for a campaign it did not change';
  END IF;
  IF EXISTS (SELECT 1 FROM campaign c JOIN policy_snapshot p ON p.policy_version = c.current_policy_version
              WHERE c.status IN ('RUNNING','WAITING') AND NOT aegis.is_roe_policy_v2(p.policy)) THEN
    RAISE EXCEPTION 'a campaign is still running on v1 configuration';
  END IF;

  -- 5. Jobs: the explicit hold, in both shapes of legacy row, and no drift from the definition.
  IF EXISTS (SELECT 1 FROM scan_job WHERE job_id IN (job_queued, job_running, job_terminal)
              AND dispatch_block_reasons IS DISTINCT FROM ARRAY['LEGACY_ACTOR','LEGACY_POLICY_V1']::text[]) THEN
    RAISE EXCEPTION 'a pinned legacy job is not held exactly for its agent actor and its v1 configuration';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM scan_job WHERE job_id = job_v1 AND dispatch_block_reasons
                  = ARRAY['LEGACY_ACTOR','LEGACY_MISSING_MANIFEST_PIN','LEGACY_MISSING_TARGET_REFS','LEGACY_POLICY_V1']::text[]) THEN
    RAISE EXCEPTION 'the pre-0003 job does not carry all four legacy reasons';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM scan_job WHERE job_id = job_terminal AND status = 'SUCCEEDED'
                  AND envelope_event_id = '01900000-0000-7000-8000-0000000d1663') THEN
    RAISE EXCEPTION 'the hold rewrote a finished legacy job';
  END IF;
  IF EXISTS (SELECT 1 FROM scan_job WHERE dispatch_block_reasons IS DISTINCT FROM aegis.legacy_dispatch_block(scan_job)) THEN
    RAISE EXCEPTION 'stored dispatch_block_reasons drifted from the legacy definition';
  END IF;

  -- 5b. OI-2/OI-18: the post-0009/pre-0010 agent-actor rows (gate-review probe P1). 0010 refuses such
  --     an actor on INSERT, so only 0011 can hold it; without LEGACY_ACTOR the queued row was
  --     dispatchable, which contradicted 0010 and 04. A held terminal row cannot be reopened either.
  IF EXISTS (SELECT 1 FROM scan_job WHERE job_id IN (job_agent_queued, job_agent_done)
              AND dispatch_block_reasons IS DISTINCT FROM ARRAY['LEGACY_ACTOR']::text[]) THEN
    RAISE EXCEPTION 'a post-0009 agent-actor job is not held exactly for LEGACY_ACTOR';
  END IF;
  FOR out IN SELECT unnest(ARRAY[
      'UPDATE scan_job SET status = ''VALIDATING'' WHERE job_id = ' || quote_literal(job_agent_queued),
      'UPDATE scan_job SET status = ''DISPATCHED'' WHERE job_id = ' || quote_literal(job_agent_queued),
      'UPDATE scan_job SET attempt = attempt + 1 WHERE job_id = ' || quote_literal(job_agent_queued)]) LOOP
    BEGIN
      EXECUTE out;
      RAISE EXCEPTION 'not blocked: %', out;
    EXCEPTION WHEN check_violation THEN actor_blocked := actor_blocked + 1;
    END;
  END LOOP;
  BEGIN
    UPDATE scan_job SET generation = 2, attempt = 1, status = 'QUEUED',
        started_at = NULL, finished_at = NULL, envelope_event_id = NULL, error = NULL
     WHERE job_id = job_agent_done;
    RAISE EXCEPTION 'a held post-0009 terminal job was reopened';
  EXCEPTION WHEN check_violation THEN
    IF SQLERRM NOT LIKE '%held%' THEN
      RAISE EXCEPTION 'the reopen was refused for another reason: %', SQLERRM;
    END IF;
    actor_blocked := actor_blocked + 1;
  END;
  out := aegis.request_job_cancel(job_agent_queued, '{"kind":"operator","id":"s1f-test"}', 'agent actor');
  IF out <> 'requested' THEN
    RAISE EXCEPTION 'a held post-0009 job could not be cancelled: %', out;
  END IF;
  out := aegis.record_job_callback(job_agent_queued, 1, 1, 'CANCELLED', NULL, NULL, NULL);
  IF out <> 'terminalized' THEN
    RAISE EXCEPTION 'a held post-0009 job could not record its terminal result: %', out;
  END IF;
  IF actor_blocked <> 4 THEN
    RAISE EXCEPTION 'post-0009 agent actor: % / 4 dispatch and reopen attempts blocked', actor_blocked;
  END IF;
  RAISE NOTICE 'OI-2/OI-18: 2 post-0009 agent-actor jobs held for LEGACY_ACTOR, 4/4 dispatch+reopen attempts blocked, cancel and terminal result still recorded';

  -- 6. No auto-resume: a v1 campaign cannot start, and a held job cannot be dispatched
  --    (VALIDATING, DISPATCHED, RUNNING or an attempt bump), whatever order the scheduler tries.
  FOR out IN SELECT unnest(ARRAY[
      'UPDATE campaign SET status = ''RUNNING'' WHERE campaign_id = ' || quote_literal(camp_l),
      'UPDATE campaign SET status = ''WAITING'' WHERE campaign_id = ' || quote_literal(camp_c),
      'UPDATE scan_job SET status = ''VALIDATING'' WHERE job_id = ' || quote_literal(job_queued),
      'UPDATE scan_job SET status = ''DISPATCHED'' WHERE job_id = ' || quote_literal(job_queued),
      'UPDATE scan_job SET status = ''RUNNING'', started_at = now() WHERE job_id = ' || quote_literal(job_queued),
      'UPDATE scan_job SET status = ''COLLECTING'' WHERE job_id = ' || quote_literal(job_queued),
      'UPDATE scan_job SET attempt = attempt + 1 WHERE job_id = ' || quote_literal(job_running)]) LOOP
    BEGIN
      EXECUTE out;
      RAISE EXCEPTION 'not blocked: %', out;
    EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
    END;
  END LOOP;
  IF blocked <> 7 THEN RAISE EXCEPTION 'only % / 7 resume/dispatch attempts blocked', blocked; END IF;

  -- 7. A held in-flight job still finalizes its result and a held queued job can still be cancelled:
  --    the hold stops a new dispatch, it does not discard evidence or trap a job.
  out := aegis.record_job_callback(job_running, 1, 1, 'SUCCEEDED', '01900000-0000-7000-8000-0000000d1672', NULL, repeat('e',64));
  IF out <> 'terminalized' THEN RAISE EXCEPTION 'held in-flight job could not record its result: %', out; END IF;
  out := aegis.request_job_cancel(job_queued, '{"kind":"operator","id":"s16-test"}', 'legacy config retired');
  IF out <> 'requested' THEN RAISE EXCEPTION 'held queued job could not be cancelled: %', out; END IF;
  out := aegis.record_job_callback(job_queued, 1, 1, 'CANCELLED', NULL, NULL, NULL);
  IF out <> 'terminalized' THEN RAISE EXCEPTION 'held queued cancel was not recorded: %', out; END IF;

  -- 8. An operator can still adopt the v2 candidate explicitly, and only then does the campaign run
  --    (the job created here is new, so 0010 requires a server-derived initiator; the fixture rows
  --    inserted before 0009 keep their legacy self-declared actor).
  --    and v2 work continue: the guard closes the v1 path without freezing the campaign forever.
  UPDATE campaign SET current_policy_version = new_l, status = 'RUNNING' WHERE campaign_id = camp_l;
  IF (SELECT status FROM campaign WHERE campaign_id = camp_l) <> 'RUNNING' THEN
    RAISE EXCEPTION 'campaign could not run after adopting the v2 candidate';
  END IF;
  BEGIN
    UPDATE campaign SET current_policy_version = 'roe-101' WHERE campaign_id = camp_l;
    RAISE EXCEPTION 'not blocked: promotion back to v1 configuration';
  EXCEPTION WHEN check_violation THEN blocked := blocked + 1;
  END;
  INSERT INTO policy_decision (decision_id,campaign_id,capability,provider,targets,input,decision,rationale,requested_by,target_refs,policy_version,scope_id,idempotency_key,trace_id)
    VALUES ('01900000-0000-7000-8000-0000000d1681',camp_l,'dns.enumerate_subdomains','subfinder','{dns:legacy.example}','{"targets":["legacy.example"]}','approved','Post-migration v2 job','{"kind":"operator","id":"s16-test"}','[{"seed_id":"01900000-0000-7000-8000-0000000d1621"},{"canonical_key":"dns:legacy.example"}]',new_l,'01900000-0000-7000-8000-0000000d1602','s16:4',repeat('9',32));
  INSERT INTO scan_job (job_id,campaign_id,decision_id,capability,provider,provider_version,adapter_version,image_digest,manifest_sha256,scan_cycle,job_fingerprint,policy_version,scope_id,input,targets,target_refs,requested_by,rationale,trace_id)
    VALUES ('01900000-0000-7000-8000-0000000d1682',camp_l,'01900000-0000-7000-8000-0000000d1681','dns.enumerate_subdomains','subfinder','v2.6.6','1.0.0','sha256:'||repeat('a',64),repeat('d',64),'01900000-0000-7000-8000-0000000d1683',repeat('f4',32),new_l,'01900000-0000-7000-8000-0000000d1602','{"targets":["legacy.example"]}','{dns:legacy.example}','[{"seed_id":"01900000-0000-7000-8000-0000000d1621"},{"canonical_key":"dns:legacy.example"}]','{"kind":"operator","id":"s16-test"}','Post-migration v2 job',repeat('9',32));
  IF EXISTS (SELECT 1 FROM scan_job WHERE job_id = '01900000-0000-7000-8000-0000000d1682' AND dispatch_block_reasons IS NOT NULL) THEN
    RAISE EXCEPTION 'a new job on adopted v2 configuration was held';
  END IF;
  UPDATE scan_job SET status = 'RUNNING', started_at = now() WHERE job_id = '01900000-0000-7000-8000-0000000d1682';

  -- 9. New snapshots are v2 only, and a legacy policy that cannot be mapped fails loudly instead of
  --    silently losing a setting.
  FOR out IN SELECT unnest(ARRAY[
      'INSERT INTO policy_snapshot VALUES (''roe-900'',' || quote_literal(camp_l) || ',''{"scan_profile":"passive","max_parallel_jobs":10,"max_duration_hours":10}'',repeat(''a'',64),''{"kind":"operator","id":"s16-test"}'')',
      'INSERT INTO policy_snapshot VALUES (''roe-901'',' || quote_literal(camp_l) || ',''{"max_parallel_jobs":51,"max_duration_hours":10}'',repeat(''a'',64),''{"kind":"operator","id":"s16-test"}'')',
      'INSERT INTO policy_snapshot VALUES (''roe-902'',' || quote_literal(camp_l) || ',''{"max_parallel_jobs":10,"max_duration_hours":10,"log_retention_days":30}'',repeat(''a'',64),''{"kind":"operator","id":"s16-test"}'')',
      'SELECT aegis.convert_legacy_policy(''{"scan_profile":"passive","max_parallel_jobs":10,"max_duration_hours":10,"log_retention_days":30}'')',
      'SELECT aegis.convert_legacy_policy(''{"scan_profile":"passive","max_parallel_jobs":10}'')',
      'SELECT aegis.convert_legacy_policy(''{"scan_profile":"passive","max_parallel_jobs":10,"max_duration_hours":10,"allowed_windows":[{"days":["mon"],"start":"08:00","end":"24:30","timezone":"Asia/Ho_Chi_Minh"}]}'')']) LOOP
    BEGIN
      EXECUTE out;
      RAISE EXCEPTION 'not blocked: %', out;
    EXCEPTION WHEN check_violation THEN shape := shape + 1;
    END;
  END LOOP;
  IF shape <> 6 THEN RAISE EXCEPTION 'only % / 6 legacy/snapshot shapes rejected', shape; END IF;

  -- 10. Re-running the tool converts nothing, and the migration emitted no event.
  SELECT count(*) INTO converted FROM aegis.migrate_legacy_policy_snapshots('{"kind":"module","id":"migration/0009"}'::jsonb);
  IF converted <> 0 THEN RAISE EXCEPTION 'second migration run converted % snapshot(s)', converted; END IF;
  IF (SELECT count(*) FROM outbox_event) <> 1 THEN
    RAISE EXCEPTION 'the migration emitted an event (outbox rows = %)', (SELECT count(*) FROM outbox_event);
  END IF;

  RAISE NOTICE 'S1.6 legacy config: v1 snapshots byte-identical, 3 v2 candidates valid, no promotion, legacy campaign paused with history';
  RAISE NOTICE 'S1.6 legacy config: 7/7 resume+dispatch attempts blocked, held jobs still finalize/cancel, adoption then 1 promotion re-blocked';
  RAISE NOTICE 'S1.6 legacy config: 6/6 legacy/snapshot shapes rejected, re-run no-op, no event emitted';
END $$;
ROLLBACK;
