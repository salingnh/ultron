-- 0001_baseline.sql — the whole contract schema in one migration.
--
-- This is the only migration of contracts/db/postgres: it creates the final schema directly, and a
-- fresh database reaches the current contract model in one step. It replaces the former 0001..0016
-- chain, which had accumulated conversion, backfill and "keep the old rows usable" machinery for
-- databases written before a rule existed. No database ever held such rows outside a throwaway
-- dev/CI/soak database (owner decision 2026-11-24), so that machinery is gone rather than carried:
--
--   * no archive/snapshot tables (legacy_contract_snapshot, policy_snapshot_migration), no v1 -> v2
--     policy converter, no dispatch-hold column or its reasons (LEGACY_*), no upgrade fixtures;
--   * a rule that a new row must satisfy is now the column's own constraint (NOT NULL) or an
--     insert-time guard on rows that genuinely span tables, not a "history is exempt" branch;
--   * an existing database is never adopted: the migration runner refuses a database that carries
--     the old chain and prints the reset command (see src/aegis/migrations.py).
--
-- What stays is every invariant the chain enforced for new rows, unchanged: search_path pinning on
-- every function of the schema, the seed/actor/decision binding of a job, the append-only guards,
-- the C04 outbox allocator/fence/watermark/publication order and the graph revision allocation they
-- share, the ingestion receipt/idempotency rules, and the roe-policy.v2 configuration guards.
--
-- sections, in dependency order:
--   1. generic guard helpers          2. shape helpers (usable from a CHECK)
--   3. sequences and tables           4. remaining functions
--   5. keys, indexes, foreign keys    6. view
--   7. append-only protection         8. domain triggers
--   9. search_path pinning            10. privileges
BEGIN;
SET LOCAL search_path = aegis, public;

-- ===========================================================================
-- 0. Schema
-- ===========================================================================

CREATE SCHEMA aegis;


-- ===========================================================================
-- 1. Generic guard helpers
--
-- Every append-only table gets no_delete/no_truncate; an immutable one also gets no_update. They
-- raise instead of silently losing or rewriting history (D26).
-- ===========================================================================


CREATE FUNCTION aegis.forbid_delete() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
BEGIN
  RAISE EXCEPTION 'DELETE bị cấm trên %.% (lưu vĩnh viễn, chỉ ghi thêm)', TG_TABLE_SCHEMA, TG_TABLE_NAME
    USING ERRCODE = 'insufficient_privilege';
END $$;


CREATE FUNCTION aegis.forbid_update() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
BEGIN
  RAISE EXCEPTION 'UPDATE bị cấm trên bảng chỉ ghi thêm %.%', TG_TABLE_SCHEMA, TG_TABLE_NAME
    USING ERRCODE = 'insufficient_privilege';
END $$;


CREATE FUNCTION aegis.forbid_value_update() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
BEGIN
  IF (to_jsonb(NEW) - TG_ARGV) IS DISTINCT FROM (to_jsonb(OLD) - TG_ARGV) THEN
    RAISE EXCEPTION 'UPDATE chỉ được đổi cột trạng thái (%) trên %.%; cột giá trị/định danh là bất biến (D26)',
      array_to_string(TG_ARGV, ', '), TG_TABLE_SCHEMA, TG_TABLE_NAME
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$;


CREATE FUNCTION aegis.protect(tbl regclass, append_only boolean) RETURNS void
    LANGUAGE plpgsql
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
BEGIN
  EXECUTE format('CREATE TRIGGER %I BEFORE DELETE ON %s FOR EACH ROW EXECUTE FUNCTION aegis.forbid_delete()',
                 'no_delete', tbl);
  EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION aegis.forbid_delete()',
                 'no_truncate', tbl);
  IF append_only THEN
    EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE ON %s FOR EACH ROW EXECUTE FUNCTION aegis.forbid_update()',
                   'no_update', tbl);
  END IF;
END $$;


-- ===========================================================================
-- 2. Shape helpers
--
-- The structural half of each contract schema that the database can decide on its own: the closed
-- key sets, types, ranges and the UUIDv7/actor/seed shapes. Semantic formats (IP, domain, IANA
-- timezone) stay in contracts/validation.py, which every consumer enables; these helpers only make
-- a bad value impossible to store. They are IMMUTABLE and pinned, so a CHECK can call them.
-- ===========================================================================


CREATE FUNCTION aegis.is_json_int(v jsonb, lo numeric DEFAULT NULL::numeric, hi numeric DEFAULT NULL::numeric) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
  SELECT v IS NOT NULL
     AND jsonb_typeof(v) = 'number'
     AND (v #>> '{}')::numeric = trunc((v #>> '{}')::numeric)   -- JSON Schema counts 10.0 as an integer
     AND (lo IS NULL OR (v #>> '{}')::numeric >= lo)
     AND (hi IS NULL OR (v #>> '{}')::numeric <= hi)
$$;


CREATE FUNCTION aegis.is_json_number(v jsonb, lo numeric DEFAULT NULL::numeric, hi numeric DEFAULT NULL::numeric, lo_exclusive boolean DEFAULT false) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
  SELECT v IS NOT NULL
     AND jsonb_typeof(v) = 'number'
     AND (lo IS NULL OR (CASE WHEN lo_exclusive
                              THEN (v #>> '{}')::numeric > lo
                              ELSE (v #>> '{}')::numeric >= lo END))
     AND (hi IS NULL OR (v #>> '{}')::numeric <= hi);
$$;


CREATE FUNCTION aegis.is_json_strings(v jsonb, max_items integer DEFAULT NULL::integer, pattern text DEFAULT NULL::text, min_length integer DEFAULT 0) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
  SELECT v IS NOT NULL
     AND jsonb_typeof(v) = 'array'
     AND (max_items IS NULL OR jsonb_array_length(v) <= max_items)
     AND NOT EXISTS (
       SELECT 1 FROM jsonb_array_elements(v) e
        WHERE jsonb_typeof(e) <> 'string'
           OR length(e #>> '{}') < min_length
           OR (pattern IS NOT NULL AND (e #>> '{}') !~ pattern))
     AND jsonb_array_length(v) = (SELECT count(DISTINCT e) FROM jsonb_array_elements(v) e);
$$;


CREATE FUNCTION aegis.is_rate_limits(v jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
  SELECT CASE
    WHEN v IS NULL OR jsonb_typeof(v) <> 'object' THEN false
    WHEN EXISTS (SELECT 1 FROM jsonb_object_keys(v) k
                  WHERE k NOT IN ('requests_per_second_per_host','packets_per_second','jobs_per_minute')) THEN false
    WHEN v ? 'requests_per_second_per_host'
         AND NOT aegis.is_json_number(v->'requests_per_second_per_host', 0, 1000, true) THEN false
    WHEN v ? 'packets_per_second' AND NOT aegis.is_json_int(v->'packets_per_second', 1, 100000) THEN false
    WHEN v ? 'jobs_per_minute'    AND NOT aegis.is_json_int(v->'jobs_per_minute', 1, 600) THEN false
    ELSE true
  END
$$;


CREATE FUNCTION aegis.is_budget(v jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
  SELECT CASE
    WHEN v IS NULL OR jsonb_typeof(v) <> 'object' THEN false
    WHEN EXISTS (SELECT 1 FROM jsonb_object_keys(v) k
                  WHERE k NOT IN ('max_llm_cost_usd','max_llm_tokens','max_jobs',
                                  'max_agent_sessions','idle_cycles_before_pause')) THEN false
    WHEN v ? 'max_llm_cost_usd' AND NOT aegis.is_json_number(v->'max_llm_cost_usd', 0) THEN false
    WHEN v ? 'max_llm_tokens'   AND NOT aegis.is_json_int(v->'max_llm_tokens', 0) THEN false
    WHEN v ? 'max_jobs'         AND NOT aegis.is_json_int(v->'max_jobs', 1) THEN false
    WHEN v ? 'max_agent_sessions' AND NOT aegis.is_json_int(v->'max_agent_sessions', 1) THEN false
    WHEN v ? 'idle_cycles_before_pause'
         AND NOT aegis.is_json_int(v->'idle_cycles_before_pause', 3, 5) THEN false
    ELSE true
  END
$$;


CREATE FUNCTION aegis.is_roe_policy_v2(policy jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'aegis', 'pg_temp'
    AS $_$
  SELECT CASE
    WHEN jsonb_typeof(policy) <> 'object' THEN false
    WHEN EXISTS (SELECT 1 FROM jsonb_object_keys(policy) k WHERE k NOT IN (
      'target_denylist','max_parallel_jobs','max_duration_hours','rate_limits',
      'budget','capability_denylist')) THEN false
    WHEN NOT aegis.is_json_int(policy->'max_parallel_jobs', 1, 50) THEN false
    WHEN NOT aegis.is_json_int(policy->'max_duration_hours', 1, 168) THEN false
    WHEN policy ? 'target_denylist'
         AND NOT aegis.is_json_strings(policy->'target_denylist', 10000, NULL, 1) THEN false
    WHEN policy ? 'rate_limits' AND NOT aegis.is_rate_limits(policy->'rate_limits') THEN false
    WHEN policy ? 'budget' AND NOT aegis.is_budget(policy->'budget') THEN false
    WHEN policy ? 'capability_denylist'
         AND NOT aegis.is_json_strings(policy->'capability_denylist', NULL,
                                       '^[a-z][a-z0-9]*\.[a-z][a-z0-9_]*$', 1) THEN false
    ELSE true
  END
$_$;


CREATE FUNCTION aegis.is_actor(actor jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
  SELECT CASE
    WHEN jsonb_typeof(actor) <> 'object' THEN false
    WHEN jsonb_typeof(actor->'kind') <> 'string' OR jsonb_typeof(actor->'id') <> 'string' THEN false
    WHEN actor->>'kind' NOT IN ('operator', 'module', 'agent') THEN false
    WHEN length(btrim(actor->>'id')) BETWEEN 1 AND 200 THEN
      (SELECT count(*) FROM jsonb_object_keys(actor)) = 2
    ELSE false
  END
$$;


CREATE FUNCTION aegis.is_initiator(actor jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
  SELECT CASE
    WHEN jsonb_typeof(actor) <> 'object' THEN false
    WHEN jsonb_typeof(actor->'kind') <> 'string' OR jsonb_typeof(actor->'id') <> 'string' THEN false
    WHEN actor->>'kind' NOT IN ('operator', 'module') THEN false
    WHEN length(btrim(actor->>'id')) BETWEEN 1 AND 200 THEN
      (SELECT count(*) FROM jsonb_object_keys(actor)) = 2
    ELSE false
  END
$$;


CREATE FUNCTION aegis.is_proposer(actor jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'aegis', 'pg_temp'
    AS $_$
  SELECT CASE
    WHEN jsonb_typeof(actor) <> 'object' THEN false
    WHEN jsonb_typeof(actor->'kind') <> 'string' OR jsonb_typeof(actor->'id') <> 'string' THEN false
    WHEN actor->>'kind' <> 'agent' THEN false
    WHEN actor->>'id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN
      (SELECT count(*) FROM jsonb_object_keys(actor)) = 2
    ELSE false
  END
$_$;


CREATE FUNCTION aegis.is_target_ref(item jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'aegis', 'pg_temp'
    AS $_$
  SELECT CASE
    WHEN jsonb_typeof(item) <> 'object' THEN false
    WHEN (SELECT count(*) FROM jsonb_object_keys(item)) <> 1 THEN false
    WHEN item ? 'seed_id' THEN
      jsonb_typeof(item->'seed_id') = 'string'
      AND item->>'seed_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    WHEN item ? 'canonical_key' THEN
      jsonb_typeof(item->'canonical_key') = 'string'
      AND length(item->>'canonical_key') BETWEEN 3 AND 2048
      AND item->>'canonical_key' ~ '^(dns|ip|service|app|url|email|oci|repo|git|artifact|purl|cloud|k8s):[^[:space:]]+$'
    ELSE false
  END
$_$;


CREATE FUNCTION aegis.is_target_refs(refs jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
  SELECT CASE
    WHEN jsonb_typeof(refs) <> 'array' THEN false
    WHEN jsonb_array_length(refs) NOT BETWEEN 1 AND 1000 THEN false
    ELSE NOT EXISTS (SELECT 1 FROM jsonb_array_elements(refs) AS e WHERE NOT aegis.is_target_ref(e))
  END
$$;


CREATE FUNCTION aegis.is_canonical_projection(targets text[], refs jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
  SELECT refs IS NULL
     OR NOT EXISTS (
       SELECT 1 FROM unnest(targets) AS t
        WHERE NOT EXISTS (
          SELECT 1 FROM jsonb_array_elements(refs) AS e
           WHERE aegis.is_target_ref(e) AND e ? 'canonical_key' AND e->>'canonical_key' = t));
$$;


CREATE FUNCTION aegis.is_wait_reason(reason jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'aegis', 'pg_temp'
    AS $_$
  SELECT CASE
    WHEN jsonb_typeof(reason) <> 'object' THEN false
    WHEN EXISTS (SELECT 1 FROM jsonb_object_keys(reason) AS k
                  WHERE k NOT IN ('code', 'detail', 'blocking_job_ids', 'since')) THEN false
    WHEN coalesce(reason->>'code', '') NOT IN (
      'DEPENDENCY_PENDING', 'DEPENDENCY_FAILED', 'CAMPAIGN_PAUSED', 'BUDGET_EXHAUSTED',
      'CONCURRENCY_LIMIT', 'RATE_LIMITED', 'PROVIDER_UNAVAILABLE', 'MANUAL_HOLD') THEN false
    WHEN reason ? 'detail' AND (jsonb_typeof(reason->'detail') <> 'string'
                                OR length(reason->>'detail') > 500) THEN false
    WHEN reason ? 'blocking_job_ids' AND (
      jsonb_typeof(reason->'blocking_job_ids') <> 'array'
      OR jsonb_array_length(reason->'blocking_job_ids') > 100
      OR EXISTS (SELECT 1 FROM jsonb_array_elements(reason->'blocking_job_ids') AS e
                  WHERE jsonb_typeof(e) <> 'string'
                     OR e #>> '{}' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')) THEN false
    WHEN coalesce(reason->>'since', '') !~
      '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$' THEN false
    ELSE true
  END
$_$;


CREATE FUNCTION aegis.policy_hash(policy jsonb) RETURNS character
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
  SELECT encode(sha256(convert_to(policy::text, 'UTF8')), 'hex')::char(64);
$$;


CREATE FUNCTION aegis.outbox_publication_lock_key() RETURNS bigint
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    SET search_path TO 'aegis', 'pg_temp'
    AS $$ SELECT 2803754796350008::bigint $$;

COMMENT ON FUNCTION aegis.outbox_publication_lock_key() IS 'C04 publication lock advisory key. Writers take it shared and keep it until commit/rollback; the dispatcher tries it exclusively to read a publishable watermark. 2803754796350008 = 0x4145474953 (AEGIS) * 10000 + 0008.';


-- ===========================================================================
-- 3. Sequences
-- ===========================================================================

CREATE SEQUENCE aegis.audit_log_audit_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


CREATE SEQUENCE aegis.graph_revision_revision_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


CREATE SEQUENCE aegis.ingestion_attempt_attempt_seq_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


CREATE SEQUENCE aegis.outbox_event_seq_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


CREATE SEQUENCE aegis.policy_version_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


-- ===========================================================================
-- 4. Tables
--
-- Columns a read model needs are inline; the invariants that must hold at write time are the
-- table's constraints below. Every timestamp is timestamptz, every identifier is a UUIDv7, and a
-- jsonb column is an object the contract publishes (validation.py validates it semantically).
-- ===========================================================================


-- --- campaign ----------------------------------------------------------------

CREATE TABLE aegis.campaign (
    campaign_id uuid NOT NULL,
    name text NOT NULL,
    objective text NOT NULL,
    status text DEFAULT 'CREATED'::text NOT NULL,
    status_reason text,
    current_policy_version text NOT NULL,
    scope_id uuid NOT NULL,
    labels jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_by jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    ended_at timestamp with time zone,
    CONSTRAINT campaign_status_check CHECK ((status = ANY (ARRAY['CREATED'::text, 'RUNNING'::text, 'WAITING'::text, 'PAUSED'::text, 'COMPLETED'::text, 'FAILED'::text, 'CANCELLED'::text])))
);


COMMENT ON TABLE aegis.campaign IS 'M01 (tạo), M02 (status). Trạng thái hiện tại; lịch sử ở campaign_status_change.';

COMMENT ON COLUMN aegis.campaign.current_policy_version IS 'The adopted policy_snapshot. It must be roe-policy.v2 configuration: creating a campaign, promoting a snapshot and moving to RUNNING/WAITING are refused for anything else (aegis.guard_campaign_v2_config).';


-- --- campaign_status_change --------------------------------------------------

CREATE TABLE aegis.campaign_status_change (
    campaign_id uuid NOT NULL,
    seq integer NOT NULL,
    from_status text,
    to_status text NOT NULL,
    reason text,
    actor jsonb NOT NULL,
    trace_id character(32),
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


COMMENT ON TABLE aegis.campaign_status_change IS 'M02. Append-only.';


-- --- campaign_target ---------------------------------------------------------

CREATE TABLE aegis.campaign_target (
    target_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    kind text NOT NULL,
    raw_value text NOT NULL,
    canonical_key text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT campaign_target_kind_check CHECK ((kind = ANY (ARRAY['domain'::text, 'ip'::text, 'cidr'::text, 'url'::text, 'email'::text, 'keyword'::text])))
);


COMMENT ON TABLE aegis.campaign_target IS 'M01. Mục tiêu hạt giống, gốc của chuỗi nguồn gốc (G5). Append-only.';


-- --- campaign_ledger ---------------------------------------------------------

CREATE TABLE aegis.campaign_ledger (
    campaign_id uuid NOT NULL,
    seq bigint NOT NULL,
    kind text NOT NULL,
    payload jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT campaign_ledger_kind_check CHECK ((kind = ANY (ARRAY['cycle_started'::text, 'cycle_finished'::text, 'objective_done'::text, 'objective_blocked'::text, 'blocker'::text, 'cursor'::text, 'budget'::text, 'idle_cycle'::text, 'stop_condition'::text])))
);


COMMENT ON TABLE aegis.campaign_ledger IS 'M02. Sổ chiến dịch ngoài hội thoại LLM. Append-only.';


-- --- scope_snapshot ----------------------------------------------------------

CREATE TABLE aegis.scope_snapshot (
    scope_id uuid NOT NULL,
    campaign_id uuid NOT NULL,
    targets jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


COMMENT ON TABLE aegis.scope_snapshot IS 'M01. Tập mục tiêu đầu vào (KHÔNG phải allowlist; chốt 13/11). Append-only.';


-- --- objective ---------------------------------------------------------------

CREATE TABLE aegis.objective (
    objective_id uuid NOT NULL,
    campaign_id uuid NOT NULL,
    parent_id uuid,
    text text NOT NULL,
    created_by jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


COMMENT ON TABLE aegis.objective IS 'M01/M03. Mục tiêu con của chiến dịch. Append-only; trạng thái ở campaign_ledger.';


-- --- policy_snapshot ---------------------------------------------------------

CREATE TABLE aegis.policy_snapshot (
    policy_version text NOT NULL,
    campaign_id uuid NOT NULL,
    policy jsonb NOT NULL,
    policy_hash character(64) NOT NULL,
    created_by jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT policy_snapshot_policy_version_check CHECK ((policy_version ~ '^roe-[1-9][0-9]*$'::text))
);


COMMENT ON TABLE aegis.policy_snapshot IS 'M01. Bản chụp RoE bất biến; đổi RoE = dòng mới với policy_version mới. Append-only.';

COMMENT ON COLUMN aegis.policy_snapshot.policy IS 'roe-policy.v2 configuration: the closed key set (no RoE time windows), types and ranges are enforced by aegis.is_roe_policy_v2 on INSERT (validate the full schema with contracts/validation.py). The table is append-only.';


-- --- policy_decision ---------------------------------------------------------

CREATE TABLE aegis.policy_decision (
    decision_id uuid NOT NULL,
    campaign_id uuid NOT NULL,
    session_id uuid,
    capability text NOT NULL,
    provider text,
    targets text[] NOT NULL,
    input jsonb NOT NULL,
    decision text NOT NULL,
    rule text,
    error jsonb,
    rationale text NOT NULL,
    requested_by jsonb NOT NULL,
    policy_version text NOT NULL,
    scope_id uuid NOT NULL,
    idempotency_key text NOT NULL,
    trace_id character(32) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    proposed_by jsonb,
    target_refs jsonb NOT NULL,
    request_hash character(64),
    CONSTRAINT policy_decision_check CHECK (((decision = 'approved'::text) OR (error IS NOT NULL))),
    CONSTRAINT policy_decision_decision_check CHECK ((decision = ANY (ARRAY['approved'::text, 'denied'::text]))),
    CONSTRAINT policy_decision_request_hash_check CHECK (((request_hash IS NULL) OR (request_hash ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT policy_decision_target_refs_shape CHECK (aegis.is_target_refs(target_refs))
);


COMMENT ON TABLE aegis.policy_decision IS 'M05. Nhật ký quyết định policy: mục tiêu + lý do (FR-002). Append-only.';

COMMENT ON COLUMN aegis.policy_decision.targets IS 'canonical-key projection of target_refs: each element is the canonical_key of a TargetRef and may be empty when every target is a keyword/CIDR seed. The request itself is attributable through target_refs.';

COMMENT ON COLUMN aegis.policy_decision.proposed_by IS 'C05 agent session that proposed the request (id = agent_session.session_id), enforced on INSERT by aegis.require_decision_proposer_session; NULL when an operator or module submitted it directly. Never a fabricated session. The table is append-only.';

COMMENT ON COLUMN aegis.policy_decision.target_refs IS 'C02 TargetRef list of the decided request ({seed_id} of a campaign_target in the same campaign/scope, or {canonical_key}). NOT NULL: a decision is not attributable to a seed without it. Immutable: policy_decision is append-only.';

COMMENT ON COLUMN aegis.policy_decision.request_hash IS 'sha256(utf8(aegis-c14n/1(submitted JobSubmit body))) written by M05 (G1.1c) for REST submissions. The unique (campaign_id, idempotency_key) row is the accepted request: a retry hashes its body and replays the stored decision/job only when the hash matches, otherwise 409 IDEMPOTENCY_CONFLICT. NULL for rows predating the column and for non-REST callers.';


-- --- provider_manifest -------------------------------------------------------

CREATE TABLE aegis.provider_manifest (
    manifest_sha256 character(64) NOT NULL,
    capability text NOT NULL,
    provider text NOT NULL,
    provider_version text NOT NULL,
    adapter_version text NOT NULL,
    image_digest text NOT NULL,
    input_schema_ref text NOT NULL,
    manifest_utf8 bytea NOT NULL,
    registered_at timestamp with time zone DEFAULT now() NOT NULL,
    registered_by jsonb NOT NULL,
    CONSTRAINT provider_manifest_adapter_version_semver CHECK ((adapter_version ~ '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$'::text)),
    CONSTRAINT provider_manifest_bytes_present CHECK ((length(manifest_utf8) > 0)),
    CONSTRAINT provider_manifest_capability_shape CHECK ((capability ~ '^[a-z][a-z0-9]*\.[a-z][a-z0-9_]*$'::text)),
    CONSTRAINT provider_manifest_image_digest_shape CHECK ((image_digest ~ '^sha256:[0-9a-f]{64}$'::text)),
    CONSTRAINT provider_manifest_input_schema_ref_shape CHECK ((input_schema_ref ~ '^schema://[a-z0-9-]+/[a-z0-9-]+/v[0-9]+$'::text)),
    CONSTRAINT provider_manifest_provider_present CHECK (((length(btrim(provider)) >= 1) AND (length(btrim(provider)) <= 200))),
    CONSTRAINT provider_manifest_provider_version_present CHECK (((length(btrim(provider_version)) >= 1) AND (length(btrim(provider_version)) <= 128))),
    CONSTRAINT provider_manifest_registered_by_actor CHECK (aegis.is_actor(registered_by)),
    CONSTRAINT provider_manifest_sha256_describes_bytes CHECK (((manifest_sha256)::text = encode(sha256(manifest_utf8), 'hex'::text))),
    CONSTRAINT provider_manifest_sha256_shape CHECK ((manifest_sha256 ~ '^[0-9a-f]{64}$'::text))
);


COMMENT ON TABLE aegis.provider_manifest IS 'M05 immutable manifest registry (G1.1c). Key = SHA-256 of the exact bytes the registry accepted; a CHECK proves the hash describes the stored bytes, and accepted rows are append-only, so a job pin (scan_job.manifest_sha256) always resolves to the same document. Resolution ("latest") is a query over this table; a job never re-resolves, it fetches by hash (interfaces/README.md §Manifest bất biến).';

COMMENT ON COLUMN aegis.provider_manifest.provider_version IS 'spec.providerVersion of the manifest: the upstream tool build (e.g. v2.17.0), not the adapter package version.';

COMMENT ON COLUMN aegis.provider_manifest.adapter_version IS 'metadata.version of the manifest: the adapter package version pinned by ApprovedTask.adapter_version.';

COMMENT ON COLUMN aegis.provider_manifest.manifest_utf8 IS 'The exact bytes hashed for manifest_sha256 (UTF-8 YAML as published by the adapter package). Never re-serialised: M06 re-hashes these bytes to verify the pin.';


-- --- agent_session -----------------------------------------------------------

CREATE TABLE aegis.agent_session (
    session_id uuid NOT NULL,
    campaign_id uuid NOT NULL,
    objective_id uuid,
    policy_version text NOT NULL,
    revision_from bigint NOT NULL,
    status text NOT NULL,
    decision text,
    stop_reason text,
    steps_used integer DEFAULT 0 NOT NULL,
    result jsonb,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    finished_at timestamp with time zone,
    CONSTRAINT agent_session_decision_check CHECK ((decision = ANY (ARRAY['continue'::text, 'wait'::text, 'stop'::text]))),
    CONSTRAINT agent_session_status_check CHECK ((status = ANY (ARRAY['RUNNING'::text, 'SUCCEEDED'::text, 'FAILED'::text, 'CANCELLED'::text]))),
    CONSTRAINT agent_session_steps_used_check CHECK (((steps_used >= 0) AND (steps_used <= 30)))
);


COMMENT ON TABLE aegis.agent_session IS 'M03. Trạng thái hiện tại; output cuối bất biến sau khi status khác RUNNING.';


-- --- scan_job ----------------------------------------------------------------

CREATE TABLE aegis.scan_job (
    job_id uuid NOT NULL,
    campaign_id uuid NOT NULL,
    decision_id uuid NOT NULL,
    capability text NOT NULL,
    provider text NOT NULL,
    provider_version text NOT NULL,
    adapter_version text NOT NULL,
    image_digest text NOT NULL,
    scan_cycle uuid NOT NULL,
    job_fingerprint character(64) NOT NULL,
    policy_version text NOT NULL,
    scope_id uuid NOT NULL,
    input jsonb NOT NULL,
    targets text[] NOT NULL,
    requested_by jsonb NOT NULL,
    rationale text NOT NULL,
    parent_job_id uuid,
    status text DEFAULT 'QUEUED'::text NOT NULL,
    error jsonb,
    envelope_event_id uuid,
    trace_id character(32) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    priority integer DEFAULT 50 NOT NULL,
    manifest_sha256 character(64) NOT NULL,
    target_refs jsonb NOT NULL,
    attempt integer DEFAULT 1 NOT NULL,
    generation integer DEFAULT 1 NOT NULL,
    cancel_requested_at timestamp with time zone,
    cancel_requested_by jsonb,
    cancel_reason text,
    wait_reason jsonb,
    proposed_by jsonb,
    approved_task jsonb,
    CONSTRAINT scan_job_approved_task_shape CHECK (((approved_task IS NULL) OR ((jsonb_typeof(approved_task) = 'object'::text) AND (approved_task ? 'signature'::text) AND (approved_task ? 'signature_key_id'::text) AND (approved_task ? 'egress_binding'::text) AND ((approved_task ->> 'manifest_sha256'::text) = (manifest_sha256)::text)))),
    CONSTRAINT scan_job_attempt_check CHECK ((attempt >= 1)),
    CONSTRAINT scan_job_cancel_actor_shape CHECK (((cancel_requested_by IS NULL) OR aegis.is_actor(cancel_requested_by))),
    CONSTRAINT scan_job_cancel_intent_complete CHECK (((cancel_requested_at IS NULL) = (cancel_requested_by IS NULL))),
    CONSTRAINT scan_job_check CHECK (((status <> 'FAILED'::text) OR (error IS NOT NULL))),
    CONSTRAINT scan_job_generation_check CHECK ((generation >= 1)),
    CONSTRAINT scan_job_image_digest_check CHECK ((image_digest ~ '^sha256:[0-9a-f]{64}$'::text)),
    CONSTRAINT scan_job_manifest_sha256_check CHECK ((manifest_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT scan_job_priority_check CHECK (((priority >= 0) AND (priority <= 100))),
    CONSTRAINT scan_job_status_check CHECK ((status = ANY (ARRAY['QUEUED'::text, 'VALIDATING'::text, 'DISPATCHED'::text, 'RUNNING'::text, 'COLLECTING'::text, 'SUCCEEDED'::text, 'FAILED'::text, 'CANCELLED'::text]))),
    CONSTRAINT scan_job_target_refs_shape CHECK (aegis.is_target_refs(target_refs)),
    CONSTRAINT scan_job_wait_reason_queued CHECK (((wait_reason IS NULL) OR (status = 'QUEUED'::text))),
    CONSTRAINT scan_job_wait_reason_shape CHECK (((wait_reason IS NULL) OR aegis.is_wait_reason(wait_reason)))
);


COMMENT ON TABLE aegis.scan_job IS 'M06. Trạng thái hiện tại; lịch sử ở job_status_change. Mỗi job = một lần chạy (scan_id = job_id).';

COMMENT ON COLUMN aegis.scan_job.job_fingerprint IS 'X-1/C03 fingerprint, aegis-c14n/1: sha256 of {campaign_id,capability,policy_version,provider,provider_version,adapter_version,image_digest,manifest_sha256,target_refs,input,scan_cycle}. It hashes target_refs (the TargetRef list), never the targets canonical-key projection: two keyword/CIDR seeds would otherwise share a fingerprint. priority, depends_on, actor/rationale/trace, job_id/decision_id, status and execution timestamps are excluded because they do not identify the scanned data. Conflicting scheduling for an existing fingerprint is rejected, not silently merged. Canonicalization and field lists: contracts/ingestion/canonicalization.v2.yaml.';

COMMENT ON COLUMN aegis.scan_job.targets IS 'canonical-key projection of target_refs: each element is the canonical_key of a TargetRef (enforced on INSERT by aegis.require_canonical_projection) and may be empty when every target is a keyword/CIDR seed. Never the source of identity or provenance.';

COMMENT ON COLUMN aegis.scan_job.requested_by IS 'C05 server-derived initiator {kind: operator|module, id}, written by M05 from its own verified principal. aegis.require_job_initiator enforces the shape on INSERT; aegis.forbid_value_update (cols_only) makes it immutable after acceptance.';

COMMENT ON COLUMN aegis.scan_job.priority IS 'Higher value first among ready jobs; dependencies and resource limits take precedence. Immutable after acceptance.';

COMMENT ON COLUMN aegis.scan_job.manifest_sha256 IS 'SHA-256 of the exact immutable manifest bytes. NOT NULL: a job without a pin cannot be dispatched, so the column cannot be NULL. aegis.forbid_value_update (cols_only) makes it immutable after acceptance.';

COMMENT ON COLUMN aegis.scan_job.target_refs IS 'C02 TargetRef list: {seed_id} for a campaign_target of the same campaign/scope (keeps keyword/CIDR seeds without inventing an asset) or {canonical_key} for a known asset. NOT NULL: a job without seed provenance is not dispatchable. Immutable after acceptance.';

COMMENT ON COLUMN aegis.scan_job.attempt IS 'Dispatch attempt within the current generation, 1 on insert, +1 per re-dispatch of a non-terminal job. A callback from another attempt is quarantined.';

COMMENT ON COLUMN aegis.scan_job.generation IS 'Re-execution generation, 1 on insert, +1 only when a terminal job is reopened (attempt back to 1, result columns cleared). Different from scan_cycle (a new scan is a new job) and from an envelope retry.';

COMMENT ON COLUMN aegis.scan_job.cancel_requested_at IS 'Cancel intent, written once by aegis.request_job_cancel and immutable afterwards; the job only becomes CANCELLED through aegis.record_job_callback. Cleared only by generation+1.';

COMMENT ON COLUMN aegis.scan_job.cancel_requested_by IS 'OI-9 cancel actor: an Actor (operator|module|agent), shape-checked; an agent may only cancel a job whose proposed_by is its own session. Written once by aegis.request_job_cancel and immutable afterwards.';

COMMENT ON COLUMN aegis.scan_job.wait_reason IS 'X-4 wait reason (job.v2#/$defs/WaitReason) while status=QUEUED: dependency, campaign pause, budget, window, concurrency, rate, provider or operator hold. NULL means dispatchable. Every change is kept in job_lifecycle_change.';

COMMENT ON COLUMN aegis.scan_job.proposed_by IS 'C05 agent session that proposed the job (id = agent_session.session_id). Enforced on INSERT by aegis.require_job_proposer_session (kind agent, UUIDv7 session, same campaign); NULL for a direct operator/module submission. Immutable after acceptance.';

COMMENT ON COLUMN aegis.scan_job.approved_task IS 'The exact ApprovedTask M05 signed and accepted for this job (OI-7/E-1): merged input, TargetRefs, manifest pin, egress binding and signature. Immutable via cols_only; M06 verifies the HMAC with the key named by signature_key_id and uses egress_binding as the broker allow-set instead of recomputing it. NULL only for rows that did not come through M05 (history and contract fixtures), which are not dispatchable by M06 without a task.';


-- --- job_dependency ----------------------------------------------------------

CREATE TABLE aegis.job_dependency (
    campaign_id uuid NOT NULL,
    job_id uuid NOT NULL,
    depends_on_job_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT job_dependency_check CHECK ((job_id <> depends_on_job_id))
);


COMMENT ON TABLE aegis.job_dependency IS 'M02/M05. Immutable dependencies in same campaign. Insert with new job in one transaction; M05 rejects cycles before dispatch. Only SUCCEEDED predecessors release a job. Failed/cancelled predecessor leaves dependent waiting with a reason.';


-- --- job_status_change -------------------------------------------------------

CREATE TABLE aegis.job_status_change (
    job_id uuid NOT NULL,
    seq integer NOT NULL,
    from_status text,
    to_status text NOT NULL,
    error jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


COMMENT ON TABLE aegis.job_status_change IS 'M06. Append-only.';


-- --- job_lifecycle_change ----------------------------------------------------

CREATE TABLE aegis.job_lifecycle_change (
    job_id uuid NOT NULL,
    seq integer NOT NULL,
    field text NOT NULL,
    old_value jsonb,
    new_value jsonb,
    at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT job_lifecycle_change_field_check CHECK ((field = ANY (ARRAY['attempt'::text, 'generation'::text, 'cancel_request'::text, 'wait_reason'::text])))
);


COMMENT ON TABLE aegis.job_lifecycle_change IS 'C06 append-only history of attempt, generation, cancel intent and wait reason. Written by the scan_job trigger; status history stays in job_status_change.';


-- --- job_callback_quarantine -------------------------------------------------

CREATE TABLE aegis.job_callback_quarantine (
    quarantine_id uuid NOT NULL,
    job_id uuid NOT NULL,
    generation integer NOT NULL,
    attempt integer NOT NULL,
    callback text NOT NULL,
    reason text NOT NULL,
    claimed jsonb DEFAULT '{}'::jsonb NOT NULL,
    payload_hash character(64),
    evidence_refs jsonb DEFAULT '[]'::jsonb NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT job_callback_quarantine_attempt_check CHECK ((attempt >= 1)),
    CONSTRAINT job_callback_quarantine_callback_check CHECK ((callback = ANY (ARRAY['started'::text, 'completed'::text]))),
    CONSTRAINT job_callback_quarantine_generation_check CHECK ((generation >= 1)),
    CONSTRAINT job_callback_quarantine_payload_hash_check CHECK (((payload_hash IS NULL) OR (payload_hash ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT job_callback_quarantine_reason_check CHECK ((reason = ANY (ARRAY['stale_generation'::text, 'stale_attempt'::text, 'attempt_not_started'::text, 'terminal_already_recorded'::text, 'cancel_not_requested'::text])))
);


COMMENT ON TABLE aegis.job_callback_quarantine IS 'C06 append-only record of a late or conflicting result callback: which generation/attempt claimed what, and why it was not applied. The payload itself stays with its evidence and C03 payload_hash.';


-- --- evidence ----------------------------------------------------------------

CREATE TABLE aegis.evidence (
    evidence_id uuid NOT NULL,
    sha256 character(64) NOT NULL,
    storage_uri text NOT NULL,
    campaign_id uuid NOT NULL,
    job_id uuid NOT NULL,
    size_bytes bigint NOT NULL,
    media_type text NOT NULL,
    kind text DEFAULT 'raw_output'::text NOT NULL,
    classification text NOT NULL,
    source_tool text NOT NULL,
    verified_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT evidence_classification_check CHECK ((classification = ANY (ARRAY['PUBLIC'::text, 'INTERNAL'::text, 'RESTRICTED'::text]))),
    CONSTRAINT evidence_sha256_check CHECK ((sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT evidence_size_bytes_check CHECK ((size_bytes >= 0))
);


COMMENT ON TABLE aegis.evidence IS 'M28. Metadata bằng chứng; object ở SeaweedFS có object lock. Append-only.';


-- --- evidence_check ----------------------------------------------------------

CREATE TABLE aegis.evidence_check (
    evidence_id uuid NOT NULL,
    checked_at timestamp with time zone DEFAULT now() NOT NULL,
    ok boolean NOT NULL,
    detail text
);


COMMENT ON TABLE aegis.evidence_check IS 'M28. Kết quả kiểm hash (sau phục hồi, định kỳ). Append-only.';


-- --- artifact ----------------------------------------------------------------

CREATE TABLE aegis.artifact (
    artifact_id uuid NOT NULL,
    digest text NOT NULL,
    kind text NOT NULL,
    origin_uri text,
    storage_uri text,
    size_bytes bigint,
    classification text NOT NULL,
    first_job_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT artifact_classification_check CHECK ((classification = ANY (ARRAY['PUBLIC'::text, 'INTERNAL'::text, 'RESTRICTED'::text]))),
    CONSTRAINT artifact_digest_check CHECK ((digest ~ '^sha256:[0-9a-f]{64}$'::text)),
    CONSTRAINT artifact_kind_check CHECK ((kind = ANY (ARRAY['oci_image'::text, 'archive'::text, 'binary'::text, 'js_bundle'::text, 'source_tree'::text, 'sbom'::text, 'other'::text])))
);


COMMENT ON TABLE aegis.artifact IS 'M28. Append-only.';


-- --- model_usage -------------------------------------------------------------

CREATE TABLE aegis.model_usage (
    usage_id uuid NOT NULL,
    campaign_id uuid,
    session_id uuid,
    provider text NOT NULL,
    model text NOT NULL,
    input_tokens integer NOT NULL,
    output_tokens integer NOT NULL,
    cost_usd numeric(12,6) NOT NULL,
    latency_ms integer NOT NULL,
    status text NOT NULL,
    error_code text,
    trace_id character(32) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT model_usage_provider_check CHECK ((provider = ANY (ARRAY['openai'::text, 'anthropic'::text]))),
    CONSTRAINT model_usage_status_check CHECK ((status = ANY (ARRAY['ok'::text, 'error'::text, 'fallback'::text, 'budget_denied'::text])))
);


COMMENT ON TABLE aegis.model_usage IS 'M04 append-only usage. New rows require nonnegative tokens/cost/latency. NOT VALID preserves earlier measurements; readers must surface invalid historical rows as an integrity error, never use them to reduce consumed budget or report an exact total.';


-- --- idempotency_record ------------------------------------------------------

CREATE TABLE aegis.idempotency_record (
    scope text NOT NULL,
    key text NOT NULL,
    request_hash character(64) NOT NULL,
    status_code integer NOT NULL,
    response jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


COMMENT ON TABLE aegis.idempotency_record IS 'M26/M27/M05: kết quả đã trả cho Idempotency-Key. Append-only.';


-- --- asset -------------------------------------------------------------------

CREATE TABLE aegis.asset (
    asset_id uuid NOT NULL,
    canonical_key text NOT NULL,
    kind text NOT NULL,
    owner text,
    exposure text,
    criticality text,
    first_seen timestamp with time zone NOT NULL,
    last_seen timestamp with time zone NOT NULL,
    first_job_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    normalization_version text NOT NULL,
    CONSTRAINT asset_check CHECK ((last_seen >= first_seen)),
    CONSTRAINT asset_criticality_check CHECK ((criticality = ANY (ARRAY['high'::text, 'medium'::text, 'low'::text, 'unknown'::text]))),
    CONSTRAINT asset_exposure_check CHECK ((exposure = ANY (ARRAY['internet'::text, 'internal'::text, 'unknown'::text]))),
    CONSTRAINT asset_kind_check CHECK ((kind = ANY (ARRAY['domain'::text, 'ip'::text, 'service'::text, 'application'::text, 'url'::text, 'email'::text, 'oci_image'::text, 'repo'::text, 'repo_snapshot'::text, 'artifact'::text, 'package'::text, 'cloud_resource'::text, 'k8s_workload'::text]))),
    CONSTRAINT asset_normalization_version_check CHECK ((normalization_version ~ '^aegis-norm/[1-9][0-9]*$'::text))
);


COMMENT ON TABLE aegis.asset IS 'M07. Một tài sản thật = một dòng (khóa chuẩn). Cột owner/exposure/criticality/last_seen là bộ đệm; lịch sử ở asset_annotation và observation.';

COMMENT ON COLUMN aegis.asset.normalization_version IS 'aegis-norm/<n> (contracts/ingestion/normalization.v2.yaml) that minted canonical_key. NOT NULL, written once: a key that came from no versioned rule set is never compared with a versioned one. A rules change is a new version plus an explicit re-key migration.';


-- --- asset_alias -------------------------------------------------------------

CREATE TABLE aegis.asset_alias (
    alias_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    namespace text NOT NULL,
    alias_value text NOT NULL,
    reason text,
    source_job_id uuid,
    observed_at timestamp with time zone NOT NULL,
    CONSTRAINT asset_alias_namespace_check CHECK ((namespace = ANY (ARRAY['original'::text, 'idna'::text, 'oci_tag'::text, 'git_branch'::text, 'git_tag'::text, 'hostname'::text, 'cpe'::text, 'other'::text])))
);


COMMENT ON TABLE aegis.asset_alias IS 'M07. Bí danh (tag image, nhánh git...). Append-only; hiệu lực tính từ chuỗi observed_at.';


-- --- asset_annotation --------------------------------------------------------

CREATE TABLE aegis.asset_annotation (
    asset_id uuid NOT NULL,
    seq integer NOT NULL,
    field text NOT NULL,
    value text,
    source text NOT NULL,
    reason text NOT NULL,
    actor jsonb NOT NULL,
    evidence_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT asset_annotation_field_check CHECK ((field = ANY (ARRAY['owner'::text, 'exposure'::text, 'criticality'::text]))),
    CONSTRAINT asset_annotation_source_check CHECK ((source = ANY (ARRAY['operator'::text, 'inferred'::text])))
);


COMMENT ON TABLE aegis.asset_annotation IS 'M07. Lịch sử chủ sở hữu, phơi nhiễm, độ quan trọng. Append-only.';


-- --- asset_campaign ----------------------------------------------------------

CREATE TABLE aegis.asset_campaign (
    asset_id uuid NOT NULL,
    campaign_id uuid NOT NULL,
    first_seen timestamp with time zone NOT NULL,
    first_job_id uuid
);


COMMENT ON TABLE aegis.asset_campaign IS 'M07. Tài sản dùng chung toàn hệ thống (single-tenant); bảng này cho biết chiến dịch nào đã chạm tới tài sản, để lọc truy vấn theo chiến dịch. Append-only.';


-- --- asset_package -----------------------------------------------------------

CREATE TABLE aegis.asset_package (
    asset_id uuid NOT NULL,
    purl text NOT NULL,
    ecosystem text NOT NULL,
    name text NOT NULL,
    version text NOT NULL
);


-- --- asset_provenance --------------------------------------------------------

CREATE TABLE aegis.asset_provenance (
    provenance_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    campaign_id uuid NOT NULL,
    from_asset_id uuid,
    from_target_id uuid,
    source_job_id uuid,
    provider text,
    observed_at timestamp with time zone NOT NULL,
    CONSTRAINT asset_provenance_check CHECK ((num_nonnulls(from_asset_id, from_target_id) = 1)),
    CONSTRAINT asset_provenance_check1 CHECK (((source_job_id IS NOT NULL) OR (from_target_id IS NOT NULL)))
);


COMMENT ON TABLE aegis.asset_provenance IS 'M27 ghi (cổng G5): tài sản được tìm ra từ mục tiêu/tài sản nào, bởi công cụ nào, lần chạy nào. Append-only.';


-- --- asset_service -----------------------------------------------------------

CREATE TABLE aegis.asset_service (
    asset_id uuid NOT NULL,
    ip inet NOT NULL,
    port integer NOT NULL,
    transport text NOT NULL,
    CONSTRAINT asset_service_port_check CHECK (((port >= 1) AND (port <= 65535))),
    CONSTRAINT asset_service_transport_check CHECK ((transport = ANY (ARRAY['tcp'::text, 'udp'::text])))
);


COMMENT ON TABLE aegis.asset_service IS 'M07. Append-only.';


-- --- asset_url ---------------------------------------------------------------

CREATE TABLE aegis.asset_url (
    asset_id uuid NOT NULL,
    scheme text NOT NULL,
    host text NOT NULL,
    port integer NOT NULL,
    path text NOT NULL,
    query text DEFAULT ''::text NOT NULL,
    CONSTRAINT asset_url_scheme_check CHECK ((scheme = ANY (ARRAY['http'::text, 'https'::text])))
);


-- --- relationship ------------------------------------------------------------

CREATE TABLE aegis.relationship (
    relationship_id uuid NOT NULL,
    type text NOT NULL,
    from_asset_id uuid NOT NULL,
    to_asset_id uuid NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    valid_from timestamp with time zone NOT NULL,
    valid_to timestamp with time zone,
    source_job_id uuid NOT NULL,
    closed_by_job_id uuid,
    confidence numeric(4,3) NOT NULL,
    campaign_id uuid NOT NULL,
    attributes jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT relationship_check CHECK ((from_asset_id <> to_asset_id)),
    CONSTRAINT relationship_confidence_check CHECK (((confidence >= (0)::numeric) AND (confidence <= (1)::numeric))),
    CONSTRAINT relationship_type_check CHECK ((type = ANY (ARRAY['SUBDOMAIN_OF'::text, 'RESOLVES_TO'::text, 'EXPOSES'::text, 'SERVES'::text, 'HAS_ENDPOINT'::text, 'HAS_ARTIFACT'::text, 'CONTAINS_PACKAGE'::text, 'DISCOVERED_FROM'::text, 'SNAPSHOT_OF'::text, 'ALIAS_OF'::text])))
);


COMMENT ON TABLE aegis.relationship IS 'M27. Một dòng = một khoảng hiệu lực của cạnh. Không thấy nữa (job có coverage complete) thì đặt valid_to; thấy lại thì mở dòng mới.';


-- --- relationship_sighting ---------------------------------------------------

CREATE TABLE aegis.relationship_sighting (
    relationship_id uuid NOT NULL,
    scan_id uuid NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    confidence numeric(4,3) NOT NULL,
    evidence_ids uuid[] DEFAULT '{}'::uuid[] NOT NULL
);


COMMENT ON TABLE aegis.relationship_sighting IS 'M27. Mỗi lần một job thấy cạnh. Append-only.';


-- --- observation -------------------------------------------------------------

CREATE TABLE aegis.observation (
    observation_id uuid NOT NULL,
    campaign_id uuid NOT NULL,
    scan_id uuid NOT NULL,
    envelope_event_id uuid NOT NULL,
    revision bigint NOT NULL,
    subject_asset_id uuid NOT NULL,
    predicate text NOT NULL,
    value jsonb,
    value_hash character(64) NOT NULL,
    polarity text DEFAULT 'present'::text NOT NULL,
    confidence numeric(4,3),
    provider text NOT NULL,
    provider_version text NOT NULL,
    evidence_ids uuid[] DEFAULT '{}'::uuid[] NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    ingested_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT observation_confidence_check CHECK (((confidence >= (0)::numeric) AND (confidence <= (1)::numeric))),
    CONSTRAINT observation_polarity_check CHECK ((polarity = ANY (ARRAY['present'::text, 'absent'::text, 'negated'::text])))
);


COMMENT ON TABLE aegis.observation IS 'M27. Điều ghi nhận được tại một thời điểm; mâu thuẫn giữa nguồn = nhiều dòng. Append-only.';


-- --- graph_revision ----------------------------------------------------------

CREATE TABLE aegis.graph_revision (
    revision bigint NOT NULL,
    campaign_id uuid NOT NULL,
    causal_job_id uuid,
    envelope_event_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER SEQUENCE aegis.graph_revision_revision_seq OWNED BY aegis.graph_revision.revision;


COMMENT ON TABLE aegis.graph_revision IS 'Append-only knowledge revision. revision comes from the same aegis.outbox_publication counter as outbox_event.seq (C04), so a revision and the events of the same transaction are published in one order under the same watermark; the projector uses aegis.outbox_batch style watermark rules and a new consumer generation for rebuilds.';

COMMENT ON COLUMN aegis.graph_revision.revision IS 'C04 publication sequence, same allocator/counter as outbox_event.seq; assigned by the allocate_seq trigger, writers must not supply it.';


-- --- finding -----------------------------------------------------------------

CREATE TABLE aegis.finding (
    finding_id uuid NOT NULL,
    fingerprint character(64) NOT NULL,
    asset_id uuid NOT NULL,
    rule_id text NOT NULL,
    category text NOT NULL,
    title text NOT NULL,
    vulnerability_ids text[] DEFAULT '{}'::text[] NOT NULL,
    location jsonb DEFAULT '{}'::jsonb NOT NULL,
    match_method text,
    status text NOT NULL,
    severity text DEFAULT 'UNRATED'::text NOT NULL,
    current_assessment uuid,
    transition_seq integer DEFAULT 1 NOT NULL,
    confidence numeric(4,3),
    secret_value text,
    secret_fingerprint character(64),
    first_seen timestamp with time zone NOT NULL,
    last_seen timestamp with time zone NOT NULL,
    first_job_id uuid NOT NULL,
    first_campaign_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT finding_category_check CHECK ((category = ANY (ARRAY['vulnerability'::text, 'misconfiguration'::text, 'exposure'::text, 'secret'::text, 'weak_crypto'::text, 'other'::text]))),
    CONSTRAINT finding_check CHECK (((category = 'secret'::text) = (secret_fingerprint IS NOT NULL))),
    CONSTRAINT finding_severity_check CHECK ((severity = ANY (ARRAY['CRITICAL'::text, 'HIGH'::text, 'MEDIUM'::text, 'LOW'::text, 'INFO'::text, 'UNRATED'::text]))),
    CONSTRAINT finding_status_check CHECK ((status = ANY (ARRAY['CANDIDATE'::text, 'CORROBORATED'::text, 'VERIFIED'::text, 'FALSE_POSITIVE'::text, 'ACCEPTED_RISK'::text, 'FIXED'::text, 'REGRESSED'::text])))
);


COMMENT ON TABLE aegis.finding IS 'M20 tạo; M20/M21/M24 đổi status qua finding_transition. Cột status/severity/last_seen là bộ đệm của bảng lịch sử.';


-- --- finding_run -------------------------------------------------------------

CREATE TABLE aegis.finding_run (
    finding_id uuid NOT NULL,
    scan_id uuid NOT NULL,
    seen boolean NOT NULL,
    status text NOT NULL,
    severity text NOT NULL,
    severity_reason text,
    assessment_id uuid,
    evidence_id uuid,
    observed_at timestamp with time zone NOT NULL,
    CONSTRAINT finding_run_check CHECK (((NOT seen) OR (evidence_id IS NOT NULL)))
);


COMMENT ON TABLE aegis.finding_run IS 'M20/M21. Một dòng cho mỗi finding ở mỗi lần chạy có kiểm tài sản đó (coverage), kể cả seen=false. Append-only.';


-- --- finding_source ----------------------------------------------------------

CREATE TABLE aegis.finding_source (
    finding_id uuid NOT NULL,
    scan_id uuid NOT NULL,
    provider text NOT NULL,
    provider_version text NOT NULL,
    scanner_severity text,
    candidate jsonb NOT NULL,
    evidence_ids uuid[] NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    CONSTRAINT finding_source_evidence_ids_check CHECK ((cardinality(evidence_ids) > 0))
);


COMMENT ON TABLE aegis.finding_source IS 'M20. Mỗi provider báo finding ở mỗi lần chạy; Trivy+Grype+OSV = 1 finding, 3 dòng. Append-only.';


-- --- finding_transition ------------------------------------------------------

CREATE TABLE aegis.finding_transition (
    finding_id uuid NOT NULL,
    seq integer NOT NULL,
    from_status text,
    to_status text NOT NULL,
    reason text NOT NULL,
    evidence_id uuid,
    actor jsonb NOT NULL,
    cause text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT finding_transition_cause_check CHECK ((cause = ANY (ARRAY['scan'::text, 'intel_revision'::text, 'verification'::text, 'operator'::text, 'regression_check'::text]))),
    CONSTRAINT finding_transition_check CHECK (((to_status <> ALL (ARRAY['VERIFIED'::text, 'FIXED'::text, 'REGRESSED'::text, 'CORROBORATED'::text])) OR (evidence_id IS NOT NULL)))
);


COMMENT ON TABLE aegis.finding_transition IS 'M20/M21/M24. Mọi lần chuyển trạng thái; seq = transition_seq của finding.changed.v1. Append-only.';


-- --- severity_assessment -----------------------------------------------------

CREATE TABLE aegis.severity_assessment (
    assessment_id uuid NOT NULL,
    finding_id uuid NOT NULL,
    severity text NOT NULL,
    assessment jsonb NOT NULL,
    kind text NOT NULL,
    trigger text NOT NULL,
    session_id uuid,
    model text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT severity_assessment_check CHECK (((kind <> 'agent'::text) OR ((model IS NOT NULL) AND (session_id IS NOT NULL)))),
    CONSTRAINT severity_assessment_kind_check CHECK ((kind = ANY (ARRAY['agent'::text, 'rule'::text, 'operator'::text]))),
    CONSTRAINT severity_assessment_severity_check CHECK ((severity = ANY (ARRAY['CRITICAL'::text, 'HIGH'::text, 'MEDIUM'::text, 'LOW'::text, 'INFO'::text, 'UNRATED'::text]))),
    CONSTRAINT severity_assessment_trigger_check CHECK ((trigger = ANY (ARRAY['scan'::text, 'intel_revision'::text, 'operator_request'::text, 'verification'::text])))
);


COMMENT ON TABLE aegis.severity_assessment IS 'M20. Mỗi lần agent đánh giá lại = một dòng kèm lý do. Append-only.';


-- --- hypothesis --------------------------------------------------------------

CREATE TABLE aegis.hypothesis (
    hypothesis_id uuid NOT NULL,
    campaign_id uuid NOT NULL,
    created_session uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


-- --- hypothesis_revision -----------------------------------------------------

CREATE TABLE aegis.hypothesis_revision (
    hypothesis_id uuid NOT NULL,
    revision integer NOT NULL,
    claim text NOT NULL,
    status text NOT NULL,
    confidence numeric(4,3) NOT NULL,
    subjects text[] DEFAULT '{}'::text[] NOT NULL,
    supporting text[] DEFAULT '{}'::text[] NOT NULL,
    refuting text[] DEFAULT '{}'::text[] NOT NULL,
    next_check text,
    session_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT hypothesis_revision_confidence_check CHECK (((confidence >= (0)::numeric) AND (confidence <= (1)::numeric))),
    CONSTRAINT hypothesis_revision_status_check CHECK ((status = ANY (ARRAY['OPEN'::text, 'SUPPORTED'::text, 'REFUTED'::text, 'INCONCLUSIVE'::text, 'ABANDONED'::text])))
);


COMMENT ON TABLE aegis.hypothesis_revision IS 'M03. Sổ giả thuyết; mỗi cập nhật một revision. Append-only.';


-- --- intel_snapshot ----------------------------------------------------------

CREATE TABLE aegis.intel_snapshot (
    snapshot_id uuid NOT NULL,
    feed text NOT NULL,
    version text NOT NULL,
    snapshot_at timestamp with time zone NOT NULL,
    fetched_at timestamp with time zone DEFAULT now() NOT NULL,
    record_count integer NOT NULL,
    source_uri text NOT NULL,
    content_sha256 character(64),
    CONSTRAINT intel_snapshot_feed_check CHECK ((feed = ANY (ARRAY['nvd'::text, 'osv'::text, 'kev'::text, 'epss'::text, 'ghsa'::text])))
);


COMMENT ON TABLE aegis.intel_snapshot IS 'M18. Mỗi lần đồng bộ thành công. Append-only.';


-- --- vulnerability_revision --------------------------------------------------

CREATE TABLE aegis.vulnerability_revision (
    vuln_rev_id uuid NOT NULL,
    vulnerability_id text NOT NULL,
    source text NOT NULL,
    snapshot_id uuid NOT NULL,
    aliases text[] DEFAULT '{}'::text[] NOT NULL,
    cvss jsonb,
    kev jsonb,
    epss jsonb,
    affected jsonb,
    references_ jsonb,
    published_at timestamp with time zone,
    modified_at timestamp with time zone,
    withdrawn boolean DEFAULT false NOT NULL,
    content_hash character(64) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT vulnerability_revision_source_check CHECK ((source = ANY (ARRAY['nvd'::text, 'osv'::text, 'kev'::text, 'epss'::text, 'ghsa'::text])))
);


COMMENT ON TABLE aegis.vulnerability_revision IS 'M18. Bản ghi intel có phiên bản; chỉ thêm khi nội dung đổi. Append-only.';


-- --- package_vuln_match ------------------------------------------------------

CREATE TABLE aegis.package_vuln_match (
    match_id uuid NOT NULL,
    package_asset_id uuid NOT NULL,
    vulnerability_id text NOT NULL,
    vuln_rev_id uuid NOT NULL,
    match_method text NOT NULL,
    affected_range text,
    matched boolean NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT package_vuln_match_match_method_check CHECK ((match_method = ANY (ARRAY['purl_range'::text, 'cpe_range'::text, 'scanner_direct'::text])))
);


COMMENT ON TABLE aegis.package_vuln_match IS 'M20. Ứng viên AFFECTED_BY (chưa phải finding). Append-only; trạng thái hiện tại = dòng mới nhất.';


-- --- ingestion_inbox ---------------------------------------------------------

CREATE TABLE aegis.ingestion_inbox (
    event_id uuid NOT NULL,
    dedup_key text NOT NULL,
    job_id uuid NOT NULL,
    payload_hash character(64) NOT NULL,
    status text NOT NULL,
    receipt jsonb,
    revision bigint,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    processed_at timestamp with time zone,
    hash_version text NOT NULL,
    CONSTRAINT ingestion_inbox_hash_version_check CHECK ((hash_version ~ '^aegis-c14n/[0-9]+$'::text)),
    CONSTRAINT ingestion_inbox_status_check CHECK ((status = ANY (ARRAY['received'::text, 'accepted'::text, 'partially_quarantined'::text, 'dead_letter'::text])))
);


COMMENT ON TABLE aegis.ingestion_inbox IS 'M27. One row per logical result: the first committed decision for a dedup_key. status only leaves received once; the receipt is immutable after it is set; a duplicate submission returns that receipt and writes ingestion_attempt instead.';

COMMENT ON COLUMN aegis.ingestion_inbox.payload_hash IS 'sha256 of the business content under aegis-c14n/1: ResultEnvelope minus event_id, dedup_key and trace. Execution timestamps (provenance.started_at/finished_at) are part of the hash; the collector freezes them with the snapshot so a retry hashes identically.';

COMMENT ON COLUMN aegis.ingestion_inbox.receipt IS 'First committed IngestReceipt for this dedup_key. Written once and returned verbatim (duplicate=true) to later submissions of the same payload_hash; a conflicting payload_hash changes nothing.';

COMMENT ON COLUMN aegis.ingestion_inbox.hash_version IS 'Canonicalization version that produced payload_hash (aegis-c14n/<n>). NOT NULL: an unversioned hash is never equal to a versioned one, so the column cannot be NULL.';


-- --- ingestion_attempt -------------------------------------------------------

CREATE TABLE aegis.ingestion_attempt (
    attempt_seq bigint NOT NULL,
    event_id uuid NOT NULL,
    dedup_key text NOT NULL,
    inbox_event_id uuid,
    payload_hash character(64) NOT NULL,
    hash_version text NOT NULL,
    outcome text NOT NULL,
    detail jsonb DEFAULT '{}'::jsonb NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ingestion_attempt_check CHECK (
CASE
    WHEN (outcome = 'first'::text) THEN (NOT (inbox_event_id IS DISTINCT FROM event_id))
    ELSE ((inbox_event_id IS NOT NULL) AND (inbox_event_id <> event_id))
END),
    CONSTRAINT ingestion_attempt_hash_version_check CHECK ((hash_version ~ '^aegis-c14n/[0-9]+$'::text)),
    CONSTRAINT ingestion_attempt_outcome_check CHECK ((outcome = ANY (ARRAY['first'::text, 'duplicate'::text, 'conflict'::text]))),
    CONSTRAINT ingestion_attempt_payload_hash_check CHECK ((payload_hash ~ '^[0-9a-f]{64}$'::text))
);


ALTER TABLE ONLY aegis.ingestion_attempt ALTER COLUMN attempt_seq SET DEFAULT nextval('aegis.ingestion_attempt_attempt_seq_seq'::regclass);


ALTER SEQUENCE aegis.ingestion_attempt_attempt_seq_seq OWNED BY aegis.ingestion_attempt.attempt_seq;


COMMENT ON TABLE aegis.ingestion_attempt IS 'M27. Append-only per-submission audit: every received envelope, including duplicate replays and conflicting content (409), written in the same transaction as the decision. It never overrides ingestion_inbox.';

COMMENT ON COLUMN aegis.ingestion_attempt.detail IS 'Decision context for a non-first submission, e.g. {"existing_payload_hash": "...", "reason": "hash_mismatch"|"hash_version_mismatch"}.';


-- --- consumer_inbox ----------------------------------------------------------

CREATE TABLE aegis.consumer_inbox (
    consumer text NOT NULL,
    dedup_key text NOT NULL,
    event_id uuid NOT NULL,
    processed_at timestamp with time zone DEFAULT now() NOT NULL
);


COMMENT ON TABLE aegis.consumer_inbox IS 'Khử trùng phía consumer (at-least-once). Append-only. Dựng lại Neo4j: dùng một consumer id thế hệ mới (vd ''m23-projector#g2'') để inbox khử trùng bắt đầu sạch thay vì bỏ qua sự kiện đã xử lý; dòng inbox cũ vẫn giữ. Checkpoint cursor chỉ sau khi commit Neo4j.';


-- --- consumer_cursor ---------------------------------------------------------

CREATE TABLE aegis.consumer_cursor (
    consumer text NOT NULL,
    last_seq bigint DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


COMMENT ON TABLE aegis.consumer_cursor IS 'Read position per consumer. last_seq is the highest publication sequence applied, and may only advance through aegis.consumer_advance inside the publication watermark, so a consumer can never skip data that was not published yet. Sequence gaps do not stall it.';


-- --- dead_letter -------------------------------------------------------------

CREATE TABLE aegis.dead_letter (
    dlq_id uuid NOT NULL,
    source text NOT NULL,
    event_id uuid,
    payload jsonb NOT NULL,
    error jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


COMMENT ON TABLE aegis.dead_letter IS 'M27 và mọi consumer. Append-only.';


-- --- quarantine_record -------------------------------------------------------

CREATE TABLE aegis.quarantine_record (
    quarantine_id uuid NOT NULL,
    event_id uuid NOT NULL,
    gate text NOT NULL,
    record_pointer text NOT NULL,
    record jsonb NOT NULL,
    reason text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT quarantine_record_gate_check CHECK ((gate = ANY (ARRAY['G1'::text, 'G2'::text, 'G3'::text, 'G4'::text, 'G5'::text, 'G6'::text, 'G7'::text])))
);


COMMENT ON TABLE aegis.quarantine_record IS 'M27. Bản ghi không qua cổng, giữ để xem lại (không bỏ đi). Append-only.';


-- --- quarantine_resolution ---------------------------------------------------

CREATE TABLE aegis.quarantine_resolution (
    quarantine_id uuid NOT NULL,
    resolution text NOT NULL,
    by_event_id uuid,
    actor jsonb NOT NULL,
    note text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT quarantine_resolution_resolution_check CHECK ((resolution = ANY (ARRAY['reingested'::text, 'discarded_as_invalid'::text])))
);


-- --- outbox_event ------------------------------------------------------------

CREATE TABLE aegis.outbox_event (
    seq bigint NOT NULL,
    event_id uuid NOT NULL,
    type text NOT NULL,
    producer text NOT NULL,
    dedup_key text NOT NULL,
    campaign_id uuid,
    payload jsonb NOT NULL,
    trace jsonb NOT NULL,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT outbox_event_producer_check CHECK ((producer ~ '^M[0-9]{2}$'::text)),
    CONSTRAINT outbox_event_type_check CHECK ((type = ANY (ARRAY['job.started.v1'::text, 'job.completed.v1'::text, 'policy.denied.v1'::text, 'asset.discovered.v1'::text, 'observation.changed.v1'::text, 'artifact.ready.v1'::text, 'knowledge.delta.v1'::text, 'intel.revision.v1'::text, 'finding.changed.v1'::text, 'job.started.v2'::text, 'job.completed.v2'::text, 'policy.denied.v2'::text, 'asset.discovered.v2'::text, 'observation.changed.v2'::text, 'artifact.ready.v2'::text, 'knowledge.delta.v2'::text, 'intel.revision.v2'::text, 'finding.changed.v2'::text])))
);


ALTER SEQUENCE aegis.outbox_event_seq_seq OWNED BY aegis.outbox_event.seq;


COMMENT ON TABLE aegis.outbox_event IS 'Append-only event log, written in the same transaction as the state change. seq is the publication sequence from aegis.outbox_publication (C04), not a bigserial: a writer INSERTS without seq and the allocate_seq trigger draws it under the shared publication lock, so commit order equals seq order and a rollback returns its number. Gaps stay legal (reserve() blocks, historical bigserial rows) and must never block dispatch: consumers read by aegis.outbox_batch up to the published watermark, never by waiting for a specific number, and dedup with consumer_inbox (at-least-once).';

COMMENT ON COLUMN aegis.outbox_event.seq IS 'C04 publication sequence: assigned by the allocate_seq trigger from aegis.outbox_publication inside the writer transaction while holding the publication lock; writers must not supply it. Shared with graph_revision.revision, so events and revisions have one order.';


-- --- outbox_publication ------------------------------------------------------

CREATE TABLE aegis.outbox_publication (
    id boolean DEFAULT true NOT NULL,
    next_seq bigint DEFAULT 1 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT outbox_publication_id_check CHECK (id),
    CONSTRAINT outbox_publication_next_seq_check CHECK ((next_seq >= 1))
);


-- the counter and the watermark are single-row state, created with the schema
INSERT INTO outbox_publication (id) VALUES (true);


COMMENT ON TABLE aegis.outbox_publication IS 'C04: single-row transactional counter shared by outbox_event and graph_revision, so events and revisions have one total publication order. A writer allocates inside its own transaction while holding the publication lock, so the number is committed or returned with the transaction. Event/revision rows stay append-only; this row is state and only next_seq/updated_at may change (D26).';


-- --- outbox_watermark --------------------------------------------------------

CREATE TABLE aegis.outbox_watermark (
    id boolean DEFAULT true NOT NULL,
    published_upto bigint DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT outbox_watermark_id_check CHECK (id),
    CONSTRAINT outbox_watermark_published_upto_check CHECK ((published_upto >= 0))
);


-- the counter and the watermark are single-row state, created with the schema
INSERT INTO outbox_watermark (id) VALUES (true);


COMMENT ON TABLE aegis.outbox_watermark IS 'C04/D25: publication watermark. published_upto is the highest sequence for which every earlier allocation has committed or been rolled back, proved by taking the publication lock exclusively (no writer transaction in flight). Consumers may read and checkpoint only at or below it.';


-- --- outbox_dispatcher -------------------------------------------------------

CREATE TABLE aegis.outbox_dispatcher (
    name text NOT NULL,
    fence bigint DEFAULT 0 NOT NULL,
    holder text,
    leased_until timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


COMMENT ON TABLE aegis.outbox_dispatcher IS 'C04/D25: dispatcher lease with a fencing token. Taking a lease increments fence; every dispatcher write presents its fence, so a superseded or expired holder is rejected instead of publishing or checkpointing out of order.';


-- --- report ------------------------------------------------------------------

CREATE TABLE aegis.report (
    report_id uuid NOT NULL,
    kind text NOT NULL,
    format text NOT NULL,
    params jsonb NOT NULL,
    storage_uri text NOT NULL,
    sha256 character(64) NOT NULL,
    created_by jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT report_format_check CHECK ((format = ANY (ARRAY['json'::text, 'sarif'::text, 'html'::text]))),
    CONSTRAINT report_kind_check CHECK ((kind = ANY (ARRAY['findings'::text, 'delta'::text, 'executive'::text])))
);


COMMENT ON TABLE aegis.report IS 'M24. Append-only.';


-- --- audit_log ---------------------------------------------------------------

CREATE TABLE aegis.audit_log (
    audit_id bigint NOT NULL,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    actor jsonb NOT NULL,
    action text NOT NULL,
    campaign_id uuid,
    session_id uuid,
    objective_id uuid,
    job_id uuid,
    capability_id text,
    provider_version text,
    policy_version text,
    scope_id uuid,
    evidence_id uuid,
    targets text[],
    details jsonb DEFAULT '{}'::jsonb NOT NULL,
    trace_id character(32) NOT NULL
);


ALTER TABLE ONLY aegis.audit_log ALTER COLUMN audit_id SET DEFAULT nextval('aegis.audit_log_audit_id_seq'::regclass);


ALTER SEQUENCE aegis.audit_log_audit_id_seq OWNED BY aegis.audit_log.audit_id;


COMMENT ON TABLE aegis.audit_log IS 'M25. Audit chỉ ghi thêm, không sửa, không xóa, lưu vĩnh viễn.';


-- --- alert_delivery ----------------------------------------------------------

CREATE TABLE aegis.alert_delivery (
    alert_id uuid NOT NULL,
    channel text NOT NULL,
    template_id text NOT NULL,
    destination text NOT NULL,
    dedup_key text NOT NULL,
    finding_id uuid,
    asset_id uuid,
    payload jsonb NOT NULL,
    status text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    sent_at timestamp with time zone,
    CONSTRAINT alert_delivery_channel_check CHECK ((channel = 'telegram'::text)),
    CONSTRAINT alert_delivery_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'sent'::text, 'failed'::text, 'suppressed'::text])))
);


COMMENT ON TABLE aegis.alert_delivery IS 'M24. dedup_key chống gửi trùng khi consumer chạy lại.';


-- --- alert_attempt -----------------------------------------------------------

CREATE TABLE aegis.alert_attempt (
    alert_id uuid NOT NULL,
    attempt integer NOT NULL,
    ok boolean NOT NULL,
    response jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


-- ===========================================================================
-- 5. Remaining functions (the guards and the allocation/fence primitives)
-- ===========================================================================


-- --- next_policy_version ---------------------------------------------------
-- policy_version is allocated by the database: roe-<nextval>. One caller (M01) promotes a snapshot
-- in the same transaction that inserts it, so the primary key is the last word on a collision.
CREATE FUNCTION aegis.next_policy_version() RETURNS text
    LANGUAGE sql
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
  SELECT 'roe-' || nextval('policy_version_seq');
$$;


CREATE FUNCTION aegis.consumer_advance(p_consumer text, p_upto bigint, p_dispatcher text, p_fence bigint) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
DECLARE wm bigint; v bigint;
BEGIN
  PERFORM aegis.outbox_fence_check(p_dispatcher, p_fence);
  SELECT published_upto INTO wm FROM outbox_watermark;
  IF p_upto > wm THEN
    RAISE EXCEPTION 'consumer % cannot checkpoint % past the published watermark % (D25)', p_consumer, p_upto, wm
      USING ERRCODE = 'object_not_in_prerequisite_state';
  END IF;
  INSERT INTO consumer_cursor (consumer, last_seq, updated_at) VALUES (p_consumer, p_upto, now())
  ON CONFLICT (consumer) DO UPDATE
     SET last_seq = greatest(consumer_cursor.last_seq, EXCLUDED.last_seq), updated_at = now()
  RETURNING last_seq INTO v;
  RETURN v;
END $$;


CREATE FUNCTION aegis.graph_revision_allocate_seq() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
BEGIN
  IF NEW.revision IS NOT NULL THEN
    RAISE EXCEPTION 'graph_revision.revision is assigned by aegis.outbox_publication_alloc() while the publication lock is held (C04); writers must not supply it'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  NEW.revision := aegis.outbox_publication_alloc();
  RETURN NEW;
END $$;


CREATE FUNCTION aegis.guard_campaign_v2_config() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
DECLARE
  v2 boolean;
BEGIN
  SELECT aegis.is_roe_policy_v2(p.policy) INTO v2
    FROM policy_snapshot p WHERE p.policy_version = NEW.current_policy_version;
  IF v2 IS NULL THEN
    RETURN NEW;   -- snapshot not inserted yet in this transaction: the deferred FK decides
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NOT v2 THEN
      RAISE EXCEPTION 'new campaign % must start on roe-policy.v2 configuration; % is v1',
        NEW.campaign_id, NEW.current_policy_version USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.current_policy_version IS DISTINCT FROM OLD.current_policy_version AND NOT v2 THEN
    RAISE EXCEPTION 'campaign % cannot adopt %: not roe-policy.v2 configuration',
      NEW.campaign_id, NEW.current_policy_version USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status AND NEW.status IN ('RUNNING','WAITING') AND NOT v2 THEN
    RAISE EXCEPTION 'campaign % cannot become % on v1 configuration %; adopt the v2 snapshot first',
      NEW.campaign_id, NEW.status, NEW.current_policy_version USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;


CREATE FUNCTION aegis.guard_scan_job_lifecycle() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
DECLARE terminal text[] := ARRAY['SUCCEEDED', 'FAILED', 'CANCELLED'];
BEGIN
  IF OLD.status = ANY(terminal) THEN
    IF NEW.status = ANY(terminal) THEN
      IF NEW.status <> OLD.status THEN
        RAISE EXCEPTION 'terminal result is final; % cannot become %', OLD.status, NEW.status
          USING ERRCODE = 'check_violation';
      END IF;
    ELSE
      -- Reopening is an explicit, fenced re-execution: a new generation with a clean result.
      IF NEW.generation <> OLD.generation + 1 OR NEW.attempt <> 1 OR NEW.status <> 'QUEUED'
         OR NEW.started_at IS NOT NULL OR NEW.finished_at IS NOT NULL
         OR NEW.envelope_event_id IS NOT NULL OR NEW.error IS NOT NULL
         OR NEW.cancel_requested_at IS NOT NULL THEN
        RAISE EXCEPTION 'reopening a terminal job needs generation+1, attempt=1, status QUEUED and a cleared result (started_at/finished_at/error/envelope_event_id/cancel intent)'
          USING ERRCODE = 'check_violation';
      END IF;
      RETURN NEW;
    END IF;
  ELSE
    IF NEW.generation <> OLD.generation THEN
      RAISE EXCEPTION 'generation changes only when a terminal job is reopened'
        USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.attempt NOT IN (OLD.attempt, OLD.attempt + 1) THEN
      RAISE EXCEPTION 'attempt increases by at most 1 per dispatch (% -> %)', OLD.attempt, NEW.attempt
        USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  IF OLD.cancel_requested_at IS NOT NULL THEN
    IF NEW.cancel_requested_at IS DISTINCT FROM OLD.cancel_requested_at
       OR NEW.cancel_requested_by IS DISTINCT FROM OLD.cancel_requested_by
       OR NEW.cancel_reason IS DISTINCT FROM OLD.cancel_reason THEN
      RAISE EXCEPTION 'cancel intent is written once; only a new generation clears it'
        USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  RETURN NEW;
END $$;

COMMENT ON FUNCTION aegis.guard_scan_job_lifecycle() IS 'C06: terminal results are final, reopening a terminal job needs generation+1/attempt=1/QUEUED with a cleared result, and the cancel intent is written once.';


CREATE FUNCTION aegis.is_time_window(v jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'aegis', 'pg_temp'
    AS $_$
  SELECT CASE
    WHEN v IS NULL OR jsonb_typeof(v) <> 'object' THEN false
    WHEN EXISTS (SELECT 1 FROM jsonb_object_keys(v) k
                  WHERE k NOT IN ('days','start','end','timezone')) THEN false
    WHEN NOT (v ? 'days' AND v ? 'start' AND v ? 'end' AND v ? 'timezone') THEN false
    WHEN NOT aegis.is_json_strings(v->'days', NULL, NULL, 1) THEN false
    WHEN jsonb_array_length(v->'days') = 0 THEN false
    WHEN EXISTS (SELECT 1 FROM jsonb_array_elements(v->'days') e
                  WHERE (e #>> '{}') NOT IN ('mon','tue','wed','thu','fri','sat','sun')) THEN false
    WHEN coalesce(v->>'start','') !~ '^([01][0-9]|2[0-3]):[0-5][0-9]$' THEN false
    WHEN coalesce(v->>'end','')  !~ '^(([01][0-9]|2[0-3]):[0-5][0-9]|24:00)$' THEN false
    WHEN length(coalesce(v->>'timezone','')) NOT BETWEEN 1 AND 255 THEN false
    ELSE true
  END
$_$;


CREATE FUNCTION aegis.is_time_windows(v jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
  SELECT v IS NOT NULL
     AND jsonb_typeof(v) = 'array'
     AND jsonb_array_length(v) <= 50
     AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(v) e WHERE NOT aegis.is_time_window(e));
$$;


CREATE FUNCTION aegis.keep_asset_normalization_version() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
BEGIN
  IF NEW.normalization_version IS DISTINCT FROM OLD.normalization_version THEN
    RAISE EXCEPTION 'asset.normalization_version is written once; a new aegis-norm/<n> needs a re-key migration, not an UPDATE'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$;

COMMENT ON FUNCTION aegis.keep_asset_normalization_version() IS 'normalization_version is immutable; re-labelling a stored key would claim a rules version it was not minted with.';


SET default_tablespace = '';

SET default_table_access_method = heap;


CREATE FUNCTION aegis.outbox_batch(p_consumer text, p_limit integer DEFAULT 100) RETURNS TABLE(seq bigint, event_id uuid, type text, producer text, dedup_key text, campaign_id uuid, payload jsonb, trace jsonb, occurred_at timestamp with time zone)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
DECLARE wm bigint; cur bigint;
BEGIN
  SELECT published_upto INTO wm FROM outbox_watermark;
  SELECT last_seq INTO cur FROM consumer_cursor WHERE consumer = p_consumer;
  RETURN QUERY
    SELECT e.seq, e.event_id, e.type, e.producer, e.dedup_key, e.campaign_id, e.payload, e.trace, e.occurred_at
      FROM outbox_event e
     WHERE e.seq > coalesce(cur, 0) AND e.seq <= wm
     ORDER BY e.seq
     LIMIT greatest(coalesce(p_limit, 100), 0);
END $$;


CREATE FUNCTION aegis.outbox_dispatch_lease(p_dispatcher text, p_holder text, p_ttl_seconds integer DEFAULT 15) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
DECLARE v bigint;
BEGIN
  INSERT INTO outbox_dispatcher (name) VALUES (p_dispatcher) ON CONFLICT (name) DO NOTHING;
  UPDATE outbox_dispatcher
     SET fence = fence + 1, holder = p_holder,
         leased_until = now() + make_interval(secs => greatest(coalesce(p_ttl_seconds, 15), 1)),
         updated_at = now()
   WHERE name = p_dispatcher
     AND (holder = p_holder OR leased_until IS NULL OR leased_until <= now())
  RETURNING fence INTO v;
  RETURN v;   -- NULL = another holder owns a live lease; the caller must not dispatch
END $$;


CREATE FUNCTION aegis.outbox_event_allocate_seq() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
BEGIN
  IF NEW.seq IS NOT NULL THEN
    RAISE EXCEPTION 'outbox_event.seq is assigned by aegis.outbox_publication_alloc() while the publication lock is held (C04); writers must not supply it'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  NEW.seq := aegis.outbox_publication_alloc();
  RETURN NEW;
END $$;


CREATE FUNCTION aegis.outbox_fence_check(p_dispatcher text, p_fence bigint) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
BEGIN
  IF p_fence IS NULL OR NOT EXISTS (
    SELECT 1 FROM outbox_dispatcher
     WHERE name = p_dispatcher AND fence = p_fence AND leased_until > now()) THEN
    RAISE EXCEPTION 'dispatcher % fence % is stale, expired or unknown; it must not publish or checkpoint', p_dispatcher, p_fence
      USING ERRCODE = 'object_not_in_prerequisite_state';
  END IF;
END $$;


CREATE FUNCTION aegis.outbox_publication_alloc() RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
DECLARE v bigint;
BEGIN
  PERFORM pg_advisory_xact_lock_shared(aegis.outbox_publication_lock_key());
  UPDATE outbox_publication SET next_seq = next_seq + 1, updated_at = now()
   WHERE id RETURNING next_seq - 1 INTO v;
  IF v IS NULL THEN RAISE EXCEPTION 'outbox_publication single row is missing'; END IF;
  RETURN v;
END $$;

COMMENT ON FUNCTION aegis.outbox_publication_alloc() IS 'C04: take the publication lock (shared, held until commit/rollback), take the next publication sequence. Called by the INSERT triggers of outbox_event/graph_revision; short transactions only, no network/LLM work inside the lock. SECURITY DEFINER so writers need no privilege on outbox_publication.';


CREATE FUNCTION aegis.outbox_publication_reserve(p_count bigint) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
DECLARE v bigint;
BEGIN
  IF p_count IS NULL OR p_count < 1 OR p_count > 10000 THEN
    RAISE EXCEPTION 'reserve count must be between 1 and 10000, got %', p_count USING ERRCODE = 'invalid_parameter_value';
  END IF;
  PERFORM pg_advisory_xact_lock_shared(aegis.outbox_publication_lock_key());
  UPDATE outbox_publication SET next_seq = next_seq + p_count, updated_at = now()
   WHERE id RETURNING next_seq - p_count INTO v;
  IF v IS NULL THEN RAISE EXCEPTION 'outbox_publication single row is missing'; END IF;
  RETURN v;
END $$;


CREATE FUNCTION aegis.outbox_watermark_refresh(p_dispatcher text, p_fence bigint) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
DECLARE
  v bigint;
  bound text;
BEGIN
  PERFORM aegis.outbox_fence_check(p_dispatcher, p_fence);
  bound := coalesce(nullif(current_setting('aegis.outbox_watermark_lock_timeout', true), ''), '5s');
  IF bound::interval <= interval '0' THEN
    RAISE EXCEPTION 'aegis.outbox_watermark_lock_timeout must be a positive interval, got %', bound
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  PERFORM set_config('lock_timeout', bound, true);
  BEGIN
    PERFORM pg_advisory_xact_lock(aegis.outbox_publication_lock_key());
  EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'watermark refresh for dispatcher % could not acquire the publication lock within % (writers active); retry on a fresh transaction', p_dispatcher, bound
      USING ERRCODE = 'lock_not_available';
  END;
  UPDATE outbox_watermark
     SET published_upto = greatest(published_upto, (SELECT next_seq - 1 FROM outbox_publication)),
         updated_at = now()
   WHERE id;
  SELECT published_upto INTO v FROM outbox_watermark;
  RETURN v;
END $$;


CREATE FUNCTION aegis.receipt_once() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
BEGIN
  IF NEW.receipt IS NOT NULL THEN
    IF NEW.receipt->>'event_id' IS DISTINCT FROM NEW.event_id::text
       OR NEW.receipt->>'payload_hash' IS DISTINCT FROM NEW.payload_hash
       OR NEW.receipt->>'hash_version' IS DISTINCT FROM NEW.hash_version THEN
      RAISE EXCEPTION 'receipt must describe its own inbox row (event_id, payload_hash, hash_version)'
        USING ERRCODE = 'check_violation';
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.receipt IS NOT NULL AND NEW.receipt IS DISTINCT FROM OLD.receipt THEN
      RAISE EXCEPTION 'accepted receipt is immutable; a duplicate submission returns the first committed receipt'
        USING ERRCODE = 'insufficient_privilege';
    END IF;
  END IF;
  RETURN NEW;
END $$;


CREATE FUNCTION aegis.record_job_callback(p_job_id uuid, p_generation integer, p_attempt integer, p_status text, p_envelope_event_id uuid DEFAULT NULL::uuid, p_error jsonb DEFAULT NULL::jsonb, p_payload_hash character DEFAULT NULL::bpchar, p_claimed jsonb DEFAULT '{}'::jsonb, p_evidence_refs jsonb DEFAULT '[]'::jsonb, p_quarantine_id uuid DEFAULT NULL::uuid) RETURNS text
    LANGUAGE plpgsql
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
DECLARE
  j scan_job;
  v_reason text;
  v_next_seq integer;
BEGIN
  IF p_status NOT IN ('SUCCEEDED', 'FAILED', 'CANCELLED') THEN
    RAISE EXCEPTION 'record_job_callback records a terminal result, got %', p_status
      USING ERRCODE = 'check_violation';
  END IF;
  SELECT * INTO j FROM scan_job WHERE job_id = p_job_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'job % not found', p_job_id USING ERRCODE = 'no_data_found';
  END IF;

  IF p_generation < j.generation THEN
    v_reason := 'stale_generation';
  ELSIF p_attempt < j.attempt THEN
    v_reason := 'stale_attempt';
  ELSIF p_attempt > j.attempt THEN
    v_reason := 'attempt_not_started';
  ELSIF j.status IN ('SUCCEEDED', 'FAILED', 'CANCELLED') THEN
    IF j.status = p_status AND j.envelope_event_id IS NOT DISTINCT FROM p_envelope_event_id THEN
      RETURN 'duplicate';  -- idempotent replay of the exact result that is already recorded
    END IF;
    v_reason := 'terminal_already_recorded';
  ELSIF j.status IN ('QUEUED', 'VALIDATING') AND p_status <> 'CANCELLED' THEN
    v_reason := 'attempt_not_started';
  ELSIF p_status = 'CANCELLED' AND j.cancel_requested_at IS NULL THEN
    v_reason := 'cancel_not_requested';
  END IF;

  IF v_reason IS NOT NULL THEN
    INSERT INTO job_callback_quarantine
      (quarantine_id, job_id, generation, attempt, callback, reason, claimed, payload_hash, evidence_refs)
    VALUES (coalesce(p_quarantine_id, gen_random_uuid()), p_job_id, p_generation, p_attempt,
            'completed', v_reason, p_claimed, p_payload_hash, p_evidence_refs)
    ON CONFLICT (job_id, generation, attempt, callback, reason) DO NOTHING;
    RETURN 'quarantined';
  END IF;

  UPDATE scan_job
     SET status = p_status, finished_at = now(), envelope_event_id = p_envelope_event_id, error = p_error
   WHERE job_id = p_job_id AND status = j.status AND generation = p_generation AND attempt = p_attempt;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'terminal CAS lost for job % on generation % attempt %', p_job_id, p_generation, p_attempt
      USING ERRCODE = 'serialization_failure';
  END IF;
  SELECT coalesce(max(seq), 0) + 1 INTO v_next_seq FROM job_status_change WHERE job_id = p_job_id;
  INSERT INTO job_status_change (job_id, seq, from_status, to_status, error)
    VALUES (p_job_id, v_next_seq, j.status, p_status, p_error);
  RETURN 'terminalized';
END $$;


CREATE FUNCTION aegis.record_job_lifecycle() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
DECLARE next_seq integer;
BEGIN
  IF NEW.attempt IS NOT DISTINCT FROM OLD.attempt
     AND NEW.generation IS NOT DISTINCT FROM OLD.generation
     AND NEW.cancel_requested_at IS NOT DISTINCT FROM OLD.cancel_requested_at
     AND NEW.cancel_requested_by IS NOT DISTINCT FROM OLD.cancel_requested_by
     AND NEW.cancel_reason IS NOT DISTINCT FROM OLD.cancel_reason
     AND NEW.wait_reason IS NOT DISTINCT FROM OLD.wait_reason THEN
    RETURN NULL;
  END IF;
  SELECT coalesce(max(seq), 0) INTO next_seq FROM job_lifecycle_change WHERE job_id = NEW.job_id;
  IF NEW.attempt IS DISTINCT FROM OLD.attempt THEN
    next_seq := next_seq + 1;
    INSERT INTO job_lifecycle_change (job_id, seq, field, old_value, new_value)
      VALUES (NEW.job_id, next_seq, 'attempt', to_jsonb(OLD.attempt), to_jsonb(NEW.attempt));
  END IF;
  IF NEW.generation IS DISTINCT FROM OLD.generation THEN
    next_seq := next_seq + 1;
    INSERT INTO job_lifecycle_change (job_id, seq, field, old_value, new_value)
      VALUES (NEW.job_id, next_seq, 'generation', to_jsonb(OLD.generation), to_jsonb(NEW.generation));
  END IF;
  IF (NEW.cancel_requested_at, NEW.cancel_requested_by, NEW.cancel_reason)
       IS DISTINCT FROM (OLD.cancel_requested_at, OLD.cancel_requested_by, OLD.cancel_reason) THEN
    next_seq := next_seq + 1;
    INSERT INTO job_lifecycle_change (job_id, seq, field, old_value, new_value)
      VALUES (NEW.job_id, next_seq, 'cancel_request',
              jsonb_build_object('requested_at', OLD.cancel_requested_at,
                                 'requested_by', OLD.cancel_requested_by,
                                 'reason', OLD.cancel_reason),
              jsonb_build_object('requested_at', NEW.cancel_requested_at,
                                 'requested_by', NEW.cancel_requested_by,
                                 'reason', NEW.cancel_reason));
  END IF;
  IF NEW.wait_reason IS DISTINCT FROM OLD.wait_reason THEN
    next_seq := next_seq + 1;
    INSERT INTO job_lifecycle_change (job_id, seq, field, old_value, new_value)
      VALUES (NEW.job_id, next_seq, 'wait_reason', OLD.wait_reason, NEW.wait_reason);
  END IF;
  RETURN NULL;
END $$;


CREATE FUNCTION aegis.relationship_close_only() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
BEGIN
  IF OLD.valid_to IS NOT NULL
     OR NEW.valid_to IS NULL
     OR NEW.valid_to < OLD.valid_from
     OR (to_jsonb(NEW) - 'valid_to' - 'closed_by_job_id') IS DISTINCT FROM (to_jsonb(OLD) - 'valid_to' - 'closed_by_job_id') THEN
    RAISE EXCEPTION 'relationship chỉ được đóng khoảng hiệu lực một lần (valid_to NULL -> giá trị)'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$;


CREATE FUNCTION aegis.request_job_cancel(p_job_id uuid, p_actor jsonb, p_reason text DEFAULT NULL::text) RETURNS text
    LANGUAGE plpgsql
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
DECLARE j scan_job;
BEGIN
  IF NOT aegis.is_actor(p_actor) THEN
    RAISE EXCEPTION 'cancel actor must be an Actor {kind: operator|module|agent, id}'
      USING ERRCODE = 'check_violation';
  END IF;
  SELECT * INTO j FROM scan_job WHERE job_id = p_job_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'job % not found', p_job_id USING ERRCODE = 'no_data_found';
  END IF;
  IF p_actor->>'kind' = 'agent'
     AND (j.proposed_by IS NULL OR j.proposed_by->>'id' <> p_actor->>'id') THEN
    RAISE EXCEPTION 'an agent may only cancel a job it proposed (proposer %)', j.proposed_by
      USING ERRCODE = 'check_violation';
  END IF;
  IF j.status IN ('SUCCEEDED', 'FAILED', 'CANCELLED') THEN
    RETURN 'terminal';
  END IF;
  IF j.cancel_requested_at IS NOT NULL THEN
    RETURN 'already_requested';
  END IF;
  UPDATE scan_job
     SET cancel_requested_at = now(), cancel_requested_by = p_actor, cancel_reason = p_reason
   WHERE job_id = p_job_id;
  RETURN 'requested';
END $$;


CREATE FUNCTION aegis.require_cancel_actor() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
BEGIN
  IF NEW.cancel_requested_by IS NULL THEN
    RETURN NEW;   -- a reopen clears the intent (C06); there is no actor to validate
  END IF;
  IF NEW.cancel_requested_by IS NOT DISTINCT FROM OLD.cancel_requested_by THEN
    RETURN NEW;   -- not this statement's change
  END IF;
  IF NOT aegis.is_actor(NEW.cancel_requested_by) THEN
    RAISE EXCEPTION 'cancel_requested_by must be an Actor {kind: operator|module|agent, id}'
      USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.cancel_requested_by->>'kind' = 'agent'
     AND (NEW.proposed_by IS NULL OR NEW.proposed_by->>'id' <> NEW.cancel_requested_by->>'id') THEN
    RAISE EXCEPTION 'an agent may only cancel a job it proposed (proposer %)', NEW.proposed_by
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

COMMENT ON FUNCTION aegis.require_cancel_actor() IS 'OI-9/R-1: the cancel intent names a shape-checked Actor and an agent cannot cancel work it did not propose. Clearing the intent (reopen) is always allowed; the rule applies when it is set.';


CREATE FUNCTION aegis.require_canonical_projection() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
BEGIN
  IF NEW.target_refs IS NOT NULL
     AND NOT aegis.is_canonical_projection(NEW.targets, NEW.target_refs) THEN
    RAISE EXCEPTION '% targets % contains a key that no TargetRef in target_refs resolves',
      TG_TABLE_NAME, NEW.targets
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

COMMENT ON FUNCTION aegis.require_canonical_projection() IS 'OI-6/R-2b: `targets` may only project canonical_key entries of `target_refs` (it is never the identity source). Enforced on INSERT only, so a row that predates the rule keeps working.';


CREATE FUNCTION aegis.require_decision_proposer_session() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
BEGIN
  IF NEW.proposed_by IS NULL THEN
    RETURN NEW;
  END IF;
  IF NOT aegis.is_proposer(NEW.proposed_by) THEN
    RAISE EXCEPTION 'proposed_by must be {kind: agent, id: <session_id>}; a label is not a session'
      USING ERRCODE = 'check_violation';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM agent_session s
                  WHERE s.session_id = (NEW.proposed_by->>'id')::uuid
                    AND s.campaign_id = NEW.campaign_id) THEN
    RAISE EXCEPTION 'proposed_by names session % which is not an agent_session of campaign %',
      NEW.proposed_by->>'id', NEW.campaign_id
      USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.session_id IS DISTINCT FROM (NEW.proposed_by->>'id')::uuid THEN
    RAISE EXCEPTION 'policy_decision.session_id (%) must be the proposing session (proposed_by.id %)',
      NEW.session_id, NEW.proposed_by->>'id'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

COMMENT ON FUNCTION aegis.require_decision_proposer_session() IS 'C05/OI-8: the decision proposer is an agent_session of the same campaign, and session_id is that session (one session per proposal, not two).';


CREATE FUNCTION aegis.require_decision_target_refs() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
DECLARE foreign_seed uuid;
BEGIN
  IF jsonb_typeof(NEW.target_refs) = 'array' THEN
    SELECT (e->>'seed_id')::uuid INTO foreign_seed
      FROM jsonb_array_elements(NEW.target_refs) AS e
     WHERE aegis.is_target_ref(e) AND e ? 'seed_id'
       AND NOT EXISTS (
         SELECT 1
           FROM campaign_target ct
           JOIN campaign c ON c.campaign_id = NEW.campaign_id
          WHERE ct.target_id = (e->>'seed_id')::uuid
            AND ct.scope_id = NEW.scope_id
            AND c.scope_id = ct.scope_id)
     LIMIT 1;
    IF foreign_seed IS NOT NULL THEN
      RAISE EXCEPTION 'decision seed % is not a campaign_target of campaign % (scope %)',
        foreign_seed, NEW.campaign_id, NEW.scope_id
        USING ERRCODE = 'foreign_key_violation';
    END IF;
  END IF;
  RETURN NEW;
END $$;

COMMENT ON FUNCTION aegis.require_decision_target_refs() IS 'OI-6: the seed a job will inherit is checked before the job exists.';


CREATE FUNCTION aegis.require_job_decision_consistency() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
DECLARE d policy_decision;
BEGIN
  SELECT * INTO d FROM policy_decision WHERE decision_id = NEW.decision_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'job % references unknown policy_decision %', NEW.job_id, NEW.decision_id
      USING ERRCODE = 'check_violation';
  END IF;
  IF d.campaign_id <> NEW.campaign_id THEN
    RAISE EXCEPTION 'job % is in campaign % but its decision % belongs to campaign %',
      NEW.job_id, NEW.campaign_id, NEW.decision_id, d.campaign_id
      USING ERRCODE = 'check_violation';
  END IF;
  IF d.requested_by IS DISTINCT FROM NEW.requested_by THEN
    RAISE EXCEPTION 'job % requested_by (%) differs from its decision (%)',
      NEW.job_id, NEW.requested_by, d.requested_by
      USING ERRCODE = 'check_violation';
  END IF;
  IF d.proposed_by IS DISTINCT FROM NEW.proposed_by THEN
    RAISE EXCEPTION 'job % proposed_by (%) differs from its decision (%)',
      NEW.job_id, NEW.proposed_by, d.proposed_by
      USING ERRCODE = 'check_violation';
  END IF;
  IF d.target_refs IS NOT NULL AND d.target_refs IS DISTINCT FROM NEW.target_refs THEN
    RAISE EXCEPTION 'job % target_refs differ from the targets its decision resolved (% vs %)',
      NEW.job_id, NEW.target_refs, d.target_refs
      USING ERRCODE = 'check_violation';
  END IF;
  IF d.capability IS DISTINCT FROM NEW.capability THEN
    RAISE EXCEPTION 'job % capability % differs from its decision %',
      NEW.job_id, NEW.capability, d.capability USING ERRCODE = 'check_violation';
  END IF;
  IF d.provider IS DISTINCT FROM NEW.provider THEN
    RAISE EXCEPTION 'job % provider % differs from its decision %',
      NEW.job_id, NEW.provider, d.provider USING ERRCODE = 'check_violation';
  END IF;
  IF d.policy_version IS DISTINCT FROM NEW.policy_version THEN
    RAISE EXCEPTION 'job % policy_version % differs from its decision %',
      NEW.job_id, NEW.policy_version, d.policy_version USING ERRCODE = 'check_violation';
  END IF;
  IF d.scope_id IS DISTINCT FROM NEW.scope_id THEN
    RAISE EXCEPTION 'job % scope_id % differs from its decision %',
      NEW.job_id, NEW.scope_id, d.scope_id USING ERRCODE = 'check_violation';
  END IF;
  IF d.input IS DISTINCT FROM NEW.input THEN
    RAISE EXCEPTION 'job % input differs from the input its decision approved (% vs %)',
      NEW.job_id, NEW.input, d.input USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

COMMENT ON FUNCTION aegis.require_job_decision_consistency() IS 'C05/OI-8/R-3: one decision, one job: same campaign, actors, resolved target_refs and the executed fields (capability, provider, policy_version, scope_id, input). M05 derives both from the same decision, so a difference is a bug or a forged job.';


CREATE FUNCTION aegis.require_job_initiator() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
BEGIN
  IF NOT aegis.is_initiator(NEW.requested_by) THEN
    RAISE EXCEPTION 'new row requires a server-derived initiator in requested_by (kind operator|module, opaque id); an agent or a self-declared label cannot start a job'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

COMMENT ON FUNCTION aegis.require_job_initiator() IS 'C05: M05 writes requested_by from its own verified principal, and the database refuses any other shape on INSERT, so an agent or a self-declared label can never start a job.';


CREATE FUNCTION aegis.require_job_proposer_session() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
BEGIN
  IF NEW.proposed_by IS NULL THEN
    RETURN NEW;
  END IF;
  IF NOT aegis.is_proposer(NEW.proposed_by) THEN
    RAISE EXCEPTION 'proposed_by must be {kind: agent, id: <session_id>}; a label is not a session'
      USING ERRCODE = 'check_violation';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM agent_session s
                  WHERE s.session_id = (NEW.proposed_by->>'id')::uuid
                    AND s.campaign_id = NEW.campaign_id) THEN
    RAISE EXCEPTION 'proposed_by names session % which is not an agent_session of campaign %',
      NEW.proposed_by->>'id', NEW.campaign_id
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

COMMENT ON FUNCTION aegis.require_job_proposer_session() IS 'C05/OI-8: a proposer is a real agent session of the same campaign; a label or a session from another campaign is refused.';


CREATE FUNCTION aegis.require_job_target_refs() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
DECLARE foreign_seed uuid;
BEGIN
  IF jsonb_typeof(NEW.target_refs) = 'array' THEN
    SELECT (e->>'seed_id')::uuid INTO foreign_seed
      FROM jsonb_array_elements(NEW.target_refs) AS e
     WHERE aegis.is_target_ref(e) AND e ? 'seed_id'
       AND NOT EXISTS (
         SELECT 1
           FROM campaign_target ct
           JOIN campaign c ON c.campaign_id = NEW.campaign_id
          WHERE ct.target_id = (e->>'seed_id')::uuid
            AND ct.scope_id = NEW.scope_id
            AND c.scope_id = ct.scope_id)
     LIMIT 1;
    IF foreign_seed IS NOT NULL THEN
      RAISE EXCEPTION 'target seed % is not a campaign_target of campaign % (scope %)',
        foreign_seed, NEW.campaign_id, NEW.scope_id
        USING ERRCODE = 'foreign_key_violation';
    END IF;
  END IF;
  RETURN NEW;
END $$;


CREATE FUNCTION aegis.require_job_v2_policy() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
BEGIN
  IF NOT coalesce((SELECT aegis.is_roe_policy_v2(p.policy) FROM policy_snapshot p
                    WHERE p.policy_version = NEW.policy_version), false) THEN
    RAISE EXCEPTION 'new job % must run on roe-policy.v2 configuration; policy_snapshot % is v1',
      NEW.job_id, NEW.policy_version USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;


CREATE FUNCTION aegis.require_provenance_seed() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
BEGIN
  IF NEW.from_target_id IS NOT NULL
     AND NOT EXISTS (
       SELECT 1
         FROM campaign_target ct
         JOIN campaign c ON c.campaign_id = NEW.campaign_id
        WHERE ct.target_id = NEW.from_target_id
          AND c.scope_id = ct.scope_id)
  THEN
    RAISE EXCEPTION 'provenance seed % is not a campaign_target of campaign %',
      NEW.from_target_id, NEW.campaign_id
      USING ERRCODE = 'foreign_key_violation';
  END IF;
  RETURN NEW;
END $$;


CREATE FUNCTION aegis.require_v2_policy_snapshot() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'aegis', 'pg_temp'
    AS $$
BEGIN
  IF NOT aegis.is_roe_policy_v2(NEW.policy) THEN
    RAISE EXCEPTION 'new policy_snapshot % must be roe-policy.v2 configuration (no RoE time windows)',
      NEW.policy_version USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;


COMMENT ON FUNCTION aegis.next_policy_version() IS 'Next free roe-<n> for a new snapshot. A concurrent writer that skips it still loses on the primary key, never on a reused version.';


-- ===========================================================================
-- 6. Keys
-- ===========================================================================


ALTER TABLE ONLY aegis.agent_session
    ADD CONSTRAINT agent_session_pkey PRIMARY KEY (session_id);


ALTER TABLE ONLY aegis.alert_attempt
    ADD CONSTRAINT alert_attempt_pkey PRIMARY KEY (alert_id, attempt);


ALTER TABLE ONLY aegis.alert_delivery
    ADD CONSTRAINT alert_delivery_dedup_key_key UNIQUE (dedup_key);


ALTER TABLE ONLY aegis.alert_delivery
    ADD CONSTRAINT alert_delivery_pkey PRIMARY KEY (alert_id);


ALTER TABLE ONLY aegis.artifact
    ADD CONSTRAINT artifact_digest_key UNIQUE (digest);


ALTER TABLE ONLY aegis.artifact
    ADD CONSTRAINT artifact_pkey PRIMARY KEY (artifact_id);


ALTER TABLE ONLY aegis.asset
    ADD CONSTRAINT asset_canonical_key_key UNIQUE (canonical_key);


ALTER TABLE ONLY aegis.asset
    ADD CONSTRAINT asset_pkey PRIMARY KEY (asset_id);


ALTER TABLE ONLY aegis.asset_alias
    ADD CONSTRAINT asset_alias_asset_id_namespace_alias_value_observed_at_key UNIQUE (asset_id, namespace, alias_value, observed_at);


ALTER TABLE ONLY aegis.asset_alias
    ADD CONSTRAINT asset_alias_pkey PRIMARY KEY (alias_id);


ALTER TABLE ONLY aegis.asset_annotation
    ADD CONSTRAINT asset_annotation_pkey PRIMARY KEY (asset_id, seq);


ALTER TABLE ONLY aegis.asset_campaign
    ADD CONSTRAINT asset_campaign_pkey PRIMARY KEY (asset_id, campaign_id);


ALTER TABLE ONLY aegis.asset_package
    ADD CONSTRAINT asset_package_pkey PRIMARY KEY (asset_id);


ALTER TABLE ONLY aegis.asset_package
    ADD CONSTRAINT asset_package_purl_key UNIQUE (purl);


ALTER TABLE ONLY aegis.asset_provenance
    ADD CONSTRAINT asset_provenance_pkey PRIMARY KEY (provenance_id);


ALTER TABLE ONLY aegis.asset_service
    ADD CONSTRAINT asset_service_ip_port_transport_key UNIQUE (ip, port, transport);


ALTER TABLE ONLY aegis.asset_service
    ADD CONSTRAINT asset_service_pkey PRIMARY KEY (asset_id);


ALTER TABLE ONLY aegis.asset_url
    ADD CONSTRAINT asset_url_pkey PRIMARY KEY (asset_id);


ALTER TABLE ONLY aegis.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (audit_id);


ALTER TABLE ONLY aegis.campaign
    ADD CONSTRAINT campaign_pkey PRIMARY KEY (campaign_id);


ALTER TABLE ONLY aegis.campaign_ledger
    ADD CONSTRAINT campaign_ledger_pkey PRIMARY KEY (campaign_id, seq);


ALTER TABLE ONLY aegis.campaign_status_change
    ADD CONSTRAINT campaign_status_change_pkey PRIMARY KEY (campaign_id, seq);


ALTER TABLE ONLY aegis.campaign_target
    ADD CONSTRAINT campaign_target_pkey PRIMARY KEY (target_id);


ALTER TABLE ONLY aegis.campaign_target
    ADD CONSTRAINT campaign_target_scope_id_kind_raw_value_key UNIQUE (scope_id, kind, raw_value);


ALTER TABLE ONLY aegis.consumer_cursor
    ADD CONSTRAINT consumer_cursor_pkey PRIMARY KEY (consumer);


ALTER TABLE ONLY aegis.consumer_inbox
    ADD CONSTRAINT consumer_inbox_pkey PRIMARY KEY (consumer, dedup_key);


ALTER TABLE ONLY aegis.dead_letter
    ADD CONSTRAINT dead_letter_pkey PRIMARY KEY (dlq_id);


ALTER TABLE ONLY aegis.evidence
    ADD CONSTRAINT evidence_job_id_sha256_key UNIQUE (job_id, sha256);


ALTER TABLE ONLY aegis.evidence
    ADD CONSTRAINT evidence_pkey PRIMARY KEY (evidence_id);


ALTER TABLE ONLY aegis.evidence
    ADD CONSTRAINT evidence_storage_uri_key UNIQUE (storage_uri);


ALTER TABLE ONLY aegis.evidence_check
    ADD CONSTRAINT evidence_check_pkey PRIMARY KEY (evidence_id, checked_at);


ALTER TABLE ONLY aegis.finding
    ADD CONSTRAINT finding_fingerprint_key UNIQUE (fingerprint);


ALTER TABLE ONLY aegis.finding
    ADD CONSTRAINT finding_pkey PRIMARY KEY (finding_id);


ALTER TABLE ONLY aegis.finding_run
    ADD CONSTRAINT finding_run_pkey PRIMARY KEY (finding_id, scan_id);


ALTER TABLE ONLY aegis.finding_source
    ADD CONSTRAINT finding_source_pkey PRIMARY KEY (finding_id, scan_id, provider);


ALTER TABLE ONLY aegis.finding_transition
    ADD CONSTRAINT finding_transition_pkey PRIMARY KEY (finding_id, seq);


ALTER TABLE ONLY aegis.graph_revision
    ADD CONSTRAINT graph_revision_pkey PRIMARY KEY (revision);


ALTER TABLE ONLY aegis.hypothesis
    ADD CONSTRAINT hypothesis_pkey PRIMARY KEY (hypothesis_id);


ALTER TABLE ONLY aegis.hypothesis_revision
    ADD CONSTRAINT hypothesis_revision_pkey PRIMARY KEY (hypothesis_id, revision);


ALTER TABLE ONLY aegis.idempotency_record
    ADD CONSTRAINT idempotency_record_pkey PRIMARY KEY (scope, key);


ALTER TABLE ONLY aegis.ingestion_attempt
    ADD CONSTRAINT ingestion_attempt_event_id_key UNIQUE (event_id);


ALTER TABLE ONLY aegis.ingestion_attempt
    ADD CONSTRAINT ingestion_attempt_pkey PRIMARY KEY (attempt_seq);


ALTER TABLE ONLY aegis.ingestion_inbox
    ADD CONSTRAINT ingestion_inbox_dedup_key_key UNIQUE (dedup_key);


ALTER TABLE ONLY aegis.ingestion_inbox
    ADD CONSTRAINT ingestion_inbox_pkey PRIMARY KEY (event_id);


ALTER TABLE ONLY aegis.intel_snapshot
    ADD CONSTRAINT intel_snapshot_feed_version_key UNIQUE (feed, version);


ALTER TABLE ONLY aegis.intel_snapshot
    ADD CONSTRAINT intel_snapshot_pkey PRIMARY KEY (snapshot_id);


ALTER TABLE ONLY aegis.job_callback_quarantine
    ADD CONSTRAINT job_callback_quarantine_job_id_generation_attempt_callback__key UNIQUE (job_id, generation, attempt, callback, reason);


ALTER TABLE ONLY aegis.job_callback_quarantine
    ADD CONSTRAINT job_callback_quarantine_pkey PRIMARY KEY (quarantine_id);


ALTER TABLE ONLY aegis.job_dependency
    ADD CONSTRAINT job_dependency_pkey PRIMARY KEY (job_id, depends_on_job_id);


ALTER TABLE ONLY aegis.job_lifecycle_change
    ADD CONSTRAINT job_lifecycle_change_pkey PRIMARY KEY (job_id, seq);


ALTER TABLE ONLY aegis.job_status_change
    ADD CONSTRAINT job_status_change_pkey PRIMARY KEY (job_id, seq);


ALTER TABLE ONLY aegis.model_usage
    ADD CONSTRAINT model_usage_pkey PRIMARY KEY (usage_id);


ALTER TABLE ONLY aegis.objective
    ADD CONSTRAINT objective_pkey PRIMARY KEY (objective_id);


ALTER TABLE ONLY aegis.observation
    ADD CONSTRAINT observation_envelope_event_id_subject_asset_id_predicate_va_key UNIQUE (envelope_event_id, subject_asset_id, predicate, value_hash, observed_at);


ALTER TABLE ONLY aegis.observation
    ADD CONSTRAINT observation_pkey PRIMARY KEY (observation_id);


ALTER TABLE ONLY aegis.outbox_dispatcher
    ADD CONSTRAINT outbox_dispatcher_pkey PRIMARY KEY (name);


ALTER TABLE ONLY aegis.outbox_event
    ADD CONSTRAINT outbox_event_event_id_key UNIQUE (event_id);


ALTER TABLE ONLY aegis.outbox_event
    ADD CONSTRAINT outbox_event_pkey PRIMARY KEY (seq);


ALTER TABLE ONLY aegis.outbox_event
    ADD CONSTRAINT outbox_event_type_dedup_key_key UNIQUE (type, dedup_key);


ALTER TABLE ONLY aegis.outbox_publication
    ADD CONSTRAINT outbox_publication_pkey PRIMARY KEY (id);


ALTER TABLE ONLY aegis.outbox_watermark
    ADD CONSTRAINT outbox_watermark_pkey PRIMARY KEY (id);


ALTER TABLE ONLY aegis.package_vuln_match
    ADD CONSTRAINT package_vuln_match_pkey PRIMARY KEY (match_id);


ALTER TABLE ONLY aegis.policy_decision
    ADD CONSTRAINT policy_decision_campaign_id_idempotency_key_key UNIQUE (campaign_id, idempotency_key);


ALTER TABLE ONLY aegis.policy_decision
    ADD CONSTRAINT policy_decision_pkey PRIMARY KEY (decision_id);


ALTER TABLE ONLY aegis.policy_snapshot
    ADD CONSTRAINT policy_snapshot_pkey PRIMARY KEY (policy_version);


ALTER TABLE ONLY aegis.provider_manifest
    ADD CONSTRAINT provider_manifest_pkey PRIMARY KEY (manifest_sha256);


ALTER TABLE ONLY aegis.provider_manifest
    ADD CONSTRAINT provider_manifest_version_unique UNIQUE (capability, provider, provider_version, adapter_version);


ALTER TABLE ONLY aegis.quarantine_record
    ADD CONSTRAINT quarantine_record_pkey PRIMARY KEY (quarantine_id);


ALTER TABLE ONLY aegis.quarantine_resolution
    ADD CONSTRAINT quarantine_resolution_pkey PRIMARY KEY (quarantine_id);


ALTER TABLE ONLY aegis.relationship
    ADD CONSTRAINT relationship_pkey PRIMARY KEY (relationship_id);


ALTER TABLE ONLY aegis.relationship_sighting
    ADD CONSTRAINT relationship_sighting_pkey PRIMARY KEY (relationship_id, scan_id);


ALTER TABLE ONLY aegis.report
    ADD CONSTRAINT report_pkey PRIMARY KEY (report_id);


ALTER TABLE ONLY aegis.scan_job
    ADD CONSTRAINT scan_job_decision_id_key UNIQUE (decision_id);


ALTER TABLE ONLY aegis.scan_job
    ADD CONSTRAINT scan_job_id_campaign_unique UNIQUE (job_id, campaign_id);


ALTER TABLE ONLY aegis.scan_job
    ADD CONSTRAINT scan_job_job_fingerprint_key UNIQUE (job_fingerprint);


ALTER TABLE ONLY aegis.scan_job
    ADD CONSTRAINT scan_job_pkey PRIMARY KEY (job_id);


ALTER TABLE ONLY aegis.scope_snapshot
    ADD CONSTRAINT scope_snapshot_pkey PRIMARY KEY (scope_id);


ALTER TABLE ONLY aegis.severity_assessment
    ADD CONSTRAINT severity_assessment_pkey PRIMARY KEY (assessment_id);


ALTER TABLE ONLY aegis.vulnerability_revision
    ADD CONSTRAINT vulnerability_revision_pkey PRIMARY KEY (vuln_rev_id);


ALTER TABLE ONLY aegis.vulnerability_revision
    ADD CONSTRAINT vulnerability_revision_vulnerability_id_source_content_hash_key UNIQUE (vulnerability_id, source, content_hash);


ALTER TABLE aegis.model_usage
    ADD CONSTRAINT model_usage_cost_nonnegative CHECK ((cost_usd >= (0)::numeric)) NOT VALID;


ALTER TABLE aegis.model_usage
    ADD CONSTRAINT model_usage_input_nonnegative CHECK ((input_tokens >= 0)) NOT VALID;


ALTER TABLE aegis.model_usage
    ADD CONSTRAINT model_usage_latency_nonnegative CHECK ((latency_ms >= 0)) NOT VALID;


ALTER TABLE aegis.model_usage
    ADD CONSTRAINT model_usage_output_nonnegative CHECK ((output_tokens >= 0)) NOT VALID;


-- ===========================================================================
-- 7. Indexes
-- ===========================================================================


CREATE INDEX asset_alias_lookup ON aegis.asset_alias USING btree (namespace, alias_value);


CREATE INDEX asset_package_name ON aegis.asset_package USING btree (ecosystem, name);


CREATE INDEX asset_provenance_asset ON aegis.asset_provenance USING btree (asset_id);


CREATE INDEX audit_campaign ON aegis.audit_log USING btree (campaign_id, occurred_at);


CREATE INDEX audit_job ON aegis.audit_log USING btree (job_id);


CREATE INDEX finding_asset ON aegis.finding USING btree (asset_id);


CREATE INDEX finding_run_time ON aegis.finding_run USING btree (finding_id, observed_at);


CREATE INDEX finding_secret_fp ON aegis.finding USING btree (secret_fingerprint) WHERE (secret_fingerprint IS NOT NULL);


CREATE INDEX finding_status_sev ON aegis.finding USING btree (status, severity);


CREATE UNIQUE INDEX ingestion_attempt_first_once ON aegis.ingestion_attempt USING btree (dedup_key) WHERE (outcome = 'first'::text);


CREATE INDEX ingestion_attempt_key ON aegis.ingestion_attempt USING btree (dedup_key, attempt_seq);


CREATE INDEX model_usage_campaign ON aegis.model_usage USING btree (campaign_id, created_at);


CREATE INDEX observation_revision ON aegis.observation USING btree (campaign_id, revision);


CREATE INDEX observation_subject ON aegis.observation USING btree (subject_asset_id, predicate, observed_at DESC);


CREATE INDEX outbox_event_type_seq ON aegis.outbox_event USING btree (type, seq);


CREATE INDEX package_vuln_match_pkg ON aegis.package_vuln_match USING btree (package_asset_id, vulnerability_id, created_at DESC);


CREATE INDEX provider_manifest_resolve ON aegis.provider_manifest USING btree (capability, provider, registered_at DESC, manifest_sha256);


CREATE INDEX relationship_from ON aegis.relationship USING btree (from_asset_id, type);


CREATE UNIQUE INDEX relationship_one_open ON aegis.relationship USING btree (type, from_asset_id, to_asset_id) WHERE (valid_to IS NULL);


CREATE INDEX relationship_to ON aegis.relationship USING btree (to_asset_id, type);


CREATE INDEX scan_job_campaign_status ON aegis.scan_job USING btree (campaign_id, status);


CREATE INDEX scan_job_ready_order ON aegis.scan_job USING btree (campaign_id, priority DESC, created_at, job_id) WHERE (status = 'QUEUED'::text);


CREATE INDEX severity_assessment_finding ON aegis.severity_assessment USING btree (finding_id, created_at DESC);


CREATE INDEX vulnerability_revision_id ON aegis.vulnerability_revision USING btree (vulnerability_id, source, created_at DESC);


-- ===========================================================================
-- 8. Foreign keys
-- ===========================================================================


ALTER TABLE ONLY aegis.agent_session
    ADD CONSTRAINT agent_session_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES aegis.campaign(campaign_id);


ALTER TABLE ONLY aegis.agent_session
    ADD CONSTRAINT agent_session_objective_id_fkey FOREIGN KEY (objective_id) REFERENCES aegis.objective(objective_id);


ALTER TABLE ONLY aegis.agent_session
    ADD CONSTRAINT agent_session_policy_version_fkey FOREIGN KEY (policy_version) REFERENCES aegis.policy_snapshot(policy_version);


ALTER TABLE ONLY aegis.alert_attempt
    ADD CONSTRAINT alert_attempt_alert_id_fkey FOREIGN KEY (alert_id) REFERENCES aegis.alert_delivery(alert_id);


ALTER TABLE ONLY aegis.alert_delivery
    ADD CONSTRAINT alert_delivery_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES aegis.asset(asset_id);


ALTER TABLE ONLY aegis.alert_delivery
    ADD CONSTRAINT alert_delivery_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES aegis.finding(finding_id);


ALTER TABLE ONLY aegis.artifact
    ADD CONSTRAINT artifact_first_job_id_fkey FOREIGN KEY (first_job_id) REFERENCES aegis.scan_job(job_id);


ALTER TABLE ONLY aegis.asset
    ADD CONSTRAINT asset_first_job_id_fkey FOREIGN KEY (first_job_id) REFERENCES aegis.scan_job(job_id);


ALTER TABLE ONLY aegis.asset_alias
    ADD CONSTRAINT asset_alias_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES aegis.asset(asset_id);


ALTER TABLE ONLY aegis.asset_alias
    ADD CONSTRAINT asset_alias_source_job_id_fkey FOREIGN KEY (source_job_id) REFERENCES aegis.scan_job(job_id);


ALTER TABLE ONLY aegis.asset_annotation
    ADD CONSTRAINT asset_annotation_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES aegis.asset(asset_id);


ALTER TABLE ONLY aegis.asset_annotation
    ADD CONSTRAINT asset_annotation_evidence_id_fkey FOREIGN KEY (evidence_id) REFERENCES aegis.evidence(evidence_id);


ALTER TABLE ONLY aegis.asset_campaign
    ADD CONSTRAINT asset_campaign_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES aegis.asset(asset_id);


ALTER TABLE ONLY aegis.asset_campaign
    ADD CONSTRAINT asset_campaign_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES aegis.campaign(campaign_id);


ALTER TABLE ONLY aegis.asset_campaign
    ADD CONSTRAINT asset_campaign_first_job_id_fkey FOREIGN KEY (first_job_id) REFERENCES aegis.scan_job(job_id);


ALTER TABLE ONLY aegis.asset_package
    ADD CONSTRAINT asset_package_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES aegis.asset(asset_id);


ALTER TABLE ONLY aegis.asset_provenance
    ADD CONSTRAINT asset_provenance_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES aegis.asset(asset_id);


ALTER TABLE ONLY aegis.asset_provenance
    ADD CONSTRAINT asset_provenance_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES aegis.campaign(campaign_id);


ALTER TABLE ONLY aegis.asset_provenance
    ADD CONSTRAINT asset_provenance_from_asset_id_fkey FOREIGN KEY (from_asset_id) REFERENCES aegis.asset(asset_id);


ALTER TABLE ONLY aegis.asset_provenance
    ADD CONSTRAINT asset_provenance_from_target_id_fkey FOREIGN KEY (from_target_id) REFERENCES aegis.campaign_target(target_id);


ALTER TABLE ONLY aegis.asset_provenance
    ADD CONSTRAINT asset_provenance_source_job_id_fkey FOREIGN KEY (source_job_id) REFERENCES aegis.scan_job(job_id);


ALTER TABLE ONLY aegis.asset_service
    ADD CONSTRAINT asset_service_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES aegis.asset(asset_id);


ALTER TABLE ONLY aegis.asset_url
    ADD CONSTRAINT asset_url_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES aegis.asset(asset_id);


ALTER TABLE ONLY aegis.campaign
    ADD CONSTRAINT campaign_policy_fk FOREIGN KEY (current_policy_version) REFERENCES aegis.policy_snapshot(policy_version) DEFERRABLE INITIALLY DEFERRED;


ALTER TABLE ONLY aegis.campaign
    ADD CONSTRAINT campaign_scope_fk FOREIGN KEY (scope_id) REFERENCES aegis.scope_snapshot(scope_id) DEFERRABLE INITIALLY DEFERRED;


ALTER TABLE ONLY aegis.campaign_ledger
    ADD CONSTRAINT campaign_ledger_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES aegis.campaign(campaign_id);


ALTER TABLE ONLY aegis.campaign_status_change
    ADD CONSTRAINT campaign_status_change_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES aegis.campaign(campaign_id);


ALTER TABLE ONLY aegis.campaign_target
    ADD CONSTRAINT campaign_target_scope_id_fkey FOREIGN KEY (scope_id) REFERENCES aegis.scope_snapshot(scope_id);


ALTER TABLE ONLY aegis.evidence
    ADD CONSTRAINT evidence_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES aegis.campaign(campaign_id);


ALTER TABLE ONLY aegis.evidence
    ADD CONSTRAINT evidence_job_id_fkey FOREIGN KEY (job_id) REFERENCES aegis.scan_job(job_id);


ALTER TABLE ONLY aegis.evidence_check
    ADD CONSTRAINT evidence_check_evidence_id_fkey FOREIGN KEY (evidence_id) REFERENCES aegis.evidence(evidence_id);


ALTER TABLE ONLY aegis.finding
    ADD CONSTRAINT finding_assessment_fk FOREIGN KEY (current_assessment) REFERENCES aegis.severity_assessment(assessment_id) DEFERRABLE INITIALLY DEFERRED;


ALTER TABLE ONLY aegis.finding
    ADD CONSTRAINT finding_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES aegis.asset(asset_id);


ALTER TABLE ONLY aegis.finding
    ADD CONSTRAINT finding_first_campaign_id_fkey FOREIGN KEY (first_campaign_id) REFERENCES aegis.campaign(campaign_id);


ALTER TABLE ONLY aegis.finding
    ADD CONSTRAINT finding_first_job_id_fkey FOREIGN KEY (first_job_id) REFERENCES aegis.scan_job(job_id);


ALTER TABLE ONLY aegis.finding_run
    ADD CONSTRAINT finding_run_assessment_id_fkey FOREIGN KEY (assessment_id) REFERENCES aegis.severity_assessment(assessment_id);


ALTER TABLE ONLY aegis.finding_run
    ADD CONSTRAINT finding_run_evidence_id_fkey FOREIGN KEY (evidence_id) REFERENCES aegis.evidence(evidence_id);


ALTER TABLE ONLY aegis.finding_run
    ADD CONSTRAINT finding_run_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES aegis.finding(finding_id);


ALTER TABLE ONLY aegis.finding_run
    ADD CONSTRAINT finding_run_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES aegis.scan_job(job_id);


ALTER TABLE ONLY aegis.finding_source
    ADD CONSTRAINT finding_source_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES aegis.finding(finding_id);


ALTER TABLE ONLY aegis.finding_source
    ADD CONSTRAINT finding_source_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES aegis.scan_job(job_id);


ALTER TABLE ONLY aegis.finding_transition
    ADD CONSTRAINT finding_transition_evidence_id_fkey FOREIGN KEY (evidence_id) REFERENCES aegis.evidence(evidence_id);


ALTER TABLE ONLY aegis.finding_transition
    ADD CONSTRAINT finding_transition_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES aegis.finding(finding_id);


ALTER TABLE ONLY aegis.graph_revision
    ADD CONSTRAINT graph_revision_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES aegis.campaign(campaign_id);


ALTER TABLE ONLY aegis.graph_revision
    ADD CONSTRAINT graph_revision_causal_job_id_fkey FOREIGN KEY (causal_job_id) REFERENCES aegis.scan_job(job_id);


ALTER TABLE ONLY aegis.graph_revision
    ADD CONSTRAINT graph_revision_envelope_event_id_fkey FOREIGN KEY (envelope_event_id) REFERENCES aegis.ingestion_inbox(event_id);


ALTER TABLE ONLY aegis.hypothesis
    ADD CONSTRAINT hypothesis_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES aegis.campaign(campaign_id);


ALTER TABLE ONLY aegis.hypothesis
    ADD CONSTRAINT hypothesis_created_session_fkey FOREIGN KEY (created_session) REFERENCES aegis.agent_session(session_id);


ALTER TABLE ONLY aegis.hypothesis_revision
    ADD CONSTRAINT hypothesis_revision_hypothesis_id_fkey FOREIGN KEY (hypothesis_id) REFERENCES aegis.hypothesis(hypothesis_id);


ALTER TABLE ONLY aegis.hypothesis_revision
    ADD CONSTRAINT hypothesis_revision_session_id_fkey FOREIGN KEY (session_id) REFERENCES aegis.agent_session(session_id);


ALTER TABLE ONLY aegis.ingestion_attempt
    ADD CONSTRAINT ingestion_attempt_inbox_event_id_fkey FOREIGN KEY (inbox_event_id) REFERENCES aegis.ingestion_inbox(event_id);


ALTER TABLE ONLY aegis.ingestion_inbox
    ADD CONSTRAINT ingestion_inbox_job_id_fkey FOREIGN KEY (job_id) REFERENCES aegis.scan_job(job_id);


ALTER TABLE ONLY aegis.job_callback_quarantine
    ADD CONSTRAINT job_callback_quarantine_job_id_fkey FOREIGN KEY (job_id) REFERENCES aegis.scan_job(job_id);


ALTER TABLE ONLY aegis.job_dependency
    ADD CONSTRAINT job_dependency_depends_on_job_id_campaign_id_fkey FOREIGN KEY (depends_on_job_id, campaign_id) REFERENCES aegis.scan_job(job_id, campaign_id);


ALTER TABLE ONLY aegis.job_dependency
    ADD CONSTRAINT job_dependency_job_id_campaign_id_fkey FOREIGN KEY (job_id, campaign_id) REFERENCES aegis.scan_job(job_id, campaign_id);


ALTER TABLE ONLY aegis.job_lifecycle_change
    ADD CONSTRAINT job_lifecycle_change_job_id_fkey FOREIGN KEY (job_id) REFERENCES aegis.scan_job(job_id);


ALTER TABLE ONLY aegis.job_status_change
    ADD CONSTRAINT job_status_change_job_id_fkey FOREIGN KEY (job_id) REFERENCES aegis.scan_job(job_id);


ALTER TABLE ONLY aegis.model_usage
    ADD CONSTRAINT model_usage_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES aegis.campaign(campaign_id);


ALTER TABLE ONLY aegis.model_usage
    ADD CONSTRAINT model_usage_session_id_fkey FOREIGN KEY (session_id) REFERENCES aegis.agent_session(session_id);


ALTER TABLE ONLY aegis.objective
    ADD CONSTRAINT objective_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES aegis.campaign(campaign_id);


ALTER TABLE ONLY aegis.objective
    ADD CONSTRAINT objective_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES aegis.objective(objective_id);


ALTER TABLE ONLY aegis.observation
    ADD CONSTRAINT observation_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES aegis.campaign(campaign_id);


ALTER TABLE ONLY aegis.observation
    ADD CONSTRAINT observation_envelope_event_id_fkey FOREIGN KEY (envelope_event_id) REFERENCES aegis.ingestion_inbox(event_id);


ALTER TABLE ONLY aegis.observation
    ADD CONSTRAINT observation_revision_fkey FOREIGN KEY (revision) REFERENCES aegis.graph_revision(revision);


ALTER TABLE ONLY aegis.observation
    ADD CONSTRAINT observation_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES aegis.scan_job(job_id);


ALTER TABLE ONLY aegis.observation
    ADD CONSTRAINT observation_subject_asset_id_fkey FOREIGN KEY (subject_asset_id) REFERENCES aegis.asset(asset_id);


ALTER TABLE ONLY aegis.package_vuln_match
    ADD CONSTRAINT package_vuln_match_package_asset_id_fkey FOREIGN KEY (package_asset_id) REFERENCES aegis.asset(asset_id);


ALTER TABLE ONLY aegis.package_vuln_match
    ADD CONSTRAINT package_vuln_match_vuln_rev_id_fkey FOREIGN KEY (vuln_rev_id) REFERENCES aegis.vulnerability_revision(vuln_rev_id);


ALTER TABLE ONLY aegis.policy_decision
    ADD CONSTRAINT policy_decision_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES aegis.campaign(campaign_id);


ALTER TABLE ONLY aegis.policy_decision
    ADD CONSTRAINT policy_decision_policy_version_fkey FOREIGN KEY (policy_version) REFERENCES aegis.policy_snapshot(policy_version);


ALTER TABLE ONLY aegis.policy_decision
    ADD CONSTRAINT policy_decision_scope_id_fkey FOREIGN KEY (scope_id) REFERENCES aegis.scope_snapshot(scope_id);


ALTER TABLE ONLY aegis.policy_decision
    ADD CONSTRAINT policy_decision_session_id_fkey FOREIGN KEY (session_id) REFERENCES aegis.agent_session(session_id);


ALTER TABLE ONLY aegis.policy_snapshot
    ADD CONSTRAINT policy_snapshot_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES aegis.campaign(campaign_id) DEFERRABLE INITIALLY DEFERRED;


ALTER TABLE ONLY aegis.quarantine_record
    ADD CONSTRAINT quarantine_record_event_id_fkey FOREIGN KEY (event_id) REFERENCES aegis.ingestion_inbox(event_id);


ALTER TABLE ONLY aegis.quarantine_resolution
    ADD CONSTRAINT quarantine_resolution_quarantine_id_fkey FOREIGN KEY (quarantine_id) REFERENCES aegis.quarantine_record(quarantine_id);


ALTER TABLE ONLY aegis.relationship
    ADD CONSTRAINT relationship_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES aegis.campaign(campaign_id);


ALTER TABLE ONLY aegis.relationship
    ADD CONSTRAINT relationship_closed_by_job_id_fkey FOREIGN KEY (closed_by_job_id) REFERENCES aegis.scan_job(job_id);


ALTER TABLE ONLY aegis.relationship
    ADD CONSTRAINT relationship_from_asset_id_fkey FOREIGN KEY (from_asset_id) REFERENCES aegis.asset(asset_id);


ALTER TABLE ONLY aegis.relationship
    ADD CONSTRAINT relationship_source_job_id_fkey FOREIGN KEY (source_job_id) REFERENCES aegis.scan_job(job_id);


ALTER TABLE ONLY aegis.relationship
    ADD CONSTRAINT relationship_to_asset_id_fkey FOREIGN KEY (to_asset_id) REFERENCES aegis.asset(asset_id);


ALTER TABLE ONLY aegis.relationship_sighting
    ADD CONSTRAINT relationship_sighting_relationship_id_fkey FOREIGN KEY (relationship_id) REFERENCES aegis.relationship(relationship_id);


ALTER TABLE ONLY aegis.relationship_sighting
    ADD CONSTRAINT relationship_sighting_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES aegis.scan_job(job_id);


ALTER TABLE ONLY aegis.scan_job
    ADD CONSTRAINT scan_job_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES aegis.campaign(campaign_id);


ALTER TABLE ONLY aegis.scan_job
    ADD CONSTRAINT scan_job_decision_id_fkey FOREIGN KEY (decision_id) REFERENCES aegis.policy_decision(decision_id);


ALTER TABLE ONLY aegis.scan_job
    ADD CONSTRAINT scan_job_parent_job_id_fkey FOREIGN KEY (parent_job_id) REFERENCES aegis.scan_job(job_id);


ALTER TABLE ONLY aegis.scan_job
    ADD CONSTRAINT scan_job_policy_version_fkey FOREIGN KEY (policy_version) REFERENCES aegis.policy_snapshot(policy_version);


ALTER TABLE ONLY aegis.scan_job
    ADD CONSTRAINT scan_job_scope_id_fkey FOREIGN KEY (scope_id) REFERENCES aegis.scope_snapshot(scope_id);


ALTER TABLE ONLY aegis.scope_snapshot
    ADD CONSTRAINT scope_snapshot_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES aegis.campaign(campaign_id) DEFERRABLE INITIALLY DEFERRED;


ALTER TABLE ONLY aegis.severity_assessment
    ADD CONSTRAINT severity_assessment_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES aegis.finding(finding_id);


ALTER TABLE ONLY aegis.severity_assessment
    ADD CONSTRAINT severity_assessment_session_id_fkey FOREIGN KEY (session_id) REFERENCES aegis.agent_session(session_id);


ALTER TABLE ONLY aegis.vulnerability_revision
    ADD CONSTRAINT vulnerability_revision_snapshot_id_fkey FOREIGN KEY (snapshot_id) REFERENCES aegis.intel_snapshot(snapshot_id);


-- ===========================================================================
-- 9. Read-model view
-- ===========================================================================

CREATE VIEW aegis.vulnerability_current AS
 SELECT DISTINCT ON (vulnerability_id, source) vuln_rev_id,
    vulnerability_id,
    source,
    snapshot_id,
    aliases,
    cvss,
    kev,
    epss,
    affected,
    references_,
    published_at,
    modified_at,
    withdrawn,
    content_hash,
    created_at
   FROM aegis.vulnerability_revision
  ORDER BY vulnerability_id, source, created_at DESC;


-- ===========================================================================
-- 10. Append-only protection
--
-- protect(table, true) = no UPDATE and no DELETE/TRUNCATE (an append-only record);
-- protect(table, false) = no DELETE/TRUNCATE (a row may be updated through its cols_only list).
-- ===========================================================================


-- append-only
SELECT aegis.protect('aegis.alert_attempt'::regclass, true);
SELECT aegis.protect('aegis.artifact'::regclass, true);
SELECT aegis.protect('aegis.asset_alias'::regclass, true);
SELECT aegis.protect('aegis.asset_annotation'::regclass, true);
SELECT aegis.protect('aegis.asset_campaign'::regclass, true);
SELECT aegis.protect('aegis.asset_package'::regclass, true);
SELECT aegis.protect('aegis.asset_provenance'::regclass, true);
SELECT aegis.protect('aegis.asset_service'::regclass, true);
SELECT aegis.protect('aegis.asset_url'::regclass, true);
SELECT aegis.protect('aegis.audit_log'::regclass, true);
SELECT aegis.protect('aegis.campaign_ledger'::regclass, true);
SELECT aegis.protect('aegis.campaign_status_change'::regclass, true);
SELECT aegis.protect('aegis.campaign_target'::regclass, true);
SELECT aegis.protect('aegis.consumer_inbox'::regclass, true);
SELECT aegis.protect('aegis.dead_letter'::regclass, true);
SELECT aegis.protect('aegis.evidence'::regclass, true);
SELECT aegis.protect('aegis.evidence_check'::regclass, true);
SELECT aegis.protect('aegis.finding_run'::regclass, true);
SELECT aegis.protect('aegis.finding_source'::regclass, true);
SELECT aegis.protect('aegis.finding_transition'::regclass, true);
SELECT aegis.protect('aegis.graph_revision'::regclass, true);
SELECT aegis.protect('aegis.hypothesis'::regclass, true);
SELECT aegis.protect('aegis.hypothesis_revision'::regclass, true);
SELECT aegis.protect('aegis.idempotency_record'::regclass, true);
SELECT aegis.protect('aegis.ingestion_attempt'::regclass, true);
SELECT aegis.protect('aegis.intel_snapshot'::regclass, true);
SELECT aegis.protect('aegis.job_callback_quarantine'::regclass, true);
SELECT aegis.protect('aegis.job_dependency'::regclass, true);
SELECT aegis.protect('aegis.job_lifecycle_change'::regclass, true);
SELECT aegis.protect('aegis.job_status_change'::regclass, true);
SELECT aegis.protect('aegis.model_usage'::regclass, true);
SELECT aegis.protect('aegis.objective'::regclass, true);
SELECT aegis.protect('aegis.observation'::regclass, true);
SELECT aegis.protect('aegis.outbox_event'::regclass, true);
SELECT aegis.protect('aegis.package_vuln_match'::regclass, true);
SELECT aegis.protect('aegis.policy_decision'::regclass, true);
SELECT aegis.protect('aegis.policy_snapshot'::regclass, true);
SELECT aegis.protect('aegis.provider_manifest'::regclass, true);
SELECT aegis.protect('aegis.quarantine_record'::regclass, true);
SELECT aegis.protect('aegis.quarantine_resolution'::regclass, true);
SELECT aegis.protect('aegis.relationship_sighting'::regclass, true);
SELECT aegis.protect('aegis.report'::regclass, true);
SELECT aegis.protect('aegis.scope_snapshot'::regclass, true);
SELECT aegis.protect('aegis.severity_assessment'::regclass, true);
SELECT aegis.protect('aegis.vulnerability_revision'::regclass, true);

-- no delete/truncate
SELECT aegis.protect('aegis.agent_session'::regclass, false);
SELECT aegis.protect('aegis.alert_delivery'::regclass, false);
SELECT aegis.protect('aegis.asset'::regclass, false);
SELECT aegis.protect('aegis.campaign'::regclass, false);
SELECT aegis.protect('aegis.consumer_cursor'::regclass, false);
SELECT aegis.protect('aegis.finding'::regclass, false);
SELECT aegis.protect('aegis.ingestion_inbox'::regclass, false);
SELECT aegis.protect('aegis.outbox_dispatcher'::regclass, false);
SELECT aegis.protect('aegis.outbox_publication'::regclass, false);
SELECT aegis.protect('aegis.outbox_watermark'::regclass, false);
SELECT aegis.protect('aegis.relationship'::regclass, false);
SELECT aegis.protect('aegis.scan_job'::regclass, false);


-- ===========================================================================
-- 11. Domain triggers
--
-- Trigger names state the rule they enforce. A rule that spans two tables (a seed of this campaign,
-- the session that proposed the job, the job its decision approved) is a trigger because PostgreSQL
-- cannot express it as a CHECK; a rule about one row's own columns is a CHECK above.
-- ===========================================================================


CREATE TRIGGER cols_only BEFORE UPDATE ON aegis.agent_session FOR EACH ROW EXECUTE FUNCTION aegis.forbid_value_update('status', 'decision', 'stop_reason', 'steps_used', 'result', 'finished_at');


CREATE TRIGGER cols_only BEFORE UPDATE ON aegis.alert_delivery FOR EACH ROW EXECUTE FUNCTION aegis.forbid_value_update('status', 'sent_at');


CREATE TRIGGER cols_only BEFORE UPDATE ON aegis.asset FOR EACH ROW EXECUTE FUNCTION aegis.forbid_value_update('owner', 'exposure', 'criticality', 'last_seen');


CREATE TRIGGER normalization_version_fixed BEFORE UPDATE ON aegis.asset FOR EACH ROW EXECUTE FUNCTION aegis.keep_asset_normalization_version();


CREATE TRIGGER seed_in_campaign BEFORE INSERT ON aegis.asset_provenance FOR EACH ROW EXECUTE FUNCTION aegis.require_provenance_seed();


CREATE TRIGGER cols_only BEFORE UPDATE ON aegis.campaign FOR EACH ROW EXECUTE FUNCTION aegis.forbid_value_update('status', 'status_reason', 'current_policy_version', 'labels', 'started_at', 'ended_at');


CREATE TRIGGER v2_config_guard BEFORE INSERT OR UPDATE ON aegis.campaign FOR EACH ROW EXECUTE FUNCTION aegis.guard_campaign_v2_config();


CREATE TRIGGER cols_only BEFORE UPDATE ON aegis.consumer_cursor FOR EACH ROW EXECUTE FUNCTION aegis.forbid_value_update('last_seq', 'updated_at');


CREATE TRIGGER cols_only BEFORE UPDATE ON aegis.finding FOR EACH ROW EXECUTE FUNCTION aegis.forbid_value_update('status', 'severity', 'current_assessment', 'transition_seq', 'confidence', 'last_seen');


CREATE TRIGGER allocate_seq BEFORE INSERT ON aegis.graph_revision FOR EACH ROW EXECUTE FUNCTION aegis.graph_revision_allocate_seq();


CREATE TRIGGER cols_only BEFORE UPDATE ON aegis.ingestion_inbox FOR EACH ROW EXECUTE FUNCTION aegis.forbid_value_update('status', 'receipt', 'revision', 'processed_at');


CREATE TRIGGER receipt_once BEFORE INSERT OR UPDATE ON aegis.ingestion_inbox FOR EACH ROW EXECUTE FUNCTION aegis.receipt_once();


CREATE TRIGGER cols_only BEFORE UPDATE ON aegis.outbox_dispatcher FOR EACH ROW EXECUTE FUNCTION aegis.forbid_value_update('fence', 'holder', 'leased_until', 'updated_at');


CREATE TRIGGER allocate_seq BEFORE INSERT ON aegis.outbox_event FOR EACH ROW EXECUTE FUNCTION aegis.outbox_event_allocate_seq();


CREATE TRIGGER cols_only BEFORE UPDATE ON aegis.outbox_publication FOR EACH ROW EXECUTE FUNCTION aegis.forbid_value_update('next_seq', 'updated_at');


CREATE TRIGGER cols_only BEFORE UPDATE ON aegis.outbox_watermark FOR EACH ROW EXECUTE FUNCTION aegis.forbid_value_update('published_upto', 'updated_at');


CREATE TRIGGER initiator_required BEFORE INSERT ON aegis.policy_decision FOR EACH ROW EXECUTE FUNCTION aegis.require_job_initiator();


CREATE TRIGGER proposer_session_required BEFORE INSERT ON aegis.policy_decision FOR EACH ROW EXECUTE FUNCTION aegis.require_decision_proposer_session();


CREATE TRIGGER target_refs_required BEFORE INSERT ON aegis.policy_decision FOR EACH ROW EXECUTE FUNCTION aegis.require_decision_target_refs();


CREATE TRIGGER targets_projection_required BEFORE INSERT ON aegis.policy_decision FOR EACH ROW EXECUTE FUNCTION aegis.require_canonical_projection();


CREATE TRIGGER v2_config_required BEFORE INSERT ON aegis.policy_snapshot FOR EACH ROW EXECUTE FUNCTION aegis.require_v2_policy_snapshot();


CREATE TRIGGER close_only BEFORE UPDATE ON aegis.relationship FOR EACH ROW EXECUTE FUNCTION aegis.relationship_close_only();


CREATE TRIGGER cancel_actor_required BEFORE UPDATE ON aegis.scan_job FOR EACH ROW EXECUTE FUNCTION aegis.require_cancel_actor();


CREATE TRIGGER cols_only BEFORE UPDATE ON aegis.scan_job FOR EACH ROW EXECUTE FUNCTION aegis.forbid_value_update('status', 'error', 'envelope_event_id', 'started_at', 'finished_at', 'attempt', 'generation', 'cancel_requested_at', 'cancel_requested_by', 'cancel_reason', 'wait_reason');


CREATE TRIGGER decision_consistency_required BEFORE INSERT ON aegis.scan_job FOR EACH ROW EXECUTE FUNCTION aegis.require_job_decision_consistency();


CREATE TRIGGER initiator_required BEFORE INSERT ON aegis.scan_job FOR EACH ROW EXECUTE FUNCTION aegis.require_job_initiator();


CREATE TRIGGER lifecycle_guard BEFORE UPDATE ON aegis.scan_job FOR EACH ROW EXECUTE FUNCTION aegis.guard_scan_job_lifecycle();


CREATE TRIGGER lifecycle_history AFTER UPDATE ON aegis.scan_job FOR EACH ROW EXECUTE FUNCTION aegis.record_job_lifecycle();


CREATE TRIGGER proposer_session_required BEFORE INSERT ON aegis.scan_job FOR EACH ROW EXECUTE FUNCTION aegis.require_job_proposer_session();


CREATE TRIGGER target_refs_required BEFORE INSERT ON aegis.scan_job FOR EACH ROW EXECUTE FUNCTION aegis.require_job_target_refs();


CREATE TRIGGER targets_projection_required BEFORE INSERT ON aegis.scan_job FOR EACH ROW EXECUTE FUNCTION aegis.require_canonical_projection();


CREATE TRIGGER v2_policy_required BEFORE INSERT ON aegis.scan_job FOR EACH ROW EXECUTE FUNCTION aegis.require_job_v2_policy();


-- ===========================================================================
-- 12. search_path pinning
--
-- CREATEFUNCTION-time pinning above covers every function this file creates; this sweep is the
-- catalog-level invariant and the test (contracts/db/postgres/tests/search_path_pinning.sql) reads
-- the same catalog, so a future migration that adds an unpinned function fails the gate instead of
-- quietly reintroducing the hole. aegis first, pg_temp last: a TEMP table cannot stand in for a
-- table of this schema, and pg_catalog keeps its implicit precedence.
-- ===========================================================================
DO $$
DECLARE
  fn record;
  pinned int := 0;
BEGIN
  FOR fn IN
    SELECT p.oid::regprocedure AS signature
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'aegis'
       AND NOT EXISTS (SELECT 1 FROM unnest(coalesce(p.proconfig, '{}'::text[])) AS cfg
                        WHERE cfg LIKE 'search_path=%')
     ORDER BY 1::text
  LOOP
    EXECUTE format('ALTER FUNCTION %s SET search_path = aegis, pg_temp', fn.signature);
    pinned := pinned + 1;
  END LOOP;
  IF pinned > 0 THEN
    RAISE EXCEPTION '0001_baseline: % aegis function(s) were created without a pinned search_path', pinned;
  END IF;
END $$;

-- ===========================================================================
-- 13. Privileges
--
-- The outbox roles see only the C04 tables and primitives they need; PUBLIC keeps nothing on the
-- dispatcher functions. Everything else stays with the schema owner. Both roles are NOLOGIN group
-- roles; a deployment attaches its service users to them.
-- ===========================================================================
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_outbox_writer') THEN
    CREATE ROLE aegis_outbox_writer NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_outbox_dispatcher') THEN
    CREATE ROLE aegis_outbox_dispatcher NOLOGIN;
  END IF;
END $$;

GRANT USAGE ON SCHEMA aegis TO aegis_outbox_writer;
GRANT USAGE ON SCHEMA aegis TO aegis_outbox_dispatcher;

REVOKE ALL ON FUNCTION aegis.consumer_advance(p_consumer text, p_upto bigint, p_dispatcher text, p_fence bigint) FROM PUBLIC;
GRANT ALL ON FUNCTION aegis.consumer_advance(p_consumer text, p_upto bigint, p_dispatcher text, p_fence bigint) TO aegis_outbox_dispatcher;

GRANT ALL ON FUNCTION aegis.graph_revision_allocate_seq() TO aegis_outbox_writer;

REVOKE ALL ON FUNCTION aegis.outbox_batch(p_consumer text, p_limit integer) FROM PUBLIC;
GRANT ALL ON FUNCTION aegis.outbox_batch(p_consumer text, p_limit integer) TO aegis_outbox_dispatcher;

REVOKE ALL ON FUNCTION aegis.outbox_dispatch_lease(p_dispatcher text, p_holder text, p_ttl_seconds integer) FROM PUBLIC;
GRANT ALL ON FUNCTION aegis.outbox_dispatch_lease(p_dispatcher text, p_holder text, p_ttl_seconds integer) TO aegis_outbox_dispatcher;

GRANT ALL ON FUNCTION aegis.outbox_event_allocate_seq() TO aegis_outbox_writer;

REVOKE ALL ON FUNCTION aegis.outbox_fence_check(p_dispatcher text, p_fence bigint) FROM PUBLIC;
GRANT ALL ON FUNCTION aegis.outbox_fence_check(p_dispatcher text, p_fence bigint) TO aegis_outbox_dispatcher;

REVOKE ALL ON FUNCTION aegis.outbox_publication_alloc() FROM PUBLIC;
GRANT ALL ON FUNCTION aegis.outbox_publication_alloc() TO aegis_outbox_writer;

GRANT ALL ON FUNCTION aegis.outbox_publication_lock_key() TO aegis_outbox_writer;
GRANT ALL ON FUNCTION aegis.outbox_publication_lock_key() TO aegis_outbox_dispatcher;

REVOKE ALL ON FUNCTION aegis.outbox_publication_reserve(p_count bigint) FROM PUBLIC;
GRANT ALL ON FUNCTION aegis.outbox_publication_reserve(p_count bigint) TO aegis_outbox_writer;

REVOKE ALL ON FUNCTION aegis.outbox_watermark_refresh(p_dispatcher text, p_fence bigint) FROM PUBLIC;
GRANT ALL ON FUNCTION aegis.outbox_watermark_refresh(p_dispatcher text, p_fence bigint) TO aegis_outbox_dispatcher;

GRANT SELECT ON TABLE aegis.consumer_cursor TO aegis_outbox_dispatcher;

GRANT INSERT ON TABLE aegis.consumer_inbox TO aegis_outbox_dispatcher;

GRANT SELECT,INSERT ON TABLE aegis.graph_revision TO aegis_outbox_writer;
GRANT SELECT ON TABLE aegis.graph_revision TO aegis_outbox_dispatcher;

GRANT SELECT ON TABLE aegis.outbox_dispatcher TO aegis_outbox_dispatcher;

GRANT SELECT,INSERT ON TABLE aegis.outbox_event TO aegis_outbox_writer;
GRANT SELECT ON TABLE aegis.outbox_event TO aegis_outbox_dispatcher;

GRANT SELECT ON TABLE aegis.outbox_watermark TO aegis_outbox_dispatcher;


-- ===========================================================================
-- 14. Remaining comments
-- ===========================================================================

COMMENT ON FUNCTION aegis.consumer_advance(p_consumer text, p_upto bigint, p_dispatcher text, p_fence bigint) IS 'C04/D25: checkpoint a consumer after a successful apply, with the dispatcher fence. A checkpoint may never pass the published watermark, so adding a consumer cannot skip unpublished data.';

COMMENT ON FUNCTION aegis.is_actor(actor jsonb) IS 'True for the audit Actor shape: exactly {kind: operator|module|agent, id non-empty}. is_initiator/is_proposer stay stricter where the role matters.';

COMMENT ON FUNCTION aegis.is_canonical_projection(targets text[], refs jsonb) IS 'True when every element of `targets` is the canonical_key of a TargetRef in `refs` (targets is a projection, never the identity source).';

COMMENT ON FUNCTION aegis.is_initiator(actor jsonb) IS 'True for a server-derived initiator: exactly {kind, id} with kind operator|module and a non-empty opaque id. An agent cannot be the initiator of a job (C05).';

COMMENT ON FUNCTION aegis.is_proposer(actor jsonb) IS 'True for a proposer: exactly {kind: agent, id} where id is the agent_session.session_id (UUIDv7). A label is not a session.';

COMMENT ON FUNCTION aegis.is_roe_policy_v2(policy jsonb) IS 'Structural mirror of campaign/roe-policy.v2.schema.json for a snapshot written in the database: closed key set (no RoE time windows), required integer limits and ranges, budget, rate limits and denylist shapes. IANA timezone names and the like are validated by contracts/validation.py. A valid roe-policy.v1 object never passes (v1 requires scan_profile, v2 allows no unknown key).';

COMMENT ON FUNCTION aegis.is_target_ref(item jsonb) IS 'True for exactly one of {seed_id} or {canonical_key}. seed_id is a target_id of campaign_target; a keyword/CIDR seed has no canonical key, so fabricating one is a shape error.';

COMMENT ON FUNCTION aegis.is_target_refs(refs jsonb) IS 'True for a non-empty TargetRef array; mirrors approved-task/job/result-envelope targets.';

COMMENT ON FUNCTION aegis.is_wait_reason(reason jsonb) IS 'True for a job.v2 WaitReason object: known code (no WINDOW_CLOSED: the RoE time windows were dropped), ISO-8601 since, known keys only. Full timestamp validation stays in contracts/validation.py.';

COMMENT ON FUNCTION aegis.outbox_batch(p_consumer text, p_limit integer) IS 'C04: next published events after a consumer cursor, in publication order, never beyond the watermark. A missing consumer row starts at 0, which is also how a new consumer generation rebuilds.';

COMMENT ON FUNCTION aegis.outbox_dispatch_lease(p_dispatcher text, p_holder text, p_ttl_seconds integer) IS 'C04: take or renew a dispatcher lease and return the new fencing token (NULL when another live holder owns it). Every renewal returns a new fence, so an old token stops working immediately.';

COMMENT ON FUNCTION aegis.outbox_fence_check(p_dispatcher text, p_fence bigint) IS 'C04/D25 fencing: raise 55000 unless the caller still holds a live lease with exactly this fence.';

COMMENT ON FUNCTION aegis.outbox_publication_reserve(p_count bigint) IS 'C04: reserve a block of publication sequences for a batch writer, returning the first number. Numbers that are never used stay permanently absent; the dispatcher advances to the watermark and never waits for a specific number, so reserved-but-empty blocks cannot stall consumers.';

COMMENT ON FUNCTION aegis.outbox_watermark_refresh(p_dispatcher text, p_fence bigint) IS 'C04: advance and return the publication watermark. Waits (blocking, not polling) for the exclusive publication lock, so new writer requests queue behind this waiter and the watermark cannot starve under continuous write load; the wait is bounded by aegis.outbox_watermark_lock_timeout (default 5s) and a timeout raises SQLSTATE 55P03 without changing the watermark (loud; the caller retries). Must run in its own short transaction: the exclusive lock is transaction-scoped and holds new writers until commit. Fence-checked; only the dispatcher role can call it.';

COMMENT ON FUNCTION aegis.policy_hash(policy jsonb) IS 'sha256 over the row''s canonical jsonb text (aegis.policy_hash(policy)). A storage/audit fingerprint so an out-of-band change of a snapshot is detectable; it is not aegis-c14n/1. Validate content with campaign/roe-policy.v2.schema.json, not with this hash.';

COMMENT ON FUNCTION aegis.record_job_callback(p_job_id uuid, p_generation integer, p_attempt integer, p_status text, p_envelope_event_id uuid, p_error jsonb, p_payload_hash character, p_claimed jsonb, p_evidence_refs jsonb, p_quarantine_id uuid) IS 'M06. Returns terminalized | duplicate | quarantined. Only the current (generation, attempt) may terminalize; a duplicate of the recorded result is idempotent; a stale or conflicting callback leaves a job_callback_quarantine row. Evidence already collected stays linked to the job.';

COMMENT ON FUNCTION aegis.request_job_cancel(p_job_id uuid, p_actor jsonb, p_reason text) IS 'M02/M26 (and the proposing session for its own job). Returns requested | already_requested | terminal. Idempotent: the first who asks records the intent; a terminal job is left untouched; the actor must be an Actor and an agent may only cancel a job it proposed.';

COMMIT;
