-- AEGIS–Vanguard: lược đồ PostgreSQL v1 (bản nháp S1, chờ Product Team duyệt)
-- Nguồn: docs/living/dac-ta-ky-thuat/05-du-lieu-api-su-kien.md. PostgreSQL là nguồn sự thật; Neo4j dựng lại được từ đây.
--
-- Quy ước
--   * Mọi ID là UUIDv7 do dịch vụ sinh (đã chốt D2, 2026-11-15). Thời gian là timestamptz, UTC.
--   * KHÔNG DELETE ở bất kỳ bảng nào (trigger aegis.forbid_delete).
--   * Bảng "append-only" cấm cả UPDATE (trigger aegis.forbid_update).
--   * Bảng "trạng thái hiện tại" (campaign, agent_session, scan_job, asset, finding, ingestion_inbox, alert_delivery)
--     chỉ cho UPDATE các cột trạng thái/bộ đệm; mọi thay đổi đồng thời ghi một dòng vào bảng lịch sử tương ứng.
--   * relationship chỉ cho UPDATE một lần: valid_to từ NULL sang có giá trị.
--   * Mỗi bảng ghi module sở hữu trong COMMENT. Module khác chỉ đọc, hoặc ghi qua API của module sở hữu.
--   * Checkpoint LangGraph do thư viện langgraph-checkpoint-postgres tạo trong schema riêng "langgraph".

CREATE SCHEMA IF NOT EXISTS aegis;
SET search_path = aegis, public;

-- ---------------------------------------------------------------------------
-- Hàm bảo vệ
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION aegis.forbid_delete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'DELETE bị cấm trên %.% (lưu vĩnh viễn, chỉ ghi thêm)', TG_TABLE_SCHEMA, TG_TABLE_NAME
    USING ERRCODE = 'insufficient_privilege';
END $$;

CREATE OR REPLACE FUNCTION aegis.forbid_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'UPDATE bị cấm trên bảng chỉ ghi thêm %.%', TG_TABLE_SCHEMA, TG_TABLE_NAME
    USING ERRCODE = 'insufficient_privilege';
END $$;

CREATE OR REPLACE FUNCTION aegis.relationship_close_only() RETURNS trigger LANGUAGE plpgsql AS $$
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

-- Gắn trigger cho danh sách bảng (gọi ở cuối file).
CREATE OR REPLACE FUNCTION aegis.protect(tbl regclass, append_only boolean) RETURNS void LANGUAGE plpgsql AS $$
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

-- ---------------------------------------------------------------------------
-- Dùng chung
-- ---------------------------------------------------------------------------
CREATE TABLE idempotency_record (
  scope          text        NOT NULL,              -- vd 'POST /campaigns', 'mcp:dns.enumerate_subdomains'
  key            text        NOT NULL,
  request_hash   char(64)    NOT NULL,              -- sha256 body chuẩn hóa; khác hash cùng key -> 409
  status_code    int         NOT NULL,
  response       jsonb       NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (scope, key)
);
COMMENT ON TABLE idempotency_record IS 'M26/M27/M05: kết quả đã trả cho Idempotency-Key. Append-only.';

-- ---------------------------------------------------------------------------
-- M01 Campaign và RoE
-- ---------------------------------------------------------------------------
CREATE TABLE campaign (
  campaign_id            uuid        PRIMARY KEY,
  name                   text        NOT NULL,
  objective              text        NOT NULL,
  status                 text        NOT NULL DEFAULT 'CREATED'
                         CHECK (status IN ('CREATED','RUNNING','WAITING','PAUSED','COMPLETED','FAILED','CANCELLED')),
  status_reason          text,
  current_policy_version text        NOT NULL,
  scope_id               uuid        NOT NULL,
  labels                 jsonb       NOT NULL DEFAULT '{}',
  created_by             jsonb       NOT NULL,      -- Actor
  created_at             timestamptz NOT NULL DEFAULT now(),
  started_at             timestamptz,
  ended_at               timestamptz
);
COMMENT ON TABLE campaign IS 'M01 (tạo), M02 (status). Trạng thái hiện tại; lịch sử ở campaign_status_change.';

CREATE TABLE campaign_status_change (
  campaign_id  uuid        NOT NULL REFERENCES campaign,
  seq          int         NOT NULL,
  from_status  text,
  to_status    text        NOT NULL,
  reason       text,
  actor        jsonb       NOT NULL,
  trace_id     char(32),
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (campaign_id, seq)
);
COMMENT ON TABLE campaign_status_change IS 'M02. Append-only.';

CREATE SEQUENCE policy_version_seq;
CREATE TABLE policy_snapshot (
  policy_version text        PRIMARY KEY CHECK (policy_version ~ '^roe-[1-9][0-9]*$'),
  campaign_id    uuid        NOT NULL REFERENCES campaign DEFERRABLE INITIALLY DEFERRED,
  policy         jsonb       NOT NULL,              -- roe-policy.v1
  policy_hash    char(64)    NOT NULL,
  created_by     jsonb       NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE policy_snapshot IS 'M01. Bản chụp RoE bất biến; đổi RoE = dòng mới với policy_version mới. Append-only.';

CREATE TABLE scope_snapshot (
  scope_id     uuid        PRIMARY KEY,
  campaign_id  uuid        NOT NULL REFERENCES campaign DEFERRABLE INITIALLY DEFERRED,
  targets      jsonb       NOT NULL,                -- campaign-create.v1#/$defs/Targets nguyên văn
  created_at   timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE scope_snapshot IS 'M01. Tập mục tiêu đầu vào (KHÔNG phải allowlist; chốt 13/11). Append-only.';

ALTER TABLE campaign
  ADD CONSTRAINT campaign_policy_fk FOREIGN KEY (current_policy_version) REFERENCES policy_snapshot DEFERRABLE INITIALLY DEFERRED,
  ADD CONSTRAINT campaign_scope_fk  FOREIGN KEY (scope_id) REFERENCES scope_snapshot DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE campaign_target (
  target_id      uuid        PRIMARY KEY,
  scope_id       uuid        NOT NULL REFERENCES scope_snapshot,
  kind           text        NOT NULL CHECK (kind IN ('domain','ip','cidr','url','email','keyword')),
  raw_value      text        NOT NULL,
  canonical_key  text,                              -- NULL cho keyword và cidr
  created_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (scope_id, kind, raw_value)
);
COMMENT ON TABLE campaign_target IS 'M01. Mục tiêu hạt giống, gốc của chuỗi nguồn gốc (G5). Append-only.';

CREATE TABLE objective (
  objective_id  uuid        PRIMARY KEY,
  campaign_id   uuid        NOT NULL REFERENCES campaign,
  parent_id     uuid        REFERENCES objective,
  text          text        NOT NULL,
  created_by    jsonb       NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE objective IS 'M01/M03. Mục tiêu con của chiến dịch. Append-only; trạng thái ở campaign_ledger.';

-- ---------------------------------------------------------------------------
-- M02 Campaign Controller / M03 Agent Harness
-- ---------------------------------------------------------------------------
CREATE TABLE campaign_ledger (
  campaign_id  uuid        NOT NULL REFERENCES campaign,
  seq          bigint      NOT NULL,
  kind         text        NOT NULL CHECK (kind IN ('cycle_started','cycle_finished','objective_done','objective_blocked',
                                                    'blocker','cursor','budget','idle_cycle','stop_condition')),
  payload      jsonb       NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (campaign_id, seq)
);
COMMENT ON TABLE campaign_ledger IS 'M02. Sổ chiến dịch ngoài hội thoại LLM. Append-only.';

CREATE TABLE agent_session (
  session_id        uuid        PRIMARY KEY,         -- = thread_id của LangGraph
  campaign_id       uuid        NOT NULL REFERENCES campaign,
  objective_id      uuid        REFERENCES objective,
  policy_version    text        NOT NULL REFERENCES policy_snapshot,
  revision_from     bigint      NOT NULL,
  status            text        NOT NULL CHECK (status IN ('RUNNING','SUCCEEDED','FAILED','CANCELLED')),
  decision          text        CHECK (decision IN ('continue','wait','stop')),
  stop_reason       text,
  steps_used        int         NOT NULL DEFAULT 0 CHECK (steps_used BETWEEN 0 AND 30),
  result            jsonb,                           -- session-result.v1
  started_at        timestamptz NOT NULL DEFAULT now(),
  finished_at       timestamptz
);
COMMENT ON TABLE agent_session IS 'M03. Trạng thái hiện tại; output cuối bất biến sau khi status khác RUNNING.';

CREATE TABLE hypothesis (
  hypothesis_id   uuid        PRIMARY KEY,
  campaign_id     uuid        NOT NULL REFERENCES campaign,
  created_session uuid        NOT NULL REFERENCES agent_session,
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE hypothesis_revision (
  hypothesis_id uuid        NOT NULL REFERENCES hypothesis,
  revision      int         NOT NULL,
  claim         text        NOT NULL,
  status        text        NOT NULL CHECK (status IN ('OPEN','SUPPORTED','REFUTED','INCONCLUSIVE','ABANDONED')),
  confidence    numeric(4,3) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
  subjects      text[]      NOT NULL DEFAULT '{}',
  supporting    text[]      NOT NULL DEFAULT '{}',
  refuting      text[]      NOT NULL DEFAULT '{}',
  next_check    text,
  session_id    uuid        NOT NULL REFERENCES agent_session,
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (hypothesis_id, revision)
);
COMMENT ON TABLE hypothesis_revision IS 'M03. Sổ giả thuyết; mỗi cập nhật một revision. Append-only.';

-- ---------------------------------------------------------------------------
-- M05 điểm kiểm / M06 Execution Gateway
-- ---------------------------------------------------------------------------
CREATE TABLE policy_decision (
  decision_id      uuid        PRIMARY KEY,
  campaign_id      uuid        NOT NULL REFERENCES campaign,
  session_id       uuid        REFERENCES agent_session,
  capability       text        NOT NULL,
  provider         text,
  targets          text[]      NOT NULL,
  input            jsonb       NOT NULL,
  decision         text        NOT NULL CHECK (decision IN ('approved','denied')),
  rule             text,                             -- luật đã từ chối
  error            jsonb,                            -- error.v1 khi denied
  rationale        text        NOT NULL,
  requested_by     jsonb       NOT NULL,
  policy_version   text        NOT NULL REFERENCES policy_snapshot,
  scope_id         uuid        NOT NULL REFERENCES scope_snapshot,
  impact_tier      text        NOT NULL CHECK (impact_tier IN ('T0','T1','T2','T3','T4')),
  idempotency_key  text        NOT NULL,
  trace_id         char(32)    NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (campaign_id, idempotency_key),
  CHECK (decision = 'approved' OR error IS NOT NULL)
);
COMMENT ON TABLE policy_decision IS 'M05. Nhật ký quyết định policy: mục tiêu + lý do (FR-002). Append-only.';

CREATE TABLE scan_job (
  job_id            uuid        PRIMARY KEY,
  campaign_id       uuid        NOT NULL REFERENCES campaign,
  decision_id       uuid        NOT NULL UNIQUE REFERENCES policy_decision,
  capability        text        NOT NULL,
  provider          text        NOT NULL,
  provider_version  text        NOT NULL,
  adapter_version   text        NOT NULL,
  image_digest      text        NOT NULL CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),  -- v1 container-only (D22)
  scan_cycle        uuid        NOT NULL,            -- định danh lần quét (D21): retry dùng lại, lần quét mới sinh mới
  job_fingerprint   char(64)    NOT NULL UNIQUE,     -- sha256(campaign, policy_version, provider, targets, input, profile, scan_cycle)
  policy_version    text        NOT NULL REFERENCES policy_snapshot,
  scope_id          uuid        NOT NULL REFERENCES scope_snapshot,
  impact_tier       text        NOT NULL CHECK (impact_tier IN ('T0','T1','T2')),
  profile           text        NOT NULL CHECK (profile IN ('passive','low-impact','standard')),
  input             jsonb       NOT NULL,
  targets           text[]      NOT NULL CHECK (cardinality(targets) > 0),
  requested_by      jsonb       NOT NULL,
  rationale         text        NOT NULL,
  parent_job_id     uuid        REFERENCES scan_job,
  status            text        NOT NULL DEFAULT 'QUEUED'
                    CHECK (status IN ('QUEUED','VALIDATING','DISPATCHED','RUNNING','COLLECTING','SUCCEEDED','FAILED','CANCELLED')),
  error             jsonb,
  envelope_event_id uuid,
  trace_id          char(32)    NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  started_at        timestamptz,
  finished_at       timestamptz,
  CHECK (status <> 'FAILED' OR error IS NOT NULL)
);
CREATE INDEX scan_job_campaign_status ON scan_job (campaign_id, status);
COMMENT ON TABLE scan_job IS 'M06. Trạng thái hiện tại; lịch sử ở job_status_change. Mỗi job = một lần chạy (scan_id = job_id).';

CREATE TABLE job_status_change (
  job_id      uuid        NOT NULL REFERENCES scan_job,
  seq         int         NOT NULL,
  from_status text,
  to_status   text        NOT NULL,
  error       jsonb,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (job_id, seq)
);
COMMENT ON TABLE job_status_change IS 'M06. Append-only.';

-- ---------------------------------------------------------------------------
-- M28 Evidence Store
-- ---------------------------------------------------------------------------
CREATE TABLE evidence (
  evidence_id     uuid        PRIMARY KEY,
  sha256          char(64)    NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  storage_uri     text        NOT NULL UNIQUE,       -- s3://evidence/{campaign_id}/{job_id}/{sha256}
  campaign_id     uuid        NOT NULL REFERENCES campaign,
  job_id          uuid        NOT NULL REFERENCES scan_job,
  size_bytes      bigint      NOT NULL CHECK (size_bytes >= 0),
  media_type      text        NOT NULL,
  kind            text        NOT NULL DEFAULT 'raw_output',
  classification  text        NOT NULL CHECK (classification IN ('PUBLIC','INTERNAL','RESTRICTED')),
  source_tool     text        NOT NULL,
  verified_at     timestamptz,                       -- lần kiểm hash gần nhất ghi ở evidence_check
  created_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (job_id, sha256)
);
COMMENT ON TABLE evidence IS 'M28. Metadata bằng chứng; object ở SeaweedFS có object lock. Append-only.';

CREATE TABLE evidence_check (
  evidence_id uuid        NOT NULL REFERENCES evidence,
  checked_at  timestamptz NOT NULL DEFAULT now(),
  ok          boolean     NOT NULL,
  detail      text,
  PRIMARY KEY (evidence_id, checked_at)
);
COMMENT ON TABLE evidence_check IS 'M28. Kết quả kiểm hash (sau phục hồi, định kỳ). Append-only.';

CREATE TABLE artifact (
  artifact_id    uuid        PRIMARY KEY,
  digest         text        NOT NULL UNIQUE CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
  kind           text        NOT NULL CHECK (kind IN ('oci_image','archive','binary','js_bundle','source_tree','sbom','other')),
  origin_uri     text,
  storage_uri    text,
  size_bytes     bigint,
  classification text        NOT NULL CHECK (classification IN ('PUBLIC','INTERNAL','RESTRICTED')),
  first_job_id   uuid        NOT NULL REFERENCES scan_job,
  created_at     timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE artifact IS 'M28. Append-only.';

-- ---------------------------------------------------------------------------
-- M27 Ingestion
-- ---------------------------------------------------------------------------
CREATE TABLE ingestion_inbox (
  event_id      uuid        PRIMARY KEY,             -- ResultEnvelope.event_id (UUIDv7, mỗi lần nộp một giá trị)
  dedup_key     text        NOT NULL UNIQUE,         -- ResultEnvelope.dedup_key, xác định từ job_id; chống nhận trùng (D23)
  job_id        uuid        NOT NULL REFERENCES scan_job,
  payload_hash  char(64)    NOT NULL,                -- khác hash cùng dedup_key -> 409
  status        text        NOT NULL CHECK (status IN ('received','accepted','partially_quarantined','dead_letter')),
  receipt       jsonb,
  revision      bigint,
  received_at   timestamptz NOT NULL DEFAULT now(),
  processed_at  timestamptz
);
COMMENT ON TABLE ingestion_inbox IS 'M27. Chống nhận trùng envelope. status chỉ đổi một lần từ received.';

CREATE TABLE quarantine_record (
  quarantine_id        uuid        PRIMARY KEY,
  event_id             uuid        NOT NULL REFERENCES ingestion_inbox,
  gate                 text        NOT NULL CHECK (gate IN ('G1','G2','G3','G4','G5','G6','G7')),
  record_pointer       text        NOT NULL,         -- JSON Pointer trong envelope, vd /results/assets/3
  record               jsonb       NOT NULL,
  reason               text        NOT NULL,
  created_at           timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE quarantine_resolution (
  quarantine_id  uuid        PRIMARY KEY REFERENCES quarantine_record,
  resolution     text        NOT NULL CHECK (resolution IN ('reingested','discarded_as_invalid')),
  by_event_id    uuid,
  actor          jsonb       NOT NULL,
  note           text,
  created_at     timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE quarantine_record IS 'M27. Bản ghi không qua cổng, giữ để xem lại (không bỏ đi). Append-only.';

CREATE TABLE dead_letter (
  dlq_id      uuid        PRIMARY KEY,
  source      text        NOT NULL,                  -- 'ingestion', 'consumer:<tên>'
  event_id    uuid,
  payload     jsonb       NOT NULL,
  error       jsonb       NOT NULL,                  -- error.v1
  created_at  timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE dead_letter IS 'M27 và mọi consumer. Append-only.';

CREATE TABLE graph_revision (
  revision          bigserial   PRIMARY KEY,
  campaign_id       uuid        NOT NULL REFERENCES campaign,
  causal_job_id     uuid        REFERENCES scan_job,
  envelope_event_id uuid        REFERENCES ingestion_inbox,
  created_at        timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE graph_revision IS 'M27 cấp, M23 phát knowledge.delta.v1. Một envelope được nhận = một revision. Append-only.';

-- ---------------------------------------------------------------------------
-- M07 Asset Inventory
-- ---------------------------------------------------------------------------
CREATE TABLE asset (
  asset_id       uuid        PRIMARY KEY,
  canonical_key  text        NOT NULL UNIQUE,
  kind           text        NOT NULL CHECK (kind IN ('domain','ip','service','application','url','email','oci_image','repo',
                                                      'repo_snapshot','artifact','package','cloud_resource','k8s_workload')),
  owner          text,                               -- GĐ2; không gán khi chưa có nguồn gốc
  exposure       text        CHECK (exposure IN ('internet','internal','unknown')),
  criticality    text        CHECK (criticality IN ('high','medium','low','unknown')),
  first_seen     timestamptz NOT NULL,
  last_seen      timestamptz NOT NULL,
  first_job_id   uuid        REFERENCES scan_job,    -- NULL nếu tài sản là mục tiêu hạt giống
  created_at     timestamptz NOT NULL DEFAULT now(),
  CHECK (last_seen >= first_seen)
);
COMMENT ON TABLE asset IS 'M07. Một tài sản thật = một dòng (khóa chuẩn). Cột owner/exposure/criticality/last_seen là bộ đệm; lịch sử ở asset_annotation và observation.';

CREATE TABLE asset_annotation (
  asset_id    uuid        NOT NULL REFERENCES asset,
  seq         int         NOT NULL,
  field       text        NOT NULL CHECK (field IN ('owner','exposure','criticality')),
  value       text,
  source      text        NOT NULL CHECK (source IN ('operator','inferred')),
  reason      text        NOT NULL,
  actor       jsonb       NOT NULL,
  evidence_id uuid        REFERENCES evidence,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (asset_id, seq)
);
COMMENT ON TABLE asset_annotation IS 'M07. Lịch sử chủ sở hữu, phơi nhiễm, độ quan trọng. Append-only.';

CREATE TABLE asset_alias (
  alias_id       uuid        PRIMARY KEY,
  asset_id       uuid        NOT NULL REFERENCES asset,
  namespace      text        NOT NULL CHECK (namespace IN ('original','idna','oci_tag','git_branch','git_tag','hostname','cpe','other')),
  alias_value    text        NOT NULL,
  reason         text,
  source_job_id  uuid        REFERENCES scan_job,
  observed_at    timestamptz NOT NULL,
  UNIQUE (asset_id, namespace, alias_value, observed_at)
);
CREATE INDEX asset_alias_lookup ON asset_alias (namespace, alias_value);
COMMENT ON TABLE asset_alias IS 'M07. Bí danh (tag image, nhánh git...). Append-only; hiệu lực tính từ chuỗi observed_at.';

CREATE TABLE asset_campaign (
  asset_id      uuid        NOT NULL REFERENCES asset,
  campaign_id   uuid        NOT NULL REFERENCES campaign,
  first_seen    timestamptz NOT NULL,
  first_job_id  uuid        REFERENCES scan_job,
  PRIMARY KEY (asset_id, campaign_id)
);
COMMENT ON TABLE asset_campaign IS 'M07. Tài sản dùng chung toàn hệ thống (single-tenant); bảng này cho biết chiến dịch nào đã chạm tới tài sản, để lọc truy vấn theo chiến dịch. Append-only.';

CREATE TABLE asset_provenance (
  provenance_id   uuid        PRIMARY KEY,
  asset_id        uuid        NOT NULL REFERENCES asset,
  campaign_id     uuid        NOT NULL REFERENCES campaign,
  from_asset_id   uuid        REFERENCES asset,
  from_target_id  uuid        REFERENCES campaign_target,
  source_job_id   uuid        REFERENCES scan_job,
  provider        text,
  observed_at     timestamptz NOT NULL,
  CHECK (num_nonnulls(from_asset_id, from_target_id) = 1),
  CHECK (source_job_id IS NOT NULL OR from_target_id IS NOT NULL)
);
CREATE INDEX asset_provenance_asset ON asset_provenance (asset_id);
COMMENT ON TABLE asset_provenance IS 'M27 ghi (cổng G5): tài sản được tìm ra từ mục tiêu/tài sản nào, bởi công cụ nào, lần chạy nào. Append-only.';

-- Chi tiết định danh theo loại (1-1 với asset; bất biến vì suy ra từ canonical_key)
CREATE TABLE asset_service (
  asset_id   uuid PRIMARY KEY REFERENCES asset,
  ip         inet NOT NULL,
  port       int  NOT NULL CHECK (port BETWEEN 1 AND 65535),
  transport  text NOT NULL CHECK (transport IN ('tcp','udp')),
  UNIQUE (ip, port, transport)
);
CREATE TABLE asset_url (
  asset_id   uuid PRIMARY KEY REFERENCES asset,
  scheme     text NOT NULL CHECK (scheme IN ('http','https')),
  host       text NOT NULL,
  port       int  NOT NULL,
  path       text NOT NULL,
  query      text NOT NULL DEFAULT ''                 -- đã chuẩn hóa, đã bỏ tham số nhạy cảm
);
CREATE TABLE asset_package (
  asset_id   uuid PRIMARY KEY REFERENCES asset,
  purl       text NOT NULL UNIQUE,
  ecosystem  text NOT NULL,
  name       text NOT NULL,
  version    text NOT NULL
);
CREATE INDEX asset_package_name ON asset_package (ecosystem, name);
COMMENT ON TABLE asset_service IS 'M07. Append-only.';

-- ---------------------------------------------------------------------------
-- M27 ghi / M23 chiếu: Observation và Relationship
-- ---------------------------------------------------------------------------
CREATE TABLE observation (
  observation_id    uuid        PRIMARY KEY,
  campaign_id       uuid        NOT NULL REFERENCES campaign,
  scan_id           uuid        NOT NULL REFERENCES scan_job,   -- = job_id
  envelope_event_id uuid        NOT NULL REFERENCES ingestion_inbox,
  revision          bigint      NOT NULL REFERENCES graph_revision,
  subject_asset_id  uuid        NOT NULL REFERENCES asset,
  predicate         text        NOT NULL,
  value             jsonb,
  value_hash        char(64)    NOT NULL,           -- sha256(canonical JSON của value) để so thay đổi nhanh
  polarity          text        NOT NULL DEFAULT 'present' CHECK (polarity IN ('present','absent','negated')),
  confidence        numeric(4,3) CHECK (confidence BETWEEN 0 AND 1),
  provider          text        NOT NULL,
  provider_version  text        NOT NULL,
  evidence_ids      uuid[]      NOT NULL DEFAULT '{}',
  observed_at       timestamptz NOT NULL,
  ingested_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (envelope_event_id, subject_asset_id, predicate, value_hash, observed_at)
);
CREATE INDEX observation_subject ON observation (subject_asset_id, predicate, observed_at DESC);
CREATE INDEX observation_revision ON observation (campaign_id, revision);
COMMENT ON TABLE observation IS 'M27. Điều ghi nhận được tại một thời điểm; mâu thuẫn giữa nguồn = nhiều dòng. Append-only.';

CREATE TABLE relationship (
  relationship_id   uuid        PRIMARY KEY,
  type              text        NOT NULL CHECK (type IN ('SUBDOMAIN_OF','RESOLVES_TO','EXPOSES','SERVES','HAS_ENDPOINT','HAS_ARTIFACT',
                                                         'CONTAINS_PACKAGE','DISCOVERED_FROM','SNAPSHOT_OF','ALIAS_OF')),
  from_asset_id     uuid        NOT NULL REFERENCES asset,
  to_asset_id       uuid        NOT NULL REFERENCES asset,
  observed_at       timestamptz NOT NULL,           -- lần thấy đầu của khoảng hiệu lực này
  valid_from        timestamptz NOT NULL,
  valid_to          timestamptz,                    -- NULL = còn hiệu lực
  source_job_id     uuid        NOT NULL REFERENCES scan_job,
  closed_by_job_id  uuid        REFERENCES scan_job,
  confidence        numeric(4,3) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
  campaign_id       uuid        NOT NULL REFERENCES campaign,
  attributes        jsonb       NOT NULL DEFAULT '{}',
  CHECK (from_asset_id <> to_asset_id)
);
CREATE UNIQUE INDEX relationship_one_open ON relationship (type, from_asset_id, to_asset_id) WHERE valid_to IS NULL;
CREATE INDEX relationship_from ON relationship (from_asset_id, type);
CREATE INDEX relationship_to   ON relationship (to_asset_id, type);
COMMENT ON TABLE relationship IS 'M27. Một dòng = một khoảng hiệu lực của cạnh. Không thấy nữa (job có coverage complete) thì đặt valid_to; thấy lại thì mở dòng mới.';

CREATE TABLE relationship_sighting (
  relationship_id uuid        NOT NULL REFERENCES relationship,
  scan_id         uuid        NOT NULL REFERENCES scan_job,
  observed_at     timestamptz NOT NULL,
  confidence      numeric(4,3) NOT NULL,
  evidence_ids    uuid[]      NOT NULL DEFAULT '{}',
  PRIMARY KEY (relationship_id, scan_id)
);
COMMENT ON TABLE relationship_sighting IS 'M27. Mỗi lần một job thấy cạnh. Append-only.';

-- ---------------------------------------------------------------------------
-- M18 Vuln Feed Sync
-- ---------------------------------------------------------------------------
CREATE TABLE intel_snapshot (
  snapshot_id   uuid        PRIMARY KEY,
  feed          text        NOT NULL CHECK (feed IN ('nvd','osv','kev','epss','ghsa')),
  version       text        NOT NULL,
  snapshot_at   timestamptz NOT NULL,
  fetched_at    timestamptz NOT NULL DEFAULT now(),
  record_count  int         NOT NULL,
  source_uri    text        NOT NULL,
  content_sha256 char(64),
  UNIQUE (feed, version)
);
COMMENT ON TABLE intel_snapshot IS 'M18. Mỗi lần đồng bộ thành công. Append-only.';

CREATE TABLE vulnerability_revision (
  vuln_rev_id      uuid        PRIMARY KEY,
  vulnerability_id text        NOT NULL,             -- CVE-..., GHSA-..., OSV id
  source           text        NOT NULL CHECK (source IN ('nvd','osv','kev','epss','ghsa')),
  snapshot_id      uuid        NOT NULL REFERENCES intel_snapshot,
  aliases          text[]      NOT NULL DEFAULT '{}',
  cvss             jsonb,                            -- [{version, vector, base_score, source}]
  kev              jsonb,                            -- {listed, date_added, due_date, ransomware}
  epss             jsonb,                            -- {score, percentile, date}
  affected         jsonb,                            -- [{purl|cpe, ranges[]}]
  references_      jsonb,
  published_at     timestamptz,
  modified_at      timestamptz,
  withdrawn        boolean     NOT NULL DEFAULT false,
  content_hash     char(64)    NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (vulnerability_id, source, content_hash)
);
CREATE INDEX vulnerability_revision_id ON vulnerability_revision (vulnerability_id, source, created_at DESC);
COMMENT ON TABLE vulnerability_revision IS 'M18. Bản ghi intel có phiên bản; chỉ thêm khi nội dung đổi. Append-only.';

CREATE VIEW vulnerability_current AS
  SELECT DISTINCT ON (vulnerability_id, source) *
  FROM vulnerability_revision
  ORDER BY vulnerability_id, source, created_at DESC;

-- ---------------------------------------------------------------------------
-- M20 Correlation, M21 Verification, M24
-- ---------------------------------------------------------------------------
CREATE TABLE package_vuln_match (
  match_id          uuid        PRIMARY KEY,
  package_asset_id  uuid        NOT NULL REFERENCES asset,
  vulnerability_id  text        NOT NULL,
  vuln_rev_id       uuid        NOT NULL REFERENCES vulnerability_revision,
  match_method      text        NOT NULL CHECK (match_method IN ('purl_range','cpe_range','scanner_direct')),
  affected_range    text,
  matched           boolean     NOT NULL,            -- false = đánh giá lại thấy không còn khớp
  created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX package_vuln_match_pkg ON package_vuln_match (package_asset_id, vulnerability_id, created_at DESC);
COMMENT ON TABLE package_vuln_match IS 'M20. Ứng viên AFFECTED_BY (chưa phải finding). Append-only; trạng thái hiện tại = dòng mới nhất.';

CREATE TABLE finding (
  finding_id         uuid        PRIMARY KEY,
  fingerprint        char(64)    NOT NULL UNIQUE,    -- sha256(asset_id | rule_id | location chuẩn hóa | fingerprint_context chuẩn hóa)
  asset_id           uuid        NOT NULL REFERENCES asset,
  rule_id            text        NOT NULL,
  category           text        NOT NULL CHECK (category IN ('vulnerability','misconfiguration','exposure','secret','weak_crypto','other')),
  title              text        NOT NULL,
  vulnerability_ids  text[]      NOT NULL DEFAULT '{}',
  location           jsonb       NOT NULL DEFAULT '{}',
  match_method       text,
  status             text        NOT NULL CHECK (status IN ('CANDIDATE','CORROBORATED','VERIFIED','FALSE_POSITIVE','ACCEPTED_RISK','FIXED','REGRESSED')),
  severity           text        NOT NULL DEFAULT 'UNRATED' CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO','UNRATED')),
  current_assessment uuid,                           -- severity_assessment mới nhất
  transition_seq     int         NOT NULL DEFAULT 1,
  confidence         numeric(4,3),
  secret_value       text,                           -- dạng rõ (chốt 13/11)
  secret_fingerprint char(64),
  first_seen         timestamptz NOT NULL,
  last_seen          timestamptz NOT NULL,
  first_job_id       uuid        NOT NULL REFERENCES scan_job,
  first_campaign_id  uuid        NOT NULL REFERENCES campaign,
  created_at         timestamptz NOT NULL DEFAULT now(),
  CHECK ((category = 'secret') = (secret_fingerprint IS NOT NULL))
);
CREATE INDEX finding_asset ON finding (asset_id);
CREATE INDEX finding_status_sev ON finding (status, severity);
CREATE INDEX finding_secret_fp ON finding (secret_fingerprint) WHERE secret_fingerprint IS NOT NULL;
COMMENT ON TABLE finding IS 'M20 tạo; M20/M21/M24 đổi status qua finding_transition. Cột status/severity/last_seen là bộ đệm của bảng lịch sử.';

CREATE TABLE finding_source (
  finding_id        uuid        NOT NULL REFERENCES finding,
  scan_id           uuid        NOT NULL REFERENCES scan_job,
  provider          text        NOT NULL,
  provider_version  text        NOT NULL,
  scanner_severity  text,
  candidate         jsonb       NOT NULL,            -- FindingCandidate nguyên văn (dữ liệu không tin cậy)
  evidence_ids      uuid[]      NOT NULL CHECK (cardinality(evidence_ids) > 0),
  observed_at       timestamptz NOT NULL,
  PRIMARY KEY (finding_id, scan_id, provider)
);
COMMENT ON TABLE finding_source IS 'M20. Mỗi provider báo finding ở mỗi lần chạy; Trivy+Grype+OSV = 1 finding, 3 dòng. Append-only.';

CREATE TABLE finding_transition (
  finding_id   uuid        NOT NULL REFERENCES finding,
  seq          int         NOT NULL,
  from_status  text,
  to_status    text        NOT NULL,
  reason       text        NOT NULL,
  evidence_id  uuid        REFERENCES evidence,
  actor        jsonb       NOT NULL,
  cause        text        NOT NULL CHECK (cause IN ('scan','intel_revision','verification','operator','regression_check')),
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (finding_id, seq),
  CHECK (to_status NOT IN ('VERIFIED','FIXED','REGRESSED','CORROBORATED') OR evidence_id IS NOT NULL)
);
COMMENT ON TABLE finding_transition IS 'M20/M21/M24. Mọi lần chuyển trạng thái; seq = transition_seq của finding.changed.v1. Append-only.';

CREATE TABLE severity_assessment (
  assessment_id  uuid        PRIMARY KEY,
  finding_id     uuid        NOT NULL REFERENCES finding,
  severity       text        NOT NULL CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO','UNRATED')),
  assessment     jsonb       NOT NULL,              -- severity-assessment.v1 đầy đủ (reasons, source_refs, uncertainty...)
  trigger        text        NOT NULL CHECK (trigger IN ('scan','intel_revision','operator_request','verification')),
  session_id     uuid        REFERENCES agent_session,
  model          text        NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX severity_assessment_finding ON severity_assessment (finding_id, created_at DESC);
ALTER TABLE finding ADD CONSTRAINT finding_assessment_fk FOREIGN KEY (current_assessment) REFERENCES severity_assessment DEFERRABLE INITIALLY DEFERRED;
COMMENT ON TABLE severity_assessment IS 'M20. Mỗi lần agent đánh giá lại = một dòng kèm lý do. Append-only.';

CREATE TABLE finding_run (
  finding_id      uuid        NOT NULL REFERENCES finding,
  scan_id         uuid        NOT NULL REFERENCES scan_job,
  seen            boolean     NOT NULL,
  status          text        NOT NULL,
  severity        text        NOT NULL,
  severity_reason text,
  assessment_id   uuid        REFERENCES severity_assessment,
  evidence_id     uuid        REFERENCES evidence,
  observed_at     timestamptz NOT NULL,
  PRIMARY KEY (finding_id, scan_id),
  CHECK (NOT seen OR evidence_id IS NOT NULL)
);
CREATE INDEX finding_run_time ON finding_run (finding_id, observed_at);
COMMENT ON TABLE finding_run IS 'M20/M21. Một dòng cho mỗi finding ở mỗi lần chạy có kiểm tài sản đó (coverage), kể cả seen=false. Append-only.';

-- ---------------------------------------------------------------------------
-- Sự kiện: outbox + inbox consumer (bus MVP)
-- ---------------------------------------------------------------------------
CREATE TABLE outbox_event (
  seq          bigserial   PRIMARY KEY,
  event_id     uuid        NOT NULL UNIQUE,
  type         text        NOT NULL CHECK (type IN ('job.started.v1','job.completed.v1','policy.denied.v1','asset.discovered.v1',
                                                    'observation.changed.v1','artifact.ready.v1','knowledge.delta.v1',
                                                    'intel.revision.v1','finding.changed.v1')),
  producer     text        NOT NULL CHECK (producer ~ '^M[0-9]{2}$'),
  dedup_key    text        NOT NULL,
  campaign_id  uuid,
  payload      jsonb       NOT NULL,
  trace        jsonb       NOT NULL,
  occurred_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (type, dedup_key)
);
CREATE INDEX outbox_event_type_seq ON outbox_event (type, seq);
COMMENT ON TABLE outbox_event IS 'Ghi trong cùng giao dịch với thay đổi dữ liệu; dispatcher đọc theo seq (LISTEN/NOTIFY để đánh thức). Append-only; giữ vĩnh viễn, là event log để dựng lại Neo4j.';

CREATE TABLE consumer_cursor (
  consumer     text        PRIMARY KEY,              -- vd 'm23-projector', 'm24-alerts', 'm02-signal'
  last_seq     bigint      NOT NULL DEFAULT 0,
  updated_at   timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE consumer_cursor IS 'Vị trí đọc outbox của từng consumer. Bảng trạng thái (cho UPDATE).';

CREATE TABLE consumer_inbox (
  consumer     text        NOT NULL,
  dedup_key    text        NOT NULL,                 -- '<type>:<dedup_key>'
  event_id     uuid        NOT NULL,
  processed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (consumer, dedup_key)
);
COMMENT ON TABLE consumer_inbox IS 'Khử trùng phía consumer (at-least-once). Append-only.';

-- ---------------------------------------------------------------------------
-- M25 Audit, M04 Model usage
-- ---------------------------------------------------------------------------
CREATE TABLE audit_log (
  audit_id          bigserial   PRIMARY KEY,
  occurred_at       timestamptz NOT NULL DEFAULT now(),
  actor             jsonb       NOT NULL,
  action            text        NOT NULL,            -- vd campaign.create, policy.decide, job.dispatch, finding.transition, graph.write
  campaign_id       uuid,
  session_id        uuid,
  objective_id      uuid,
  job_id            uuid,
  capability_id     text,
  provider_version  text,
  policy_version    text,
  scope_id          uuid,
  evidence_id       uuid,
  targets           text[],
  details           jsonb       NOT NULL DEFAULT '{}',
  trace_id          char(32)    NOT NULL
);
CREATE INDEX audit_campaign ON audit_log (campaign_id, occurred_at);
CREATE INDEX audit_job ON audit_log (job_id);
COMMENT ON TABLE audit_log IS 'M25. Audit chỉ ghi thêm, không sửa, không xóa, lưu vĩnh viễn.';

CREATE TABLE model_usage (
  usage_id       uuid        PRIMARY KEY,
  campaign_id    uuid        REFERENCES campaign,
  session_id     uuid        REFERENCES agent_session,
  profile        text        NOT NULL CHECK (profile IN ('LOW','MID','HIGH')),
  provider       text        NOT NULL CHECK (provider IN ('openai','anthropic')),
  model          text        NOT NULL,
  input_tokens   int         NOT NULL,
  output_tokens  int         NOT NULL,
  cost_usd       numeric(12,6) NOT NULL,
  latency_ms     int         NOT NULL,
  status         text        NOT NULL CHECK (status IN ('ok','error','fallback','budget_denied')),
  error_code     text,
  trace_id       char(32)    NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX model_usage_campaign ON model_usage (campaign_id, created_at);
COMMENT ON TABLE model_usage IS 'M04. Một dòng mỗi lời gọi model. Append-only.';

-- ---------------------------------------------------------------------------
-- M24 Cảnh báo và báo cáo
-- ---------------------------------------------------------------------------
CREATE TABLE alert_delivery (
  alert_id     uuid        PRIMARY KEY,
  channel      text        NOT NULL CHECK (channel IN ('telegram')),
  template_id  text        NOT NULL,
  destination  text        NOT NULL,                 -- Telegram chat/group id
  dedup_key    text        NOT NULL UNIQUE,          -- vd 'finding.changed:<finding_id>:<seq>'
  finding_id   uuid        REFERENCES finding,
  asset_id     uuid        REFERENCES asset,
  payload      jsonb       NOT NULL,                 -- nội dung đã render, đầy đủ (không che secret)
  status       text        NOT NULL CHECK (status IN ('pending','sent','failed','suppressed')),
  created_at   timestamptz NOT NULL DEFAULT now(),
  sent_at      timestamptz
);
CREATE TABLE alert_attempt (
  alert_id     uuid        NOT NULL REFERENCES alert_delivery,
  attempt      int         NOT NULL,
  ok           boolean     NOT NULL,
  response     jsonb,
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (alert_id, attempt)
);
COMMENT ON TABLE alert_delivery IS 'M24. dedup_key chống gửi trùng khi consumer chạy lại.';

CREATE TABLE report (
  report_id    uuid        PRIMARY KEY,
  kind         text        NOT NULL CHECK (kind IN ('findings','delta','executive')),
  format       text        NOT NULL CHECK (format IN ('json','sarif','html')),
  params       jsonb       NOT NULL,
  storage_uri  text        NOT NULL,
  sha256       char(64)    NOT NULL,
  created_by   jsonb       NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE report IS 'M24. Append-only.';

-- ---------------------------------------------------------------------------
-- Gắn bảo vệ
-- ---------------------------------------------------------------------------
DO $$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY[
  'idempotency_record','campaign_status_change','policy_snapshot','scope_snapshot','campaign_target','objective',
  'campaign_ledger','hypothesis','hypothesis_revision','policy_decision','job_status_change','evidence','evidence_check',
  'artifact','quarantine_record','quarantine_resolution','dead_letter','graph_revision','asset_annotation','asset_alias',
  'asset_campaign','asset_provenance','asset_service','asset_url','asset_package','observation','relationship_sighting',
  'intel_snapshot','vulnerability_revision','package_vuln_match','finding_source','finding_transition',
  'severity_assessment','finding_run','outbox_event','consumer_inbox','audit_log','model_usage','alert_attempt','report'
] LOOP PERFORM aegis.protect(t::regclass, true); END LOOP; END $$;

DO $$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY[
  'campaign','agent_session','scan_job','ingestion_inbox','asset','finding','alert_delivery','consumer_cursor','relationship'
] LOOP PERFORM aegis.protect(t::regclass, false); END LOOP; END $$;
CREATE TRIGGER close_only BEFORE UPDATE ON relationship FOR EACH ROW EXECUTE FUNCTION aegis.relationship_close_only();
