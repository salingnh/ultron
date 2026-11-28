// AEGIS–Vanguard: ràng buộc và chỉ mục Neo4j v2 (Neo4j 2026.10). Chạy idempotent khi projector khởi động.
CREATE CONSTRAINT asset_key IF NOT EXISTS FOR (a:Asset) REQUIRE a.canonical_key IS UNIQUE;
CREATE CONSTRAINT asset_id IF NOT EXISTS FOR (a:Asset) REQUIRE a.asset_id IS UNIQUE;
CREATE CONSTRAINT vuln_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.vulnerability_id IS UNIQUE;
CREATE CONSTRAINT finding_id IF NOT EXISTS FOR (f:Finding) REQUIRE f.finding_id IS UNIQUE;
CREATE CONSTRAINT evidence_id IF NOT EXISTS FOR (e:Evidence) REQUIRE e.evidence_id IS UNIQUE;
CREATE CONSTRAINT job_id IF NOT EXISTS FOR (j:Job) REQUIRE j.job_id IS UNIQUE;
CREATE CONSTRAINT observation_id IF NOT EXISTS FOR (o:Observation) REQUIRE o.observation_id IS UNIQUE;
CREATE CONSTRAINT campaign_id IF NOT EXISTS FOR (c:Campaign) REQUIRE c.campaign_id IS UNIQUE;
CREATE CONSTRAINT target_id IF NOT EXISTS FOR (t:Target) REQUIRE t.target_id IS UNIQUE;
CREATE CONSTRAINT hypothesis_id IF NOT EXISTS FOR (h:Hypothesis) REQUIRE h.hypothesis_id IS UNIQUE;
CREATE CONSTRAINT relationship_id IF NOT EXISTS FOR ()-[r:SUBDOMAIN_OF]-() REQUIRE r.relationship_id IS UNIQUE;
// Mỗi loại cạnh từ PostgreSQL có ràng buộc relationship_id tương tự (projector sinh từ danh sách loại cạnh).
CREATE INDEX asset_kind IF NOT EXISTS FOR (a:Asset) ON (a.kind);
CREATE INDEX finding_status IF NOT EXISTS FOR (f:Finding) ON (f.status, f.severity);
// Không đánh chỉ mục Asset.campaign_ids: Neo4j giới hạn kích thước khóa chỉ mục, còn projector
// nối thêm một id cho mỗi chiến dịch (projector-upserts.cypher câu 1) nên một tài sản gặp vài trăm
// chiến dịch là vượt giới hạn và MỌI lần ghi node đó hỏng (đo được: property size 8181). Không truy
// vấn nào dùng chỉ mục này: lọc theo chiến dịch là phép "thuộc danh sách" (`$campaign_id IN
// coalesce(a.campaign_ids, [])`, PROFILE cho NodeByLabelScan + Filter); chỉ mục RANGE chỉ phục vụ
// so sánh cả danh sách. DROP ... IF EXISTS áp dụng cả cho database đã có chỉ mục.
DROP INDEX asset_campaigns IF EXISTS;
