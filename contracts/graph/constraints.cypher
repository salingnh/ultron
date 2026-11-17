// AEGIS–Vanguard: ràng buộc và chỉ mục Neo4j v2 (Neo4j 5.x). Chạy idempotent khi projector khởi động.
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
CREATE INDEX asset_campaigns IF NOT EXISTS FOR (a:Asset) ON (a.campaign_ids);
CREATE INDEX finding_status IF NOT EXISTS FOR (f:Finding) ON (f.status, f.severity);
