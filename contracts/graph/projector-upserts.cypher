// Mẫu Cypher tham số hóa của projector M23. Không nối chuỗi. Nhãn phụ (:Domain, :IP...) đặt bằng apoc-free
// cách: mỗi kind một câu lệnh riêng, chọn trong mã theo bảng kind→label ở model.md.

// 1. Tài sản (một câu cho mỗi kind; ví dụ domain)
MERGE (a:Asset {canonical_key: $canonical_key})
ON CREATE SET a.asset_id = $asset_id, a.kind = $kind, a.first_seen = datetime($first_seen)
SET a:Domain,
    a.last_seen = CASE WHEN a.last_seen IS NULL OR datetime($last_seen) > a.last_seen THEN datetime($last_seen) ELSE a.last_seen END,
    a.campaign_ids = CASE WHEN $campaign_id IN coalesce(a.campaign_ids, []) THEN a.campaign_ids ELSE coalesce(a.campaign_ids, []) + $campaign_id END,
    a.pg_revision = $revision
RETURN a.asset_id;

// 2. Khoảng hiệu lực của cạnh (relationship_id từ PostgreSQL; một khoảng = một cạnh Neo4j)
MATCH (f:Asset {asset_id: $from_asset_id}), (t:Asset {asset_id: $to_asset_id})
MERGE (f)-[r:SUBDOMAIN_OF {relationship_id: $relationship_id}]->(t)
ON CREATE SET r.observed_at = datetime($observed_at), r.valid_from = datetime($valid_from),
              r.source_job_id = $source_job_id, r.confidence = $confidence, r.campaign_id = $campaign_id
SET r.valid_to = CASE WHEN $valid_to IS NULL THEN NULL ELSE datetime($valid_to) END;

// 3. Finding và bằng chứng
MATCH (a:Asset {asset_id: $asset_id})
MERGE (fd:Finding {finding_id: $finding_id})
SET fd.fingerprint = $fingerprint, fd.rule_id = $rule_id, fd.title = $title,
    fd.status = $status, fd.severity = $severity, fd.transition_seq = $transition_seq,
    fd.secret_value = $secret_value
MERGE (a)-[h:HAS_FINDING]->(fd)
ON CREATE SET h.observed_at = datetime($observed_at), h.valid_from = datetime($observed_at),
              h.source_job_id = $source_job_id, h.confidence = $confidence;

MATCH (fd:Finding {finding_id: $finding_id})
MERGE (e:Evidence {evidence_id: $evidence_id})
ON CREATE SET e.sha256 = $sha256, e.storage_uri = $storage_uri, e.source_tool = $source_tool
MERGE (fd)-[s:SUPPORTED_BY]->(e)
ON CREATE SET s.observed_at = datetime($observed_at), s.valid_from = datetime($observed_at),
              s.source_job_id = $source_job_id, s.confidence = 1.0;

// 4. Ứng viên phơi nhiễm CVE: nút :Vulnerability (nguồn vulnerability_current) và cạnh AFFECTED_BY
//    từ tài sản bị ảnh hưởng. Chỉ là ứng viên (package_vuln_match), không phải finding; các nhãn
//    nguồn được phép (service, application, package) do projector kiểm trước khi chạy câu này.
MATCH (a:Asset {asset_id: $asset_id})
MERGE (v:Vulnerability {vulnerability_id: $vulnerability_id})
SET v.cvss_base = $cvss_base, v.kev = $kev, v.epss = $epss,
    v.snapshot_id = $node_snapshot_id
MERGE (a)-[r:AFFECTED_BY]->(v)
ON CREATE SET r.valid_from = datetime($observed_at)
SET r.observed_at = datetime($observed_at), r.match_method = $match_method,
    r.affected_range = $affected_range, r.confidence = $confidence,
    r.snapshot_id = $snapshot_id, r.match_id = $match_id, r.campaign_id = $campaign_id;

// 4b. Rút ứng viên: bản intel mới không còn khớp nên M20 ghi quyết định ngược lại (`matched = false`,
//     migration 0008) và phát cùng loại sự kiện; projector xoá cạnh AFFECTED_BY của đúng cặp
//     (tài sản, CVE) đó, rồi xoá nút :Vulnerability nếu không còn cạnh nào trỏ tới (một lần dựng lại
//     từ PostgreSQL cũng không tạo nút mồ côi, nên hai đường phải ra cùng đồ thị). Projector chỉ chạy
//     câu này khi không còn quyết định khớp nào cho cặp đó: chiến dịch khác vẫn có thể giữ ứng viên.
MATCH (a:Asset {asset_id: $asset_id})-[r:AFFECTED_BY]->(v:Vulnerability {vulnerability_id: $vulnerability_id})
DELETE r
WITH v
WHERE NOT (v)--()
DELETE v;

// 5. Observation: chỉ predicate có `graph: true` trong contracts/ingestion/predicates.v2.yaml (M23
// lọc theo registry, không đưa mọi observation vào đồ thị). `subject` là canonical_key của tài sản
// bị quan sát; giá trị đầy đủ ở PostgreSQL, ở đây là value_summary để đồ thị không phình.
MERGE (o:Observation {observation_id: $observation_id})
SET o.predicate = $predicate, o.value_summary = $value_summary, o.polarity = $polarity,
    o.subject = $subject, o.observed_at = datetime($observed_at),
    o.confidence = $confidence, o.pg_revision = $revision;
