*Domain Model • Graph Ontology • Evidence • Contracts • Security Semantics*

Phiên bản: 1.0 \| Ngày: 12/11/2026 \| Trạng thái: Thiết kế đề xuất

Phạm vi: hệ thống nội bộ, single-tenant; không yêu cầu đăng nhập người dùng ở MVP; giới hạn phạm vi thực thi và an toàn scanner vẫn bắt buộc.

| **Mục tiêu** | Nền tảng AI Agent điều phối đánh giá bề mặt tấn công và lỗ hổng có kiểm soát         |
|--------------|--------------------------------------------------------------------------------------|
| **Triết lý** | OSS-first • Capability-based • Durable campaigns • Evidence-first                    |
| **Nhóm đọc** | CTO • Security Architect • SOC • AppSec • Platform Engineering                       |
| **Căn cứ**   | Hai file nghiên cứu đầu vào; tài liệu chính thức OSS; quyết định kiến trúc của dự án |

# 1. Nguyên tắc mô hình dữ liệu

Dữ liệu được chia thành Asset (đối tượng tồn tại), Observation (thực tế ghi nhận có thời gian), Finding (đánh giá điểm yếu), Evidence (bằng chứng có checksum) và Hypothesis (giả thuyết chưa được xác minh). Tránh một node “Vulnerability” vừa đại diện CVE toàn cục vừa đại diện lỗ hổng trên từng hệ thống. CVE là định danh intelligence; Finding là instance gắn asset/version/environment.

<img src="markdown/media/03_Mo_hinh_du_lieu_KnowledgeGraph_API/media/image1.png" style="width:6.5in;height:0.59187in" />

Hình 1. Chuỗi quan hệ dữ liệu tối thiểu để trace từ domain đến finding và evidence.

# 2. Các entity chuẩn

| **Entity**    | **Định danh / thuộc tính**                                                        | **Lưu trữ đích**                   |
|---------------|-----------------------------------------------------------------------------------|------------------------------------|
| Asset         | asset_id, kind, canonical_key, owner, exposure, criticality, first_seen/last_seen | PostgreSQL index + Neo4j node      |
| AssetAlias    | namespace, alias_value, reason, validity                                          | Entity-resolution layer            |
| Service       | asset_id, host_ip, port, protocol, banner, observed_at                            | Graph/SQL                          |
| Endpoint      | normalized URL, HTTP method, api_contract_id, auth_context                        | Graph                              |
| Artifact      | digest, kind, origin_uri, storage_uri, size, classification                       | MinIO + SQL metadata               |
| Package       | purl, version, ecosystem, license                                                 | Graph/SQL + SBOM                   |
| Vulnerability | source, vulnerability_id, cvss, references, affected ranges                       | Intel cache                        |
| Finding       | finding_id, asset_id, rule_id, severity, confidence, lifecycle                    | PostgreSQL source of truth         |
| Observation   | observation_id, scan_id, subject_id, predicate, value, time                       | Append-only SQL / graph projection |
| Evidence      | evidence_id, sha256, storage_uri, redaction, source_tool                          | MinIO + SQL metadata               |
| Hypothesis    | hypothesis_id, claim, supporting/refuting evidence, status                        | SQL/Graph                          |
| Campaign      | campaign_id, scope_id, objective, budget, state, cursor                           | PostgreSQL / Temporal              |
| ScanJob       | job_id, capability, provider, fingerprint, input_ref, state                       | PostgreSQL                         |
| Policy        | policy_version, allowlist, impact_class, windows, rate                            | PostgreSQL                         |
| Provenance    | provider, version, execution, source URI, observed_at                             | On all records                     |

# 3. Ontology và tính thời gian

| **Relation**     | **Nguồn → đích**            | **Ý nghĩa**                            |
|------------------|-----------------------------|----------------------------------------|
| RESOLVES_TO      | Domain → IP                 | Observed DNS resolution, time-bound    |
| EXPOSES          | IP → Service                | Network observation trong policy scope |
| SERVES           | Service → Application       | Application inference / evidence       |
| HAS_ENDPOINT     | Application → Endpoint      | URL/path known through crawl/contract  |
| HAS_ARTIFACT     | Application/Repo → Artifact | Hash-preserved artifact snapshot       |
| CONTAINS_PACKAGE | Artifact → Package          | SBOM inventory                         |
| AFFECTED_BY      | Package → Vulnerability     | Candidate mapping theo range/source    |
| HAS_FINDING      | Asset → Finding             | Finding concrete trên asset            |
| SUPPORTED_BY     | Finding → Evidence          | Evidence immutable reference           |
| DERIVED_FROM     | Observation → Job           | Source provenance / trace              |

Quan hệ DNS, port, package và CVE có tính thời điểm. Các cạnh chứa observed_at, valid_from, valid_to, source_job_id, confidence. “Not found” không đồng nghĩa “không tồn tại”; cần phân biệt unknown, absent-at-time và explicit negative evidence. Trong ngữ cảnh REA, static call graph là static-only, không thể dùng đơn độc để khẳng định runtime reachability/VEX \[SRC-01, SRC-12\].

# 4. Canonical identity và deduplication

| **Asset kind** | **Canonical key**                                                | **Ghi chú**                                    |
|----------------|------------------------------------------------------------------|------------------------------------------------|
| domain         | dns:\<lowercase_fqdn_without_trailing_dot\>                      | Giữ alias raw và IDNA normalization            |
| ip             | ip:\<normalized_ipv4_or_ipv6\>                                   | Không gán owner nếu chưa có provenance         |
| service        | service:\<ip\>:\<port\>/\<transport\>                            | Tách observed protocol app layer               |
| url            | url:\<scheme\>://\<host\>:\<port\>/\<path\>?\<normalized-query\> | Không lưu token/sensitive query                |
| oci-image      | oci:sha256:\<manifest_digest\>                                   | Không dùng mutable tag làm identity            |
| repo-snapshot  | git:\<repo_identity\>@\<commit_sha\>                             | Git branch là mutable alias                    |
| package        | purl:\<normalized_purl\>                                         | Version pin, qualifiers                        |
| finding        | hash(asset_id, rule_id, location, normalized evidence context)   | Dùng fingerprint ổn định theo scanner versions |

# 5. Data ingestion — concurrency and provenance

Scanner upload raw evidence đến MinIO qua signed URL rồi gửi ResultEnvelope tới Ingestion API. Parser validate JSON schema, xác thực checksum, lưu inbox event với unique event_id và dedup key, sau đó transactionally upsert PostgreSQL; Graph projector cập nhật Neo4j qua parameterized Cypher với unique constraints. Không dùng trực tiếp Graph Conductor như chức năng sẵn có vì bản tham chiếu mới là RFC/issue \[SRC-18\].

MERGE (a:Asset {canonical_key: \$canonical_key})

ON CREATE SET a.asset_id = \$asset_id, a.first_seen = \$observed_at

SET a.last_seen = \$observed_at,

a.kind = \$kind

RETURN a.asset_id;

Khi chạy đồng thời, dùng unique constraint Asset(canonical_key), retry transaction với exponential backoff, deterministic merge rules cho thuộc tính. Giá trị mâu thuẫn được lưu thành multiple observations thay vì ghi đè dữ liệu gốc.

# 6. ResultEnvelope và mẫu dữ liệu

{

"schema_version":"1.0",

"job_id":"job-0021",

"campaign_id":"camp-0001",

"capability":"network.discover_services",

"provider":{"name":"nmap","version":"pinned-release"},

"policy_version":"roe-12",

"status":"succeeded",

"results":{

"assets":\[{"kind":"service","canonical_key":"service:10.0.0.10:443/tcp"}\],

"observations":\[{"predicate":"port_open","value":true,"observed_at":"2026-11-12T08:00:00Z"}\],

"relationships":\[\], "findings":\[\]

},

"evidence":\[{"sha256":"\<HEX_SHA256\>","uri":"s3://evidence/\<OBJECT_ID\>","classification":"internal"}\],

"errors":\[\],

"provenance":{"input_fingerprint":"\<HASH\>","adapter_version":"1.0.0"}

}

# 7. REST API contract v1

| **Method** | **Path**                      | **Ý nghĩa**                        | **Idempotency**          |
|------------|-------------------------------|------------------------------------|--------------------------|
| POST       | /api/v1/campaigns             | Tạo campaign với RoE snapshot      | Idempotency-Key required |
| GET        | /api/v1/campaigns/{id}        | Tình trạng, budgets, counters      | Read only                |
| POST       | /api/v1/campaigns/{id}/pause  | Tạm dừng campaign                  | Safe retry               |
| POST       | /api/v1/campaigns/{id}/resume | Tiếp tục campaign                  | Safe retry               |
| POST       | /api/v1/campaigns/{id}/cancel | Hủy và phát cancel jobs            | Safe retry               |
| GET        | /api/v1/campaigns/{id}/events | Timeline/SSE events                | Cursor pagination        |
| GET        | /api/v1/capabilities          | List capability và providers       | Read only                |
| POST       | /api/v1/jobs                  | Submit validated job               | Idempotency-Key required |
| GET        | /api/v1/jobs/{id}             | Status và result refs              | Read only                |
| POST       | /api/v1/jobs/{id}/cancel      | Cancel child job                   | Safe retry               |
| POST       | /api/v1/ingestion/results     | Normalized results / evidence refs | Unique event_id          |
| GET        | /api/v1/assets/{id}/graph     | Graph neighborhood bounded         | Read only                |
| GET        | /api/v1/findings              | Filter/export findings             | Cursor pagination        |

# 8. API validation responses

POST /api/v1/campaigns

Idempotency-Key: camp-root-2026-11-12

{

"name": "Internal baseline",

"scope": {"domains": \["internal.example"\], "cidrs": \["10.20.0.0/24"\]},

"policy": {"scan_profile": "low-impact", "max_parallel_jobs": 10,

"blackout_windows": \[\], "max_duration_hours": 168},

"objective": "Inventory and identify vulnerabilities without service disruption"

}

HTTP/1.1 202 Accepted

{"campaign_id":"camp-0001","status":"CREATED","policy_version":"roe-12"}

API chưa có user login ở MVP theo yêu cầu; chỉ phục vụ private ingress/VPN và áp dụng network-level allowlist, CSRF protection nếu dùng cookie, hạn chế CORS, request validation, mTLS/service credentials giữa các service. Khi bổ sung SSO sau này, đặt xác thực ở API boundary mà không thay đổi nội bộ capabilities.

# 9. Event catalog và cơ chế delivery

| **Event type**     | **Payload tối thiểu**                     | **Consumer semantics**           |
|--------------------|-------------------------------------------|----------------------------------|
| job.started.v1     | job_id, campaign_id, provider, time       | At-least-once; idempotent        |
| job.completed.v1   | job_id, status, evidence_refs, time       | Signal Temporal, dedup on job_id |
| knowledge.delta.v1 | revision, changed_entities, causal_job_id | Queue follow-up within RoE       |
| finding.changed.v1 | finding_id, previous/new, evidence_ref    | Report/ticket recomputation      |
| intel.revision.v1  | feed, version, impacted_ids               | Selective re-evaluation          |
| policy.denied.v1   | job_id, scope/policy reason               | Audit / notification             |

# 10. Risk prioritization model

CVSS phản ánh mức độ nghiêm trọng kỹ thuật; EPSS là xác suất dự báo; CISA KEV thể hiện bằng chứng khai thác đã biết. Không gộp EPSS với CVSS theo phép cộng thô rồi gọi đó là điểm chuẩn. Hệ thống dùng rules-first: KEV + confirmed affected asset + exposure đẩy vào hàng ưu tiên cao; các trường hợp còn lại dùng weighted factors có trọng số cấu hình để xếp hạng nội bộ, giải thích theo bằng chứng.

risk = priority_rules(

cisa_kev, confirmed_affected, internet_exposure,

business_criticality, epss, cvss,

mitigations, evidence_confidence)

\# Output: tier, reasons\[\], source_refs\[\], uncertainty\[\], recommended_actions\[\]

\# Public PoC != verified exploitability; VEX != proof of non-reachability.

# 11. Evidence and sensitive data handling

- MinIO path: evidence/{campaign_id}/{job_id}/{sha256}; object immutable theo version hoặc object lock nếu cần.

- Không lưu plaintext discovered secrets trong Neo4j hoặc LLM prompts; finding chỉ có fingerprint/masked preview/vault ref.

- Data classification: PUBLIC, INTERNAL, RESTRICTED; retention đề xuất 30/90/180 ngày tùy policy và pháp lý.

- Mọi artifact xuất từ web/Git/registry đều xem là untrusted; không chạy nhị phân hoặc script trong control plane.

- Prompt chỉ nạp đoạn trích đã được parse, gắn nguồn và giới hạn; schema validator, policy enforcement ngoài LLM.

- Chỉ sử dụng credential được cấp hợp lệ cho gray-box; không tự xác minh secret bằng đăng nhập vào dịch vụ thật.

# 12. Các data quality gates

| **Gate**      | **Validation**                                        | **Nếu không đạt**                        |
|---------------|-------------------------------------------------------|------------------------------------------|
| G1 Identity   | Canonical key hợp lệ                                  | Quarantine record                        |
| G2 Provenance | Tool/version/time/job/source xác định                 | Mark unsupported / incomplete            |
| G3 Evidence   | Checksum + storage ref tồn tại                        | Finding không thể VERIFIED               |
| G4 Status     | Schema enum hợp lệ                                    | Dead-letter queue / report error         |
| G5 Scope      | Asset/target thuộc policy                             | Quarantine + policy alert                |
| G6 Safety     | Không plaintext secrets/raw uncontrolled instructions | Redact and isolate                       |
| G7 Dedup      | Unique keys transaction                               | Merge, preserve independent observations |

# 13. Knowledge retrieval cho agent

Graph Query service cung cấp các truy vấn đã đăng ký: get_asset_neighbors, get_recent_observations, get_unverified_hypotheses, get_package_cve_matches, summarize_campaign_delta, get_evidence_excerpt. Các truy vấn có maximum_hops, max_records, timeout và scope predicate. LangGraph không được chạy Cypher tự do trong production.

# Nguồn tham khảo và tính xác thực

SRC-01/SRC-02 là nội dung nghiên cứu do người dùng cung cấp. Những khẳng định từ tài liệu nghiên cứu được sử dụng như đầu vào thiết kế; các năng lực OSS chính thức đã đối chiếu được ghi tại các URL bên dưới (truy cập 12/11/2026). Chi tiết phụ thuộc phiên bản triển khai phải kiểm tra lại khi pin release.

\[SRC-01\] Tài liệu đầu vào: Đặc Tả Hệ Thống Rà Quét Lỗ Hổng AI.docx — Tệp do người dùng cung cấp; nguồn định hướng, không phải bằng chứng triển khai OSS.

\[SRC-02\] Tài liệu đầu vào: AEGIS-Vanguard HTML — Tệp HTML do người dùng cung cấp; bản thể hiện tương tác của nghiên cứu.

\[SRC-03\] LangGraph persistence — https://github.com/langchain-ai/docs/blob/main/src/oss/langgraph/persistence.mdx

\[SRC-12\] REA repository — https://github.com/morluto/rea

\[SRC-17\] CVE-2026-61732 primary record — https://www.cve.org/CVERecord?id=CVE-2026-61732

\[SRC-18\] Flowsint Graph Conductor proposal (not a released feature) — https://github.com/reconurge/flowsint/issues/133
