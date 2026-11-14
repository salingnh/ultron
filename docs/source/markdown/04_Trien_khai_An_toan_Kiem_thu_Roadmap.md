*Kubernetes • Threat Model • SLO • Runbooks • Test Plan • Backlog*

Phiên bản: 1.0 \| Ngày: 12/11/2026 \| Trạng thái: Thiết kế đề xuất

Phạm vi: hệ thống nội bộ, single-tenant; không yêu cầu đăng nhập người dùng ở MVP; giới hạn phạm vi thực thi và an toàn scanner vẫn bắt buộc.

| **Mục tiêu** | Nền tảng AI Agent điều phối đánh giá bề mặt tấn công và lỗ hổng có kiểm soát         |
|--------------|--------------------------------------------------------------------------------------|
| **Triết lý** | OSS-first • Capability-based • Durable campaigns • Evidence-first                    |
| **Nhóm đọc** | CTO • Security Architect • SOC • AppSec • Platform Engineering                       |
| **Căn cứ**   | Hai file nghiên cứu đầu vào; tài liệu chính thức OSS; quyết định kiến trúc của dự án |

# 1. Mô hình triển khai Kubernetes / on-prem

<img src="markdown/media/04_Trien_khai_An_toan_Kiem_thu_Roadmap/media/image1.png" style="width:6.5in;height:0.87434in" />

Hình 1. Ranh giới mạng, execution và data để triển khai cluster nội bộ.

| **Namespace / workload**              | **Replicas (MVP)** | **Nguồn lực và chính sách**                        |
|---------------------------------------|--------------------|----------------------------------------------------|
| aegis-control: web/api/registry       | 2/2/2              | Pod anti-affinity, private ingress, read-only fs   |
| aegis-orchestration: temporal workers | 2                  | Worker concurrency bounded; Temporal cluster riêng |
| aegis-agent: langgraph worker         | 2                  | No hostPath, no Docker socket, PG checkpoint       |
| aegis-execution: scanner Jobs         | 0..50              | ResourceQuota, seccomp, NetworkPolicy, TTL cleanup |
| aegis-data: PostgreSQL, Neo4j, MinIO  | HA tùy platform    | Backup/snapshots, restricted ingress               |
| aegis-observability: collector        | 2                  | OTel/Prometheus/Loki optional                      |

# 2. Scanner job execution contract

Execution Gateway chỉ nhận manifests từ registry đã duyệt; tạo Job với image digest cố định, service account không có API cluster privileges, allowPrivilegeEscalation=false, runAsNonRoot khi phù hợp, readOnlyRootFilesystem=true, drop ALL capabilities, seccomp RuntimeDefault. Các OSS yêu cầu raw socket cần đánh giá riêng và không mặc định bật privileged.

apiVersion: batch/v1

kind: Job

metadata:

name: aegis-scan-\<job-id\>

namespace: aegis-execution

spec:

ttlSecondsAfterFinished: 3600

backoffLimit: 1

template:

spec:

serviceAccountName: aegis-scanner-noapi

restartPolicy: Never

containers:

\- name: scanner

image: registry.internal/aegis/nmap@sha256:\<PIN\>

securityContext:

allowPrivilegeEscalation: false

capabilities: {drop: \["ALL"\]}

seccompProfile: {type: RuntimeDefault}

resources:

requests: {cpu: "250m", memory: "256Mi"}

limits: {cpu: "2", memory: "2Gi"}

\# Namespace ResourceQuota, Pod Security Admission và NetworkPolicy

\# phải được thiết lập riêng; manifest này chỉ minh họa fields quan trọng.

# 3. Threat model STRIDE và kiểm soát

| **Threat**             | **Bề mặt**                          | **Control**                                      |
|------------------------|-------------------------------------|--------------------------------------------------|
| Spoofing               | Fake job event / source attribution | Service mTLS, signed task IDs, event provenance  |
| Tampering              | Tool output/evidence changes        | SHA256, immutable storage, manifest signatures   |
| Repudiation            | Không chứng minh hoạt động agent    | Append-only audit + trace IDs + policy snapshot  |
| Information Disclosure | Source code, secrets, incident data | Object ACL, redaction, short-lived credentials   |
| Denial of Service      | Scanner overload / LLM loops        | Rate budget, timeout, circuit breaker, quotas    |
| Elevation of Privilege | Agent sandbox → control plane       | NetworkPolicy, no Docker.sock, no cluster-admin  |
| Prompt Injection       | Web content/README/tool output      | Untrusted boundary + deterministic policy checks |
| Supply Chain           | Malicious tool image/PoC/template   | Pin digest, allowlist, SBOM, template review     |

CVE-2026-61732 đã được công bố ngày 24/09/2026 liên quan đến role-boundary forgery trong output của Decepticon trước 1.1.17 \[SRC-17\]. Nó minh họa rõ nguy cơ prompt injection từ nội dung thu thập. Không chỉ dùng regex; cần tách vai trò data/instruction, output sanitation, typed parsing, no privileged tool exposure và policy enforcement độc lập. Việc đóng gói \<UNTRUSTED_TOOL_OUTPUT\> chỉ là defense-in-depth chứ không tạo ranh giới an toàn tuyệt đối.

# 4. Safety gates và xác minh có kiểm soát

| **Impact tier**          | **Ví dụ loại thao tác**                                    | **Quy trình**                                       |
|--------------------------|------------------------------------------------------------|-----------------------------------------------------|
| T0 Passive               | Read-only OSINT, parse local artifact                      | Tự động nếu scope hợp lệ                            |
| T1 Low-impact            | DNS, HTTP HEAD/GET, inventory                              | Rate limits + allowlist + blackout                  |
| T2 Active bounded        | Nmap service scan, curated Nuclei checks                   | Approve profile/campaign + resource ceiling         |
| T3 Intrusive             | State-changing dynamic validation, risky browser workflows | Manual approval + staging/lab + target-specific RoE |
| T4 Prohibited by default | Untrusted PoC execution, lateral movement, persistence     | Blocked; thay bằng metadata và lab simulation       |

# 5. Backup/restore, DR và dữ liệu quan trọng

| **Storage**          | **Backup**                                  | **Recovery objective thiết kế**              |
|----------------------|---------------------------------------------|----------------------------------------------|
| PostgreSQL           | Daily full + continuous WAL where supported | RPO ≤15 phút, RTO ≤2 giờ                     |
| Temporal persistence | DB backup consistent with deployment        | RPO/RTO theo backend Temporal                |
| Neo4j                | Supported backup/snapshot & periodic export | Rebuildable graph from event log; RPO ≤1 giờ |
| MinIO                | Versioning, replication hoặc backup bucket  | RPO ≤1 giờ; verify hashes                    |
| Registry/Policies    | GitOps declarative + signed release         | Reproducible rollout                         |

Các chỉ tiêu RPO/RTO là mục tiêu đề xuất, cần kiểm tra với hạ tầng và khối lượng dữ liệu thật. Restore drill tối thiểu hàng quý; test đối soát finding count, graph revision và evidence hashes sau phục hồi.

# 6. SLO / capacity và kịch bản load

| **SLI/SLO**       | **Mục tiêu gợi ý**                   | **Đo lường**                |
|-------------------|--------------------------------------|-----------------------------|
| API availability  | ≥99.5% tháng trong môi trường nội bộ | Synthetic health + alerts   |
| Campaign recovery | ≤5 phút sau worker restart           | Chaos test process/pod kill |
| Job queue delay   | P95 \<2 phút tại ≤50 jobs concurrent | Queue metrics               |
| Registry lookup   | P95 \<300ms @100 providers           | Benchmark synthetic         |
| Ingestion latency | P95 \<30s cho output nhỏ (\<1MB)     | End-to-end tracing          |
| Data integrity    | 0 duplicate idempotency key jobs     | Replay soak test            |
| Trace coverage    | 100% jobs có ID/provenance/error     | Audit query                 |

# 7. Test strategy và acceptance gates

| **Test suite**    | **Kịch bản**                                      | **Pass criteria**                                 |
|-------------------|---------------------------------------------------|---------------------------------------------------|
| Unit              | Normalize domain/url/purl and score               | Known fixtures expected outputs                   |
| Contract          | CLI/REST/MCP/SubAgent adapters                    | All interface methods and negative inputs pass    |
| Integration       | Domain→service→artifact→finding                   | Evidence-backed graph relationships               |
| Failure injection | Kill pod mid scan, temporal replay, loss of queue | No lost campaign progress / duplicate jobs        |
| 7-day soak        | 10k orchestration steps, 50+ jobs concurrent      | Bounded memory/CPU; recovery proof                |
| Security          | Prompt injection, target escape, DNS rebinding    | No unauthorized job execution                     |
| Privacy           | Secret in web bundle or code output               | No secret plaintext in graph/prompt/log           |
| Regression        | Adapter version bump, license check               | Golden outputs unchanged or migration plan        |
| Performance       | Large 10GB artifacts; 1M nodes                    | Queue/backpressure and ingestion within tuned SLO |

# 8. Operator runbooks

| **Tình huống**            | **Thao tác vận hành**                              | **Kết quả phải báo**                                 |
|---------------------------|----------------------------------------------------|------------------------------------------------------|
| Agent không tiến triển    | Pause; inspect novelty, budget, pending jobs       | last useful delta, root cause, recommended next step |
| Nhiều scanner thất bại    | Check adapter health, worker resource, route/proxy | counts by error class; retry policy                  |
| Graph ingest xung đột     | Inspect unique collisions, DLQ, replay events      | Record IDs affected; zero evidence loss              |
| LLM provider 429/outage   | Route fallback nếu được phép hoặc wait             | Provider, cost impact, incomplete work               |
| Nghi ngờ prompt injection | Quarantine artifact, audit tool-output path        | Impact boundary / containment / affected campaign    |
| Mất DB/Temporal           | Stop new jobs, restore, reconcile external jobs    | Recovery point, missing refs, audit trail            |

# 9. Observability và dashboard

Dashboard vận hành hiển thị Campaign Overview (status, elapsed, budgets, latest delta), Job Map (provider/asset/state/error), Knowledge Growth (new assets/relationships/findings by cycle), Safety (denied requests, scope escapes), AI (turn count, tokens, model route, decision uncertainty), Findings (candidate/corroborated/verified/fixed). Mọi chart cần drilldown về source evidence và nguyên nhân thay đổi trạng thái.

# 10. Backlog triển khai được phân rã

| **Sprint / Epic**   | **Tickets ưu tiên**                                                     | **Definition of Done**                       |
|---------------------|-------------------------------------------------------------------------|----------------------------------------------|
| S1 Contracts        | RoE schema, manifest v1, result envelope, event schema                  | OpenAPI/JSON schemas, fixtures, schema tests |
| S2 Durable engine   | Temporal server + workers; campaign CRUD/signals; LangGraph PG saver    | Resume test restart pod                      |
| S3 Tool gateway     | Adapter SDK, K8s job runner, scope validator, quotas                    | CLI scanner runs only in allowed subnet      |
| S4 Data graph       | Canonical identity, ingestion, evidence object store, Neo4j constraints | Idempotent upsert verified under concurrency |
| S5 Discovery        | Subfinder, Nmap, httpx, Nuclei adapters                                 | Domain→finding demo with provenance          |
| S6 Supply chain     | Syft, Trivy, CVE/KEV/EPSS feed adapters                                 | Image→pURL→CVE correlation demo              |
| S7 Reasoning        | Planner/context builder/hypothesis ledger/delta evaluator               | No-loop evaluation; bounded budgets          |
| S8 UI & reports     | Campaign/job list, graph neighborhood, findings export                  | Operators see failures and pending work      |
| S9 Reverse pipeline | Flowsint pivots, JS static analysis, REA sandbox                        | Artifact→new endpoint→follow-up demo         |
| S10 Hardening       | Chaos, prompt injection tests, backup/restore, 7d soak                  | Security sign-off / SLO pass                 |
| S11 Advanced        | Strix/Decepticon adapters with approval gates                           | Only after separate threat model and pilot   |

# 11. RACI tổ chức thực hiện

| **Vai trò**              | **Trách nhiệm**                                          |
|--------------------------|----------------------------------------------------------|
| Product Owner / SOC Lead | Ưu tiên use case, policy và nghiệm thu nghiệp vụ         |
| Solution Architect       | System boundaries, ADRs, architecture review             |
| AI/Agent Engineer        | LangGraph graph, model routing, evaluation               |
| Platform Engineer        | Temporal, K8s execution, CI/CD, observability            |
| Backend Engineer         | Registry/API, job state, ingestion                       |
| Data/Graph Engineer      | Ontology, entity resolution, graph queries               |
| AppSec Engineer          | Tool vetting, scan profiles, test fixtures, verification |
| QA/SRE                   | Chaos, performance, security gate, recovery drill        |

# 12. Go-live checklist

- RoE định nghĩa rõ mạng, tên miền, repositories, owners, blackout, rate và impact tiers.

- API chỉ có thể truy cập qua private ingress; service credentials & encrypted storage hoạt động.

- Không container nào của agent/scanner có Docker socket hoặc quyền cluster-admin.

- Images và versions được pin; license/attribution record được duyệt.

- Evidence được kiểm tra SHA256; secrets mask đúng trong log/report/prompt.

- Có thể replay Temporal/worker restart mà không tạo duplicate jobs.

- Agent tự dừng khi hết budget hoặc không còn novelty; ghi rõ chưa hoàn thành.

- Có dashboard lỗi, alert on failures và runbooks đã diễn tập.

- Có bộ dataset kiểm thử độc lập với source nghiên cứu và báo cáo kết quả.

# 13. Ma trận các giả định / quyết định chưa khóa

| **Vấn đề**         | **Quyết định hiện tại** | **Khi nào xem xét lại**                                  |
|--------------------|-------------------------|----------------------------------------------------------|
| User auth          | Không ở MVP             | Khi mở truy cập đa nhóm/người ngoài private network      |
| Multi-tenant       | Không                   | Khi phục vụ tổ chức/đơn vị độc lập                       |
| Graph Conductor    | Tự xây Ingestion API    | Nếu upstream có stable shipped component được kiểm chứng |
| GUAC               | P1 optional             | Khi cần lineage/SLSA/VEX scale lớn                       |
| Strix/Decepticon   | P2 approval-gated       | Khi sandbox+ethics+RoE đã đạt test                       |
| Temporal HA sizing | Theo infra sẵn có       | Sau load test 7 ngày / 10k steps                         |

# Nguồn tham khảo và tính xác thực

SRC-01/SRC-02 là nội dung nghiên cứu do người dùng cung cấp. Những khẳng định từ tài liệu nghiên cứu được sử dụng như đầu vào thiết kế; các năng lực OSS chính thức đã đối chiếu được ghi tại các URL bên dưới (truy cập 12/11/2026). Chi tiết phụ thuộc phiên bản triển khai phải kiểm tra lại khi pin release.

\[SRC-01\] Tài liệu đầu vào: Đặc Tả Hệ Thống Rà Quét Lỗ Hổng AI.docx — Tệp do người dùng cung cấp; nguồn định hướng, không phải bằng chứng triển khai OSS.

\[SRC-02\] Tài liệu đầu vào: AEGIS-Vanguard HTML — Tệp HTML do người dùng cung cấp; bản thể hiện tương tác của nghiên cứu.

\[SRC-03\] LangGraph persistence — https://github.com/langchain-ai/docs/blob/main/src/oss/langgraph/persistence.mdx

\[SRC-04\] LangGraph Graph API / recursion — https://github.com/langchain-ai/docs/blob/main/src/oss/langgraph/graph-api.mdx

\[SRC-05\] Temporal Event History — https://docs.temporal.io/encyclopedia/event-history

\[SRC-06\] Temporal Workflows — https://docs.temporal.io/workflows

\[SRC-10\] Decepticon repository — https://github.com/BitterSecurity/Decepticon

\[SRC-12\] REA repository — https://github.com/morluto/rea

\[SRC-13\] Strix repository — https://github.com/usestrix/strix

\[SRC-15\] Nuclei repository — https://github.com/projectdiscovery/nuclei

\[SRC-16\] Syft repository — https://github.com/anchore/syft

\[SRC-17\] CVE-2026-61732 primary record — https://www.cve.org/CVERecord?id=CVE-2026-61732

\[SRC-18\] Flowsint Graph Conductor proposal (not a released feature) — https://github.com/reconurge/flowsint/issues/133
