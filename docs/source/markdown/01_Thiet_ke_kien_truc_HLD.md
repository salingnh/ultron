*Logical Architecture • Agent Harness • Durable Campaign • Security Boundaries*

Phiên bản: 1.0 \| Ngày: 12/11/2026 \| Trạng thái: Thiết kế đề xuất

Phạm vi: hệ thống nội bộ, single-tenant; không yêu cầu đăng nhập người dùng ở MVP; giới hạn phạm vi thực thi và an toàn scanner vẫn bắt buộc.

| **Mục tiêu** | Nền tảng AI Agent điều phối đánh giá bề mặt tấn công và lỗ hổng có kiểm soát         |
|--------------|--------------------------------------------------------------------------------------|
| **Triết lý** | OSS-first • Capability-based • Durable campaigns • Evidence-first                    |
| **Nhóm đọc** | CTO • Security Architect • SOC • AppSec • Platform Engineering                       |
| **Căn cứ**   | Hai file nghiên cứu đầu vào; tài liệu chính thức OSS; quyết định kiến trúc của dự án |

# 1. Kiến trúc tham chiếu và ranh giới dịch vụ

Sơ đồ tổng thể phân hệ giữ ba mặt phẳng logic: Control Plane (UI/API, planning, governance), Execution Plane (isolated scanner jobs) và Data/Knowledge Plane. Khác nghiên cứu gốc \[SRC-01\], Neo4j không dual-home trực tiếp cho sandbox; scanner chỉ gửi kết quả tới Ingestion API. Cách này giảm bề mặt truy cập và bảo đảm chuẩn hóa trước khi ghi graph.

<img src="markdown/media/01_Thiet_ke_kien_truc_HLD/media/image1.png" style="width:6.5in;height:0.87434in" />

Hình 1. Bố trí triển khai và đường lưu thông dữ liệu được phép.

| **Service**             | **Vai trò**                                                  | **Scale/State**                   |
|-------------------------|--------------------------------------------------------------|-----------------------------------|
| UI + Backend API        | Tạo campaign, dashboards, graph query, report, policy config | Stateless replicas; PostgreSQL    |
| Campaign Controller     | Temporal Workflows, pause/resume, events, timers, fanout     | Temporal durable state            |
| Agent Runtime           | LangGraph Planner/Analyst/Verifier; checkpoint per session   | Ephemeral worker + PG checkpoints |
| Registry/Policy Gateway | Capability matching, safe profiles, validation               | Stateless; config versioned       |
| Execution Gateway       | Job dedup, Kubernetes Jobs, resource limits                  | PostgreSQL job table + K8s        |
| Ingestion/Normalizer    | Parse raw output, schema validation, entity resolution       | Idempotent consumer               |
| Graph Query API         | Read-only graph patterns, bounded queries                    | Neo4j constrained queries         |
| Intel Fetchers          | NVD/OSV/KEV/EPSS delta sync + cache                          | Batch/scheduled workers           |
| Reporting               | Finding lifecycle, delta, SARIF/JSON/HTML, PR suggestions    | Stateless report workers          |

# 2. Agent harness: LangGraph

Một agent session xử lý objective hữu hạn, thường một nhóm giả thuyết và dữ liệu delta. Graph node gợi ý: BuildContext → Plan → SelectCapabilities → ValidatePlan → Dispatch → Await/Receive → Analyze → Evaluate → Finish. Không giữ toàn bộ log scanner trong context. LangGraph checkpointer dùng thread_id gắn session_id; long-term memory nằm ngoài state \[SRC-03, SRC-04\].

| **Graph node** | **Input**                      | **Output**         | **Đảm bảo**                     |
|----------------|--------------------------------|--------------------|---------------------------------|
| BuildContext   | Objective + graph delta + RoE  | ContextBundle v1   | Giới hạn token và trace sources |
| Planner        | Context + capability summaries | TaskPlan JSON      | JSON Schema / bounded breadth   |
| PolicyCheck    | Plan + RoE + target ownership  | ApprovedTask\[\]   | Deterministic deny by default   |
| ToolSelect     | Task + registry search         | ProviderSelection  | Provider version pinned         |
| ReviewResult   | Normalized outputs             | HypothesisUpdates  | Confidence/evidence required    |
| DecideNext     | Progress metrics + budgets     | continue/wait/stop | Deterministic stopping criteria |

# 3. Temporal: vòng đời chiến dịch bền vững

<img src="markdown/media/01_Thiet_ke_kien_truc_HLD/media/image2.png" style="width:6.5in;height:0.78993in" />

Hình 2. Một campaign gồm các chu kỳ agent ngắn và scanner jobs bất đồng bộ.

CampaignWorkflow là nguồn sự thật về trạng thái dài hạn. Mỗi agent session được chạy như Temporal Activity (hoặc child workflow nếu cần), được timeout và retry có kiểm soát. Scan jobs sử dụng lệnh dispatch idempotent; Temporal chỉ giữ job_id/output URI, không lưu log lớn trong history. Periodic Continue-As-New tránh Event History tăng vô hạn \[SRC-05, SRC-06\].

CampaignWorkflow(campaign_id):

while campaign_is_active:

delta = fetch_unprocessed_knowledge_delta(campaign_id)

plan = run_agent_session(delta, bounded_steps=30)

validated = enforce_policy(plan, snapshot_policy_version)

job_ids = dispatch_idempotent(validated)

outcomes = await_job_events_or_timer(job_ids)

ingest_evidence_refs(outcomes)

evaluate_progress_and_budgets()

if should_continue_as_new(): continue_as_new(campaign_id, cursor)

publish_final_snapshot()

# 4. State machines và failure recovery

| **Thực thể**  | **Trạng thái**                                                                     | **Chuyển tiếp quan trọng**                                      |
|---------------|------------------------------------------------------------------------------------|-----------------------------------------------------------------|
| Campaign      | CREATED, RUNNING, WAITING, PAUSED, COMPLETED, FAILED, CANCELLED                    | Pause giữ jobs theo chính sách; cancel phát tín hiệu đến worker |
| Agent Session | QUEUED, RUNNING, CHECKPOINTED, WAITING, DONE, FAILED                               | Resume từ LangGraph checkpoint; side effect idempotent          |
| Scan Job      | QUEUED, VALIDATING, DISPATCHED, RUNNING, COLLECTING, SUCCEEDED, FAILED, CANCELLED  | Timeout/retry và reconcile K8s trạng thái                       |
| Finding       | CANDIDATE, CORROBORATED, VERIFIED, FALSE_POSITIVE, ACCEPTED_RISK, FIXED, REGRESSED | Mọi thay đổi lưu người/nguồn, thời điểm, evidence               |

Không nhầm “workflow replay” của Temporal với chạy lại công cụ. Activity có thể được retry; do đó Execution Gateway bắt buộc có unique(job_fingerprint) theo campaign/policy/provider/asset/scan_profile, và kiểm tra Job tồn tại trước khi tạo K8s Job mới.

# 5. Continuous feedback and event-driven orchestration

| **Event**              | **Producer**      | **Consumer**               | **Hệ quả**                           |
|------------------------|-------------------|----------------------------|--------------------------------------|
| asset.discovered.v1    | Normalizer        | Graph, planner queue       | Tạo delta nếu canonical asset mới    |
| observation.changed.v1 | Normalizer        | Correlation engine         | Cập nhật công nghệ, reachability     |
| artifact.ready.v1      | Artifact service  | REA/Syft adapter           | Phân tích khi artifact trong scope   |
| intel.updated.v1       | Intel sync        | Vulnerability matcher      | Re-evaluate findings liên quan       |
| job.completed.v1       | Execution gateway | Temporal signal            | Tiếp tục campaign không busy polling |
| finding.confirmed.v1   | Verifier          | Reporting / ticket adapter | Tạo report và rescan plan            |

# 6. Khả năng độc lập của OSS

<img src="markdown/media/01_Thiet_ke_kien_truc_HLD/media/image3.png" style="width:6.2in;height:3.88418in" />

Hình 3. Một capability nhiều provider, một output contract.

Registry chỉ công bố các capability cấp nghiệp vụ vào agent. CLI wrappers dùng JSONL/stdout parser; HTTP adapters dùng REST polling/webhook; MCP adapters dùng client an toàn và lựa chọn tools động; sub-agent adapters (Strix/Decepticon) xem cả phiên chạy như một job có status/result. MCP là giao thức giao tiếp, KHÔNG thay cho job scheduler, schema canon hay policy.

# 7. Sandboxing, trust boundaries, network segmentation

| **Boundary**              | **Cho phép**                                  | **Cấm / kiểm soát**                                     |
|---------------------------|-----------------------------------------------|---------------------------------------------------------|
| Browser/UI → API          | Ingress mạng nội bộ/VPN                       | Không public internet; không cần login chỉ ở MVP        |
| Agent → Tool Gateway      | Gọi capability theo contract                  | Không shell trực tiếp, không quyền cluster-admin        |
| Gateway → Scanner workers | K8s Jobs theo image allowlist                 | Không docker.sock, hostPath, privileged                 |
| Scanner → Targets         | CIDR/host allowlist, rate/time windows        | Không mở rộng từ DNS sang IP ngoài scope                |
| Scanner → Data            | Upload signed result URI / ingestion endpoint | Không truy cập trực tiếp Neo4j/PostgreSQL               |
| Ingestion → Graph         | Parameterized upsert + dedup                  | Không raw Cypher do LLM sinh                            |
| External feeds → AI       | Metadata đã parse/label untrusted             | Không coi nội dung website/README là system instruction |

# 8. AI model routing và quản lý ngân sách

| **Nhóm tác vụ**                    | **Model profile** | **Context / quality control**                 |
|------------------------------------|-------------------|-----------------------------------------------|
| Classification / simple extraction | LOW               | Structured output, test trên dataset          |
| Planning / correlation             | MID               | Limited registry search + citations           |
| Complex code reasoning             | HIGH              | Evidence references, independent verification |
| Final reporting                    | MID/HIGH          | No ungrounded claims; report schema           |

LiteLLM (hoặc model gateway tương đương) đứng sau ModelClient interface, tránh khóa cứng model/provider. Budget của campaign gồm token, spend, scanner count, wall-clock, active-target concurrency và delta novelty. Ngưỡng dừng thực thi nằm trong mã ứng dụng, không phải chỉ do prompt.

# 9. Context management và long-term memory

- Working context: objective hiện tại, 10–30 observations quan trọng nhất, tools phù hợp và policy snapshot.

- Campaign ledger: completed objectives, pending hypotheses, blockers, scan job refs, graph revision/cursor, remaining budgets.

- Knowledge memory: graph asset, packages, vulnerabilities, observations, evidences có provenance và TTL.

- No raw logs in prompt: lưu MinIO, rút gọn qua deterministic parser; LLM chỉ nhận summaries kèm URI/trích đoạn và độ tin cậy.

- Stale data: observation có first_seen/last_seen/expiry; scan result cũ phải có label stale trước khi dùng để suy luận.

# 10. Cơ chế chống vòng lặp vô nghĩa

ProgressScore đề xuất = 0.35×new_assets + 0.25×new_verified_findings + 0.20×resolved_hypotheses + 0.20×new_relationships, các thành phần chuẩn hóa trong \[0,1\] trên cửa sổ chu kỳ. Đây là heuristic THIẾT KẾ cần hiệu chỉnh, không phải thuật toán OSS có sẵn. Nếu 3–5 chu kỳ liên tiếp không có evidence mới hữu ích, workflow giảm cấp hoặc tạm dừng và ghi lý do. Không tự động quét ngoài scope để tăng điểm novelty.

# 11. Quan sát vận hành và traceability

Mọi log/event/trace liên kết bằng campaign_id, session_id, objective_id, job_id, capability_id, provider_version, policy_version, evidence_id. Metrics: agent_turns, tokens, cost, pending_jobs, retry_rate, normalization_errors, graph_upsert_conflicts, scanner_target_rate, policy_denials, mean_time_to_first_finding, scan_novelty. Trace model decisions không chứa plaintext secrets; audit log thể hiện công cụ đã chạy, mục tiêu, thời gian và kết quả thành công/thất bại.

# 12. ADR chi tiết và các trade-off

| **ADR** | **Chọn**                                             | **Không chọn / lý do**                                  |
|---------|------------------------------------------------------|---------------------------------------------------------|
| HLD-001 | Temporal điều phối campaign; LangGraph micro-session | Không một LangGraph run chạy nhiều ngày không phân đoạn |
| HLD-002 | Central ingestion API đến Neo4j                      | Không dual-home Neo4j với vùng scanner                  |
| HLD-003 | Cap registry với SDK và conformance                  | Không nạp vài trăm MCP tools vào một prompt             |
| HLD-004 | K8s batch jobs + HPA worker pool                     | Không giao shell và Docker socket cho LLM               |
| HLD-005 | Metadata-level PoC discovery                         | Không tự thực thi mã PoC Internet trên production       |
| HLD-006 | No user login MVP / network protected                | Không xem “internal” là đủ để bỏ scope/audit            |

# 13. Rủi ro kiến trúc còn mở

| **Open item**                      | **Người chịu trách nhiệm** | **Quyết định / thử nghiệm cần làm**                         |
|------------------------------------|----------------------------|-------------------------------------------------------------|
| LangGraph/Temporal session nesting | Platform lead              | Spike replay + activity cancellation                        |
| Flowsint Enricher extraction       | OSS integration lead       | Đánh giá import library so với API facade                   |
| REA tool catalog compression       | Reverse lead               | Đo context size thực tế trên version pin                    |
| Strix sandbox semantics            | AppSec lead                | Kiểm tra noninteractive result mapping + policy enforcement |
| Graph identity collisions          | Data lead                  | Benchmark upserts đồng thời 100 workers                     |

# Nguồn tham khảo và tính xác thực

SRC-01/SRC-02 là nội dung nghiên cứu do người dùng cung cấp. Những khẳng định từ tài liệu nghiên cứu được sử dụng như đầu vào thiết kế; các năng lực OSS chính thức đã đối chiếu được ghi tại các URL bên dưới (truy cập 12/11/2026). Chi tiết phụ thuộc phiên bản triển khai phải kiểm tra lại khi pin release.

\[SRC-01\] Tài liệu đầu vào: Đặc Tả Hệ Thống Rà Quét Lỗ Hổng AI.docx — Tệp do người dùng cung cấp; nguồn định hướng, không phải bằng chứng triển khai OSS.

\[SRC-02\] Tài liệu đầu vào: AEGIS-Vanguard HTML — Tệp HTML do người dùng cung cấp; bản thể hiện tương tác của nghiên cứu.

\[SRC-03\] LangGraph persistence — https://github.com/langchain-ai/docs/blob/main/src/oss/langgraph/persistence.mdx

\[SRC-04\] LangGraph Graph API / recursion — https://github.com/langchain-ai/docs/blob/main/src/oss/langgraph/graph-api.mdx

\[SRC-05\] Temporal Event History — https://docs.temporal.io/encyclopedia/event-history

\[SRC-06\] Temporal Workflows — https://docs.temporal.io/workflows

\[SRC-07\] Flowsint repository — https://github.com/reconurge/flowsint

\[SRC-08\] Flowsint enrichers — https://github.com/reconurge/flowsint/blob/main/docs/getting-started/enrichers.mdx

\[SRC-10\] Decepticon repository — https://github.com/BitterSecurity/Decepticon

\[SRC-11\] Decepticon package boundary — https://github.com/BitterSecurity/Decepticon/blob/main/packages/decepticon/README.md

\[SRC-12\] REA repository — https://github.com/morluto/rea

\[SRC-13\] Strix repository — https://github.com/usestrix/strix

\[SRC-17\] CVE-2026-61732 primary record — https://www.cve.org/CVERecord?id=CVE-2026-61732

\[SRC-18\] Flowsint Graph Conductor proposal (not a released feature) — https://github.com/reconurge/flowsint/issues/133
