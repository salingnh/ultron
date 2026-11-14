# ARCHITECTURE: AEGIS–Vanguard

> Kiến trúc rút gọn cho AI agent. Nguồn chuẩn: [docs/living/dac-ta-ky-thuat/](docs/living/dac-ta-ky-thuat/README.md) (đặc biệt tab Nền tảng và Dữ liệu, API, sự kiện). Mã module M01–M28, tên sự kiện và tên endpoint phải dùng **đúng như đặc tả**.

## 1. Công nghệ sử dụng

| Lớp | Công nghệ | Trạng thái |
| --- | --- | --- |
| Điều phối dài hạn | **Temporal** (CampaignWorkflow, Activity idempotent, Continue-As-New) | Đã chốt |
| Suy luận agent | **LangGraph** (Planner, Analyst, Verifier), checkpoint trên PostgreSQL | Đã chốt |
| Nguồn sự thật | **PostgreSQL** | Đã chốt |
| Đồ thị tri thức | **Neo4j** (chiếu lại được từ PostgreSQL) | Đã chốt |
| Bằng chứng thô | **MinIO** (SHA-256, signed URL, versioning/object lock) | Đã chốt |
| Chạy công cụ quét | **Podman** rootless, mỗi lần gọi một container, sau interface `ContainerRunner`. Kubernetes để sau | Đã chốt |
| Giao tiếp agent–công cụ | **MCP** server duy nhất (Registry + điểm kiểm + bộ chạy) | Đã chốt |
| LLM | `ModelClient` tự dựng, driver chuẩn OpenAI Chat Completions và Anthropic Messages; profile LOW/MID/HIGH | Đã chốt |
| Quan sát | **OpenTelemetry** (Prometheus, Loki tùy chọn) | Đã chốt |
| Giao diện | **React + TypeScript + Vite**, **React Flow** (ELK/dagre) cho luồng quét, **Cytoscape.js** cho đồ thị (Sigma.js nếu quá lớn), SSE cho thời gian thực | Đã chốt |
| Cảnh báo | Telegram Bot API | Đã chốt |
| Ngôn ngữ backend | **Python** (vì LangGraph và Temporal Python SDK) | *Đề xuất, khóa ở epic S1* |
| Bus sự kiện | Bảng outbox trong PostgreSQL + Temporal signal; chưa cần message broker | Đã chốt cho MVP |

## 2. Ba mặt phẳng và bốn vùng mạng

```
            ┌──────────────────────── Mạng điều khiển ────────────────────────┐
 Người dùng │ Web UI (M26) ─ REST /api/v1 + SSE ─ Backend API                  │
 (VPN /     │ Temporal worker (M01, M02)   LangGraph worker (M03) ─ M04 → LLM  │
  private   │ MCP server: Registry + điểm kiểm (M05) → bộ chạy (M06)           │
  ingress)  │ Ingestion API (M27) · Graph Query API (M23) · OTel collector     │
            └───────────────┬─────────────────────────────────┬────────────────┘
                            │ chỉ vùng điều khiển vào được    │ tạo container
            ┌───────────────▼────────────┐   ┌────────────────▼──────────────────┐
            │ Mạng dữ liệu               │   │ Mạng thực thi (chỉ đi ra ngoài)   │
            │ PostgreSQL · Neo4j · MinIO │   │ Container scanner, 1 lần gọi = 1  │
            │ Temporal server            │   │ container; KHÔNG vào mạng dữ liệu │
            └────────────────────────────┘   └───────────────────────────────────┘
```

Ràng buộc cứng:
- **Scanner không bao giờ ghi thẳng vào cơ sở dữ liệu.** Kết quả ghi vào thư mục riêng của container, bằng chứng tải lên MinIO qua signed URL, rồi `ResultEnvelope` đi qua **Ingestion API (M27)**, cửa ghi duy nhất.
- **Agent đọc đồ thị chỉ qua truy vấn đã đăng ký** (`get_asset_neighbors`, `get_recent_observations`, `get_unverified_hypotheses`, `get_package_cve_matches`, `summarize_campaign_delta`, `get_evidence_excerpt`), có giới hạn bước nhảy, số bản ghi, thời gian, luôn lọc theo chiến dịch.

## 3. Luồng dữ liệu chính

### 3.1 Vòng lặp chiến dịch (Temporal ngoài, LangGraph trong)

```text
CampaignWorkflow(campaign_id):
  while campaign_is_active:
    delta     = fetch_unprocessed_knowledge_delta(campaign_id)
    plan      = run_agent_session(delta, bounded_steps=30)        # LangGraph, JSON
    validated = enforce_policy(plan, snapshot_policy_version)     # M05, mã, không phải LLM
    job_ids   = dispatch_idempotent(validated)                    # M06, Podman
    outcomes  = await_job_events_or_timer(job_ids)                # signal job.completed.v1
    ingest_evidence_refs(outcomes)                                # M27 → PG → Neo4j
    evaluate_progress_and_budgets()                               # dừng nếu 3–5 chu kỳ không có gì mới
    if should_continue_as_new(): continue_as_new(campaign_id, cursor)
  publish_final_snapshot()
```

### 3.2 Đường đi của một kết quả quét

agent đề xuất capability (vd `network.discover_services`) → MCP server → điểm kiểm M05 (kiểm schema, tốc độ, khung giờ; ghi mục tiêu và lý do) → M06 tạo container Podman (image theo digest) → container ghi kết quả → MinIO (bằng chứng, SHA-256) → `POST /api/v1/ingestion/results` (ResultEnvelope) → M27 kiểm schema và checksum, dedup, upsert PostgreSQL trong giao dịch → projector M23 `MERGE` sang Neo4j bằng Cypher tham số hóa → phát `asset.discovered.v1`, `observation.changed.v1`, `knowledge.delta.v1` → M02/M03 đọc delta cho vòng sau.

### 3.3 Cảnh báo sớm không cần quét lại

M18 đồng bộ NVD, OSV, KEV, EPSS → `intel.revision.v1` → M20 đánh giá lại có chọn lọc các tài sản bị ảnh hưởng → `finding.changed.v1` → M24 gửi Telegram theo template.

## 4. Danh mục module

**Lõi (tự xây, 17):** M01 Campaign và RoE · M02 Campaign Controller · M03 Agent Harness · M04 LLM Gateway · M05 Capability Registry và điểm kiểm · M06 Execution Gateway · M27 Ingestion và Normalizer · M07 Asset Inventory · M23 Knowledge Graph và Delta · M28 Evidence Store · M18 Vuln Feed Sync · M19 PoC Availability Index · M20 Correlation và Scoring · M21 Evidence Verification · M26 Web UI và Backend API · M24 Reporting và Remediation · M25 Telemetry và Audit.

**Kết nối OSS (11, bọc bằng adapter, không fork):** M08 Domain và ASN (Subfinder, asnmap, BBOT, SpiderFoot-ng, nguồn tự dựng) · M09 DNS/IP/Port (DNSx, Naabu, Nerva, cdncheck, Nmap) · M10 Web (httpx, Katana, Nuclei, tlsx, urlfinder) · M13 SBOM (Trivy, Syft) · M14 Vulns (Trivy, Grype, OSV-Scanner) · M15 JS (webcrack, jsluice) · M16 Binary (bộ giải nén tự dựng; REA tùy chọn) · M12 Code (Opengrep, Gitleaks) · M17 Secret (Gitleaks, TruffleHog, Betterleaks) · M11 Config (Prowler, Kubescape, kube-bench) · M22 SubAgent (để sau).

Bản đồ trực quan: [docs/living/04-ban-do-module.html](docs/living/04-ban-do-module.html).

## 5. Hợp đồng chung (chốt ở epic S1)

- **CapabilityProvider manifest** (`apiVersion: aegis.io/v1`): capability, image digest, input/output schema ref, permissions, safety profile, budget, handlers `validate/execute/status/cancel/collect`.
- **ResultEnvelope**: `schema_version`, `job_id`, `campaign_id`, `capability`, `provider`, `policy_version`, `status`, `results{assets, observations, relationships, findings}`, `evidence[{sha256, uri, classification}]`, `errors`, `provenance`.
- **Adapter SDK**: `describe, validate, start, status, cancel, collect, health`. Năm cấp tích hợp L0 import file → L1 CLI trong container → L2 REST → L3 MCP whitelist → L4 sub-agent (để sau). MVP dùng L0–L2.
- **Khóa định danh chuẩn**: `dns:<fqdn>`, `ip:<ip>`, `service:<ip>:<port>/<transport>`, `url:<…>`, `oci:sha256:<digest>`, `git:<repo>@<sha>`, `purl:<purl>`, `cloud:<provider>:<account>:<region>:<type>/<id>`, `k8s:<cluster>/<ns>/<kind>/<name>`. Tag và branch chỉ là alias.
- **Sự kiện v1**: `job.started.v1`, `job.completed.v1`, `policy.denied.v1`, `asset.discovered.v1`, `observation.changed.v1`, `artifact.ready.v1`, `knowledge.delta.v1`, `intel.revision.v1`, `finding.changed.v1`. Consumer idempotent, at-least-once.
- **Mã lỗi chuẩn**: INPUT_INVALID, OUT_OF_SCOPE, APPROVAL_REQUIRED, POLICY_DENIED, RATE_LIMITED, TOOL_UNAVAILABLE, DEPENDENCY_MISSING, NETWORK_TIMEOUT, EXECUTION_TIMEOUT, RESOURCE_LIMIT, OUTPUT_INVALID, EVIDENCE_INCOMPLETE, CANCELLED, INTERNAL_ERROR.
- **Vòng đời finding**: CANDIDATE → CORROBORATED → VERIFIED → FALSE_POSITIVE / ACCEPTED_RISK / FIXED → REGRESSED.
- **REST** dưới `/api/v1`, POST tạo tài nguyên bắt buộc `Idempotency-Key`, phân trang theo cursor. Danh sách endpoint: tab Dữ liệu, API và sự kiện, mục 4.

## 6. Cấu trúc thư mục (đề xuất, khóa ở S1)

Repo hiện mới có tài liệu. Cấu trúc dưới là đề xuất ban đầu để các subagent làm song song theo năm luồng việc; thay đổi phải qua agent review kiến trúc.

```
/
├── PRD.md ARCHITECTURE.md DESIGN.md RULES.md TASKS.md PROGRESS.md AGENTS.md CLAUDE.md
├── docs/                    # tài liệu dự án (living/ là chuẩn, source/ là tham khảo)
├── contracts/               # S1: JSON Schema, OpenAPI v1, schema sự kiện, schema công cụ MCP, fixture
├── services/
│   ├── orchestrator/        # M01, M02 (Temporal workflow, activity)
│   ├── agent/               # M03 (LangGraph), M04 (ModelClient)
│   ├── mcp-server/          # M05 Registry + điểm kiểm, M06 ContainerRunner
│   ├── ingestion/           # M27
│   ├── knowledge/           # M07, M23 (projector, graph query), M28
│   ├── intel/               # M18, M19, M20, M21
│   ├── reporting/           # M24
│   └── api/                 # M26 backend, REST + SSE
├── adapters/<module>/<tool>/   # manifest.yaml, parser, fixtures/, conformance test
├── web/                     # M26 frontend (React, TS, Vite)
├── deploy/                  # compose cho Temporal, PostgreSQL, Neo4j, MinIO; mạng; registry
├── observability/           # M25: cấu hình OTel, dashboard
└── tests/                   # e2e, chaos, prompt injection, lab
```

Luồng việc và quyền sửa: điều phối và agent (M01–M04); cổng công cụ và adapter (M05, M06, M08–M17); dữ liệu và đồ thị (M07, M23, M27, M28); tình báo và đánh giá (M18–M21, M24); giao diện và vận hành (M25, M26). Sửa ngoài luồng của mình cần agent review kiến trúc đồng ý.

## 7. Lưu trữ và phục hồi

| Kho | Lưu gì | Mục tiêu |
| --- | --- | --- |
| PostgreSQL | Campaign, policy, job, finding, `FindingRun`, observation, outbox, audit, checkpoint LangGraph | RPO 15 phút, RTO 2 giờ |
| Neo4j | Đồ thị tài sản, quan hệ có thời gian | RPO 1 giờ; dựng lại được từ PostgreSQL |
| MinIO | Bằng chứng `evidence/{campaign_id}/{job_id}/{sha256}` | RPO 1 giờ; kiểm hash sau phục hồi |

Mọi dữ liệu lưu vĩnh viễn, chỉ ghi thêm. Mỗi cạnh mang `observed_at`, `valid_from`, `valid_to`, `source_job_id`, `confidence`.
