*SRS • Feature Catalog • Capability Registry • Adapter SDK • Conformance*

Phiên bản: 1.0 \| Ngày: 12/11/2026 \| Trạng thái: Thiết kế đề xuất

Phạm vi: hệ thống nội bộ, single-tenant; không yêu cầu đăng nhập người dùng ở MVP; giới hạn phạm vi thực thi và an toàn scanner vẫn bắt buộc.

| **Mục tiêu** | Nền tảng AI Agent điều phối đánh giá bề mặt tấn công và lỗ hổng có kiểm soát         |
|--------------|--------------------------------------------------------------------------------------|
| **Triết lý** | OSS-first • Capability-based • Durable campaigns • Evidence-first                    |
| **Nhóm đọc** | CTO • Security Architect • SOC • AppSec • Platform Engineering                       |
| **Căn cứ**   | Hai file nghiên cứu đầu vào; tài liệu chính thức OSS; quyết định kiến trúc của dự án |

# 1. Cách sử dụng tài liệu

Mỗi module bên dưới là năng lực dự kiến của AEGIS–Vanguard, không hàm ý tất cả đều có sẵn trong upstream. Ký hiệu P0: bắt buộc MVP; P1: mở rộng V1; P2: nâng cao V2. Loại tích hợp: CLI, API, MCP, SDK, SubAgent. OSS chỉ là nhà cung cấp có thể chọn, luôn cần spike xác thực input/output và license trước khi đóng gói image.

# 2. Functional requirements — SRS traceability

| **ID** | **Priority** | **Requirement**                             | **Acceptance test**                                  |
|--------|--------------|---------------------------------------------|------------------------------------------------------|
| FR-001 | P0           | Tạo campaign từ scope domains/CIDRs/repos   | Reject target ngoài allowlist; lưu policy_version    |
| FR-002 | P0           | Có RoE khung giờ, blackout, rate limits     | 100% active job gắn policy snapshot và target match  |
| FR-003 | P0           | Tìm provider theo capability input/output   | Registry trả providers tương thích; deny unknown     |
| FR-004 | P0           | Execute/cancel/status/result chuẩn hóa      | Một adapter CLI/REST/MCP đạt conformance             |
| FR-005 | P0           | Agent planning nhiều vòng, có checkpoint    | Resume sau restart và không mất task ledger          |
| FR-006 | P0           | Campaign durable, pause/resume/cancel       | Test fault injection và idempotency                  |
| FR-007 | P0           | Discovery domain/IP/port/web                | Graph tạo đủ domain→IP→service→endpoint              |
| FR-008 | P0           | Ingest artifacts và scan image/SBOM         | SBOM/pURL lưu kèm source artifact digest             |
| FR-009 | P0           | Match CVE/OSV/KEV/EPSS                      | Evidence source+timestamp, phân biệt candidate       |
| FR-010 | P0           | Entity resolution và dedup                  | Không trùng canonical entity khi retry               |
| FR-011 | P0           | Evidence store có checksum và provenance    | 100% finding có evidence/unsupported status          |
| FR-012 | P0           | UI campaign progress/jobs/errors            | Hiển thị blocked, incomplete, failed minh bạch       |
| FR-013 | P1           | Flowsint enrichers feed vào graph           | Có provenance và pivot chain                         |
| FR-014 | P1           | Phân tích JS/source map/repo                | Trích xuất endpoints và packages trong scope         |
| FR-015 | P1           | REA static reverse qua MCP                  | Chỉ chạy on-demand; dữ liệu được cô lập              |
| FR-016 | P1           | Finding verification + negative control     | Tách verified/corroborated/unknown                   |
| FR-017 | P1           | Incremental re-scan theo delta              | Không quét lại tài sản không đổi ngoài TTL policy    |
| FR-018 | P1           | Risk scoring theo bối cảnh                  | CVSS/KEV/EPSS/exposure/criticality có giải thích     |
| FR-019 | P1           | Báo cáo SARIF/JSON/HTML                     | Output hợp lệ và không lộ secrets                    |
| FR-020 | P1           | Integration CI/Git/registry/cloud read-only | Credential cấp riêng, không dùng leak secrets        |
| FR-021 | P2           | SubAgent Strix/Decepticon approval-gated    | Chỉ lab/staging/authorized target; artifacts sandbox |
| FR-022 | P2           | Fix suggestions / PR draft                  | Không auto merge hoặc auto apply production          |

# 3. Danh mục module hệ thống (25 năng lực)

| **ID** | **Module**                   | **Responsibility**                      | **Output**                       | **Provider / Priority**          |
|--------|------------------------------|-----------------------------------------|----------------------------------|----------------------------------|
| M01    | Campaign & RoE               | Objective, scope, policy snapshot       | Campaign, authorization window   | Custom / P0                      |
| M02    | Temporal Lifecycle           | signals, timers, retry, Continue-As-New | Workflow history, campaign state | Temporal / P0                    |
| M03    | LangGraph Agent Harness      | planner, analyst, verifier              | Plans, hypotheses, sessions      | LangGraph / P0                   |
| M04    | LLM Gateway                  | model routing, cost, fallback           | Call metrics, model result       | LiteLLM / P0                     |
| M05    | Capability Registry          | tool discovery & schema versioning      | Providers, manifests             | Custom / P0                      |
| M06    | Execution Gateway            | K8s Jobs, idempotency, limits           | Job events, raw artifact refs    | Custom / P0                      |
| M07    | Asset Inventory              | canonical assets & ownership            | Graph nodes/edges                | Custom + Neo4j / P0              |
| M08    | Domain / ASN Discovery       | Passive OSINT and inventory             | Domain, ASN, CIDR                | Flowsint, Amass, Subfinder / P0  |
| M09    | DNS/IP/Port Discovery        | Resolvers, port fingerprint             | IP, port, protocol               | DNSx, Naabu, Nmap / P0           |
| M10    | Web Fingerprint & Crawl      | HTTP metadata/URLs/SPA                  | Endpoints, technologies          | httpx, Katana / P0               |
| M11    | Config & Infrastructure      | Cloud/K8s/host misconfig inventory      | Exposure/config findings         | Prowler, kube-bench / P1         |
| M12    | Code Repository Analysis     | SAST, commits, source manifests         | Code findings, packages          | Semgrep, Gitleaks / P1           |
| M13    | Image & Filesystem SBOM      | OCI image/SBOM generation               | CycloneDX/SPDX, pURL             | Syft, Trivy / P0                 |
| M14    | Image/Dependency Vulns       | Scan SBOM/OCI/packages                  | Vulnerability candidates         | Trivy, Grype, OSV / P0           |
| M15    | JS / SourceMap Analysis      | Deobfuscate & AST                       | Endpoints, script evidence       | webcrack, jsluice / P1           |
| M16    | Binary / App Reversing       | ELF/PE/APK/Electron analysis            | Analysis evidence refs           | REA / P1                         |
| M17    | Secret Exposure Detection    | Repo/config/asset secrets               | Masked secret finding            | Gitleaks, TruffleHog / P1        |
| M18    | Vuln Feed Sync               | NVD, OSV, KEV, EPSS                     | Versioned intelligence records   | Feed adapters / P0               |
| M19    | PoC Availability Index       | Index references/metadata               | Exploit availability context     | SploitScan, GitHub metadata / P1 |
| M20    | Correlation & Scoring        | CVE↔pURL/CPE, exposure, VEX             | Prioritized findings             | Custom; GUAC optional / P0–P1    |
| M21    | Evidence Verification        | Confirm via safe methods                | Verification status              | Nuclei curated; verifier / P1    |
| M22    | SubAgent Security Assessment | Advanced autonomous analysis            | Evidence/report artifact         | Strix, Decepticon / P2           |
| M23    | Knowledge Graph & Delta      | Versioned edges and graph events        | Asset/relationship changes       | Neo4j + custom / P0              |
| M24    | Reporting & Remediation      | SARIF/report/ticket/PR drafts           | Actions, rescan requests         | Custom; DefectDojo optional / P1 |
| M25    | Telemetry & Audit            | Traces, metrics, scanner history        | Observability and audit          | OpenTelemetry / P0               |

# 4. Đặc tả chuẩn Capability Contract

Một capability chỉ nên thể hiện hành động nghiệp vụ ổn định: \`network.discover_services\`, \`artifact.generate_sbom\`, \`vuln.scan_web\`, \`intel.enrich_cve\`. Provider là implementation với version, package image digest và runtime requirements. Tầng registry lưu schema input/output, impact tier, required scope kind, max concurrency, latency estimate, provider health, license attribution.

apiVersion: aegis.io/v1

kind: CapabilityProvider

metadata:

name: nmap-services

version: 1.0.0

spec:

capability: network.discover_services

providerVersion: pinned-nmap-release

runtime: {type: kubernetes-job, imageDigest: "sha256:\<PIN\>"}

inputSchemaRef: schema://network/discover-services/v1

outputSchemaRef: schema://common/result-envelope/v1

permissions: {scopeRequired: true, networkAccess: active}

safety: {defaultProfile: low-impact, approvalRequired: false}

budget: {timeoutSeconds: 1800, maxConcurrency: 4}

handlers: \[validate, execute, status, cancel, collect\]

compatibilityTests: \[schema, policy, cancellation, idempotency\]

# 5. Adapter SDK — lifecycle và error taxonomy

| **Operation** | **Signature logic**                   | **Bảo đảm**                                     |
|---------------|---------------------------------------|-------------------------------------------------|
| describe      | () -\> Manifest                       | Không side effects                              |
| validate      | (Context, Input) -\> ValidationResult | Validate schema + policy + target normalization |
| start         | (Context, Input, key) -\> JobHandle   | Idempotency key; không thực thi nếu deny        |
| poll/status   | (JobHandle) -\> JobState              | Trạng thái ổn định, có retry_after              |
| cancel        | (JobHandle) -\> CancelResult          | Best effort; cancellation audit                 |
| collect       | (JobHandle) -\> ResultEnvelope        | Raw evidence URI + structured results           |
| health        | () -\> Health                         | Provider version/tool dependencies              |

Error codes chuẩn: INPUT_INVALID, OUT_OF_SCOPE, APPROVAL_REQUIRED, POLICY_DENIED, RATE_LIMITED, TOOL_UNAVAILABLE, DEPENDENCY_MISSING, NETWORK_TIMEOUT, EXECUTION_TIMEOUT, RESOURCE_LIMIT, OUTPUT_INVALID, EVIDENCE_INCOMPLETE, CANCELLED, INTERNAL_ERROR. Error được lưu nguyên nhân kỹ thuật + mô tả dễ đọc + next_action, không được tự chuyển FAILED thành SUCCEEDED.

# 6. Provider selection algorithm

providers = registry.lookup(capability, input_type)

providers = \[p for p in providers if p.healthy and p.schema_compatible\]

providers = \[p for p in providers if policy.allows(p, target, profile)\]

ranked = rank(providers, keys=\[coverage, safety, confidence, cost, latency\])

selected = ranked\[0\] if ranked else BLOCKED

\# LLM có thể đề xuất; policy + schema + scope là quyết định bắt buộc ở code.

# 7. Tích hợp 4 OSS trọng tâm — reuse vs custom

| **OSS**    | **Năng lực upstream đã xác thực**                                                    | **Cách sử dụng**                                         | **Không giả định**                                      |
|------------|--------------------------------------------------------------------------------------|----------------------------------------------------------|---------------------------------------------------------|
| Flowsint   | Graph-oriented investigations, enrichers native/Docker/Python/external \[SRC-07,08\] | Enricher facade hoặc CLI provider; import pivot outcomes | Không coi Graph Conductor RFC#133 là sản phẩm shipped   |
| Decepticon | Agent roles, middleware, LangGraph/Deep Agents, LiteLLM \[SRC-10,11\]                | SubAgent job, reuse patterns/middleware có chọn lọc      | Không dùng trực tiếp shell/C2 hay coi mọi agent safe    |
| REA        | MCP reverse analysis cho native/JS/Electron/.NET/APK… \[SRC-12\]                     | MCP adapter on-demand, compact tool surface              | Không coi static pseudocode là source chính xác         |
| Strix      | Headless scan, multi-agent security assessment, reports \[SRC-13\]                   | Container/SubAgent adapter lab/staging                   | Không mặc định cho phép dynamic exploitation production |

# 8. Cấp độ tích hợp và chiến lược nâng cấp

| **Level**         | **Cách làm**                                | **Khi nào chọn**                           |
|-------------------|---------------------------------------------|--------------------------------------------|
| L0 Import         | Đọc JSON/SARIF/SBOM do OSS xuất thủ công    | Kiểm tra parser trong spike                |
| L1 CLI Wrapper    | Container CLI + output mapping              | Scanner ổn định có CLI                     |
| L2 REST Service   | Service adapter, polling/webhook            | OSS có API dài hạn                         |
| L3 MCP Capability | MCP server qua bridge/whitelist             | REA và công cụ native MCP                  |
| L4 Sub-agent Job  | Phiên agent độc lập, trả report và evidence | Strix/Decepticon, không expose tool nội bộ |

Upgrade cadence: lock image digests, maintain compatibility matrix (adapter version ↔ upstream version), lưu results fixtures, canary một provider, rollback provider manifest. Release và license cần pin cụ thể tại giai đoạn triển khai.

# 9. Bộ conformance test tối thiểu

- Contract validation: manifest/schema hợp lệ; input sai bị từ chối trước khi gọi OSS.

- Policy: target ngoài scope, blackout và rate-limit đều fail-closed.

- Idempotency: gửi cùng request/key 100 lần chỉ tạo một job.

- Cancellation: timeout/cancel kết thúc container và trả kết quả trung thực.

- Result determinism: parse fixture lặp lại không đổi canonical IDs.

- Safety: stdout chứa instruction giả mạo được coi là untrusted data.

- Operational: raw output lớn không bị đưa trực tiếp vào LLM và workflow history.

- Upgrade: adapter chạy trên pinned provider version mới trong CI.

# 10. SRS ngoài chức năng (tóm tắt)

| **ID** | **Quality attribute** | **Target đề xuất**                                            |
|--------|-----------------------|---------------------------------------------------------------|
| NFR-01 | Reliability           | Campaign 7 ngày; restart workers không mất trạng thái         |
| NFR-02 | Data integrity        | Graph ingestion idempotent; evidence sha256                   |
| NFR-03 | Scalability           | ≥50 scanner jobs đồng thời ban đầu; benchmark theo môi trường |
| NFR-04 | Performance           | Registry lookup P95 \< 300 ms tại 100 providers               |
| NFR-05 | Privacy               | Secret values redacted, TTL/retention theo classification     |
| NFR-06 | Observability         | 100% task có campaign/job/trace IDs                           |
| NFR-07 | Maintainability       | Adapter độc lập release; compatibility suite                  |
| NFR-08 | Security              | Mọi active job scope-check; namespace sandbox no privileged   |

# 11. Mức độ kiểm chứng license

Tại ngày đối chiếu 12/11/2026: Flowsint Apache-2.0 kể từ 25/01/2026 (lịch sử AGPL cần chú ý khi lấy commit cũ) \[SRC-09\]; Decepticon Apache-2.0 \[SRC-10\]; REA MIT, các engine thương mại như IDA/Hopper vẫn có license riêng \[SRC-12\]; Strix Apache-2.0 theo pyproject \[SRC-14\]; Nuclei MIT \[SRC-15\]; Syft Apache-2.0 \[SRC-16\]. Các phần mềm phụ trợ khác trong danh mục phải được rà lại license tại phiên bản pin trước khi sử dụng. Đây không phải tư vấn pháp lý.

# Nguồn tham khảo và tính xác thực

SRC-01/SRC-02 là nội dung nghiên cứu do người dùng cung cấp. Những khẳng định từ tài liệu nghiên cứu được sử dụng như đầu vào thiết kế; các năng lực OSS chính thức đã đối chiếu được ghi tại các URL bên dưới (truy cập 12/11/2026). Chi tiết phụ thuộc phiên bản triển khai phải kiểm tra lại khi pin release.

\[SRC-01\] Tài liệu đầu vào: Đặc Tả Hệ Thống Rà Quét Lỗ Hổng AI.docx — Tệp do người dùng cung cấp; nguồn định hướng, không phải bằng chứng triển khai OSS.

\[SRC-02\] Tài liệu đầu vào: AEGIS-Vanguard HTML — Tệp HTML do người dùng cung cấp; bản thể hiện tương tác của nghiên cứu.

\[SRC-07\] Flowsint repository — https://github.com/reconurge/flowsint

\[SRC-08\] Flowsint enrichers — https://github.com/reconurge/flowsint/blob/main/docs/getting-started/enrichers.mdx

\[SRC-09\] Flowsint licensing notice — https://github.com/reconurge/flowsint/blob/main/NOTICE

\[SRC-10\] Decepticon repository — https://github.com/BitterSecurity/Decepticon

\[SRC-11\] Decepticon package boundary — https://github.com/BitterSecurity/Decepticon/blob/main/packages/decepticon/README.md

\[SRC-12\] REA repository — https://github.com/morluto/rea

\[SRC-13\] Strix repository — https://github.com/usestrix/strix

\[SRC-14\] Strix pyproject/license — https://github.com/usestrix/strix/blob/main/pyproject.toml

\[SRC-15\] Nuclei repository — https://github.com/projectdiscovery/nuclei

\[SRC-16\] Syft repository — https://github.com/anchore/syft

\[SRC-18\] Flowsint Graph Conductor proposal (not a released feature) — https://github.com/reconurge/flowsint/issues/133
