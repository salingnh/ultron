*Vision • Scope • Business Capabilities • Architecture Decisions • Roadmap*

Phiên bản: 1.0 \| Ngày: 12/11/2026 \| Trạng thái: Thiết kế đề xuất

Phạm vi: hệ thống nội bộ, single-tenant; không yêu cầu đăng nhập người dùng ở MVP; giới hạn phạm vi thực thi và an toàn scanner vẫn bắt buộc.

| **Mục tiêu** | Nền tảng AI Agent điều phối đánh giá bề mặt tấn công và lỗ hổng có kiểm soát         |
|--------------|--------------------------------------------------------------------------------------|
| **Triết lý** | OSS-first • Capability-based • Durable campaigns • Evidence-first                    |
| **Nhóm đọc** | CTO • Security Architect • SOC • AppSec • Platform Engineering                       |
| **Căn cứ**   | Hai file nghiên cứu đầu vào; tài liệu chính thức OSS; quyết định kiến trúc của dự án |

# 1. Tóm tắt điều hành

AEGIS–Vanguard là nền tảng rà quét lỗ hổng và quản trị bề mặt tấn công được điều phối bằng AI Agent cho tài sản tổ chức sở hữu hoặc đã được ủy quyền. Mục tiêu là hợp nhất công cụ OSS rời rạc thành một hệ thống liên tục khám phá → làm giàu tri thức → đánh giá yếu điểm → kiểm chứng an toàn → báo cáo và theo dõi khắc phục. Hệ thống kế thừa ý tưởng Knowledge Feedback Loop, dual-plane sandbox và phân tích artifact từ hai nghiên cứu đầu vào \[SRC-01, SRC-02\].

Quyết định kỹ thuật trung tâm: LangGraph đảm nhiệm reasoning/state của từng phiên agent; Temporal đảm nhiệm vòng đời chiến dịch nhiều ngày và distributed activities; Capability Registry + Adapter SDK thống nhất Flowsint, ProjectDiscovery, Trivy/Syft, REA và các sub-agent Strix/Decepticon; Neo4j + PostgreSQL + MinIO lưu tri thức có bằng chứng và nguồn gốc. Đây là kiến trúc ĐỀ XUẤT của dự án, không phải một sản phẩm OSS đã tích hợp sẵn.

<img src="markdown/media/00_Tong_quan_du_an_AEGIS_Vanguard/media/image1.png" style="width:6.2in;height:6.97884in" />

Hình 1. Sơ đồ ý niệm: vòng lặp agent – thực thi – dữ liệu tri thức.

# 2. Bài toán và kết quả mong đợi

| **Hiện trạng**                                                       | **Hệ quả**                          | **Mục tiêu giải quyết**                                                       |
|----------------------------------------------------------------------|-------------------------------------|-------------------------------------------------------------------------------|
| Các kết quả Nmap/Nuclei/Trivy/OSINT không có định danh tài sản chung | Trùng lặp findings, mất mối quan hệ | Ontology chuẩn, hợp nhất entity và provenance                                 |
| Rà quét theo kế hoạch tĩnh, ít tận dụng dữ liệu mới                  | Bỏ sót tài sản và mối liên hệ       | Tự sinh nhiệm vụ follow-up trong scope dựa trên delta tri thức                |
| Các dự án OSS có giao thức và runtime khác nhau                      | Chi phí tích hợp cao                | Capability contract + adapters + conformance tests                            |
| AI Agent dài hạn có thể lỗi, tràn context hoặc lặp vô ích            | Không đủ độ tin cậy vận hành        | Temporal lifecycle, LangGraph session checkpoint, ngân sách và điều kiện dừng |
| Xác minh và ưu tiên lỗ hổng thiếu bối cảnh                           | Tốn công SOC/AppSec                 | Correlate CVE/EPSS/KEV, exposure, criticality và bằng chứng                   |

# 3. Mục tiêu / phi mục tiêu

| **Mục tiêu MVP**                                       | **Không thuộc MVP**                                             |
|--------------------------------------------------------|-----------------------------------------------------------------|
| Black-box, gray-box, white-box discovery trong phạm vi | Không quét ngoài phạm vi do agent tự suy diễn                   |
| Tích hợp nhanh OSS qua adapter và result schema        | Không viết lại Nmap/Nuclei/Trivy/Flowsint                       |
| Chiến dịch bền vững 7 ngày, có resume và retry an toàn | Không cung cấp C2, persistence hay hoạt động xâm nhập trái phép |
| Knowledge graph và evidence traceability               | Không mặc định dùng secret tìm thấy để truy cập hệ thống        |
| Web UI nội bộ không login giai đoạn đầu                | Không có multi-tenant, SSO, RBAC người dùng ở MVP               |
| Phân loại, triage, xuất báo cáo và rescan              | Không tự áp dụng bản vá vào production                          |

# 4. Đối tượng sử dụng và kịch bản nghiệp vụ

| **Persona**            | **Kịch bản**                                                 | **Giá trị**                      |
|------------------------|--------------------------------------------------------------|----------------------------------|
| Security Analyst / SOC | Khởi chạy campaign; xem findings mới; truy nguyên bằng chứng | Phát hiện sớm, ít nhiễu          |
| AppSec                 | Mapping repo/image/SBOM → CVE; theo dõi fix / regression     | Rút ngắn xác minh và remediation |
| Infrastructure / SRE   | Đối chiếu host/IP/service/config; cửa sổ rà quét             | Giảm rủi ro gián đoạn            |
| Security Architect     | Xem attack surface và các quan hệ có nguy cơ                 | Ra quyết định theo đồ thị        |
| Platform Engineer      | Tích hợp scanner OSS mới và giám sát workload                | Mở rộng bằng contract ổn định    |

# 5. Phạm vi năng lực sản phẩm

| **Nhóm năng lực**          | **Đầu vào**                       | **Đầu ra chính**                    | **Ưu tiên** |
|----------------------------|-----------------------------------|-------------------------------------|-------------|
| Asset Discovery            | Domain/CIDR/seed asset            | Asset/Service/Endpoint graph        | P0          |
| Artifact Analysis          | Repo, image, JS, binary được phép | Package, endpoint, config, evidence | P0–P1       |
| Vulnerability Intelligence | CVE, pURL, CPE, KEV/EPSS          | Candidate findings, context risk    | P0          |
| Agent Campaign             | Objective, RoE, budgets           | Plans, jobs, resume state           | P0          |
| Verification & Remediation | Findings đã triage                | Evidence status, owner, rescan      | P1          |
| Continuous Monitoring      | Changes, intelligence feeds       | Delta, re-evaluation, notifications | P1–P2       |

# 6. Nguyên tắc thiết kế

- OSS-first: chỉ viết lớp hợp nhất; tuyệt đối không fork OSS nếu một adapter nhỏ giải quyết được.

- Capability-first: agent yêu cầu năng lực nghiệp vụ, không gọi trực tiếp binary/CLI tùy ý.

- Evidence-first: phân biệt observation, giả thuyết, finding và verified finding; mọi kết luận có provenance.

- Durable-but-bounded: campaign có thể chạy lâu nhưng mỗi agent session và scan job đều có budget, checkpoint, timeout.

- Scope by construction: target, credential và policy được validate trước, trong và sau mỗi job.

- Safe by default: passive/read-only trước; những tác vụ chủ động rủi ro cao cần approval và sandbox.

- Human-operable: UI phải hiển thị agent đã làm gì, thất bại ở đâu, còn gì chưa làm và lý do.

# 7. Quyết định công nghệ trọng tâm

| **Quyết định (ADR)**         | **Lựa chọn**                                   | **Lý do / đánh đổi**                                                |
|------------------------------|------------------------------------------------|---------------------------------------------------------------------|
| ADR-01 Long-running campaign | Temporal + LangGraph                           | Workflow durability tách khỏi LLM reasoning; thêm vận hành Temporal |
| ADR-02 Tool integration      | Capability Registry / Adapter SDK / MCP façade | Ngăn tool explosion; hỗ trợ CLI, REST, MCP, sub-agent               |
| ADR-03 Data truth            | PostgreSQL + Neo4j + MinIO                     | Ràng buộc giao dịch và graph traversal; tránh đẩy raw data vào LLM  |
| ADR-04 Runtime               | Kubernetes Jobs trong namespace cô lập         | Resource quotas, reproducibility, dễ mở rộng                        |
| ADR-05 AI routing            | LiteLLM optional + model profiles              | Độc lập provider, có audit ngân sách                                |
| ADR-06 Tenancy/Auth          | Single tenant; UI chưa cần login               | Giảm scope; vẫn chặn ở network ingress và scanner permissions       |

# 8. Vòng đời nghiệp vụ 7 pha

1.  Scope & RoE: nhập tên miền, CIDR, repo, artifact, cửa sổ quét được phép.

2.  Baseline Discovery: seed graph từ black-/gray-/white-box.

3.  Artifact Enrichment: nhận diện và phân tích tài liệu, image, JS, package và binary được phép.

4.  Knowledge Feedback: hợp nhất evidence và tạo giả thuyết / nhiệm vụ mới trong scope.

5.  Vulnerability Correlation: đối chiếu version/pURL/CPE với CVE, KEV, EPSS, exploit availability metadata.

6.  Safe Verification: passive/low-impact validation; kiểm chứng chủ động chỉ khi được duyệt và trong môi trường thích hợp.

7.  Reporting & Reassessment: dedup, ưu tiên, ticket/PR đề xuất, rescan và lịch sử thay đổi.

# 9. Roadmap triển khai đề xuất

| **Giai đoạn**                | **Phạm vi giao hàng**                                                  | **Exit criteria**                                    |
|------------------------------|------------------------------------------------------------------------|------------------------------------------------------|
| P0 Foundation (3–4 tuần)     | API, RoE, Registry, adapter SDK, Temporal/LangGraph skeleton, storage  | 1 campaign end-to-end có resume và audit             |
| MVP Discovery (4–6 tuần)     | Subfinder/Nmap/Nuclei/Trivy/Syft, graph normalizer, dashboard          | Domain → service → CVE → evidence không trùng        |
| V1 Enrichment (6–8 tuần)     | Flowsint, JS/artifact analysis, REA, CVE feedback loop                 | Phát hiện endpoint mới và lên lịch task có kiểm soát |
| V1.5 Assurance (4–6 tuần)    | Verifier, scoring, CI/CD, exports, benchmark & reliability             | 7 ngày / 10k steps theo bài test có giám sát         |
| V2 Advanced (sau nghiệm thu) | Strix/Decepticon adapter, sandbox validation, advanced graph reasoning | Được phê duyệt qua threat model và evaluation gates  |

Các mốc thời gian trên là ước lượng sơ bộ với nhóm đa kỹ năng; không phải cam kết tiến độ. Nên làm spike kỹ thuật 1–2 tuần xác nhận API/runtime của 4 OSS trước khi khóa backlog.

# 10. KPI và yêu cầu nghiệm thu

| **KPI**             | **Mục tiêu thiết kế**                                        | **Phương pháp đo**                  |
|---------------------|--------------------------------------------------------------|-------------------------------------|
| Campaign durability | 7 ngày liên tục; ≥10.000 bước điều phối không mất trạng thái | Chaos test pod restart, DB failover |
| Duplicate execution | Không sinh job trùng cho cùng idempotency key                | Replay 1.000 events                 |
| Data provenance     | 100% finding có source/evidence hoặc trạng thái unsupported  | Schema validation                   |
| Connector lead time | Một CLI scanner đơn giản tích hợp trong ≤2 ngày công         | Timed engineering drill             |
| Policy coverage     | 100% active jobs gắn scope_id và policy_version              | Audit query                         |
| Finding quality     | Đo precision/recall trên bộ dữ liệu đánh giá cố định         | Golden datasets / manual triage     |
| Operator visibility | 100% job lỗi có error category và next step                  | Acceptance UI test                  |

# 11. Rủi ro trọng yếu và lựa chọn xử lý

| **Rủi ro**                             | **Biện pháp ưu tiên**                                                              |
|----------------------------------------|------------------------------------------------------------------------------------|
| Prompt injection qua tool output       | Untrusted-data boundary; parse/validate; policy ở tầng code, không ủy thác cho LLM |
| Scanner gây gián đoạn                  | Safe profile, rate limit, blackout, segmentation, approval rủi ro                  |
| Tích hợp OSS thay đổi breaking API     | Version pin, compatibility contract, integration test, fallback                    |
| Graph trùng entity / race condition    | Canonical keys, upsert transaction, unique constraints, single ingestion API       |
| Dữ liệu nhạy cảm/secret trong artifact | Không lưu plaintext secret; masking/vault reference; retention                     |
| LLM tool explosion và cost             | Capability search, dynamic tool reveal, summary memory, token budgets              |

# 12. Các điểm cần xác minh trước triển khai

Nguồn nghiên cứu mô tả kiến trúc “Offensive Vaccine”, Graph Conductor, auto patch và nhiều thao tác kỹ thuật. Không nên mặc định tất cả đã tồn tại trong upstream. Issue \#133 của Flowsint là bản RFC/draft; vì vậy Graph Ingestion API được xác định là module phải tự xây \[SRC-18\]. Kết quả static reachability chỉ là evidence hỗ trợ VEX, không mặc nhiên chứng minh không khai thác được. PoC thu thập từ Internet là untrusted; MVP chỉ index metadata, không thực thi tự động.

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

\[SRC-09\] Flowsint licensing notice — https://github.com/reconurge/flowsint/blob/main/NOTICE

\[SRC-10\] Decepticon repository — https://github.com/BitterSecurity/Decepticon

\[SRC-11\] Decepticon package boundary — https://github.com/BitterSecurity/Decepticon/blob/main/packages/decepticon/README.md

\[SRC-12\] REA repository — https://github.com/morluto/rea

\[SRC-13\] Strix repository — https://github.com/usestrix/strix

\[SRC-14\] Strix pyproject/license — https://github.com/usestrix/strix/blob/main/pyproject.toml

\[SRC-15\] Nuclei repository — https://github.com/projectdiscovery/nuclei

\[SRC-16\] Syft repository — https://github.com/anchore/syft

\[SRC-17\] CVE-2026-61732 primary record — https://www.cve.org/CVERecord?id=CVE-2026-61732

\[SRC-18\] Flowsint Graph Conductor proposal (not a released feature) — https://github.com/reconurge/flowsint/issues/133
