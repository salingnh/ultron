# AEGIS–Vanguard: Đặc tả kỹ thuật

Nov 12, 2026 · @T

Bộ đặc tả này mô tả chi tiết 28 module của AEGIS–Vanguard, nền tảng chạy chúng và các module kết nối tận dụng OSS sẵn có. Nó triển khai các quyết định trong [bản tổng quan hệ thống hợp nhất](../00-tong-quan-he-thong-hop-nhat.md); khi hai tài liệu lệch nhau, bản tổng quan được ưu tiên.

Lịch giao từng module theo giai đoạn nằm ở [kế hoạch triển khai](../02-ke-hoach-trien-khai.md).

**Quyết định đã chốt, ngày 12 và 13/11/2026.** Cả năm tab đã được viết lại theo bảng này. Bảng đầy đủ kèm ảnh hưởng tiến độ nằm ở mục 10 của [kế hoạch triển khai](../02-ke-hoach-trien-khai.md); lý do chọn công cụ nằm ở [bản đánh giá OSS](../03-danh-gia-oss.md).

| Điểm | Quyết định | Module chịu ảnh hưởng |
| --- | --- | --- |
| Đội thực hiện | AI agent viết mã và review chéo; Product Team duyệt ở mỗi cổng nghiệm thu | Tất cả |
| LLM | ModelClient tự dựng, nhận endpoint tương thích OpenAI hoặc Anthropic; local hay cloud do dev cấu hình; không dùng LiteLLM | M04 |
| Đăng nhập | Chưa có ở MVP | M26 |
| Đầu vào | IP, domain, URL, email, từ khóa | M01, M07, M08 |
| Giao tiếp agent với công cụ | Qua MCP. M05 và M06 là lớp mỏng trong một MCP server | M03, M05, M06 |
| Hạ tầng chạy | Mỗi lần gọi công cụ là một container Podman trên một máy đã có sẵn; ba mạng tách riêng; Kubernetes để sau | M06, tab Nền tảng |
| Phạm vi quét | Không giới hạn. Tài sản quét được thì coi như thuộc tổ chức và có quan hệ nguồn gốc trong đồ thị | M01, M05, M23 |
| Giao diện | GĐ1 có màn hình luồng quét (React Flow) và đồ thị tri thức (Cytoscape.js); agent truy vấn đồ thị qua MCP | M26, M23 |
| Cắm thêm công cụ | Thêm một công cụ chỉ cần manifest và parser, không sửa mã lõi | M05, M08 đến M17 |
| Công cụ OSS | Theo bản đánh giá OSS: ưu tiên ProjectDiscovery; bỏ Amass, Flowsint, Semgrep CE; thêm BBOT, Opengrep, Kubescape, Betterleaks; REA là tùy chọn | M08 đến M17 |
| Mẫu Nuclei | Toàn bộ mẫu chính thức và mẫu người dùng thêm | M10 |
| Secret | Lưu dạng rõ trong database và đồ thị, hiển thị đầy đủ, không che ở đâu | M04, M12, M17, M24, M26, M28 |
| Finding | Không đo precision, recall. Có bằng chứng xác nhận và dẫn chứng để người dùng tự kiểm lại thì là lỗ hổng | M20, M21 |
| Mức nghiêm trọng | AI agent đánh giá và ghi lý do; không dùng công thức trọng số | M20 |
| Gộp tài sản | Tài sản do nhiều công cụ cùng tìm thấy được gộp thành một nút theo khóa chuẩn | M07, M23, M27 |
| Lưu dữ liệu | Vĩnh viễn, không xóa, không ghi đè; lưu lịch sử trạng thái và mức nghiêm trọng theo từng lần chạy, kể cả lần không còn thấy lỗ hổng | M07, M20, M23, M28 |
| Cảnh báo | Bot Telegram; template và group id cấu hình được; ngưỡng gửi chốt ở giai đoạn sau | M24 |
| Đánh giá lại theo KEV và EPSS | Có trong MVP | M18, M20 |
| Tra cứu rò rỉ theo domain | Có; người dùng tự cấu hình API key | M08 |
| Phạm vi GĐ3 | Đủ mã nguồn, secret, cloud, Kubernetes; giữ TruffleHog | M11, M12, M17 |
| Sao lưu | Giữ mục tiêu của tài liệu nguồn: PostgreSQL RPO 15 phút, RTO 2 giờ; Neo4j và MinIO RPO 1 giờ. Đây là cách mình hiểu từ yêu cầu không mất dữ liệu, Product Team chưa xác nhận riêng | Tab Nền tảng |

## 1. Phạm vi và cách đọc

Bộ đặc tả chia làm năm tab, đọc theo thứ tự từ chung đến riêng.

| Tab | Nội dung | Ai nên đọc trước |
| --- | --- | --- |
| Tổng quan đặc tả | Danh mục 28 module, hợp đồng chung, yêu cầu phi chức năng | Mọi người |
| Nền tảng | Container (Podman, Kubernetes về sau), Temporal, LangGraph, lưu trữ, LLM gateway, bảo mật nền | Platform Engineer, SRE |
| Module lõi | Đặc tả chi tiết 17 module dự án tự xây | Backend, AI/Agent, Data Engineer |
| Module kết nối OSS | Adapter SDK và 11 module bọc công cụ OSS | AppSec, Backend Engineer |
| Dữ liệu, API và sự kiện | Thực thể, khóa định danh, REST API, sự kiện | Mọi kỹ sư |

**Quy ước**

- **Mã module.** M01 đến M25 giữ nguyên theo tài liệu 02. M26, M27, M28 là ba module mới được tách ra vì HLD có dịch vụ tương ứng nhưng tài liệu 02 chưa gán mã.
- **Mức ưu tiên.** P0 là bắt buộc cho MVP, P1 là mở rộng, P2 là nâng cao và thuộc nhánh để sau.
- **Giai đoạn.** GĐ1 Nền tảng (3 đến 4 tuần), GĐ2 MVP Khám phá (4 đến 6 tuần), GĐ3 V1 Làm giàu (6 đến 8 tuần), GĐ4 V1.5 Bảo đảm (4 đến 6 tuần). MVP là hết GĐ2.
- **Tầng tác động.** T0 thụ động, T1 tác động thấp, T2 chủ động có giới hạn, T3 xâm nhập, T4 cấm mặc định. MVP chỉ dùng T0 đến T2.
- **Trạng thái.** Toàn bộ là thiết kế đề xuất. Chi tiết nào không có trong tài liệu nguồn 00–04 được ghi rõ là "đề xuất mới".

**Ngoài phạm vi bộ đặc tả này:** red-team, C2, chạy PoC khai thác, tự vá production, multi-tenant. M22 được mô tả ở mức ranh giới để không chặn đường mở rộng về sau.

## 2. Danh mục module

Hệ thống có 28 module: 17 module lõi tự xây và 11 module kết nối OSS. Trong đó 20 module có phần giao trong MVP (15 lõi, 5 kết nối).

**Module lõi (tự xây)**

| Mã | Module | Nhóm | Công nghệ nền | Ưu tiên | Giai đoạn giao |
| --- | --- | --- | --- | --- | --- |
| M01 | Campaign và RoE | Điều phối | PostgreSQL | P0 | GĐ1 |
| M02 | Campaign Controller | Điều phối | Temporal | P0 | GĐ1 |
| M03 | Agent Harness | Điều phối | LangGraph | P0 | GĐ1 khung, GĐ2 đầy đủ |
| M04 | LLM Gateway | Điều phối | ModelClient tự dựng, chuẩn OpenAI và Anthropic | P0 | GĐ1 |
| M05 | Capability Registry và điểm kiểm trong MCP server | Thực thi và policy | Tự xây | P0 | GĐ1 |
| M06 | Execution Gateway | Thực thi và policy | Container Podman, Kubernetes về sau | P0 | GĐ1 |
| M27 | Ingestion và Normalizer | Dữ liệu và tri thức | Tự xây | P0 | GĐ1 |
| M07 | Asset Inventory | Dữ liệu và tri thức | PostgreSQL, Neo4j | P0 | GĐ1, hoàn thiện GĐ2 |
| M23 | Knowledge Graph và Delta | Dữ liệu và tri thức | Neo4j | P0 | GĐ1, hoàn thiện GĐ2 |
| M28 | Evidence Store | Dữ liệu và tri thức | MinIO | P0 | GĐ1 |
| M18 | Vuln Feed Sync | Tình báo và đánh giá | Feed adapter | P0 | GĐ2 |
| M19 | PoC Availability Index | Tình báo và đánh giá | Tự xây | P1 | GĐ3 |
| M20 | Correlation và Scoring | Tình báo và đánh giá | Tự xây | P0 đến P1 | GĐ2 đối chiếu, GĐ4 agent đánh giá mức nghiêm trọng |
| M21 | Evidence Verification | Tình báo và đánh giá | Tự xây | P1 | GĐ4 |
| M26 | Web UI và Backend API | Giao diện và vận hành | Tự xây | P0 | GĐ1 API, màn hình luồng quét và đồ thị; GĐ2 findings |
| M24 | Reporting và Remediation | Giao diện và vận hành | Tự xây | P1 | GĐ2 xuất cơ bản, GĐ4 đầy đủ |
| M25 | Telemetry và Audit | Giao diện và vận hành | OpenTelemetry | P0 | GĐ1 |

**Module kết nối OSS**

| Mã | Module | Công cụ OSS | Ưu tiên | Giai đoạn giao |
| --- | --- | --- | --- | --- |
| M08 | Domain và ASN Discovery | Subfinder, asnmap, BBOT, SpiderFoot-ng, nguồn tự dựng | P0 | GĐ2; SpiderFoot-ng và hai nguồn tự dựng ở GĐ3 |
| M09 | DNS, IP và Port Discovery | DNSx, Naabu, Nerva, cdncheck, Nmap | P0 | GĐ2 |
| M10 | Web Fingerprint và Crawl | httpx, Katana, Nuclei, tlsx, urlfinder | P0 | GĐ2 |
| M13 | Image và Filesystem SBOM | Syft, Trivy | P0 | GĐ2 |
| M14 | Image và Dependency Vulns | Trivy, Grype, OSV-Scanner | P0 | GĐ2 |
| M11 | Config và Infrastructure | Prowler, Kubescape, kube-bench | P1 | GĐ3 |
| M12 | Code Repository Analysis | Opengrep, Gitleaks | P1 | GĐ3 |
| M17 | Secret Exposure Detection | Gitleaks, TruffleHog, Betterleaks | P1 | GĐ3 |
| M15 | JS và SourceMap Analysis | webcrack, jsluice | P1 | GĐ3 |
| M16 | Binary và App Reversing | Bộ giải nén tự dựng; REA tùy chọn | P1 | GĐ3 |
| M22 | SubAgent Security Assessment | Strix, Decepticon | P2 | Để sau |

Ba chỗ khác tài liệu nguồn, là đề xuất mới:

- Nuclei được xếp vào M10 cho việc kiểm tra theo mẫu ở GĐ2. Tài liệu 02 đặt Nuclei dưới M21 (P1), trong khi roadmap lại giao adapter Nuclei ngay ở MVP.
- M11, M12 và M17 được gán vào GĐ3. Tài liệu 02 xếp chúng P1 nhưng backlog của tài liệu 04 chưa có sprint nào cho chúng.
- Phần đánh giá lại theo feed tình báo của M20 được kéo vào GĐ2 để phục vụ cảnh báo sớm.

## 3. Hợp đồng chung

Bốn hợp đồng dưới đây ràng buộc mọi module; module nào không tuân thủ thì không được đưa vào Registry.

**3.1 Capability contract.** Agent và workflow chỉ gọi năng lực nghiệp vụ ổn định, không gọi tên công cụ. Một capability có thể có nhiều provider; mỗi provider khai báo bằng manifest.

```yaml
apiVersion: aegis.io/v1
kind: CapabilityProvider
metadata:
  name: nmap-services
  version: 1.0.0
spec:
  capability: network.discover_services
  providerVersion: pinned-nmap-release
  runtime: {type: container, imageDigest: "sha256:<PIN>"}
  inputSchemaRef: schema://network/discover-services/v1
  outputSchemaRef: schema://common/result-envelope/v1
  permissions: {scopeRequired: false, networkAccess: active}
  safety: {defaultProfile: low-impact, approvalRequired: false}
  budget: {timeoutSeconds: 1800, maxConcurrency: 4}
  handlers: [validate, execute, status, cancel, collect]
  compatibilityTests: [schema, policy, cancellation, idempotency]
```

**3.2 ResultEnvelope.** Mọi provider trả kết quả theo một phong bì duy nhất. Bằng chứng thô nằm ở MinIO, phong bì chỉ mang tham chiếu và checksum.

```json
{
  "schema_version": "1.0",
  "job_id": "job-0021",
  "campaign_id": "camp-0001",
  "capability": "network.discover_services",
  "provider": {"name": "nmap", "version": "pinned-release"},
  "policy_version": "roe-12",
  "status": "succeeded",
  "results": {
    "assets": [{"kind": "service", "canonical_key": "service:10.0.0.10:443/tcp"}],
    "observations": [{"predicate": "port_open", "value": true, "observed_at": "2026-11-12T08:00:00Z"}],
    "relationships": [],
    "findings": []
  },
  "evidence": [{"sha256": "<HEX_SHA256>", "uri": "s3://evidence/<OBJECT_ID>", "classification": "internal"}],
  "errors": [],
  "provenance": {"input_fingerprint": "<HASH>", "adapter_version": "1.0.0"}
}
```

**3.3 Mã lỗi chuẩn.** Mỗi lỗi lưu nguyên nhân kỹ thuật, mô tả dễ đọc và `next_action`. Không module nào được tự chuyển FAILED thành SUCCEEDED.

| Nhóm | Mã lỗi |
| --- | --- |
| Đầu vào và policy | INPUT\_INVALID, OUT\_OF\_SCOPE, APPROVAL\_REQUIRED, POLICY\_DENIED, RATE\_LIMITED |
| Công cụ và môi trường | TOOL\_UNAVAILABLE, DEPENDENCY\_MISSING, NETWORK\_TIMEOUT, EXECUTION\_TIMEOUT, RESOURCE\_LIMIT |
| Kết quả | OUTPUT\_INVALID, EVIDENCE\_INCOMPLETE |
| Khác | CANCELLED, INTERNAL\_ERROR |

**3.4 Idempotency và định danh truy vết.**

- Mọi API ghi nhận `Idempotency-Key`. Gửi cùng key 100 lần chỉ tạo một job.
- Execution Gateway giữ ràng buộc unique trên `job_fingerprint`, tính từ campaign, policy, provider, asset và scan profile.
- Mọi log, event và trace mang đủ: `campaign_id`, `session_id`, `objective_id`, `job_id`, `capability_id`, `provider_version`, `policy_version`, `evidence_id`.
- Mọi job chủ động mang `scope_id` và `policy_version` của bản chụp policy tại lúc duyệt.

## 4. Yêu cầu phi chức năng chung

Tám yêu cầu dưới đây áp dụng cho toàn hệ thống; ngưỡng là mục tiêu thiết kế, cần đo lại trên hạ tầng thật.

| Mã | Thuộc tính | Mục tiêu |
| --- | --- | --- |
| NFR-01 | Độ tin cậy | Chiến dịch 7 ngày; restart worker không mất trạng thái; phục hồi trong 5 phút |
| NFR-02 | Toàn vẹn dữ liệu | Ingestion idempotent; bằng chứng có SHA-256; không xóa, không ghi đè; có lịch sử theo từng lần chạy |
| NFR-03 | Khả năng mở rộng | Từ 50 scanner job đồng thời; độ trễ hàng đợi P95 dưới 2 phút |
| NFR-04 | Hiệu năng | Registry lookup P95 dưới 300 ms với 100 provider; ingestion P95 dưới 30 giây cho output dưới 1 MB |
| NFR-05 | Riêng tư | Dữ liệu lưu vĩnh viễn, không tự xóa; secret lưu và hiển thị đầy đủ, không che |
| NFR-06 | Quan sát | 100% tác vụ có campaign, job và trace ID |
| NFR-07 | Bảo trì | Adapter phát hành độc lập; có bộ compatibility test |
| NFR-08 | Bảo mật | Mọi job chủ động đi qua điểm kiểm và ghi nguồn gốc mục tiêu (không giới hạn phạm vi); container không privileged |

API nội bộ nhằm mức sẵn sàng từ 99,5% mỗi tháng.

## 5. Điểm còn mở

Các điểm dưới đây là câu hỏi kỹ thuật, sẽ có câu trả lời từ spike GĐ0 hoặc khi viết schema ở epic S1. Không còn quyết định nghiệp vụ nào đang mở.

- [ ] Lồng phiên LangGraph trong Temporal: chạy như Activity hay child workflow; hủy và replay có an toàn không.
- [ ] Nmap và Naabu có chạy được trong container Podman không root không, hay cần profile riêng cho raw socket.
- [ ] Định dạng output và cờ dòng lệnh của từng OSS tại phiên bản pin; bảng trong tab Module kết nối OSS là dự kiến.
- [ ] Tên capability trong tab Module kết nối OSS là đề xuất; tên cuối cùng chốt khi viết manifest.

* [ ] Hạ tầng truyền sự kiện: outbox trên PostgreSQL cộng signal của Temporal là đề xuất ở tab Dữ liệu, API và sự kiện; xác nhận trong epic S1.
* [ ] Quan hệ `SUBDOMAIN_OF`, bảng `FindingRun` và các endpoint cho finding, lịch sử và báo cáo delta là thiết kế mới; chi tiết trường dữ liệu chốt khi viết schema ở epic S1.
* [ ] FR-017 (quét lại theo delta) chưa được gán module và giai đoạn trong tài liệu nguồn; kế hoạch triển khai tạm đặt ở M02 và M23, GĐ3.
