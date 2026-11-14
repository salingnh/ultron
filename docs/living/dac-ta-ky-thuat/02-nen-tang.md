# Nền tảng

Nền tảng là lớp hạ tầng dùng chung mà mọi module chạy trên đó: container Podman, MCP server, Temporal, LangGraph, ba kho lưu trữ, LLM gateway và lớp quan sát.

## 1. Môi trường chạy

Đã chốt ngày 13/11/2026: chưa có Kubernetes. Hệ thống chạy trên một máy nội bộ; mỗi công cụ quét chạy trong một container Podman riêng. Bộ chạy container nằm sau một giao diện chung (`ContainerRunner`), nên chuyển sang Kubernetes sau này chỉ là thay bộ chạy.

| Vùng | Thành phần | Mạng | Chính sách |
| --- | --- | --- | --- |
| Điều khiển | Web UI, API, MCP server (Registry, điểm kiểm, bộ chạy), Temporal worker, LangGraph worker | Mạng điều khiển | Chỉ mở cổng giao diện trong mạng nội bộ; checkpoint ở PostgreSQL |
| Dữ liệu | PostgreSQL, Neo4j, MinIO, Temporal server | Mạng dữ liệu | Chỉ vùng điều khiển vào được; sao lưu định kỳ; lưu vĩnh viễn |
| Thực thi | Container công cụ quét, mỗi lần gọi một container | Mạng thực thi, chỉ đi ra ngoài | Không vào được mạng dữ liệu; kết quả ghi vào thư mục riêng rồi được MCP server đọc và gửi Ingestion |
| Quan sát | OpenTelemetry collector | Mạng điều khiển | Prometheus và Loki tùy chọn |

**Hợp đồng chạy container công cụ.** Bộ chạy chỉ nhận lệnh đã qua điểm kiểm và tạo container với các ràng buộc sau:

- Image cố định theo digest, lấy từ registry nội bộ; chỉ image trong allowlist.
- Podman không cần root nếu công cụ cho phép; không chạy privileged; không mount socket của Podman hay Docker; không dùng mạng của máy chủ.
- Bỏ toàn bộ Linux capability, chỉ cấp riêng quyền raw socket cho công cụ cần (Naabu, Nmap) theo kết luận spike 2; root filesystem chỉ đọc; chỉ ghi vào một thư mục kết quả.
- Có giới hạn CPU, bộ nhớ và thời gian chạy; tự hủy khi xong hoặc hết giờ; không tự chạy lại.
- Tham số có cấu trúc theo schema của manifest, không nhận dòng lệnh tùy ý.

**Giao tiếp agent với công cụ.** Agent gọi công cụ qua một MCP server duy nhất. MCP server đưa ra năng lực cấp nghiệp vụ (ví dụ `dns.enumerate_subdomains`) và các truy vấn đồ thị chỉ đọc, không đưa tên công cụ thô. Mỗi lời gọi mang trace ID và khóa chống trùng, đi qua điểm kiểm (M05), rồi mới tới bộ chạy (M06). Điểm kiểm cho qua mọi mục tiêu và ghi mục tiêu cùng lý do được chọn. Hệ thống không giới hạn phạm vi quét; nếu sau này cần luật giới hạn thì cắm vào điểm này.

**Giao diện.** React, TypeScript và Vite; Cytoscape.js cho màn hình đồ thị tri thức (Sigma.js nếu đồ thị vượt vài chục nghìn nút); React Flow với bố cục ELK hoặc dagre cho màn hình luồng quét; cập nhật thời gian thực qua SSE. Giao diện có sẵn của Temporal dùng để debug. Giấy phép và phiên bản xác minh ở GĐ0.

## 2. Điều phối: Temporal và LangGraph

Temporal giữ trạng thái dài hạn của chiến dịch; LangGraph chỉ chạy các phiên suy luận ngắn bên trong.

| Thành phần | Vai trò | Trạng thái lưu ở đâu | Giới hạn |
| --- | --- | --- | --- |
| Temporal `CampaignWorkflow` | Nguồn sự thật về vòng đời chiến dịch: signal, timer, retry | Temporal Event History | Continue-As-New định kỳ để history không phình |
| Temporal Activity | Chạy một phiên agent, gửi job, nạp bằng chứng | Không giữ | Có timeout và retry; phải idempotent |
| LangGraph session | Suy luận cho một mục tiêu hữu hạn | Checkpoint ở PostgreSQL, `thread_id` gắn `session_id` | Khoảng 30 bước mỗi phiên |
| Campaign ledger | Mục tiêu đã xong, giả thuyết chờ, blocker, job ref, cursor đồ thị, ngân sách còn lại | PostgreSQL | Không nằm trong hội thoại LLM |

Vòng lặp chiến dịch:

```text
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
```

Ba quy tắc vận hành:

- Temporal chỉ giữ `job_id` và URI kết quả, không giữ log lớn trong history.
- Replay của workflow không được chạy lại công cụ. Activity có thể bị retry, nên Execution Gateway kiểm Job đã tồn tại trước khi tạo mới.
- Workflow chờ sự kiện `job.completed.v1` qua signal, không busy polling.

## 3. Lưu trữ

Ba kho lưu trữ có vai trò tách bạch; PostgreSQL là nguồn sự thật, Neo4j dựng lại được từ event log.

| Kho | Lưu gì | Không lưu gì | Sao lưu | Mục tiêu phục hồi |
| --- | --- | --- | --- | --- |
| PostgreSQL | Campaign, policy, job, finding, observation, inbox sự kiện, audit, checkpoint LangGraph | Log thô, artifact | Full hằng ngày và WAL liên tục | RPO tối đa 15 phút, RTO tối đa 2 giờ |
| Neo4j | Đồ thị tài sản, quan hệ, đường đi | Trạng thái giao dịch | Backup, snapshot, export định kỳ | RPO tối đa 1 giờ; dựng lại được từ event log |
| MinIO | Bằng chứng thô, artifact, báo cáo | Metadata truy vấn | Versioning, replication hoặc bucket backup | RPO tối đa 1 giờ; kiểm hash sau phục hồi |
| Temporal persistence | Event History của workflow | Dữ liệu nghiệp vụ lớn | Theo backend Temporal | Theo backend Temporal |

Đường dẫn bằng chứng theo mẫu `evidence/{campaign_id}/{job_id}/{sha256}`, bất biến theo version hoặc object lock. Diễn tập phục hồi tối thiểu mỗi quý, đối soát số finding, revision đồ thị và hash bằng chứng.

## 4. LLM gateway và model profile

Mọi lời gọi LLM đi qua một `ModelClient` interface, tự dựng với hai driver theo chuẩn OpenAI Chat Completions và Anthropic Messages, để không khóa cứng vào một nhà cung cấp và không phụ thuộc LiteLLM.

| Nhóm tác vụ | Profile | Kiểm soát chất lượng |
| --- | --- | --- |
| Phân loại, trích xuất đơn giản | LOW | Structured output, kiểm trên dataset |
| Lập kế hoạch, tương quan | MID | Tìm capability có giới hạn, bắt buộc dẫn nguồn |
| Suy luận mã phức tạp | HIGH | Tham chiếu bằng chứng, xác minh độc lập |
| Báo cáo cuối | MID hoặc HIGH | Không có khẳng định thiếu căn cứ; theo report schema |

Gateway ghi nhận token, chi phí và model đã dùng cho từng lời gọi. Fallback giữa các nhà cung cấp chỉ xảy ra khi policy dữ liệu cho phép. Việc ánh xạ LOW, MID, HIGH sang model cụ thể là cấu hình triển khai, chưa chốt trong đặc tả này.

ModelClient chỉ cần nhận endpoint tương thích OpenAI hoặc Anthropic; dùng model local hay cloud do dev cấu hình khi chạy. Chốt 13/11: không che secret ở bất cứ đâu. Database, đồ thị, dữ liệu gửi model, giao diện, báo cáo và tin cảnh báo đều dùng giá trị đầy đủ.

## 5. Mạng, bảo mật nền và xác thực

Mỗi ranh giới giữa hai vùng có một danh sách cho phép và một danh sách cấm; mặc định là từ chối.

| Ranh giới | Cho phép | Cấm hoặc kiểm soát |
| --- | --- | --- |
| Trình duyệt tới API | Ingress mạng nội bộ hoặc VPN | Không public Internet |
| Agent tới MCP server | Gọi capability theo contract | Không shell trực tiếp, không tự mở container |
| Gateway tới scanner | Container Podman theo image allowlist | Không mount socket, không privileged, không mạng máy chủ |
| Scanner tới mục tiêu | Mọi mục tiêu, ghi nguồn gốc vào audit; có trần tốc độ; khung giờ là cấu hình tùy chọn | Tài sản agent lần ra: quét được thì coi như thuộc tổ chức, ghi quan hệ và nguồn gốc trong đồ thị (chốt 13/11) |
| Scanner tới dữ liệu | Tải lên qua signed URL, gọi Ingestion API | Không truy cập trực tiếp Neo4j hay PostgreSQL |
| Ingestion tới đồ thị | Upsert tham số hóa, có khử trùng | Không Cypher thô do LLM sinh |
| Feed ngoài tới AI | Metadata đã parse, gắn nhãn không tin cậy | Không coi nội dung web hay README là chỉ dẫn |

**Bảo mật dịch vụ.** mTLS hoặc service credential giữa các dịch vụ; task ID có chữ ký; credential ngắn hạn cho scanner gray-box, cấp riêng theo mục tiêu; lưu trữ được mã hóa.

**Xác thực người dùng.** MVP chưa có đăng nhập. API chỉ phục vụ qua private ingress hoặc VPN, có allowlist mức mạng, hạn chế CORS, kiểm tra request, và chống CSRF nếu dùng cookie.

**Điểm tích hợp SSO về sau.** Khi mở truy cập cho nhiều nhóm, xác thực được đặt tại biên API và nối với hệ thống SSO sẵn có của tổ chức qua OIDC, không đổi các capability bên trong. Để việc này không phải sửa lại dữ liệu, ngay từ MVP mọi bản ghi audit và thao tác duyệt đã có trường `actor`; khi chưa có đăng nhập, trường này ghi định danh do người vận hành khai báo. Trường `actor` là đề xuất mới.

## 6. Quan sát, CI/CD và cấu hình

Mọi thành phần phát trace, metric và log theo OpenTelemetry, liên kết bằng bộ ID truy vết chung.

**Metric bắt buộc:** `agent_turns`, `tokens`, `cost`, `pending_jobs`, `retry_rate`, `normalization_errors`, `graph_upsert_conflicts`, `scanner_target_rate`, `policy_denials`, `mean_time_to_first_finding`, `scan_novelty`.

**Sáu dashboard vận hành**

| Dashboard | Hiển thị |
| --- | --- |
| Campaign Overview | Trạng thái, thời gian đã chạy, ngân sách, delta mới nhất |
| Job Map | Provider, tài sản, trạng thái, lỗi |
| Knowledge Growth | Tài sản, quan hệ, finding mới theo chu kỳ |
| Safety | Yêu cầu bị từ chối do sai schema hoặc vượt tốc độ |
| AI | Số lượt, token, model đã dùng, độ không chắc chắn |
| Findings | Candidate, corroborated, verified, fixed |

Mỗi biểu đồ cho phép đi xuống tới bằng chứng nguồn và nguyên nhân đổi trạng thái. Trace không che dữ liệu, theo quyết định 13/11.

**CI/CD và cấu hình.** Registry và policy được khai báo theo GitOps, phát hành có chữ ký. Image scanner được pin theo digest và có SBOM. Mỗi adapter có ma trận tương thích giữa phiên bản adapter và phiên bản upstream, chạy conformance test trong CI, triển khai canary từng provider và rollback bằng manifest.
