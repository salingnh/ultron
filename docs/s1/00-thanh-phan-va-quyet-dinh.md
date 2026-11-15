# S1: Thành phần, hợp đồng ghép nối và các quyết định cần chốt

> Bản nháp ngày 2026-11-15, theo chỉ đạo của Product Team: chốt schema dữ liệu và contract để các agent dev làm độc lập. Đây là đầu ra của epic S1 (T1.2 đến T1.8) được kéo lên sớm trong GĐ0. Sau khi Product Team duyệt, tài liệu này được gộp vào `docs/living/dac-ta-ky-thuat/` và `contracts/` trở thành hợp đồng chính thức v1.
>
> Mã nguồn hợp đồng: [contracts/](../../contracts/README.md). Kiểm tra: `python3 -I contracts/tests/validate_contracts.py` (33 schema, 13 fixture, OpenAPI 23 operation, kiểm chéo DDL) và DDL đã chạy trên PostgreSQL 16 kèm smoke test.

## 1. Ghép nối các thành phần

Mỗi mũi tên là một hợp đồng có file trong `contracts/`. Không có mũi tên nào khác: module không gọi nhau ngoài các đường này.

```text
 Web UI ──REST /api/v1 (openapi.v1)──▶ M26 API ──▶ M01 (campaign, RoE) ──Temporal start/signal──▶ M02 CampaignWorkflow
   ▲  SSE (event-envelope.v1)              │                                                         │ Activity
   │                                        └──POST /jobs (job-submit.v1)──┐                         ▼
   │                                                                         │         M03 Agent (LangGraph)
   │                                                     ContextBundle.v1 ◀─┼── fetch_delta     │  ModelClient ─▶ M04 ─▶ LLM
   │                                                                         │                   │ MCP tools/call
   │                                                                         ▼                   ▼ (capability-request.v1)
   │                                                              M05 điểm kiểm (MCP server) ◀───┘   graph.* (graph-queries.v1) ─▶ M23
   │                                                                │ ApprovedTask.v1 (ký HMAC)
   │                                                                ▼
   │                                                  M06 Execution Gateway ── ContainerSpec ─▶ Podman (container scanner)
   │                                                                │  collector: sha256 → M28 EvidenceStore → MinIO
   │                                                                │  parser(adapter) → ResultEnvelope.v1
   │                                                                ▼
   │                                                  M27 Ingestion  POST /ingestion/results  (G1–G7, 1 giao dịch PG)
   │                                                                │ outbox_event (9 sự kiện .v1)
   │                         ┌──────────────────┬───────────────────┼────────────────────┬─────────────────┐
   │                         ▼                  ▼                   ▼                    ▼                 ▼
   └────────────── M26 SSE    M23 projector → Neo4j    M02 signal job_completed    M20 correlation   M24 cảnh báo Telegram
                                                                                        ▲ intel.revision.v1
                                                                                  M18 feed NVD/OSV/KEV/EPSS
```

Ba điểm ghép nối quan trọng nhất, cũng là nơi dễ lệch nhất giữa các agent:

1. **ResultEnvelope v1** (`ingestion/result-envelope.v1.schema.json`): mọi adapter trả đúng một dạng; tham chiếu tài sản bằng `canonical_key`, không bằng `asset_id`; có `coverage` để M20 biết lần chạy đã kiểm gì (ghi `FindingRun seen=false` đúng chỗ).
2. **Outbox + 9 sự kiện** (`events/`, bảng `outbox_event`, `consumer_inbox`): ghi sự kiện cùng giao dịch với dữ liệu; consumer khử trùng theo `dedup_key`; outbox giữ vĩnh viễn và là event log để dựng lại Neo4j.
3. **Công cụ MCP** (`mcp/`): agent chỉ thấy capability cấp nghiệp vụ và 6 truy vấn đồ thị; mỗi lời gọi mang `trace_id` và `idempotency_key` trong `_meta`; trả `job_id` ngay, không chờ.

## 2. Danh mục hợp đồng

| Hợp đồng | File | Bên phát | Bên nhận | Task |
| --- | --- | --- | --- | --- |
| Định danh, khóa chuẩn, trace | `common/ids.v1` | mọi module | mọi module | T1.19 |
| Lỗi chuẩn | `common/error.v1` | mọi module | M26, M02, UI | T1.4 |
| Tạo chiến dịch, RoE | `campaign/*.v1` | UI | M01 | T1.2 |
| Manifest provider | `capability/provider-manifest.v1` | tác giả adapter | M05 Registry | T1.3 |
| ApprovedTask, ScanJob | `capability/approved-task.v1`, `job.v1`, `job-submit.v1` | M05, M06 | M06, M26 | T1.3 |
| Đầu vào capability | `capabilities/<nhóm>/<tên>.v1` | M03 | M05, adapter | T1.6 |
| ResultEnvelope, predicate | `ingestion/*` | M06 collector | M27 | T1.4 |
| 9 sự kiện | `events/*` | M05, M06, M18, M20, M21, M23, M24, M27, M28 | xem bảng sự kiện đặc tả | T1.5 |
| Công cụ MCP | `mcp/*` | M03 | M05, M23 | T1.6 |
| Phiên agent | `agent/*` | M02 ↔ M03 | | T1.10 |
| Finding, mức nghiêm trọng | `finding/*` | M20, M21 | M24, M26 | T2.x |
| REST v1 | `api/openapi.v1.yaml` | M26, M27 | UI, dịch vụ | T1.7 |
| Lược đồ PostgreSQL | `db/postgres/0001_init.sql` | | mọi module lõi | T1.19–T1.22 |
| Mô hình Neo4j | `graph/*` | M23 | M23, M26 | T1.22 |
| Interface nội bộ | `interfaces/README.md` | | | T1.9–T1.21 |

## 3. Gói việc cho từng agent dev

Mỗi gói làm độc lập được vì: hợp đồng đã cố định, mỗi interface có bản giả trong `tests/fakes/`, và mỗi gói chỉ ghi vào bảng mình sở hữu (cột "Module sở hữu" trong COMMENT của DDL). Gói nào cũng phải qua `validate_contracts.py` và test của chính nó.

| Gói | Module | Sở hữu (thư mục, bảng) | Cài đặt | Dùng (qua bản giả khi chưa có) | Xong khi |
| --- | --- | --- | --- | --- | --- |
| A. Điều phối | M01, M02 | `services/orchestrator/`; `campaign*`, `policy_snapshot`, `scope_snapshot`, `campaign_target`, `objective`, `campaign_ledger` | REST campaign (openapi), `CampaignWorkflow`, signal/query, Activity | M03 (giả trả `AgentSessionResult` cố định), outbox | Tắt worker giữa chừng, chiến dịch chạy tiếp; pause/resume/cancel idempotent |
| B. Agent | M03, M04 | `services/agent/`; `agent_session`, `hypothesis*`, `model_usage`, schema `langgraph` | LangGraph Planner, `ModelClient` 2 driver, ContextBundle → AgentSessionResult | MCP server giả (trả `capability-response.v1`), ModelClient giả | Một đường Planner chạy trọn; output luôn hợp lệ schema; test prompt injection không sinh job |
| C. Cổng công cụ | M05, M06 | `services/mcp-server/`; `policy_decision`, `scan_job`, `job_status_change`, `idempotency_record` (scope mcp) | MCP tools/list + tools/call, Registry đọc `adapters/`, điểm kiểm, `PodmanRunner`, collector | M27 giả (nhận envelope, trả receipt), M28 giả | 100 lần cùng key chỉ 1 job; container không tới mạng dữ liệu; Subfinder thêm bằng manifest + parser |
| D. Adapter | M08, M09 (GĐ1: DNSx, Subfinder) | `adapters/<module>/<tool>/` | manifest, parser thuần, fixture, conformance | `ResultEnvelope v1`, registry predicate | Parse lại fixture cho cùng output; manifest qua validator |
| E. Dữ liệu | M27, M07, M28 | `services/ingestion/`, `services/knowledge/` (phần M07, M28); `asset*`, `observation`, `relationship*`, `evidence*`, `artifact`, `ingestion_inbox`, `quarantine_*`, `dead_letter`, `graph_revision`, `outbox_event` | `POST /ingestion/results`, G1–G7, chuẩn hóa khóa, EvidenceStore | Không cần giả (là gốc) | 1.000 envelope song song không trùng; gửi lại không tạo bản ghi |
| F. Đồ thị | M23 | `services/knowledge/` (phần M23); Neo4j; `consumer_cursor` (m23) | Projector, 6 truy vấn đăng ký, `knowledge.delta.v1` | Outbox thật từ gói E hoặc fixture outbox | Dựng lại Neo4j từ PG giống hệt; truy vấn vượt giới hạn bị cắt |
| G. Tình báo (GĐ2) | M18, M20, M21, M24 | `services/intel/`, `services/reporting/`; `intel_snapshot`, `vulnerability_revision`, `package_vuln_match`, `finding*`, `severity_assessment`, `alert_*`, `report` | Feed sync, khớp CVE, FindingRun, chuyển trạng thái, Telegram | Fixture feed, `intel.revision.v1` giả | Giả lập CVE vào KEV → tin Telegram không cần quét lại |
| H. Giao diện | M26 web, M25 | `web/`, `services/api/`, `observability/`; `audit_log` | Màn hình chiến dịch, luồng quét, đồ thị; SSE; OTel | Mock server sinh từ `openapi.v1.yaml` (Prism) | Người xem thấy chiến dịch chạy và đồ thị lớn dần mà không đọc log |

Thứ tự phụ thuộc: E và C là đường găng của GĐ1 (mọi thứ đi qua ingestion và cổng công cụ). A, B, D, F, H bắt đầu cùng lúc nhờ bản giả. G thuộc GĐ2, chỉ cần schema `finding/*` đã chốt.

## 4. Quyết định cần Product Team chốt

Bốn quyết định đầu đổi cách các agent làm việc nên cần Product Team chọn (đã gửi kèm khuyến nghị). Các quyết định còn lại là mặc định kỹ thuật đã viết vào hợp đồng; duyệt PR này nghĩa là chấp nhận, hoặc ghi ý kiến vào PR để đổi.

| Mã | Câu hỏi | Khuyến nghị (đã áp dụng trong bản nháp) | Lý do | Ảnh hưởng nếu đổi |
| --- | --- | --- | --- | --- |
| **D1** | Ngôn ngữ backend | Python 3.12 cho mọi dịch vụ; web TypeScript | LangGraph và Temporal Python SDK là lõi; một ngôn ngữ giúp sinh kiểu từ schema một lần | Interface trong `interfaces/README.md` viết lại chữ ký; schema giữ nguyên |
| **D2** | Định dạng ID | **Đã chốt 2026-11-15:** UUIDv7 ở mọi nơi (kiểu `uuid` trong PG) | Sắp theo thời gian, index tốt, sinh phân tán không đụng nhau | Ví dụ đặc tả dùng `camp-0001`; nếu muốn tiền tố dễ đọc (`cmp_...`) thì đổi `ids.v1#/$defs/Id` và kiểu cột |
| **D3** | Ai tải bằng chứng lên MinIO | **Đã chốt 2026-11-15:** Collector của M06 (mạng điều khiển) băm SHA-256 và tải lên, container chỉ ghi `/out` | Đặc tả vừa nói "scanner tải lên qua signed URL" vừa cấm mạng thực thi vào mạng dữ liệu (nơi có MinIO). Hai điều này mâu thuẫn; cách này giữ nguyên cách ly mạng | Nếu giữ signed URL thì phải mở đường mạng thực thi → MinIO và bỏ một phần cách ly |
| **D4** | Cấu trúc thư mục | Monorepo theo ARCHITECTURE.md mục 6, thêm `contracts/` ở gốc như bản nháp này | Hợp đồng dùng chung cần một nơi; CI một chỗ | Đổi đường dẫn trong gói việc mục 3 |
| D5 | Xác thực giữa dịch vụ ở MVP | Service token qua header `X-Aegis-Service-Token`; `ApprovedTask` ký HMAC; mTLS để sau | Một máy, một mạng điều khiển; mTLS tốn công cấu hình ở GĐ1 | Thêm mTLS không đổi schema |
| D6 | Agent đề xuất job bằng cách nào | Gọi công cụ MCP capability trong phiên; M05 quyết định và tạo job idempotent; workflow chỉ chờ `job_id` | Khớp "M05 là lớp mỏng trong MCP server"; replay không tạo job mới nhờ `idempotency_key` | Nếu spike T0.5 chọn workflow tự dispatch: dùng trường `proposals` đã có sẵn trong `AgentSessionResult` |
| D7 | Thang mức nghiêm trọng | `CRITICAL, HIGH, MEDIUM, LOW, INFO, UNRATED`; agent chọn kèm `reasons`, `source_refs`, `uncertainty` bắt buộc | Đặc tả chưa có thang; cần enum để lọc, cảnh báo, SARIF | |
| D8 | Tài sản thuộc chiến dịch hay dùng chung | Dùng chung toàn hệ thống (single-tenant, "một đồ thị tri thức"); bảng `asset_campaign` cho biết chiến dịch nào chạm tới; truy vấn agent vẫn lọc theo chiến dịch | Hai chiến dịch thấy cùng domain phải cùng một nút | |
| D9 | Khóa chuẩn và cạnh mới | Thêm khóa `app:`, `email:`, `repo:`, `artifact:`; thêm cạnh `DISCOVERED_FROM`, `SNAPSHOT_OF`, `ALIAS_OF` | Đặc tả có nút Application, Email, Repo nhưng chưa có khóa; G5 cần cạnh nguồn gốc | |
| D10 | Endpoint bổ sung | `GET /campaigns`, `POST /campaigns/{id}/policy`, `GET /campaigns/{id}/flow`, `GET /jobs`, `GET /assets` | Màn hình GĐ1 cần (danh sách chiến dịch, luồng quét, điểm vào đồ thị, job lỗi) | Đánh dấu `x-aegis-status: proposed` trong OpenAPI |
| D11 | Bảng chuyển trạng thái finding | `finding/transitions.v1.yaml`; `FIXED` cần bằng chứng mới, `seen=false` một mình không đủ; mở lại `FALSE_POSITIVE`/`ACCEPTED_RISK` về `CANDIDATE` | Đặc tả có 7 trạng thái nhưng chưa có luật chuyển | |
| D12 | `scan_id` là gì | `scan_id = job_id`: mỗi job là một lần chạy | Đặc tả dùng `scan_id` mà chưa định nghĩa | |
| D13 | Thay đổi giá trị cột "hiện tại" | Cho UPDATE cột trạng thái ở 8 bảng (campaign, job, asset, finding...) với điều kiện mọi thay đổi có dòng lịch sử; cấm DELETE mọi bảng; cạnh chỉ được đặt `valid_to` một lần | Giữ đúng "không xóa, không ghi đè dữ liệu quét" mà truy vấn trạng thái hiện tại vẫn nhanh. Trigger trong DDL cưỡng chế | |

Vẫn để sau như đặc tả: ngưỡng gửi Telegram, ánh xạ LOW/MID/HIGH sang model cụ thể, giấy phép Nerva/dnstwist.

## 5. Điểm còn chờ spike GĐ0

| Spike | Điều có thể làm đổi hợp đồng | Chỗ đã chừa |
| --- | --- | --- |
| T0.2 LangGraph trong Temporal | Activity hay child workflow | `interfaces/README.md` mục 7 viết theo Activity; đổi sang child workflow không đổi schema |
| T0.3 Naabu/Nmap rootless | Cần `NET_RAW` hay không | `permissions.rawSocket` trong manifest, `ContainerSpec.raw_socket` |
| T0.4 Upsert Neo4j đồng thời | Lọc theo `campaign_ids` mảng hay cạnh `TOUCHED` | Cả hai có trong `graph/model.md` |
| T0.5 MCP | SDK, cách đọc `_meta`, P95 | `mcp/README.md` |
| T0.6 BBOT → ResultEnvelope | Predicate, loại tài sản BBOT sinh ra | Thêm vào `predicates.v1.yaml` |

## 6. Việc tiếp theo sau khi duyệt

1. Gộp tài liệu này vào `docs/living/dac-ta-ky-thuat/` (tab mới "Hợp đồng tích hợp"), cập nhật ARCHITECTURE.md mục 5 và 6 theo D1–D4.
2. T1.1 khung repo: đưa `validate_contracts.py`, smoke test DDL và sinh kiểu vào CI (action pin theo commit SHA).
3. Viết bản giả `tests/fakes/` cho 6 interface để các gói A–H bắt đầu song song.
4. Thêm schema đầu vào cho 10 capability GĐ2 còn lại khi viết adapter tương ứng.
