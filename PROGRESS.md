# PROGRESS: AEGIS–Vanguard

> Nhật ký tiến độ cho AI agent. Cập nhật sau mỗi task hoặc PR: thêm dòng vào "Đã hoàn thành", ghi lỗi vào "Đang lỗi hoặc bị chặn", sửa "Bước tiếp theo". Ghi ngày theo định dạng YYYY-MM-DD. Không xóa lịch sử, chỉ ghi thêm.

## Trạng thái hiện tại

- **Giai đoạn đang mở:** GĐ0 Chuẩn bị (chưa bắt đầu; chưa chốt ngày bắt đầu).
- **Cổng gần nhất đã qua:** chưa có.
- **Mã sản phẩm:** chưa có. Repo mới chứa tài liệu.
- **Quyết định còn mở:** D5–D13 (mặc định kỹ thuật trong [docs/s1/00-thanh-phan-va-quyet-dinh.md](docs/s1/00-thanh-phan-va-quyet-dinh.md) mục 4), chấp nhận khi Product Team duyệt PR hợp đồng S1. D1–D4 đã chốt 2026-11-15: Python 3.12, UUIDv7, collector M06 tải bằng chứng, monorepo + `contracts/`.
- **Tái định vị 2026-11-16:** Product Team chốt D14–D28 ([docs/s1/00-thanh-phan-va-quyet-dinh.md](docs/s1/00-thanh-phan-va-quyet-dinh.md) mục 7): sản phẩm chuyển sang **pentest chủ động** (mở tầng T3), kèm sửa contract S1. AGENTS.md, PRD, RULES, bảng tầng tác động và `contracts/` sẽ được viết lại theo mục 7; cho tới khi đó các file đó vẫn mang định vị "chỉ phòng thủ" cũ.

## Đã hoàn thành

| Ngày | Việc | Tham chiếu |
| --- | --- | --- |
| 2026-11-12 | Bộ tài liệu thiết kế 00–04, đặc tả kỹ thuật, kế hoạch triển khai, đánh giá OSS | `docs/` |
| 2026-11-13 | Chốt toàn bộ quyết định Product Team (phạm vi quét, secret dạng rõ, agent đánh giá mức nghiêm trọng, không đo precision/recall, lưu vĩnh viễn, Podman, MCP, Telegram) | `docs/living/02-ke-hoach-trien-khai.md` mục 10 |
| 2026-11-14 | Đưa tài liệu vào repo (`docs/living`, `docs/source`) và thêm bộ file hướng dẫn cho AI agent (PRD, ARCHITECTURE, DESIGN, RULES, TASKS, PROGRESS, AGENTS, CLAUDE) | PR đầu tiên |
| 2026-11-15 | Bản nháp hợp đồng S1: JSON Schema (ID, lỗi, RoE, manifest, ResultEnvelope, 9 sự kiện, MCP, agent, finding), OpenAPI v1, DDL PostgreSQL, mô hình Neo4j, interface nội bộ, fixture và bộ kiểm tra; phân 8 gói việc cho agent dev | `contracts/`, `docs/s1/` |
| 2026-11-15 | Product Team chốt D1 Python 3.12, D2 UUIDv7, D3 collector M06 tải bằng chứng, D4 monorepo + `contracts/` | `docs/s1/` mục 4 |
| 2026-11-16 | Review độc lập contract/thiết kế S1 từ ba vai trò (AI engineer, SE, security); Product Team chốt D14–D28 tái định vị pentest chủ động + sửa contract | `docs/s1/` mục 7 |

## Đang lỗi hoặc bị chặn

| Ngày | Vấn đề | Ảnh hưởng | Người xử lý |
| --- | --- | --- | --- |
| 2026-11-14 | Ba sơ đồ nhúng (kiến trúc tổng thể, hai lộ trình) không xuất được sang Markdown trong `docs/living/` | Thiếu hình minh họa; nội dung chữ vẫn đủ | Product Team (xuất ảnh từ Claude Docs nếu cần) |
| 2026-11-14 | Ngôn ngữ backend và cấu trúc thư mục mới là đề xuất | Cần khóa ở epic S1 trước khi subagent viết mã | Agent review kiến trúc + Product Team |
| 2026-11-15 | Đặc tả mâu thuẫn: scanner "tải bằng chứng lên MinIO qua signed URL" nhưng mạng thực thi không được vào mạng dữ liệu (nơi có MinIO) | Đã chốt D3 (2026-11-15): collector M06 ở mạng điều khiển tải lên; cần sửa câu "signed URL" trong `docs/living/` khi gộp S1 | Agent review kiến trúc |
| 2026-11-14 | Giấy phép Nerva và dnstwist chưa xác minh | Chặn đóng gói adapter tương ứng | T0.7 |
| 2026-11-16 | **P0** `job_fingerprint` unique vĩnh viễn (`contracts/db/postgres/0001_init.sql:236`) chặn quét lại cùng đầu vào → không sinh được bằng chứng FIXED/REGRESSED | Verifier không đóng/mở lại finding được | D21 (thêm `scan_cycle`) |
| 2026-11-16 | **P0** `ApprovedTask` bắt buộc `image_digest` (`approved-task.v1.schema.json:7`) trong khi manifest cho rest/import và DDL để nullable (`0001_init.sql:235`) — lệch ba chiều | L0/L2 không có đường contract nhất quán | D22 (v1 chỉ container) |
| 2026-11-16 | **P0** `event_id` UUIDv5 (`interfaces/README.md:57`) bị `ids.v1.schema.json:10` (ép UUIDv7) từ chối — lỗi tự mâu thuẫn, fail ngay lần nộp đầu | Luồng ingestion không chạy | D23 |
| 2026-11-16 | **P0** append-only không cưỡng chế: `protect(false)` chỉ cấm DELETE, cột giá trị (`targets`, `secret_value`) vẫn UPDATE tự do (`0001_init.sql:44-55,793-795`) | Phá cam kết "không ghi đè"; audit không có chuỗi băm | D26 (trigger theo cột) + chuỗi băm audit |
| 2026-11-16 | **P0** luồng đánh giá severity chưa có contract (trigger/ngân sách/đường lui); `finding.v1` bắt buộc severity nhưng M20 giao agent severity ở GĐ4 | Kịch bản KEV→Telegram phụ thuộc bước LLM chưa định nghĩa | D18 |
| 2026-11-16 | **P0** prompt injection có thể sinh job quét/tấn công tùy ý: M05 cho qua mọi mục tiêu, nguồn gốc chỉ là `rationale` do LLM viết | Confused-deputy; nguy hiểm hơn khi mở T3 | D16 (denylist bắt buộc) + kiểm `origin_ref` (đề xuất) |
| 2026-11-16 | **P0** collector băm/tải "từng file trong `output_dir`" không chặn symlink/trần (`interfaces/README.md:55`) | Symlink trong `/out` kéo file máy chủ (token, khóa) vào kho bằng chứng | D27 |
| 2026-11-16 | **P1** outbox `bigserial`+`last_seq` có thể bỏ sót giao dịch commit muộn (`0001_init.sql:667,685`); `graph_revision` cùng kiểu | Mất `policy.denied`/`finding.changed` → mất cảnh báo; agent không thấy delta | D25 (watermark) |
| 2026-11-16 | **P1** quy tắc version mâu thuẫn: RULES.md:53 (tăng version) vs `contracts/README.md:39` (thêm field trong v1) với `additionalProperties:false` | Thêm field phá consumer cũ | D24 |
| 2026-11-16 | **P1** rebuild Neo4j bị `consumer_inbox` dedup vĩnh viễn chặn (`graph/model.md:3`, `0001_init.sql:690-697`); thiếu `projection_generation` | Replay bỏ qua sự kiện đã xử lý, không tái dựng được đồ thị | Kỹ thuật kèm D-set (rebuild có generation) |
| 2026-11-16 | **P1** target bắt buộc `CanonicalKey` (`approved-task.v1:21`, `result-envelope:61`) nhưng keyword/CIDR không có canonical key (`0001_init.sql:132`) | Job khám phá từ keyword không ghi được provenance trung thực | Cần `TargetRef` phân biệt seed với asset key |
| 2026-11-16 | **P1** kết quả một phần/đến muộn chưa có quy tắc: `job.completed.v1` chỉ 3 trạng thái terminal, một `event_id`/job | Nguy cơ 409 hoặc mất cập nhật muộn | Kỹ thuật kèm D-set (state machine + fencing) |
| 2026-11-16 | **P1** `ModelClient` chưa đủ hai driver: `ModelResponse.content:str` mất khối nội dung, `finish_reason` không chuẩn, thiếu xử lý sai schema/cắt/refusal (`interfaces/README.md:74-95`) | Vòng tool call thứ hai và fallback không triển khai đúng được | Kỹ thuật kèm D-set |
| 2026-11-16 | **P1** agent tự khai `campaign_id` khi truy vấn bằng chứng (`mcp/graph-queries.v1.schema.json:13,516`) | Agent bị tiêm có thể đọc bằng chứng chiến dịch khác | Server suy `campaign` từ session, bỏ khỏi input |
| 2026-11-16 | **P1** tài liệu còn nói "che secret" (`docs/living/02-ke-hoach-trien-khai.md:129`, `04-module-ket-noi-oss.md:171`) trái quyết định 13/11 (lưu dạng rõ) | Hai chỗ mâu thuẫn, cần thống nhất khi gộp S1 | Agent review kiến trúc |

## Bước tiếp theo

1. **Sửa tài liệu quản trị theo D14–D28 (nhánh `redesign/pentest-repositioning-s1`):** Bước 2 viết lại AGENTS.md/PRD/RULES/bảng tầng tác động; Bước 3 sửa contract + DDL (B1–B8, D16–D28) và kiểm bằng validator.
2. Product Team duyệt hợp đồng S1 (D1–D13); sau đó gộp vào `docs/living/`.
3. T0.1 Chốt ngày bắt đầu, cấu hình agent review kiến trúc và bảo mật.
3. T0.2–T0.6 Chạy năm spike (ưu tiên spike 1, 2, 4 vì nằm trên đường găng).
4. T0.7 Lập bảng pin phiên bản và giấy phép.
5. T0.8 Dựng môi trường dev; T0.10 dựng lab.
6. T0.11 Khóa backlog GĐ1, demo cổng G0.

## Rủi ro cần theo dõi

- Spike 1 thất bại (LangGraph không lồng an toàn trong Temporal) → thiết kế lại S2; không bắt đầu S2 trước kết luận.
- Một máy không đủ tải ở GĐ3–GĐ4 → theo dõi tải từ GĐ2; Kubernetes là thay bộ chạy.
- Không giới hạn phạm vi khi chạy công cụ thật ở GĐ2 → chấp nhận theo quyết định 13/11; bắt buộc ghi nguồn gốc và audit.
- **(2026-11-16, cao) Tái định vị pentest chủ động + không giới hạn phạm vi + T3 tự duyệt:** hệ thống có thể tự động tấn công bên thứ ba không đồng thuận nếu agent bị prompt injection; rủi ro pháp lý. Giảm thiểu bằng denylist bắt buộc (D16); theo dõi sát và cân nhắc thêm `origin_ref`/phạm vi ủy quyền cho T3 nếu sự cố xảy ra.
