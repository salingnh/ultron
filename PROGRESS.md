# PROGRESS: AEGIS–Vanguard

> Nhật ký tiến độ cho AI agent. Cập nhật sau mỗi task hoặc PR: thêm dòng vào "Đã hoàn thành", ghi lỗi vào "Đang lỗi hoặc bị chặn", sửa "Bước tiếp theo". Ghi ngày theo định dạng YYYY-MM-DD. Không xóa lịch sử, chỉ ghi thêm.

## Trạng thái hiện tại

- **Giai đoạn đang mở:** GĐ0 Chuẩn bị (chưa bắt đầu; chưa chốt ngày bắt đầu).
- **Cổng gần nhất đã qua:** chưa có.
- **Mã sản phẩm:** chưa có. Repo mới chứa tài liệu.
- **Quyết định còn mở:** D5–D13 (mặc định kỹ thuật trong [docs/s1/00-thanh-phan-va-quyet-dinh.md](docs/s1/00-thanh-phan-va-quyet-dinh.md) mục 4), chấp nhận khi Product Team duyệt PR hợp đồng S1. D1–D4 đã chốt 2026-11-15: Python 3.12, UUIDv7, collector M06 tải bằng chứng, monorepo + `contracts/`.

## Đã hoàn thành

| Ngày | Việc | Tham chiếu |
| --- | --- | --- |
| 2026-11-12 | Bộ tài liệu thiết kế 00–04, đặc tả kỹ thuật, kế hoạch triển khai, đánh giá OSS | `docs/` |
| 2026-11-13 | Chốt toàn bộ quyết định Product Team (phạm vi quét, secret dạng rõ, agent đánh giá mức nghiêm trọng, không đo precision/recall, lưu vĩnh viễn, Podman, MCP, Telegram) | `docs/living/02-ke-hoach-trien-khai.md` mục 10 |
| 2026-11-14 | Đưa tài liệu vào repo (`docs/living`, `docs/source`) và thêm bộ file hướng dẫn cho AI agent (PRD, ARCHITECTURE, DESIGN, RULES, TASKS, PROGRESS, AGENTS, CLAUDE) | PR đầu tiên |
| 2026-11-15 | Bản nháp hợp đồng S1: JSON Schema (ID, lỗi, RoE, manifest, ResultEnvelope, 9 sự kiện, MCP, agent, finding), OpenAPI v1, DDL PostgreSQL, mô hình Neo4j, interface nội bộ, fixture và bộ kiểm tra; phân 8 gói việc cho agent dev | `contracts/`, `docs/s1/` |
| 2026-11-15 | Product Team chốt D1 Python 3.12, D2 UUIDv7, D3 collector M06 tải bằng chứng, D4 monorepo + `contracts/` | `docs/s1/` mục 4 |

## Đang lỗi hoặc bị chặn

| Ngày | Vấn đề | Ảnh hưởng | Người xử lý |
| --- | --- | --- | --- |
| 2026-11-14 | Ba sơ đồ nhúng (kiến trúc tổng thể, hai lộ trình) không xuất được sang Markdown trong `docs/living/` | Thiếu hình minh họa; nội dung chữ vẫn đủ | Product Team (xuất ảnh từ Claude Docs nếu cần) |
| 2026-11-14 | Ngôn ngữ backend và cấu trúc thư mục mới là đề xuất | Cần khóa ở epic S1 trước khi subagent viết mã | Agent review kiến trúc + Product Team |
| 2026-11-15 | Đặc tả mâu thuẫn: scanner "tải bằng chứng lên MinIO qua signed URL" nhưng mạng thực thi không được vào mạng dữ liệu (nơi có MinIO) | Đã chốt D3 (2026-11-15): collector M06 ở mạng điều khiển tải lên; cần sửa câu "signed URL" trong `docs/living/` khi gộp S1 | Agent review kiến trúc |
| 2026-11-14 | Giấy phép Nerva và dnstwist chưa xác minh | Chặn đóng gói adapter tương ứng | T0.7 |

## Bước tiếp theo

1. Product Team duyệt hợp đồng S1 (D1–D13); sau đó gộp vào `docs/living/`.
2. T0.1 Chốt ngày bắt đầu, cấu hình agent review kiến trúc và bảo mật.
3. T0.2–T0.6 Chạy năm spike (ưu tiên spike 1, 2, 4 vì nằm trên đường găng).
4. T0.7 Lập bảng pin phiên bản và giấy phép.
5. T0.8 Dựng môi trường dev; T0.10 dựng lab.
6. T0.11 Khóa backlog GĐ1, demo cổng G0.

## Rủi ro cần theo dõi

- Spike 1 thất bại (LangGraph không lồng an toàn trong Temporal) → thiết kế lại S2; không bắt đầu S2 trước kết luận.
- Một máy không đủ tải ở GĐ3–GĐ4 → theo dõi tải từ GĐ2; Kubernetes là thay bộ chạy.
- Không giới hạn phạm vi khi chạy công cụ thật ở GĐ2 → chấp nhận theo quyết định 13/11; bắt buộc ghi nguồn gốc và audit.
